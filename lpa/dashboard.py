"""Live dashboard: a 1 Hz sampler over engine / pipeline / Laya counters and a loopback-only HTTP server for the UI."""
import json, os, threading, time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .model import SEVERITIES
from .netutil import known_service

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


class Sampler:
    """Every second: packets/s, bytes in/out per s, Laya calls & mean latency in that second, alerts by severity."""
    def __init__(self, engine, pipeline, source="", period=1.0, keep=1800):
        self.e = engine; self.p = pipeline; self.source = source; self.period = period
        self.series = deque(maxlen=keep); self.lock = threading.Lock()
        self.prev = None; self.done = False; self.t0 = time.time(); self.status = "starting"
        self._stop = threading.Event()
        threading.Thread(target=self._run, name="sampler", daemon=True).start()

    def _totals(self):
        m = self.e.m
        with m.lock:
            pk, by = m.packets, m.bytes
            bo, bi = sum(m.bytes_out.values()), sum(m.bytes_in.values())
        st = self.p.stats
        with st.lock:
            calls = st.calls; lat_sum = sum(c for _, c, _ in st.lat); nlat = len(st.lat)
        with self.p.lock:
            sev = Counter(SEVERITIES[a.final] for a in self.p.alerts if a.laya is not None or not self.p.client)
        return time.time(), pk, by, bo, bi, calls, lat_sum, nlat, sev

    def sample(self):
        cur = self._totals()
        if self.prev is not None:
            t, pk, by, bo, bi, calls, ls, nl, sev = cur
            pt, ppk, pby, pbo, pbi, pcalls, pls, pnl, psev = self.prev
            dt = max(t - pt, 1e-3)
            dl = nl - pnl
            avg = (ls - pls) / dl if dl > 0 and ls >= pls else None
            row = {"t": round(t, 2), "packets": pk, "pps": round((pk - ppk) / dt, 1), "bps_out": round((bo - pbo) / dt),
                   "bps_in": round((bi - pbi) / dt), "bps": round((by - pby) / dt), "laya_calls": calls,
                   "laya_calls_dt": calls - pcalls, "laya_ms": round(avg, 1) if avg is not None else None,
                   "sev": {s: sev.get(s, 0) - psev.get(s, 0) for s in SEVERITIES}}
            with self.lock:
                self.series.append(row)
        self.prev = cur

    def _run(self):
        n = 0
        while not self._stop.wait(self.period):
            n += 1
            try:
                self.sample()
                c = self.p.client
                if c is not None and n % 15 == 0 and not c.stats.up:    # notice a Laya server started after us
                    c.health()
            except Exception as ex:                     # the UI must never take the analyser down
                print(f"[dashboard] sampler: {ex}")

    def stop(self):
        self._stop.set()

    def clear_history(self):
        """Start fresh: charts, alerts, Laya call log and counters. Capture and detection keep running."""
        e, p = self.e, self.p
        e.clear_history(); p.clear_history()
        if getattr(e, "reviewer", None):
            e.reviewer.clear_history()
        with self.lock:
            self.series.clear(); self.prev = None; self.t0 = time.time()
        e.m.note("history cleared from the dashboard")

    # ------------------------------------------------------------------ state for the UI
    def state(self, since=0.0):
        e, p = self.e, self.p
        m = e.m
        with self.lock:
            series = [r for r in self.series if r["t"] > since]
        with m.lock:
            proto = dict(m.proto.most_common(8)); app = dict(m.app.most_common(6))
            remote = m.remote_bytes.most_common(10); domains = m.domains.most_common(10)
            totals = {"packets": m.packets, "decoded": m.decoded, "bytes": m.bytes, "flows_active": m.flows_active,
                      "flows_total": m.flows_total, "cap_first": m.cap_first, "cap_last": m.cap_last,
                      "bytes_out": sum(m.bytes_out.values()), "bytes_in": sum(m.bytes_in.values()),
                      "duplicates": m.duplicates, "undecoded": dict(m.undecoded), "errors": m.errors,
                      "self_excluded": m.self_excluded}
            log = [{"t": t, "msg": x} for t, x in m.log]; samples = list(m.undecoded_samples)
        with p.lock:
            alerts = list(p.alerts)
        shown = [a for a in alerts if a.laya is not None or not p.client]
        sev = Counter(SEVERITIES[a.final] for a in shown)
        det = Counter(a.category for a in shown if a.final >= 1)
        verdicts = Counter((a.laya or {}).get("verdict", "n/a") for a in shown)
        recent = sorted(shown, key=lambda a: (a.final, a.id), reverse=True)[:150]
        recent.sort(key=lambda a: a.id, reverse=True)
        names = e.names
        return {
            "now": time.time(), "uptime": time.time() - self.t0, "pid": os.getpid(), "source": self.source, "status": self.status,
            "series": series, "totals": totals, "proto": proto, "app": app,
            "remote": [{"ip": ip, "bytes": b, "name": names.get(ip), "service": known_service(names.get(ip))} for ip, b in remote],
            "domains": [{"domain": d, "queries": n, "service": known_service(d)} for d, n in domains],
            "severity": {s: sev.get(s, 0) for s in SEVERITIES}, "categories": dict(det.most_common(10)),
            "verdicts": dict(verdicts), "laya": p.stats.snapshot(), "laya_enabled": bool(p.client),
            "alerts": [a.to_dict() for a in recent], "pending": len(alerts) - len(shown),
            "log": log, "undecoded_samples": samples,
            "review": e.reviewer.snapshot() if getattr(e, "reviewer", None) else None,
        }


class Dashboard:
    def __init__(self, sampler, host="127.0.0.1", port=8765):
        smp = sampler

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype); self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def _same_origin(self):
                """State-changing requests must come from this dashboard: a matching Host (defeats DNS rebinding),
                a matching Origin when the browser sends one (defeats cross-site forms), and a custom header that a
                cross-site page cannot add without a CORS preflight, which this server never grants."""
                port = self.server.server_address[1]
                ok_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
                origin = self.headers.get("Origin")
                return (self.headers.get("Host") in ok_hosts and self.headers.get("X-LPA-Request") == "1"
                        and (origin is None or origin.split("://", 1)[-1] in ok_hosts))

            def do_POST(self):
                if self.path == "/api/reset":
                    if not self._same_origin():
                        return self._send(403, b"forbidden", "text/plain")
                    smp.clear_history()
                    return self._send(200, b'{"ok": true}', "application/json")
                self._send(404, b"not found", "text/plain")

            def do_GET(self):
                if self.path in ("/", "/index.html"):
                    with open(HTML, "rb") as f:
                        return self._send(200, f.read(), "text/html; charset=utf-8")
                if self.path.startswith("/api/calls"):
                    after = 0
                    if "after=" in self.path:
                        try:
                            after = int(self.path.split("after=", 1)[1].split("&")[0])
                        except ValueError:
                            pass
                    c = smp.p.client
                    calls = c.log.since(after) if c is not None else []
                    return self._send(200, json.dumps({"enabled": c is not None, "calls": calls}, default=str).encode(),
                                      "application/json")
                if self.path.startswith("/api/state"):
                    since = 0.0
                    if "since=" in self.path:
                        try:
                            since = float(self.path.split("since=", 1)[1].split("&")[0])
                        except ValueError:
                            pass
                    return self._send(200, json.dumps(smp.state(since), default=str).encode(), "application/json")
                self._send(404, b"not found", "text/plain")

        self.httpd = ThreadingHTTPServer((host, port), H)
        self.httpd.daemon_threads = True
        self.url = f"http://{host}:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, name="dashboard", daemon=True).start()

    def close(self):
        self.httpd.shutdown()
