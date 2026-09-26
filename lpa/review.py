"""Laya as a continuous traffic classifier (in the spirit of the Jev packet classifier).

Every conversation (local device <-> remote endpoint/port) and every device seen on the local network is summarised in
plain English, including a sanitised preview of any cleartext payload, and Laya classifies it on a background worker.
Detectors still catch the known patterns; this path lets Laya read what they have no rule for (shell commands in a
payload, IRC bot chatter, exploit URLs, odd devices advertising telnet...). Findings above a threshold become alerts.
"""
import heapq, itertools, queue, re, statistics, threading, time
from collections import Counter, defaultdict

from . import decode as D
from .detectors import Detector
from .model import CATEGORIES
from .netutil import human_bytes, ip_class, is_public, known_service, registrable, svc_port

# Question wording chosen with tools/laya_flow_eval.py: naming the concrete threat types (AUC 0.956 on labelled
# synthetic traffic) beat a generic "attack or data theft" question (0.777) by a wide margin.
CONV_Q = {"type": "noul",
          "instructions": "Is this network conversation malicious: malware, a backdoor or remote shell, a botnet, a crypto-miner, "
                          "scanning, exploitation or data theft?",
          "criteria": {"true": "malicious", "false": "normal use of the internet or the local network"}}
CONV_CAT = {"type": "choice", "instructions": "Which category best describes `traffic`?", "criteria": CATEGORIES}
DEVICE_Q = {"type": "noul",
            "instructions": "Does `device` look compromised, backdoored or dangerously insecure (e.g. open telnet, outdated firmware)?",
            "criteria": {"true": "compromised or dangerously insecure device", "false": "an ordinary home or office device"}}
# On real laptop traffic Laya gives ordinary TLS-on-443 conversations 0.6-0.8 when no domain name is known, so a bare
# threshold is too noisy. A review becomes an alert at p >= FLAG_AT, or at p >= FLAG_CORROBORATED when the conversation
# also has something concrete for Laya to have read: a cleartext payload, a non-standard port, or ICMP data.
FLAG_AT, FLAG_CORROBORATED = 0.90, 0.70
STANDARD_PORTS = {80, 443, 53, 123, 853, 993, 995, 465, 587, 22, 5223, 3478, 19302, 5228, 8443, 67, 68, 5353, 1900, 137, 138}

ECHO_TYPES = {0, 8, 128, 129}
ICMP_NAMES = {0: "echo reply (ping)", 8: "echo request (ping)", 3: "destination unreachable (error about a packet this host sent)",
              11: "time exceeded (traceroute / routing error)", 5: "redirect", 128: "echo request (ping)", 129: "echo reply (ping)",
              1: "destination unreachable (error about a packet this host sent)", 135: "neighbour solicitation",
              136: "neighbour advertisement", 133: "router solicitation", 134: "router advertisement"}
_SECRET = re.compile(r"(?i)(pass(?:word|wd)?|pwd|token|secret|authorization:\s*\w+)([ =:]+)(\S+)")


def preview(b, limit=90):
    """Readable, redacted view of the first bytes of a payload (or a short description if it is binary)."""
    if not b:
        return None
    b = bytes(b[:400])
    if b[:1] == b"\x16" and b[1:2] == b"\x03":
        return "TLS handshake"
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)
    if printable < 0.75:
        return f"binary data ({len(b)}+ bytes)"
    t = b.decode("latin-1")
    t = re.sub(r"\r?\n", " | ", t)
    t = _SECRET.sub(lambda m: m.group(1) + m.group(2) + "[redacted]", t)
    t = re.sub(r"[^\x20-\x7e]", ".", t)
    return t[:limit] + ("..." if len(t) > limit else "")


class Conv:
    __slots__ = ("key", "local", "remote", "port", "proto", "first", "last", "conns", "starts", "up", "down", "pk_up",
                 "pk_down", "failed", "names", "c_payload", "s_payload", "tls", "http", "dns_q", "reviewed_at",
                 "reviewed_conns", "reviewed_bytes", "result", "icmp", "inbound")

    def __init__(self, key, local, remote, port, proto, ts):
        self.key = key; self.local = local; self.remote = remote; self.port = port; self.proto = proto
        self.first = self.last = ts; self.conns = 0; self.starts = []; self.up = self.down = self.pk_up = self.pk_down = 0
        self.failed = 0; self.names = set(); self.c_payload = self.s_payload = None; self.tls = set(); self.http = []
        self.dns_q = Counter(); self.reviewed_at = None; self.reviewed_conns = 0; self.reviewed_bytes = 0; self.result = None
        self.icmp = Counter(); self.inbound = None      # True when the remote side sent the first packet


class ConversationTracker(Detector):
    name = "laya-review"

    def __init__(self, reviewer, min_age=8.0, idle=5.0):
        self.rv = reviewer; self.convs = {}; self.min_age = min_age; self.idle = idle
        self.devices = defaultdict(lambda: {"mac": None, "hostname": None, "vendor": None, "ssdp": set(), "mdns": set(),
                                            "listens": set(), "first": None, "reviewed": None, "sig": None, "result": None})

    # ------------------------------------------------------------------ collection (packet thread)
    def on_packet(self, p, flow, eng):
        if not p.ipv:
            return
        self._device_info(p, eng)
        if p.src == p.dst or ip_class(p.dst) in ("multicast", "broadcast") or ip_class(p.src) in ("multicast", "broadcast"):
            return
        s_in, d_in = eng.is_inside(p.src), eng.is_inside(p.dst)
        if s_in and d_in:                         # local <-> local: orient around this laptop, else around the client
            me = self._me(eng)
            if me in (p.src, p.dst):
                local = me
            else:
                local = flow.client if flow is not None else p.src
            remote = p.dst if local == p.src else p.src
        elif s_in and is_public(p.dst):
            local, remote = p.src, p.dst
        elif is_public(p.src) and d_in:
            local, remote = p.dst, p.src
        else:
            return
        port = flow.sport if flow is not None else 0   # the service (server-side) port; ICMP has none
        proto = {D.TCP: "TCP", D.UDP: "UDP", D.ICMP: "ICMP", D.ICMP6: "ICMPv6"}.get(p.proto, f"IP{p.proto}")
        k = (local, remote, port, proto)
        c = self.convs.get(k)
        if c is None:
            c = self.convs[k] = Conv(k, local, remote, port, proto, p.ts)
            c.inbound = flow is not None and flow.client == remote
        c.last = p.ts
        if p.src == local:
            c.up += p.wirelen; c.pk_up += 1
        else:
            c.down += p.wirelen; c.pk_down += 1
        if flow is not None and flow.pc + flow.ps == 1:
            c.conns += 1
            if len(c.starts) < 200:
                c.starts.append(p.ts)
        if p.proto == D.TCP and p.flags & D.RST and p.src == remote:
            c.failed += 1
        if p.icmp:
            c.icmp[p.icmp[0]] += 1
        n = eng.names.get(remote)
        if n:
            c.names.add(n)
        if p.tls:
            if p.tls.get("sni"):
                c.names.add(p.tls["sni"])
            c.tls.add(p.tls["version"])
        if p.http and p.http.get("kind") == "request" and len(c.http) < 3:
            h = p.http
            c.http.append(f"{h['method']} {h['path'][:60]} Host:{h['host'][:40]} UA:{h['ua'][:40]}")
        if p.dns and not p.dns["qr"] and p.dns["qname"] and p.src == local and len(c.dns_q) < 200:
            c.dns_q[registrable(p.dns["qname"])] += 1
        if p.payload and not p.tls and not p.dns:
            if p.src == local and c.c_payload is None:
                c.c_payload = preview(p.payload)
            elif p.src == remote and c.s_payload is None:
                c.s_payload = preview(p.payload)

    @staticmethod
    def _me(eng):
        if eng.local_ips:
            return next(iter(eng.local_ips)) if len(eng.local_ips) == 1 else None
        return eng._top_sender()

    def _device_info(self, p, eng):
        if p.dhcp and p.dhcp.get("op") == 1 and (p.dhcp.get("hostname") or p.dhcp.get("vendor")):
            ip = p.dhcp.get("requested") or (p.src if p.src != "0.0.0.0" else None) or p.dhcp["chaddr"]
            if ip not in eng.local_ips:                               # DHCP requests come from 0.0.0.0: key by requested IP
                d = self.devices[ip]; d["mac"] = d["mac"] or p.dhcp["chaddr"]
                d["hostname"] = p.dhcp.get("hostname") or d["hostname"]; d["vendor"] = p.dhcp.get("vendor") or d["vendor"]
                if d["first"] is None:
                    d["first"] = p.ts
        if not eng.is_inside(p.src) or p.src in eng.local_ips or (not eng.local_ips and eng.label(p.src).endswith("(this laptop)")):
            return
        d = None
        if p.proto == D.UDP and 1900 in (p.sport, p.dport) and p.payload:
            txt = bytes(p.payload[:600]).decode("latin-1", "replace")
            for key in ("SERVER:", "USER-AGENT:", "NT:", "ST:"):
                m = re.search(r"(?im)^" + key + r"\s*(.+)$", txt)
                if m:
                    d = d or self.devices[p.src]; d["ssdp"].add(f"{key.rstrip(':').lower()} {m.group(1).strip()[:70]}")
        if p.dns and 5353 in (p.sport, p.dport) and p.dns.get("qr"):
            d = d or self.devices[p.src]
            for name, _t, val in p.dns["answers"][:8]:
                for x in (name, str(val)):
                    if "._tcp" in x or "._udp" in x or x.endswith(".local"):
                        d["mdns"].add(x[:60])
        if p.proto == D.TCP and p.flags & D.SYN and p.flags & D.ACK:
            d = d or self.devices[p.src]; d["listens"].add(p.sport)
        if d is not None:
            d["mac"] = d["mac"] or p.src_mac
            if d["first"] is None:
                d["first"] = p.ts

    # ------------------------------------------------------------------ scheduling (packet thread, 1 Hz)
    def tick(self, now, eng, final=False):
        tiny = defaultdict(list)                  # probes: <= 3 packets, no payload -> grouped per (local, remote)
        for c in list(self.convs.values()):
            if c.reviewed_at is None and c.pk_up + c.pk_down <= 3 and not (c.c_payload or c.s_payload) \
                    and not c.proto.startswith("ICMP"):
                tiny[(c.local, c.remote)].append(c)   # grouped below once the whole burst is over
                continue
            ready = final or now - c.first >= self.min_age or now - c.last >= self.idle
            if not ready:
                continue
            total = c.up + c.down
            if c.reviewed_at is None:
                self.rv.offer(self._conv_item(c, eng))
            elif (now - c.reviewed_at >= 60 and (c.conns >= max(4, 2 * c.reviewed_conns)
                                                 or total >= max(100_000, 4 * c.reviewed_bytes))):
                self.rv.offer(self._conv_item(c, eng))
            else:
                continue
            c.reviewed_at = now; c.reviewed_conns = c.conns; c.reviewed_bytes = total
        for (local, remote), cs in tiny.items():
            quiet = now - max(c.last for c in cs)
            if not final and (quiet < self.idle or (len(cs) < 3 and quiet < 30)):
                continue                                        # wait until the burst is over; a lone probe may grow
            for c in cs:
                c.reviewed_at = now; c.reviewed_conns = c.conns; c.reviewed_bytes = c.up + c.down
            self.rv.offer(self._conv_item(cs[0], eng) if len(cs) == 1 else self._probe_item(cs, eng))
        if int(now) % 60 == 0 or final:                     # forget long-idle, reviewed conversations
            for k, c in list(self.convs.items()):
                if c.reviewed_at is not None and now - c.last > 900:
                    del self.convs[k]
        for ip, d in self.devices.items():
            sig = (d["hostname"], d["vendor"], len(d["ssdp"]), len(d["mdns"]), len(d["listens"]))
            if sig != d["sig"] and (d["reviewed"] is None or now - d["reviewed"] >= 60 or final):
                d["sig"] = sig; d["reviewed"] = now
                if any(sig[:2]) or any(sig[2:]):
                    self.rv.offer(self._device_item(ip, d, eng))

    # ------------------------------------------------------------------ plain-English summaries
    def _conv_item(self, c, eng):
        names = sorted(c.names)[:3]
        svc = next((known_service(n) for n in names if known_service(n)), None)
        who = "this laptop" if c.local in eng.local_ips or eng.label(c.local).endswith("(this laptop)") else "local device"
        rclass = "internet" if is_public(c.remote) else "local network"
        rname = (", ".join(names) + (f" [{svc}]" if svc else "")) if names else "no domain name seen"
        dur = max(0.0, c.last - c.first)
        where = c.proto if c.proto.startswith("ICMP") else f"{c.proto} port {c.port} ({svc_port(c.port, c.proto.lower())})"
        direction = "connections from" if c.inbound and c.proto != "UDP" else "and"
        parts = [f"{who} {c.local} {direction} {rclass} host {c.remote} ({rname}), {where}",
                 f"{c.conns} connection{'s' if c.conns != 1 else ''} over {_dur(dur)}",
                 f"sent {human_bytes(c.up)} in {c.pk_up} packets, received {human_bytes(c.down)} in {c.pk_down} packets"]
        if c.failed:
            parts.append(f"{c.failed} connection resets from the remote side")
        if len(c.starts) >= 4:
            iv = [b - a for a, b in zip(c.starts, c.starts[1:])]; med = statistics.median(iv)
            jit = statistics.median([abs(x - med) for x in iv]) / med if med else 9
            parts.append(f"connections every {med:.1f} s ({'very regular' if jit < 0.1 else 'regular' if jit < 0.3 else 'irregular'})")
        if c.tls:
            parts.append("encrypted with " + "/".join({0x0304: "TLS1.3", 0x0303: "TLS1.2", 0x0302: "TLS1.1", 0x0301: "TLS1.0",
                                                       0x0300: "SSL3"}.get(v, hex(v)) for v in sorted(c.tls)))
        if c.icmp:
            parts.append("ICMP " + ", ".join(f"{ICMP_NAMES.get(t, f'type {t}')} x{n}" for t, n in c.icmp.most_common(3)))
        if c.dns_q:
            parts.append(f"{sum(c.dns_q.values())} DNS queries for {len(c.dns_q)} domains, e.g. " +
                         ", ".join(d for d, _ in c.dns_q.most_common(6)))
        traffic = "; ".join(parts) + "."
        payload = []
        if c.http:
            payload.append("HTTP requests: " + " || ".join(c.http))
        if c.c_payload and not c.http:
            payload.append(f"first data sent: '{c.c_payload}'")
        if c.s_payload:
            payload.append(f"first data received: '{c.s_payload}'")
        state = {"traffic": traffic}
        if payload:
            state["payload"] = " ; ".join(payload)
        return {"kind": "conversation", "key": c.key, "state": state, "local": c.local, "remote": c.remote,
                "port": c.port, "proto": c.proto, "known": bool(svc), "ts": c.last, "names": names,
                "icmp_echo_data": bool(c.icmp and set(c.icmp) <= ECHO_TYPES and (c.c_payload or c.s_payload)),
                "sig": (registrable(names[0]) if names else c.remote, c.port, c.proto, bool(c.s_payload or c.c_payload))}

    def _probe_item(self, cs, eng):
        c0 = cs[0]; ports = sorted({c.port for c in cs}); resets = sum(c.failed for c in cs)
        names = sorted({n for c in cs for n in c.names})[:2]
        who = "this laptop" if eng.label(c0.local).endswith("(this laptop)") else "local device"
        rclass = "internet" if is_public(c0.remote) else "local network"
        inbound = sum(1 for c in cs if c.inbound) > len(cs) / 2
        span = _dur(max(c.last for c in cs) - min(c.first for c in cs))
        plist = f"{', '.join(map(str, ports[:10]))}{' ...' if len(ports) > 10 else ''}"
        rname = ', '.join(names) or 'no domain name seen'
        if inbound:
            traffic = (f"{rclass} host {c0.remote} ({rname}) sent {len(cs)} unsolicited {c0.proto} connection attempts to "
                       f"{len(ports)} different ports ({plist}) on {who} {c0.local} within {span}; no data exchanged.")
        else:
            replied = sum(1 for c in cs if c.pk_down)
            traffic = (f"{who} {c0.local} sent {len(cs)} short {c0.proto} connection attempts to {len(ports)} different ports "
                       f"({plist}) on {rclass} host {c0.remote} ({rname}) within {span}; no data exchanged; "
                       f"{replied} got a reply, {resets} were refused with a reset.")
        return {"kind": "conversation", "key": ("probe", c0.local, c0.remote, ports[0]), "state": {"traffic": traffic},
                "local": c0.local, "remote": c0.remote, "port": ports[0], "proto": c0.proto, "known": False,
                "ts": max(c.last for c in cs), "names": names, "sig": ("probe", c0.remote, len(ports))}

    def _device_item(self, ip, d, eng):
        bits = [f"local network device {ip}" + (f" (MAC {d['mac']})" if d["mac"] else "")]
        if d["hostname"]:
            bits.append(f"hostname '{d['hostname']}'")
        if d["vendor"]:
            bits.append(f"DHCP vendor '{d['vendor']}'")
        if d["ssdp"]:
            bits.append("UPnP/SSDP announces " + "; ".join(sorted(d["ssdp"])[:4]))
        if d["mdns"]:
            bits.append("mDNS services " + ", ".join(sorted(d["mdns"])[:6]))
        if d["listens"]:
            bits.append("accepts connections on ports " + ", ".join(f"{p} ({svc_port(p)})" for p in sorted(d["listens"])[:10]))
        return {"kind": "device", "key": ("device", ip), "state": {"device": "; ".join(bits) + "."}, "local": ip,
                "remote": None, "port": None, "proto": None, "known": False, "ts": time.time(), "names": [],
                "sig": ("device", ip, str(sorted(d["listens"])), d["hostname"])}


def _dur(s):
    return f"{s:.0f} s" if s < 120 else f"{s / 60:.1f} min" if s < 7200 else f"{s / 3600:.1f} h"


class Reviewer:
    """Background worker: asks Laya about conversations/devices, unknown endpoints first; flags likely threats as alerts."""
    def __init__(self, client, engine_ref, flag_at=FLAG_AT, max_pending=500, ptr=True):
        self.client = client; self.eng = engine_ref; self.flag_at = flag_at; self.max = max_pending
        self.ptr = ptr; self.ptr_cache = {}; self.ptr_jobs = {}
        if ptr:
            from concurrent.futures import ThreadPoolExecutor
            self.ptr_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ptr")
        self.heap = []; self.cv = threading.Condition(); self.seq = itertools.count()
        self.cache = {}; self.lock = threading.Lock()
        self.reviewed = 0; self.cached = 0; self.flagged = 0; self.skipped = 0; self.results = []   # recent results
        self.idle = threading.Event(); self.idle.set()
        threading.Thread(target=self._run, name="laya-review", daemon=True).start()

    def offer(self, item):
        if self.ptr and item["kind"] == "conversation" and not item["names"] and item["remote"] \
                and is_public(item["remote"]) and item["remote"] not in self.ptr_jobs:
            eng = self.eng()
            if eng is not None:                          # so the engine can drop our own PTR queries from the capture
                import ipaddress
                eng.own_ptr.add(ipaddress.ip_address(item["remote"]).reverse_pointer)
            self.ptr_jobs[item["remote"]] = self.ptr_pool.submit(self._lookup, item["remote"])   # resolve while queued
        pri = 0 if item["kind"] == "device" else 1 if not item["known"] else 2   # unknown remotes before known services
        with self.cv:
            if len(self.heap) >= self.max:
                self.skipped += 1; return
            heapq.heappush(self.heap, (pri, next(self.seq), item)); self.idle.clear(); self.cv.notify()

    def pending(self):
        with self.cv:
            return len(self.heap)

    def _run(self):
        while True:
            with self.cv:
                while not self.heap:
                    self.idle.set(); self.cv.wait()
                _, _, item = heapq.heappop(self.heap)
            try:
                self._review(item)
            except Exception as e:
                with self.lock:
                    self.results.append({**_public(item), "error": str(e)[:120]})

    @staticmethod
    def _lookup(ip):
        try:
            import socket
            return socket.gethostbyaddr(ip)[0].lower()
        except (OSError, UnicodeError):
            return None

    def _name_for(self, ip):
        """Reverse DNS for addresses whose forward lookup happened before the capture started. Runs in a pool from
        offer(); the review waits at most 0.5 s so a slow resolver never stalls Laya."""
        if ip in self.ptr_cache:
            return self.ptr_cache[ip]
        job = self.ptr_jobs.get(ip)
        if job is None:
            return None
        try:
            name = job.result(timeout=0.5)
        except Exception:
            return None                                  # still resolving (or failed): review without the name
        self.ptr_cache[ip] = name
        return name

    def _review(self, item):
        if self.ptr and item["kind"] == "conversation" and not item["names"] and item["remote"] and is_public(item["remote"]):
            n = self._name_for(item["remote"])
            if n:
                svc = known_service(n)
                item["names"] = [n]; item["known"] = bool(svc)
                item["state"] = {**item["state"], "traffic": item["state"]["traffic"].replace(
                    "no domain name seen", f"reverse DNS {n}" + (f" [{svc}]" if svc else ""), 1)}
                item["sig"] = (registrable(n),) + tuple(item["sig"][1:])
        sig = item["sig"]; hit = self.cache.get(sig) if item["kind"] == "conversation" and item["known"] else None
        if hit is not None:                        # same known service, same shape: reuse the verdict
            p, cat, ms = hit; cached = True
        else:
            if item["kind"] == "device":
                a, ms = self.client.ask(item["state"], {"threat": DEVICE_Q}, purpose="device review", subject=item["local"])
                cat = "device"
                p = a["threat"]["noul"]
            else:                                        # the NPU runs one question per pass: ask the category only
                subj = f"{item['local']} ↔ {(item['names'] or [item['remote']])[0]}:{item['port']}/{item['proto']}"
                a, ms = self.client.ask(item["state"], {"threat": CONV_Q}, purpose="conversation review", subject=subj)
                p = a["threat"]["noul"]; cat = "benign" if p < 0.5 else "unclassified"
                if p >= FLAG_CORROBORATED:               # ~4x the cost of the threat question (larger NPU bucket)
                    a2, ms2 = self.client.ask(item["state"], {"category": CONV_CAT}, purpose="conversation category",
                                              subject=subj)
                    cat = a2["category"]["choice"]; ms += ms2
            cached = False
            self.cache[sig] = (p, cat, ms)
        why = corroboration(item)
        flag = not item["known"] and (p >= self.flag_at or (p >= FLAG_CORROBORATED and bool(why)))
        res = {**_public(item), "p": round(p, 3), "category": cat, "ms": round(ms, 1), "cached": cached,
               "wall": time.time(), "flagged": flag, "why": why}
        with self.lock:
            self.reviewed += 1; self.cached += cached
            self.results.append(res)
            if len(self.results) > 2000:
                del self.results[:500]
        if flag:
            with self.lock:
                self.flagged += 1
            self._flag(item, p, cat, ms, why)

    def _flag(self, item, p, cat, ms, why=()):
        eng = self.eng()
        if eng is None:
            return
        text = item["state"].get("traffic") or item["state"].get("device")
        if item["state"].get("payload"):
            text += " Payload: " + item["state"]["payload"]
        sev = 2 if p >= 0.9 else 1
        title = "Laya flagged a suspicious device" if item["kind"] == "device" else "Laya flagged a suspicious conversation"
        laya = {"mode": "review", "verdict": "malicious" if p >= 0.9 else "suspicious", "p_malicious": round(p, 3),
                "category": cat, "ms": round(ms, 1), "adjust": 0, "corroborated_by": list(why)}
        eng.emit(item["ts"], "laya-review", cat if cat in CATEGORIES else "benign", sev, title, text, item["local"],
                 item["remote"], key=("laya-review", item["key"]), evidence={"state": item["state"]}, laya=laya)

    def snapshot(self, n=40):
        with self.lock:
            rs = list(self.results)
            return {"reviewed": self.reviewed, "cached": self.cached, "flagged": self.flagged, "skipped": self.skipped,
                    "pending": self.pending(), "top": sorted(rs[-800:], key=lambda r: -r.get("p", 0))[:n],
                    "recent": rs[-n:][::-1]}

    def drain(self, timeout=120):
        self.idle.wait(timeout)


def corroboration(item):
    """Concrete things in the summary that Laya's judgement can rest on (empty for plain TLS on a standard port)."""
    why = []
    st = item["state"]
    if item["kind"] == "device":
        return ["device profile"] if st.get("device") else []
    pl = st.get("payload") or ""
    if pl and any(k in pl for k in ("first data sent: '", "first data received: '", "HTTP requests:")) \
            and "binary data" not in pl and "TLS handshake" not in pl:
        why.append("cleartext payload")
    if item["proto"] in ("TCP", "UDP") and item["port"] and item["port"] not in STANDARD_PORTS and item["port"] < 49152:
        why.append(f"non-standard port {item['port']}")
    if item.get("icmp_echo_data"):                       # pings carrying data; ICMP errors quote headers and don't count
        why.append("ping packets carrying data")
    return why


def _public(item):
    return {"kind": item["kind"], "local": item["local"], "remote": item["remote"], "port": item["port"],
            "proto": item["proto"], "names": item["names"], "known": item["known"], "state": item["state"]}
