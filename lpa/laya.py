"""Laya client (Jev-compatible POST /v1/systemone on a local Laya server) and the alert triage pipeline.

Detectors produce evidence; Laya reads the alert's plain-English story and returns
  threat   : p(real threat) -> benign / suspicious / malicious, moving the heuristic severity down / keeping / up one level
  category : which threat class the evidence describes
For 'domain' alerts it answers whether the domain name itself looks malicious and what kind it is.
If Laya is unreachable the pipeline degrades to heuristic-only alerts and retries periodically.
"""
import json, os, queue, threading, time, urllib.error, urllib.request
from collections import deque

from .model import CATEGORIES, SEVERITIES

# Laya's own presets use named state fields referenced in backticks and true/false criteria on yes/no questions;
# phrased that way the threat question ranks real threats above benign look-alikes far better (tools/laya_eval.py:
# AUC 0.87 vs 0.47-0.70 for free-form verdict questions on the same 30 labelled alert stories).
THREAT_Q = {"type": "noul", "instructions": "Does `evidence` describe an attack, malware, data theft or an exposed password on "
                                            "the laptop's network?",
            "criteria": {"true": "a real security threat", "false": "ordinary traffic of the user or a legitimate service"}}
CATEGORY_Q = {"type": "choice", "instructions": "Which category best describes `evidence`?", "criteria": CATEGORIES}
RAISE_AT, LOWER_AT = 0.75, 0.42           # p(threat) cut-offs chosen on tools/laya_eval.py (no true threat below 0.44)
DOMAIN_QS = {"sus": {"type": "noul", "instructions": "Does this domain name look malicious: randomly generated (DGA), a typo-squat "
                                                     "or look-alike of a well-known brand, phishing, or used for DNS tunnelling?"},
             "kind": {"type": "choice", "instructions": "What best describes this domain name?",
                      "criteria": {"legitimate": "well-known company, CDN, cloud or software service",
                                   "dga": "random-looking machine generated name",
                                   "lookalike": "imitates a brand with typos or extra words, phishing",
                                   "tunnel": "encoded data in subdomain labels",
                                   "dynamic_dns": "free dynamic DNS host"}}}
DEFAULT_URLS = ["http://127.0.0.1:8002", "http://127.0.0.1:8001", "http://127.0.0.1:8004", "http://127.0.0.1:8000"]


class LayaStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = 0; self.errors = 0; self.questions = 0; self.tokens = 0
        self.lat = deque(maxlen=5000)           # (wall_ts, client_ms, server_ms)
        self.backend = None; self.url = None; self.up = False; self.last_error = None
        self.queued = 0; self.dropped = 0; self.upgraded = 0; self.downgraded = 0

    def snapshot(self):
        with self.lock:
            lat = [c for _, c, _ in self.lat]
            recent = [c for t, c, _ in self.lat if time.time() - t < 60]
            return {"calls": self.calls, "errors": self.errors, "questions": self.questions, "tokens": self.tokens,
                    "avg_ms": round(sum(lat) / len(lat), 1) if lat else None,
                    "avg_ms_60s": round(sum(recent) / len(recent), 1) if recent else None,
                    "p95_ms": round(sorted(lat)[int(len(lat) * 0.95)], 1) if lat else None,
                    "backend": self.backend, "url": self.url, "up": self.up, "last_error": self.last_error,
                    "queued": self.queued, "dropped": self.dropped, "upgraded": self.upgraded, "downgraded": self.downgraded}


class CallLog:
    """Ring buffer of every Laya request/response, for the dashboard's call inspector."""
    def __init__(self, keep=500):
        self.lock = threading.Lock(); self.calls = deque(maxlen=keep); self.next_id = 1

    def add(self, **rec):
        with self.lock:
            rec["id"] = self.next_id; self.next_id += 1
            self.calls.append(rec)

    def since(self, after_id=0, limit=200):
        with self.lock:
            return [c for c in self.calls if c["id"] > after_id][-limit:]


def summarise_answers(answers):
    """'threat=yes 0.82 · category=exfiltration 0.64' - one line per call for the dashboard."""
    out = []
    for qid, a in (answers or {}).items():
        if a.get("type") == "noul":
            out.append(f"{qid}: {'yes' if a['noul'] >= 0.5 else 'no'} {a['noul']:.2f}")
        elif a.get("type") == "choice":
            out.append(f"{qid}: {a['choice']} {a.get('answer_confidence', 0):.2f}")
        elif a.get("type") == "score":
            out.append(f"{qid}: {a.get('score', 0):.2f}")
    return " · ".join(out)


class LayaClient:
    def __init__(self, url=None, timeout=10.0, stats=None):
        self.urls = [url.rstrip("/")] if url else DEFAULT_URLS
        self.url = None; self.timeout = timeout; self.stats = stats or LayaStats()
        self.fail_streak = 0; self.retry_at = 0.0; self.log = CallLog()

    def health(self):
        for u in self.urls:
            try:
                with urllib.request.urlopen(u + "/health", timeout=2) as r:
                    info = json.load(r)
                self.url = u
                with self.stats.lock:
                    self.stats.url = u; self.stats.up = True; self.stats.backend = r.headers.get("X-Laya-Backend") or info.get("device")
                return info
            except (OSError, ValueError):
                continue
        with self.stats.lock:
            self.stats.up = False
        return None

    def ask(self, state, questions, purpose="", subject=""):
        """POST /v1/systemone. `purpose` / `subject` only label the call in the dashboard's call log."""
        wall = time.time()
        try:
            answers, ms, meta = self._ask(state, questions)
        except Exception as e:
            self.log.add(wall=wall, purpose=purpose, subject=subject, request={"model": "english", "state": state,
                         "questions": questions}, response=None, error=str(e)[:300], ms=None, summary="error")
            raise
        self.log.add(wall=wall, purpose=purpose, subject=subject, url=self.url,
                     request={"model": "english", "state": state, "questions": questions}, response=meta["raw"],
                     error=None, ms=round(ms, 1), server_ms=meta["server_ms"], backend=meta["backend"],
                     tokens=meta["tokens"], summary=summarise_answers(answers))
        return answers, ms

    def _ask(self, state, questions):
        if self.url is None or (self.fail_streak >= 3 and time.time() < self.retry_at):
            if time.time() < self.retry_at or self.health() is None:
                self.retry_at = time.time() + 15
                raise ConnectionError("Laya server not reachable")
        body = json.dumps({"model": "english", "state": state, "questions": questions}).encode()
        headers = {"Content-Type": "application/json"}
        if os.environ.get("LAYA_API_KEY"):                    # laya-serve can require a bearer key
            headers["Authorization"] = "Bearer " + os.environ["LAYA_API_KEY"]
        req = urllib.request.Request(self.url + "/v1/systemone", body, headers)
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.load(r); srv = float(r.headers.get("X-Server-Time-Ms") or 0); be = r.headers.get("X-Laya-Backend")
        except urllib.error.HTTPError as e:                     # 422 = question does not fit the NPU budget: not an outage
            with self.stats.lock:
                self.stats.errors += 1; self.stats.last_error = f"HTTP {e.code}: {e.read()[:200]!r}"
            raise
        except (OSError, ValueError) as e:
            self.fail_streak += 1; self.retry_at = time.time() + 15
            with self.stats.lock:
                self.stats.errors += 1; self.stats.last_error = str(e)[:200]; self.stats.up = False
            raise ConnectionError(str(e))
        ms = (time.perf_counter() - t0) * 1e3
        self.fail_streak = 0
        with self.stats.lock:
            s = self.stats
            s.calls += 1; s.questions += len(questions); s.tokens += out.get("usage", {}).get("input_tokens", 0)
            s.lat.append((time.time(), ms, srv)); s.up = True
            if be:
                s.backend = be
        return out["answers"], ms, {"raw": out, "server_ms": srv, "backend": be,
                                    "tokens": out.get("usage", {}).get("input_tokens", 0)}


def _trim(story, limit=900):
    return story if len(story) <= limit else story[:limit - 3] + "..."


def judge(client, alert):
    """Ask Laya about one alert; returns the dict stored on alert.laya and the new final severity."""
    base = alert.severity
    if alert.laya_mode == "domain":
        dom = alert.evidence.get("domain") or alert.dst
        a, ms = client.ask({"domain": dom}, DOMAIN_QS, purpose="domain check", subject=dom)
        sus = a["sus"]["noul"]; kind = a["kind"]["choice"]
        adj = 1 if sus >= 0.9 and kind != "legitimate" else -1 if sus < 0.5 or (kind == "legitimate" and sus < 0.8) else 0
        res = {"mode": "domain", "p_malicious": round(sus, 3), "kind": kind, "kind_p": a["kind"]["answer_confidence"],
               "verdict": "malicious" if adj > 0 else "benign" if adj < 0 else "suspicious", "ms": round(ms, 1)}
    else:
        a, ms = client.ask({"alert": alert.title, "evidence": _trim(alert.story)}, {"threat": THREAT_Q, "category": CATEGORY_Q},
                           purpose="alert triage", subject=alert.title)
        p = a["threat"]["noul"]
        adj = 1 if p >= RAISE_AT else -1 if p <= LOWER_AT else 0
        res = {"mode": "triage", "verdict": "malicious" if adj > 0 else "benign" if adj < 0 else "suspicious",
               "p_malicious": round(p, 3), "category": a["category"]["choice"],
               "category_p": a["category"]["answer_confidence"], "ms": round(ms, 1)}
    final = max(0, min(4, base + adj))
    if base >= 3 and adj < 0:
        final = base        # Laya only de-noises weak/ambiguous findings; high/critical detector evidence is never lowered
    res["adjust"] = final - base
    return res, final


class Pipeline:
    """Alert sink used by the Engine: triages alerts on a worker thread, then fans them out to outputs."""
    def __init__(self, client=None, outputs=(), max_queue=2000):
        self.client = client; self.outputs = list(outputs)
        self.q = queue.Queue(maxsize=max_queue)
        self.stats = client.stats if client else LayaStats()
        self.lock = threading.Lock(); self.alerts = []          # all alerts in emit order (dashboard / report)
        self._stop = False
        if client:
            self.worker = threading.Thread(target=self._run, name="laya-triage", daemon=True); self.worker.start()

    def submit(self, alert):
        with self.lock:
            self.alerts.append(alert)
        if not self.client or alert.laya is not None:      # no Laya, or Laya already judged it (continuous review)
            return self._out(alert)
        try:
            self.q.put_nowait(alert)
            with self.stats.lock:
                self.stats.queued = self.q.qsize()
        except queue.Full:
            with self.stats.lock:
                self.stats.dropped += 1
            alert.laya = {"mode": "skipped", "reason": "triage queue full"}
            self._out(alert)

    def update(self, alert):
        for o in self.outputs:
            o.update(alert)

    def _run(self):
        while True:
            a = self.q.get()
            if a is None:
                self.q.task_done(); return
            try:
                a.laya, a.final = judge(self.client, a)
                with self.stats.lock:
                    self.stats.upgraded += a.final > a.severity; self.stats.downgraded += a.final < a.severity
            except Exception as e:                   # Laya down / 422 / bad answer: keep the heuristic verdict
                a.laya = {"mode": "unavailable", "reason": str(e)[:160]}
            with self.stats.lock:
                self.stats.queued = self.q.qsize()
            self._out(a)
            self.q.task_done()

    def _out(self, a):
        for o in self.outputs:
            try:
                o.alert(a)
            except Exception as e:                   # an output must never kill triage
                print(f"[lpa] output error: {e}")

    def drain(self, timeout=None):
        if not self.client:
            return
        t0 = time.time()
        while self.q.unfinished_tasks and (timeout is None or time.time() - t0 < timeout):
            time.sleep(0.05)

    def severity_counts(self):
        with self.lock:
            c = {s: 0 for s in SEVERITIES}
            for a in self.alerts:
                c[SEVERITIES[a.final]] += 1
            return c
