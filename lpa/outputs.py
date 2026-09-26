"""Alert outputs: coloured console lines and a JSON-lines file."""
import datetime, json, os, sys, threading

from .model import SEVERITIES

COLORS = {0: "\033[37m", 1: "\033[36m", 2: "\033[33m", 3: "\033[31m", 4: "\033[1;97;41m"}
RESET = "\033[0m"


def _enable_vt():
    if os.name == "nt":                         # turn on ANSI colours in the Windows console
        try:
            import ctypes
            k = ctypes.windll.kernel32; h = k.GetStdHandle(-11); m = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(m)):
                k.SetConsoleMode(h, m.value | 4)
        except Exception:
            pass


def ts_str(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def laya_str(l):
    if not l:
        return ""
    if l.get("mode") in ("unavailable", "skipped"):
        return f"Laya: n/a ({l.get('reason', '')[:40]})"
    if l["mode"] == "domain":
        return f"Laya: {l['verdict']} p={l['p_malicious']:.2f} kind={l['kind']} {l['ms']:.0f}ms"
    return f"Laya: {l['verdict']} p={l['p_malicious']:.2f} [{l['category']}] {l['ms']:.0f}ms"


class Console:
    def __init__(self, min_severity=1, color=None, stream=None):
        self.min = min_severity; self.out = stream or sys.stdout
        self.color = self.out.isatty() if color is None else color
        self.lock = threading.Lock()
        if self.color:
            _enable_vt()

    def alert(self, a):
        if a.final < self.min:
            return
        arrow = "↑" if a.final > a.severity else "↓" if a.final < a.severity else " "
        sev = f"{SEVERITIES[a.final].upper():8s}{arrow}"
        c, r = (COLORS[a.final], RESET) if self.color else ("", "")
        line = f"{ts_str(a.ts)} {c}[{sev}]{r} {a.title}\n           {a.story}\n           {laya_str(a.laya)}"
        with self.lock:
            print(line, file=self.out, flush=True)

    def update(self, a):
        pass


class JsonLines:
    def __init__(self, path):
        self.f = open(path, "a", encoding="utf-8"); self.lock = threading.Lock()

    def alert(self, a):
        with self.lock:
            self.f.write(json.dumps(a.to_dict(), default=str) + "\n"); self.f.flush()

    def update(self, a):
        pass

    def close(self):
        self.f.close()
