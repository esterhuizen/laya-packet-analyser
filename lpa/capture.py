"""Packet sources. Each yields (ts, linktype, data, wirelen).

  files     pcap/pcapng files (optionally replayed at capture speed for demos)
  stdin     a live pcap stream, e.g.  dumpcap -i Wi-Fi -w - | lpa live --source stdin
  follow    a capture file that another tool is still writing
  pktmon    Windows built-in Packet Monitor (no Npcap needed; requires an elevated/Administrator shell).
            Captured in back-to-back slices (stop -> restart -> convert), so there is a sub-second gap between slices.
  iface     Linux AF_PACKET raw socket (root)
"""
import os, queue, shutil, subprocess, sys, tempfile, threading, time

from .pcapio import Follow, read_packets


def from_files(paths, replay=None, stop=None):
    for path in paths:
        with open(path, "rb") as f:
            first = None; t0 = None
            for pkt in read_packets(f):
                if stop is not None and stop.is_set():
                    return
                if replay:
                    if first is None:
                        first, t0 = pkt[0], time.time()
                    delay = (pkt[0] - first) / replay - (time.time() - t0)
                    if delay > 0:
                        time.sleep(min(delay, 5.0))
                yield pkt


def from_stdin():
    yield from read_packets(sys.stdin.buffer)


def from_follow(path, stop):
    f = Follow(path, stop=stop)
    try:
        yield from read_packets(f)
    finally:
        f.close()


def is_admin():
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class Pktmon:
    """Rolling pktmon capture: slice N is converted/analysed while slice N+1 is recording."""
    def __init__(self, slice_s=3.0, workdir=None, comp="nics", log=print, keep=False):
        self.slice = slice_s; self.comp = comp; self.log = log; self.keep = keep
        self.dir = workdir or tempfile.mkdtemp(prefix="lpa-pktmon-")
        os.makedirs(self.dir, exist_ok=True)
        self.files = queue.Queue(); self.stop_ev = threading.Event(); self.gaps = []

    def _pm(self, *args, check=True, timeout=60):
        try:
            r = subprocess.run(["pktmon", *args], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:          # a hung pktmon call must not freeze the capture forever
            if check:
                raise RuntimeError(f"pktmon {args[0]} did not finish within {timeout} s")
            return subprocess.CompletedProcess(args, 1, "", f"timeout after {timeout} s")
        if check and r.returncode != 0:
            raise RuntimeError(f"pktmon {' '.join(args)} failed: {(r.stdout + r.stderr).strip()[:400]}")
        return r

    def _start(self, n):
        etl = os.path.join(self.dir, f"slice{n:06d}.etl")
        self._pm("start", "--capture", "--comp", self.comp, "--pkt-size", "0", "--file-name", etl, "--log-mode", "circular",
                 "--file-size", "256")
        return etl

    def _loop(self):
        n = 0; failures = 0
        while not self.stop_ev.is_set():
            try:
                etl = self._start(n)
                while not self.stop_ev.wait(self.slice):
                    t0 = time.perf_counter()
                    self._pm("stop")
                    n += 1; nxt = self._start(n)
                    self.gaps.append(time.perf_counter() - t0)
                    self.files.put(etl); etl = nxt; failures = 0
                self._pm("stop", check=False); self.files.put(etl)
            except Exception as e:                   # pktmon hiccup: log it, reset the session and carry on
                failures += 1; n += 1
                self.log(f"[pktmon] {e} (restart {failures})")
                self._pm("stop", check=False)
                if failures >= 10:
                    self.log("[pktmon] giving up after 10 consecutive failures")
                    break
                self.stop_ev.wait(min(10, 2 * failures))
        self.files.put(None)

    def packets(self):
        if shutil.which("pktmon") is None:
            raise RuntimeError("pktmon.exe not found (Windows 10 2004+ required)")
        if not is_admin():
            raise PermissionError("pktmon needs an elevated shell: open PowerShell as Administrator and run lpa live there")
        self._pm("stop", check=False)                           # a stale session blocks 'start'
        threading.Thread(target=self._loop, name="pktmon", daemon=True).start()
        while True:
            etl = self.files.get()
            if etl is None:
                return
            pcap = etl[:-4] + ".pcapng"
            r = self._pm("etl2pcap", etl, "--out", pcap, check=False)
            if r.returncode == 0 and os.path.exists(pcap):
                try:
                    with open(pcap, "rb") as f:
                        yield from read_packets(f)
                except Exception as e:
                    self.log(f"[pktmon] could not read {os.path.basename(pcap)}: {e!r}")
            else:
                self.log(f"[pktmon] conversion of {os.path.basename(etl)} failed: {(r.stdout + r.stderr).strip()[:200]}")
            for p in (etl, pcap):
                if self.keep and p == pcap:
                    continue                                   # keep converted slices for inspection
                try:
                    os.remove(p)
                except OSError:
                    pass

    def stop(self):
        self.stop_ev.set()


def from_iface(name, stop):
    import socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((name, 0)); s.settimeout(0.5)
    while not stop.is_set():
        try:
            data = s.recv(65535)
        except socket.timeout:
            continue
        yield time.time(), 1, data, len(data)


def local_addresses():
    """This machine's own IP addresses (labels them 'this laptop' in alerts)."""
    import socket
    ips = set()
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(sa[0].split("%")[0])
    except OSError:
        pass
    for target in ("192.0.2.1", "2001:db8::1"):              # route lookup only; nothing is sent
        try:
            fam = socket.AF_INET6 if ":" in target else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((target, 9)); ips.add(s.getsockname()[0].split("%")[0])
        except OSError:
            pass
    return {i for i in ips if not i.startswith(("127.", "::1", "fe80"))}
