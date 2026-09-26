"""lpa command line.

  lpa                                            live capture of this laptop (the default; same as 'lpa live')
  lpa analyse capture.pcapng [more.pcap ...]     analyse Wireshark / tcpdump / pktmon dumps (add --replay 1 to play back in real time)
  lpa live                                       Windows: pktmon; raises a UAC prompt and continues elevated if needed
  lpa live --source stdin                        read a live pcap stream: dumpcap -i Wi-Fi -w - | lpa live --source stdin
  lpa live --source follow:C:\\cap\\ring.pcapng    analyse a capture file while another tool writes it
  lpa synth demo.pcap                            write a synthetic capture with benign traffic plus one example of each attack
  lpa laya-check                                 check the local Laya server and time one triage question
"""
import argparse, os, sys, threading, time, webbrowser

from . import __version__
from .capture import Pktmon, from_files, from_follow, from_iface, from_stdin, is_admin, local_addresses
from .engine import Engine
from .laya import LayaClient, Pipeline
from .model import SEVERITIES
from .netutil import human_bytes
from .outputs import Console, JsonLines


def build(args, source_desc, live):
    client = None
    if not args.no_laya:
        client = LayaClient(args.laya_url, timeout=args.laya_timeout)
        info = client.health()
        if info:
            print(f"[lpa] Laya server {client.url} ({client.stats.backend or info.get('device')}) - alerts will be triaged by Laya")
        else:
            print("[lpa] WARNING: no Laya server answered on " + ", ".join(client.urls) +
                  "\n      alerts are heuristic-only until one is up (start it with: local-laya/bin/serve start npu)")
    outputs = [] if args.quiet else [Console(SEVERITIES.index(args.min_severity))]
    if args.jsonl:
        outputs.append(JsonLines(args.jsonl))
    pipe = Pipeline(client, outputs)
    local = set(args.local or [])
    if live and not args.local:
        local |= local_addresses()
    from .detectors import all_detectors
    dets = all_detectors(); reviewer = None
    if client and not args.no_review:
        from .review import ConversationTracker, Reviewer
        holder = {}
        reviewer = Reviewer(client, lambda: holder.get("eng"), flag_at=args.flag_at, ptr=not args.no_ptr)
        dets.append(ConversationTracker(reviewer))
    eng = Engine(pipe, local_ips=local, detectors=dets, dedupe=(live and getattr(args, "source", "") == "pktmon"))
    eng.reviewer = reviewer
    if reviewer:
        holder["eng"] = eng
        print(f"[lpa] Laya reviews every conversation and local device (alert at p >= {args.flag_at}, or >= 0.70 corroborated)")
    sampler = dash = None
    if not args.no_gui:
        from .dashboard import Dashboard, Sampler
        sampler = Sampler(eng, pipe, source=source_desc)
        dash = None
        for port in range(args.port, args.port + 10):          # another instance may hold the default port
            try:
                dash = Dashboard(sampler, port=port); break
            except OSError as e:
                err = e
        try:
            if dash is None:
                raise err
            print(f"[lpa] dashboard: {dash.url}")
            if live:
                write_status(dash.url)
            if not args.no_browser:
                threading.Timer(0.8, lambda: webbrowser.open(dash.url)).start()
        except OSError as e:
            print(f"[lpa] dashboard could not start on port {args.port}: {e}")
    return eng, pipe, sampler, dash


def run_stream(eng, pipe, sampler, packets, live, stop):
    t0 = time.time(); last_status = t0; n = 0
    if sampler:
        sampler.status = "live" if live else "analysing"
    try:
        for ts, lt, data, wl in packets:
            try:
                eng.feed(ts, lt, data, wl)
            except Exception as e:                     # one odd packet must never end a live capture
                eng.m.errors += 1
                if eng.m.errors <= 5 or eng.m.errors % 1000 == 0:
                    import traceback
                    eng.m.note(f"packet error #{eng.m.errors}: {e!r} at {traceback.format_exc(limit=-2).strip()[-240:]}")
            n += 1
            if stop.is_set():
                break
            if live and time.time() - last_status >= 30:
                last_status = time.time(); status(eng, pipe, t0)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[lpa] capture error: {e}"); eng.m.note(f"capture stopped: {e!r}")
        if sampler:
            sampler.status = "error"
    if sampler and sampler.status != "error":
        sampler.status = "stopped" if live else "finished"
    eng.m.note("capture ended")
    eng.finish()
    if getattr(eng, "reviewer", None):
        eng.reviewer.drain(timeout=300)
    pipe.drain(timeout=120)
    return time.time() - t0


def status(eng, pipe, t0):
    m = eng.m; s = pipe.stats.snapshot(); sev = pipe.severity_counts()
    print(f"[lpa] {m.packets:,} packets ({m.packets / max(time.time() - t0, 1e-3):,.0f}/s) · {m.flows_active} active flows · "
          f"alerts " + " ".join(f"{k}={v}" for k, v in sev.items() if v) +
          f" · Laya {s['calls']} calls, avg {s['avg_ms'] or 0:.0f} ms", flush=True)


def summary(eng, pipe, wall):
    m = eng.m; s = pipe.stats.snapshot(); sev = pipe.severity_counts()
    span = (m.cap_last - m.cap_first) if m.cap_first is not None else 0
    print("\n" + "=" * 78)
    print(f"Packets: {m.packets:,} ({human_bytes(m.bytes)}), capture span {span:.0f} s, analysed in {wall:.1f} s "
          f"({m.packets / max(wall, 1e-3):,.0f} packets/s)")
    if m.duplicates or m.undecoded:
        print(f"Dropped as duplicates: {m.duplicates:,}   undecoded by link type: {dict(m.undecoded)}")
    print(f"Flows: {m.flows_total:,}   Alerts: " + ", ".join(f"{v} {k}" for k, v in sev.items() if v) if any(sev.values())
          else f"Flows: {m.flows_total:,}   Alerts: none")
    if pipe.client:
        print(f"Laya: {s['calls']} calls, avg {s['avg_ms'] or 0:.0f} ms (p95 {s['p95_ms'] or 0:.0f} ms) on {s['backend']}; "
              f"raised {s['upgraded']}, lowered {s['downgraded']}, errors {s['errors']}")
    with pipe.lock:
        top = sorted(pipe.alerts, key=lambda a: (-a.final, a.id))[:12]
    if top:
        print("Top findings:")
        for a in top:
            l = a.laya or {}
            lv = f" [Laya {l.get('verdict')} {l.get('p_malicious', 0):.2f}]" if l.get("mode") in ("triage", "domain", "review") else ""
            print(f"  {SEVERITIES[a.final].upper():8s} {a.title}{f' x{a.count}' if a.count > 1 else ''} - {a.src or ''}"
                  f"{' -> ' + str(a.dst) if a.dst else ''}{lv}")
    print("=" * 78)


def keep_open(dash, sampler, stop):
    if not dash:
        return
    sampler.status = "finished"
    print(f"[lpa] analysis finished; dashboard still at {dash.url} - press Ctrl+C to exit")
    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass


def cmd_analyse(args):
    for f in args.files:
        if not os.path.exists(f):
            sys.exit(f"no such file: {f}")
    desc = "file: " + ", ".join(os.path.basename(f) for f in args.files) + (f" (replay x{args.replay})" if args.replay else "")
    eng, pipe, sampler, dash = build(args, desc, live=False)
    stop = threading.Event()
    wall = run_stream(eng, pipe, sampler, from_files(args.files, args.replay, stop), False, stop)
    summary(eng, pipe, wall)
    if not stop.is_set() and not args.exit:
        keep_open(dash, sampler, stop)


STATUS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "live.json")


def write_status(url):
    """Tell a non-elevated launcher which instance is live (it cannot see elevated processes' command lines)."""
    import json
    try:
        with open(STATUS_FILE, "w") as f:
            json.dump({"pid": os.getpid(), "url": url, "started": time.time()}, f)
    except OSError:
        pass


def read_status():
    import json
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def relaunch_elevated(args):
    """Re-run this command through lpa.cmd with the UAC 'runas' verb (a new console window). True if launched.
    The browser is opened from this non-elevated process so it never runs as Administrator."""
    cmd = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lpa.cmd")
    if not os.path.exists(cmd):
        return False
    import ctypes, subprocess
    user_args = [a for a in sys.argv[1:] if a != "live"]
    params = subprocess.list2cmdline(["live", *user_args, "--pause-on-exit", "--no-browser"])
    prev = read_status()
    if prev:
        print(f"[lpa] note: an analyser started at {time.strftime('%H:%M:%S', time.localtime(prev['started']))} "
              f"(pid {prev['pid']}) may still be running - close its window if so")
    launched = time.time()
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", cmd, params, os.path.dirname(cmd), 1)
    if rc <= 32:                                     # <= 32 is an error, e.g. the UAC prompt was declined
        return False
    if not (args.no_gui or args.no_browser):
        for _ in range(240):                         # wait up to 2 minutes for *this* elevated instance to report in
            st = read_status()
            if st and st.get("started", 0) >= launched:
                webbrowser.open(st["url"]); print(f"[lpa] dashboard: {st['url']} (pid {st['pid']})"); break
            time.sleep(0.5)
        else:
            print("[lpa] the elevated analyser did not report in within 2 minutes - check its window")
    return True


def cmd_live(args):
    stop = threading.Event()
    src = args.source
    if src == "pktmon":
        if os.name != "nt":
            sys.exit("pktmon is Windows only; on Linux use --source iface:eth0 (root) or --source stdin")
        if not is_admin():
            if args.no_elevate or not relaunch_elevated(args):
                sys.exit("Live capture with pktmon needs Administrator rights.\n"
                         "Open 'Terminal (Admin)' / PowerShell as Administrator and run:  lpa.cmd")
            print("[lpa] live capture is running in the elevated window (close it or press Ctrl+C there to stop)")
            return
        logbox = {}
        def pmlog(msg):
            print(msg)
            if "eng" in logbox:
                logbox["eng"].m.note(msg)
        pm = Pktmon(args.slice, workdir=args.keep_slices, log=pmlog, keep=bool(args.keep_slices))
        packets = pm.packets(); desc = f"live: Windows pktmon ({args.slice:g} s slices)"
    elif src == "stdin":
        packets = from_stdin(); desc = "live: pcap stream on stdin"
    elif src.startswith("follow:"):
        packets = from_follow(src[7:], stop); desc = "live: following " + os.path.basename(src[7:])
    elif src.startswith("iface:"):
        packets = from_iface(src[6:], stop); desc = "live: interface " + src[6:]
    else:
        sys.exit(f"unknown source {src!r}")
    eng, pipe, sampler, dash = build(args, desc, live=True)
    if src == "pktmon":
        logbox["eng"] = eng
    print(f"[lpa] {desc}; this machine: {', '.join(sorted(eng.local_ips)) or 'unknown'}; Ctrl+C to stop")
    try:
        wall = run_stream(eng, pipe, sampler, packets, True, stop)
    finally:
        stop.set()
        if src == "pktmon":
            pm.stop()
    summary(eng, pipe, wall)
    if args.pause_on_exit:
        input("capture stopped - press Enter to close this window")


def cmd_synth(args):
    from .synth import write_demo
    n = write_demo(args.out, seed=args.seed)
    print(f"wrote {n} packets to {args.out}")


def cmd_laya_check(args):
    c = LayaClient(args.laya_url)
    info = c.health()
    if not info:
        sys.exit("no Laya server reachable on " + ", ".join(c.urls))
    print(f"Laya at {c.url}: {info}")
    from .laya import judge
    from .model import Alert
    a = Alert(time.time(), "check", "command_and_control", 2, "Periodic beaconing",
              "192.168.1.20 (this laptop) contacted 185.220.101.4 (internet, no domain name seen) on TCP port 4444 48 times at a "
              "regular interval of 30.0 seconds (jitter 1%), about 220 B per contact; no DNS lookup was seen for this address.")
    for i in range(3):
        res, final = judge(c, a)
        print(f"  try {i + 1}: verdict={res['verdict']} p_threat={res['p_malicious']:.2f} category={res['category']} "
              f"severity medium -> {SEVERITIES[final]}  {res['ms']:.0f} ms")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lpa", description="Laya packet analyser - security findings from packets, triaged by a local Laya model.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--laya-url", help="Laya server base URL (default: first of :8002 npu, :8001 gpu, :8004, :8000 cpu)")
        p.add_argument("--laya-timeout", type=float, default=10.0)
        p.add_argument("--no-laya", action="store_true", help="heuristics only")
        p.add_argument("--no-review", action="store_true", help="Laya triages alerts only; do not review every conversation")
        p.add_argument("--flag-at", type=float, default=0.90, help="p(threat) at which a Laya review alone raises an alert "
                                                                     "(0.70 when corroborated by payload / port / ICMP data)")
        p.add_argument("--no-ptr", action="store_true", help="no reverse-DNS lookups to name unnamed remote hosts for Laya")
        p.add_argument("--local", action="append", metavar="IP", help="this laptop's IP (repeatable; auto-detected when live)")
        p.add_argument("--min-severity", default="low", choices=SEVERITIES, help="console threshold (default low)")
        p.add_argument("--jsonl", metavar="PATH", help="append every alert as JSON to this file")
        p.add_argument("--quiet", action="store_true", help="no console alerts")
        p.add_argument("--no-gui", action="store_true", help="do not start the dashboard")
        p.add_argument("--no-browser", action="store_true", help="start the dashboard but do not open a browser")
        p.add_argument("--port", type=int, default=8765, help="dashboard port on 127.0.0.1 (default 8765)")

    p = sub.add_parser("analyse", aliases=["analyze"], help="analyse pcap / pcapng files")
    p.add_argument("files", nargs="+"); common(p)
    p.add_argument("--replay", type=float, metavar="SPEED", help="play the capture back at SPEED x real time (e.g. 1, 10)")
    p.add_argument("--exit", action="store_true", help="exit when done instead of keeping the dashboard open")
    p.set_defaults(fn=cmd_analyse)

    p = sub.add_parser("live", help="analyse live traffic")
    p.add_argument("--source", default="pktmon", help="pktmon | stdin | follow:PATH | iface:NAME (default pktmon)")
    p.add_argument("--slice", type=float, default=3.0, help="pktmon slice length in seconds (latency vs overhead)")
    p.add_argument("--keep-slices", metavar="DIR", help="keep pktmon's converted pcapng slices in DIR (diagnostics)")
    p.add_argument("--no-elevate", action="store_true", help="do not raise a UAC prompt when not running as Administrator")
    p.add_argument("--pause-on-exit", action="store_true", help=argparse.SUPPRESS)
    common(p); p.set_defaults(fn=cmd_live)

    p = sub.add_parser("synth", help="write a synthetic demo capture")
    p.add_argument("out"); p.add_argument("--seed", type=int, default=7); p.set_defaults(fn=cmd_synth)

    p = sub.add_parser("laya-check", help="check the Laya server")
    p.add_argument("--laya-url"); p.set_defaults(fn=cmd_laya_check)

    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or (argv[0] not in sub.choices and argv[0] not in ("-h", "--help", "--version")):
        argv = ["live", *argv]                       # live capture is the default command
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(line_buffering=True)          # alerts appear promptly even when piped / redirected
    except (AttributeError, ValueError):
        pass
    args.fn(args)


if __name__ == "__main__":
    main()
