"""Evaluate Laya's continuous conversation/device review.

  labelled: samples/demo.pcap (synthetic; threats known by remote address)      -> AUC per prompt variant
  real:     any extra pcap/pcapng of your own traffic (assumed benign)           -> how often each variant would flag it
Run on Windows (Laya is on Windows loopback):  python tools/laya_flow_eval.py samples\\demo.pcap [real.pcapng ...]
"""
import argparse, os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lpa.engine import Engine  # noqa: E402
from lpa.laya import LayaClient  # noqa: E402
from lpa.pcapio import read_packets  # noqa: E402
from lpa.review import (CONV_Q, DEVICE_Q, FLAG_AT, FLAG_CORROBORATED, ConversationTracker,  # noqa: E402
                        corroboration)

THREAT_REMOTES = {"185.220.101.4", "91.92.240.11", "45.83.64.1", "203.0.113.66", "104.21.3.7", "203.0.113.50",
                  "45.137.21.9", "194.55.186.30", "203.0.113.120", "51.15.69.136"}
AMBIGUOUS = {"93.184.216.34", "198.51.100.21", "198.51.100.7", "198.51.100.9", "192.168.1.1", "192.168.1.66"}
THREAT_DEVICES = {"192.168.1.44"}

Q_ALT = {"type": "noul", "instructions": "Is this network conversation malicious: malware, a backdoor or remote shell, a botnet, "
                                         "a crypto-miner, scanning, exploitation or data theft?",
         "criteria": {"true": "malicious", "false": "normal use of the internet or the local network"}}


class Collect:
    def __init__(self):
        self.items = []

    def offer(self, item):
        self.items.append(item)


class Null:
    def submit(self, a):
        pass

    def update(self, a):
        pass


def items_from(path):
    col = Collect(); eng = Engine(Null(), detectors=[ConversationTracker(col)])
    with open(path, "rb") as f:
        for pk in read_packets(f):
            eng.feed(*pk)
    eng.finish()
    return col.items


def label(it):
    if it["kind"] == "device":
        return 1 if it["local"] in THREAT_DEVICES else 0
    if it["remote"] in AMBIGUOUS:
        return None
    return 1 if it["remote"] in THREAT_REMOTES else 0


def auc(pairs):
    pos = [s for l, s in pairs if l == 1]; neg = [s for l, s in pairs if l == 0]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / max(1, len(pos) * len(neg))


def variants(it):
    st = it["state"]
    if it["kind"] == "device":
        return {"shipped": (st, {"threat": DEVICE_Q})}
    merged = {"traffic": st["traffic"] + (" Payload: " + st["payload"] if st.get("payload") else "")}
    prose = merged["traffic"]
    return {"shipped": (st, {"threat": CONV_Q}), "merged": (merged, {"threat": CONV_Q}),
            "alt_q": (st, {"threat": Q_ALT}), "prose_alt": (prose, {"threat": Q_ALT})}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("labelled"); ap.add_argument("real", nargs="*")
    ap.add_argument("--url", default=None); ap.add_argument("--show", type=int, default=40); a = ap.parse_args()
    c = LayaClient(a.url); c.health(); t0 = time.time()
    lab_items = [(label(it), it) for it in items_from(a.labelled)]
    lab_items = [(l, it) for l, it in lab_items if l is not None]
    scores = {}
    print(f"labelled items: {len(lab_items)} ({sum(l for l, _ in lab_items)} threats)")
    rows = []; rows_all = []
    for l, it in lab_items:
        for v, (state, qs) in variants(it).items():
            p = c.ask(state, qs)[0]["threat"]["noul"]
            scores.setdefault(v, []).append((l, p))
            if v == "alt_q":
                rows.append((p, l, it))
            if v == "shipped":
                rows_all.append((p, l, it))
    for p, l, it in sorted(rows, key=lambda r: -r[0])[:a.show]:
        print(f"  {'THREAT' if l else 'benign'} p={p:.2f}  {(it['state'].get('traffic') or it['state'].get('device'))[:120]}")
    print("\nAUC on labelled synthetic traffic:")
    for v, pairs in scores.items():
        n1 = [p for l, p in pairs if l == 1]; n0 = [p for l, p in pairs if l == 0]
        print(f"  {v:10s} AUC={auc(pairs):.3f}  threats flagged@0.8 {sum(p >= .8 for p in n1)}/{len(n1)}  "
              f"benign flagged@0.8 {sum(p >= .8 for p in n0)}/{len(n0)}  @0.9 {sum(p >= .9 for p in n1)}/{len(n1)} vs {sum(p >= .9 for p in n0)}/{len(n0)}")
    def flags(p, it):
        return not it["known"] and (p >= FLAG_AT or (p >= FLAG_CORROBORATED and bool(corroboration(it))))
    sh = [(l, p, it) for (p, l, it) in rows_all]
    print(f"\nSHIPPED RULE on synthetic: threats alerted {sum(flags(p, it) for l, p, it in sh if l)}/{sum(l for l, _, _ in sh)}, "
          f"benign alerted {sum(flags(p, it) for l, p, it in sh if not l)}/{sum(1 - l for l, _, _ in sh)}")
    for l, p, it in sh:
        if flags(p, it):
            print(f"   alert ({'THREAT' if l else 'benign'}) p={p:.2f} {corroboration(it)} {(it['state'].get('traffic') or it['state'].get('device'))[:100]}")
    print("\nthreshold sweep (synthetic threats caught vs synthetic benign flagged):")
    for v, pairs in scores.items():
        n1 = sorted(p for l, p in pairs if l == 1); n0 = sorted(p for l, p in pairs if l == 0)
        cells = [f"{t:.2f}:{sum(p >= t for p in n1)}/{sum(p >= t for p in n0)}" for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8)]
        print(f"  {v:10s} " + "  ".join(cells))
    for path in a.real:
        its = items_from(path); real = {}
        for it in its:
            for v, (state, qs) in variants(it).items():
                real.setdefault(v, []).append((c.ask(state, qs)[0]["threat"]["noul"], it))
        print(f"\nreal traffic {os.path.basename(path)}: {len(its)} items")
        for v, ps in real.items():
            print(f"  {v:10s} " + "  ".join(f"{t:.2f}:{sum(p >= t for p, _ in ps)}/{len(ps)}" for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8)))
        al = [(p, it) for p, it in real["shipped"] if flags(p, it)]
        print(f"  SHIPPED RULE on real traffic: {len(al)}/{len(real['shipped'])} conversations would alert")
        for p, it in al:
            print(f"   alert p={p:.2f} {corroboration(it)} {(it['state'].get('traffic') or it['state'].get('device'))[:110]}")
        for p, it in sorted(real["shipped"], key=lambda r: -r[0])[:6]:
            print(f"    p={p:.2f}  {(it['state'].get('traffic') or it['state'].get('device'))[:130]}")
    s = c.stats.snapshot()
    print(f"\n{s['calls']} Laya calls, avg {s['avg_ms']} ms, {time.time() - t0:.0f} s")


if __name__ == "__main__":
    main()
