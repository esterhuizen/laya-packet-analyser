"""Evaluate Laya triage prompt variants on labelled detector-style stories (1 = real threat, 0 = benign look-alike).

  python tools/laya_eval.py [--url http://127.0.0.1:8002]      (on the machine running Laya)
Prints AUC and accuracy of each state/question framing so the production prompt is chosen on evidence.
"""
import argparse, json, os, sys, time, urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lpa.model import CATEGORIES  # noqa: E402

CASES = [
 (1, "Periodic beaconing", "192.168.1.20 (this laptop) contacted 185.220.101.4 (internet, no domain name seen) on TCP port 4444 (tcp/4444) 20 times at a regular interval of 30.0 seconds (jitter 1%), about 514 B per contact; no DNS lookup was seen for this address."),
 (0, "Periodic beaconing", "192.168.1.20 (this laptop) contacted 52.113.194.132 (teams.microsoft.com, Teams) on TCP port 443 (HTTPS) 14 times at a regular interval of 60.2 seconds (jitter 9%), about 2.4 kB per contact."),
 (1, "Periodic beaconing", "192.168.1.20 (this laptop) contacted 91.92.240.11 (internet, no domain name seen) on TCP port 443 (HTTPS) 12 times at a regular interval of 44.9 seconds (jitter 0%), about 580 B per contact; no DNS lookup was seen for this address."),
 (0, "Periodic beaconing", "192.168.1.20 (this laptop) contacted 17.57.146.20 (api.push.apple.com, Apple) on TCP port 5223 (tcp/5223) 11 times at a regular interval of 300.0 seconds (jitter 2%), about 300 B per contact."),
 (1, "Port scan", "192.168.1.20 (this laptop) sent TCP connection attempts to 300 different ports on 192.168.1.1 (default gateway) within 60 seconds (ports 1, 2, 3, 4, 5, 6, 7, 8 ... 300); 290 attempts were refused with a reset."),
 (1, "Inbound port scan from the internet", "The internet host 45.83.64.1 (internet, no domain name seen) sent TCP connection attempts to 12 different ports on 192.168.1.20 (this laptop) within 60 seconds (ports 21, 22, 23, 25, 80, 135, 139, 443 ... 8080)."),
 (1, "DNS tunnelling / data exfiltration over DNS", "192.168.1.20 (this laptop) queried 25 different subdomains of evil-tunnel.xyz within 2 minutes; the subdomain labels average 52 characters with 4.9 bits/char entropy (looks like encoded data), 25 were TXT/NULL queries. Example: mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpjqwe.x1.t.evil-tunnel.xyz"),
 (0, "Unusual spike in DNS queries", "192.168.1.20 (this laptop) had 180 DNS queries in 10 seconds, versus a normal level of about 20 (z-score 6)."),
 (1, "Burst of failed DNS lookups (possible DGA malware)", "192.168.1.20 (this laptop) looked up 15 different domain names that do not exist within 60 seconds, e.g. cfmgfxzwqpjzfv.info, dskfxhwmkqjbfqd.top, fzsdhssktvtvfdgr.biz. Malware with a domain generation algorithm does this to find its server."),
 (1, "Password submitted over unencrypted HTTP", "192.168.1.20 (this laptop) submitted a form containing a password/secret field to http://paypa1-secure-login.com/signin over unencrypted HTTP."),
 (1, "Credentials sent over unencrypted HTTP (basic)", "192.168.1.20 (this laptop) sent an HTTP Authorization basic header for user 'admin' to http://example.com/admin over unencrypted HTTP; the password or token can be captured."),
 (1, "Cleartext FTP login", "192.168.1.20 (this laptop) sent a FTP USER command for user 'backup' to 198.51.100.21 (internet, no domain name seen) without encryption, so the password can be read by anyone on the path."),
 (1, "Suspicious download over HTTP", "192.168.1.20 (this laptop) requested http://91.92.240.11/payload.exe using user-agent 'WindowsPowerShell/5.1' from a bare IP address with no domain name; scripts and executables fetched this way are a common malware delivery step."),
 (0, "Suspicious download over HTTP", "192.168.1.20 (this laptop) requested http://download.windowsupdate.com/c/msdownload/update/software/defu/2026/09/am_delta.exe using user-agent 'Microsoft BITS/7.8'."),
 (1, "Executable downloaded over unencrypted HTTP", "192.168.1.20 (this laptop) downloaded an executable file (PE) from 91.92.240.11 (internet, no domain name seen) port 80 over unencrypted HTTP, so it could have been tampered with or come from a malicious server."),
 (1, "Gateway MAC address changed (ARP spoofing)", "The MAC address for 192.168.1.1 (default gateway) changed from aa:bb:cc:00:11:22 to de:ad:be:ef:00:01 - this is the default gateway, so all internet traffic may now pass through another device."),
 (0, "IP address changed MAC (possible ARP spoofing)", "The MAC address for 192.168.1.37 (local network) changed from 3a:11:9c:40:02:7e to 3a:11:9c:40:02:7f."),
 (1, "Multiple DHCP servers (rogue DHCP)", "2 different DHCP servers answered on this network (192.168.1.1, 192.168.1.66); a rogue DHCP server can hand out a malicious gateway or DNS server."),
 (1, "Large one-way upload", "192.168.1.20 (this laptop) uploaded 2.1 GB to 104.21.3.7 (internet, no domain name seen) port 443 in 9.5 minutes (3.7 MB/s) while receiving only 4.1 MB."),
 (0, "Large one-way upload", "192.168.1.20 (this laptop) uploaded 820 MB to 13.107.42.12 (my.microsoftpersonalcontent.com, OneDrive) port 443 in 10.2 minutes (1.3 MB/s) while receiving only 6.0 MB."),
 (0, "Unusual spike in bytes downloaded", "192.168.1.20 (this laptop) had 480 MB bytes downloaded in 10 seconds, versus a normal level of about 2 MB (z-score 30)."),
 (0, "Unusual spike in new connections", "192.168.1.20 (this laptop) had 240 new connections in 10 seconds, versus a normal level of about 25 (z-score 7)."),
 (1, "Possible ICMP tunnel", "15 ping packets with large, varying payloads (348-913 bytes) between 192.168.1.20 (this laptop) and 203.0.113.50 (internet, no domain name seen) within 60 seconds; normal pings are small and uniform."),
 (0, "Outdated TLS 1.0 connection", "192.168.1.20 (this laptop) negotiated TLS 1.0 with 192.168.1.50 (local network) port 443; this protocol version is deprecated and has known weaknesses."),
 (1, "Connection to suspicious port 4444", "192.168.1.20 (this laptop) opened a TCP connection to 185.220.101.4 (internet, no domain name seen) on port 4444, a port commonly associated with Metasploit default."),
 (0, "Connection to suspicious port 5900", "192.168.1.20 (this laptop) opened a TCP connection to 20.84.10.3 (remote-support.teamviewer.com) on port 5900, a port commonly associated with VNC."),
 (0, "Host sweep on SSDP", "192.168.1.20 (this laptop) tried UPnP (port 1900) on 16 different hosts within 60 seconds, 0 of them refused."),
 (0, "Unencrypted web traffic", "192.168.1.20 (this laptop) browsed http://neverssl.com/ over plain HTTP (not HTTPS)."),
 (1, "Inbound connection accepted from the internet on port 3389", "192.168.1.20 (this laptop) accepted a TCP connection on port 3389 (RDP) from the internet host 45.83.64.1 (internet, no domain name seen): a service on this machine is reachable from the internet."),
 (0, "Port scan", "192.168.1.20 (this laptop) sent UDP connection attempts to 22 different ports on 142.250.70.100 (www.google.com, Google) within 60 seconds (ports 49152, 49153 ... 65000); 0 attempts were refused with a reset."),
]

VERDICT = {"type": "choice", "instructions": "What is your verdict on this network activity seen on a laptop?",
           "criteria": {"benign": "normal expected activity of a known service", "suspicious": "unusual, could be malicious, worth investigating",
                        "malicious": "clear attack, malware, or data theft"}}
VERDICT2 = {"type": "choice", "instructions": "A security analyst reviews this alert from a laptop's network monitor. What should they conclude?",
            "criteria": {"false_positive": "harmless: a known company's service, the user's normal activity, or routine network housekeeping",
                         "investigate": "unusual and possibly malicious, needs a closer look",
                         "true_threat": "an attack, malware, data theft or exposed secret that needs action now"}}
ALERT = {"type": "noul", "instructions": "Should the laptop owner be alerted because this looks like an attack, malware, data theft or exposed password?"}
BENIGN = {"type": "noul", "instructions": "Is this activity caused by a well-known legitimate service or normal user behaviour?"}
SEV = {"type": "score", "instructions": "How dangerous is this network activity for the laptop owner?",
       "criteria": ["harmless normal traffic", "minor or informational", "suspicious, worth checking", "likely attack or compromise", "active attack or data theft"]}


THREAT_TF = {"type": "noul", "instructions": "Does `evidence` describe an attack, malware, data theft or an exposed password on the laptop's network?",
             "criteria": {"true": "a real security threat", "false": "ordinary traffic of the user or a legitimate service"}}
LEGIT_TF = {"type": "noul", "instructions": "Is the other party in `evidence` a well-known legitimate company or service?",
            "criteria": {"true": "a well-known company, cloud or software service", "false": "unknown, unnamed or suspicious host"}}
RISK_SC = {"type": "score", "instructions": "How much risk does `evidence` show for the laptop owner?",
           "criteria": ["none: routine traffic", "minor: worth knowing", "serious: likely attack or leak", "severe: active compromise or stolen data"]}
VERDICT3 = {"type": "choice", "instructions": "What does `evidence` show?",
            "criteria": {"routine": "routine traffic of the user, the operating system or a well-known service",
                         "risky": "insecure practice or unusual behaviour without clear malice",
                         "attack": "an attack, malware, data theft or a leaked password"}}


def ask(url, state, qs):
    body = json.dumps({"model": "english", "state": state, "questions": qs}).encode()
    with urllib.request.urlopen(urllib.request.Request(url + "/v1/systemone", body, {"Content-Type": "application/json"}), timeout=30) as r:
        return json.load(r)["answers"]


def auc(pairs):
    pos = [s for l, s in pairs if l]; neg = [s for l, s in pairs if not l]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--url", default="http://127.0.0.1:8002")
    ap.add_argument("--production", action="store_true", help="only evaluate the shipped judge()"); a = ap.parse_args()
    if a.production:
        return production(a.url)
    states = {"title+story": lambda t, s: {"alert": t, "evidence": s},
              "prefixed": lambda t, s: f"Network monitor alert '{t}': {s}",
              "fields": lambda t, s: {"alert": t, "evidence": s}}
    qs = {"verdict": (VERDICT, lambda x: 1 - x["probabilities"]["benign"]),
          "verdict_pmal": (VERDICT, lambda x: x["probabilities"]["malicious"]),
          "verdict2": (VERDICT2, lambda x: 1 - x["probabilities"]["false_positive"]),
          "alert": (ALERT, lambda x: x["noul"]), "benign": (BENIGN, lambda x: 1 - x["noul"]), "sev": (SEV, lambda x: x["score"]),
          "threat_tf": (THREAT_TF, lambda x: x["noul"]), "legit_tf": (LEGIT_TF, lambda x: 1 - x["noul"]),
          "risk": (RISK_SC, lambda x: x["score"]), "verdict3": (VERDICT3, lambda x: x["probabilities"]["attack"]),
          "verdict3_nr": (VERDICT3, lambda x: 1 - x["probabilities"]["routine"])}
    t0 = time.time(); results = {}
    for sname, sf in states.items():
        answers = [(lab, ask(a.url, sf(t, s), {k: v for k, (v, _) in qs.items() if k not in ("verdict_pmal", "verdict3_nr")})) for lab, t, s in CASES]
        for qname, (q, score) in qs.items():
            key = {"verdict_pmal": "verdict", "verdict3_nr": "verdict3"}.get(qname, qname)
            pairs = [(lab, score(ans[key])) for lab, ans in answers]
            results[(sname, qname)] = auc(pairs)
        if sname == "fields":
            print("per-case (story / verdict):")
            for (lab, t, _), (_, ans) in zip(CASES, answers):
                v = ans["verdict"]; print(f"  {lab} {v['choice']:10s} pB={v['probabilities']['benign']:.2f} pM={v['probabilities']['malicious']:.2f}  "
                                          f"v3={ans['verdict3']['choice']:8s} thr={ans['threat_tf']['noul']:.2f} legit={ans['legit_tf']['noul']:.2f} risk={ans['risk']['score']:.2f}  {t[:44]}")
    print("\nAUC (1.0 = perfect ranking of threats above benign look-alikes):")
    for (s, q), v in sorted(results.items(), key=lambda kv: -kv[1]):
        print(f"  {v:.3f}  state={s:12s} question={q}")
    print(f"{len(CASES)} cases, {time.time() - t0:.0f} s")



def production(url):
    """How the shipped judge() treats each labelled case."""
    from lpa.laya import LayaClient, judge
    from lpa.model import Alert, SEVERITIES
    c = LayaClient(url); c.health(); rows = []
    for lab, t, s in CASES:
        res, final = judge(c, Alert(0, "eval", "benign", 2, t, s))
        rows.append((lab, res["adjust"])); print(f"  {'THREAT ' if lab else 'benign '} {res['verdict']:10s} p={res['p_malicious']:.2f} {res['category']:20s} {t[:50]}")
    for lab in (1, 0):
        adj = [a for l, a in rows if l == lab]
        print(f"{'threats' if lab else 'benign '}: raised {adj.count(1)}, kept {adj.count(0)}, lowered {adj.count(-1)} of {len(adj)}")


if __name__ == "__main__":
    main()
