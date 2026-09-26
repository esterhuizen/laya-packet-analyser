"""Deterministic detectors. Each turns packet/flow evidence into Alerts with a plain-English 'story' that Laya triages.

Severity scale: 0 info, 1 low, 2 medium, 3 high, 4 critical (heuristic; Laya may move it one level either way).
"""
import base64, math, re, statistics
from collections import Counter, defaultdict, deque

from . import decode as D
from .netutil import (DYNDNS, SUSPICIOUS_PORTS, dga_score, entropy, human_bytes, ip_class, is_public, known_service,
                      lookalike, registrable, svc_port)

QUIET_PORTS = {53, 123, 5353, 5355, 1900, 137, 138, 67, 68, 3702, 443, 80}


class Detector:
    name = "base"

    def on_packet(self, p, flow, eng):
        pass

    def on_flow_end(self, f, eng):
        pass

    def tick(self, now, eng, final=False):
        pass


class Window:
    """{key: {item: last_ts}} with time-based pruning."""
    def __init__(self, span):
        self.span = span; self.d = defaultdict(dict)

    def add(self, key, item, ts):
        self.d[key][item] = ts

    def items(self, key, now):
        s = self.d.get(key)
        if not s:
            return {}
        old = [i for i, t in s.items() if now - t > self.span]
        for i in old:
            del s[i]
        if not s:
            del self.d[key]
        return s

    def prune(self, now):
        for k in list(self.d):
            self.items(k, now)


# ---------------------------------------------------------------------------------------------- scanning
class PortScan(Detector):
    name = "port-scan"

    def __init__(self, vertical=20, sweep=15, inbound=8, span=60):
        self.vert = Window(span); self.sweep = Window(span); self.inb = Window(span); self.fail = Window(span)
        self.icmp = Window(span)
        self.tv, self.ts_, self.ti = vertical, sweep, inbound

    def on_packet(self, p, flow, eng):
        if not p.ipv or p.src == p.dst:
            return
        if p.proto == D.TCP:
            if p.flags & D.SYN and not p.flags & D.ACK:
                self._probe(p, eng)
            elif p.flags & D.RST and eng.is_inside(p.dst):
                self.fail.add(p.dst, (p.src, p.sport), p.ts)
        elif p.proto == D.UDP and p.dport not in QUIET_PORTS and p.sport not in QUIET_PORTS and ip_class(p.dst) in ("private", "public"):
            if flow is not None and flow.client == p.src and flow.pc == 1:
                self._probe(p, eng)
        elif p.proto in (D.ICMP, D.ICMP6) and p.icmp and p.icmp[0] in (8, 128) and ip_class(p.dst) == "private":
            self.icmp.add(p.src, p.dst, p.ts)
            hosts = self.icmp.items(p.src, p.ts)
            if len(hosts) >= self.ts_:
                eng.emit(p.ts, self.name, "reconnaissance", 2, "Ping sweep of local network",
                         f"{eng.label(p.src)} sent ICMP echo (ping) to {len(hosts)} different local addresses within 60 seconds, "
                         f"e.g. {', '.join(sorted(hosts)[:5])}.", p.src, None, key=(self.name, "ping", p.src),
                         evidence={"hosts": len(hosts)})

    def _probe(self, p, eng):
        proto = "TCP" if p.proto == D.TCP else "UDP"
        inbound = is_public(p.src) and eng.is_inside(p.dst)
        if inbound:
            self.inb.add((p.src, p.dst), p.dport, p.ts)
            ports = self.inb.items((p.src, p.dst), p.ts)
            if len(ports) >= self.ti:
                eng.emit(p.ts, self.name, "reconnaissance", 3, "Inbound port scan from the internet",
                         f"The internet host {eng.label(p.src)} sent {proto} connection attempts to {len(ports)} different ports "
                         f"on {eng.label(p.dst)} within 60 seconds (ports {_ports(ports)}).", p.src, p.dst,
                         key=(self.name, "in", p.src, p.dst), evidence={"ports": len(ports)})
            return
        self.vert.add((p.src, p.dst), (proto, p.dport), p.ts)
        ports = self.vert.items((p.src, p.dst), p.ts)
        if len(ports) >= self.tv:
            refused = len(self.fail.items(p.src, p.ts))
            eng.emit(p.ts, self.name, "reconnaissance", 3 if len(ports) >= 100 else 2, "Port scan",
                     f"{eng.label(p.src)} sent {proto} connection attempts to {len(ports)} different ports on "
                     f"{eng.label(p.dst)} within 60 seconds (ports {_ports([x[1] for x in ports])}); "
                     f"{refused} attempts were refused with a reset.", p.src, p.dst,
                     key=(self.name, "v", p.src, p.dst), evidence={"ports": len(ports), "refused": refused})
        if p.dport in (443, 80) and is_public(p.dst):
            return                                               # browsers talk to many web servers
        self.sweep.add((p.src, proto, p.dport), p.dst, p.ts)
        hosts = self.sweep.items((p.src, proto, p.dport), p.ts)
        failed = {h for h, _ in self.fail.items(p.src, p.ts)}
        n_priv = sum(1 for h in hosts if ip_class(h) == "private")
        if n_priv >= self.ts_ or len(failed & set(hosts)) >= self.ts_:
            eng.emit(p.ts, self.name, "reconnaissance", 2, f"Host sweep on {svc_port(p.dport, proto.lower())}",
                     f"{eng.label(p.src)} tried {svc_port(p.dport, proto.lower())} (port {p.dport}) on {len(hosts)} different "
                     f"hosts within 60 seconds, {len(failed & set(hosts))} of them refused.", p.src, None,
                     key=(self.name, "h", p.src, p.dport), evidence={"hosts": len(hosts)})

    def tick(self, now, eng, final=False):
        if int(now) % 30 == 0:
            for w in (self.vert, self.sweep, self.inb, self.fail, self.icmp):
                w.prune(now)


def _ports(ports):
    s = sorted(ports)
    return ", ".join(map(str, s[:8])) + (f" ... {s[-1]}" if len(s) > 8 else "")


class SynFlood(Detector):
    name = "syn-flood"

    def __init__(self, threshold=400, span=10):
        self.w = defaultdict(deque); self.acks = Counter(); self.th = threshold; self.span = span

    def on_packet(self, p, flow, eng):
        if p.proto != D.TCP:
            return
        if p.flags & D.SYN and not p.flags & D.ACK:
            q = self.w[p.dst]; q.append((p.ts, p.src))
            while q and p.ts - q[0][0] > self.span:
                q.popleft()
            if len(q) >= self.th:
                srcs = Counter(s for _, s in q)
                completed = sum(1 for f in eng.flows.values() if f.server == p.dst and f.synack) or 0
                if completed < len(q) * 0.3:
                    eng.emit(p.ts, self.name, "denial_of_service", 3, "SYN flood",
                             f"{len(q)} TCP SYN packets to {eng.label(p.dst)} port {p.dport} in {self.span} seconds from "
                             f"{len(srcs)} sources (top {eng.label(srcs.most_common(1)[0][0])}); few handshakes completed.",
                             None, p.dst, key=(self.name, p.dst), evidence={"syns": len(q), "sources": len(srcs)})
                q.clear()


# ---------------------------------------------------------------------------------------------- C2 beaconing
class Beaconing(Detector):
    """Regular activity bursts from an inside host to one public endpoint (new connections or keep-alive bursts)."""
    name = "beaconing"
    GAP = 2.0

    def __init__(self, min_events=10, max_cv=0.15, min_period=5.0):
        self.ev = defaultdict(lambda: deque(maxlen=64)); self.last = {}; self.done = {}
        self.min_events, self.max_cv, self.min_period = min_events, max_cv, min_period

    def on_packet(self, p, flow, eng):
        if flow is None or p.src != flow.client or not is_public(flow.server) or not eng.is_inside(flow.client):
            return
        if flow.sport in (53, 123, 853) or flow.proto not in (D.TCP, D.UDP):
            return
        k = (flow.client, flow.server, flow.sport, flow.proto)
        last = self.last.get(k)
        if last is None or p.ts - last > self.GAP:
            self.ev[k].append((p.ts, 0))
        self.last[k] = p.ts
        if self.ev[k]:
            t, b = self.ev[k][-1]; self.ev[k][-1] = (t, b + p.wirelen)

    def tick(self, now, eng, final=False):
        if int(now) % 10 and not final:
            return
        for k, q in list(self.ev.items()):
            if len(q) < self.min_events:
                if now - self.last.get(k, now) > 3600:
                    del self.ev[k]; self.last.pop(k, None)
                continue
            times = [t for t, _ in q]
            iv = [b - a for a, b in zip(times, times[1:])]
            mean = statistics.fmean(iv)
            if mean < self.min_period:
                continue
            med = statistics.median(iv)
            dev = [abs(x - med) for x in iv]
            cv = 1.4826 * statistics.median(dev) / med if med else 9          # robust CV: tolerates a missed beat
            if cv > self.max_cv:
                continue
            prev = self.done.get(k)
            if prev and len(q) < prev * 2:
                continue
            self.done[k] = len(q)
            client, server, port, proto = k
            name = eng.names.get(server)
            svc = known_service(name) if name else None
            sizes = [b for _, b in q]
            sev = 0 if svc else 2 if (name is None or port not in (443, 80)) else 1
            if port in SUSPICIOUS_PORTS:
                sev = 3
            pname = "TCP" if proto == D.TCP else "UDP"
            eng.emit(now, self.name, "command_and_control", sev, "Periodic beaconing",
                     f"{eng.label(client)} contacted {eng.label(server)} on {pname} port {port} ({svc_port(port)}) "
                     f"{len(q)} times at a regular interval of {med:.1f} seconds (jitter {cv * 100:.0f}%), "
                     f"about {human_bytes(statistics.median(sizes))} per contact"
                     f"{'; no DNS lookup was seen for this address' if name is None else ''}.",
                     client, server, key=(self.name, k), evidence={"events": len(q), "period_s": round(med, 2),
                                                                    "jitter": round(cv, 3), "port": port, "name": name})


# ---------------------------------------------------------------------------------------------- DNS
class DnsAnomalies(Detector):
    name = "dns"

    def __init__(self):
        self.sub = Window(120); self.nx = Window(60); self.seen = set(); self.txt = Counter(); self.llmnr = False

    def on_packet(self, p, flow, eng):
        d = p.dns
        if not d or not d["qname"]:
            return
        q = d["qname"].rstrip("."); mdns = 5353 in (p.sport, p.dport); llmnr = 5355 in (p.sport, p.dport)
        if llmnr or 137 in (p.sport, p.dport):
            if not self.llmnr:
                self.llmnr = True
                eng.emit(p.ts, self.name, "policy_risk", 0, "LLMNR name resolution in use",
                         f"{eng.label(p.src)} uses LLMNR multicast name resolution (asked for '{q}'). Any device on the "
                         f"local network can answer these queries, which tools like Responder abuse to capture password hashes.",
                         p.src, None, key=(self.name, "llmnr"))
            return
        if mdns or q.endswith((".local", ".lan", ".home", ".arpa", ".localdomain", ".internal")) or "." not in q:
            return
        client = p.dst if d["qr"] else p.src
        reg = registrable(q); svc = known_service(q)
        if d["qr"] and d["rcode"] == 3:
            self.nx.add(client, q, p.ts)
            nx = self.nx.items(client, p.ts)
            if len(nx) >= 15:
                eng.emit(p.ts, self.name, "dns_tunneling", 2, "Burst of failed DNS lookups (possible DGA malware)",
                         f"{eng.label(client)} looked up {len(nx)} different domain names that do not exist within 60 seconds, "
                         f"e.g. {', '.join(sorted(nx)[:6])}. Malware with a domain generation algorithm does this to find its server.",
                         client, None, key=(self.name, "nx", client), evidence={"nxdomains": len(nx), "sample": sorted(nx)[:10]})
        if d["qr"]:
            return
        sub = q[: -len(reg)].rstrip(".")
        if sub and not svc:
            self.sub.add((client, reg), sub, p.ts)
            if d["qtype"] in (16, 10):                       # TXT / NULL
                self.txt[(client, reg)] += 1
            subs = self.sub.items((client, reg), p.ts)
            if len(subs) >= 25:
                longest = [max(len(x) for x in s.split(".")) for s in subs]
                avg_len = sum(longest) / len(longest)
                avg_ent = sum(entropy(s.replace(".", "")) for s in subs) / len(subs)
                if avg_len >= 20 or avg_ent >= 3.8:
                    eng.emit(p.ts, self.name, "dns_tunneling", 3, "DNS tunnelling / data exfiltration over DNS",
                             f"{eng.label(client)} queried {len(subs)} different subdomains of {reg} within 2 minutes; the "
                             f"subdomain labels average {avg_len:.0f} characters with {avg_ent:.1f} bits/char entropy "
                             f"(looks like encoded data), {self.txt[(client, reg)]} were TXT/NULL queries. Example: {q[:90]}",
                             client, None, key=(self.name, "tun", client, reg),
                             evidence={"subdomains": len(subs), "avg_label": round(avg_len, 1), "entropy": round(avg_ent, 2)})
        if len(q) > 150 or any(len(lbl) > 60 for lbl in q.split(".")):
            if not svc:
                eng.emit(p.ts, self.name, "dns_tunneling", 1, "Unusually long DNS name",
                         f"{eng.label(client)} looked up an unusually long name ({len(q)} characters): {q[:120]}",
                         client, None, key=(self.name, "long", client, reg))
        if reg in self.seen or svc:
            return
        self.seen.add(reg)
        reasons = []; sev = 0
        dga = dga_score(q)
        if dga >= 0.6:
            reasons.append(f"its name looks randomly generated (score {dga:.2f})"); sev = max(sev, 2)
        la = lookalike(q)
        if la:
            reasons.append(f"it imitates the brand '{la}'"); sev = max(sev, 2)
        if reg in DYNDNS or any(q.endswith("." + x) for x in DYNDNS):
            reasons.append("it is a free dynamic-DNS / tunnelling host often used by malware"); sev = max(sev, 1)
        if reasons:
            eng.emit(p.ts, self.name, "dns_tunneling" if dga >= 0.6 else "malware_delivery", sev, "Suspicious domain looked up",
                     f"{eng.label(client)} looked up the domain {q}: " + "; ".join(reasons) + ".",
                     client, q, key=(self.name, "dom", reg), evidence={"domain": q, "dga": round(dga, 2), "lookalike": la},
                     laya_mode="domain")


# ---------------------------------------------------------------------------------------------- cleartext secrets, HTTP
PW_RE = re.compile(rb"(?i)(?:^|[&\"'\s{,])(pass(?:word|wd)?|pwd|passphrase|secret|api[_-]?key|token)[\"']?\s*[=:]")
EXE_EXT = (".exe", ".dll", ".scr", ".ps1", ".hta", ".bat", ".cmd", ".vbs", ".js", ".jar", ".msi", ".lnk", ".iso", ".sh", ".elf", ".bin")
TOOL_UA = ("powershell", "curl/", "wget", "python-requests", "python-urllib", "certutil", "bitsadmin", "winhttp", "go-http-client",
           "microsoft bits")


class Cleartext(Detector):
    name = "cleartext"

    def __init__(self):
        self.http_hosts = set()

    def on_packet(self, p, flow, eng):
        if p.auth:
            a = p.auth; client, server = p.src, p.dst
            if a["proto"] == "Telnet":
                eng.emit(p.ts, self.name, "credential_exposure", 2, "Telnet session (unencrypted remote login)",
                         f"{eng.label(client)} is using Telnet with {eng.label(server)}; everything typed, including passwords, "
                         f"crosses the network unencrypted.", client, server, key=(self.name, "telnet", client, server))
            else:
                who = f" for user '{a['user']}'" if a.get("user") else ""
                eng.emit(p.ts, self.name, "credential_exposure", 3, f"Cleartext {a['proto']} login",
                         f"{eng.label(client)} sent a {a['proto']} {a['field']} command{who} to {eng.label(server)} without "
                         f"encryption, so the password can be read by anyone on the path.", client, server,
                         key=(self.name, a["proto"], client, server), evidence={"proto": a["proto"], "user": a.get("user")})
        h = p.http
        if not h:
            if p.exe and flow is not None and is_public(p.src):
                self._exe(p, flow, eng, p.exe, "")
            return
        if h["kind"] == "response":
            if flow is not None and is_public(flow.server) and (h["exe"] or "msdownload" in h["ctype"] or "dosexec" in h["ctype"]
                                                                or any(x in h["disposition"].lower() for x in EXE_EXT)):
                self._exe(p, flow, eng, h["exe"] or h["ctype"], h["disposition"])
            return
        client, server = p.src, p.dst
        host = h["host"] or server
        url = f"http://{host}{h['path']}"
        auth = h["auth"]
        if auth:
            scheme = auth.split(" ", 1)[0].lower(); user = ""
            if scheme == "basic":
                try:
                    user = base64.b64decode(auth.split(" ", 1)[1]).decode("latin-1").split(":", 1)[0]
                except Exception:
                    pass
            sev = 3 if scheme in ("basic", "bearer", "digest") else 2
            eng.emit(p.ts, self.name, "credential_exposure", sev, f"Credentials sent over unencrypted HTTP ({scheme})",
                     f"{eng.label(client)} sent an HTTP Authorization {scheme} header{f' for user {user!r}' if user else ''} to "
                     f"{url[:120]} over unencrypted HTTP; the password or token can be captured.", client, server,
                     key=(self.name, "httpauth", client, host), evidence={"url": url[:200], "scheme": scheme, "user": user})
        if h["method"] in ("POST", "PUT") and PW_RE.search(h["body"]):
            eng.emit(p.ts, self.name, "credential_exposure", 3, "Password submitted over unencrypted HTTP",
                     f"{eng.label(client)} submitted a form containing a password/secret field to {url[:120]} over unencrypted HTTP.",
                     client, server, key=(self.name, "form", client, host), evidence={"url": url[:200]})
        ua = h["ua"].lower(); path = h["path"].lower().split("?")[0]
        bare_ip = bool(re.fullmatch(r"[0-9.]+(:\d+)?", host))
        if is_public(server) and (path.endswith(EXE_EXT) or (bare_ip and any(t in ua for t in TOOL_UA))):
            eng.emit(p.ts, self.name, "malware_delivery", 3 if bare_ip else 2, "Suspicious download over HTTP",
                     f"{eng.label(client)} requested {url[:120]} using user-agent '{h['ua'][:60]}'"
                     f"{' from a bare IP address with no domain name' if bare_ip else ''}; scripts and executables fetched this "
                     f"way are a common malware delivery step.", client, server, key=(self.name, "dl", client, url[:200]),
                     evidence={"url": url[:200], "ua": h["ua"][:160]})
        if is_public(server) and not known_service(host) and host not in self.http_hosts:
            self.http_hosts.add(host)
            eng.emit(p.ts, self.name, "policy_risk", 0, "Unencrypted web traffic",
                     f"{eng.label(client)} browsed {url[:120]} over plain HTTP (not HTTPS).", client, server,
                     key=(self.name, "http", host))

    def _exe(self, p, flow, eng, kind, disposition):
        eng.emit(p.ts, self.name, "malware_delivery", 3, "Executable downloaded over unencrypted HTTP",
                 f"{eng.label(flow.client)} downloaded an executable file ({kind}{', ' + disposition[:60] if disposition else ''}) "
                 f"from {eng.label(flow.server)} port {flow.sport} over unencrypted HTTP, so it could have been tampered with "
                 f"or come from a malicious server.", flow.client, flow.server, key=(self.name, "exe", flow.client, flow.server))


# ---------------------------------------------------------------------------------------------- TLS
class Tls(Detector):
    name = "tls"
    NAMES = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

    def __init__(self, ja3_block=None):
        self.ja3_block = ja3_block or {}

    def on_packet(self, p, flow, eng):
        t = p.tls
        if not t or flow is None:
            return
        v = t["version"]
        if t["hs"] == "server" and v <= 0x0302:
            eng.emit(p.ts, self.name, "policy_risk", 2 if v == 0x0300 else 1, f"Outdated {self.NAMES.get(v, hex(v))} connection",
                     f"{eng.label(flow.client)} negotiated {self.NAMES.get(v, hex(v))} with {eng.label(flow.server)} port "
                     f"{flow.sport}; this protocol version is deprecated and has known weaknesses.", flow.client, flow.server,
                     key=(self.name, "ver", flow.server, v))
        if t["hs"] == "client" and t["ja3"] in self.ja3_block:
            eng.emit(p.ts, self.name, "command_and_control", 3, "TLS fingerprint matches known malware",
                     f"{eng.label(flow.client)} opened a TLS connection to {eng.label(flow.server)} whose client fingerprint "
                     f"(JA3 {t['ja3']}) matches '{self.ja3_block[t['ja3']]}'.", flow.client, flow.server,
                     key=(self.name, "ja3", flow.client, t["ja3"]), evidence={"ja3": t["ja3"]})


# ---------------------------------------------------------------------------------------------- ports / exposure
class RiskyPorts(Detector):
    name = "ports"

    def on_packet(self, p, flow, eng):
        if p.proto != D.TCP or flow is None:
            return
        fl = p.flags
        if fl & D.SYN and not fl & D.ACK and eng.is_inside(p.src) and is_public(p.dst):
            if p.dport in SUSPICIOUS_PORTS and p.dport != 23:
                eng.emit(p.ts, self.name, "command_and_control", 2, f"Connection to suspicious port {p.dport}",
                         f"{eng.label(p.src)} opened a TCP connection to {eng.label(p.dst)} on port {p.dport}, a port commonly "
                         f"associated with {SUSPICIOUS_PORTS[p.dport]}.", p.src, p.dst, key=(self.name, "sus", p.src, p.dst, p.dport))
            elif p.dport in (445, 139):
                eng.emit(p.ts, self.name, "policy_risk", 2, "Windows file sharing (SMB) to the internet",
                         f"{eng.label(p.src)} tried SMB (port {p.dport}) to the internet host {eng.label(p.dst)}; this can leak "
                         f"Windows password hashes (NTLM) to that server.", p.src, p.dst, key=(self.name, "smb", p.src, p.dst))
        elif fl & D.SYN and fl & D.ACK and eng.is_inside(p.src) and is_public(p.dst):
            eng.emit(p.ts, self.name, "reconnaissance", 3, f"Inbound connection accepted from the internet on port {p.sport}",
                     f"{eng.label(p.src)} accepted a TCP connection on port {p.sport} ({svc_port(p.sport)}) from the internet "
                     f"host {eng.label(p.dst)}: a service on this machine is reachable from the internet.", p.dst, p.src,
                     key=(self.name, "exposed", p.src, p.sport))
        elif fl & D.SYN and not fl & D.ACK and is_public(p.src) and eng.is_inside(p.dst) and p.dport in (3389, 445, 22, 5900, 23):
            eng.emit(p.ts, self.name, "reconnaissance", 2, f"Internet host probing {svc_port(p.dport)}",
                     f"The internet host {eng.label(p.src)} tried to connect to {svc_port(p.dport)} (port {p.dport}) on "
                     f"{eng.label(p.dst)}.", p.src, p.dst, key=(self.name, "probe", p.src, p.dport))


# ---------------------------------------------------------------------------------------------- L2 spoofing
class Spoofing(Detector):
    name = "spoofing"

    def __init__(self):
        self.bind = {}; self.mac_ips = Window(60); self.unsol = defaultdict(deque); self.req = {}; self.dhcp_servers = {}

    def on_packet(self, p, flow, eng):
        if p.dhcp:
            self._dhcp(p, eng)
        if p.icmp and p.proto == D.ICMP and p.icmp[0] == 5 or p.icmp and p.proto == D.ICMP6 and p.icmp[0] == 137:
            eng.emit(p.ts, self.name, "spoofing_mitm", 2, "ICMP redirect received",
                     f"{eng.label(p.src)} sent an ICMP redirect to {eng.label(p.dst)}, telling it to route traffic through "
                     f"another gateway; attackers use this for man-in-the-middle.", p.src, p.dst, key=(self.name, "redir", p.src))
        if not p.arp:
            return
        op, sha, spa, tha, tpa = p.arp
        if spa == "0.0.0.0" or sha in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        if op == 1:
            self.req[tpa] = p.ts
        else:
            if p.ts - self.req.get(spa, -99) > 5 and spa != tpa:          # reply nobody asked for
                q = self.unsol[sha]; q.append(p.ts)
                while q and p.ts - q[0] > 10:
                    q.popleft()
                if len(q) >= 10:
                    eng.emit(p.ts, self.name, "spoofing_mitm", 2, "Flood of unsolicited ARP replies",
                             f"The device {sha} sent {len(q)} ARP replies nobody asked for within 10 seconds (latest claims "
                             f"{spa}); this is typical of ARP poisoning tools.", spa, None, key=(self.name, "unsol", sha))
        prev = self.bind.get(spa)
        gw_mac = eng.gw_macs.most_common(1)[0][0] if eng.gw_macs else None
        if gw_mac and sha == gw_mac and prev is None:
            eng.gateway_ips.add(spa)
        if prev and prev[0] != sha and p.ts - prev[1] < 3600:
            is_gw = spa in eng.gateway_ips or prev[0] == gw_mac
            eng.emit(p.ts, self.name, "spoofing_mitm", 4 if is_gw else 3,
                     "Gateway MAC address changed (ARP spoofing)" if is_gw else "IP address changed MAC (possible ARP spoofing)",
                     f"The MAC address for {eng.label(spa)} changed from {prev[0]} to {sha}"
                     f"{' - this is the default gateway, so all internet traffic may now pass through another device' if is_gw else ''}.",
                     spa, None, key=(self.name, "arp", spa, sha), evidence={"ip": spa, "old_mac": prev[0], "new_mac": sha})
        self.bind[spa] = (sha, p.ts)
        self.mac_ips.add(sha, spa, p.ts)
        ips = self.mac_ips.items(sha, p.ts)
        if len(ips) >= 6:
            eng.emit(p.ts, self.name, "spoofing_mitm", 2, "One device claims many IP addresses",
                     f"The device {sha} claimed {len(ips)} different IP addresses via ARP within 60 seconds "
                     f"({', '.join(sorted(ips)[:6])}).", None, None, key=(self.name, "many", sha))

    def _dhcp(self, p, eng):
        d = p.dhcp
        if d.get("router"):
            eng.gateway_ips.add(d["router"])
        if d["type"] in (2, 5) and d.get("server"):
            self.dhcp_servers[d["server"]] = p.ts
            live = {s for s, t in self.dhcp_servers.items() if p.ts - t < 3600}
            if len(live) >= 2:
                eng.emit(p.ts, self.name, "spoofing_mitm", 3, "Multiple DHCP servers (rogue DHCP)",
                         f"{len(live)} different DHCP servers answered on this network ({', '.join(sorted(live))}); a rogue "
                         f"DHCP server can hand out a malicious gateway or DNS server.", d["server"], None,
                         key=(self.name, "dhcp", tuple(sorted(live))))


class IcmpTunnel(Detector):
    name = "icmp"

    def __init__(self):
        self.big = defaultdict(deque)

    def on_packet(self, p, flow, eng):
        if not p.icmp or p.icmp[0] not in (8, 0, 128, 129) or len(p.payload) < 200:
            return
        k = tuple(sorted((p.src, p.dst))); q = self.big[k]; q.append((p.ts, len(p.payload)))
        while q and p.ts - q[0][0] > 60:
            q.popleft()
        if len(q) >= 10 and len({s for _, s in q}) >= 3:
            inside = p.src if eng.is_inside(p.src) else p.dst; other = p.dst if inside == p.src else p.src
            eng.emit(p.ts, self.name, "exfiltration", 2, "Possible ICMP tunnel",
                     f"{len(q)} ping packets with large, varying payloads ({min(s for _, s in q)}-{max(s for _, s in q)} bytes) "
                     f"between {eng.label(inside)} and {eng.label(other)} within 60 seconds; normal pings are small and uniform.",
                     inside, other, key=(self.name, k))


# ---------------------------------------------------------------------------------------------- volume / behaviour anomalies
class Volume(Detector):
    """Per inside host, 10-second buckets; EWMA baseline; alert on large deviations. Also big one-way uploads per flow."""
    name = "anomaly"
    METRICS = {"upload": ("bytes uploaded to the internet", 20e6), "download": ("bytes downloaded", 200e6),
               "new_flows": ("new connections", 150), "remotes": ("different internet hosts contacted", 60),
               "dns": ("DNS queries", 150), "failed": ("refused / reset connections", 60)}

    def __init__(self, bucket=10.0, warmup=18, z=5.0, alpha=0.05):
        self.bucket = bucket; self.warm = warmup; self.z = z; self.alpha = alpha
        self.cur = defaultdict(Counter); self.rem = defaultdict(set); self.top = defaultdict(Counter)
        self.base = {}; self.n = Counter(); self.start = None; self.cool = {}

    def on_packet(self, p, flow, eng):
        if not p.ipv:
            return
        if self.start is None:
            self.start = p.ts
        if eng.is_inside(p.src) and is_public(p.dst):
            c = self.cur[p.src]; c["upload"] += p.wirelen; self.rem[p.src].add(p.dst); self.top[p.src][p.dst] += p.wirelen
            if flow is not None and flow.pc == 1 and flow.ps == 0 and p.src == flow.client:
                c["new_flows"] += 1
            if p.dns and not p.dns["qr"]:
                c["dns"] += 1
        elif is_public(p.src) and eng.is_inside(p.dst):
            self.cur[p.dst]["download"] += p.wirelen
            if p.proto == D.TCP and p.flags & D.RST:
                self.cur[p.dst]["failed"] += 1
        elif eng.is_inside(p.src) and p.dns and not p.dns["qr"]:
            self.cur[p.src]["dns"] += 1

    def tick(self, now, eng, final=False):
        if self.start is None or (now - self.start) % self.bucket >= 1.0 and not final:
            return
        for host in set(self.cur) | {h for h, _ in self.base}:
            c = self.cur.get(host, Counter()); c["remotes"] = len(self.rem.get(host, ()))
            self.n[host] += 1
            for m, (desc, floor) in self.METRICS.items():
                x = float(c[m]); b = self.base.get((host, m))
                if b is None:
                    self.base[(host, m)] = [x, 0.0]; continue
                mean, var = b
                if self.n[host] > self.warm and x > floor:
                    sd = math.sqrt(var) if var > 0 else max(mean * 0.5, 1.0)
                    z = (x - mean) / sd
                    if z >= self.z and now - self.cool.get((host, m), -1e9) > 300:
                        self.cool[(host, m)] = now
                        self._alert(now, eng, host, m, desc, x, mean, z)
                        continue                                     # do not absorb the spike into the baseline
                d = x - mean
                b[0] = mean + self.alpha * d
                b[1] = (1 - self.alpha) * (var + self.alpha * d * d)
        self.cur.clear(); self.rem.clear(); self.top.clear()

    def _alert(self, now, eng, host, metric, desc, x, mean, z):
        fmt = human_bytes if metric in ("upload", "download") else (lambda v: f"{v:.0f}")
        top = self.top.get(host)
        extra = ""
        if metric == "upload" and top:
            dst, n = top.most_common(1)[0]; extra = f" Most of it ({human_bytes(n)}) went to {eng.label(dst)}."
        cat = {"upload": "exfiltration", "new_flows": "reconnaissance", "remotes": "reconnaissance", "dns": "dns_tunneling",
               "failed": "reconnaissance", "download": "benign"}[metric]
        eng.emit(now, self.name, cat, 1 if metric == "download" else 2, f"Unusual spike in {desc}",
                 f"{eng.label(host)} had {fmt(x)} {desc} in {self.bucket:.0f} seconds, versus a normal level of about "
                 f"{fmt(mean)} (z-score {z:.0f}).{extra}", host, None, key=(self.name, host, metric, int(now // 300)),
                 evidence={"metric": metric, "value": x, "baseline": round(mean, 1), "z": round(z, 1)})

    def on_flow_end(self, f, eng):
        self._upload(f, eng, f.last)

    def _upload(self, f, eng, now):
        if f.bc < 100e6 or f.bc < 10 * max(f.bs, 1) or not is_public(f.server) or f.upload_alerted * 1e9 > f.bc:
            return
        f.upload_alerted = int(f.bc // 1e9) + 1
        svc = known_service(f.name) if f.name else None
        dur = max(1.0, f.last - f.first)
        eng.emit(now, self.name, "exfiltration", 1 if svc else 2, "Large one-way upload",
                 f"{eng.label(f.client)} uploaded {human_bytes(f.bc)} to {eng.label(f.server)} port {f.sport} in "
                 f"{dur / 60:.1f} minutes ({human_bytes(f.bc / dur)}/s) while receiving only {human_bytes(f.bs)}.",
                 f.client, f.server, key=(self.name, "up", f.client, f.server, f.sport, f.first),
                 evidence={"bytes_up": f.bc, "bytes_down": f.bs, "seconds": round(dur)})


class UploadWatch(Detector):
    """Checks long-running flows for large one-way uploads without waiting for them to end."""
    name = "anomaly-upload"

    def __init__(self, vol):
        self.vol = vol

    def tick(self, now, eng, final=False):
        if int(now) % 15 and not final:
            return
        for f in list(eng.flows.values()):
            if f.bc >= 100e6:
                self.vol._upload(f, eng, now)


def all_detectors(ja3_block=None):
    vol = Volume()
    return [PortScan(), SynFlood(), Beaconing(), DnsAnomalies(), Cleartext(), Tls(ja3_block), RiskyPorts(), Spoofing(),
            IcmpTunnel(), vol, UploadWatch(vol)]
