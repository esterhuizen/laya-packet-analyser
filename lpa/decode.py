"""Packet decoding: link layer -> ARP / IPv4 / IPv6 -> TCP / UDP / ICMP -> DNS, TLS hello, HTTP, DHCP, cleartext auth.

Everything is best-effort: malformed or truncated packets decode as far as possible and never raise.
"""
import hashlib, ipaddress, socket, struct

TCP, UDP, ICMP, ICMP6 = 6, 17, 1, 58
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


class Packet:
    __slots__ = ("ts", "wirelen", "src_mac", "dst_mac", "arp", "ipv", "src", "dst", "ttl", "proto", "sport", "dport",
                 "flags", "payload", "icmp", "dns", "tls", "http", "dhcp", "auth", "exe", "l3key")

    def __init__(self, ts, wirelen):
        self.ts = ts; self.wirelen = wirelen
        self.src_mac = self.dst_mac = self.arp = self.ipv = self.src = self.dst = self.ttl = self.proto = None
        self.sport = self.dport = None; self.flags = 0; self.payload = b""
        self.icmp = self.dns = self.tls = self.http = self.dhcp = self.auth = self.exe = None
        self.l3key = None                        # identity of the network-layer packet, for de-duplicating capture points


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def decode(ts, linktype, data, wirelen):
    """Return a Packet, or None for frames we do not understand (e.g. 802.11 radiotap control frames)."""
    p = Packet(ts, wirelen)
    try:
        if linktype == 1:                        # Ethernet
            if len(data) < 14:
                return None
            p.dst_mac, p.src_mac = mac(data[0:6]), mac(data[6:12])
            et = struct.unpack("!H", data[12:14])[0]; off = 14
            if et not in (0x0800, 0x86DD, 0x0806, 0x8100, 0x88A8) and _is_80211(data):
                return _wifi(p, data)            # pktmon logs Wi-Fi frames at the NIC as raw 802.11 despite linktype 1
            while et in (0x8100, 0x88A8) and len(data) >= off + 4:   # VLAN tags
                et = struct.unpack("!H", data[off + 2:off + 4])[0]; off += 4
            return _l3(p, et, data[off:])
        if linktype == 105:                      # IEEE 802.11
            return _wifi(p, data)
        if linktype == 127 and len(data) >= 4:   # 802.11 + radiotap
            return _wifi(p, data[struct.unpack("<H", data[2:4])[0]:])
        if linktype == 113:                      # Linux cooked SLL
            return _l3(p, struct.unpack("!H", data[14:16])[0], data[16:])
        if linktype == 276:                      # Linux cooked SLL2
            return _l3(p, struct.unpack("!H", data[0:2])[0], data[20:])
        if linktype in (101, 12, 14):            # raw IP
            return _l3(p, 0x0800 if data[:1] and data[0] >> 4 == 4 else 0x86DD, data)
        if linktype == 228:
            return _l3(p, 0x0800, data)
        if linktype == 229:
            return _l3(p, 0x86DD, data)
        if linktype in (0, 108):                 # BSD loopback / null
            fam = struct.unpack("<I", data[:4])[0]
            if fam > 0xFFFF:
                fam = struct.unpack(">I", data[:4])[0]
            return _l3(p, 0x0800 if fam == 2 else 0x86DD, data[4:])
    except (struct.error, IndexError, ValueError):
        return p if p.ipv or p.arp else None
    return None


SNAP = b"\xaa\xaa\x03\x00\x00\x00"


def _wifi_hdr_len(d):
    fc0, fc1 = d[0], d[1]
    if (fc0 >> 2) & 3 != 2:                      # not a data frame
        return None
    n = 24 + (6 if fc1 & 3 == 3 else 0)          # 4-address (WDS) frames
    if fc0 & 0x80:                               # QoS data subtypes carry a 2-byte QoS control
        n += 2
    if fc1 & 0x80:                               # +HTC / order bit
        n += 4
    return n


def _is_80211(d):
    if len(d) < 32:
        return False
    n = _wifi_hdr_len(d)
    return n is not None and d[n:n + 6] == SNAP


def _wifi(p, d):
    n = _wifi_hdr_len(d) if len(d) >= 32 else None
    if n is None or d[n:n + 6] != SNAP:
        return None                              # management/control frames, or encrypted payloads
    fc1 = d[1]; a1, a2, a3 = mac(d[4:10]), mac(d[10:16]), mac(d[16:22])
    to_ds, from_ds = fc1 & 1, fc1 & 2
    p.dst_mac, p.src_mac = (a3, a2) if to_ds and not from_ds else (a1, a3) if from_ds and not to_ds else (a1, a2)
    p.wirelen = max(0, p.wirelen - (n + 8) + 14)  # report the Ethernet-equivalent size so byte counts match
    return _l3(p, struct.unpack("!H", d[n + 6:n + 8])[0], d[n + 8:])


def _l3(p, et, d):
    p.l3key = (et, hash(bytes(d[:80])), len(d))
    if et == 0x0806 and len(d) >= 28:
        op = struct.unpack("!H", d[6:8])[0]
        p.arp = (op, mac(d[8:14]), socket.inet_ntoa(d[14:18]), mac(d[18:24]), socket.inet_ntoa(d[24:28]))
        return p
    if et == 0x0800 and len(d) >= 20 and d[0] >> 4 == 4:
        ihl = (d[0] & 0x0F) * 4
        total = struct.unpack("!H", d[2:4])[0]
        frag = struct.unpack("!H", d[6:8])[0]
        p.ipv = 4; p.ttl = d[8]; p.proto = d[9]
        p.src = socket.inet_ntoa(d[12:16]); p.dst = socket.inet_ntoa(d[16:20])
        body = d[ihl:total] if total >= ihl and total <= len(d) else d[ihl:]
        if frag & 0x1FFF:                        # non-first fragment: no L4 header
            return p
        return _l4(p, body)
    if et == 0x86DD and len(d) >= 40:
        p.ipv = 6; p.ttl = d[7]
        nh = d[6]; p.src = _ip6(d[8:24]); p.dst = _ip6(d[24:40])
        body = d[40:40 + struct.unpack("!H", d[4:6])[0]] or d[40:]
        for _ in range(8):                       # walk extension headers
            if nh in (0, 43, 60) and len(body) >= 8:
                nh, body = body[0], body[(body[1] + 1) * 8:]
            elif nh == 44 and len(body) >= 8:
                if struct.unpack("!H", body[2:4])[0] & 0xFFF8:
                    p.proto = body[0]; return p
                nh, body = body[0], body[8:]
            else:
                break
        p.proto = nh
        return _l4(p, body)
    return None


def _ip6(b):
    return str(ipaddress.IPv6Address(b))


def _l4(p, b):
    if p.proto == TCP and len(b) >= 20:
        p.sport, p.dport = struct.unpack("!HH", b[0:4])
        p.flags = b[13]
        p.payload = b[(b[12] >> 4) * 4:]
        if p.payload:
            _tcp_app(p)
    elif p.proto == UDP and len(b) >= 8:
        p.sport, p.dport = struct.unpack("!HH", b[0:4])
        p.payload = b[8:]
        if p.payload:
            _udp_app(p)
    elif p.proto in (ICMP, ICMP6) and len(b) >= 4:
        p.icmp = (b[0], b[1]); p.payload = b[8:]
    return p


# ---------------------------------------------------------------- UDP applications
def _udp_app(p):
    ports = (p.sport, p.dport)
    if 53 in ports or 5353 in ports or 5355 in ports:
        p.dns = parse_dns(p.payload)
    elif 67 in ports or 68 in ports:
        p.dhcp = parse_dhcp(p.payload)


def _name(msg, off, depth=0):
    labels = []; jumped = False; end = off
    for _ in range(128):
        if off >= len(msg):
            raise ValueError("name overrun")
        n = msg[off]
        if n == 0:
            off += 1; break
        if n & 0xC0 == 0xC0:
            if depth > 10:
                raise ValueError("pointer loop")
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            rest, _ = _name(msg, ptr, depth + 1)
            if rest:
                labels.append(rest)
            off = None; break
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace")); off += 1 + n
    return ".".join(labels).lower(), (end if jumped else off)


def parse_dns(m):
    """-> dict(qr, rcode, qname, qtype, answers=[(name, type, value)]) or None."""
    if len(m) < 12:
        return None
    try:
        _id, fl, qd, an = struct.unpack("!HHHH", m[:8])
        d = {"qr": bool(fl & 0x8000), "rcode": fl & 0x0F, "qname": None, "qtype": None, "answers": []}
        off = 12
        for i in range(min(qd, 4)):
            name, off = _name(m, off)
            qtype = struct.unpack("!H", m[off:off + 2])[0]; off += 4
            if i == 0:
                d["qname"], d["qtype"] = name, qtype
        for _ in range(min(an, 32)):
            name, off = _name(m, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", m[off:off + 10]); off += 10
            rd = m[off:off + rdlen]; off += rdlen
            if rtype == 1 and rdlen == 4:
                d["answers"].append((name, 1, socket.inet_ntoa(rd)))
            elif rtype == 28 and rdlen == 16:
                d["answers"].append((name, 28, _ip6(rd)))
            elif rtype in (5, 12):                       # CNAME, PTR (mDNS service instances)
                d["answers"].append((name, rtype, _name(m, off - rdlen)[0]))
            elif rtype == 33 and rdlen > 6:               # SRV target
                d["answers"].append((name, 33, _name(m, off - rdlen + 6)[0]))
        return d
    except (ValueError, IndexError, struct.error):
        return None


def parse_dhcp(m):
    if len(m) < 240 or m[236:240] != b"\x63\x82\x53\x63":
        return None
    d = {"op": m[0], "yiaddr": socket.inet_ntoa(m[16:20]), "chaddr": mac(m[28:34]), "type": None, "server": None, "router": None,
         "hostname": None, "vendor": None, "requested": None}
    i = 240
    while i < len(m) and m[i] != 255:
        if m[i] == 0:
            i += 1; continue
        code, ln = m[i], m[i + 1]; v = m[i + 2:i + 2 + ln]
        if code == 53 and ln:
            d["type"] = v[0]
        elif code == 54 and ln == 4:
            d["server"] = socket.inet_ntoa(v)
        elif code == 3 and ln >= 4:
            d["router"] = socket.inet_ntoa(v[:4])
        elif code == 12:
            d["hostname"] = v.decode("latin-1", "replace")[:60]
        elif code == 60:
            d["vendor"] = v.decode("latin-1", "replace")[:60]
        elif code == 50 and ln == 4:
            d["requested"] = socket.inet_ntoa(v)
        i += 2 + ln
    return d


# ---------------------------------------------------------------- TCP applications
def _tcp_app(p):
    pl = p.payload
    if pl[0] == 0x16 and len(pl) >= 6 and pl[1] == 3:
        p.tls = parse_tls_hello(pl)
    elif pl.startswith(HTTP_METHODS):
        p.http = parse_http_request(pl)
    elif pl.startswith(b"HTTP/1."):
        p.http = parse_http_response(pl)
    elif pl[:2] == b"MZ" and p.sport in (80, 8080, 21, 20) or pl[:4] == b"\x7fELF":
        p.exe = "PE" if pl[:2] == b"MZ" else "ELF"
    if p.dport in (21, 110, 143, 25, 587, 23, 119, 1143) or p.sport == 23:
        p.auth = parse_cleartext_auth(p.dport, pl)


def _ext_list(b, width):
    return [int.from_bytes(b[i:i + width], "big") for i in range(0, len(b) - width + 1, width)]


def parse_tls_hello(pl):
    """ClientHello -> {hs: 'client', version, sni, ja3, ja3_str}; ServerHello -> {hs: 'server', version}."""
    try:
        if pl[5] not in (1, 2):
            return None
        hs = pl[9:]
        ver = struct.unpack("!H", hs[0:2])[0]
        off = 2 + 32
        sid = hs[off]; off += 1 + sid
        if pl[5] == 2:
            off += 3                              # cipher (2) + compression (1)
            sel = ver
            if off + 2 <= len(hs):
                end = off + 2 + struct.unpack("!H", hs[off:off + 2])[0]; off += 2
                while off + 4 <= min(end, len(hs)):
                    et, el = struct.unpack("!HH", hs[off:off + 4])
                    if et == 43 and el == 2:
                        sel = struct.unpack("!H", hs[off + 4:off + 6])[0]
                    off += 4 + el
            return {"hs": "server", "version": sel}
        cl = struct.unpack("!H", hs[off:off + 2])[0]
        ciphers = [c for c in _ext_list(hs[off + 2:off + 2 + cl], 2) if c not in GREASE]; off += 2 + cl
        off += 1 + hs[off]                        # compression methods
        sni = None; exts = []; groups = []; pfmt = []; versions = []
        if off + 2 <= len(hs):
            end = off + 2 + struct.unpack("!H", hs[off:off + 2])[0]; off += 2
            while off + 4 <= min(end, len(hs)):
                et, el = struct.unpack("!HH", hs[off:off + 4]); ed = hs[off + 4:off + 4 + el]
                if et not in GREASE:
                    exts.append(et)
                if et == 0 and len(ed) >= 5:
                    n = struct.unpack("!H", ed[3:5])[0]; sni = ed[5:5 + n].decode("ascii", "replace").lower()
                elif et == 10 and len(ed) >= 2:
                    groups = [g for g in _ext_list(ed[2:], 2) if g not in GREASE]
                elif et == 11 and ed:
                    pfmt = list(ed[1:1 + ed[0]])
                elif et == 43 and ed:
                    versions = [v for v in _ext_list(ed[1:1 + ed[0]], 2) if v not in GREASE]
                off += 4 + el
        ja3 = ",".join([str(ver), "-".join(map(str, ciphers)), "-".join(map(str, exts)),
                        "-".join(map(str, groups)), "-".join(map(str, pfmt))])
        return {"hs": "client", "version": max(versions) if versions else ver, "sni": sni,
                "ja3": hashlib.md5(ja3.encode()).hexdigest(), "ja3_str": ja3}
    except (IndexError, struct.error):
        return None


def _headers(block):
    h = {}
    for line in block.split(b"\r\n")[1:]:
        k, sep, v = line.partition(b":")
        if sep:
            h[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return h


def parse_http_request(pl):
    head, _, body = pl.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
    if len(first) < 2:
        return None
    h = _headers(head)
    return {"kind": "request", "method": first[0], "path": first[1][:200], "host": h.get("host", ""),
            "ua": h.get("user-agent", "")[:160], "auth": h.get("authorization", ""),
            "ctype": h.get("content-type", ""), "body": body[:2048]}


def parse_http_response(pl):
    head, _, body = pl.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
    h = _headers(head)
    exe = "PE" if body[:2] == b"MZ" else "ELF" if body[:4] == b"\x7fELF" else None
    return {"kind": "response", "status": first[1] if len(first) > 1 else "", "ctype": h.get("content-type", ""),
            "length": h.get("content-length", ""), "disposition": h.get("content-disposition", ""), "exe": exe}


def parse_cleartext_auth(dport, pl):
    """Detect cleartext logins; returns {'proto', 'user', 'secret': True} with the secret itself never stored."""
    line = pl.split(b"\r\n", 1)[0][:200].decode("latin-1")
    up = line.upper()
    if dport == 21 and up.startswith(("USER ", "PASS ")):
        return {"proto": "FTP", "field": up[:4], "user": line[5:].strip() if up.startswith("USER") else None}
    if dport in (110, 1143) and up.startswith(("USER ", "PASS ", "APOP ")):
        return {"proto": "POP3", "field": up[:4], "user": line[5:].strip() if up.startswith("USER") else None}
    if dport in (143, 1143):
        parts = line.split(" ")
        if len(parts) >= 3 and parts[1].upper() in ("LOGIN", "AUTHENTICATE"):
            return {"proto": "IMAP", "field": parts[1].upper(), "user": parts[2] if parts[1].upper() == "LOGIN" else None}
    if dport in (25, 587) and up.startswith("AUTH "):
        return {"proto": "SMTP", "field": "AUTH", "user": None}
    if dport == 119 and up.startswith("AUTHINFO "):
        return {"proto": "NNTP", "field": "AUTHINFO", "user": None}
    if dport == 23 or dport is None:
        return {"proto": "Telnet", "field": "session", "user": None}
    return None
