"""Streaming pcap / pcapng reader and a minimal pcap writer (stdlib only).

read_packets(stream) yields (ts: float, linktype: int, data: bytes, wirelen: int). The stream only needs .read(n);
it may be a regular file, a pipe (stdin from dumpcap/tcpdump -w -) or a Follow() wrapper around a growing file.
"""
import struct, time

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


class FormatError(Exception):
    pass


class Follow:
    """File-like wrapper that waits for more data at EOF (tail -f for a capture file still being written)."""
    def __init__(self, path, poll=0.25, stop=None):
        self.f = open(path, "rb"); self.poll = poll; self.stop = stop

    def read(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.f.read(n - len(buf))
            if chunk:
                buf += chunk; continue
            if self.stop is not None and self.stop.is_set():
                return buf
            time.sleep(self.poll)
        return buf

    def close(self):
        self.f.close()


def _read_exact(stream, n):
    buf = stream.read(n)
    while buf is not None and len(buf) < n:
        more = stream.read(n - len(buf))
        if not more:
            break
        buf += more
    if not buf:
        return None
    if len(buf) < n:
        raise EOFError("truncated capture")
    return buf


def read_packets(stream):
    magic = _read_exact(stream, 4)
    if magic is None:
        return
    if magic in PCAP_MAGICS:
        yield from _read_pcap(stream, magic)
    elif magic == PCAPNG_SHB:
        yield from _read_pcapng(stream)
    else:
        raise FormatError(f"not a pcap/pcapng capture (magic {magic.hex()})")


def _read_pcap(stream, magic):
    endian, res = PCAP_MAGICS[magic]
    hdr = _read_exact(stream, 20)
    if hdr is None:
        return
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", hdr)
    linktype &= 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    while True:
        try:
            h = _read_exact(stream, 16)
            if h is None:
                return
            sec, frac, incl, orig = rec.unpack(h)
            if incl > 262144 * 4:
                raise FormatError(f"implausible record length {incl}")
            data = _read_exact(stream, incl) or b""
        except EOFError:
            return                              # capture cut mid-record (e.g. killed writer): keep what we have
        yield sec + frac * res, linktype, data, orig


def _read_pcapng(stream):
    # the SHB magic has been consumed; read its length + byte-order magic to learn the endianness
    head = _read_exact(stream, 8)
    if head is None:
        return
    bom = head[4:8]
    if bom == b"\x4d\x3c\x2b\x1a":
        e = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        e = ">"
    else:
        raise FormatError("bad pcapng byte-order magic")
    blen = struct.unpack(e + "I", head[:4])[0]
    if _read_exact(stream, blen - 12) is None:  # rest of SHB
        return
    ifaces = []                                  # [(linktype, ts_resolution_seconds)]
    while True:
        try:
            h = _read_exact(stream, 8)
            if h is None:
                return
            if h[:4] == PCAPNG_SHB:                  # a new section (concatenated captures): endianness may change
                bom = _read_exact(stream, 4)
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack(e + "I", h[4:8])[0]
                _read_exact(stream, blen - 12)
                ifaces = []
                continue
            btype, blen = struct.unpack(e + "II", h)
            if blen < 12 or blen > 64 * 1024 * 1024:
                raise FormatError(f"bad pcapng block length {blen}")
            body = _read_exact(stream, blen - 8) or b""
        except EOFError:
            return
        body = body[:-4]                         # trailing block length
        if btype == 1:                           # Interface Description Block
            linktype = struct.unpack(e + "H", body[:2])[0]
            ifaces.append((linktype, _if_tsresol(body[8:], e)))
        elif btype == 6:                         # Enhanced Packet Block
            iid, tsh, tsl, cap, orig = struct.unpack(e + "IIIII", body[:20])
            lt, res = ifaces[iid] if iid < len(ifaces) else (1, 1e-6)
            yield ((tsh << 32) | tsl) * res, lt, body[20:20 + cap], orig
        elif btype == 3:                         # Simple Packet Block
            orig = struct.unpack(e + "I", body[:4])[0]
            lt = ifaces[0][0] if ifaces else 1
            yield time.time(), lt, body[4:4 + min(orig, len(body) - 4)], orig
        elif btype == 2:                         # obsolete Packet Block
            iid, _drops, tsh, tsl, cap, orig = struct.unpack(e + "HHIIII", body[:20])
            lt, res = ifaces[iid] if iid < len(ifaces) else (1, 1e-6)
            yield ((tsh << 32) | tsl) * res, lt, body[20:20 + cap], orig
        # other blocks (name resolution, statistics, custom, decryption secrets) are skipped


def _if_tsresol(opts, e):
    i = 0
    while i + 4 <= len(opts):
        code, olen = struct.unpack(e + "HH", opts[i:i + 4])
        if code == 0:
            break
        if code == 9 and olen >= 1:
            v = opts[i + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        i += 4 + ((olen + 3) & ~3)
    return 1e-6


class PcapWriter:
    """Classic little-endian microsecond pcap writer (used for synthetic test captures and --save)."""
    def __init__(self, f, linktype=1, snaplen=262144):
        self.f = f
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts, data, wirelen=None):
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec += 1; usec -= 1000000
        self.f.write(struct.pack("<IIII", sec, usec, len(data), wirelen or len(data)) + data)
