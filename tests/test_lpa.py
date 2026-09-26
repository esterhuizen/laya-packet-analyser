"""python3 -m unittest discover -s tests   (stdlib only; no Laya server needed - Laya is faked)"""
import io, os, struct, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lpa import decode as D  # noqa: E402
from lpa import synth as S  # noqa: E402
from lpa.engine import Engine  # noqa: E402
from lpa.laya import Pipeline, judge  # noqa: E402
from lpa.model import Alert  # noqa: E402
from lpa.netutil import dga_score, ip_class, lookalike  # noqa: E402
from lpa.pcapio import PcapWriter, read_packets  # noqa: E402


def pcapng(frames, tsresol=6):
    """Minimal little-endian pcapng writer (SHB + IDB with if_tsresol + EPBs) for reader tests."""
    def block(t, body):
        body += b"\0" * ((4 - len(body) % 4) % 4)
        n = len(body) + 12
        return struct.pack("<II", t, n) + body + struct.pack("<I", n)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0))
    for ts, data in frames:
        t = int(ts * 10 ** tsresol)
        out += block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(data), len(data)) + data)
    return out


class Collect:
    def __init__(self):
        self.alerts = []

    def submit(self, a):
        self.alerts.append(a)

    def update(self, a):
        pass


class TestIO(unittest.TestCase):
    def test_pcap_roundtrip(self):
        f = io.BytesIO(); w = PcapWriter(f)
        w.write(1.5, b"x" * 60); w.write(2.25, b"y" * 54, wirelen=1514)
        f.seek(0); pk = list(read_packets(f))
        self.assertEqual([(round(p[0], 3), p[1], len(p[2]), p[3]) for p in pk], [(1.5, 1, 60, 60), (2.25, 1, 54, 1514)])

    def test_pcapng_nanosecond(self):
        frame = S.eth(S.LAPTOP_MAC, S.GW_MAC, 0x0800, S.ipv4(S.LAPTOP, "8.8.8.8", 17, S.udp(5000, 53, S.dns("example.org"))))
        pk = list(read_packets(io.BytesIO(pcapng([(1790000000.123456789, frame)], tsresol=9))))
        self.assertAlmostEqual(pk[0][0], 1790000000.123456789, places=5)
        p = D.decode(*pk[0])
        self.assertEqual((p.src, p.dst, p.dns["qname"]), (S.LAPTOP, "8.8.8.8", "example.org"))

    def test_truncated_capture_stops_cleanly(self):
        f = io.BytesIO(); w = PcapWriter(f); w.write(1, b"z" * 100)
        data = f.getvalue()[:-30]
        self.assertEqual(list(read_packets(io.BytesIO(data))), [])


class TestDecode(unittest.TestCase):
    def test_tls_sni_and_ja3(self):
        f = S.eth(S.LAPTOP_MAC, S.GW_MAC, 0x0800, S.ipv4(S.LAPTOP, "1.1.1.1", 6, S.tcp(5000, 443, 0x18, S.client_hello("api.example.com"))))
        p = D.decode(0, 1, f, len(f))
        self.assertEqual(p.tls["sni"], "api.example.com"); self.assertEqual(len(p.tls["ja3"]), 32)

    def test_http_basic_and_ftp(self):
        f = S.eth(S.LAPTOP_MAC, S.GW_MAC, 0x0800, S.ipv4(S.LAPTOP, "1.1.1.1", 6, S.tcp(5000, 21, 0x18, b"PASS hunter2\r\n")))
        p = D.decode(0, 1, f, len(f))
        self.assertEqual(p.auth["proto"], "FTP"); self.assertNotIn("hunter2", repr(p.auth))

    def test_garbage_never_raises(self):
        import random
        random.seed(1)
        for n in range(2000):
            data = bytes(random.randrange(256) for _ in range(random.randrange(0, 120)))
            for lt in (1, 101, 113, 0):
                D.decode(0, lt, data, len(data))


class TestNetutil(unittest.TestCase):
    def test_ip_class(self):
        self.assertEqual(ip_class("192.168.1.5"), "private"); self.assertEqual(ip_class("198.51.100.1"), "public")
        self.assertEqual(ip_class("224.0.0.251"), "multicast"); self.assertEqual(ip_class("fe80::1"), "private")

    def test_domains(self):
        self.assertEqual(lookalike("paypa1-secure-login.com"), "paypal")
        self.assertIsNone(lookalike("www.paypal.com")); self.assertIsNone(lookalike("github.com"))
        self.assertGreater(dga_score("xkqjzvbnwpryt.biz"), 0.6); self.assertLess(dga_score("wikipedia.org"), 0.4)


class TestDetectorsOnSynthetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, path = tempfile.mkstemp(suffix=".pcap"); os.close(fd)
        S.write_demo(path)
        cls.sink = Collect(); eng = Engine(cls.sink)
        with open(path, "rb") as f:
            for pk in read_packets(f):
                eng.feed(*pk)
        eng.finish(); os.remove(path)
        cls.titles = {a.title for a in cls.sink.alerts}

    def test_every_planted_attack_is_found(self):
        expected = ["Port scan", "Inbound port scan from the internet", "DNS tunnelling / data exfiltration over DNS",
                    "Burst of failed DNS lookups (possible DGA malware)", "Password submitted over unencrypted HTTP",
                    "Credentials sent over unencrypted HTTP (basic)", "Cleartext FTP login", "Suspicious download over HTTP",
                    "Executable downloaded over unencrypted HTTP", "Gateway MAC address changed (ARP spoofing)",
                    "Multiple DHCP servers (rogue DHCP)", "Periodic beaconing", "Large one-way upload",
                    "Unusual spike in bytes uploaded to the internet", "Possible ICMP tunnel", "Outdated TLS 1.0 connection",
                    "Windows file sharing (SMB) to the internet", "Connection to suspicious port 4444", "Suspicious domain looked up"]
        for t in expected:
            self.assertIn(t, self.titles)

    def test_benign_background_is_quiet(self):
        benign_ips = {ip for _, ip in S.BENIGN} | {"52.113.194.132", "185.125.190.57"}
        noisy = [a.title for a in self.sink.alerts if (a.src in benign_ips or a.dst in benign_ips) and a.severity >= 1]
        self.assertEqual(noisy, [])

    def test_beacons_have_right_period(self):
        periods = sorted(a.evidence["period_s"] for a in self.sink.alerts if a.title == "Periodic beaconing")
        self.assertAlmostEqual(periods[0], 30, delta=1); self.assertAlmostEqual(periods[-1], 45, delta=1)


class FakeLaya:
    def __init__(self, p_threat):
        self.p = p_threat

    def ask(self, state, questions, **kw):
        if "threat" in questions:
            return {"threat": {"noul": self.p}, "category": {"choice": "benign", "answer_confidence": 0.5}}, 5.0
        return {"sus": {"noul": self.p}, "kind": {"choice": "dga", "answer_confidence": 0.6}}, 5.0


class TestTriageRules(unittest.TestCase):
    def mk(self, sev, cat="reconnaissance"):
        return Alert(0, "t", cat, sev, "title", "story")

    def test_raise_lower_keep(self):
        self.assertEqual(judge(FakeLaya(0.9), self.mk(2))[1], 3)
        self.assertEqual(judge(FakeLaya(0.6), self.mk(2))[1], 2)
        self.assertEqual(judge(FakeLaya(0.2), self.mk(2))[1], 1)

    def test_high_findings_never_lowered(self):
        self.assertEqual(judge(FakeLaya(0.05), self.mk(3))[1], 3)
        self.assertEqual(judge(FakeLaya(0.05), self.mk(4, "spoofing_mitm"))[1], 4)
        self.assertEqual(judge(FakeLaya(0.95), self.mk(4))[1], 4)

    def test_pipeline_survives_laya_outage(self):
        class Down:
            from lpa.laya import LayaStats
            stats = LayaStats()

            def ask(self, *a, **kw):
                raise ConnectionError("down")
        got = []

        class Out:
            def alert(self, a):
                got.append(a)

            def update(self, a):
                pass
        p = Pipeline(Down(), [Out()]); a = self.mk(2); p.submit(a); p.drain(5)
        self.assertEqual(got, [a]); self.assertEqual(a.final, 2); self.assertEqual(a.laya["mode"], "unavailable")


class TestLayaReview(unittest.TestCase):
    def test_review_flags_reverse_shell_only(self):
        from lpa.laya import LayaStats
        from lpa.review import ConversationTracker, Reviewer, preview

        class ContentLaya:            # stands in for Laya: suspicious only of the reverse-shell payload
            stats = LayaStats()

            def ask(self, state, qs, **kw):
                text = str(state)
                return {"threat": {"noul": 0.95 if "whoami" in text else 0.2},
                        "category": {"choice": "command_and_control"}}, 1.0
        fd, path = tempfile.mkstemp(suffix=".pcap"); os.close(fd); S.write_demo(path)
        sink = Collect(); holder = {}
        rv = Reviewer(ContentLaya(), lambda: holder.get("eng"), ptr=False)
        eng = Engine(sink, detectors=[ConversationTracker(rv)]); holder["eng"] = eng
        with open(path, "rb") as f:
            for pk in read_packets(f):
                eng.feed(*pk)
        eng.finish(); rv.drain(60); os.remove(path)
        flagged = [a for a in sink.alerts if a.detector == "laya-review"]
        self.assertEqual({a.dst for a in flagged}, {"45.137.21.9"})
        self.assertEqual(flagged[0].laya["mode"], "review")
        self.assertGreater(rv.reviewed, 50)
        self.assertIn("[redacted]", preview(b"USER bob\r\nPASS hunter2\r\n"))
        self.assertNotIn("hunter2", preview(b"login=bob&password=hunter2"))


if __name__ == "__main__":
    unittest.main()
