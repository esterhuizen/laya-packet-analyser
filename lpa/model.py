"""Shared data types: Alert and severity helpers."""
import itertools, time

SEVERITIES = ["info", "low", "medium", "high", "critical"]
CATEGORIES = {   # also the Laya 'category' choice criteria (kept short: the NPU budget is 512 tokens per question)
    "benign": "normal laptop traffic: browsing, updates, sync, streaming, local discovery",
    "reconnaissance": "port scan or host sweep",
    "command_and_control": "regular automated callbacks (beaconing) to a remote controller",
    "exfiltration": "unusually large upload of data",
    "dns_tunneling": "data hidden in DNS queries or random generated domains",
    "credential_exposure": "passwords or tokens sent in cleartext",
    "malware_delivery": "executable or script downloaded from a suspicious source",
    "spoofing_mitm": "ARP, DHCP, DNS or ICMP spoofing, man-in-the-middle",
    "denial_of_service": "packet flood or half-open connection flood",
    "policy_risk": "insecure but not necessarily malicious: old TLS, telnet, SMB to internet, cleartext web",
}
_ids = itertools.count(1)


class Alert:
    __slots__ = ("id", "ts", "first_ts", "detector", "category", "severity", "title", "story", "src", "dst", "key",
                 "evidence", "count", "laya", "final", "laya_mode", "wall")

    def __init__(self, ts, detector, category, severity, title, story, src=None, dst=None, key=None, evidence=None,
                 laya_mode="triage"):
        self.id = next(_ids); self.ts = self.first_ts = ts; self.detector = detector; self.category = category
        self.severity = severity; self.final = severity; self.title = title; self.story = story
        self.src = src; self.dst = dst; self.key = key or (detector, src, dst, title)
        self.evidence = evidence or {}; self.count = 1; self.laya = None; self.laya_mode = laya_mode
        self.wall = time.time()

    def to_dict(self):
        return {"id": self.id, "ts": self.ts, "first_ts": self.first_ts, "detector": self.detector, "category": self.category,
                "severity": SEVERITIES[self.severity], "final_severity": SEVERITIES[self.final], "title": self.title,
                "story": self.story, "src": self.src, "dst": self.dst, "count": self.count, "evidence": self.evidence,
                "laya": self.laya}
