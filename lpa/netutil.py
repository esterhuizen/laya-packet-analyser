"""Address classification, domain heuristics (entropy, DGA-likeness, look-alikes) and well-known service names."""
import ipaddress, math, re
from collections import Counter
from functools import lru_cache

MULTI_SUFFIX = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "net.nz", "org.nz", "govt.nz",
                "co.za", "org.za", "co.jp", "ne.jp", "com.br", "com.cn", "com.mx", "co.in", "co.kr", "com.sg", "com.tr"}

# registrable domains whose traffic is routine on a laptop; lowers noise for DNS / beacon / upload heuristics
KNOWN_SERVICES = {
    "microsoft.com": "Microsoft", "microsoftonline.com": "Microsoft login", "live.com": "Microsoft", "live.net": "Microsoft",
    "windows.com": "Windows", "windows.net": "Microsoft Azure", "windowsupdate.com": "Windows Update", "msn.com": "Microsoft",
    "office.com": "Microsoft 365", "office.net": "Microsoft 365", "office365.com": "Microsoft 365", "sharepoint.com": "SharePoint",
    "onedrive.com": "OneDrive", "bing.com": "Bing", "azure.com": "Azure", "azureedge.net": "Azure CDN", "msedge.net": "Microsoft",
    "skype.com": "Skype", "teams.microsoft.com": "Teams", "xboxlive.com": "Xbox", "visualstudio.com": "Visual Studio",
    "vscode-cdn.net": "VS Code", "msftconnecttest.com": "Windows connectivity check", "trafficmanager.net": "Azure",
    "aka.ms": "Microsoft", "digicert.com": "DigiCert OCSP", "lencr.org": "Let's Encrypt", "sectigo.com": "Sectigo",
    "google.com": "Google", "googleapis.com": "Google APIs", "gstatic.com": "Google static", "googlevideo.com": "YouTube video",
    "youtube.com": "YouTube", "ytimg.com": "YouTube", "googleusercontent.com": "Google", "gvt1.com": "Google updates",
    "gvt2.com": "Google", "doubleclick.net": "Google ads", "googlesyndication.com": "Google ads", "google-analytics.com": "Google",
    "googletagmanager.com": "Google", "1e100.net": "Google", "apple.com": "Apple", "icloud.com": "iCloud",
    "mzstatic.com": "Apple", "aaplimg.com": "Apple", "amazonaws.com": "AWS", "amazon.com": "Amazon",
    "cloudfront.net": "CloudFront CDN", "akamaiedge.net": "Akamai CDN", "akamai.net": "Akamai CDN",
    "akamaihd.net": "Akamai CDN", "akadns.net": "Akamai DNS", "edgekey.net": "Akamai", "edgesuite.net": "Akamai",
    "cloudflare.com": "Cloudflare", "cloudflare-dns.com": "Cloudflare DNS", "fastly.net": "Fastly CDN",
    "fastly-edge.com": "Fastly", "jsdelivr.net": "jsDelivr CDN", "github.com": "GitHub", "githubusercontent.com": "GitHub",
    "github.io": "GitHub Pages", "ubuntu.com": "Ubuntu", "canonical.com": "Canonical", "debian.org": "Debian",
    "mozilla.org": "Mozilla", "mozilla.com": "Mozilla", "mozilla.net": "Mozilla", "firefox.com": "Firefox",
    "facebook.com": "Facebook", "fbcdn.net": "Facebook CDN", "instagram.com": "Instagram", "whatsapp.net": "WhatsApp",
    "whatsapp.com": "WhatsApp", "zoom.us": "Zoom", "slack.com": "Slack", "slack-edge.com": "Slack",
    "spotify.com": "Spotify", "scdn.co": "Spotify", "netflix.com": "Netflix", "nflxvideo.net": "Netflix",
    "dropbox.com": "Dropbox", "dropboxapi.com": "Dropbox", "anthropic.com": "Anthropic", "claude.ai": "Claude",
    "openai.com": "OpenAI", "discord.com": "Discord", "discord.gg": "Discord", "twitter.com": "Twitter/X", "x.com": "Twitter/X",
    "twimg.com": "Twitter/X", "linkedin.com": "LinkedIn", "licdn.com": "LinkedIn", "wikipedia.org": "Wikipedia",
    "pypi.org": "PyPI", "pythonhosted.org": "PyPI", "npmjs.org": "npm", "npmjs.com": "npm", "docker.io": "Docker",
    "docker.com": "Docker", "steampowered.com": "Steam", "steamcontent.com": "Steam", "nvidia.com": "NVIDIA",
    "qualcomm.com": "Qualcomm", "ntp.org": "NTP pool", "time.windows.com": "Windows time", "wsl.localhost": "WSL",
    "solana.com": "Solana", "helius-rpc.com": "Helius", "binance.com": "Binance",
}
BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "facebook", "instagram", "netflix", "outlook", "office365",
          "icloud", "binance", "coinbase", "metamask", "phantom", "solana", "github", "linkedin", "dropbox", "wellsfargo",
          "chase", "bankofamerica", "westpac", "anz", "asb", "kiwibank", "whatsapp", "telegram", "steam", "docusign"]
DYNDNS = {"duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "servebeer.com", "dynu.net", "freedns.afraid.org",
          "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net", "portmap.io", "3utilities.com", "sytes.net"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work", "rest", "cam", "icu", "sbs"}
SUSPICIOUS_PORTS = {4444: "Metasploit default", 1337: "leet/backdoor", 31337: "Back Orifice", 6666: "IRC", 6667: "IRC botnet C2",
                    6668: "IRC", 6669: "IRC", 9001: "Tor relay", 9030: "Tor directory", 9050: "Tor SOCKS", 9150: "Tor Browser",
                    5555: "Android debug", 2323: "Telnet alt (Mirai)", 1080: "SOCKS proxy", 3127: "MyDoom", 12345: "NetBus",
                    8545: "Ethereum RPC", 5900: "VNC", 23: "Telnet"}

_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                               "169.254.0.0/16", "fc00::/7", "fe80::/10")]


@lru_cache(maxsize=65536)
def ip_class(ip):
    """'private' | 'multicast' | 'broadcast' | 'loopback' | 'public' | 'unspecified'."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "public"
    if a.is_unspecified:
        return "unspecified"
    if a.is_loopback:
        return "loopback"
    if a.is_multicast:
        return "multicast"
    if a.version == 4 and (ip == "255.255.255.255" or ip.endswith(".255")):
        return "broadcast"
    if any(a.version == n.version and a in n for n in _PRIVATE):     # RFC1918 / CGNAT / link-local / ULA only:
        return "private"                                                # ipaddress.is_private also covers TEST-NETs
    return "public"


def is_public(ip):
    return ip_class(ip) == "public"


def registrable(domain):
    parts = domain.rstrip(".").lower().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def known_service(domain):
    if not domain:
        return None
    d = domain.rstrip(".").lower()
    if d in KNOWN_SERVICES:
        return KNOWN_SERVICES[d]
    return KNOWN_SERVICES.get(registrable(d))


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


_VOWELS = set("aeiou")


def dga_score(domain):
    """0..1 heuristic for machine-generated second-level labels (entropy, consonant runs, digits, length)."""
    reg = registrable(domain); label = reg.split(".")[0]
    if len(label) < 7:
        return 0.0
    ent = entropy(label)
    digits = sum(ch.isdigit() for ch in label) / len(label)
    vowels = sum(ch in _VOWELS for ch in label) / len(label)
    run = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz]+", label)), default=0)
    s = 0.0
    s += min(1.0, max(0.0, (ent - 3.0) / 1.2)) * 0.4
    s += min(1.0, digits * 3) * 0.2 if 0 < digits < 1 else 0
    s += (0.2 if vowels < 0.22 else 0.1 if vowels < 0.3 else 0)
    s += min(0.2, max(0, run - 3) * 0.07)
    s += 0.1 if len(label) >= 14 else 0
    tld = reg.rsplit(".", 1)[-1]
    s += 0.1 if tld in SUSPICIOUS_TLDS else 0
    return min(1.0, s)


def _lev(a, b):
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def lookalike(domain):
    """Return the imitated brand if the domain looks like a typo-squat / brand-bait of a well-known brand, else None."""
    if known_service(domain):
        return None
    reg = registrable(domain); label = reg.split(".")[0]
    norm = label.translate(_HOMO).replace("rn", "m").replace("vv", "w")
    if domain.startswith("xn--") or ".xn--" in domain:
        return "punycode (IDN homograph)"
    for b in BRANDS:
        if len(b) < 4:
            continue
        if norm == b and label != b:
            return b                                   # paypa1 -> paypal
        if b in norm and norm != b and ("-" in label or any(w in norm for w in ("login", "secure", "verify", "account",
                                                                                "update", "support", "wallet", "signin"))):
            return b                                   # microsoft-account-verify
        if len(norm) >= 5 and 0 < _lev(norm, b) <= (1 if len(b) < 7 else 2):
            return b                                   # gooogle, amazan
    return None


def svc_port(port, proto="tcp"):
    return {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
            445: "SMB", 139: "NetBIOS", 3389: "RDP", 5900: "VNC", 123: "NTP", 67: "DHCP", 68: "DHCP", 5353: "mDNS",
            5355: "LLMNR", 137: "NetBIOS-NS", 1900: "SSDP", 993: "IMAPS", 995: "POP3S", 587: "SMTP submission",
            8080: "HTTP-alt", 8443: "HTTPS-alt", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            1194: "OpenVPN", 51820: "WireGuard", 500: "IKE", 4500: "IPsec NAT-T", 853: "DNS-over-TLS"}.get(port, f"{proto}/{port}")


def human_bytes(n):
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
