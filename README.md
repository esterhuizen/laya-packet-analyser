# laya-packet-analyser

Finds security problems in this laptop's network traffic, either live or from a Wireshark/tcpdump/pktmon dump.
It uses deterministic detectors plus a second opinion from **[Laya](https://huggingface.co/convaiinnovations/laya)
running locally** (any Jev-compatible `POST /v1/systemone` server: stock `laya-serve` on the CPU, or an NPU/GPU build). A live dashboard shows packets scanned (total and per second), Laya calls and average Laya
response time, throughput, alerts, threat categories and top hosts/domains.

Pure Python standard library: nothing to install, no Npcap needed.

## Quick start

**1. Run a Laya server on the same machine.** The analyser tries `127.0.0.1` ports 8002, 8001, 8004 and 8000 in that
order, or uses `--laya-url`. The stock package works on CPU:

```powershell
pip install laya fastapi uvicorn
$env:LAYA_HOST="127.0.0.1"; laya-serve          # http://127.0.0.1:8000  (set LAYA_API_KEY on both sides to require a key)
```

It was developed against Laya 0.3.20 on a Snapdragon X Elite, served on the Hexagon NPU at :8002. The NPU needs
about 100 ms per question; the CPU is several times slower, which only affects how quickly the review queue drains.

**2. Run the analyser.** It needs Python 3.10+ on Windows and nothing else (standard library only).

```powershell
lpa.cmd                                            # LIVE capture of this laptop (the default) + dashboard at http://127.0.0.1:8765/
lpa.cmd analyse C:\captures\wifi.pcapng           # a pcap / pcapng file instead (Wireshark, tcpdump, pktmon etl2pcap)
lpa.cmd synth demo.pcap                            # synthetic capture: benign traffic + 22 kinds of attack
lpa.cmd analyse demo.pcap --replay 20              # replay it at 20x real time
lpa.cmd laya-check                                 # is Laya up, and how fast is one triage?
```

`win\lpa.cmd` runs the package with the Windows `py` launcher; set `LPA_PYTHON` to use a specific python.exe.
Without the launcher, set `PYTHONPATH` to the repo and run `python -m lpa`. On Linux, file analysis works
directly (`python3 -m lpa analyse file.pcap`), and live capture uses `--source iface:eth0` (root) or `--source stdin`.

**Live capture** uses Windows' built-in Packet Monitor (pktmon), which needs Administrator rights. When `lpa` is not
elevated, Windows shows a UAC prompt. Accept it and capture continues in a new elevated console window; press Ctrl+C
there to stop. The dashboard is still opened in your normal, non-elevated browser. Pass `--no-elevate` to get an
error instead of the prompt, or start it from *Terminal (Admin)* to skip the prompt.

pktmon is captured in back-to-back slices (default 3 s, `--slice`). Alerts therefore lag by a few seconds, and there
is a short gap while one slice stops and the next starts. On Wi-Fi, pktmon logs raw 802.11 frames and up to five
copies of each packet (one per stack layer); the analyser decodes 802.11 and de-duplicates on the IP packet. For
gapless capture, install Wireshark/Npcap and pipe dumpcap in:
`dumpcap -i Wi-Fi -w - | lpa.cmd live --source stdin`. You can also point it at a file another tool is still writing:
`--source follow:C:\cap\ring.pcapng`.

**From WSL**, `bin/lpa` does the same. It mirrors `lpa/` to `%USERPROFILE%\laya-packet-analyser` and runs it with
Windows Python, because WSL in NAT mode cannot reach a Laya server on Windows loopback. It converts WSL file paths
automatically.

Useful options: `--jsonl alerts.jsonl` (every alert as JSON), `--min-severity medium` (console), `--no-laya`
(heuristics only), `--no-gui` / `--no-browser`, `--port`, `--local IP` (name the laptop's address), `--exit`.

## How it works

```
packets ─► decode (Ethernet/SLL/raw → ARP, IPv4/6 → TCP/UDP/ICMP → DNS, TLS hello + JA3, HTTP, DHCP, FTP/POP/IMAP/SMTP/Telnet)
        ─► flows + IP→name map (DNS answers, SNI, Host)
        ─► detectors ─► alert (heuristic severity + plain-English story) ─► Laya triage ─► console / JSONL / dashboard
```

Detector time is *capture* time, so a file and a live capture behave identically.

| Detector | Finds |
|---|---|
| port-scan | vertical scans, local host sweeps, ping sweeps, inbound scans from the internet |
| syn-flood | half-open SYN floods |
| beaconing | regular callbacks to one internet endpoint (robust jitter, known services demoted) |
| dns | DNS tunnelling (many high-entropy subdomains, TXT), NXDOMAIN bursts (DGA), DGA-looking / brand look-alike / dynamic-DNS domains, LLMNR |
| cleartext | HTTP Basic/Bearer auth, passwords in HTTP forms, FTP/POP3/IMAP/SMTP logins, Telnet, PowerShell/curl downloads from bare IPs, executables over HTTP |
| tls | SSL 3.0 / TLS 1.0 / 1.1 negotiated, optional JA3 blocklist |
| ports | connections to backdoor/IRC/Tor ports, SMB to the internet, internet → laptop connections accepted or probed |
| spoofing | gateway MAC change (ARP spoofing), unsolicited ARP floods, one MAC claiming many IPs, rogue DHCP, ICMP redirects |
| icmp | ICMP tunnels (large, varying ping payloads) |
| anomaly | per-host EWMA baselines (upload, download, new connections, remote hosts, DNS, resets) with z-score spikes; large one-way uploads |

### What Laya does

Laya works in two ways, both on the NPU.

**1. Live review of every conversation and device (like the Jev packet classifier).** Every conversation, meaning a
local device talking to one remote endpoint and port, becomes a short plain-English summary: names, ports, volumes,
timing regularity, TLS version, DNS queries, and a *sanitised preview of any cleartext payload* (passwords redacted).
Bursts of short probes are grouped into one "N ports tried" item. Other devices on the network are profiled from
what they broadcast: DHCP hostname and vendor, UPnP/SSDP server strings, mDNS services, and open ports seen. Laya
classifies each item on a background worker, unknown endpoints first. Conversations with the same known service
reuse the verdict. Remote hosts with no DNS name are named by reverse DNS first; a bare IP turns out to be
`berlin01.tor-exit.artikel10.org`, for instance. The dashboard's **Laya live review** panel ranks everything by
Laya's threat score.

A review becomes an alert only when it is corroborated: p ≥ 0.90, or p ≥ 0.70 together with a cleartext payload, a
non-standard port or ICMP data. The reason: on real laptop traffic Laya scores ordinary TLS-on-443 conversations
with unknown names at 0.6–0.8, so a bare threshold floods you. Measured with `tools/laya_flow_eval.py`:

| | synthetic threats alerted | synthetic benign alerted | real Wi-Fi traffic alerted |
|---|---|---|---|
| shipped rule | 6 / 19 (reverse shell, IRC bot, exe download, port-4444 C2, ICMP tunnel) | 0 / 66 | 0 / 19 |

The question wording mattered most. Naming the concrete threat types ("malware, a backdoor or remote shell, a
botnet, a crypto-miner, scanning, exploitation or data theft") gives AUC 0.94–0.96 on labelled traffic; a generic
"attack or data theft" question gives 0.78. Laya still misses some threats on its own: a crypto-miner login (0.45),
an IoT exploit URL (0.46) and a 150 MB upload (0.11). The rule detectors cover those.

**2. Triage of detector alerts.** Each detector alert is sent as `{"alert": title, "evidence": story}` with a
yes/no threat question (true/false criteria, `` `evidence` `` referenced) and a category choice.
Suspicious-domain alerts ask about the domain name itself. p(threat) ≥ 0.75 raises the severity one level.
p ≤ 0.42 lowers it one level, but only for low/medium alerts; high and critical detector evidence is never lowered.
On 30 labelled alert stories (`tools/laya_eval.py`) this lowered 9 of 13 benign look-alikes, raised 5 of 17
threats, and lowered no high-severity threat. Free-form "verdict" questions scored AUC 0.47–0.70; Laya's native
style scored 0.87.

Options: `--no-review` (triage only), `--flag-at` (default 0.90), `--no-ptr` (no reverse-DNS lookups).

Latency on the NPU: about 100 ms per question when idle. A review asks two questions (threat + category), and
under heavy replay load calls take about 0.5 s. Both workers use bounded queues. If Laya is down, detector alerts
are still emitted with their heuristic severity, the client re-checks every 15 s, and the review pauses.

## Files

```
lpa/pcapio.py     streaming pcap/pcapng reader (stdin, growing files), pcap writer
lpa/decode.py     protocol decoding            lpa/netutil.py   IP classes, domain heuristics, known services
lpa/engine.py     flows, names, alert folding  lpa/detectors.py all detectors
lpa/laya.py       Laya client, triage rules, pipeline
lpa/review.py     Laya live review: conversation + device summaries, background classifier, corroborated alerts
lpa/capture.py    files / stdin / follow / pktmon / AF_PACKET sources
lpa/dashboard.py  1 Hz sampler + loopback HTTP API     lpa/dashboard.html  the UI (canvas charts, light/dark)
lpa/synth.py      synthetic demo capture       lpa/cli.py       commands
tests/test_lpa.py python3 -m unittest discover -s tests
tools/laya_eval.py       alert-triage prompt/threshold evaluation     tools/laya_flow_eval.py  live-review evaluation
                         (both run on Windows, where Laya is reachable)
```

## What it sees

- **Seen:** everything this laptop sends and receives, on all its network adapters (pktmon `--comp nics`), plus
  what other devices on the Wi-Fi broadcast (ARP, DHCP, mDNS, UPnP/SSDP). Those broadcasts feed the device profiles.
- **Not seen:** traffic between other devices and the internet. A Wi-Fi adapter only passes up frames addressed to
  it, and WPA2/3 encrypts each device's traffic with its own key. To cover the whole network, feed in a capture from
  the router (`ssh root@router "tcpdump -i br-lan -U -w -" | lpa.cmd live --source stdin`) or from a mirrored switch
  port.
- **Excluded:** the analyser's own traffic. That is everything on loopback (the dashboard on 127.0.0.1:8765 and
  Laya on 127.0.0.1:800x) and the reverse-DNS lookups the Laya review makes. The Capture health panel counts it.

## Dashboard

Graphs:
- packets scanned, total and per second
- calls to Laya and average Laya response time
- throughput
- alerts over time

Panels:
- Laya verdicts, threat categories, protocol mix, top hosts and domains
- **Laya calls**: every `/v1/systemone` request, one summary row each (time, purpose, subject, answer, latency);
  click a row for the full request JSON, the answers as probability bars, and the raw response. Filter by purpose,
  search, or pause.
- **Laya live review**: every conversation and device, ranked by threat score
- the alert feed, with evidence you can expand
- **Capture health**: frames read and decoded, pktmon duplicates, excluded own traffic, errors, and pktmon messages

## Limits

- Encrypted traffic is judged on metadata only (SNI, sizes, timing, JA3), with no TLS interception.
- The domain allowlist (`KNOWN_SERVICES` in `lpa/netutil.py`) is short. Extend it for your apps to cut beacon and
  upload noise.
- Tested on Windows 11 ARM64 (Snapdragon X Elite, Wi-Fi) with Python 3.12 and 3.14, and on Linux Python 3.12
  (file analysis and the unit tests).

## Licence

MIT: free to use, copy, modify and redistribute for any purpose, commercial or not. See [LICENSE](LICENSE).
Laya itself is a separate project under Apache-2.0; this repository does not include its model or code.
