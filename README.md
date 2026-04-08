# 🛡️ NetSniffer — Network Anomaly Detection Audit Tool

A complete network audit toolkit for IT security professionals. Collects network telemetry data and applies rule-based anomaly detection to identify DNS policy violations, ARP spoofing, SSL interception, latency issues, and segmentation failures.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  collector.sh   │ ──► │ audit_output.json │ ──► │   analyzer.py    │
│  (Bash)         │     │ (JSON data)       │     │  (Python 3.10+)  │
│                 │     │                   │     │                  │
│ • nslookup      │     │ • DNS results     │     │ • Rule engine    │
│ • dig           │     │ • ARP table       │     │ • 7 detection    │
│ • arp -a        │     │ • Routes          │     │   rules          │
│ • ip route      │     │ • SSL certs       │     │ • HTML report    │
│ • traceroute    │     │ • Traceroute      │     │   generator      │
│ • openssl       │     │ • WHOIS           │     │                  │
│ • whois         │     │ • Machine info    │     │                  │
│ • ip a          │     │ • Baseline        │     │                  │
│ • resolv.conf   │     │                   │     │                  │
└─────────────────┘     └──────────────────┘     └──────────────────┘
                                                         │
                                                         ▼
                                                  ┌──────────────┐
                                                  │ audit_report  │
                                                  │   .html       │
                                                  │               │
                                                  │ Professional  │
                                                  │ IT audit      │
                                                  │ report        │
                                                  └──────────────┘
```

## Quick Start

### Step 1: Collect Data (on Linux target machine)

```bash
chmod +x collector.sh
sudo ./collector.sh
```

This generates `audit_output.json` with all network telemetry data.

### Step 2: Analyze & Generate Report

```bash
python3 analyzer.py
```

This reads `audit_output.json`, detects anomalies, and generates `audit_report.html`.

### Step 3: View Report

```bash
xdg-open audit_report.html
# or
firefox audit_report.html
```

### Quick Test (without running collector)

A sample data file is included for testing:

```bash
cp audit_output_sample.json audit_output.json
python3 analyzer.py
```

## Detection Rules

| # | Rule | Severity | Description |
|---|------|----------|-------------|
| 1 | **Blocked Domain Resolution** | CRITICAL | Detects when domains that should be blocked (facebook.com, spotify.com, youtube.com) are resolving to IP addresses |
| 2 | **DNS Timeout** | HIGH | Detects when the primary DNS server (1.1.1.1) is not responding |
| 3 | **Cross-Segment ARP** | HIGH | Detects ARP entries from 192.168.3.x visible on the 192.168.4.x segment (or vice versa) |
| 4 | **Unknown SSL CA** | CRITICAL | Detects certificates not issued by a recognized public Certificate Authority |
| 5 | **Traceroute Latency Spike** | MEDIUM | Detects >100ms latency jumps between consecutive traceroute hops |
| 6 | **Gateway MAC Mismatch** | CRITICAL | Detects when gateway MAC differs from known baseline (ARP spoofing indicator) |
| 7 | **DNS Configuration Audit** | HIGH/MEDIUM | Detects unexpected or missing DNS servers in resolv.conf |

## Network Baseline

| Parameter | Value |
|-----------|-------|
| Segments | 10.0.6.0/24, 10.0.5.0/24 |
| DNS Servers | 1.1.1.1, 8.8.8.8 |
| DNS Provider | FortiSASE (Fortinet) |
| Default Gateway | 10.0.5.1 |
| Blocked Domains | facebook.com, spotify.com, youtube.com |
| Machine IP | 10.0.5.50 |

## Severity Classification

- 🔴 **CRITICAL** — Immediate action required (policy bypass, MITM, spoofing)
- 🟠 **HIGH** — Significant risk (DNS failure, unauthorized config)
- 🟡 **MEDIUM** — Moderate concern (latency, missing config)
- 🔵 **LOW** — Informational (minor deviations)

## Customization

### Adding Gateway MAC Baseline

Edit `analyzer.py` and set:

```python
BASELINE["gateway_mac"] = "00:1a:2b:3c:4d:5e"  # Your known gateway MAC
```

### Adding Custom Blocked Domains

Edit `collector.sh` — `DOMAINS` array, and `analyzer.py` — `BASELINE["blocked_domains"]`.

### Adjusting Latency Threshold

```python
BASELINE["latency_spike_threshold_ms"] = 150  # Default: 100
```

## Requirements

### Collector (collector.sh)
- Bash 4+
- Tools: `nslookup`, `dig`, `arp`, `ip`, `traceroute`, `openssl`, `whois`
- Root/sudo recommended for complete ARP table

### Analyzer (analyzer.py)
- Python 3.10+ (uses `dataclasses`, type hints)
- No external dependencies (stdlib only)

## License

Internal IT audit tool — for authorized use only.
