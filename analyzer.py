#!/usr/bin/env python3
"""
NetSniffer -- Network Anomaly Analyzer v1.0
Reads audit_output.json, applies rule-based anomaly detection,
and generates a professional HTML audit report.
"""

import json
import re
import sys
import os
from datetime import datetime, timezone

# Fix Windows console encoding (cp1252 cannot handle Unicode box chars/emojis)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
from dataclasses import dataclass, field
from typing import Optional
from html import escape as html_escape


# ============================================================================
#  Configuration — Known Network Baseline
# ============================================================================

BASELINE = {
    "segments": ["10.0.6.0/24", "10.0.5.0/24"],
    "dns_servers": ["1.1.1.1", "8.8.8.8"],
    "dns_provider": "FortiSASE (Fortinet)",
    "gateway_ip": "10.0.5.1",
    "gateway_mac": None,  # Set after first discovery, or manually below
    "blocked_domains": ["facebook.com", "spotify.com", "youtube.com"],
    "machine_ip": "10.0.5.50",
    "machine_segment": "192.168.4",
    "known_cas": [
        "DigiCert", "Let's Encrypt", "Comodo", "Sectigo", "GlobalSign",
        "GeoTrust", "Thawte", "Symantec", "VeriSign", "Entrust",
        "GoDaddy", "Amazon", "Google Trust Services", "Microsoft",
        "Baltimore", "ISRG", "Starfield", "Actalis", "Buypass",
        "QuoVadis", "SwissSign", "T-Systems", "Certum", "IdenTrust",
        "Trustwave", "SSL.com", "ZeroSSL", "USERTrust",
        "CloudFlare", "Cloudflare", "Apple", "Meta", "Facebook",
        "WhatsApp", "Fastly", "Akamai",
    ],
    "latency_spike_threshold_ms": 100,
}

# Allow manual gateway MAC override
# BASELINE["gateway_mac"] = "aa:bb:cc:dd:ee:ff"

INPUT_FILE = "audit_output.json"
OUTPUT_FILE = "audit_report.html"


# ============================================================================
#  Data Structures
# ============================================================================

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    """Represents a single anomaly finding."""
    id: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    category: str
    description: str
    evidence: str
    recommendation: str
    cve_ref: Optional[str] = None


# ============================================================================
#  Anomaly Detection Rules
# ============================================================================

class AnomalyDetector:
    """Rule-based anomaly detection engine."""

    def __init__(self, data: dict):
        self.data = data
        self.findings: list[Finding] = []
        self.finding_counter = 0
        self.baseline = data.get("baseline", BASELINE)
        # Merge defaults for keys not in the JSON baseline
        for k, v in BASELINE.items():
            if k not in self.baseline:
                self.baseline[k] = v

    def _next_id(self) -> str:
        self.finding_counter += 1
        return f"NET-{self.finding_counter:03d}"

    def add_finding(self, **kwargs):
        kwargs["id"] = self._next_id()
        self.findings.append(Finding(**kwargs))

    # ── Rule 1: Blocked domains resolving ──────────────────────────────
    def check_blocked_domains(self):
        """Blocked domains (facebook, spotify, youtube) should NOT resolve."""
        blocked = self.baseline.get("blocked_domains", [])
        nslookup_entries = self.data.get("dns", {}).get("nslookup", [])

        for entry in nslookup_entries:
            domain = entry.get("domain", "")
            output = entry.get("output", "")

            # Check if this domain should be blocked
            is_blocked = any(b in domain for b in blocked)
            if not is_blocked:
                continue

            # Check if it resolved to an address (contains "Address:" lines after the server line)
            lines = output.split("\\n") if "\\n" in output else output.split("\n")
            resolved_ips = []
            past_server = False
            for line in lines:
                if "Server:" in line or "server:" in line:
                    past_server = True
                    continue
                if past_server and re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', line):
                    ip = re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', line).group(1)
                    resolved_ips.append(ip)
                # Also catch "Name:" + "Address:" patterns
                if re.search(r'name\s*=|Name:', line, re.IGNORECASE):
                    past_server = True

            # Check for NXDOMAIN / SERVFAIL / no answer
            has_nxdomain = any(kw in output.upper() for kw in ["NXDOMAIN", "SERVFAIL", "** SERVER CAN'T FIND", "NO ANSWER", "TIMED OUT", "connection timed out"])

            if resolved_ips and not has_nxdomain:
                self.add_finding(
                    title=f"Blocked domain '{domain}' is resolving",
                    severity="CRITICAL",
                    category="DNS Policy Violation",
                    description=(
                        f"The domain '{domain}' is configured as blocked in the "
                        f"FortiSASE policy, but DNS resolution returned valid IP addresses. "
                        f"This indicates the DNS filtering policy is being bypassed or is "
                        f"misconfigured."
                    ),
                    evidence=f"Resolved IPs: {', '.join(resolved_ips)}",
                    recommendation=(
                        "Verify FortiSASE DNS filtering rules for this domain. Check if "
                        "the client is using the designated DNS servers (1.1.1.1, 8.8.8.8). "
                        "Investigate possible DNS-over-HTTPS bypass."
                    ),
                )
            elif has_nxdomain or not resolved_ips:
                # Domain is correctly blocked — no finding, but we can note it
                pass

    # ── Rule 2: Primary DNS timeout ────────────────────────────────────
    def check_dns_timeout(self):
        """Detect if primary DNS (1.1.1.1) is timing out."""
        dig_entries = self.data.get("dns", {}).get("dig", [])
        primary_dns = self.baseline.get("dns_servers", ["1.1.1.1"])[0]

        for entry in dig_entries:
            output = entry.get("output", "")
            domain = entry.get("domain", "")

            # Look for timeout indicators
            timeout_indicators = [
                "connection timed out",
                "no servers could be reached",
                "timed out",
                ";; connection timed out; no servers could be reached",
                "communications error",
            ]

            is_timeout = any(t in output.lower() for t in timeout_indicators)

            # Check if the query was made against the primary DNS
            uses_primary = primary_dns in output

            if is_timeout:
                severity = "HIGH" if uses_primary else "MEDIUM"
                self.add_finding(
                    title=f"DNS timeout for '{domain}'",
                    severity=severity,
                    category="DNS Availability",
                    description=(
                        f"DNS query for '{domain}' timed out. "
                        f"{'Primary DNS server ' + primary_dns + ' appears unreachable.' if uses_primary else 'A DNS server is not responding.'} "
                        f"This may indicate network connectivity issues, DNS server overload, "
                        f"or firewall blocking."
                    ),
                    evidence=self._truncate(output, 300),
                    recommendation=(
                        f"Check connectivity to {primary_dns}. Verify FortiSASE tunnel status. "
                        f"Test with: dig @{primary_dns} {domain} +timeout=10"
                    ),
                )

    # ── Rule 3: Cross-segment ARP entries ──────────────────────────────
    def check_cross_segment_arp(self):
        """Detect ARP entries from other segments (e.g., 192.168.3.x on 192.168.4.x)."""
        arp_output = self.data.get("network_config", {}).get("arp_table", "")
        machine_segment = self.baseline.get("machine_segment", "192.168.4")
        segments = self.baseline.get("segments", [])

        # Determine "other" segments
        other_segments = []
        for seg in segments:
            prefix = seg.rsplit(".", 1)[0]  # e.g., "192.168.3"
            if prefix != machine_segment:
                other_segments.append(prefix)

        if not other_segments:
            return

        lines = arp_output.split("\\n") if "\\n" in arp_output else arp_output.split("\n")
        cross_entries = []

        for line in lines:
            for other_seg in other_segments:
                if other_seg + "." in line:
                    # Extract the IP
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        cross_entries.append({
                            "ip": ip_match.group(1),
                            "segment": other_seg,
                            "raw_line": line.strip(),
                        })

        if cross_entries:
            ips = [e["ip"] for e in cross_entries]
            self.add_finding(
                title=f"Cross-segment ARP entries detected ({len(cross_entries)} entries)",
                severity="HIGH",
                category="Network Segmentation",
                description=(
                    f"ARP table on machine {self.baseline.get('machine_ip', 'N/A')} "
                    f"(segment {machine_segment}.0/24) contains entries from other segments: "
                    f"{', '.join(set(e['segment'] for e in cross_entries))}. "
                    f"This indicates improper VLAN segmentation, routing leakage, or "
                    f"potential ARP spoofing."
                ),
                evidence=f"Cross-segment IPs: {', '.join(ips[:10])}",
                recommendation=(
                    "Review VLAN and switch configurations. Verify that inter-VLAN routing "
                    "is properly restricted. Check for rogue devices bridging segments. "
                    "Investigate possible ARP spoofing attacks."
                ),
            )

    # ── Rule 4: SSL certificate issuer validation ──────────────────────
    def check_ssl_certificates(self):
        """Detect SSL certificates not issued by known public CAs."""
        ssl_entries = self.data.get("ssl_certificates", [])
        known_cas = self.baseline.get("known_cas", BASELINE["known_cas"])

        for entry in ssl_entries:
            domain = entry.get("domain", "")
            output = entry.get("output", "")

            # Parse issuer
            issuer_match = re.search(r'issuer\s*=\s*(.*?)(?:\\n|\n|$)', output, re.IGNORECASE)
            if not issuer_match:
                # Could not retrieve certificate — possible interception or block
                if "connect:" in output.lower() or "error" in output.lower() or "unable" in output.lower():
                    self.add_finding(
                        title=f"SSL connection failed for '{domain}'",
                        severity="MEDIUM",
                        category="SSL/TLS Security",
                        description=(
                            f"Could not establish SSL/TLS connection to '{domain}'. "
                            f"The connection may be blocked by the firewall, or the "
                            f"domain may be intercepted."
                        ),
                        evidence=self._truncate(output, 300),
                        recommendation=(
                            "Check if the domain is blocked by FortiSASE. "
                            "Verify SSL inspection policies."
                        ),
                    )
                continue

            issuer_line = issuer_match.group(1).strip()

            # Check if issuer matches any known CA
            is_known = any(ca.lower() in issuer_line.lower() for ca in known_cas)

            if not is_known:
                self.add_finding(
                    title=f"Unknown SSL certificate issuer for '{domain}'",
                    severity="CRITICAL",
                    category="SSL/TLS Security",
                    description=(
                        f"The SSL certificate for '{domain}' was issued by an "
                        f"unrecognized Certificate Authority. This may indicate "
                        f"SSL/TLS interception (MITM), a self-signed certificate, "
                        f"or a corporate proxy performing deep packet inspection."
                    ),
                    evidence=f"Issuer: {issuer_line}",
                    recommendation=(
                        "Verify if the issuer is a legitimate corporate CA (e.g., "
                        "FortiSASE SSL inspection CA). If unexpected, investigate "
                        "for potential MITM attacks. Compare with expected issuer chain."
                    ),
                )

    # ── Rule 5: Traceroute latency spikes ──────────────────────────────
    def check_traceroute_latency(self):
        """Detect latency spikes > 100ms between consecutive hops."""
        traceroute_entries = self.data.get("traceroute", [])
        threshold = self.baseline.get("latency_spike_threshold_ms", 100)

        for entry in traceroute_entries:
            domain = entry.get("domain", "")
            output = entry.get("output", "")

            lines = output.split("\\n") if "\\n" in output else output.split("\n")
            prev_latency = None
            prev_hop = None

            for line in lines:
                # Match hop lines: " 1  10.0.5.1  1.234 ms  ..."
                hop_match = re.match(r'\s*(\d+)\s+', line)
                if not hop_match:
                    continue

                hop_num = int(hop_match.group(1))

                # Extract latency values (in ms)
                latencies = re.findall(r'([\d.]+)\s*ms', line)
                if not latencies:
                    # Hop with * * * (timeout)
                    prev_latency = None
                    prev_hop = hop_num
                    continue

                # Use the minimum latency for this hop
                try:
                    min_latency = min(float(l) for l in latencies)
                except ValueError:
                    continue

                if prev_latency is not None and prev_hop is not None:
                    delta = min_latency - prev_latency
                    if delta > threshold:
                        self.add_finding(
                            title=f"Traceroute latency spike to '{domain}' (hop {prev_hop}→{hop_num})",
                            severity="MEDIUM",
                            category="Network Performance",
                            description=(
                                f"A latency spike of {delta:.1f}ms was detected between "
                                f"hop {prev_hop} ({prev_latency:.1f}ms) and hop {hop_num} "
                                f"({min_latency:.1f}ms) in traceroute to '{domain}'. "
                                f"Threshold: {threshold}ms. This may indicate congested "
                                f"links, geographic distance, or traffic inspection."
                            ),
                            evidence=f"Hop {prev_hop}: {prev_latency:.1f}ms → Hop {hop_num}: {min_latency:.1f}ms (Δ{delta:.1f}ms)",
                            recommendation=(
                                "Investigate the network path between these hops. "
                                "Check for congested links, QoS policies, or "
                                "deep packet inspection appliances."
                            ),
                        )

                prev_latency = min_latency
                prev_hop = hop_num

    # ── Rule 6: Gateway MAC mismatch ───────────────────────────────────
    def check_gateway_mac(self):
        """Detect gateway MAC mismatch (potential ARP spoofing)."""
        arp_output = self.data.get("network_config", {}).get("arp_table", "")
        gateway_ip = self.baseline.get("gateway_ip", self.baseline.get("gateway", "10.0.5.1"))
        known_mac = self.baseline.get("gateway_mac")

        lines = arp_output.split("\\n") if "\\n" in arp_output else arp_output.split("\n")

        gateway_mac_found = None
        for line in lines:
            if gateway_ip in line:
                # Extract MAC address (various formats)
                mac_match = re.search(r'((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', line)
                if mac_match:
                    gateway_mac_found = mac_match.group(1).lower()
                    break

        if gateway_mac_found is None:
            self.add_finding(
                title="Gateway not found in ARP table",
                severity="MEDIUM",
                category="Network Configuration",
                description=(
                    f"The default gateway {gateway_ip} was not found in the ARP table. "
                    f"This may indicate the gateway is unreachable or ARP entries have expired."
                ),
                evidence="Gateway IP not present in ARP table output.",
                recommendation=(
                    f"Verify gateway reachability: ping {gateway_ip}. "
                    f"Check network cable and switch port status."
                ),
            )
            return

        if known_mac and gateway_mac_found != known_mac.lower():
            self.add_finding(
                title="Gateway MAC address mismatch — possible ARP spoofing",
                severity="CRITICAL",
                category="ARP Security",
                description=(
                    f"The MAC address for gateway {gateway_ip} is '{gateway_mac_found}', "
                    f"but the known baseline MAC is '{known_mac}'. This mismatch may indicate "
                    f"ARP spoofing, a rogue device, or a legitimate infrastructure change."
                ),
                evidence=f"Expected MAC: {known_mac} | Found MAC: {gateway_mac_found}",
                recommendation=(
                    "IMMEDIATELY investigate: compare with switch MAC address table. "
                    "Enable Dynamic ARP Inspection (DAI) on managed switches. "
                    "If this is a planned change, update the baseline."
                ),
            )
        else:
            # Store discovered MAC for reference if no baseline was set
            if not known_mac:
                self.baseline["gateway_mac"] = gateway_mac_found

    # ── Additional: Check resolv.conf DNS configuration ────────────────
    def check_resolv_conf(self):
        """Verify resolv.conf uses the expected DNS servers."""
        resolv_output = self.data.get("network_config", {}).get("resolv_conf", "")
        expected_dns = self.baseline.get("dns_servers", [])

        lines = resolv_output.split("\\n") if "\\n" in resolv_output else resolv_output.split("\n")
        configured_dns = []
        for line in lines:
            ns_match = re.match(r'\s*nameserver\s+([\d.]+)', line)
            if ns_match:
                configured_dns.append(ns_match.group(1))

        # Check for unexpected DNS servers
        unexpected = [dns for dns in configured_dns if dns not in expected_dns]
        if unexpected:
            self.add_finding(
                title="Unexpected DNS servers in resolv.conf",
                severity="HIGH",
                category="DNS Configuration",
                description=(
                    f"The system's resolv.conf contains DNS servers not in the "
                    f"approved baseline: {', '.join(unexpected)}. Expected servers: "
                    f"{', '.join(expected_dns)}. Unauthorized DNS could bypass "
                    f"FortiSASE filtering policies."
                ),
                evidence=f"Configured: {', '.join(configured_dns)} | Expected: {', '.join(expected_dns)}",
                recommendation=(
                    "Reconfigure DNS to use approved FortiSASE servers. "
                    "Investigate how unauthorized DNS servers were added. "
                    "Consider enforcing DNS through DHCP and firewall rules."
                ),
            )

        # Check if expected DNS are missing
        missing = [dns for dns in expected_dns if dns not in configured_dns]
        if missing and configured_dns:
            self.add_finding(
                title="Expected DNS servers missing from resolv.conf",
                severity="MEDIUM",
                category="DNS Configuration",
                description=(
                    f"The following expected DNS servers are not configured: "
                    f"{', '.join(missing)}."
                ),
                evidence=f"Missing: {', '.join(missing)} | Configured: {', '.join(configured_dns)}",
                recommendation=(
                    "Add the missing FortiSASE DNS servers to the network configuration."
                ),
            )

    # ── Utility ────────────────────────────────────────────────────────
    @staticmethod
    def _truncate(text: str, max_len: int = 300) -> str:
        if len(text) > max_len:
            return text[:max_len] + "... [truncated]"
        return text

    # ── Run All Rules ──────────────────────────────────────────────────
    def run_all(self) -> list[Finding]:
        """Execute all anomaly detection rules."""
        rules = [
            ("Blocked Domain Resolution", self.check_blocked_domains),
            ("DNS Timeout Detection", self.check_dns_timeout),
            ("Cross-Segment ARP", self.check_cross_segment_arp),
            ("SSL Certificate Validation", self.check_ssl_certificates),
            ("Traceroute Latency Analysis", self.check_traceroute_latency),
            ("Gateway MAC Verification", self.check_gateway_mac),
            ("DNS Configuration Audit", self.check_resolv_conf),
        ]

        print("\n🔍 Running anomaly detection rules...\n")
        for name, rule_fn in rules:
            print(f"  ▶ {name}...")
            try:
                rule_fn()
            except Exception as e:
                print(f"    ⚠ Error in rule '{name}': {e}")

        # Sort findings by severity
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        print(f"\n✅ Analysis complete: {len(self.findings)} findings detected.\n")
        return self.findings


# ============================================================================
#  HTML Report Generator
# ============================================================================

class ReportGenerator:
    """Generates a professional HTML audit report."""

    SEVERITY_COLORS = {
        "CRITICAL": {"bg": "#dc2626", "text": "#fff", "border": "#991b1b", "glow": "rgba(220,38,38,0.3)"},
        "HIGH":     {"bg": "#ea580c", "text": "#fff", "border": "#c2410c", "glow": "rgba(234,88,12,0.3)"},
        "MEDIUM":   {"bg": "#d97706", "text": "#fff", "border": "#b45309", "glow": "rgba(217,119,6,0.3)"},
        "LOW":      {"bg": "#0284c7", "text": "#fff", "border": "#0369a1", "glow": "rgba(2,132,199,0.3)"},
        "INFO":     {"bg": "#6b7280", "text": "#fff", "border": "#4b5563", "glow": "rgba(107,114,128,0.3)"},
    }

    SEVERITY_ICONS = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🔵",
        "INFO":     "⚪",
    }

    def __init__(self, data: dict, findings: list[Finding]):
        self.data = data
        self.findings = findings
        self.metadata = data.get("metadata", {})
        self.baseline = data.get("baseline", BASELINE)

    def _severity_badge(self, severity: str) -> str:
        colors = self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS["INFO"])
        icon = self.SEVERITY_ICONS.get(severity, "⚪")
        return (
            f'<span class="badge" style="background:{colors["bg"]};color:{colors["text"]};'
            f'border:1px solid {colors["border"]};box-shadow:0 0 12px {colors["glow"]}">'
            f'{icon} {severity}</span>'
        )

    def _summary_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def generate(self) -> str:
        counts = self._summary_counts()
        total = len(self.findings)
        timestamp = self.metadata.get("timestamp", datetime.now(timezone.utc).isoformat())
        hostname = html_escape(self.metadata.get("hostname", "N/A"))
        user = html_escape(self.metadata.get("user", "N/A"))
        kernel = html_escape(self.metadata.get("kernel", "N/A"))
        os_info = html_escape(self.metadata.get("os", "N/A"))

        # Risk score (weighted)
        risk_score = counts["CRITICAL"] * 40 + counts["HIGH"] * 25 + counts["MEDIUM"] * 10 + counts["LOW"] * 5
        risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 20 else "LOW"
        risk_color_map = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#22c55e"}
        risk_color = risk_color_map.get(risk_label, "#6b7280")

        # Build summary cards
        summary_cards = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            colors = self.SEVERITY_COLORS[sev]
            icon = self.SEVERITY_ICONS[sev]
            summary_cards += f'''
            <div class="summary-card" style="border-left:4px solid {colors["bg"]}">
                <div class="card-count" style="color:{colors["bg"]}">{counts[sev]}</div>
                <div class="card-label">{icon} {sev}</div>
            </div>'''

        # Build findings table rows
        table_rows = ""
        for f in self.findings:
            table_rows += f'''
            <tr>
                <td class="mono">{html_escape(f.id)}</td>
                <td>{self._severity_badge(f.severity)}</td>
                <td>{html_escape(f.category)}</td>
                <td><strong>{html_escape(f.title)}</strong></td>
            </tr>'''

        # Build detailed findings
        detail_cards = ""
        for f in self.findings:
            colors = self.SEVERITY_COLORS.get(f.severity, self.SEVERITY_COLORS["INFO"])
            detail_cards += f'''
            <div class="finding-card" style="border-left:4px solid {colors["bg"]}">
                <div class="finding-header">
                    <span class="finding-id">{html_escape(f.id)}</span>
                    {self._severity_badge(f.severity)}
                    <span class="finding-category">{html_escape(f.category)}</span>
                </div>
                <h3>{html_escape(f.title)}</h3>
                <div class="finding-body">
                    <div class="finding-section">
                        <h4>📋 Description</h4>
                        <p>{html_escape(f.description)}</p>
                    </div>
                    <div class="finding-section evidence">
                        <h4>🔎 Evidence</h4>
                        <pre>{html_escape(f.evidence)}</pre>
                    </div>
                    <div class="finding-section recommendation">
                        <h4>🛡️ Recommendation</h4>
                        <p>{html_escape(f.recommendation)}</p>
                    </div>
                </div>
            </div>'''

        # Build network baseline section
        baseline_html = f'''
        <div class="baseline-grid">
            <div class="baseline-item">
                <span class="bl-label">Network Segments</span>
                <span class="bl-value">{', '.join(self.baseline.get('segments', []))}</span>
            </div>
            <div class="baseline-item">
                <span class="bl-label">DNS Servers</span>
                <span class="bl-value">{', '.join(self.baseline.get('dns_servers', []))}</span>
            </div>
            <div class="baseline-item">
                <span class="bl-label">DNS Provider</span>
                <span class="bl-value">{html_escape(self.baseline.get('dns_provider', 'N/A'))}</span>
            </div>
            <div class="baseline-item">
                <span class="bl-label">Default Gateway</span>
                <span class="bl-value">{html_escape(self.baseline.get('gateway', self.baseline.get('gateway_ip', 'N/A')))}</span>
            </div>
            <div class="baseline-item">
                <span class="bl-label">Machine IP</span>
                <span class="bl-value">{html_escape(self.baseline.get('machine_ip', 'N/A'))}</span>
            </div>
            <div class="baseline-item">
                <span class="bl-label">Blocked Domains</span>
                <span class="bl-value">{', '.join(self.baseline.get('blocked_domains', []))}</span>
            </div>
        </div>'''

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Network Anomaly Detection Audit Report generated by NetSniffer">
    <title>NetSniffer — Network Audit Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #1a1f35;
            --bg-card-hover: #222845;
            --border-color: #2a3055;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent: #6366f1;
            --accent-glow: rgba(99,102,241,0.15);
            --gradient-1: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%);
            --gradient-2: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
            --gradient-header: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            --shadow-lg: 0 10px 40px rgba(0,0,0,0.4);
            --shadow-card: 0 4px 20px rgba(0,0,0,0.3);
            --radius: 12px;
            --radius-sm: 8px;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
        }}

        /* ── Header ── */
        .report-header {{
            background: var(--gradient-header);
            border-bottom: 1px solid var(--border-color);
            padding: 48px 0 40px;
            position: relative;
            overflow: hidden;
        }}

        .report-header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%);
            pointer-events: none;
        }}

        .report-header::after {{
            content: '';
            position: absolute;
            bottom: -30%;
            left: -5%;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, rgba(139,92,246,0.08) 0%, transparent 70%);
            pointer-events: none;
        }}

        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 32px;
            position: relative;
            z-index: 1;
        }}

        .logo {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .logo-icon {{
            width: 52px;
            height: 52px;
            background: var(--gradient-1);
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: 0 4px 20px rgba(99,102,241,0.3);
        }}

        .logo-text h1 {{
            font-size: 26px;
            font-weight: 800;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }}

        .logo-text p {{
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 400;
            margin-top: 2px;
        }}

        .report-badge {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 10px 18px;
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .header-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            position: relative;
            z-index: 1;
        }}

        .info-item {{
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: var(--radius-sm);
            padding: 14px 18px;
            backdrop-filter: blur(10px);
        }}

        .info-item .label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 4px;
            font-weight: 600;
        }}

        .info-item .value {{
            font-size: 14px;
            color: var(--text-primary);
            font-weight: 500;
        }}

        /* ── Risk Score ── */
        .risk-banner {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 28px 32px;
            margin: -24px 0 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 24px;
            box-shadow: var(--shadow-lg);
            position: relative;
            z-index: 2;
        }}

        .risk-score {{
            display: flex;
            align-items: center;
            gap: 20px;
        }}

        .risk-circle {{
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            border: 3px solid;
            font-weight: 800;
            font-size: 28px;
        }}

        .risk-circle small {{
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.8;
        }}

        .risk-details h2 {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 4px;
        }}

        .risk-details p {{
            font-size: 13px;
            color: var(--text-secondary);
        }}

        /* ── Summary Cards ── */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 36px;
        }}

        .summary-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 24px;
            text-align: center;
            transition: all 0.3s ease;
            box-shadow: var(--shadow-card);
        }}

        .summary-card:hover {{
            transform: translateY(-2px);
            background: var(--bg-card-hover);
        }}

        .card-count {{
            font-size: 42px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 8px;
        }}

        .card-label {{
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        /* ── Section Headers ── */
        .section {{
            margin-bottom: 40px;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
        }}

        .section-header h2 {{
            font-size: 20px;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .section-header .section-icon {{
            font-size: 22px;
        }}

        .section-header .section-count {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 4px 14px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            margin-left: auto;
        }}

        /* ── Findings Table ── */
        .findings-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: var(--shadow-card);
        }}

        .findings-table th {{
            background: rgba(99,102,241,0.08);
            padding: 14px 20px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-muted);
            font-weight: 700;
            border-bottom: 1px solid var(--border-color);
        }}

        .findings-table td {{
            padding: 14px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            font-size: 14px;
            vertical-align: middle;
        }}

        .findings-table tr:last-child td {{
            border-bottom: none;
        }}

        .findings-table tr:hover td {{
            background: rgba(255,255,255,0.02);
        }}

        .mono {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: var(--accent);
            font-weight: 500;
        }}

        /* ── Badge ── */
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }}

        /* ── Finding Cards ── */
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 0;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: var(--shadow-card);
            transition: all 0.3s ease;
        }}

        .finding-card:hover {{
            box-shadow: 0 8px 30px rgba(0,0,0,0.4);
            transform: translateY(-1px);
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px 24px;
            background: rgba(255,255,255,0.02);
            border-bottom: 1px solid rgba(255,255,255,0.04);
        }}

        .finding-id {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: var(--accent);
            font-weight: 600;
        }}

        .finding-category {{
            margin-left: auto;
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 500;
        }}

        .finding-card h3 {{
            padding: 16px 24px 0;
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .finding-body {{
            padding: 16px 24px 24px;
        }}

        .finding-section {{
            margin-bottom: 16px;
        }}

        .finding-section:last-child {{
            margin-bottom: 0;
        }}

        .finding-section h4 {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-muted);
            margin-bottom: 8px;
            font-weight: 700;
        }}

        .finding-section p {{
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.7;
        }}

        .finding-section pre {{
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: var(--radius-sm);
            padding: 14px 18px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #e2e8f0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        .finding-section.evidence {{
            background: rgba(0,0,0,0.15);
            border-radius: var(--radius-sm);
            padding: 16px;
            margin-left: -8px;
            margin-right: -8px;
        }}

        .finding-section.recommendation {{
            background: rgba(99,102,241,0.05);
            border: 1px solid rgba(99,102,241,0.1);
            border-radius: var(--radius-sm);
            padding: 16px;
            margin-left: -8px;
            margin-right: -8px;
        }}

        .finding-section.recommendation p {{
            color: #a5b4fc;
        }}

        /* ── Baseline ── */
        .baseline-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
        }}

        .baseline-item {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .bl-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            font-weight: 700;
        }}

        .bl-value {{
            font-size: 14px;
            color: var(--text-primary);
            font-weight: 500;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* ── Footer ── */
        .report-footer {{
            text-align: center;
            padding: 32px 0;
            border-top: 1px solid var(--border-color);
            margin-top: 48px;
        }}

        .report-footer p {{
            font-size: 12px;
            color: var(--text-muted);
        }}

        .report-footer .footer-brand {{
            font-weight: 700;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        /* ── No Findings ── */
        .no-findings {{
            text-align: center;
            padding: 60px 32px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
        }}

        .no-findings .icon {{
            font-size: 48px;
            margin-bottom: 16px;
        }}

        .no-findings h3 {{
            font-size: 20px;
            margin-bottom: 8px;
            color: #22c55e;
        }}

        .no-findings p {{
            color: var(--text-secondary);
            font-size: 14px;
        }}

        /* ── Print ── */
        @media print {{
            body {{
                background: #fff;
                color: #1a1a1a;
            }}

            .container {{ max-width: 100%; }}

            .report-header {{
                background: #f8fafc;
                border-bottom: 2px solid #e2e8f0;
            }}

            .logo-text h1 {{
                -webkit-text-fill-color: #6366f1;
            }}

            .summary-card, .finding-card, .baseline-item, .risk-banner {{
                background: #fff;
                border-color: #e2e8f0;
                box-shadow: none;
            }}

            .findings-table th {{ background: #f1f5f9; }}

            .finding-section pre {{
                background: #f8fafc;
                border-color: #e2e8f0;
            }}
        }}

        /* ── Responsive ── */
        @media (max-width: 768px) {{
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .header-top {{ flex-direction: column; gap: 16px; }}
            .risk-banner {{ flex-direction: column; text-align: center; }}
            .baseline-grid {{ grid-template-columns: 1fr; }}
        }}

        /* ── Animations ── */
        @keyframes fadeInUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .section {{
            animation: fadeInUp 0.5s ease-out;
        }}

        .finding-card {{
            animation: fadeInUp 0.4s ease-out;
        }}
    </style>
</head>
<body>

<!-- ═══════════════ HEADER ═══════════════ -->
<header class="report-header">
    <div class="container">
        <div class="header-top">
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <div class="logo-text">
                    <h1>NetSniffer</h1>
                    <p>Network Anomaly Detection — Audit Report</p>
                </div>
            </div>
            <div class="report-badge">
                Report generated: {timestamp}
            </div>
        </div>
        <div class="header-info">
            <div class="info-item">
                <div class="label">Hostname</div>
                <div class="value">{hostname}</div>
            </div>
            <div class="info-item">
                <div class="label">Operator</div>
                <div class="value">{user}</div>
            </div>
            <div class="info-item">
                <div class="label">Kernel</div>
                <div class="value">{kernel}</div>
            </div>
            <div class="info-item">
                <div class="label">OS</div>
                <div class="value">{os_info}</div>
            </div>
        </div>
    </div>
</header>

<main class="container">

    <!-- ═══════════════ RISK BANNER ═══════════════ -->
    <div class="risk-banner">
        <div class="risk-score">
            <div class="risk-circle" style="border-color:{risk_color};color:{risk_color}">
                {risk_score}
                <small>Score</small>
            </div>
            <div class="risk-details">
                <h2>Overall Risk: {risk_label}</h2>
                <p>{total} finding{"s" if total != 1 else ""} detected across {len(set(f.category for f in self.findings)) if self.findings else 0} categories</p>
            </div>
        </div>
        <div>
            {self._severity_badge(risk_label)}
        </div>
    </div>

    <!-- ═══════════════ SUMMARY CARDS ═══════════════ -->
    <div class="section">
        <div class="section-header">
            <span class="section-icon">📊</span>
            <h2>Findings Summary</h2>
        </div>
        <div class="summary-grid">
            {summary_cards}
        </div>
    </div>

    <!-- ═══════════════ FINDINGS TABLE ═══════════════ -->
    <div class="section">
        <div class="section-header">
            <span class="section-icon">📋</span>
            <h2>Findings Index</h2>
            <span class="section-count">{total} total</span>
        </div>
        {"" if not self.findings else f"""
        <table class="findings-table">
            <thead>
                <tr>
                    <th style="width:90px">ID</th>
                    <th style="width:120px">Severity</th>
                    <th style="width:180px">Category</th>
                    <th>Finding</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>"""}
        {"""
        <div class="no-findings">
            <div class="icon">✅</div>
            <h3>No Anomalies Detected</h3>
            <p>All network checks passed against the known baseline.</p>
        </div>""" if not self.findings else ""}
    </div>

    <!-- ═══════════════ DETAILED FINDINGS ═══════════════ -->
    {"" if not self.findings else f"""
    <div class="section">
        <div class="section-header">
            <span class="section-icon">🔍</span>
            <h2>Detailed Findings</h2>
        </div>
        {detail_cards}
    </div>"""}

    <!-- ═══════════════ BASELINE ═══════════════ -->
    <div class="section">
        <div class="section-header">
            <span class="section-icon">⚙️</span>
            <h2>Network Baseline Configuration</h2>
        </div>
        {baseline_html}
    </div>

</main>

<!-- ═══════════════ FOOTER ═══════════════ -->
<footer class="report-footer">
    <div class="container">
        <p>
            Generated by <span class="footer-brand">NetSniffer v1.0</span> —
            Network Anomaly Detection Suite
        </p>
        <p style="margin-top:6px">
           This report is confidential. Distribution is restricted to authorized personnel only.
        </p>
    </div>
</footer>

</body>
</html>'''

        return html


# ============================================================================
#  Main Execution
# ============================================================================

def main():
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║         NetSniffer — Network Anomaly Analyzer v1.0         ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    # Load audit data
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: '{INPUT_FILE}' not found.")
        print(f"   Run collector.sh first to generate the audit data.")
        sys.exit(1)

    print(f"📂 Loading audit data from '{INPUT_FILE}'...")
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in '{INPUT_FILE}': {e}")
        sys.exit(1)

    print(f"   ✓ Loaded successfully")
    print(f"   ✓ Timestamp: {data.get('metadata', {}).get('timestamp', 'N/A')}")
    print(f"   ✓ Host: {data.get('metadata', {}).get('hostname', 'N/A')}")

    # Run anomaly detection
    detector = AnomalyDetector(data)
    findings = detector.run_all()

    # Print summary to console
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("┌─────────────────────────────────────────┐")
    print("│           FINDINGS SUMMARY              │")
    print("├─────────────────────────────────────────┤")
    for sev, count in counts.items():
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}[sev]
        bar = "█" * count + "░" * (10 - min(count, 10))
        print(f"│  {icon} {sev:<10} {bar}  {count:>3}  │")
    print(f"├─────────────────────────────────────────┤")
    print(f"│  Total findings: {len(findings):<22} │")
    print(f"└─────────────────────────────────────────┘")
    print()

    # List findings
    if findings:
        for f in findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "⚪")
            print(f"  {icon} [{f.id}] [{f.severity}] {f.title}")
        print()

    # Generate HTML report
    print(f"📝 Generating HTML report...")
    generator = ReportGenerator(data, findings)
    html = generator.generate()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"   ✓ Report saved to: {OUTPUT_FILE}")
    print()
    print(f"🌐 Open the report:")
    print(f"   xdg-open {OUTPUT_FILE}")
    print(f"   or: firefox {OUTPUT_FILE}")
    print()


if __name__ == "__main__":
    main()
