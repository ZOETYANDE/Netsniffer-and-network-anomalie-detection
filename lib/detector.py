"""
NetSniffer v2.0 — Anomaly Detection Engine
Rule-based detection comparing live data against baseline.
"""

import re
from dataclasses import dataclass
from typing import Optional

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str
    rule_id: str = ""
    cve_ref: Optional[str] = None


class AnomalyDetector:
    def __init__(self, data: dict, baseline: dict, exceptions: list = None):
        self.data = data
        self.baseline = baseline
        self.exceptions = exceptions or []
        self.findings: list[Finding] = []
        self.counter = 0

    def _id(self) -> str:
        self.counter += 1
        return f"NET-{self.counter:03d}"

    def _add(self, rule_id: str = "", **kw):
        # Check exceptions
        for exc in self.exceptions:
            if exc and exc.get("rule") == rule_id:
                match_str = exc.get("match", "")
                if match_str and match_str in kw.get("evidence", "") + kw.get("title", ""):
                    return  # Suppressed
        kw["id"] = self._id()
        kw["rule_id"] = rule_id
        self.findings.append(Finding(**kw))

    @staticmethod
    def _trunc(text: str, n: int = 300) -> str:
        return text[:n] + "..." if len(text) > n else text

    def _lines(self, text: str) -> list[str]:
        return text.split("\\n") if "\\n" in text else text.split("\n")

    # ── Rule 1: Blocked domains resolving ──
    def check_blocked_domains(self):
        blocked = self.baseline.get("blocked_domains", [])
        for entry in self.data.get("dns", {}).get("nslookup", []):
            domain = entry.get("domain", "")
            output = entry.get("output", "")
            if not any(b in domain for b in blocked):
                continue
            lines = self._lines(output)
            resolved = []
            past_server = False
            for line in lines:
                if "Server:" in line:
                    past_server = True
                    continue
                if past_server:
                    m = re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        resolved.append(m.group(1))
            has_block = any(k in output.upper() for k in ["NXDOMAIN", "SERVFAIL", "CAN'T FIND", "TIMED OUT"])
            if resolved and not has_block:
                self._add(rule_id="blocked_domain_resolving",
                    title=f"Blocked domain '{domain}' is resolving",
                    severity="CRITICAL", category="DNS Policy Violation",
                    description=f"'{domain}' is blocked by FortiSASE policy but DNS returned valid IPs. DNS filtering may be bypassed.",
                    evidence=f"Resolved IPs: {', '.join(resolved)}",
                    recommendation="Verify FortiSASE DNS filtering. Check if client uses designated DNS servers. Investigate DNS-over-HTTPS bypass.")

    # ── Rule 2: DNS timeout ──
    def check_dns_timeout(self):
        primary = self.baseline.get("dns_servers", ["1.1.1.1"])[0]
        keywords = self.baseline.get("dns_timeout_keywords", ["connection timed out", "no servers could be reached", "timed out"])
        for entry in self.data.get("dns", {}).get("dig", []):
            output = entry.get("output", "")
            domain = entry.get("domain", "")
            if any(k in output.lower() for k in keywords):
                uses_primary = primary in output
                self._add(rule_id="dns_timeout",
                    title=f"DNS timeout for '{domain}'",
                    severity="HIGH" if uses_primary else "MEDIUM", category="DNS Availability",
                    description=f"DNS query for '{domain}' timed out. {'Primary DNS ' + primary + ' unreachable.' if uses_primary else 'DNS server not responding.'}",
                    evidence=self._trunc(output), recommendation=f"Check connectivity to {primary}. Verify FortiSASE tunnel status.")

    # ── Rule 3: Cross-segment ARP ──
    def check_cross_segment_arp(self):
        arp = self.data.get("network_config", {}).get("arp_table", "")
        my_seg = self.baseline.get("machine_segment", "192.168.4")
        other_segs = [s.rsplit(".", 1)[0] for s in self.baseline.get("segments", []) if s.rsplit(".", 1)[0] != my_seg]
        if not other_segs:
            return
        cross = []
        for line in self._lines(arp):
            for seg in other_segs:
                if seg + "." in line:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        cross.append(m.group(1))
        if cross:
            self._add(rule_id="cross_segment_arp",
                title=f"Cross-segment ARP entries ({len(cross)} entries)", severity="HIGH", category="Network Segmentation",
                description=f"ARP table on {self.baseline.get('machine_ip', 'N/A')} contains entries from other segments. Possible VLAN leak or ARP spoof.",
                evidence=f"Cross-segment IPs: {', '.join(cross[:10])}", recommendation="Review VLAN config. Check for rogue bridging devices. Investigate ARP spoofing.")

    # ── Rule 4: SSL CA validation ──
    def check_ssl_certificates(self):
        cas = self.baseline.get("known_cas", [])
        for entry in self.data.get("ssl_certificates", []):
            domain = entry.get("domain", "")
            output = entry.get("output", "")
            m = re.search(r'issuer\s*=\s*(.*?)(?:\\n|\n|$)', output, re.IGNORECASE)
            if not m:
                if any(k in output.lower() for k in ["connect:", "error", "unable", "refused"]):
                    self._add(rule_id="ssl_connection_failed", title=f"SSL connection failed for '{domain}'",
                        severity="MEDIUM", category="SSL/TLS Security",
                        description=f"Cannot establish SSL to '{domain}'. May be blocked or intercepted.",
                        evidence=self._trunc(output), recommendation="Check FortiSASE blocking rules.")
                continue
            issuer = m.group(1).strip()
            if not any(ca.lower() in issuer.lower() for ca in cas):
                self._add(rule_id="ssl_unknown_ca",
                    title=f"Unknown SSL CA for '{domain}'", severity="CRITICAL", category="SSL/TLS Security",
                    description=f"Certificate for '{domain}' issued by unrecognized CA. Possible MITM or corporate SSL inspection.",
                    evidence=f"Issuer: {issuer}", recommendation="Verify if issuer is legitimate corporate CA. Investigate for MITM.")

    # ── Rule 5: Traceroute latency spike ──
    def check_traceroute_latency(self):
        threshold = self.baseline.get("latency_spike_threshold_ms", 100)
        for entry in self.data.get("traceroute", []):
            domain = entry.get("domain", "")
            prev_lat, prev_hop = None, None
            for line in self._lines(entry.get("output", "")):
                hm = re.match(r'\s*(\d+)\s+', line)
                if not hm:
                    continue
                hop = int(hm.group(1))
                lats = re.findall(r'([\d.]+)\s*ms', line)
                if not lats:
                    prev_lat, prev_hop = None, hop
                    continue
                try:
                    ml = min(float(x) for x in lats)
                except ValueError:
                    continue
                if prev_lat is not None and (delta := ml - prev_lat) > threshold:
                    self._add(rule_id="traceroute_latency_spike",
                        title=f"Latency spike to '{domain}' (hop {prev_hop}->{hop})", severity="MEDIUM", category="Network Performance",
                        description=f"{delta:.1f}ms spike between hop {prev_hop} ({prev_lat:.1f}ms) and hop {hop} ({ml:.1f}ms). Threshold: {threshold}ms.",
                        evidence=f"Hop {prev_hop}: {prev_lat:.1f}ms -> Hop {hop}: {ml:.1f}ms (D{delta:.1f}ms)",
                        recommendation="Check for congested links, DPI appliances, or geographic routing.")
                prev_lat, prev_hop = ml, hop

    # ── Rule 6: Gateway MAC mismatch ──
    def check_gateway_mac(self):
        arp = self.data.get("network_config", {}).get("arp_table", "")
        gw_raw = self.baseline.get("gateway_ip", self.baseline.get("gateway", "10.0.5.1"))
        gw_ips = gw_raw if isinstance(gw_raw, list) else [gw_raw]
        known_mac = self.baseline.get("gateway_mac")
        lines = self._lines(arp)
        for gw_ip in gw_ips:
            found_mac = None
            for line in lines:
                if gw_ip in line:
                    m = re.search(r'((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', line)
                    if m:
                        found_mac = m.group(1).lower()
                        break
            if found_mac is None:
                self._add(rule_id="gateway_missing", title=f"Gateway {gw_ip} not in ARP table",
                    severity="MEDIUM", category="Network Configuration",
                    description=f"Gateway {gw_ip} not found in ARP table.", evidence=f"{gw_ip} absent",
                    recommendation=f"Verify reachability: ping {gw_ip}")
            elif known_mac and found_mac != known_mac.lower():
                self._add(rule_id="gateway_mac_mismatch",
                    title=f"Gateway {gw_ip} MAC mismatch — ARP spoofing?", severity="CRITICAL", category="ARP Security",
                    description=f"MAC for {gw_ip} is '{found_mac}', expected '{known_mac}'.",
                    evidence=f"Expected: {known_mac} | Found: {found_mac}",
                    recommendation="IMMEDIATELY investigate. Enable Dynamic ARP Inspection.")

    # ── Rule 7: resolv.conf DNS audit ──
    def check_resolv_conf(self):
        resolv = self.data.get("network_config", {}).get("resolv_conf", "")
        expected = self.baseline.get("dns_servers", [])
        configured = [m.group(1) for line in self._lines(resolv) if (m := re.match(r'\s*nameserver\s+([\d.]+)', line))]
        unexpected = [d for d in configured if d not in expected]
        if unexpected:
            self._add(rule_id="unexpected_dns", title="Unexpected DNS servers in resolv.conf",
                severity="HIGH", category="DNS Configuration",
                description=f"Unauthorized DNS: {', '.join(unexpected)}. Expected: {', '.join(expected)}. May bypass FortiSASE filtering.",
                evidence=f"Configured: {', '.join(configured)} | Expected: {', '.join(expected)}",
                recommendation="Reconfigure DNS. Investigate how unauthorized DNS was added.")
        missing = [d for d in expected if d not in configured]
        if missing and configured:
            self._add(rule_id="missing_dns", title="Expected DNS servers missing",
                severity="MEDIUM", category="DNS Configuration",
                description=f"Missing DNS servers: {', '.join(missing)}.",
                evidence=f"Missing: {', '.join(missing)}", recommendation="Add FortiSASE DNS to network config.")

    # ── Rule 8: Certificate expiry warning ──
    def check_cert_expiry(self):
        import re
        from datetime import datetime, timezone
        for entry in self.data.get("ssl_certificates", []):
            domain = entry.get("domain", "")
            output = entry.get("output", "")
            m = re.search(r'notAfter\s*=\s*(.+?)(?:\\n|\n|$)', output)
            if not m:
                continue
            try:
                expiry_str = m.group(1).strip()
                for fmt in ["%b %d %H:%M:%S %Y GMT", "%b  %d %H:%M:%S %Y GMT"]:
                    try:
                        expiry = datetime.strptime(expiry_str, fmt).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        continue
                else:
                    continue
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                if days_left < 0:
                    self._add(rule_id="cert_expired", title=f"Certificate EXPIRED for '{domain}'",
                        severity="CRITICAL", category="SSL/TLS Security",
                        description=f"Certificate expired {abs(days_left)} days ago.",
                        evidence=f"Expiry: {expiry_str}", recommendation="Renew certificate immediately.")
                elif days_left < 30:
                    self._add(rule_id="cert_expiring", title=f"Certificate expiring soon for '{domain}'",
                        severity="HIGH", category="SSL/TLS Security",
                        description=f"Certificate expires in {days_left} days.",
                        evidence=f"Expiry: {expiry_str}", recommendation="Plan certificate renewal.")
            except Exception:
                pass

    # ── Rule 9: Duplicate IPs in ARP ──
    def check_duplicate_ips(self):
        arp = self.data.get("network_config", {}).get("arp_table", "")
        ip_macs = {}
        for line in self._lines(arp):
            ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            mac_m = re.search(r'((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', line)
            if ip_m and mac_m:
                ip, mac = ip_m.group(1), mac_m.group(1).lower()
                if ip in ip_macs and ip_macs[ip] != mac:
                    self._add(rule_id="duplicate_ip", title=f"Duplicate IP detected: {ip}",
                        severity="HIGH", category="ARP Security",
                        description=f"IP {ip} has multiple MAC addresses. Possible ARP spoofing.",
                        evidence=f"{ip}: {ip_macs[ip]} vs {mac}",
                        recommendation="Investigate for ARP spoofing or IP conflict.")
                ip_macs[ip] = mac

    # ── Rule 10: Open sensitive ports ──
    def check_open_ports(self):
        ports_output = self.data.get("network_config", {}).get("open_ports", "")
        if "nmap not available" in ports_output:
            return
        risky_ports = {21: "FTP", 23: "Telnet", 25: "SMTP", 445: "SMB", 3389: "RDP",
                       5900: "VNC", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                       6379: "Redis", 27017: "MongoDB", 11211: "Memcached"}
        for port, svc in risky_ports.items():
            if re.search(rf'{port}/tcp\s+open', ports_output):
                self._add(rule_id="risky_open_port", title=f"Sensitive port open: {port}/{svc}",
                    severity="MEDIUM" if port in (25, 445) else "HIGH", category="Port Security",
                    description=f"Port {port} ({svc}) is open. This may expose sensitive services.",
                    evidence=f"nmap: {port}/tcp open",
                    recommendation=f"Verify if {svc} should be exposed. Apply firewall rules.")

    # ── Rule 11: Rogue Device Detection ──
    def check_rogue_devices(self):
        auth_devices = self.baseline.get("authorized_devices", [])
        if not auth_devices:
            return  # Skip if no authorized devices configured
        
        auth_set = {d.lower() for d in auth_devices}
        
        for entry in self.data.get("subnet_scans", []):
            segment = entry.get("segment", "")
            output = entry.get("output", "")
            
            # Parse nmap output for IPs and MACs
            current_ip = None
            for line in self._lines(output):
                ip_match = re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_ip = ip_match.group(1)
                    
                mac_match = re.search(r'MAC Address:\s*((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', line)
                if mac_match and current_ip:
                    mac = mac_match.group(1).lower()
                    if current_ip not in auth_set and mac not in auth_set:
                        self._add(rule_id="rogue_device", title=f"Unauthorized device active on {segment}",
                            severity="HIGH", category="Asset Discovery",
                            description=f"Device at IP {current_ip} (MAC: {mac}) is active but NOT in the authorized_devices baseline.",
                            evidence=f"IP: {current_ip} | MAC: {mac}",
                            recommendation="Investigate device to rule out Shadow IT or rogue intrusion. Add to baseline.yml if legitimate.")
                    current_ip = None

    # ── Run All ──
    def run_all(self) -> list[Finding]:
        rules = [
            ("Blocked Domain Resolution",   self.check_blocked_domains),
            ("DNS Timeout Detection",        self.check_dns_timeout),
            ("Cross-Segment ARP",            self.check_cross_segment_arp),
            ("SSL Certificate Validation",   self.check_ssl_certificates),
            ("Certificate Expiry Check",     self.check_cert_expiry),
            ("Traceroute Latency Analysis",  self.check_traceroute_latency),
            ("Gateway MAC Verification",     self.check_gateway_mac),
            ("DNS Configuration Audit",      self.check_resolv_conf),
            ("Duplicate IP Detection",       self.check_duplicate_ips),
            ("Open Port Analysis",           self.check_open_ports),
            ("Stealth Rogue Device Check",   self.check_rogue_devices),
        ]
        print("\n[*] Running anomaly detection (11 rules)...\n")
        for name, fn in rules:
            print(f"  > {name}...")
            try:
                fn()
            except Exception as e:
                print(f"    [!] Error: {e}")
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        print(f"\n[+] Analysis complete: {len(self.findings)} findings.\n")
        return self.findings
