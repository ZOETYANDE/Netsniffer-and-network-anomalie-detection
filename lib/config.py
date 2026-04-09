"""
NetSniffer v2.0 — Configuration Loader
Reads baseline.yml and exceptions.yml
"""

import os
import sys

# Default baseline (used when no YAML config is available)
DEFAULT_BASELINE = {
    "segments": ["10.0.6.0/24", "10.0.5.0/24"],
    "dns_servers": ["1.1.1.1", "8.8.8.8", "208.67.222.222", "208.67.220.220"],
    "dns_provider": "FortiSASE (Fortinet)",
    "gateway": ["10.0.5.1", "192.168.3.1"],
    "gateway_mac": None,
    "authorized_devices": [],
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
        "WhatsApp", "Fastly", "Akamai", "Certainly",
    ],
    "external_services": [
        "web.whatsapp.com", "www.facebook.com", "open.spotify.com", "google.com",
    ],
    "latency_spike_threshold_ms": 100,
}

DEFAULT_ORG = {
    "name": "IT Security Audit",
    "auditor": "Auditeur SI",
    "classification": "CONFIDENTIAL",
}


def load_yaml_config(config_path):
    """Load baseline.yml and return merged config dict."""
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML not installed. Using default config.")
        print("    Install with: pip install PyYAML")
        return DEFAULT_BASELINE.copy(), DEFAULT_ORG.copy(), []

    if not os.path.exists(config_path):
        print(f"[!] Config not found: {config_path} — using defaults")
        return DEFAULT_BASELINE.copy(), DEFAULT_ORG.copy(), []

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    # Build baseline from YAML
    baseline = DEFAULT_BASELINE.copy()
    net = cfg.get("network", {})
    if net.get("segments"):
        baseline["segments"] = net["segments"]
    if net.get("machine_ip"):
        baseline["machine_ip"] = net["machine_ip"]
    if net.get("machine_segment"):
        baseline["machine_segment"] = net["machine_segment"]

    # Gateways
    gw_list = cfg.get("gateways", [])
    if gw_list:
        baseline["gateway"] = [g["ip"] for g in gw_list if "ip" in g]
        # Use first gateway MAC as baseline if set
        for g in gw_list:
            if g.get("mac"):
                baseline["gateway_mac"] = g["mac"]
                break

    # DNS
    dns_cfg = cfg.get("dns", {})
    if dns_cfg.get("servers"):
        baseline["dns_servers"] = dns_cfg["servers"]
    if dns_cfg.get("provider"):
        baseline["dns_provider"] = dns_cfg["provider"]

    # Blocked domains
    if cfg.get("blocked_domains"):
        baseline["blocked_domains"] = cfg["blocked_domains"]

    # Authorized devices
    if cfg.get("authorized_devices"):
        baseline["authorized_devices"] = cfg["authorized_devices"]

    # Known CAs
    if cfg.get("known_cas"):
        baseline["known_cas"] = cfg["known_cas"]

    # External services (cert expiry suppressed for these)
    if cfg.get("external_services"):
        baseline["external_services"] = cfg["external_services"]

    # Thresholds
    thresholds = cfg.get("thresholds", {})
    if thresholds.get("latency_spike_ms"):
        baseline["latency_spike_threshold_ms"] = thresholds["latency_spike_ms"]

    # Organization
    org = cfg.get("organization", DEFAULT_ORG)

    return baseline, org, []


def load_exceptions(exceptions_path):
    """Load exceptions/allowlist from YAML."""
    try:
        import yaml
    except ImportError:
        return []

    if not os.path.exists(exceptions_path):
        return []

    with open(exceptions_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    return cfg.get("exceptions", []) or []
