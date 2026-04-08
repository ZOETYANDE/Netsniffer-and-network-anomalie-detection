#!/usr/bin/env bash
# ============================================================================
#  NetSniffer — Network Audit Collector v1.0
#  Collects DNS, ARP, routing, SSL, and WHOIS data for anomaly detection.
#  Output: audit_output.json
# ============================================================================

set -euo pipefail

# --- Configuration ---
DOMAINS=("web.whatsapp.com" "www.facebook.com" "open.spotify.com" "google.com")
OUTPUT_FILE="audit_output.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
USER_VAL=$(whoami 2>/dev/null || echo "unknown")
KERNEL_VAL=$(uname -r 2>/dev/null || echo "unknown")
OS_VAL=$(cat /etc/os-release 2>/dev/null | grep -E '^PRETTY_NAME=' | cut -d'"' -f2 || uname -s 2>/dev/null || echo "unknown")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Helper Functions ---

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           NetSniffer — Network Audit Collector v1.0        ║"
    echo "║                  Anomaly Detection Suite                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}[*] Timestamp : ${TIMESTAMP}${NC}"
    echo -e "${YELLOW}[*] Host      : ${HOSTNAME_VAL}${NC}"
    echo -e "${YELLOW}[*] User      : ${USER_VAL}${NC}"
    echo -e "${YELLOW}[*] Kernel    : ${KERNEL_VAL}${NC}"
    echo ""
}

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# Escape a string for safe JSON embedding (handles quotes, backslashes, newlines, tabs)
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"      # backslash
    s="${s//\"/\\\"}"      # double quotes
    s="${s//$'\n'/\\n}"    # newlines
    s="${s//$'\r'/}"       # carriage returns
    s="${s//$'\t'/\\t}"    # tabs
    printf '%s' "$s"
}

# Run a command, capture output+errors, return JSON-safe string
run_cmd() {
    local cmd="$1"
    local result
    result=$(eval "$cmd" 2>&1) || true
    json_escape "$result"
}

# --- Main Collection ---

banner

log_info "Starting network data collection..."
echo ""

# ── 1. Machine Info ──
log_info "Collecting machine information..."
IP_ADDR_OUTPUT=$(run_cmd "ip a")
RESOLV_CONF_OUTPUT=$(run_cmd "cat /etc/resolv.conf")

# ── 2. DNS Lookups (nslookup + dig) ──
log_info "Running DNS lookups for ${#DOMAINS[@]} domains..."
NSLOOKUP_RESULTS=""
DIG_RESULTS=""

for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    log_info "  → nslookup ${domain}"
    ns_out=$(run_cmd "nslookup ${domain}")

    log_info "  → dig ${domain}"
    dig_out=$(run_cmd "dig ${domain} +stats +time=5")

    # Build JSON entries with comma handling
    separator=""
    [[ $i -gt 0 ]] && separator=","

    NSLOOKUP_RESULTS="${NSLOOKUP_RESULTS}${separator}{\"domain\":\"${domain}\",\"output\":\"${ns_out}\"}"
    DIG_RESULTS="${DIG_RESULTS}${separator}{\"domain\":\"${domain}\",\"output\":\"${dig_out}\"}"
done

# ── 3. ARP Table ──
log_info "Collecting ARP table..."
ARP_OUTPUT=$(run_cmd "arp -a")

# ── 4. Routing Table ──
log_info "Collecting routing table..."
IP_ROUTE_OUTPUT=$(run_cmd "ip route")

# ── 5. Traceroute ──
log_info "Running traceroute (this may take a moment)..."
TRACEROUTE_RESULTS=""

for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    log_info "  → traceroute ${domain}"
    tr_out=$(run_cmd "traceroute -m 15 -w 3 ${domain}")

    separator=""
    [[ $i -gt 0 ]] && separator=","

    TRACEROUTE_RESULTS="${TRACEROUTE_RESULTS}${separator}{\"domain\":\"${domain}\",\"output\":\"${tr_out}\"}"
done

# ── 6. SSL/TLS Certificate Check ──
log_info "Checking SSL/TLS certificates..."
SSL_RESULTS=""

for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    log_info "  → openssl s_client ${domain}:443"
    ssl_out=$(run_cmd "echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>&1 | openssl x509 -noout -issuer -subject -dates 2>&1")

    separator=""
    [[ $i -gt 0 ]] && separator=","

    SSL_RESULTS="${SSL_RESULTS}${separator}{\"domain\":\"${domain}\",\"output\":\"${ssl_out}\"}"
done

# ── 7. WHOIS ──
log_info "Running WHOIS lookups..."
WHOIS_RESULTS=""

for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    log_info "  → whois ${domain}"
    whois_out=$(run_cmd "whois ${domain} 2>&1 | head -50")

    separator=""
    [[ $i -gt 0 ]] && separator=","

    WHOIS_RESULTS="${WHOIS_RESULTS}${separator}{\"domain\":\"${domain}\",\"output\":\"${whois_out}\"}"
done

# ── 8. Assemble JSON ──
log_info "Assembling JSON output..."

cat > "${OUTPUT_FILE}" <<JSONEOF
{
  "metadata": {
    "tool": "NetSniffer Network Audit Collector",
    "version": "1.0",
    "timestamp": "${TIMESTAMP}",
    "hostname": "${HOSTNAME_VAL}",
    "user": "${USER_VAL}",
    "kernel": "${KERNEL_VAL}",
    "os": "$(json_escape "$OS_VAL")"
  },
  "network_config": {
    "ip_addresses": "$(json_escape "$(ip a 2>&1)")",
    "resolv_conf": "$(json_escape "$(cat /etc/resolv.conf 2>&1)")",
    "routing_table": "${IP_ROUTE_OUTPUT}",
    "arp_table": "${ARP_OUTPUT}"
  },
  "dns": {
    "nslookup": [${NSLOOKUP_RESULTS}],
    "dig": [${DIG_RESULTS}]
  },
  "traceroute": [${TRACEROUTE_RESULTS}],
  "ssl_certificates": [${SSL_RESULTS}],
  "whois": [${WHOIS_RESULTS}],
  "baseline": {
    "segments": ["10.0.6.0/24", "10.0.5.0/24"],
    "dns_servers": ["1.1.1.1", "8.8.8.8"],
    "dns_provider": "FortiSASE (Fortinet)",
    "gateway": "10.0.5.1",
    "blocked_domains": ["facebook.com", "spotify.com", "youtube.com"],
    "machine_ip": "10.0.5.50"
  }
}
JSONEOF

echo ""
log_info "Collection complete!"
log_info "Output saved to: ${GREEN}${BOLD}${OUTPUT_FILE}${NC}"
echo ""
echo -e "${CYAN}[*] Next step: Run the analyzer${NC}"
echo -e "${CYAN}    python3 analyzer.py${NC}"
echo ""
