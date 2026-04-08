#!/usr/bin/env bash
# ============================================================================
#  NetSniffer — Network Audit Collector v2.0
#  Enterprise-grade network data collection with multi-host SSH support.
#  Reads configuration from config/baseline.yml
#  Output: outputs/audit_output.json (or per-host files)
# ============================================================================

set -euo pipefail

VERSION="2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/baseline.yml"
OUTPUT_DIR="${SCRIPT_DIR}/outputs"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
USER_VAL=$(whoami 2>/dev/null || echo "unknown")
KERNEL_VAL=$(uname -r 2>/dev/null || echo "unknown")
OS_VAL=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s 2>/dev/null || echo "unknown")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Default Configuration (overridden by YAML config) ──
DOMAINS=("web.whatsapp.com" "www.facebook.com" "open.spotify.com" "google.com")
BLOCKED_DOMAINS=("facebook.com" "spotify.com" "youtube.com")
DNS_SERVERS=("1.1.1.1" "8.8.8.8")
SEGMENTS=("10.0.6.0/24" "10.0.5.0/24")
GATEWAYS=("10.0.5.1" "192.168.3.1")
MACHINE_IP="10.0.5.50"
TRACEROUTE_MAX_HOPS=15
TRACEROUTE_WAIT=3
REMOTE_HOSTS=()
OUTPUT_FILE=""

# ── CLI Flags ──
MODE="local"         # local | remote | remote-only
SPECIFIC_HOST=""
VERBOSE=false
QUIET=false

# ============================================================================
#  Helper Functions
# ============================================================================

banner() {
    [[ "$QUIET" == true ]] && return
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║         NetSniffer — Network Audit Collector v${VERSION}             ║"
    echo "║              Enterprise Anomaly Detection Suite                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${DIM}Timestamp : ${TIMESTAMP}${NC}"
    echo -e "  ${DIM}Host      : ${HOSTNAME_VAL}${NC}"
    echo -e "  ${DIM}User      : ${USER_VAL}${NC}"
    echo -e "  ${DIM}Config    : ${CONFIG_FILE}${NC}"
    echo ""
}

log_info()  { [[ "$QUIET" == true ]] || echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1" >&2; }
log_debug() { [[ "$VERBOSE" == true ]] && echo -e "${DIM}[D] $1${NC}" || true; }

usage() {
    cat <<EOF
${BOLD}NetSniffer Collector v${VERSION}${NC} — Network Audit Data Collection

${BOLD}USAGE:${NC}
    $(basename "$0") [OPTIONS]

${BOLD}OPTIONS:${NC}
    -c, --config FILE       Path to baseline YAML config (default: config/baseline.yml)
    -o, --output DIR        Output directory (default: outputs/)
    -r, --remote USER@HOST  Collect from a remote host via SSH (can repeat)
    -H, --hosts-file FILE   Read remote hosts from file (one per line: user@host)
    -l, --local-only        Only collect from the local machine (skip remotes in config)
    -R, --remote-only       Only collect from remote hosts (skip local)
    -v, --verbose           Verbose output
    -q, --quiet             Suppress banner and info messages
    -h, --help              Show this help

${BOLD}EXAMPLES:${NC}
    # Local collection with default config
    sudo ./collector.sh

    # Use custom config
    sudo ./collector.sh -c /path/to/baseline.yml

    # Collect from remote hosts
    sudo ./collector.sh -r root@10.0.5.10 -r admin@192.168.3.5

    # Use hosts file
    sudo ./collector.sh --hosts-file targets.txt

    # Remote only (skip local machine)
    sudo ./collector.sh --remote-only --hosts-file targets.txt

EOF
    exit 0
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

run_cmd() {
    local cmd="$1"
    local result
    log_debug "Running: $cmd"
    result=$(eval "$cmd" 2>&1) || true
    json_escape "$result"
}

# ============================================================================
#  YAML Config Parser (pure bash — handles simple YAML)
# ============================================================================

parse_yaml_list() {
    # Extract a YAML list under a given key from the config file
    local file="$1"
    local key="$2"
    local in_section=false
    local indent=""
    local results=()

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip Windows carriage returns
        line="${line%$'\r'}"
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        if [[ "$line" =~ ^[[:space:]]*${key}: ]]; then
            in_section=true
            continue
        fi

        if [[ "$in_section" == true ]]; then
            # Check if line is a list item (starts with -)
            if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+(.+) ]]; then
                local val="${BASH_REMATCH[1]}"
                # Remove quotes
                val="${val%\"}"
                val="${val#\"}"
                val="${val%\'}"
                val="${val#\'}"
                results+=("$val")
            elif [[ ! "$line" =~ ^[[:space:]] ]]; then
                # New top-level key — end of section
                break
            elif [[ "$line" =~ ^[[:space:]]+[a-zA-Z_]+: ]]; then
                # New nested key — end of list
                break
            fi
        fi
    done < "$file"

    if [[ ${#results[@]} -gt 0 ]]; then
        printf '%s\n' "${results[@]}"
    fi
}

parse_yaml_value() {
    # Extract a single YAML value
    local file="$1"
    local key="$2"
    local val

    val=$(grep -E "^[[:space:]]*${key}:" "$file" 2>/dev/null | head -1 | sed "s/.*${key}:[[:space:]]*//;s/[\"']//g;s/[[:space:]]*#.*//;s/[[:space:]]*$//;s/\r//" || true)
    echo "$val"
}

load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "Config file not found: ${CONFIG_FILE}"
        log_warn "Using default configuration"
        return
    fi

    log_info "Loading config from: ${CONFIG_FILE}"

    # Load target domains
    local domains_list
    mapfile -t domains_list < <(parse_yaml_list "$CONFIG_FILE" "target_domains")
    if [[ ${#domains_list[@]} -gt 0 ]]; then
        DOMAINS=("${domains_list[@]}")
        log_debug "Loaded ${#DOMAINS[@]} target domains"
    fi

    # Load blocked domains
    local blocked_list
    mapfile -t blocked_list < <(parse_yaml_list "$CONFIG_FILE" "blocked_domains")
    if [[ ${#blocked_list[@]} -gt 0 ]]; then
        BLOCKED_DOMAINS=("${blocked_list[@]}")
        log_debug "Loaded ${#BLOCKED_DOMAINS[@]} blocked domains"
    fi

    # Load DNS servers
    local dns_list
    mapfile -t dns_list < <(parse_yaml_list "$CONFIG_FILE" "servers")
    if [[ ${#dns_list[@]} -gt 0 ]]; then
        DNS_SERVERS=("${dns_list[@]}")
        log_debug "Loaded ${#DNS_SERVERS[@]} DNS servers"
    fi

    # Load segments
    local seg_list
    mapfile -t seg_list < <(parse_yaml_list "$CONFIG_FILE" "segments")
    if [[ ${#seg_list[@]} -gt 0 ]]; then
        SEGMENTS=("${seg_list[@]}")
        log_debug "Loaded ${#SEGMENTS[@]} segments"
    fi

    # Load machine IP
    local mip
    mip=$(parse_yaml_value "$CONFIG_FILE" "machine_ip")
    [[ -n "$mip" ]] && MACHINE_IP="$mip"

    # Load thresholds
    local max_hops
    max_hops=$(parse_yaml_value "$CONFIG_FILE" "traceroute_max_hops")
    [[ -n "$max_hops" ]] && TRACEROUTE_MAX_HOPS="$max_hops"

    local wait_s
    wait_s=$(parse_yaml_value "$CONFIG_FILE" "traceroute_wait_seconds")
    [[ -n "$wait_s" ]] && TRACEROUTE_WAIT="$wait_s"

    log_info "Config loaded: ${#DOMAINS[@]} domains, ${#SEGMENTS[@]} segments"
}

# ============================================================================
#  Data Collection (core function — works locally or via SSH)
# ============================================================================

collect_data() {
    local host_label="${1:-local}"
    local ssh_prefix="${2:-}"   # empty for local, "ssh user@host" for remote
    local output_file="${3:-${OUTPUT_DIR}/audit_output.json}"

    log_info "=== Collecting from: ${BOLD}${host_label}${NC} ==="

    # Get host info
    local h_hostname h_user h_kernel h_os h_timestamp
    h_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    if [[ -n "$ssh_prefix" ]]; then
        h_hostname=$(${ssh_prefix} hostname 2>/dev/null || echo "$host_label")
        h_user=$(${ssh_prefix} whoami 2>/dev/null || echo "unknown")
        h_kernel=$(${ssh_prefix} uname -r 2>/dev/null || echo "unknown")
        h_os=$(${ssh_prefix} bash -c 'grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d\" -f2 || uname -s' 2>/dev/null || echo "unknown")
    else
        h_hostname=$(hostname 2>/dev/null || echo "$host_label")
        h_user=$(whoami 2>/dev/null || echo "unknown")
        h_kernel=$(uname -r 2>/dev/null || echo "unknown")
        h_os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s 2>/dev/null || echo "unknown")
    fi

    # ── 1. Machine Info ──
    log_info "  Collecting network interfaces..."
    local ip_addr_out
    local resolv_out
    if [[ -n "$ssh_prefix" ]]; then
        ip_addr_out=$(run_cmd "${ssh_prefix} ip a")
        resolv_out=$(run_cmd "${ssh_prefix} cat /etc/resolv.conf")
    else
        ip_addr_out=$(run_cmd "ip a")
        resolv_out=$(run_cmd "cat /etc/resolv.conf")
    fi

    # ── 2. DNS Lookups ──
    log_info "  Running DNS lookups for ${#DOMAINS[@]} domains..."
    local nslookup_results="" dig_results=""

    for i in "${!DOMAINS[@]}"; do
        domain="${DOMAINS[$i]}"
        log_info "    -> nslookup + dig ${domain}"
        if [[ -n "$ssh_prefix" ]]; then
            ns_out=$(run_cmd "${ssh_prefix} nslookup ${domain}")
            dig_out=$(run_cmd "${ssh_prefix} dig ${domain} +stats +time=5")
        else
            ns_out=$(run_cmd "nslookup ${domain}")
            dig_out=$(run_cmd "dig ${domain} +stats +time=5")
        fi

        sep=""; [[ $i -gt 0 ]] && sep=","
        nslookup_results="${nslookup_results}${sep}{\"domain\":\"${domain}\",\"output\":\"${ns_out}\"}"
        dig_results="${dig_results}${sep}{\"domain\":\"${domain}\",\"output\":\"${dig_out}\"}"
    done

    # ── 3. ARP Table ──
    log_info "  Collecting ARP table..."
    local arp_out
    if [[ -n "$ssh_prefix" ]]; then
        arp_out=$(run_cmd "${ssh_prefix} arp -a")
    else
        arp_out=$(run_cmd "arp -a")
    fi

    # ── 4. Routing Table ──
    log_info "  Collecting routing table..."
    local route_out
    if [[ -n "$ssh_prefix" ]]; then
        route_out=$(run_cmd "${ssh_prefix} ip route")
    else
        route_out=$(run_cmd "ip route")
    fi

    # ── 5. Traceroute ──
    log_info "  Running traceroute..."
    local traceroute_results=""

    for i in "${!DOMAINS[@]}"; do
        domain="${DOMAINS[$i]}"
        log_info "    -> traceroute ${domain}"
        if [[ -n "$ssh_prefix" ]]; then
            tr_out=$(run_cmd "${ssh_prefix} traceroute -m ${TRACEROUTE_MAX_HOPS} -w ${TRACEROUTE_WAIT} ${domain}")
        else
            tr_out=$(run_cmd "traceroute -m ${TRACEROUTE_MAX_HOPS} -w ${TRACEROUTE_WAIT} ${domain}")
        fi

        sep=""; [[ $i -gt 0 ]] && sep=","
        traceroute_results="${traceroute_results}${sep}{\"domain\":\"${domain}\",\"output\":\"${tr_out}\"}"
    done

    # ── 6. SSL/TLS Certificates ──
    log_info "  Checking SSL/TLS certificates..."
    local ssl_results=""

    for i in "${!DOMAINS[@]}"; do
        domain="${DOMAINS[$i]}"
        log_info "    -> openssl s_client ${domain}:443"
        if [[ -n "$ssh_prefix" ]]; then
            ssl_out=$(run_cmd "${ssh_prefix} bash -c 'echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>&1 | openssl x509 -noout -issuer -subject -dates 2>&1'")
        else
            ssl_out=$(run_cmd "bash -c 'echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>&1 | openssl x509 -noout -issuer -subject -dates 2>&1'")
        fi

        sep=""; [[ $i -gt 0 ]] && sep=","
        ssl_results="${ssl_results}${sep}{\"domain\":\"${domain}\",\"output\":\"${ssl_out}\"}"
    done

    # ── 7. WHOIS ──
    log_info "  Running WHOIS lookups..."
    local whois_results=""

    for i in "${!DOMAINS[@]}"; do
        domain="${DOMAINS[$i]}"
        log_info "    -> whois ${domain}"
        if [[ -n "$ssh_prefix" ]]; then
            whois_out=$(run_cmd "${ssh_prefix} bash -c 'whois ${domain} 2>&1 | head -50'")
        else
            whois_out=$(run_cmd "bash -c 'whois ${domain} 2>&1 | head -50'")
        fi

        sep=""; [[ $i -gt 0 ]] && sep=","
        whois_results="${whois_results}${sep}{\"domain\":\"${domain}\",\"output\":\"${whois_out}\"}"
    done

    # ── 7.5 Subnet Discovery (Evasive) ──
    log_info "  Running stealth subnet discovery..."
    local subnet_results=""

    for i in "${!SEGMENTS[@]}"; do
        segment="${SEGMENTS[$i]}"
        log_info "    -> scanning ${segment}"
        # -sn (Ping scan only), -PR (ARP ping), -T2 (Polite), --randomize-hosts, --data-length 16
        if [[ -n "$ssh_prefix" ]]; then
            scan_out=$(run_cmd "${ssh_prefix} bash -c 'command -v nmap &>/dev/null && sudo nmap -sn -PR -T2 --randomize-hosts --data-length 16 ${segment} 2>/dev/null | grep -E \"Nmap scan report for|MAC Address\" || echo nmap_not_available'")
        else
            scan_out=$(run_cmd "bash -c 'command -v nmap &>/dev/null && sudo nmap -sn -PR -T2 --randomize-hosts --data-length 16 ${segment} 2>/dev/null | grep -E \"Nmap scan report for|MAC Address\" || echo nmap_not_available'")
        fi

        sep=""; [[ $i -gt 0 ]] && sep=","
        subnet_results="${subnet_results}${sep}{\"segment\":\"${segment}\",\"output\":\"${scan_out}\"}"
    done

    # ── 8. Open Ports (if nmap available) ──
    local nmap_out="nmap not available"
    if command -v nmap &>/dev/null; then
        log_info "  Scanning common ports with nmap..."
        if [[ -n "$ssh_prefix" ]]; then
            nmap_out=$(run_cmd "${ssh_prefix} nmap -sT -T4 --top-ports 100 localhost")
        else
            nmap_out=$(run_cmd "nmap -sT -T4 --top-ports 100 localhost")
        fi
    else
        log_warn "  nmap not installed — skipping port scan"
    fi

    # ── 9. Active Connections ──
    log_info "  Collecting active connections..."
    local netstat_out
    if command -v ss &>/dev/null; then
        if [[ -n "$ssh_prefix" ]]; then
            netstat_out=$(run_cmd "${ssh_prefix} ss -tunapl")
        else
            netstat_out=$(run_cmd "ss -tunapl")
        fi
    else
        if [[ -n "$ssh_prefix" ]]; then
            netstat_out=$(run_cmd "${ssh_prefix} netstat -tunapl")
        else
            netstat_out=$(run_cmd "netstat -tunapl")
        fi
    fi

    # ── Build JSON segments/gateways arrays ──
    local seg_json=""
    for i in "${!SEGMENTS[@]}"; do
        [[ $i -gt 0 ]] && seg_json="${seg_json},"
        seg_json="${seg_json}\"${SEGMENTS[$i]}\""
    done

    local dns_json=""
    for i in "${!DNS_SERVERS[@]}"; do
        [[ $i -gt 0 ]] && dns_json="${dns_json},"
        dns_json="${dns_json}\"${DNS_SERVERS[$i]}\""
    done

    local blocked_json=""
    for i in "${!BLOCKED_DOMAINS[@]}"; do
        [[ $i -gt 0 ]] && blocked_json="${blocked_json},"
        blocked_json="${blocked_json}\"${BLOCKED_DOMAINS[$i]}\""
    done

    local gw_json=""
    for i in "${!GATEWAYS[@]}"; do
        [[ $i -gt 0 ]] && gw_json="${gw_json},"
        gw_json="${gw_json}\"${GATEWAYS[$i]}\""
    done

    # ── Assemble JSON ──
    mkdir -p "$(dirname "$output_file")"

    cat > "${output_file}" <<JSONEOF
{
  "metadata": {
    "tool": "NetSniffer Network Audit Collector",
    "version": "${VERSION}",
    "timestamp": "${h_timestamp}",
    "hostname": "$(json_escape "$h_hostname")",
    "user": "$(json_escape "$h_user")",
    "kernel": "$(json_escape "$h_kernel")",
    "os": "$(json_escape "$h_os")",
    "host_label": "${host_label}",
    "config_file": "$(json_escape "$CONFIG_FILE")"
  },
  "network_config": {
    "ip_addresses": "${ip_addr_out}",
    "resolv_conf": "${resolv_out}",
    "routing_table": "${route_out}",
    "arp_table": "${arp_out}",
    "open_ports": "${nmap_out}",
    "active_connections": "${netstat_out}"
  },
  "dns": {
    "nslookup": [${nslookup_results}],
    "dig": [${dig_results}]
  },
  "traceroute": [${traceroute_results}],
  "ssl_certificates": [${ssl_results}],
  "whois": [${whois_results}],
  "subnet_scans": [${subnet_results}],
  "baseline": {
    "segments": [${seg_json}],
    "dns_servers": [${dns_json}],
    "dns_provider": "Enterprise DNS",
    "gateway": [${gw_json}],
    "blocked_domains": [${blocked_json}],
    "machine_ip": "${MACHINE_IP}"
  }
}
JSONEOF

    log_info "  Output saved: ${GREEN}${output_file}${NC}"
}

# ============================================================================
#  CLI Argument Parser
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"; shift 2 ;;
            -o|--output)
                OUTPUT_DIR="$2"; shift 2 ;;
            -r|--remote)
                REMOTE_HOSTS+=("$2"); MODE="remote"; shift 2 ;;
            -H|--hosts-file)
                if [[ -f "$2" ]]; then
                    while IFS= read -r line; do
                        [[ -z "$line" || "$line" =~ ^# ]] && continue
                        REMOTE_HOSTS+=("$line")
                    done < "$2"
                    MODE="remote"
                else
                    log_error "Hosts file not found: $2"
                    exit 1
                fi
                shift 2 ;;
            -l|--local-only)
                MODE="local"; shift ;;
            -R|--remote-only)
                MODE="remote-only"; shift ;;
            -v|--verbose)
                VERBOSE=true; shift ;;
            -q|--quiet)
                QUIET=true; shift ;;
            -h|--help)
                usage ;;
            *)
                log_error "Unknown option: $1"
                usage ;;
        esac
    done
}

# ============================================================================
#  Main
# ============================================================================

main() {
    parse_args "$@"
    banner
    load_config
    mkdir -p "$OUTPUT_DIR"

    local total_hosts=0
    local start_time=$(date +%s)

    # ── Local Collection ──
    if [[ "$MODE" != "remote-only" ]]; then
        OUTPUT_FILE="${OUTPUT_DIR}/audit_output.json"
        collect_data "local" "" "$OUTPUT_FILE"
        ((total_hosts++)) || true
    fi

    # ── Remote Collection ──
    if [[ "$MODE" == "remote" || "$MODE" == "remote-only" ]]; then
        for remote in "${REMOTE_HOSTS[@]}"; do
            # Parse user@host:port or user@host
            local user_host="${remote%%:*}"
            local port="${remote##*:}"
            [[ "$port" == "$remote" ]] && port="22"

            local host_label="${user_host##*@}"
            local ssh_cmd="ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -p ${port} ${user_host}"

            log_info "Testing SSH connection to ${user_host}..."
            if ${ssh_cmd} "echo ok" &>/dev/null; then
                local remote_output="${OUTPUT_DIR}/audit_output_${host_label}.json"
                collect_data "${host_label}" "${ssh_cmd}" "$remote_output"
                ((total_hosts++)) || true
            else
                log_error "Cannot connect to ${user_host} — skipping"
            fi
        done
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    echo -e "${GREEN}${BOLD}============================================${NC}"
    echo -e "${GREEN}${BOLD}  Collection complete!${NC}"
    echo -e "${GREEN}  Hosts scanned: ${total_hosts}${NC}"
    echo -e "${GREEN}  Duration: ${duration}s${NC}"
    echo -e "${GREEN}  Output dir: ${OUTPUT_DIR}/${NC}"
    echo -e "${GREEN}${BOLD}============================================${NC}"
    echo ""
    echo -e "${CYAN}Next step: Run the analyzer${NC}"
    echo -e "${CYAN}  python3 analyzer.py${NC}"
    echo -e "${CYAN}  python3 analyzer.py --format html,json,csv${NC}"
    echo ""
}

main "$@"
