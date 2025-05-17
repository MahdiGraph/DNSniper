#!/usr/bin/env bash
# DNSniper Core Functions - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.3

# Strict error handling mode for robustness
set -o errexit  # Exit on error
set -o pipefail # Exit on pipe failure
set -o nounset  # Treat unset variables as errors

# ANSI color codes (primarily for interactive use, logs should be plain)
RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; BLUE='\e[34m';
CYAN='\e[36m'; WHITE='\e[97m'; MAGENTA='\e[35m';
BOLD='\e[1m'; DIM='\e[2m'; NC='\e[0m';

# --- Core Paths ---
BASE_DIR="/etc/dnsniper"
DEFAULT_FILE="$BASE_DIR/domains-default.txt"    # Auto-updated blocklist
ADD_FILE="$BASE_DIR/domains-add.txt"        # User-added domains to block
REMOVE_FILE="$BASE_DIR/domains-remove.txt"    # User-added domains to whitelist/unblock
IP_ADD_FILE="$BASE_DIR/ips-add.txt"           # User-added IPs to block
IP_REMOVE_FILE="$BASE_DIR/ips-remove.txt"     # User-added IPs to whitelist/unblock
CONFIG_FILE="$BASE_DIR/config.conf"           # Main configuration
HISTORY_DIR="$BASE_DIR/history"               # Domain IP resolution history
DATA_DIR="$BASE_DIR/data"                     # CDN, Expired domains data
STATUS_DIR="$BASE_DIR/status"                 # Runtime status files
STATUS_FILE="$STATUS_DIR/status.json"         # Detailed JSON status
PROGRESS_FILE="$STATUS_DIR/progress.txt"      # Simple text progress for basic monitoring
CDN_DOMAINS_FILE="$DATA_DIR/cdn_domains.txt"  # Domains suspected of CDN usage
EXPIRED_DOMAINS_FILE="$DATA_DIR/expired_domains.txt" # Domains removed from default list, pending rule expiry
RULES_V4_FILE="$BASE_DIR/iptables.rules"      # DNSniper's canonical IPv4 ruleset for persistence
RULES_V6_FILE="$BASE_DIR/ip6tables.rules"     # DNSniper's canonical IPv6 ruleset
BIN_CMD="/usr/local/bin/dnsniper"             # Path to the main executable script
LOG_FILE="$BASE_DIR/dnsniper.log"             # Main log file
LOCK_FILE="/var/run/dnsniper.pid"             # Changed to /var/run for PID files, ensure writable by service user if not root

# --- IPSet Definitions (if used directly, currently managed via iptables comments) ---
IPSET4_NAME="dnsniper-ipv4"
IPSET6_NAME="dnsniper-ipv6"

# --- Global State Variables (initialized by ensure_environment later) ---
LOGGING_ENABLED=0
STATUS_ENABLED=1

# --- Default Configuration Values (Fallbacks) ---
_LATEST_COMMIT_CACHE="" # Cache for latest commit hash
_get_latest_commit_from_git() { # Renamed for clarity
    if [[ -z "$_LATEST_COMMIT_CACHE" ]]; then
        if ! command -v git &>/dev/null; then
            _LATEST_COMMIT_CACHE="main" # Fallback to main branch
        else
            local commit_hash
            commit_hash=$(git ls-remote https://github.com/MahdiGraph/DNSniper.git HEAD 2>/dev/null | cut -f1)
            if [[ -z "$commit_hash" ]]; then
                _LATEST_COMMIT_CACHE="main" # Fallback if fetch fails
            else
                _LATEST_COMMIT_CACHE="$commit_hash"
            fi
        fi
    fi
    echo "$_LATEST_COMMIT_CACHE"
}

DEFAULT_SCHEDULER_ENABLED=1
DEFAULT_SCHEDULE_MINUTES=60
DEFAULT_MAX_IPS=10
DEFAULT_TIMEOUT=30
_DEFAULT_URL_VAL="" # Cache for the default URL
_get_default_url_val() { # Renamed
    if [[ -z "$_DEFAULT_URL_VAL" ]]; then
        _DEFAULT_URL_VAL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/$(_get_latest_commit_from_git)/domains-default.txt"
    fi
    echo "$_DEFAULT_URL_VAL"
}
DEFAULT_AUTO_UPDATE=1
DEFAULT_EXPIRE_ENABLED=1
DEFAULT_EXPIRE_MULTIPLIER=5 # e.g., 5 * 60min = 5 hours default expiry for removed default domains
DEFAULT_BLOCK_SOURCE=1      # Block traffic FROM malicious IPs
DEFAULT_BLOCK_DESTINATION=1 # Block traffic TO malicious IPs
DEFAULT_LOGGING_ENABLED=0   # Log to file disabled by default
DEFAULT_STATUS_ENABLED=1    # status.json enabled by default

# --- Firewall Chain Names ---
IPT_CHAIN="DNSniper"      # For IPv4 rules
IPT6_CHAIN="DNSniper6"    # For IPv6 rules (consistent naming)

# --- Version ---
VERSION="2.1.3"

# --- Essential Dependencies (checked by installer) ---
# For core functions: iptables, ip6tables, curl, dig, sort, comm, date, ps, grep, sed, awk, mktemp, wc, head, stat, du
# Git is optional (for latest commit fetching, installer handles this primarily).

# --- Helper Functions ---

# Logging function
log() {
    local level="$1" message="$2" verbose_opt="${3:-}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S') # ISO 8601 like format

    # Write to log file if enabled
    if [[ "${LOGGING_ENABLED:-0}" -eq 1 ]]; then
        echo "[$timestamp] [$level] :: $message" >> "$LOG_FILE" 2>/dev/null || true
    fi

    # Conditional output to stderr (for errors/warnings) or stdout (for verbose info in interactive shells)
    # Avoids polluting stdout if script output is piped.
    # DNSniper_NONINTERACTIVE is an environment variable that can be set to 1 by background tasks.
    if [[ "${DNSniper_NONINTERACTIVE:-0}" -eq 0 ]]; then # If interactive or not explicitly non-interactive
        if [[ "$level" == "ERROR" && -t 2 ]]; then
            echo -e "${RED}${BOLD}Error:${NC} $message" >&2
        elif [[ "$level" == "WARNING" && -t 2 ]]; then
            echo -e "${YELLOW}${BOLD}Warning:${NC} $message" >&2
        elif [[ "$level" == "INFO" && "$verbose_opt" == "verbose" && -t 1 ]]; then
            # Only show verbose INFO to stdout if it's a TTY to avoid breaking scripts
            echo -e "${BLUE}Info:${NC} $message"
        fi
    fi
}

# Robustly get a configuration value with a default
get_config_value() {
    local key_to_find="$1"
    local default_return_value="$2"
    local found_value=""

    if [[ -f "$CONFIG_FILE" ]]; then
        # Read value, remove potential comments (#) and leading/trailing whitespace.
        # Handles values with spaces if not quoted, but quotes are safer in config.
        found_value=$(grep "^${key_to_find}=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/[[:space:]]*#.*$//;s/[[:space:]]*$//')
        # Remove surrounding quotes if present
        found_value="${found_value#\"}"; found_value="${found_value%\"}"
        found_value="${found_value#\'}"; found_value="${found_value%\'}"
    fi

    if [[ -z "$found_value" ]]; then
        echo "$default_return_value"
    else
        echo "$found_value"
    fi
}


# Initialize LOGGING_ENABLED state from config
_initialize_logging_state() {
    local log_setting
    log_setting=$(get_config_value "logging_enabled" "$DEFAULT_LOGGING_ENABLED")
    if [[ "$log_setting" == "1" ]]; then
        LOGGING_ENABLED=1
        # Ensure log file is writable, create if not exists
        touch "$LOG_FILE" 2>/dev/null || log "WARNING" "Log file $LOG_FILE is not writable or cannot be created."
        chmod 640 "$LOG_FILE" 2>/dev/null # Restrict permissions slightly
    else
        LOGGING_ENABLED=0
    fi
}

# Initialize STATUS_ENABLED state from config and prepare status directory/file
_initialize_status_tracking_state() {
    mkdir -p "$STATUS_DIR" 2>/dev/null || log "WARNING" "Status directory $STATUS_DIR cannot be created."
    chmod 750 "$STATUS_DIR" 2>/dev/null # Restrict permissions

    local status_setting
    status_setting=$(get_config_value "status_enabled" "$DEFAULT_STATUS_ENABLED")
    if [[ "$status_setting" == "1" ]]; then
        STATUS_ENABLED=1
        # Initialize status file if it doesn't exist or is empty
        if [[ ! -s "$STATUS_FILE" ]]; then # -s checks if file exists and has size > 0
            update_status "idle" "DNSniper system initialized." "0" "0"
        fi
        chmod 640 "$STATUS_FILE" "$PROGRESS_FILE" 2>/dev/null
    else
        STATUS_ENABLED=0
    fi
}

# Update status.json and progress.txt files
update_status() {
    if [[ "${STATUS_ENABLED:-0}" -eq 0 ]]; then return 0; fi
    local current_status="$1" description="$2" percentage="$3" eta_seconds="$4"
    local current_timestamp json_timestamp formatted_readable_time

    current_timestamp=$(date +%s)
    json_timestamp=$current_timestamp # Keep original for JSON
    formatted_readable_time=$(date '+%Y-%m-%d %H:%M:%S %Z' -d "@$current_timestamp") # Human-readable

    # Create JSON content (ensure proper escaping if description can have quotes)
    # For simplicity, assuming description does not contain double quotes.
    # Using printf for more control over formatting.
    printf '{\n  "status": "%s",\n  "message": "%s",\n  "progress": %s,\n  "eta_seconds": %s,\n  "timestamp_unix": %s,\n  "last_updated_human": "%s"\n}\n' \
        "$current_status" "$description" "$percentage" "$eta_seconds" "$json_timestamp" "$formatted_readable_time" > "$STATUS_FILE.tmp"
    
    if mv "$STATUS_FILE.tmp" "$STATUS_FILE"; then
        # Update simple progress file
        echo "$percentage% - $description (ETA: ${eta_seconds}s)" > "$PROGRESS_FILE"
    else
        log "ERROR" "Failed to update status file $STATUS_FILE."
    fi
    return 0
}

# Read and output the content of status.json
get_status() {
    if [[ -f "$STATUS_FILE" ]]; then
        cat "$STATUS_FILE"
    else
        # Fallback JSON if status file is missing
        printf '{\n  "status": "unknown",\n  "message": "Status file not found.",\n  "progress": 0,\n  "eta_seconds": 0,\n  "timestamp_unix": 0,\n  "last_updated_human": "N/A"\n}\n'
    fi
}

# Safe echo (mainly for installer, less critical here but kept for consistency)
echo_safe() {
    echo -e "$1"
}

# --- IP Validation Functions ---
is_ipv6() {
    local ip_addr="$1"; [[ "$ip_addr" =~ ^([0-9a-fA-F]{1,4}:){1,7}(:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4})(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^::([0-9a-fA-F]{1,4}:){0,6}([0-9a-fA-F]{1,4})?(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^([0-9a-fA-F]{1,4}:){1,6}:([0-9a-fA-F]{1,4})?(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})(/[0-9]{1,3})?$ ]] || \
    [[ "$ip_addr" =~ ^(([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,5})?(/[0-9]{1,3})?$ ]]
}
is_valid_ipv4() { # Handles single IP, CIDR, and IP-IP range
    local ip_addr="$1"
    if [[ "$ip_addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})-([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then # IP Range
        for i in 1 2 3 4 5 6 7 8; do [[ ${BASH_REMATCH[$i]} -gt 255 ]] && return 1; done
        local s_ip="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.${BASH_REMATCH[4]}"
        local e_ip="${BASH_REMATCH[5]}.${BASH_REMATCH[6]}.${BASH_REMATCH[7]}.${BASH_REMATCH[8]}"
        local s_dec; s_dec=$(echo "$s_ip" | awk -F. '{print ($1 * 2^24) + ($2 * 2^16) + ($3 * 2^8) + $4}')
        local e_dec; e_dec=$(echo "$e_ip" | awk -F. '{print ($1 * 2^24) + ($2 * 2^16) + ($3 * 2^8) + $4}')
        [[ $s_dec -le $e_dec ]] && return 0 || return 1
    elif [[ "$ip_addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$ ]]; then # CIDR
        for i in 1 2 3 4; do [[ ${BASH_REMATCH[$i]} -gt 255 ]] && return 1; done
        [[ ${BASH_REMATCH[5]} -le 32 ]] && return 0 || return 1
    elif [[ "$ip_addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then # Single IP
        for i in 1 2 3 4; do [[ ${BASH_REMATCH[$i]} -gt 255 ]] && return 1; done
        return 0
    fi; return 1
}
is_valid_domain() { # Basic validation
    local domain_name="$1"
    # Slightly more permissive, allows underscores (common in some internal/service names)
    # and longer TLDs. Doesn't validate TLD existence.
    [[ "$domain_name" =~ ^([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.[a-zA-Z]{2,24}$ ]] && \
    [[ "${#domain_name}" -le 253 ]] # Max length
}
is_critical_ip() { # Check against private, loopback, link-local, and server's own IPs
    local ip_to_check="$1"
    local base_ip_to_check="${ip_to_check%/*}" # Remove CIDR for comparison
    if [[ "$base_ip_to_check" =~ ^([0-9.]+-){1}[0-9.]+$ ]]; then # If it's an IP range, check start IP
        base_ip_to_check="${base_ip_to_check%%-*}"
    fi

    # Common local/private/special IPs
    case "$base_ip_to_check" in
        127.*|0.0.0.0|::1|224.*|239.*|ff0*|169.254.*|10.*|192.168.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;; # 172.16.0.0 - 172.31.255.255
    esac

    # Check server's own IPs (more robustly)
    local server_ips
    mapfile -t server_ips < <(ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 ; \
                               ip -o -6 addr show | awk '{print $4}' | cut -d/ -f1 | grep -v '^fe80') # Exclude link-local IPv6
    for srv_ip in "${server_ips[@]}"; do
        if [[ "$base_ip_to_check" == "$srv_ip" ]]; then return 0; fi # Exact match
        # Check if IP range contains a server IP (simplified check, assumes /32 or single IPs for server)
        if [[ "$ip_to_check" =~ ^([0-9.]+-){1}[0-9.]+$ ]]; then # If input is a range
             local start_ip_range="${ip_to_check%%-*}"
             local end_ip_range="${ip_to_check##*-}"
             local s_dec; s_dec=$(echo "$start_ip_range" | awk -F. '{print ($1 * 2^24) + ($2 * 2^16) + ($3 * 2^8) + $4}')
             local e_dec; e_dec=$(echo "$end_ip_range" | awk -F. '{print ($1 * 2^24) + ($2 * 2^16) + ($3 * 2^8) + $4}')
             local srv_dec; srv_dec=$(echo "$srv_ip" | awk -F. '{print ($1 * 2^24) + ($2 * 2^16) + ($3 * 2^8) + $4}')
             if [[ "$srv_dec" -ge "$s_dec" && "$srv_dec" -le "$e_dec" ]]; then return 0; fi
        fi
    done
    # Check default gateway
    if command -v ip &>/dev/null; then
        local gateway_ip; gateway_ip=$(ip route | grep default | awk '{print $3}' | head -n 1)
        if [[ -n "$gateway_ip" && "$base_ip_to_check" == "$gateway_ip" ]]; then return 0; fi
    fi
    return 1 # Not critical
}

# Exit with error message and code
exit_with_error() {
    log "CRITICAL" "$1" # Log as critical before exiting
    echo -e "${RED}${BOLD}CRITICAL Error:${NC} $1" >&2
    exit "${2:-1}" # Exit with provided code or 1 by default
}

# --- System and Firewall Persistence ---
_detect_os_family() { # internal helper
    if [[ -f /etc/os-release ]]; then
        # خانم /etc/os-release for ID or ID_LIKE
        # shellcheck disable=SC1091
        source /etc/os-release
        if [[ -n "${ID_LIKE:-}" ]]; then echo "$ID_LIKE"; return; fi
        if [[ -n "${ID:-}" ]]; then echo "$ID"; return; fi
    fi
    # Fallbacks for older systems
    if [[ -f /etc/debian_version ]]; then echo "debian"; return; fi
    if [[ -f /etc/redhat-release || -f /etc/centos-release ]]; then echo "rhel fedora"; return; fi # Broader for yum/dnf
    echo "unknown"
}
make_rules_persistent() {
    log "INFO" "Attempting to make firewall rules persistent." "verbose"
    local os_family current_os_type
    os_family=$(_detect_os_family)
    
    # Save DNSniper's own canonical rules files first
    iptables-save > "$RULES_V4_FILE.tmp" 2>/dev/null && mv "$RULES_V4_FILE.tmp" "$RULES_V4_FILE" || log "ERROR" "Failed to save IPv4 rules to $RULES_V4_FILE"
    ip6tables-save > "$RULES_V6_FILE.tmp" 2>/dev/null && mv "$RULES_V6_FILE.tmp" "$RULES_V6_FILE" || log "ERROR" "Failed to save IPv6 rules to $RULES_V6_FILE"

    # System-specific persistence
    # This relies on the installer having set up the appropriate tools (iptables-persistent, iptables-services)
    # or the dnsniper-firewall.service to load from $RULES_V4_FILE / $RULES_V6_FILE.
    if [[ "$os_family" == *"debian"* || "$os_family" == *"ubuntu"* ]]; then # Covers debian, ubuntu
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save &>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null # Fallback for older iptables-persistent
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
            log "INFO" "Used netfilter-persistent (or direct save) for Debian/Ubuntu." "verbose"
        elif command -v iptables-save &>/dev/null; then # Older systems
             mkdir -p /etc/iptables 2>/dev/null
             iptables-save > /etc/iptables/rules.v4 2>/dev/null
             ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
             log "INFO" "Saved rules to /etc/iptables/ for Debian/Ubuntu (iptables-persistent style)." "verbose"
        fi
    elif [[ "$os_family" == *"rhel"* || "$os_family" == *"fedora"* || "$os_family" == *"centos"* ]]; then # Covers RHEL, CentOS, Fedora
        # For these, iptables-services usually handles loading /etc/sysconfig/iptables if enabled.
        # DNSniper's systemd service (dnsniper-firewall.service) loads from its own files, making this less critical here.
        # However, some users might expect /etc/sysconfig to be updated.
        if [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || log "WARNING" "Failed to save to /etc/sysconfig/iptables"
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || log "WARNING" "Failed to save to /etc/sysconfig/ip6tables"
            log "INFO" "Saved rules to /etc/sysconfig/ for RHEL/Fedora family (iptables-services style)." "verbose"
        fi
    fi
    # If systemd is primary, dnsniper-firewall.service handles loading $RULES_V[46]_FILE on boot.
    # No explicit 'save' needed here for systemd beyond updating DNSniper's own rule files.
    log "INFO" "Firewall rule persistence attempts complete. Primary method is via dnsniper-firewall.service."
}

# Initialize iptables chains for DNSniper
_initialize_firewall_chains() {
    local chain_created_v4=0 chain_created_v6=0
    # IPv4
    if ! iptables -L "$IPT_CHAIN" -n &>/dev/null; then # -n avoids DNS lookups, faster
        iptables -N "$IPT_CHAIN" || exit_with_error "Failed to create IPv4 chain $IPT_CHAIN."
        log "INFO" "Created IPv4 chain: $IPT_CHAIN"
        chain_created_v4=1
    fi
    # IPv6
    if ! ip6tables -L "$IPT6_CHAIN" -n &>/dev/null; then
        ip6tables -N "$IPT6_CHAIN" || exit_with_error "Failed to create IPv6 chain $IPT6_CHAIN."
        log "INFO" "Created IPv6 chain: $IPT6_CHAIN"
        chain_created_v6=1
    fi

    # Ensure our chains are linked to INPUT and OUTPUT. Insert at top (pos 1) for priority.
    # Remove old jump rules first to prevent duplication if script is re-run without full teardown.
    iptables -D INPUT -j "$IPT_CHAIN" 2>/dev/null || true
    iptables -D OUTPUT -j "$IPT_CHAIN" 2>/dev/null || true
    iptables -I INPUT 1 -j "$IPT_CHAIN" || exit_with_error "Failed to link $IPT_CHAIN to IPv4 INPUT."
    iptables -I OUTPUT 1 -j "$IPT_CHAIN" || exit_with_error "Failed to link $IPT_CHAIN to IPv4 OUTPUT."
    
    ip6tables -D INPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    ip6tables -D OUTPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    ip6tables -I INPUT 1 -j "$IPT6_CHAIN" || exit_with_error "Failed to link $IPT6_CHAIN to IPv6 INPUT."
    ip6tables -I OUTPUT 1 -j "$IPT6_CHAIN" || exit_with_error "Failed to link $IPT6_CHAIN to IPv6 OUTPUT."

    if [[ $chain_created_v4 -eq 1 || $chain_created_v6 -eq 1 ]]; then
        log "INFO" "DNSniper firewall chains created and linked to INPUT/OUTPUT."
        make_rules_persistent # Save immediately if chains were just created/linked.
    fi
}

# Ensure base environment (directories, config, logging state) is ready
ensure_environment() {
    mkdir -p "$BASE_DIR" "$HISTORY_DIR" "$DATA_DIR" "$STATUS_DIR" \
        || exit_with_error "Failed to create base directories under $BASE_DIR."
    
    # Create essential files if they don't exist
    touch "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$IP_ADD_FILE" "$IP_REMOVE_FILE" \
          "$CDN_DOMAINS_FILE" "$EXPIRED_DOMAINS_FILE" \
          2>/dev/null || log "WARNING" "Could not touch one or more list/data files."

    # Create config file with defaults if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "INFO" "Configuration file ($CONFIG_FILE) not found. Creating with defaults."
        cat > "$CONFIG_FILE" << EOF
# DNSniper Configuration File (auto-generated with defaults)
scheduler_enabled=$(DEFAULT_SCHEDULER_ENABLED)
schedule_minutes=$(DEFAULT_SCHEDULE_MINUTES)
max_ips=$(DEFAULT_MAX_IPS)
timeout=$(DEFAULT_TIMEOUT)
update_url='$(_get_default_url_val)'
auto_update=$(DEFAULT_AUTO_UPDATE)
expire_enabled=$(DEFAULT_EXPIRE_ENABLED)
expire_multiplier=$(DEFAULT_EXPIRE_MULTIPLIER)
block_source=$(DEFAULT_BLOCK_SOURCE)
block_destination=$(DEFAULT_BLOCK_DESTINATION)
logging_enabled=$(DEFAULT_LOGGING_ENABLED)
status_enabled=$(DEFAULT_STATUS_ENABLED)
EOF
    fi
    
    _initialize_logging_state    # Sets LOGGING_ENABLED based on config
    _initialize_status_tracking_state # Sets STATUS_ENABLED and prepares status files
    _initialize_firewall_chains  # Sets up iptables chains

    # Initialize ipset if available and we decide to use it directly
    # if command -v ipset &>/dev/null; then
    #    ipset create "$IPSET4_NAME" hash:ip family inet -exist 2>/dev/null || true
    #    ipset create "$IPSET6_NAME" hash:ip family inet6 -exist 2>/dev/null || true
    # fi
    log "INFO" "DNSniper environment checks complete." "verbose"
    return 0
}

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        exit_with_error "This script must be run as root (or with sudo)."
    fi
}

# Check for essential command-line dependencies
check_dependencies() { # Called by main script UI usually
    local missing_cmds=()
    # Add any other critical commands here if needed by core logic
    for cmd_tool in iptables ip6tables curl dig sort comm date ps grep sed awk mktemp wc head stat du; do
        if ! command -v "$cmd_tool" &>/dev/null; then
            missing_cmds+=("$cmd_tool")
        fi
    done
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        exit_with_error "Missing essential dependencies: ${missing_cmds[*]}. Please install them."
    fi
}

# Secure download function with timeout and SSL validation
secure_download() {
    local target_url="$1" dest_file="$2" conn_timeout="$3"
    log "INFO" "Securely downloading from $target_url to $dest_file (timeout: ${conn_timeout}s)" "verbose"
    
    # Use curl with strict SSL, specific TLS version, and timeouts
    if curl --fail --silent --location --show-error \
            --connect-timeout "$conn_timeout" --max-time "$((conn_timeout * 2))" \
            --proto '=https' --tlsv1.2 --ssl-reqd \
            --no-keepalive \
            "$target_url" -o "$dest_file.tmpdownload"; then
        # Check if downloaded file is non-empty
        if [[ -s "$dest_file.tmpdownload" ]]; then
            mv "$dest_file.tmpdownload" "$dest_file"
            log "INFO" "Successfully downloaded $target_url" "verbose"
            return 0
        else
            rm -f "$dest_file.tmpdownload" 2>/dev/null
            log "ERROR" "Download from $target_url succeeded, but the resulting file was empty."
            return 1
        fi
    else
        local curl_exit_code=$?
        rm -f "$dest_file.tmpdownload" 2>/dev/null
        log "ERROR" "Failed to download from $target_url. Curl exit code: $curl_exit_code."
        return 1
    fi
}

# Fetch and update the default domain blocklist
update_default() {
    log "INFO" "Starting update of default domains list."
    update_status "running" "Updating default domains list" "10" "0"

    local list_url current_timeout
    list_url=$(get_config_value "update_url" "$(_get_default_url_val)")
    current_timeout=$(get_config_value "timeout" "$DEFAULT_TIMEOUT")

    echo_safe "${BLUE}Fetching domains from: ${DIM}$list_url${NC}" # For interactive calls
    update_status "running" "Fetching: $list_url" "20" "$current_timeout"

    local expiration_is_enabled
    expiration_is_enabled=$(get_config_value "expire_enabled" "$DEFAULT_EXPIRE_ENABLED")
    
    # IMPORTANT: Create a sorted, unique copy of the current default file *before* overwriting
    local previous_default_sorted_unique
    previous_default_sorted_unique=$(mktemp)
    if [[ -f "$DEFAULT_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$DEFAULT_FILE" | grep -v '^[[:space:]]*$' | tr -d '\r' | \
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$previous_default_sorted_unique"
    fi # If it doesn't exist, temp file remains empty, comm will work.

    update_status "running" "Downloading list..." "40" "$current_timeout"
    if secure_download "$list_url" "$DEFAULT_FILE.downloaded" "$current_timeout"; then
        update_status "running" "Processing downloaded list..." "60" "0"
        
        # Atomically replace the old default file with the new one
        if ! mv "$DEFAULT_FILE.downloaded" "$DEFAULT_FILE"; then
            rm -f "$DEFAULT_FILE.downloaded" &>/dev/null
            log "ERROR" "Failed to move downloaded list to $DEFAULT_FILE."
            update_status "error" "Update failed (file move)" "0" "0"
            rm -f "$previous_default_sorted_unique"
            return 1
        fi

        if [[ "$expiration_is_enabled" == "1" ]]; then
            update_status "running" "Identifying domains removed from default list..." "80" "0"
            local new_default_sorted_unique domains_for_expiration_log
            new_default_sorted_unique=$(mktemp)
            domains_for_expiration_log=$(mktemp)

            # Normalize the newly downloaded list
            grep -v '^[[:space:]]*#' "$DEFAULT_FILE" | grep -v '^[[:space:]]*$' | tr -d '\r' | \
                sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$new_default_sorted_unique"
            
            # Find domains in previous list but NOT in new list (these were removed)
            # comm -23 <file1_sorted_unique> <file2_sorted_unique> # prints lines only in file1
            comm -23 "$previous_default_sorted_unique" "$new_default_sorted_unique" | while IFS= read -r removed_domain_entry; do
                if [[ -n "$removed_domain_entry" ]]; then # Ensure it's not an empty line from comm
                    local entry_timestamp
                    entry_timestamp=$(date +%s)
                    echo "${removed_domain_entry},${entry_timestamp},default" >> "$domains_for_expiration_log" # Domain,Timestamp,Source
                    log "INFO" "Domain '$removed_domain_entry' appears removed from default list. Marked for expiration tracking." "verbose"
                fi
            done

            if [[ -s "$domains_for_expiration_log" ]]; then # If any domains were logged for expiration
                cat "$domains_for_expiration_log" >> "$EXPIRED_DOMAINS_FILE"
                # Keep EXPIRED_DOMAINS_FILE sorted and unique (by domain, then timestamp - though simple sort -u works on whole line)
                local sorted_expired_tmp; sorted_expired_tmp=$(mktemp)
                sort -u "$EXPIRED_DOMAINS_FILE" > "$sorted_expired_tmp" && mv "$sorted_expired_tmp" "$EXPIRED_DOMAINS_FILE"
            fi
            rm -f "$new_default_sorted_unique" "$domains_for_expiration_log"
        fi
        rm -f "$previous_default_sorted_unique" # Clean up

        update_status "completed" "Default domains list updated successfully." "100" "0"
        log "INFO" "Default domains list updated from $list_url."
        echo_safe "${GREEN}Default domains list updated.${NC}" # For interactive calls
    else
        log "ERROR" "Failed to download default domains list from $list_url."
        update_status "error" "Download of default list failed." "0" "0"
        rm -f "$previous_default_sorted_unique"
        return 1
    fi
    return 0
}


# Resolve a domain to its IP addresses (IPv4 and IPv6)
resolve_domain() {
    local domain_to_resolve="$1" lookup_timeout="$2" max_dns_retries="2"
    local -a ipv4_results=() ipv6_results=()
    local attempt_count=0 dns_query_ok=0
    
    log "INFO" "Resolving IPs for: $domain_to_resolve (timeout: ${lookup_timeout}s, retries: $max_dns_retries)" "verbose"
    local dig_cmd_prefix="nice -n 15" # Very low priority for dig

    while [[ $attempt_count -lt $max_dns_retries && $dns_query_ok -eq 0 ]]; do
        local v4_output v6_output dig_v4_ec dig_v6_ec
        
        # IPv4 lookup
        # Half timeout for A, half for AAAA. +short +time=T +tries=1 means T seconds total for this type.
        v4_output=$($dig_cmd_prefix dig +short +time="$((lookup_timeout / 2))" +tries=1 A "$domain_to_resolve" 2>&1)
        dig_v4_ec=$?
        if [[ $dig_v4_ec -eq 0 && -n "$v4_output" ]] && ! echo "$v4_output" | grep -qiE "(connection (time|refuse)|timed out|server failed|no servers could be reached)"; then
            mapfile -t -O "${#ipv4_results[@]}" current_v4_resolved < <(echo "$v4_output")
            ipv4_results+=("${current_v4_resolved[@]}")
            dns_query_ok=1 # At least one type of lookup succeeded.
        else
            log "WARNING" "IPv4 lookup attempt $((attempt_count + 1)) for '$domain_to_resolve' failed or empty. dig output: $v4_output (exit: $dig_v4_ec)" "verbose"
        fi

        # IPv6 lookup
        v6_output=$($dig_cmd_prefix dig +short +time="$((lookup_timeout / 2))" +tries=1 AAAA "$domain_to_resolve" 2>&1)
        dig_v6_ec=$?
        if [[ $dig_v6_ec -eq 0 && -n "$v6_output" ]] && ! echo "$v6_output" | grep -qiE "(connection (time|refuse)|timed out|server failed|no servers could be reached)"; then
            mapfile -t -O "${#ipv6_results[@]}" current_v6_resolved < <(echo "$v6_output")
            ipv6_results+=("${current_v6_resolved[@]}")
            dns_query_ok=1
        else
            log "WARNING" "IPv6 lookup attempt $((attempt_count + 1)) for '$domain_to_resolve' failed or empty. dig output: $v6_output (exit: $dig_v6_ec)" "verbose"
        fi
        
        if [[ $dns_query_ok -eq 0 ]]; then
            attempt_count=$((attempt_count + 1))
            if [[ $attempt_count -lt $max_dns_retries ]]; then
                log "INFO" "Retrying DNS resolution for '$domain_to_resolve' (attempt ${attempt_count}/${max_dns_retries}) after 1s pause." "verbose"
                sleep 1
            fi
        fi
    done

    # Deduplicate and validate IPs using an associative array (Bash 4.0+)
    declare -A unique_validated_ips_map
    local -a final_ips_list=()

    for ip_result in "${ipv4_results[@]}"; do
        if is_valid_ipv4 "$ip_result" && [[ -z "${unique_validated_ips_map[$ip_result]}" ]]; then
            final_ips_list+=("$ip_result")
            unique_validated_ips_map["$ip_result"]=1
        fi
    done
    for ip_result in "${ipv6_results[@]}"; do
        if is_ipv6 "$ip_result" && [[ -z "${unique_validated_ips_map[$ip_result]}" ]]; then
            final_ips_list+=("$ip_result")
            unique_validated_ips_map["$ip_result"]=1
        fi
    done

    if [[ ${#final_ips_list[@]} -gt 0 ]]; then
        printf "%s\n" "${final_ips_list[@]}" # Output each IP on a new line
        return 0
    else
        log "WARNING" "No valid unique IP addresses found for '$domain_to_resolve' after all attempts."
        return 1 # No IPs found or all were invalid
    fi
}


# Check for expired domains (removed from default list) and unblock their IPs
check_expired_domains() {
    local expiration_is_enabled current_schedule_minutes current_expire_multiplier
    expiration_is_enabled=$(get_config_value "expire_enabled" "$DEFAULT_EXPIRE_ENABLED")
    if [[ "$expiration_is_enabled" != "1" ]]; then return 0; fi # Feature disabled

    log "INFO" "Starting check for expired domain rules."
    update_status "running" "Checking for expired domain rules" "10" "0"

    current_schedule_minutes=$(get_config_value "schedule_minutes" "$DEFAULT_SCHEDULE_MINUTES")
    current_expire_multiplier=$(get_config_value "expire_multiplier" "$DEFAULT_EXPIRE_MULTIPLIER")
    local expire_after_seconds=$((current_schedule_minutes * current_expire_multiplier * 60))
    local current_unix_time; current_unix_time=$(date +%s)

    local unexpired_entries_temp domains_to_unblock_temp rules_changed_flag=0
    unexpired_entries_temp=$(mktemp)
    domains_to_unblock_temp=$(mktemp)

    if [[ -f "$EXPIRED_DOMAINS_FILE" ]]; then
        update_status "running" "Processing $EXPIRED_DOMAINS_FILE" "20" "0"
        local line_num=0 total_lines
        total_lines=$(wc -l < "$EXPIRED_DOMAINS_FILE" | awk '{print $1}')

        # Process line by line to handle potentially large files
        while IFS=, read -r domain_name timestamp_removed source_list || [[ -n "$domain_name" ]]; do # Handle last line without newline
            line_num=$((line_num + 1))
            [[ "$domain_name" =~ ^[[:space:]]*# || -z "$domain_name" ]] && continue # Skip comments/empty

            # Progress update
            if [[ $((line_num % 100)) -eq 0 && "$total_lines" -gt 0 ]]; then # Update every 100 lines
                update_status "running" "Checked $line_num/$total_lines expired entries" "$((20 + (line_num * 70 / total_lines)))" "0"
            fi

            if [[ "$source_list" == "default" ]]; then # Only process 'default' list expirations
                local expiry_timestamp=$((timestamp_removed + expire_after_seconds))
                if [[ "$current_unix_time" -gt "$expiry_timestamp" ]]; then
                    # Domain has expired, mark for unblocking
                    echo "$domain_name" >> "$domains_to_unblock_temp"
                    log "INFO" "Domain '$domain_name' (removed at $timestamp_removed from default) has now fully expired. Queued for rule removal." "verbose"
                else
                    # Not yet expired, keep in the list
                    echo "$domain_name,$timestamp_removed,$source_list" >> "$unexpired_entries_temp"
                fi
            else # Not from default list (e.g. custom manual add, though not typical for this file)
                echo "$domain_name,$timestamp_removed,$source_list" >> "$unexpired_entries_temp"
            fi
        done < "$EXPIRED_DOMAINS_FILE"

        if [[ -s "$domains_to_unblock_temp" ]]; then # If there are domains to unblock
            rules_changed_flag=1
            log "INFO" "Found expired domains. Proceeding to remove their firewall rules."
            echo_safe "${YELLOW}Removing rules for expired domains...${NC}" # For interactive

            sort -u "$domains_to_unblock_temp" | while IFS= read -r expired_domain; do
                log "INFO" "Processing unblock for expired domain: $expired_domain" "verbose"
                echo_safe "${DIM}  - Unblocking $expired_domain${NC}"
                # Get IPs from history to unblock correctly
                local historical_ips_csv; historical_ips_csv=$(get_domain_ips "$expired_domain")
                if [[ -n "$historical_ips_csv" ]]; then
                    IFS=',' read -ra ips_to_unblock_arr <<< "$historical_ips_csv"
                    for an_ip_to_unblock in "${ips_to_unblock_arr[@]}"; do
                        if whitelist_ip "$an_ip_to_unblock" "DNSniper: $expired_domain"; then
                            echo_safe "${GREEN}    - Rule for $an_ip_to_unblock (from $expired_domain) removed.${NC}"
                        fi
                    done
                else
                    log "WARNING" "No IP history found for expired domain '$expired_domain'. Cannot unblock specific IPs." "verbose"
                fi
                # To ensure it's not re-added if user manually whitelisted then un-whitelisted,
                # we can also ensure it's effectively whitelisted in the domain lists.
                # This depends on desired logic: is expiry just for default list rules, or full removal?
                # Current logic focuses on unblocking rules for 'default' list removals.
            done
        fi
        # Update the EXPIRED_DOMAINS_FILE with remaining (unexpired) entries
        mv "$unexpired_entries_temp" "$EXPIRED_DOMAINS_FILE"
    else
         mv "$unexpired_entries_temp" "$EXPIRED_DOMAINS_FILE" # Ensure it's an empty file if source was empty
    fi
    rm -f "$domains_to_unblock_temp" # unexpired_entries_temp was mv'd

    if [[ "$rules_changed_flag" -eq 1 ]]; then
        update_status "running" "Persisting rule changes after expiration checks" "95" "0"
        make_rules_persistent
        log "INFO" "Firewall rules updated after processing expired domains."
    fi
    update_status "completed" "Expired domain rule check finished." "100" "0"
}


# Merge domains from default list + add list, then subtract remove list.
# Optimized with sort and comm for performance on large lists.
merge_domains() {
    log "INFO" "Starting domain list merge operation." "verbose"
    
    local default_s_u add_s_u remove_s_u combined_s_u final_s_u
    default_s_u=$(mktemp); add_s_u=$(mktemp); remove_s_u=$(mktemp)
    combined_s_u=$(mktemp); final_s_u=$(mktemp)

    # Prepare sorted, unique lists from each file, removing comments/empty lines and DOS CRs.
    [[ -f "$DEFAULT_FILE" ]] && grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$DEFAULT_FILE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$default_s_u"
    [[ -f "$ADD_FILE" ]] && grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$ADD_FILE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$add_s_u"
    [[ -f "$REMOVE_FILE" ]] && grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$REMOVE_FILE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$remove_s_u"

    # Merge default_s_u and add_s_u, keeping unique entries
    sort -m -u "$default_s_u" "$add_s_u" > "$combined_s_u"

    # Subtract domains in remove_s_u from combined_s_u
    # comm -23 <file1> <file2>  => lines unique to file1
    if [[ -s "$remove_s_u" ]]; then # Only run comm if remove list has content
        comm -23 "$combined_s_u" "$remove_s_u" > "$final_s_u"
        cat "$final_s_u"
    else
        cat "$combined_s_u" # No removals needed
    fi
    
    rm -f "$default_s_u" "$add_s_u" "$remove_s_u" "$combined_s_u" "$final_s_u"
    # Output is to stdout
}

# Get list of custom IPs (add list minus remove list).
# Optimized with sort and comm.
get_custom_ips() {
    log "INFO" "Getting final list of custom IPs to block." "verbose"

    local ip_add_s_u ip_remove_s_u final_ips_to_block
    ip_add_s_u=$(mktemp); ip_remove_s_u=$(mktemp); final_ips_to_block=$(mktemp)

    # Prepare sorted, unique IP lists, validating format.
    if [[ -f "$IP_ADD_FILE" ]]; then
        grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$IP_ADD_FILE" | tr -d '\r' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        while IFS= read -r ip_line; do # Validate each IP/range/CIDR
            if is_valid_ipv4 "$ip_line" || is_ipv6 "$ip_line"; then echo "$ip_line";
            else log "WARNING" "Invalid IP format in $IP_ADD_FILE, ignoring: '$ip_line'"; fi
        done | sort -u > "$ip_add_s_u"
    fi

    if [[ -f "$IP_REMOVE_FILE" ]]; then
        grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$IP_REMOVE_FILE" | tr -d '\r' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        while IFS= read -r ip_line; do
            if is_valid_ipv4 "$ip_line" || is_ipv6 "$ip_line"; then echo "$ip_line";
            else log "WARNING" "Invalid IP format in $IP_REMOVE_FILE, ignoring: '$ip_line'"; fi
        done | sort -u > "$ip_remove_s_u"
    fi
    
    if [[ -s "$ip_remove_s_u" ]]; then
        comm -23 "$ip_add_s_u" "$ip_remove_s_u" > "$final_ips_to_block"
        cat "$final_ips_to_block"
    else
        cat "$ip_add_s_u"
    fi

    rm -f "$ip_add_s_u" "$ip_remove_s_u" "$final_ips_to_block"
    # Output is to stdout
}


# Record IP resolution history for a domain
record_history() {
    local domain_name="$1" resolved_ips_csv="$2"
    log "INFO" "Recording IP history for '$domain_name'. IPs: $resolved_ips_csv" "verbose"
    
    local safe_domain_filename history_file_path max_history_entries
    safe_domain_filename=$(echo "$domain_name" | tr -c 'a-zA-Z0-9._-' '_') # Sanitize for filename
    history_file_path="$HISTORY_DIR/${safe_domain_filename}.txt"
    max_history_entries=$(get_config_value "max_ips" "$DEFAULT_MAX_IPS") # max_ips config also controls history depth
    
    local current_timestamp; current_timestamp=$(date +%s)
    local new_history_entry="$current_timestamp,$resolved_ips_csv"
    
    local temp_history_file; temp_history_file=$(mktemp)
    echo "$new_history_entry" > "$temp_history_file" # Add new entry at the top

    if [[ -f "$history_file_path" ]]; then
        # Append max_ips-1 old entries, effectively keeping 'max_ips' total entries
        head -n "$((max_history_entries - 1))" "$history_file_path" >> "$temp_history_file" 2>/dev/null
    fi
    
    if mv "$temp_history_file" "$history_file_path"; then
        return 0
    else
        log "ERROR" "Failed to write history for '$domain_name' to $history_file_path."
        rm -f "$temp_history_file" 2>/dev/null
        return 1
    fi
}

# Get most recent IPs for a domain from its history file
get_domain_ips() {
    local domain_name="$1"
    local safe_domain_filename history_file_path
    safe_domain_filename=$(echo "$domain_name" | tr -c 'a-zA-Z0-9._-' '_')
    history_file_path="$HISTORY_DIR/${safe_domain_filename}.txt"

    if [[ -f "$history_file_path" && -s "$history_file_path" ]]; then
        local latest_entry; latest_entry=$(head -n 1 "$history_file_path" 2>/dev/null)
        if [[ -n "$latest_entry" ]]; then
            echo "${latest_entry#*,}" # Return CSV of IPs (everything after first comma)
            return 0
        fi
    fi
    # No history or empty history file
    echo "" # Return empty string
    return 1
}


# Detect CDN usage based on IP flux over time
detect_cdn() {
    local -a domains_to_check=("${@}") # Pass domains as an array
    if [[ ${#domains_to_check[@]} -eq 0 ]]; then return 0; fi

    log "INFO" "Starting CDN detection for ${#domains_to_check[@]} domains." "verbose"
    local -a found_cdn_domains=()
    local cdn_candidates_log_temp; cdn_candidates_log_temp=$(mktemp)
    local current_unix_time_cdn; current_unix_time_cdn=$(date +%s)

    # Load existing known CDN domains to avoid re-processing or re-logging
    local -A known_cdn_map # Associative array for quick lookups
    if [[ -f "$CDN_DOMAINS_FILE" ]]; then
        while IFS=, read -r cdn_domain_entry _ || [[ -n "$cdn_domain_entry" ]]; do
            [[ "$cdn_domain_entry" =~ ^[[:space:]]*# || -z "$cdn_domain_entry" ]] && continue
            known_cdn_map["$cdn_domain_entry"]=1
        done < "$CDN_DOMAINS_FILE"
    fi

    local processed_cdn_check=0 total_to_check_cdn=${#domains_to_check[@]}
    for a_domain_to_check_cdn in "${domains_to_check[@]}"; do
        processed_cdn_check=$((processed_cdn_check + 1))
        if [[ $((processed_cdn_check % 50)) -eq 0 && "$total_to_check_cdn" -gt 0 ]]; then # Progress update
            update_status "running" "CDN Check: $processed_cdn_check/$total_to_check_cdn domains" \
                "$((85 + (processed_cdn_check * 10 / total_to_check_cdn)))" "0"
        fi

        if [[ -n "${known_cdn_map[$a_domain_to_check_cdn]}" ]]; then continue; fi # Skip if already known

        local safe_domain_hist_fname history_file_path_cdn
        safe_domain_hist_fname=$(echo "$a_domain_to_check_cdn" | tr -c 'a-zA-Z0-9._-' '_')
        history_file_path_cdn="$HISTORY_DIR/${safe_domain_hist_fname}.txt"

        if [[ ! -f "$history_file_path_cdn" || $(wc -l < "$history_file_path_cdn" | awk '{print $1}') -lt 2 ]]; then
            continue # Need at least 2 history entries to compare
        fi

        # Compare last two IP sets from history
        local -a history_lines_arr last_ips_csv prev_ips_csv
        mapfile -t history_lines_arr < <(head -n 2 "$history_file_path_cdn")
        last_ips_csv="${history_lines_arr[0]#*,}"
        prev_ips_csv="${history_lines_arr[1]#*,}"
        
        # Convert CSVs to sorted unique IP arrays for comparison
        local -a last_ips_arr_sorted prev_ips_arr_sorted
        mapfile -t last_ips_arr_sorted < <(echo "$last_ips_csv" | tr ',' '\n' | sort -u)
        mapfile -t prev_ips_arr_sorted < <(echo "$prev_ips_csv" | tr ',' '\n' | sort -u)

        # Calculate Jaccard Index (Intersection over Union) for similarity
        # For simplicity: if less than 50% overlap of IPs, suspect CDN (heuristic)
        local common_ips_count=0
        local -A temp_ip_map_cdn
        for ip_val in "${last_ips_arr_sorted[@]}"; do temp_ip_map_cdn["$ip_val"]=1; done
        for ip_val in "${prev_ips_arr_sorted[@]}"; do [[ -n "${temp_ip_map_cdn[$ip_val]}" ]] && common_ips_count=$((common_ips_count + 1)); done
        
        local total_unique_ips_combined=$((${#last_ips_arr_sorted[@]} + ${#prev_ips_arr_sorted[@]} - common_ips_count))
        local similarity_percentage=0
        if [[ $total_unique_ips_combined -gt 0 ]]; then
            similarity_percentage=$(( (common_ips_count * 100) / total_unique_ips_combined ))
        fi

        # Threshold for CDN suspicion (e.g., if similarity is less than 70%)
        # Or if IP count is very high (e.g. > max_ips / 2, indicating wide IP spread)
        # This needs careful tuning. Let's use a simple IP change heuristic for now.
        # Count how many IPs changed. If more than 30% of IPs changed, flag it.
        local changed_ips_count=$((total_unique_ips_combined - (2 * common_ips_count) + common_ips_count)) # This is total - common. Simpler:
        changed_ips_count=$(( ${#last_ips_arr_sorted[@]} - common_ips_count + ${#prev_ips_arr_sorted[@]} - common_ips_count ))


        # Heuristic: if more than 3 IPs are different OR total IPs > 5 and similarity < 50%
        if [[ $changed_ips_count -gt 3 || ( $total_unique_ips_combined -gt 5 && $similarity_percentage -lt 50 ) ]]; then
            found_cdn_domains+=("$a_domain_to_check_cdn")
            echo "$a_domain_to_check_cdn,$current_unix_time_cdn" >> "$cdn_candidates_log_temp"
            log "INFO" "Domain '$a_domain_to_check_cdn' flagged as potential CDN due to IP flux (Similarity: $similarity_percentage%, Changed: $changed_ips_count)." "verbose"
        fi
    done

    if [[ ${#found_cdn_domains[@]} -gt 0 ]]; then
        # Merge new candidates with existing CDN_DOMAINS_FILE
        if [[ -f "$CDN_DOMAINS_FILE" ]]; then cat "$CDN_DOMAINS_FILE" >> "$cdn_candidates_log_temp"; fi
        local sorted_cdn_tmp; sorted_cdn_tmp=$(mktemp)
        sort -u "$cdn_candidates_log_temp" > "$sorted_cdn_tmp" && mv "$sorted_cdn_tmp" "$CDN_DOMAINS_FILE"
        
        # Display warning for interactive sessions
        if [[ -t 1 ]]; then
            echo_safe "\n${YELLOW}${BOLD}[!] Potential CDN Usage Detected for:${NC}"
            local display_count=0
            for cdn_dom_display in "${found_cdn_domains[@]}"; do
                echo_safe "${YELLOW}  - $cdn_dom_display${NC}"
                display_count=$((display_count + 1))
                if [[ $display_count -ge 5 && ${#found_cdn_domains[@]} -gt 5 ]]; then
                    echo_safe "${YELLOW}  ...and $((${#found_cdn_domains[@]} - 5)) more.${NC}"
                    break
                fi
            done
            echo_safe "${DIM}These domains show significant IP address changes typical of CDNs.${NC}"
            echo_safe "${DIM}Consider adding them to your whitelist ($REMOVE_FILE) to avoid blocking legitimate services.${NC}"
            # No automatic whitelisting prompt here, user should review.
        fi
    fi
    rm -f "$cdn_candidates_log_temp"
    return 0
}



# Block a specific IP/CIDR/Range using iptables/ip6tables
block_ip() {
    local ip_to_block="$1" rule_comment="$2"
    local ipt_cmd ip6t_cmd target_chain_v4 target_chain_v6
    ipt_cmd="iptables"; ip6t_cmd="ip6tables"
    target_chain_v4="$IPT_CHAIN"; target_chain_v6="$IPT6_CHAIN"
    
    local do_block_source do_block_destination rules_were_added=0
    do_block_source=$(get_config_value "block_source" "$DEFAULT_BLOCK_SOURCE")
    do_block_destination=$(get_config_value "block_destination" "$DEFAULT_BLOCK_DESTINATION")

    # Determine if IPv4 or IPv6 and set appropriate command/chain
    local current_ipt_cmd current_target_chain
    if is_ipv6 "$ip_to_block"; then
        current_ipt_cmd="$ip6t_cmd"; current_target_chain="$target_chain_v6"
    elif is_valid_ipv4 "$ip_to_block"; then # Covers single, CIDR, range
        current_ipt_cmd="$ipt_cmd"; current_target_chain="$target_chain_v4"
    else
        log "ERROR" "Invalid IP format for blocking: '$ip_to_block'."
        return 1 # Invalid IP
    fi
    
    # Construct rule parts based on IP type (single, CIDR, range)
    local match_opts=""
    if [[ "$ip_to_block" =~ ^([0-9.]+-){1}[0-9.]+$ && "$current_ipt_cmd" == "$ipt_cmd" ]]; then # IPv4 Range
        match_opts="-m iprange --src-range $ip_to_block" # For source blocking
        # For destination blocking, it will be --dst-range
    else # Single IP or CIDR (iptables handles -s/-d for CIDR directly)
        match_opts="-s $ip_to_block" # For source blocking
        # For destination blocking, it will be -d
    fi

    # Block traffic FROM the IP (INPUT chain perspective)
    if [[ "$do_block_source" == "1" ]]; then
        local src_match_opt="${match_opts}" # Default is source match
        if [[ "$ip_to_block" =~ ^([0-9.]+-){1}[0-9.]+$ && "$current_ipt_cmd" == "$ipt_cmd" ]]; then
            src_match_opt="-m iprange --src-range $ip_to_block"
        else
            src_match_opt="-s $ip_to_block"
        fi
        # Check if rule exists: -C returns 0 if exists, 1 if not
        if ! $current_ipt_cmd -C "$current_target_chain" $src_match_opt -j DROP -m comment --comment "$rule_comment" &>/dev/null; then
            if $current_ipt_cmd -A "$current_target_chain" $src_match_opt -j DROP -m comment --comment "$rule_comment"; then
                log "INFO" "Added SOURCE block rule for IP/Range: $ip_to_block ($rule_comment)" "verbose"
                rules_were_added=1
            else
                log "ERROR" "Failed to add SOURCE block rule for IP/Range: $ip_to_block"
            fi
        fi
    fi

    # Block traffic TO the IP (OUTPUT chain perspective)
    if [[ "$do_block_destination" == "1" ]]; then
        local dst_match_opt
        if [[ "$ip_to_block" =~ ^([0-9.]+-){1}[0-9.]+$ && "$current_ipt_cmd" == "$ipt_cmd" ]]; then
            dst_match_opt="-m iprange --dst-range $ip_to_block"
        else
            dst_match_opt="-d $ip_to_block"
        fi
        if ! $current_ipt_cmd -C "$current_target_chain" $dst_match_opt -j DROP -m comment --comment "$rule_comment" &>/dev/null; then
            if $current_ipt_cmd -A "$current_target_chain" $dst_match_opt -j DROP -m comment --comment "$rule_comment"; then
                log "INFO" "Added DESTINATION block rule for IP/Range: $ip_to_block ($rule_comment)" "verbose"
                rules_were_added=1
            else
                log "ERROR" "Failed to add DESTINATION block rule for IP/Range: $ip_to_block"
            fi
        fi
    fi
    # Return 0 if rules were added (success), 1 if no rules were added (e.g., all existed or error)
    # This logic might need refinement: should "already exists" be success or neutral?
    # For now, if any rule was successfully added, consider it a success for this function call.
    [[ $rules_were_added -eq 1 ]] && return 0 || return 1
}

# Whitelist/Unblock a specific IP/CIDR/Range
whitelist_ip() {
    local ip_to_whitelist="$1" rule_comment_pattern="$2" # Pattern for comment matching
    local ipt_cmd ip6t_cmd target_chain_v4 target_chain_v6 rules_removed_flag=0
    ipt_cmd="iptables"; ip6t_cmd="ip6tables"
    target_chain_v4="$IPT_CHAIN"; target_chain_v6="$IPT6_CHAIN"

    local do_block_source do_block_destination
    do_block_source=$(get_config_value "block_source" "$DEFAULT_BLOCK_SOURCE")
    do_block_destination=$(get_config_value "block_destination" "$DEFAULT_BLOCK_DESTINATION")

    local current_ipt_cmd current_target_chain
    if is_ipv6 "$ip_to_whitelist"; then
        current_ipt_cmd="$ip6t_cmd"; current_target_chain="$target_chain_v6"
    elif is_valid_ipv4 "$ip_to_whitelist"; then
        current_ipt_cmd="$ipt_cmd"; current_target_chain="$target_chain_v4"
    else
        log "ERROR" "Invalid IP format for whitelisting: '$ip_to_whitelist'."
        return 1
    fi

    # Remove source blocking rules
    if [[ "$do_block_source" == "1" ]]; then
        local src_match_opt_wl
        if [[ "$ip_to_whitelist" =~ ^([0-9.]+-){1}[0-9.]+$ && "$current_ipt_cmd" == "$ipt_cmd" ]]; then
            src_match_opt_wl="-m iprange --src-range $ip_to_whitelist"
        else
            src_match_opt_wl="-s $ip_to_whitelist"
        fi
        # Loop to delete all matching rules (iptables -D only removes one instance at a time)
        while $current_ipt_cmd -C "$current_target_chain" $src_match_opt_wl -j DROP -m comment --comment "$rule_comment_pattern" &>/dev/null; do
            if $current_ipt_cmd -D "$current_target_chain" $src_match_opt_wl -j DROP -m comment --comment "$rule_comment_pattern"; then
                log "INFO" "Removed SOURCE block rule for IP/Range: $ip_to_whitelist ($rule_comment_pattern)" "verbose"
                rules_removed_flag=1
            else
                log "ERROR" "Error trying to remove SOURCE block for $ip_to_whitelist. Breaking loop."
                break # Avoid infinite loop on error
            fi
        done
    fi

    # Remove destination blocking rules
    if [[ "$do_block_destination" == "1" ]]; then
        local dst_match_opt_wl
        if [[ "$ip_to_whitelist" =~ ^([0-9.]+-){1}[0-9.]+$ && "$current_ipt_cmd" == "$ipt_cmd" ]]; then
            dst_match_opt_wl="-m iprange --dst-range $ip_to_whitelist"
        else
            dst_match_opt_wl="-d $ip_to_whitelist"
        fi
        while $current_ipt_cmd -C "$current_target_chain" $dst_match_opt_wl -j DROP -m comment --comment "$rule_comment_pattern" &>/dev/null; do
            if $current_ipt_cmd -D "$current_target_chain" $dst_match_opt_wl -j DROP -m comment --comment "$rule_comment_pattern"; then
                log "INFO" "Removed DESTINATION block rule for IP/Range: $ip_to_whitelist ($rule_comment_pattern)" "verbose"
                rules_removed_flag=1
            else
                log "ERROR" "Error trying to remove DESTINATION block for $ip_to_whitelist. Breaking loop."
                break
            fi
        done
    fi
    
    # Persist changes if any rules were removed
    # if [[ "$rules_removed_flag" -eq 1 ]]; then make_rules_persistent; fi # Caller often does this in batch
    [[ $rules_removed_flag -eq 1 ]] && return 0 || return 1 # 0 if rules removed, 1 otherwise
}


# Count currently active IP block rules (approximates blocked IPs)
count_blocked_ips() {
    local v4_rule_count=0 v6_rule_count=0
    # Count unique IPs/CIDRs/Ranges in DNSniper v4 chain
    # This is a simplification; true IP count for ranges/CIDRs is complex.
    # This counts *rules*.
    v4_rule_count=$(iptables-save 2>/dev/null | grep -E -- "-A $IPT_CHAIN" | grep -vE -- "-j LOG" | wc -l | awk '{print $1}')
    v6_rule_count=$(ip6tables-save 2>/dev/null | grep -E -- "-A $IPT6_CHAIN" | grep -vE -- "-j LOG" | wc -l | awk '{print $1}')
    echo $((v4_rule_count + v6_rule_count))
}


# Main workhorse function: resolves domains, applies blocks, handles custom IPs.
resolve_block() {
    log "INFO" "DNSniper run started. PID: $$"
    update_status "running" "DNSniper run started" "5" "0"

    local auto_update_is_on
    auto_update_is_on=$(get_config_value "auto_update" "$DEFAULT_AUTO_UPDATE")
    if [[ "$auto_update_is_on" == "1" ]]; then
        log "INFO" "Auto-update is enabled. Starting default list update..."
        # Run update_default in background to not block initial processing too much.
        (nice -n 10 update_default &)
        # Brief sleep to let it kick off, merge_domains will pick up latest if ready.
        sleep 0.5 # Non-critical, just to splay tasks slightly
    fi

    # Concurrently check for expired domains
    log "INFO" "Starting concurrent check for expired domain rules."
    (nice -n 10 check_expired_domains &) 
    local expired_check_pid=$! # Capture PID to wait/check later if needed

    log "INFO" "Merging domain lists..."
    local merged_domains_tmpfile; merged_domains_tmpfile=$(mktemp)
    # Run merge_domains also with lower priority if it's heavy
    if nice -n 8 merge_domains > "$merged_domains_tmpfile"; then
        log "INFO" "Domain lists merged successfully into $merged_domains_tmpfile." "verbose"
    else
        log "ERROR" "Failed to merge domain lists. Aborting domain processing phase."
        rm -f "$merged_domains_tmpfile"
        # Wait for expired_check_pid to finish before erroring out fully
        wait "$expired_check_pid" 2>/dev/null 
        return 1
    fi
    
    local total_domains_in_merged_list; total_domains_in_merged_list=$(wc -l < "$merged_domains_tmpfile" | awk '{print $1}')
    if [[ "$total_domains_in_merged_list" -eq 0 ]]; then
        log "INFO" "No domains to process after merging lists."
        echo_safe "${YELLOW}No domains currently in blocklists.${NC}" # Interactive feedback
    else
        log "INFO" "Processing $total_domains_in_merged_list domains from merged list."
        update_status "running" "Processing $total_domains_in_merged_list domains" "20" "0" # Initial progress for domain phase
        echo_safe "${BLUE}Processing $total_domains_in_merged_list domains...${NC}"

        local dns_lookup_timeout; dns_lookup_timeout=$(get_config_value "timeout" "$DEFAULT_TIMEOUT")
        local domains_processed_count=0 successful_resolves_count=0 ip_rules_added_count=0
        local batch_processing_size=25 # Process in smaller batches for responsiveness & periodic persistence
        local -a current_domain_batch=()
        local overall_start_time; overall_start_time=$(date +%s)

        while IFS= read -r current_domain_from_list || { [[ -n "$current_domain_from_list" ]]; current_domain_batch+=("$current_domain_from_list"); false; }; do
            # Add to batch. The 'false' part ensures last line is processed if no trailing newline.
            [[ -n "$current_domain_from_list" ]] && current_domain_batch+=("$current_domain_from_list")

            if [[ ${#current_domain_batch[@]} -ge $batch_processing_size || \
                  ($((domains_processed_count + ${#current_domain_batch[@]})) -ge $total_domains_in_merged_list && ${#current_domain_batch[@]} -gt 0) ]]; then
                # Process the current batch
                for a_domain_in_batch in "${current_domain_batch[@]}"; do
                    domains_processed_count=$((domains_processed_count + 1))
                    local current_progress_percent=$((20 + (domains_processed_count * 60 / total_domains_in_merged_list))) # Domain processing up to 80%
                    local time_elapsed_so_far=$(( $(date +%s) - overall_start_time ))
                    local estimated_time_remaining=0
                    if [[ $domains_processed_count -gt 5 && $time_elapsed_so_far -gt 1 ]]; then # Basic ETA
                        estimated_time_remaining=$(( (time_elapsed_so_far * (total_domains_in_merged_list - domains_processed_count)) / domains_processed_count ))
                    fi
                    update_status "running" "Domain $domains_processed_count/$total_domains_in_merged_list: $a_domain_in_batch" \
                        "$current_progress_percent" "$estimated_time_remaining"

                    if ! is_valid_domain "$a_domain_in_batch"; then
                        log "WARNING" "Skipping invalid domain from list: '$a_domain_in_batch'"
                        continue
                    fi
                    
                    log "INFO" "Attempting to resolve IPs for: $a_domain_in_batch" "verbose"
                    local -a resolved_ips_for_domain=()
                    mapfile -t resolved_ips_for_domain < <(resolve_domain "$a_domain_in_batch" "$dns_lookup_timeout")

                    if [[ ${#resolved_ips_for_domain[@]} -eq 0 ]]; then
                        log "WARNING" "No valid IPs resolved for domain: '$a_domain_in_batch'" "verbose"
                        continue # Skip to next domain in batch
                    fi
                    successful_resolves_count=$((successful_resolves_count + 1))
                    
                    local resolved_ips_as_csv; resolved_ips_as_csv=$(IFS=,; echo "${resolved_ips_for_domain[*]}")
                    record_history "$a_domain_in_batch" "$resolved_ips_as_csv" # Record all resolved IPs

                    for an_ip_address in "${resolved_ips_for_domain[@]}"; do
                        if is_critical_ip "$an_ip_address"; then
                            log "WARNING" "Skipping critical IP '$an_ip_address' for domain '$a_domain_in_batch'." "verbose"
                            continue
                        fi
                        if block_ip "$an_ip_address" "DNSniper: $a_domain_in_batch"; then
                            ip_rules_added_count=$((ip_rules_added_count + 1))
                            # Log for block_ip itself is verbose, no need for duplicate here unless summarizing
                        fi
                    done
                done # End of batch domain loop
                make_rules_persistent # Persist firewall rules after each batch
                current_domain_batch=() # Reset batch for next set of domains
                log "INFO" "Batch processed. $domains_processed_count/$total_domains_in_merged_list domains handled." "verbose"
            fi # End of batch processing trigger
        done < "$merged_domains_tmpfile"
        
        log "INFO" "Domain processing phase complete. $successful_resolves_count domains had IPs resolved. $ip_rules_added_count IP rules potentially added/verified."
        echo_safe "${GREEN}Domain processing finished. Resolved $successful_resolves_count domains. Added/verified $ip_rules_added_count IP rules.${NC}"
        
        # Optional: CDN Detection (can be slow, run if interactive or forced)
        if [[ -t 1 || "${1:-}" == "--force-cdn-check" ]]; then
             update_status "running" "Performing CDN detection analysis" "85" "0"
             local -a domains_list_for_cdn_check=()
             mapfile -t domains_list_for_cdn_check < "$merged_domains_tmpfile" # Read the processed list
             if [[ ${#domains_list_for_cdn_check[@]} -gt 0 ]]; then
                 nice -n 15 detect_cdn "${domains_list_for_cdn_check[@]}"
             fi
        fi
    fi # End if total_domains > 0
    rm -f "$merged_domains_tmpfile"

    # Process Custom IPs
    log "INFO" "Processing custom IP block list."
    update_status "running" "Processing custom IP list" "90" "0"
    local custom_ips_tmpfile; custom_ips_tmpfile=$(mktemp)
    nice -n 8 get_custom_ips > "$custom_ips_tmpfile" # get_custom_ips is optimized
    local total_custom_ips_to_process; total_custom_ips_to_process=$(wc -l < "$custom_ips_tmpfile" | awk '{print $1}')

    if [[ "$total_custom_ips_to_process" -gt 0 ]]; then
        echo_safe "${BLUE}Processing $total_custom_ips_to_process custom IP entries...${NC}"
        local custom_ip_rules_added_count=0
        while IFS= read -r custom_ip_entry_to_block; do
            if is_critical_ip "$custom_ip_entry_to_block"; then
                log "WARNING" "Skipping critical custom IP: '$custom_ip_entry_to_block'" "verbose"
                continue
            fi
            if block_ip "$custom_ip_entry_to_block" "DNSniper: custom IP"; then
                custom_ip_rules_added_count=$((custom_ip_rules_added_count + 1))
            fi
        done < "$custom_ips_tmpfile"
        log "INFO" "Custom IP processing complete. $custom_ip_rules_added_count custom IP rules potentially added/verified."
        echo_safe "${GREEN}Custom IP processing finished. Added/verified $custom_ip_rules_added_count rules.${NC}"
    else
        log "INFO" "No custom IPs to process."
    fi
    rm -f "$custom_ips_tmpfile"
    
    # Wait for the concurrent expired domain check to finish if it hasn't already
    if kill -0 "$expired_check_pid" 2>/dev/null; then
        log "INFO" "Waiting for background expired domain check (PID $expired_check_pid) to complete..." "verbose"
        update_status "running" "Finalizing: Waiting for expiration check" "95" "0"
        wait "$expired_check_pid" 2>/dev/null || log "WARNING" "Background expired domain check (PID $expired_check_pid) finished with an error or was already done."
    fi
    log "INFO" "Expired domain check process has completed."

    update_status "running" "Finalizing: Persisting all firewall rule changes" "98" "0"
    make_rules_persistent # Final comprehensive persistence
    
    update_status "completed" "DNSniper run finished successfully." "100" "0"
    log "INFO" "DNSniper run completed. PID: $$"
    return 0
}