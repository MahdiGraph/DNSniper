#!/usr/bin/env bash
# DNSniper Core Functions - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.0

# Strict error handling mode
set -o errexit
set -o pipefail
set -o nounset

# ANSI color codes and formatting
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
WHITE='\e[97m'
MAGENTA='\e[35m'
BOLD='\e[1m'
DIM='\e[2m'
NC='\e[0m'

# Paths
BASE_DIR="/etc/dnsniper"
DEFAULT_FILE="$BASE_DIR/domains-default.txt"
ADD_FILE="$BASE_DIR/domains-add.txt"
REMOVE_FILE="$BASE_DIR/domains-remove.txt"
IP_ADD_FILE="$BASE_DIR/ips-add.txt"
IP_REMOVE_FILE="$BASE_DIR/ips-remove.txt"
CONFIG_FILE="$BASE_DIR/config.conf"
DB_FILE="$BASE_DIR/history.db"
RULES_V4_FILE="$BASE_DIR/iptables.rules"
RULES_V6_FILE="$BASE_DIR/ip6tables.rules"
BIN_CMD="/usr/local/bin/dnsniper"
LOG_FILE="$BASE_DIR/dnsniper.log"
LOCK_FILE="$BASE_DIR/dnsniper.lock"

# IPSet definitions
IPSET4="dnsniper-ipv4"
IPSET6="dnsniper-ipv6"

# Logging state
LOGGING_ENABLED=0

# Retrieve latest commit hash from GitHub
latest_commit=$(git ls-remote https://github.com/MahdiGraph/DNSniper.git | head -n 1 | cut -f1)
if [[ -z "$latest_commit" ]]; then
    echo -e "${RED}${BOLD}Error:${NC} Failed to retrieve latest commit hash."
    exit 1
fi

# Defaults
DEFAULT_SCHEDULER_ENABLED=1
DEFAULT_SCHEDULE_MINUTES=60
DEFAULT_MAX_IPS=10
DEFAULT_TIMEOUT=30
DEFAULT_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/${latest_commit}/domains-default.txt"
DEFAULT_AUTO_UPDATE=1
DEFAULT_EXPIRE_ENABLED=1
DEFAULT_EXPIRE_MULTIPLIER=5
DEFAULT_BLOCK_SOURCE=1
DEFAULT_BLOCK_DESTINATION=1
DEFAULT_LOGGING_ENABLED=0

# Chain names
IPT_CHAIN="DNSniper"
IPT6_CHAIN="DNSniper6"

# Version
VERSION="2.1.0"

# Dependencies
DEPENDENCIES=(iptables ip6tables curl dig sqlite3)

# Helper functions
log() {
    local level="$1" message="$2" verbose="${3:-}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # Only write to log file if logging is enabled
    if [[ $LOGGING_ENABLED -eq 1 ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${RED}Error:${NC} $message" >&2
    elif [[ "$level" == "WARNING" ]]; then
        echo -e "${YELLOW}Warning:${NC} $message" >&2
    elif [[ "$level" == "INFO" && "$verbose" == "verbose" ]]; then
        echo -e "${BLUE}Info:${NC} $message"
    fi
}

# Initialize logging state
initialize_logging() {
    # Read from config file
    local logging_setting=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$logging_setting" == "1" ]]; then
        LOGGING_ENABLED=1
    else
        LOGGING_ENABLED=0
    fi
}

# Enhanced echo with error checking
echo_safe() {
    echo -e "$1"
}

# SQL escape
sql_escape() {
    local s=$1
    s=${s//\'/\'\'}
    printf "%s" "$s"
}

# Check if IP is IPv6
is_ipv6() {
    local ip="$1"
    [[ "$ip" =~ .*:.* ]]  # Simple pattern for IPv6 detection
}

# Validate IPv4
is_valid_ipv4() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ "$octet" -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Validate domain
is_valid_domain() {
    local domain="$1"
    # Basic domain name validation
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

# Check if an IP is critical (system IP, private network, etc.)
is_critical_ip() {
    local ip="$1"
    # Check common private/local IPs
    [[ "$ip" == "127.0.0.1" ||
       "$ip" == "0.0.0.0" ||
       "$ip" == "::1" ||
       "$ip" =~ ^169\.254\. ||
       "$ip" =~ ^192\.168\. ||
       "$ip" =~ ^10\. ||
       "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
    # Check server's public IP
    local server_ip
    server_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || curl -s --max-time 5 icanhazip.com 2>/dev/null || echo "")
    [[ -n "$server_ip" && "$ip" == "$server_ip" ]] && return 0
    # Check default gateway
    if command -v ip &>/dev/null; then
        local gateway
        gateway=$(ip route | grep default | awk '{print $3}' | head -n 1)
        [[ -n "$gateway" && "$ip" == "$gateway" ]] && return 0
    fi
    return 1
}

# Exit with error message
exit_with_error() {
    log "ERROR" "$1"
    echo -e "${RED}Error:${NC} $1" >&2
    exit "${2:-1}"
}

# Detect persistence mechanism and OS type
detect_system() {
    # Detect OS family with more comprehensive checks
    if [[ -f /etc/debian_version ]]; then
        # Check for Ubuntu specifically
        if grep -qi ubuntu /etc/os-release 2>/dev/null; then
            echo "ubuntu"
        else
            echo "debian"
        fi
    elif [[ -f /etc/redhat-release ]]; then
        # Check for CentOS or RHEL
        if grep -qi "centos\|centos linux" /etc/redhat-release 2>/dev/null; then
            echo "centos"
        elif grep -qi "red hat\|redhat" /etc/redhat-release 2>/dev/null; then
            echo "rhel"
        else
            echo "redhat" # Generic RedHat-based
        fi
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    elif [[ -f /etc/os-release ]]; then
        # Check /etc/os-release for more information
        if grep -qi "debian" /etc/os-release; then
            echo "debian"
        elif grep -qi "ubuntu" /etc/os-release; then
            echo "ubuntu"
        elif grep -qi "centos" /etc/os-release; then
            echo "centos"
        elif grep -qi "fedora" /etc/os-release; then
            echo "fedora"
        elif grep -qi "red hat\|rhel" /etc/os-release; then
            echo "rhel"
        else
            echo "unknown"
        fi
    else
        echo "unknown"
    fi
}

# Make iptables rules persistent based on system type
make_rules_persistent() {
    local os_type=$(detect_system)
    # Create necessary directories based on OS type
    if [[ "$os_type" == "debian" || "$os_type" == "ubuntu" ]]; then
        mkdir -p /etc/iptables/ 2>/dev/null || true
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        chmod 644 /etc/iptables/rules.v4 /etc/iptables/rules.v6 2>/dev/null || true
    elif [[ "$os_type" == "centos" || "$os_type" == "rhel" || "$os_type" == "redhat" ]]; then
        # CentOS/RHEL uses /etc/sysconfig
        if [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
            chmod 600 /etc/sysconfig/iptables /etc/sysconfig/ip6tables 2>/dev/null || true
        fi
    elif [[ "$os_type" == "fedora" ]]; then
        # Fedora might use firewalld, but we'll save rules to same location as RHEL
        if [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
        fi
    fi
    # Save to our local rules files too for backup
    iptables-save > "$RULES_V4_FILE" 2>/dev/null || true
    ip6tables-save > "$RULES_V6_FILE" 2>/dev/null || true
    # Save ipset if available (optional)
    if command -v ipset &>/dev/null && ipset list ${IPSET4} >/dev/null 2>&1; then
        ipset save > /etc/ipset.conf 2>/dev/null || true
    fi
}

# Initialize iptables chains
initialize_chains() {
    # Create IPv4 chain if it doesn't exist
    if ! iptables -L "$IPT_CHAIN" &>/dev/null; then
        iptables -N "$IPT_CHAIN" 2>/dev/null || true
        log "INFO" "Created IPv4 chain $IPT_CHAIN" "verbose"
    fi
    # Create IPv6 chain if it doesn't exist
    if ! ip6tables -L "$IPT6_CHAIN" &>/dev/null; then
        ip6tables -N "$IPT6_CHAIN" 2>/dev/null || true
        log "INFO" "Created IPv6 chain $IPT6_CHAIN" "verbose"
    fi
    # Make sure our chains are referenced in the main chains if not already
    if ! iptables -C INPUT -j "$IPT_CHAIN" &>/dev/null; then
        iptables -I INPUT -j "$IPT_CHAIN" 2>/dev/null || true
    fi
    if ! iptables -C OUTPUT -j "$IPT_CHAIN" &>/dev/null; then
        iptables -I OUTPUT -j "$IPT_CHAIN" 2>/dev/null || true
    fi
    if ! ip6tables -C INPUT -j "$IPT6_CHAIN" &>/dev/null; then
        ip6tables -I INPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    fi
    if ! ip6tables -C OUTPUT -j "$IPT6_CHAIN" &>/dev/null; then
        ip6tables -I OUTPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    fi
    # Make the rules persistent
    make_rules_persistent
}

# Prepare environment: dirs, files, DB
ensure_environment() {
    # Create base directory if it doesn't exist
    mkdir -p "$BASE_DIR" 2>/dev/null || true
    
    # Create empty files if they don't exist
    touch "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$IP_ADD_FILE" "$IP_REMOVE_FILE" 2>/dev/null || true
    
    # Create config file with defaults if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
# DNSniper Configuration
scheduler_enabled=$DEFAULT_SCHEDULER_ENABLED
schedule_minutes=$DEFAULT_SCHEDULE_MINUTES
max_ips=$DEFAULT_MAX_IPS
timeout=$DEFAULT_TIMEOUT
update_url='$DEFAULT_URL'
auto_update=$DEFAULT_AUTO_UPDATE
expire_enabled=$DEFAULT_EXPIRE_ENABLED
expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
block_source=$DEFAULT_BLOCK_SOURCE
block_destination=$DEFAULT_BLOCK_DESTINATION
logging_enabled=$DEFAULT_LOGGING_ENABLED
EOF
    fi
    
    # Check for required commands
    for cmd in ${DEPENDENCIES[@]}; do
        if ! command -v $cmd >/dev/null 2>&1; then
            echo "Warning: $cmd is not installed. Some features may not work." >&2
        fi
    done
    
    # Initialize SQLite DB: safe defaults + busy_timeout
# Initialize SQLite DB: simple and reliable
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$DB_FILE" <<SQL
PRAGMA busy_timeout = 3000;
CREATE TABLE IF NOT EXISTS history(
    domain TEXT,
    ips    TEXT,
    ts     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_history_domain ON history(domain);
CREATE TABLE IF NOT EXISTS expired_domains(
    domain TEXT PRIMARY KEY,
    last_seen TEXT,
    source TEXT
);
SQL
    else
        echo "Warning: sqlite3 not found, database functionality disabled." >&2
    fi


    
    # Initialize iptables chains
    initialize_chains
    
    # Initialize ipset if available
    if command -v ipset >/dev/null 2>&1; then
        ipset create "$IPSET4" hash:ip family inet -exist 2>/dev/null || true
        ipset create "$IPSET6" hash:ip family inet6 -exist 2>/dev/null || true
    fi
    
    # Initialize logging
    initialize_logging
    
    return 0
}

# Check privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        exit_with_error "Must run as root (sudo)."
    fi
}

# Check dependencies
check_dependencies() {
    local missing=()
    for cmd in "${DEPENDENCIES[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        exit_with_error "Missing dependencies: ${missing[*]}\nPlease install them using your system's package manager."
    fi
}

# Fetch default domains list
update_default() {
    log "INFO" "Updating default domains list" "verbose"
    local update_url=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$update_url" ]]; then
        update_url="$DEFAULT_URL"
    fi
    if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]]; then
        timeout="$DEFAULT_TIMEOUT"
    fi
    echo_safe "${BLUE}Fetching default domains from $update_url...${NC}"
    
    # Keep track of domains that were in the default list but are removed now
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$expire_enabled" == "1" ]]; then
        # Get current default domains
        local old_domains=()
        if [[ -f "$DEFAULT_FILE" ]]; then
            while IFS= read -r d || [[ -n "$d" ]]; do
                [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
                d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
                [[ -z "$d" ]] && continue
                old_domains+=("$d")
            done < "$DEFAULT_FILE"
        fi
    fi
    
    if curl -sfL --connect-timeout "$timeout" --max-time "$timeout" "$update_url" -o "$DEFAULT_FILE.tmp"; then
        # Verify the downloaded file has content
        if [[ -s "$DEFAULT_FILE.tmp" ]]; then
            if ! mv "$DEFAULT_FILE.tmp" "$DEFAULT_FILE"; then
                rm -f "$DEFAULT_FILE.tmp" &>/dev/null || true
                log "ERROR" "Failed to update default domains file"
                echo_safe "${RED}Failed to update default domains file${NC}"
                return 1
            fi
            
            # Process expired domains if feature is enabled
            if [[ "$expire_enabled" == "1" ]]; then
                # Get new default domains
                local new_domains=()
                while IFS= read -r d || [[ -n "$d" ]]; do
                    [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
                    d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
                    [[ -z "$d" ]] && continue
                    new_domains+=("$d")
                done < "$DEFAULT_FILE"
                
                # Find domains that were in old list but not in new list
                for old_dom in "${old_domains[@]}"; do
                    local found=0
                    for new_dom in "${new_domains[@]}"; do
                        if [[ "$old_dom" == "$new_dom" ]]; then
                            found=1
                            break
                        fi
                    done
                    if [[ $found -eq 0 ]]; then
                        # Domain was removed, add/update in expired_domains table
                        local esc_dom=$(sql_escape "$old_dom")
                        sqlite3 "$DB_FILE" <<SQL 2>/dev/null
INSERT OR REPLACE INTO expired_domains(domain, last_seen, source)
VALUES('$esc_dom', datetime('now'), 'default');
SQL
                        log "INFO" "Tracking expired domain: $old_dom" "verbose"
                    fi
                done
            fi
            
            log "INFO" "Default domains successfully updated" "verbose"
            echo_safe "${GREEN}Default domains successfully updated${NC}"
        else
            rm -f "$DEFAULT_FILE.tmp" &>/dev/null || true
            log "ERROR" "Downloaded file is empty"
            echo_safe "${RED}Downloaded file is empty${NC}"
            return 1
        fi
    else
        rm -f "$DEFAULT_FILE.tmp" 2>/dev/null || true
        log "ERROR" "Error downloading default domains from $update_url"
        echo_safe "${RED}Error downloading default domains${NC}"
        return 1
    fi
    return 0
}

# Check for expired domains and remove their rules
check_expired_domains() {
    # Check if domain expiration is enabled
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$expire_enabled" != "1" ]]; then
        return 0
    fi
    
    log "INFO" "Checking for expired domains" "verbose"
    
    # Get schedule to determine update frequency
    local schedule_minutes=$(grep '^schedule_minutes=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$schedule_minutes" || ! "$schedule_minutes" =~ ^[0-9]+$ ]]; then
        schedule_minutes=$DEFAULT_SCHEDULE_MINUTES
    fi
    
    # Get expiration multiplier
    local expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]]; then
        expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
    fi
    
    # Calculate expiration time in minutes
    local expire_minutes=$((schedule_minutes * expire_multiplier))
    
    # Get domains that have expired
    local expired_domains
    expired_domains=$(sqlite3 "$DB_FILE" "SELECT domain FROM expired_domains
                                        WHERE source='default' AND
                                        datetime(last_seen, '+$expire_minutes minutes') < datetime('now');" 2>/dev/null)
    
    # Process expired domains
    if [[ -n "$expired_domains" ]]; then
        echo_safe "${YELLOW}Found expired domains to clean up...${NC}"
        while IFS= read -r domain; do
            echo_safe "${YELLOW}Removing expired domain:${NC} $domain"
            # Get IPs associated with this domain
            local esc_dom=$(sql_escape "$domain")
            local ips
            ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
            if [[ -n "$ips" ]]; then
                IFS=',' read -ra ip_list <<< "$ips"
                # Unblock each IP
                for ip in "${ip_list[@]}"; do
                    if unblock_ip "$ip" "DNSniper: $domain"; then
                        echo_safe "  - ${GREEN}Unblocked expired IP:${NC} $ip"
                    fi
                done
            fi
            # Remove from expired domains tracking
            sqlite3 "$DB_FILE" "DELETE FROM expired_domains WHERE domain='$esc_dom';" 2>/dev/null
            # If domain was manually added to remove list, honor that
            if ! grep -Fxq "$domain" "$REMOVE_FILE" 2>/dev/null; then
                echo "$domain" >> "$REMOVE_FILE"
            fi
            log "INFO" "Removed expired domain: $domain" "verbose"
        done <<< "$expired_domains"
        # Make rules persistent
        make_rules_persistent
    fi
}

# Merge default + added, minus removed domains
# Performance optimized version of merge_domains
merge_domains() {
    log "INFO" "Merging domain lists"
    # Use temporary files for better performance with large lists
    local tmpfile=$(mktemp)
    # Start with default domains, filtering comments and empty lines
    if [[ -f "$DEFAULT_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$DEFAULT_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile" || true
    fi
    # Add custom domains, filtering duplicates
    if [[ -f "$ADD_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$ADD_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | while read -r domain; do
            if ! grep -Fxq "$domain" "$tmpfile"; then
                echo "$domain" >> "$tmpfile"
            fi
        done
    fi
    # Apply removals by grep -v for each line in REMOVE_FILE
    if [[ -f "$REMOVE_FILE" && -s "$tmpfile" ]]; then
        local tmprm=$(mktemp)
        cp "$tmpfile" "$tmprm"
        grep -v '^[[:space:]]*#' "$REMOVE_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | while read -r domain; do
            if [[ -n "$domain" ]]; then
                grep -Fxv "$domain" "$tmprm" > "$tmpfile" || true
                cp "$tmpfile" "$tmprm"
            fi
        done
        rm -f "$tmprm"
    fi
    # Output results
    cat "$tmpfile"
    # Clean up
    rm -f "$tmpfile"
}

# Get list of custom IPs to block
get_custom_ips() {
    log "INFO" "Getting custom IP list"
    # Use temporary files for better performance with large lists
    local tmpfile=$(mktemp)
    # Get custom IPs, filtering comments and empty lines
    if [[ -f "$IP_ADD_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$IP_ADD_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile" || true
    fi
    # Apply removals
    if [[ -f "$IP_REMOVE_FILE" && -s "$tmpfile" ]]; then
        local tmprm=$(mktemp)
        cp "$tmpfile" "$tmprm"
        grep -v '^[[:space:]]*#' "$IP_REMOVE_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | while read -r ip; do
            if [[ -n "$ip" ]]; then
                grep -Fxv "$ip" "$tmprm" > "$tmpfile" || true
                cp "$tmpfile" "$tmprm"
            fi
        done
        rm -f "$tmprm"
    fi
    # Filter invalid IPs
    if [[ -s "$tmpfile" ]]; then
        local tmpvalid=$(mktemp)
        while IFS= read -r ip; do
            if is_ipv6 "$ip" || is_valid_ipv4 "$ip"; then
                echo "$ip" >> "$tmpvalid"
            else
                log "WARNING" "Invalid IP format ignored: $ip"
            fi
        done < "$tmpfile"
        cat "$tmpvalid"
        rm -f "$tmpvalid"
    fi
    # Clean up
    rm -f "$tmpfile"
}

# Record history and trim to max_ips
record_history() {
    local domain="$1" ips_csv="$2"
    # Protect against SQL injection
    domain=$(sql_escape "$domain")
    ips_csv=$(sql_escape "$ips_csv")
    log "INFO" "Recording history for domain: $domain with IPs: $ips_csv"
    local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Validate max_ips
    if [[ -z "$max_ips" || ! "$max_ips" =~ ^[0-9]+$ ]]; then
        log "WARNING" "Invalid max_ips value, using default: $DEFAULT_MAX_IPS"
        max_ips=$DEFAULT_MAX_IPS
    fi
    if ! sqlite3 "$DB_FILE" <<SQL 2>/dev/null
INSERT INTO history(domain,ips,ts) VALUES('$domain','$ips_csv',strftime('%s','now'));
DELETE FROM history
WHERE rowid NOT IN (
   SELECT rowid FROM history
   WHERE domain='$domain'
   ORDER BY ts DESC
   LIMIT $max_ips
);
SQL
    then
        log "ERROR" "Error recording history for domain: $domain"
        return 1
    fi
    return 0
}

# Detect CDN by comparing last two resolves
detect_cdn() {
    # Get domains from args
    local domains=("$@")
    if [[ ${#domains[@]} -eq 0 ]]; then
        return 0
    fi
    local warnings=()
    log "INFO" "Detecting CDN usage for ${#domains[@]} domains"
    # Process domains in smaller batches for better performance
    local batch_size=50
    local total_domains=${#domains[@]}
    for ((i=0; i<total_domains; i+=batch_size)); do
        local end=$((i + batch_size))
        [[ $end -gt $total_domains ]] && end=$total_domains
        # Process this batch
        for ((j=i; j<end; j++)); do
            local dom="${domains[j]}"
            # Escape special characters for SQL
            local esc_dom=$(sql_escape "$dom")
            # Get the last two sets of IPs for this domain
            local rows
            rows=$(sqlite3 -separator '|' "$DB_FILE" \
                "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 2;" 2>/dev/null)
            # Continue if we don't have enough history
            if [[ -z "$rows" || $(echo "$rows" | wc -l) -lt 2 ]]; then
                continue
            fi
            # Parse rows into arrays
            local last prev
            IFS='|' read -r last prev <<< "$rows"
            # Skip if either is empty
            [[ -z "$last" || -z "$prev" ]] && continue
            # Convert CSV to arrays
            local last_ips prev_ips
            IFS=',' read -ra last_ips <<< "$last"
            IFS=',' read -ra prev_ips <<< "$prev"
            # Compare the IP sets
            local changes=0
            for ip in "${last_ips[@]}"; do
                local found=0
                for pip in "${prev_ips[@]}"; do
                    if [[ "$ip" == "$pip" ]]; then
                        found=1
                        break
                    fi
                done
                if [[ $found -eq 0 ]]; then
                    changes=1
                    break
                fi
            done
            [[ $changes -eq 1 ]] && warnings+=("$dom")
        done
    done
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo_safe "${YELLOW}${BOLD}[!] Domains likely using CDN:${NC}"
        # Display warnings in a more readable format for large lists
        if [[ ${#warnings[@]} -le 10 ]]; then
            # Show all if 10 or fewer
            echo_safe "${YELLOW}${warnings[*]}${NC}"
        else
            # Show first 10 with count if more than 10
            for ((i=0; i<10; i++)); do
                echo_safe "${YELLOW}${warnings[i]}${NC}"
            done
            echo_safe "${YELLOW}...and $((${#warnings[@]} - 10)) more${NC}"
        fi
        log "WARNING" "Potential CDN domains detected: ${warnings[*]}"
    fi
}

# Block a specific IP with iptables/ip6tables
block_ip() {
    local ip="$1" comment="$2"
    local tbl="iptables"
    local chain="$IPT_CHAIN"
    # Use correct iptables command based on IP type
    if is_ipv6 "$ip"; then
        tbl="ip6tables"
        chain="$IPT6_CHAIN"
    fi
    # Get rule type settings
    local block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Validate settings, use defaults if invalid
    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
    local rules_added=0
    # Block source IP in INPUT chain if enabled
    if [[ "$block_source" == "1" ]]; then
        if ! $tbl -C "$chain" -s "$ip" -j DROP -m comment --comment "$comment" &>/dev/null; then
            if $tbl -A "$chain" -s "$ip" -j DROP -m comment --comment "$comment"; then
                rules_added=1
            else
                log "ERROR" "Failed to add source rule for $ip" "verbose"
            fi
        fi
    fi
    # Block destination IP in OUTPUT chain if enabled
    if [[ "$block_destination" == "1" ]]; then
        if ! $tbl -C "$chain" -d "$ip" -j DROP -m comment --comment "$comment" &>/dev/null; then
            if $tbl -A "$chain" -d "$ip" -j DROP -m comment --comment "$comment"; then
                rules_added=1
            else
                log "ERROR" "Failed to add destination rule for $ip" "verbose"
            fi
        fi
    fi
    return $((1 - rules_added))
}

# Unblock a specific IP from iptables/ip6tables
unblock_ip() {
    local ip="$1" comment_pattern="$2"
    local tbl="iptables"
    local chain="$IPT_CHAIN"
    local success=0
    # Use correct iptables command based on IP type
    if is_ipv6 "$ip"; then
        tbl="ip6tables"
        chain="$IPT6_CHAIN"
    fi
    # Get rule type settings to know what to unblock
    local block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Validate settings, use defaults if invalid
    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
    # Try to remove rule from chain (source)
    if [[ "$block_source" == "1" ]]; then
        while $tbl -C "$chain" -s "$ip" -j DROP -m comment --comment "$comment_pattern" &>/dev/null 2>&1; do
            $tbl -D "$chain" -s "$ip" -j DROP -m comment --comment "$comment_pattern"
            success=1
        done
    fi
    # Try to remove rule from chain (destination)
    if [[ "$block_destination" == "1" ]]; then
        while $tbl -C "$chain" -d "$ip" -j DROP -m comment --comment "$comment_pattern" &>/dev/null 2>&1; do
            $tbl -D "$chain" -d "$ip" -j DROP -m comment --comment "$comment_pattern"
            success=1
        done
    fi
    # Make rules persistent if we made changes
    if [[ $success -eq 1 ]]; then
        make_rules_persistent
    fi
    return $((1 - success))
}

# Count actual blocked IPs (not just rules)
count_blocked_ips() {
    local v4_rules v6_rules
    # Use more efficient approach for large rule sets
    # For IPv4 rules
    v4_rules=$(iptables-save 2>/dev/null | grep -E "$IPT_CHAIN.*DROP" | grep -o -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l)
    # For IPv6 rules
    v6_rules=$(ip6tables-save 2>/dev/null | grep -E "$IPT6_CHAIN.*DROP" | grep -o -E '([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}' | sort -u | wc -l)
    # Return total
    echo $((v4_rules + v6_rules))
}

# Check if a domain has active IP blocks
has_active_blocks() {
    local domain="$1"
    local esc_dom=$(sql_escape "$domain")
    # First check if domain exists in history
    local count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM history WHERE domain='$esc_dom';" 2>/dev/null || echo 0)
    if [[ $count -eq 0 ]]; then
        return 1  # No records found
    fi
    # Get the most recent IPs for this domain
    local ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
    if [[ -z "$ips" ]]; then
        return 1  # No IPs found
    fi
    # Convert CSV to array
    local ip_list=()
    IFS=',' read -ra ip_list <<< "$ips"
    # Check if any IP is actively blocked
    for ip in "${ip_list[@]}"; do
        local blocked=0
        # Determine which table to use
        local tbl="iptables"
        if is_ipv6 "$ip"; then
            tbl="ip6tables"
        fi
        # Check if IP is blocked in firewall
        if $tbl-save 2>/dev/null | grep -q "$ip.*DNSniper: $domain"; then
            return 0  # At least one IP is actively blocked
        fi
    done
    return 1  # No active blocks found
}

# Resolve domains and apply iptables/ip6tables rules - Performance optimized
resolve_block() {
    log "INFO" "Starting domain resolution and blocking" "verbose"
    # Check if we should auto-update
    local auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$auto_update" || ! "$auto_update" =~ ^[0-9]+$ ]]; then
        auto_update=$DEFAULT_AUTO_UPDATE
    fi
    if [[ $auto_update -eq 1 ]]; then
        echo_safe "${BLUE}Auto-updating domain lists...${NC}"
        update_default
    fi
    # Check for expired domains
    check_expired_domains
    echo_safe "${BLUE}Resolving domains...${NC}"
    # Get domains
    local domains=()
    # Using temp file approach for better performance with large domain lists
    local tmpdomains=$(mktemp)
    merge_domains > "$tmpdomains"
    # Count domains
    local total=$(wc -l < "$tmpdomains")
    if [[ $total -eq 0 ]]; then
        echo_safe "${YELLOW}No domains to process.${NC}"
        log "INFO" "No domains to process" "verbose"
        rm -f "$tmpdomains"
    else
        echo_safe "${BLUE}Processing ${total} domains...${NC}"
        # Get timeout from settings
        local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]]; then
            log "WARNING" "Invalid timeout value, using default: $DEFAULT_TIMEOUT"
            timeout=$DEFAULT_TIMEOUT
        fi
        local success_count=0
        local ip_count=0
        # Process domains in batches for better performance
        local batch_size=50
        local progress=0
        while IFS= read -r dom || [[ -n "$dom" ]]; do
            progress=$((progress + 1))
            # Show progress for large domain lists
            if [[ $total -gt 100 && $((progress % 10)) -eq 0 ]]; then
                echo_safe "${BLUE}Progress: $progress/$total domains ($(( (progress * 100) / total ))%)${NC}"
            fi
            # Skip invalid domains
            if ! is_valid_domain "$dom"; then
                log "WARNING" "Invalid domain format: $dom"
                continue
            fi
            log "INFO" "Processing domain: $dom" "verbose"
            # Resolve IPv4 addresses with timeout
            local v4=()
            mapfile -t v4 < <(dig +short +time="$timeout" +tries=2 A "$dom" 2>/dev/null || echo "")
            # Resolve IPv6 addresses with timeout
            local v6=()
            mapfile -t v6 < <(dig +short +time="$timeout" +tries=2 AAAA "$dom" 2>/dev/null || echo "")
            # Combine and deduplicate
            local all=("${v4[@]}" "${v6[@]}")
            local unique=()
            # Deduplicate and filter invalid IPs
            for ip in "${all[@]}"; do
                [[ -z "$ip" ]] && continue
                # Skip if not a valid IP format
                if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_ipv6 "$ip"; then
                    log "WARNING" "Invalid IP format: $ip for domain $dom"
                    continue
                fi
                # Check if it's a critical IP
                if is_critical_ip "$ip"; then
                    log "WARNING" "Skipping critical IP: $ip for domain $dom" "verbose"
                    continue
                fi
                # Check if already in unique array
                local found=0
                for u in "${unique[@]}"; do
                    if [[ "$u" == "$ip" ]]; then
                        found=1
                        break
                    fi
                done
                [[ $found -eq 0 ]] && unique+=("$ip")
            done
            # If no valid IPs found
            if [[ ${#unique[@]} -eq 0 ]]; then
                log "WARNING" "No valid IP addresses found for domain: $dom" "verbose"
                continue
            fi
            # Convert array to CSV for storage
            local ips_csv=$(IFS=,; echo "${unique[*]}")
            # Record in history
            if record_history "$dom" "$ips_csv"; then
                success_count=$((success_count + 1))
            fi
            # Block each IP
            for ip in "${unique[@]}"; do
                if block_ip "$ip" "DNSniper: $dom"; then
                    log "INFO" "Successfully blocked IP: $ip for domain: $dom"
                    ip_count=$((ip_count + 1))
                else
                    log "ERROR" "Error blocking IP: $ip for domain: $dom"
                fi
            done
            # Periodically make rules persistent for large domain lists
            if [[ $total -gt 100 && $((progress % 50)) -eq 0 ]]; then
                make_rules_persistent
            fi
        done < "$tmpdomains"
        # Clean up
        rm -f "$tmpdomains"
        echo_safe "${GREEN}Domain resolution complete. $success_count/$total domains processed, $ip_count new IPs blocked.${NC}"
        log "INFO" "Domain resolution complete. $success_count/$total domains processed, $ip_count new IPs blocked." "verbose"
        # Run CDN detection only for interactive mode or if explicitly requested
        if [[ -t 1 || "$1" == "force-cdn-check" ]]; then
            # Get list of domains again for CDN detection
            mapfile -t domains < <(merge_domains)
            detect_cdn "${domains[@]}"
        fi
    fi
    # Also block custom IPs
    local custom_ips=()
    local tmpcustomips=$(mktemp)
    get_custom_ips > "$tmpcustomips"
    local custom_total=$(wc -l < "$tmpcustomips")
    if [[ $custom_total -gt 0 ]]; then
        echo_safe "${BLUE}Processing ${custom_total} custom IPs...${NC}"
        local custom_blocked=0
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            # Skip critical IPs
            if is_critical_ip "$ip"; then
                log "WARNING" "Skipping critical IP: $ip" "verbose"
                continue
            fi
            if block_ip "$ip" "DNSniper: custom"; then
                log "INFO" "Successfully blocked custom IP: $ip"
                custom_blocked=$((custom_blocked + 1))
            else
                log "ERROR" "Error blocking custom IP: $ip"
            fi
            # Periodically make rules persistent for large IP lists
            if [[ $custom_total -gt 100 && $((custom_blocked % 50)) -eq 0 ]]; then
                make_rules_persistent
            fi
        done < "$tmpcustomips"
        # Clean up
        rm -f "$tmpcustomips"
        echo_safe "${GREEN}Custom IP blocking complete. $custom_blocked/$custom_total IPs blocked.${NC}"
        log "INFO" "Custom IP blocking complete. $custom_blocked/$custom_total IPs blocked." "verbose"
    else
        rm -f "$tmpcustomips"
    fi
    # Make sure the rules are persistent
    make_rules_persistent
    return 0
}