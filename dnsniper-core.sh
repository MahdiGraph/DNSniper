#!/usr/bin/env bash
# DNSniper Core Library - Shared functions for DNSniper
# Version: 2.0.0

# Default paths
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
LOG_FILE="$BASE_DIR/dnsniper.log"
LOG_DIR="$BASE_DIR/logs"
STATUS_FILE="$BASE_DIR/status.txt"

# IPSet definitions
IPSET4="dnsniper-ipv4"
IPSET6="dnsniper-ipv6"

# ANSI colors (only used in interactive mode)
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
MAGENTA='\e[35m'
BOLD='\e[1m'
NC='\e[0m'

# Chain names
IPT_CHAIN="DNSniper"
IPT6_CHAIN="DNSniper6"

# Version
VERSION="2.0.0"

# Default Configuration Values
DEFAULT_MAX_IPS=10
DEFAULT_TIMEOUT=30
DEFAULT_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
DEFAULT_AUTO_UPDATE=1
DEFAULT_EXPIRE_ENABLED=1
DEFAULT_EXPIRE_MULTIPLIER=5
DEFAULT_BLOCK_SOURCE=1
DEFAULT_BLOCK_DESTINATION=1
DEFAULT_LOGGING_ENABLED=1
DEFAULT_LOG_MAX_SIZE=10
DEFAULT_LOG_ROTATE_COUNT=5
DEFAULT_AUTOMATIC_EXECUTION=1

# Logging state
LOGGING_ENABLED=0

# Initialize logging
init_logging() {
    # Read from config file
    local logging_setting=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_LOGGING_ENABLED")
    if [[ "$logging_setting" == "1" ]]; then
        LOGGING_ENABLED=1
        # Make sure log directory exists
        mkdir -p "$LOG_DIR" 2>/dev/null || true
    else
        LOGGING_ENABLED=0
    fi
}

# Log function
log() {
    local level="$1" message="$2" verbose="${3:-}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Only write to log file if logging is enabled
    if [[ $LOGGING_ENABLED -eq 1 ]]; then
        # Check if log file is too large
        local max_size=$(grep '^log_max_size=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_LOG_MAX_SIZE")
        local max_size_bytes=$((max_size * 1024 * 1024))
        
        # If log file exists and is larger than max size, rotate it
        if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo "0") -gt $max_size_bytes ]]; then
            rotate_logs
        fi
        
        # Make sure log directory exists
        mkdir -p "$LOG_DIR" 2>/dev/null || true
        
        # Write to log file
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    # Only print to console if in verbose mode or error/warning
    if [ -t 1 ]; then  # Only print if terminal is interactive
        if [[ "$level" == "ERROR" ]]; then
            echo -e "${RED}Error:${NC} $message" >&2
        elif [[ "$level" == "WARNING" ]]; then
            echo -e "${YELLOW}Warning:${NC} $message" >&2
        elif [[ "$level" == "INFO" && "$verbose" == "verbose" ]]; then
            echo -e "${BLUE}Info:${NC} $message"
        fi
    fi
}

# Rotate logs
rotate_logs() {
    # Make sure log directory exists
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    
    # Get rotation count from config
    local rotate_count=$(grep '^log_rotate_count=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_LOG_ROTATE_COUNT")
    
    # Remove the oldest log if rotation limit is reached
    if [[ -f "$LOG_DIR/dnsniper.$rotate_count.log" ]]; then
        rm -f "$LOG_DIR/dnsniper.$rotate_count.log" 2>/dev/null || true
    fi
    
    # Shift all logs up by one number
    for (( i=rotate_count-1; i>=1; i-- )); do
        local j=$((i+1))
        if [[ -f "$LOG_DIR/dnsniper.$i.log" ]]; then
            mv "$LOG_DIR/dnsniper.$i.log" "$LOG_DIR/dnsniper.$j.log" 2>/dev/null || true
        fi
    done
    
    # Move current log to rotation
    if [[ -f "$LOG_FILE" ]]; then
        cp "$LOG_FILE" "$LOG_DIR/dnsniper.1.log" 2>/dev/null || true
        truncate -s 0 "$LOG_FILE" 2>/dev/null || true
    fi
    
    log "INFO" "Log file rotated" "verbose"
}

# Update status
update_status() {
    local status="$1"
    echo "$status" > "$STATUS_FILE"
    log "INFO" "Status updated to: $status" "verbose"
}

# Get current status
get_status() {
    if [ -f "$STATUS_FILE" ]; then
        cat "$STATUS_FILE"
    else
        echo "UNKNOWN"
    fi
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

# Detect system OS type
detect_system() {
    # Detect OS family
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
        ipset save > "$BASE_DIR/ipset.conf" 2>/dev/null || true
    fi
    
    log "INFO" "Firewall rules made persistent" "verbose"
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

# Ensure environment is prepared
ensure_environment() {
    # Create base directory if it doesn't exist
    mkdir -p "$BASE_DIR" 2>/dev/null || true
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    
    # Create empty files if they don't exist
    touch "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$IP_ADD_FILE" "$IP_REMOVE_FILE" 2>/dev/null || true
    
    # Create config file with defaults if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
# DNSniper Configuration
max_ips=$DEFAULT_MAX_IPS
timeout=$DEFAULT_TIMEOUT
update_url='$DEFAULT_URL'
auto_update=$DEFAULT_AUTO_UPDATE
expire_enabled=$DEFAULT_EXPIRE_ENABLED
expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
block_source=$DEFAULT_BLOCK_SOURCE
block_destination=$DEFAULT_BLOCK_DESTINATION
logging_enabled=$DEFAULT_LOGGING_ENABLED
log_max_size=$DEFAULT_LOG_MAX_SIZE
log_rotate_count=$DEFAULT_LOG_ROTATE_COUNT
automatic_execution=$DEFAULT_AUTOMATIC_EXECUTION
EOF
    fi
    
    # Initialize SQLite DB: WAL mode, tables + index
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$DB_FILE" <<SQL
PRAGMA journal_mode=WAL;
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
        log "WARNING" "sqlite3 not found, database functionality disabled" "verbose"
    fi
    
    # Initialize iptables chains
    initialize_chains
    
    # Initialize ipset if available
    if command -v ipset &>/dev/null; then
        ipset create "$IPSET4" hash:ip family inet -exist 2>/dev/null || true
        ipset create "$IPSET6" hash:ip family inet6 -exist 2>/dev/null || true
    fi
    
    # Initialize logging
    init_logging
    
    # Initialize status file if it doesn't exist
    if [[ ! -f "$STATUS_FILE" ]]; then
        echo "READY" > "$STATUS_FILE"
    fi
    
    log "INFO" "Environment setup complete" "verbose"
    return 0
}

# Merge domain lists (default + added - removed)
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

# Get custom IP list
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

# Record domain history in database
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
BEGIN TRANSACTION;
INSERT INTO history(domain,ips,ts) VALUES('$domain','$ips_csv',strftime('%s','now'));
DELETE FROM history
WHERE rowid NOT IN (
   SELECT rowid FROM history
   WHERE domain='$domain'
   ORDER BY ts DESC
   LIMIT $max_ips
);
COMMIT;
SQL
    then
        log "ERROR" "Error recording history for domain: $domain"
        return 1
    fi
    
    return 0
}

# Block a specific IP
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

# Unblock a specific IP
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

# Check for expired domains
check_expired_domains() {
    # Check if domain expiration is enabled
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$expire_enabled" != "1" ]]; then
        return 0
    fi
    
    log "INFO" "Checking for expired domains" "verbose"
    
    # Get update frequency
    local update_minutes=60 # Default to hourly
    
    # Get expiration multiplier
    local expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]]; then
        expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
    fi
    
    # Calculate expiration time in minutes
    local expire_minutes=$((update_minutes * expire_multiplier))
    
    # Get domains that have expired
    local expired_domains
    expired_domains=$(sqlite3 "$DB_FILE" "SELECT domain FROM expired_domains
                                          WHERE source='default' AND
                                          datetime(last_seen, '+$expire_minutes minutes') < datetime('now');" 2>/dev/null)
    
    # Process expired domains
    if [[ -n "$expired_domains" ]]; then
        log "INFO" "Found expired domains to clean up" "verbose"
        
        while IFS= read -r domain; do
            log "INFO" "Removing expired domain: $domain"
            
            # Get IPs associated with this domain
            local esc_dom=$(sql_escape "$domain")
            local ips
            ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
            
            if [[ -n "$ips" ]]; then
                IFS=',' read -ra ip_list <<< "$ips"
                
                # Unblock each IP
                for ip in "${ip_list[@]}"; do
                    if unblock_ip "$ip" "DNSniper: $domain"; then
                        log "INFO" "Unblocked expired IP: $ip for domain: $domain"
                    fi
                done
            fi
            
            # Remove from expired domains tracking
            sqlite3 "$DB_FILE" "DELETE FROM expired_domains WHERE domain='$esc_dom';" 2>/dev/null
            
            # If domain was manually added to remove list, honor that
            if ! grep -Fxq "$domain" "$REMOVE_FILE" 2>/dev/null; then
                echo "$domain" >> "$REMOVE_FILE"
            fi
        done <<< "$expired_domains"
        
        # Make rules persistent
        make_rules_persistent
    fi
}

# Update default domains list
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
    
    log "INFO" "Fetching default domains from $update_url" "verbose"
    
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
    
    # Create a temporary file for the download
    local temp_file=$(mktemp)
    
    # Attempt to download with retry logic
    local max_retries=3
    local retry_count=0
    local success=false
    
    while [[ $retry_count -lt $max_retries && $success == false ]]; do
        if curl -sfL --connect-timeout "$timeout" --max-time "$timeout" "$update_url" -o "$temp_file"; then
            success=true
        else
            retry_count=$((retry_count + 1))
            log "WARNING" "Download attempt $retry_count failed, retrying..." "verbose"
            sleep 2
        fi
    done
    
    if [[ "$success" == "true" ]]; then
        # Verify the downloaded file has content
        if [[ -s "$temp_file" ]]; then
            # Create a backup of the current file
            if [[ -f "$DEFAULT_FILE" ]]; then
                cp "$DEFAULT_FILE" "$DEFAULT_FILE.bak" 2>/dev/null || true
            fi
            
            # Move the new file into place
            if mv "$temp_file" "$DEFAULT_FILE"; then
                log "INFO" "Default domains successfully updated" "verbose"
                
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
                
                return 0
            else
                rm -f "$temp_file" 2>/dev/null || true
                log "ERROR" "Failed to update default domains file"
                return 1
            fi
        else
            rm -f "$temp_file" 2>/dev/null || true
            log "ERROR" "Downloaded file is empty"
            return 1
        fi
    else
        rm -f "$temp_file" 2>/dev/null || true
        log "ERROR" "Error downloading default domains from $update_url after $max_retries attempts"
        return 1
    fi
}

# Count blocked IPs
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

# Clean all DNSniper firewall rules
clean_rules() {
    log "INFO" "Cleaning firewall rules"
    
    # Remove references to our chains
    iptables -D INPUT -j "$IPT_CHAIN" 2>/dev/null || true
    iptables -D OUTPUT -j "$IPT_CHAIN" 2>/dev/null || true
    ip6tables -D INPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    ip6tables -D OUTPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    
    # Flush our chains
    iptables -F "$IPT_CHAIN" 2>/dev/null || true
    ip6tables -F "$IPT6_CHAIN" 2>/dev/null || true
    
    # Delete our chains
    iptables -X "$IPT_CHAIN" 2>/dev/null || true
    ip6tables -X "$IPT6_CHAIN" 2>/dev/null || true
    
    # Remove ipsets if they exist
    if command -v ipset &>/dev/null; then
        ipset destroy "$IPSET4" 2>/dev/null || true
        ipset destroy "$IPSET6" 2>/dev/null || true
    fi
    
    # Make changes persistent
    make_rules_persistent
    
    log "INFO" "All firewall rules cleaned"
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
        log "WARNING" "Potential CDN domains detected: ${warnings[*]}"
        # Return the domains as a space separated list
        echo "${warnings[*]}"
    fi
}

# Resolve domains and block IPs
resolve_and_block() {
    update_status "RUNNING"
    log "INFO" "Starting domain resolution and blocking" "verbose"
    
    # Check if we should auto-update
    local auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$auto_update" || ! "$auto_update" =~ ^[0-9]+$ ]]; then
        auto_update=$DEFAULT_AUTO_UPDATE
    fi
    
    if [[ $auto_update -eq 1 ]]; then
        log "INFO" "Auto-updating domain lists"
        update_default
    fi
    
    # Check for expired domains
    check_expired_domains
    
    log "INFO" "Resolving domains"
    
    # Get domains
    local domains=()
    
    # Using temp file approach for better performance with large domain lists
    local tmpdomains=$(mktemp)
    merge_domains > "$tmpdomains"
    
    # Count domains
    local total=$(wc -l < "$tmpdomains")
    if [[ $total -eq 0 ]]; then
        log "INFO" "No domains to process"
        rm -f "$tmpdomains"
    else
        log "INFO" "Processing $total domains"
        
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
        
        log "INFO" "Domain resolution complete. $success_count/$total domains processed, $ip_count new IPs blocked."
        
        # Run CDN detection
        mapfile -t domains < <(merge_domains)
        cdn_domains=$(detect_cdn "${domains[@]}")
        if [[ -n "$cdn_domains" ]]; then
            log "WARNING" "Potential CDN domains detected: $cdn_domains"
        fi
    fi
    
    # Also block custom IPs
    local custom_ips=()
    local tmpcustomips=$(mktemp)
    get_custom_ips > "$tmpcustomips"
    local custom_total=$(wc -l < "$tmpcustomips")
    
    if [[ $custom_total -gt 0 ]]; then
        log "INFO" "Processing $custom_total custom IPs"
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
        
        log "INFO" "Custom IP blocking complete. $custom_blocked/$custom_total IPs blocked."
    else
        rm -f "$tmpcustomips"
    fi
    
    # Make sure the rules are persistent
    make_rules_persistent
    
    update_status "READY"
    return 0
}