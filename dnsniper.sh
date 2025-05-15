#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 1.3.2
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
# Logging state
LOGGING_ENABLED=0
# Defaults
DEFAULT_CRON="0 * * * * $BIN_CMD --run >/dev/null 2>&1"
DEFAULT_MAX_IPS=10
DEFAULT_TIMEOUT=30
DEFAULT_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
DEFAULT_AUTO_UPDATE=1
DEFAULT_EXPIRE_ENABLED=1
DEFAULT_EXPIRE_MULTIPLIER=5
DEFAULT_BLOCK_SOURCE=1
DEFAULT_BLOCK_DESTINATION=1
DEFAULT_BLOCK_FORWARD=0
DEFAULT_LOGGING_ENABLED=0
# Chain names
IPT_CHAIN="DNSniper"
IPT6_CHAIN="DNSniper6"
# Version
VERSION="1.3.2"
# Dependencies
DEPENDENCIES=(iptables ip6tables curl dig sqlite3 crontab)
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
# Display banner
show_banner() {
    if [[ -t 1 ]]; then  # Only show banner in interactive terminal
        clear
        echo -e "${BLUE}${BOLD}"
        echo -e "    ____  _   _ ____       _                 "
        echo -e "   |   _\\| \\ | /_ __|_ __ (_)_ __   ___ _ __ "
        echo -e "   | | | |  \\| \\___ \\ '_ \\| | '_ \\ / _\\ '__|"
        echo -e "   | |_| | |\\  |___) | | | | | |_) |  __/ |  "
        echo -e "   |____/|_| \\_|____/|_| |_|_| .__/ \\___|_|  "
        echo -e "                             |_|              "
        echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v$VERSION ${NC}"
        echo -e ""
    fi
}
# SQL escape
sql_escape() {
    local input="$1"
    echo "${input//\'/\'\'}"  # Replace ' with ''
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
    # Detect OS family
    if [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]]; then
        echo "redhat"
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    else
        echo "unknown"
    fi
}
# Make iptables rules persistent based on system type
make_rules_persistent() {
    local os_type=$(detect_system)
    local success=0
    case "$os_type" in
        debian)
            # For Debian/Ubuntu
            if command -v netfilter-persistent &>/dev/null; then
                log "INFO" "Using netfilter-persistent for rule persistence" "verbose"
                netfilter-persistent save &>/dev/null && success=1
            elif [[ -d /etc/iptables ]]; then
                log "INFO" "Saving rules to /etc/iptables/" "verbose"
                iptables-save > /etc/iptables/rules.v4 2>/dev/null && \
                ip6tables-save > /etc/iptables/rules.v6 2>/dev/null && \
                success=1
            else
                log "INFO" "Creating persistence files in $BASE_DIR" "verbose"
                # Save rules to our own directory
                iptables-save > "$RULES_V4_FILE" 2>/dev/null && \
                ip6tables-save > "$RULES_V6_FILE" 2>/dev/null && \
                success=1
                # Create systemd unit for loading rules at boot if not exists
                if [[ ! -f /etc/systemd/system/dnsniper-firewall.service ]]; then
                    create_systemd_service
                fi
            fi
            ;;
        redhat|fedora)
            # For RHEL/CentOS/Fedora
            if command -v service &>/dev/null && \
               systemctl list-unit-files iptables.service &>/dev/null; then
                log "INFO" "Using iptables service for rule persistence" "verbose"
                service iptables save &>/dev/null && \
                service ip6tables save &>/dev/null && \
                success=1
            else
                log "INFO" "Creating persistence files in $BASE_DIR" "verbose"
                # Save rules to our own directory
                iptables-save > "$RULES_V4_FILE" 2>/dev/null && \
                ip6tables-save > "$RULES_V6_FILE" 2>/dev/null && \
                success=1
                # Create systemd unit for loading rules at boot if not exists
                if [[ ! -f /etc/systemd/system/dnsniper-firewall.service ]]; then
                    create_systemd_service
                fi
            fi
            ;;
        *)
            # Generic method for other systems
            log "INFO" "Creating persistence files in $BASE_DIR" "verbose"
            iptables-save > "$RULES_V4_FILE" 2>/dev/null && \
            ip6tables-save > "$RULES_V6_FILE" 2>/dev/null && \
            success=1
            # Create systemd unit for loading rules at boot if not exists
            if [[ ! -f /etc/systemd/system/dnsniper-firewall.service ]]; then
                create_systemd_service
            fi
            ;;
    esac
    if [[ $success -eq 1 ]]; then
        log "INFO" "Firewall rules have been made persistent" "verbose"
        return 0
    else
        log "WARNING" "Could not make firewall rules persistent automatically."
        log "WARNING" "You may need to install iptables-persistent package." "verbose"
        return 1
    fi
}
# Create systemd service for loading rules at boot
create_systemd_service() {
    log "INFO" "Creating systemd service for firewall rules persistence" "verbose"
    cat > /etc/systemd/system/dnsniper-firewall.service << EOF
[Unit]
Description=DNSniper Firewall Rules
After=network.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore $RULES_V4_FILE
ExecStart=/sbin/ip6tables-restore $RULES_V6_FILE
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload &>/dev/null || true
    systemctl enable dnsniper-firewall.service &>/dev/null || true
    log "INFO" "DNSniper firewall systemd service enabled" "verbose"
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
    # Add FORWARD chain if block_forward is enabled
    local block_forward=$(grep '^block_forward=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$block_forward" == "1" ]]; then
        if ! iptables -C FORWARD -j "$IPT_CHAIN" &>/dev/null; then
            iptables -I FORWARD -j "$IPT_CHAIN" 2>/dev/null || true
        fi
    fi
    if ! ip6tables -C INPUT -j "$IPT6_CHAIN" &>/dev/null; then
        ip6tables -I INPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    fi
    if ! ip6tables -C OUTPUT -j "$IPT6_CHAIN" &>/dev/null; then
        ip6tables -I OUTPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    fi
    # Add FORWARD chain for IPv6 if block_forward is enabled
    if [[ "$block_forward" == "1" ]]; then
        if ! ip6tables -C FORWARD -j "$IPT6_CHAIN" &>/dev/null; then
            ip6tables -I FORWARD -j "$IPT6_CHAIN" 2>/dev/null || true
        fi
    fi
    # Make the rules persistent
    make_rules_persistent
}
### 1) Prepare environment: dirs, files, DB, cron
ensure_environment() {
    log "INFO" "Setting up environment" "verbose"
    # Create base directory if it doesn't exist
    if [[ ! -d "$BASE_DIR" ]]; then
        if ! mkdir -p "$BASE_DIR" &>/dev/null; then
            exit_with_error "Cannot create directory $BASE_DIR"
        fi
    fi
    # Create required files if they don't exist
    for file in "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$IP_ADD_FILE" "$IP_REMOVE_FILE" "$CONFIG_FILE"; do
        if [[ ! -f "$file" ]]; then
            if ! touch "$file" &>/dev/null; then
                exit_with_error "Cannot create file $file"
            fi
        fi
    done
    # Set defaults in config file
    if ! grep -q '^cron=' "$CONFIG_FILE" 2>/dev/null; then
        echo "cron='$DEFAULT_CRON'" >> "$CONFIG_FILE"
    fi
    if ! grep -q '^max_ips=' "$CONFIG_FILE" 2>/dev/null; then
        echo "max_ips=$DEFAULT_MAX_IPS" >> "$CONFIG_FILE"
    fi
    if ! grep -q '^timeout=' "$CONFIG_FILE" 2>/dev/null; then
        echo "timeout=$DEFAULT_TIMEOUT" >> "$CONFIG_FILE"
    fi
    if ! grep -q '^update_url=' "$CONFIG_FILE" 2>/dev/null; then
        echo "update_url='$DEFAULT_URL'" >> "$CONFIG_FILE"
    fi
    if ! grep -q '^auto_update=' "$CONFIG_FILE" 2>/dev/null; then
        echo "auto_update=$DEFAULT_AUTO_UPDATE" >> "$CONFIG_FILE"
    fi
    # Add new config options for domain expiration
    if ! grep -q '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null; then
        echo "expire_enabled=$DEFAULT_EXPIRE_ENABLED" >> "$CONFIG_FILE"
    fi
    if ! grep -q '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null; then
        echo "expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER" >> "$CONFIG_FILE"
    fi
    # Add new config options for block rule types
    if ! grep -q '^block_source=' "$CONFIG_FILE" 2>/dev/null; then
        echo "block_source=$DEFAULT_BLOCK_SOURCE" >> "$CONFIG_FILE"
    fi
    if ! grep -q '^block_destination=' "$CONFIG_FILE" 2>/dev/null; then
        echo "block_destination=$DEFAULT_BLOCK_DESTINATION" >> "$CONFIG_FILE"
    fi
    if ! grep -q '^block_forward=' "$CONFIG_FILE" 2>/dev/null; then
        echo "block_forward=$DEFAULT_BLOCK_FORWARD" >> "$CONFIG_FILE"
    fi
    # Add new config option for logging
    if ! grep -q '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null; then
        echo "logging_enabled=$DEFAULT_LOGGING_ENABLED" >> "$CONFIG_FILE"
    fi
    # Initialize SQLite history DB
    if ! sqlite3 "$DB_FILE" <<SQL 2>/dev/null
CREATE TABLE IF NOT EXISTS history(
  domain TEXT,
  ips TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_domain ON history(domain);
CREATE INDEX IF NOT EXISTS idx_ts ON history(ts);
-- Table for tracking domains expiration
CREATE TABLE IF NOT EXISTS expired_domains(
  domain TEXT PRIMARY KEY,
  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
  source TEXT DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_expired_domain ON expired_domains(domain);
CREATE INDEX IF NOT EXISTS idx_last_seen ON expired_domains(last_seen);
SQL
    then
        exit_with_error "Problem initializing SQLite database"
    fi
    # Install or update cron job
    local cron_expr=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    if [[ -n "$cron_expr" && "$cron_expr" != "# DNSniper disabled" ]]; then
        if ! (crontab -l 2>/dev/null | grep -vF "$BIN_CMD" || true; echo "$cron_expr") | crontab -; then
            log "WARNING" "Problem updating crontab"
        else
            log "INFO" "Cron job successfully updated" "verbose"
        fi
    fi
    # Initialize iptables chains
    initialize_chains
    return 0
}
### 2) Check privileges and dependencies
check_root() {
    if [[ $EUID -ne 0 ]]; then
        exit_with_error "Must run as root (sudo)."
    fi
}
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
### 3) Fetch default domains list from GitHub
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
### 4) Check for expired domains and remove their rules
check_expired_domains() {
    # Check if domain expiration is enabled
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$expire_enabled" != "1" ]]; then
        return 0
    fi
    log "INFO" "Checking for expired domains" "verbose"
    # Get cron schedule to determine update frequency
    local cron_expr=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local update_minutes=60 # Default to hourly if can't determine
    if [[ "$cron_expr" == "# DNSniper disabled" ]]; then
        # Cron is disabled, use 60 minutes as default
        update_minutes=60
    elif [[ "$cron_expr" =~ \*/([0-9]+)[[:space:]] ]]; then
        # Format */X * * * *
        update_minutes="${BASH_REMATCH[1]}"
    elif [[ "$cron_expr" =~ ^[0-9]+[[:space:]]+\*/([0-9]+) ]]; then
        # Format Y */X * * *
        update_minutes=$((${BASH_REMATCH[1]} * 60))
    fi
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
### 5) Merge default + added, minus removed domains
merge_domains() {
    log "INFO" "Merging domain lists"
    local merged_domains=()
    local d
    # Read from default file
    if [[ -f "$DEFAULT_FILE" ]]; then
        while IFS= read -r d || [[ -n "$d" ]]; do
            [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
            d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
            [[ -z "$d" ]] && continue
            merged_domains+=("$d")
        done < "$DEFAULT_FILE"
    fi
    # Read from add file
    if [[ -f "$ADD_FILE" ]]; then
        while IFS= read -r d || [[ -n "$d" ]]; do
            [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
            d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
            [[ -z "$d" ]] && continue
            # Check if domain already exists in list
            local found=0
            for existing in "${merged_domains[@]}"; do
                if [[ "$existing" == "$d" ]]; then
                    found=1
                    break
                fi
            done
            [[ $found -eq 0 ]] && merged_domains+=("$d")
        done < "$ADD_FILE"
    fi
    # Read from remove file for exceptions
    local remove_domains=()
    if [[ -f "$REMOVE_FILE" ]]; then
        while IFS= read -r d || [[ -n "$d" ]]; do
            [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
            d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
            [[ -z "$d" ]] && continue
            remove_domains+=("$d")
        done < "$REMOVE_FILE"
    fi
    # Filter out domains in the remove list
    local filtered_domains=()
    for d in "${merged_domains[@]}"; do
        local should_remove=0
        for rd in "${remove_domains[@]}"; do
            if [[ "$d" == "$rd" ]]; then
                should_remove=1
                break
            fi
        done
        [[ $should_remove -eq 0 ]] && filtered_domains+=("$d")
    done
    # Output each domain on separate line
    for domain in "${filtered_domains[@]}"; do
        echo "$domain"
    done
}
### 6) Get list of custom IPs to block
get_custom_ips() {
    log "INFO" "Getting custom IP list"
    local custom_ips=()
    local ip
    # Read from custom IP add file
    if [[ -f "$IP_ADD_FILE" ]]; then
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            [[ -z "$ip" || "$ip" =~ ^[[:space:]]*# ]] && continue
            ip=$(echo "$ip" | tr -d '\r' | tr -d '\n' | xargs)
            [[ -z "$ip" ]] && continue
            # Validate IP format (very basic check)
            if is_ipv6 "$ip" || is_valid_ipv4 "$ip"; then
                custom_ips+=("$ip")
            else
                log "WARNING" "Invalid IP format ignored: $ip"
            fi
        done < "$IP_ADD_FILE"
    fi
    # Read from custom IP remove file
    local remove_ips=()
    if [[ -f "$IP_REMOVE_FILE" ]]; then
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            [[ -z "$ip" || "$ip" =~ ^[[:space:]]*# ]] && continue
            ip=$(echo "$ip" | tr -d '\r' | tr -d '\n' | xargs)
            [[ -z "$ip" ]] && continue
            remove_ips+=("$ip")
        done < "$IP_REMOVE_FILE"
    fi
    # Filter out IPs in the remove list
    local filtered_ips=()
    for ip in "${custom_ips[@]}"; do
        local should_remove=0
        for rip in "${remove_ips[@]}"; do
            if [[ "$ip" == "$rip" ]]; then
                should_remove=1
                break
            fi
        done
        [[ $should_remove -eq 0 ]] && filtered_ips+=("$ip")
    done
    # Output each IP on separate line
    for ip in "${filtered_ips[@]}"; do
        echo "$ip"
    done
}
### 7) Record history and trim to max_ips
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
INSERT INTO history(domain,ips) VALUES('$domain','$ips_csv');
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
### 8) Detect CDN by comparing last two resolves
detect_cdn() {
    local domains=("$@")
    local warnings=()
    log "INFO" "Detecting CDN usage for ${#domains[@]} domains"
    for dom in "${domains[@]}"; do
        # Escape special characters for SQL
        local esc_dom=$(sql_escape "$dom")
        # Get the last two sets of IPs for this domain
        local rows
        rows=$(sqlite3 -separator '|' "$DB_FILE" \
            "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 2;" 2>/dev/null)
        # If not enough history, skip
        [[ $(echo "$rows" | wc -l) -lt 2 ]] && continue
        # Parse rows into arrays
        local last prev
        IFS='|' read -r last prev <<< "$rows"
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
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo_safe "${YELLOW}${BOLD}[!] Domains likely using CDN:${NC} ${warnings[*]}"
        log "WARNING" "Potential CDN domains detected: ${warnings[*]}"
    fi
}
### 9) Block a specific IP with iptables/ip6tables
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
    local block_forward=$(grep '^block_forward=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Validate settings, use defaults if invalid
    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
    [[ -z "$block_forward" || ! "$block_forward" =~ ^[01]$ ]] && block_forward=$DEFAULT_BLOCK_FORWARD
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
    # Block destination IP in INPUT and OUTPUT chains if enabled
    if [[ "$block_destination" == "1" ]]; then
        if ! $tbl -C "$chain" -d "$ip" -j DROP -m comment --comment "$comment" &>/dev/null; then
            if $tbl -A "$chain" -d "$ip" -j DROP -m comment --comment "$comment"; then
                rules_added=1
            else
                log "ERROR" "Failed to add destination rule for $ip" "verbose"
            fi
        fi
    fi
    # Block in FORWARD chain if enabled
    if [[ "$block_forward" == "1" ]]; then
        # Ensure our chain is referenced in FORWARD
        if ! $tbl -C FORWARD -j "$chain" &>/dev/null; then
            $tbl -I FORWARD -j "$chain" 2>/dev/null || true
        fi
        # Add specific FORWARD rules
        if ! $tbl -C "$chain" -s "$ip" -m comment --comment "$comment" -j DROP &>/dev/null; then
            $tbl -A "$chain" -s "$ip" -m comment --comment "$comment" -j DROP
            rules_added=1
        fi
        if ! $tbl -C "$chain" -d "$ip" -m comment --comment "$comment" -j DROP &>/dev/null; then
            $tbl -A "$chain" -d "$ip" -m comment --comment "$comment" -j DROP
            rules_added=1
        fi
    fi
    return $((1 - rules_added))
}
### 10) Unblock a specific IP from iptables/ip6tables
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
    local block_forward=$(grep '^block_forward=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Validate settings, use defaults if invalid
    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
    [[ -z "$block_forward" || ! "$block_forward" =~ ^[01]$ ]] && block_forward=$DEFAULT_BLOCK_FORWARD
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
    # Try to remove from FORWARD chain
    if [[ "$block_forward" == "1" ]]; then
        while $tbl -C "$chain" -s "$ip" -m comment --comment "$comment_pattern" -j DROP &>/dev/null 2>&1; do
            $tbl -D "$chain" -s "$ip" -m comment --comment "$comment_pattern" -j DROP
            success=1
        done
        while $tbl -C "$chain" -d "$ip" -m comment --comment "$comment_pattern" -j DROP &>/dev/null 2>&1; do
            $tbl -D "$chain" -d "$ip" -m comment --comment "$comment_pattern" -j DROP
            success=1
        done
    fi
    # Make rules persistent if we made changes
    if [[ $success -eq 1 ]]; then
        make_rules_persistent
    fi
    return $((1 - success))
}
### 11) Count actual blocked IPs (not just rules)
count_blocked_ips() {
    local v4_rules v6_rules unique_ips
    local ipv4_list ipv6_list
    # Get unique IPs by extracting from actual rules
    ipv4_list=$(iptables-save 2>/dev/null | grep -E "$IPT_CHAIN.*DROP" | grep -o -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    ipv6_list=$(ip6tables-save 2>/dev/null | grep -E "$IPT6_CHAIN.*DROP" | grep -o -E '([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}' | sort -u)
    # Count unique IPs
    v4_rules=$(echo "$ipv4_list" | wc -l)
    v6_rules=$(echo "$ipv6_list" | wc -l)
    # Return total (accounting for empty results)
    if [[ -z "$ipv4_list" ]]; then v4_rules=0; fi
    if [[ -z "$ipv6_list" ]]; then v6_rules=0; fi
    echo $((v4_rules + v6_rules))
}
### 12) Check if a domain has active IP blocks
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
### 13) Apply block rule type changes
apply_rule_type_changes() {
    log "INFO" "Applying rule type changes" "verbose"
    echo_safe "${BLUE}Applying rule type changes...${NC}"
    
    # Clear rules directly without prompting
    echo_safe "${BLUE}Removing existing rules...${NC}"
    iptables -F "$IPT_CHAIN" 2>/dev/null && ip6tables -F "$IPT6_CHAIN" 2>/dev/null
    log "INFO" "All firewall rules cleared for rule type changes" "verbose"
    
    # If forward blocking is enabled/disabled, adjust chains
    local block_forward=$(grep '^block_forward=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$block_forward" == "1" ]]; then
        # Add our chains to FORWARD chains if not already there
        if ! iptables -C FORWARD -j "$IPT_CHAIN" &>/dev/null; then
            iptables -I FORWARD -j "$IPT_CHAIN" 2>/dev/null || true
        fi
        if ! ip6tables -C FORWARD -j "$IPT6_CHAIN" &>/dev/null; then
            ip6tables -I FORWARD -j "$IPT6_CHAIN" 2>/dev/null || true
        fi
    else
        # Remove references to our chains from FORWARD
        iptables -D FORWARD -j "$IPT_CHAIN" 2>/dev/null || true
        ip6tables -D FORWARD -j "$IPT6_CHAIN" 2>/dev/null || true
    fi
    
    # Make sure the changes to chain references are persistent
    make_rules_persistent
    
    # Run a full resolve_block to rebuild the rules with new settings
    resolve_block
    
    echo_safe "${GREEN}Rule type changes applied successfully.${NC}"
}
### 14) Resolve domains and apply iptables/ip6tables rules
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
    mapfile -t domains < <(merge_domains)
    local total=${#domains[@]}
    if [[ $total -eq 0 ]]; then
        echo_safe "${YELLOW}No domains to process.${NC}"
        log "INFO" "No domains to process" "verbose"
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
        for dom in "${domains[@]}"; do
            echo_safe "${BOLD}Domain:${NC} ${GREEN}$dom${NC}"
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
                    echo_safe "  - ${YELLOW}Skipped critical IP${NC}: $ip"
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
                echo_safe "  ${YELLOW}No valid IP addresses found${NC}"
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
                    echo_safe "  - ${RED}Blocked${NC}: $ip"
                    log "INFO" "Successfully blocked IP: $ip for domain: $dom"
                    ip_count=$((ip_count + 1))
                else
                    echo_safe "  - ${RED}Error blocking${NC}: $ip"
                    log "ERROR" "Error blocking IP: $ip for domain: $dom"
                fi
            done
            echo
        done
        echo_safe "${GREEN}Domain resolution complete. $success_count/$total domains processed, $ip_count new IPs blocked.${NC}"
        log "INFO" "Domain resolution complete. $success_count/$total domains processed, $ip_count new IPs blocked." "verbose"
        # Run CDN detection
        detect_cdn "${domains[@]}"
    fi
    # Also block custom IPs
    local custom_ips=()
    mapfile -t custom_ips < <(get_custom_ips)
    local custom_total=${#custom_ips[@]}
    if [[ $custom_total -gt 0 ]]; then
        echo_safe "${BLUE}Processing ${custom_total} custom IPs...${NC}"
        local custom_blocked=0
        for ip in "${custom_ips[@]}"; do
            # Skip critical IPs
            if is_critical_ip "$ip"; then
                echo_safe "  - ${YELLOW}Skipped critical IP${NC}: $ip"
                log "WARNING" "Skipping critical IP: $ip" "verbose"
                continue
            fi
            if block_ip "$ip" "DNSniper: custom"; then
                echo_safe "  - ${RED}Blocked${NC}: $ip"
                log "INFO" "Successfully blocked custom IP: $ip"
                custom_blocked=$((custom_blocked + 1))
            else
                echo_safe "  - ${RED}Error blocking${NC}: $ip"
                log "ERROR" "Error blocking custom IP: $ip"
            fi
        done
        echo_safe "${GREEN}Custom IP blocking complete. $custom_blocked/$custom_total IPs blocked.${NC}"
        log "INFO" "Custom IP blocking complete. $custom_blocked/$custom_total IPs blocked." "verbose"
    fi
    # Make sure the rules are persistent
    make_rules_persistent
    return 0
}
### 15) Interactive menu functions
# --- Settings submenu ---
settings_menu() {
    while true; do
        show_banner
        echo_safe "${BLUE}${BOLD}SETTINGS${NC}"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        echo_safe "${YELLOW}1.${NC} Set Schedule"
        echo_safe "${YELLOW}2.${NC} Set Max IPs Per Domain"
        echo_safe "${YELLOW}3.${NC} Set Timeout"
        echo_safe "${YELLOW}4.${NC} Set Update URL"
        echo_safe "${YELLOW}5.${NC} Toggle Auto-Update"
        echo_safe "${YELLOW}6.${NC} Import/Export"
        echo_safe "${YELLOW}7.${NC} Rule Expiration Settings"
        echo_safe "${YELLOW}8.${NC} Block Rule Types"
        echo_safe "${YELLOW}9.${NC} Toggle Logging"
        echo_safe "${YELLOW}0.${NC} Back to Main Menu"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        read -rp "Select option: " choice
        case "$choice" in
            1) set_schedule ;;
            2) set_max_ips ;;
            3) set_timeout ;;
            4) set_update_url ;;
            5) toggle_auto_update ;;
            6) import_export_menu ;;
            7) expiration_settings ;;
            8) rule_types_settings ;;
            9) toggle_logging ;;
            0) return ;;
            *) echo_safe "${RED}Invalid selection. Please choose 0-9.${NC}" ;;
        esac
        read -rp "Press Enter to continue..."
    done
}

# Toggle logging function
toggle_logging() {
    echo_safe "${BOLD}=== Toggle Logging ===${NC}"
    if [[ $LOGGING_ENABLED -eq 1 ]]; then
        echo_safe "${BLUE}Logging is currently:${NC} ${GREEN}Enabled${NC}"
        echo_safe "${YELLOW}Note:${NC} Logs are stored in $LOG_FILE"
        read -rp "Disable logging? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^logging_enabled=.*|logging_enabled=0|" "$CONFIG_FILE"
            LOGGING_ENABLED=0
            echo_safe "${YELLOW}Logging disabled.${NC}"
            log "INFO" "Logging disabled by user"
        else
            echo_safe "${YELLOW}No change.${NC}"
        fi
    else
        echo_safe "${BLUE}Logging is currently:${NC} ${RED}Disabled${NC}"
        echo_safe "${YELLOW}Note:${NC} Logs will be stored in $LOG_FILE when enabled"
        read -rp "Enable logging? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^logging_enabled=.*|logging_enabled=1|" "$CONFIG_FILE"
            LOGGING_ENABLED=1
            echo_safe "${GREEN}Logging enabled.${NC}"
            log "INFO" "Logging enabled by user"
        else
            echo_safe "${YELLOW}No change.${NC}"
        fi
    fi
}

# Rule expiration settings
expiration_settings() {
    echo_safe "${BOLD}=== Rule Expiration Settings ===${NC}"
    # Get current settings
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Validate settings, use defaults if invalid
    [[ -z "$expire_enabled" || ! "$expire_enabled" =~ ^[01]$ ]] && expire_enabled=$DEFAULT_EXPIRE_ENABLED
    [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]] && expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
    # Get cron schedule to determine update frequency
    local cron_expr=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local update_minutes=60 # Default to hourly if can't determine
    if [[ "$cron_expr" == "# DNSniper disabled" ]]; then
        # Cron is disabled, use 60 minutes as default for display purposes
        update_minutes=60
    elif [[ "$cron_expr" =~ \*/([0-9]+)[[:space:]] ]]; then
        # Format */X * * * *
        update_minutes="${BASH_REMATCH[1]}"
    elif [[ "$cron_expr" =~ ^[0-9]+[[:space:]]+\*/([0-9]+) ]]; then
        # Format Y */X * * *
        update_minutes=$((${BASH_REMATCH[1]} * 60))
    fi
    # Calculate actual expiration time
    local expire_minutes=$((update_minutes * expire_multiplier))
    local expire_hours=$((expire_minutes / 60))
    local expire_days=$((expire_hours / 24))
    local expire_display
    if [[ $expire_days -gt 1 ]]; then
        expire_display="$expire_days days"
    elif [[ $expire_hours -gt 1 ]]; then
        expire_display="$expire_hours hours"
    else
        expire_display="$expire_minutes minutes"
    fi
    # Display current settings
    if [[ "$expire_enabled" == "1" ]]; then
        echo_safe "${BLUE}Rule expiration:${NC} ${GREEN}Enabled${NC}"
        echo_safe "${BLUE}Current expiration time:${NC} ${YELLOW}$expire_display${NC} ($expire_multiplier x update frequency)"
        echo_safe "\n${YELLOW}Note:${NC} Rule expiration only applies to domains from the default list, not custom domains."
        echo_safe "Expired rules are automatically removed after the specified time."
        # Ask to toggle
        read -rp "Disable rule expiration? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^expire_enabled=.*|expire_enabled=0|" "$CONFIG_FILE"
            echo_safe "${YELLOW}Rule expiration disabled.${NC}"
            log "INFO" "Rule expiration disabled by user" "verbose"
        else
            # If not disabling, ask to change multiplier
            read -rp "Change expiration multiplier? (current: $expire_multiplier) [y/N]: " change_mult
            if [[ "$change_mult" =~ ^[Yy] ]]; then
                read -rp "New multiplier (1-100): " new_mult
                if [[ "$new_mult" =~ ^[0-9]+$ && $new_mult -ge 1 && $new_mult -le 100 ]]; then
                    sed -i "s|^expire_multiplier=.*|expire_multiplier=$new_mult|" "$CONFIG_FILE"
                    # Calculate new expiration time
                    local new_expire_minutes=$((update_minutes * new_mult))
                    local new_expire_hours=$((new_expire_minutes / 60))
                    local new_expire_days=$((new_expire_hours / 24))
                    local new_expire_display
                    if [[ $new_expire_days -gt 1 ]]; then
                        new_expire_display="$new_expire_days days"
                    elif [[ $new_expire_hours -gt 1 ]]; then
                        new_expire_display="$new_expire_hours hours"
                    else
                        new_expire_display="$new_expire_minutes minutes"
                    fi
                    echo_safe "${GREEN}Expiration multiplier set to $new_mult (${new_expire_display}).${NC}"
                    log "INFO" "Expiration multiplier updated to $new_mult" "verbose"
                else
                    echo_safe "${RED}Invalid input. Please enter a number between 1 and 100.${NC}"
                fi
            else
                echo_safe "${YELLOW}No change.${NC}"
            fi
        fi
    else
        echo_safe "${BLUE}Rule expiration:${NC} ${RED}Disabled${NC}"
        echo_safe "${BLUE}Default expiration time:${NC} ${YELLOW}$expire_display${NC} ($expire_multiplier x update frequency)"
        echo_safe "\n${YELLOW}Note:${NC} When enabled, rule expiration only applies to domains from the default list."
        read -rp "Enable rule expiration? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^expire_enabled=.*|expire_enabled=1|" "$CONFIG_FILE"
            echo_safe "${GREEN}Rule expiration enabled.${NC}"
            log "INFO" "Rule expiration enabled by user" "verbose"
            # Ask to change multiplier
            read -rp "Change expiration multiplier? (current: $expire_multiplier) [y/N]: " change_mult
            if [[ "$change_mult" =~ ^[Yy] ]]; then
                read -rp "New multiplier (1-100): " new_mult
                if [[ "$new_mult" =~ ^[0-9]+$ && $new_mult -ge 1 && $new_mult -le 100 ]]; then
                    sed -i "s|^expire_multiplier=.*|expire_multiplier=$new_mult|" "$CONFIG_FILE"
                    # Calculate new expiration time
                    local new_expire_minutes=$((update_minutes * new_mult))
                    local new_expire_hours=$((new_expire_minutes / 60))
                    local new_expire_days=$((new_expire_hours / 24))
                    local new_expire_display
                    if [[ $new_expire_days -gt 1 ]]; then
                        new_expire_display="$new_expire_days days"
                    elif [[ $new_expire_hours -gt 1 ]]; then
                        new_expire_display="$new_expire_hours hours"
                    else
                        new_expire_display="$new_expire_minutes minutes"
                    fi
                    echo_safe "${GREEN}Expiration multiplier set to $new_mult (${new_expire_display}).${NC}"
                    log "INFO" "Expiration multiplier updated to $new_mult" "verbose"
                else
                    echo_safe "${RED}Invalid input. Please enter a number between 1 and 100.${NC}"
                fi
            fi
        else
            echo_safe "${YELLOW}No change.${NC}"
        fi
    fi
}
# Rule types settings
rule_types_settings() {
    local need_apply=0
    echo_safe "${BOLD}=== Block Rule Types ===${NC}"
    # Get current settings
    local block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_forward=$(grep '^block_forward=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Validate settings, use defaults if invalid
    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
    [[ -z "$block_forward" || ! "$block_forward" =~ ^[01]$ ]] && block_forward=$DEFAULT_BLOCK_FORWARD
    # Store original values for comparison
    local orig_source=$block_source
    local orig_destination=$block_destination
    local orig_forward=$block_forward
    # Display current settings
    echo_safe "${BLUE}Current rule types:${NC}"
    echo_safe "  ${block_source:+${GREEN}✓${NC}}${block_source:=${RED}✗${NC}} Source IPs      (block traffic FROM malicious IPs)"
    echo_safe "  ${block_destination:+${GREEN}✓${NC}}${block_destination:=${RED}✗${NC}} Destination IPs (block traffic TO malicious IPs)"
    echo_safe "  ${block_forward:+${GREEN}✓${NC}}${block_forward:=${RED}✗${NC}} Forward        (block forwarded traffic through this server)"
    echo_safe "\n${YELLOW}Note:${NC} Changing these settings will affect all existing and future blocking rules."
    # Allow toggles
    read -rp "Toggle Source blocking? [y/N]: " toggle_source
    if [[ "$toggle_source" =~ ^[Yy] ]]; then
        block_source=$((1 - block_source))
        sed -i "s|^block_source=.*|block_source=$block_source|" "$CONFIG_FILE"
        if [[ $block_source -eq 1 ]]; then
            echo_safe "${GREEN}Source IP blocking enabled.${NC}"
        else
            echo_safe "${RED}Source IP blocking disabled.${NC}"
        fi
        need_apply=1
    fi
    read -rp "Toggle Destination blocking? [y/N]: " toggle_dest
    if [[ "$toggle_dest" =~ ^[Yy] ]]; then
        block_destination=$((1 - block_destination))
        sed -i "s|^block_destination=.*|block_destination=$block_destination|" "$CONFIG_FILE"
        if [[ $block_destination -eq 1 ]]; then
            echo_safe "${GREEN}Destination IP blocking enabled.${NC}"
        else
            echo_safe "${RED}Destination IP blocking disabled.${NC}"
        fi
        need_apply=1
    fi
    read -rp "Toggle Forward blocking? [y/N]: " toggle_forward
    if [[ "$toggle_forward" =~ ^[Yy] ]]; then
        block_forward=$((1 - block_forward))
        sed -i "s|^block_forward=.*|block_forward=$block_forward|" "$CONFIG_FILE"
        if [[ $block_forward -eq 1 ]]; then
            echo_safe "${GREEN}Forward traffic blocking enabled.${NC}"
        else
            echo_safe "${RED}Forward traffic blocking disabled.${NC}"
        fi
        need_apply=1
    fi
    # If changes were made, ask to apply them now
    if [[ $need_apply -eq 1 ]]; then
        echo_safe "\n${YELLOW}Warning:${NC} Rule type changes have been saved but require rule reconfiguration to take effect."
        read -rp "Apply changes now? (Recommended) [Y/n]: " apply_now
        if [[ ! "$apply_now" =~ ^[Nn] ]]; then
            apply_rule_type_changes
        else
            echo_safe "${YELLOW}Changes will take effect on next 'Run Now' or cron job execution.${NC}"
            log "WARNING" "Rule type changes deferred until next run" "verbose"
        fi
    else
        echo_safe "${YELLOW}No changes made.${NC}"
    fi
}
# Set schedule
set_schedule() {
    echo_safe "${BOLD}=== Set Schedule ===${NC}"
    echo_safe "${BLUE}Current schedule:${NC} $(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)"
    read -rp "Run every how many minutes (0=disabled): " m
    if [[ "$m" =~ ^[0-9]+$ ]]; then
        if [[ $m -eq 0 ]]; then
            # Disable cron
            sed -i "s|^cron=.*|cron='# DNSniper disabled'|" "$CONFIG_FILE"
            crontab -l 2>/dev/null | grep -vF "$BIN_CMD" | crontab -
            echo_safe "${YELLOW}Scheduling disabled.${NC}"
            log "INFO" "Scheduling disabled by user" "verbose"
        else
            # Set cron to run every m minutes
            local expr
            if [[ $m -eq 60 ]]; then
                expr="0 * * * * $BIN_CMD --run >/dev/null 2>&1"
            elif [[ $m -lt 60 ]]; then
                expr="*/$m * * * * $BIN_CMD --run >/dev/null 2>&1"
            else
                local hours=$((m / 60))
                expr="0 */$hours * * * $BIN_CMD --run >/dev/null 2>&1"
            fi
            sed -i "s|^cron=.*|cron='$expr'|" "$CONFIG_FILE"
            ensure_environment
            echo_safe "${GREEN}Scheduled to run every $m minutes.${NC}"
            log "INFO" "Schedule updated to run every $m minutes" "verbose"
        fi
    else
        echo_safe "${RED}Invalid input. Please enter a number.${NC}"
    fi
}
# Set max IPs
set_max_ips() {
    echo_safe "${BOLD}=== Set Max IPs Per Domain ===${NC}"
    local current=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    echo_safe "${BLUE}Current max IPs per domain:${NC} $current"
    read -rp "New max IPs per domain (5-50): " n
    if [[ "$n" =~ ^[0-9]+$ && $n -ge 5 && $n -le 50 ]]; then
        sed -i "s|^max_ips=.*|max_ips=$n|" "$CONFIG_FILE"
        echo_safe "${GREEN}Max IPs per domain set to $n.${NC}"
        log "INFO" "Max IPs per domain updated to $n" "verbose"
    else
        echo_safe "${RED}Invalid input. Please enter a number between 5 and 50.${NC}"
    fi
}
# Set timeout
set_timeout() {
    echo_safe "${BOLD}=== Set Timeout ===${NC}"
    local current=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    echo_safe "${BLUE}Current timeout:${NC} $current seconds"
    read -rp "New timeout in seconds (5-60): " t
    if [[ "$t" =~ ^[0-9]+$ && $t -ge 5 && $t -le 60 ]]; then
        sed -i "s|^timeout=.*|timeout=$t|" "$CONFIG_FILE"
        echo_safe "${GREEN}Timeout set to $t seconds.${NC}"
        log "INFO" "Timeout updated to $t seconds" "verbose"
    else
        echo_safe "${RED}Invalid input. Please enter a number between 5 and 60.${NC}"
    fi
}
# Set update URL
set_update_url() {
    echo_safe "${BOLD}=== Set Update URL ===${NC}"
    local current=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    echo_safe "${BLUE}Current update URL:${NC} $current"
    read -rp "New update URL: " url
    if [[ -n "$url" ]]; then
        # Basic URL validation
        if [[ "$url" =~ ^https?:// ]]; then
            sed -i "s|^update_url=.*|update_url='$url'|" "$CONFIG_FILE"
            echo_safe "${GREEN}Update URL set to $url.${NC}"
            log "INFO" "Update URL changed to: $url" "verbose"
        else
            echo_safe "${RED}Invalid URL. Must start with http:// or https://.${NC}"
        fi
    else
        echo_safe "${YELLOW}No change.${NC}"
    fi
}
# Toggle auto-update
toggle_auto_update() {
    echo_safe "${BOLD}=== Toggle Auto-Update ===${NC}"
    local current=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$current" || ! "$current" =~ ^[0-9]+$ ]]; then
        current=$DEFAULT_AUTO_UPDATE
    fi
    if [[ $current -eq 1 ]]; then
        echo_safe "${BLUE}Auto-update is currently:${NC} ${GREEN}Enabled${NC}"
        read -rp "Disable auto-update? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^auto_update=.*|auto_update=0|" "$CONFIG_FILE"
            echo_safe "${YELLOW}Auto-update disabled.${NC}"
            log "INFO" "Auto-update disabled by user" "verbose"
        else
            echo_safe "${YELLOW}No change.${NC}"
        fi
    else
        echo_safe "${BLUE}Auto-update is currently:${NC} ${RED}Disabled${NC}"
        read -rp "Enable auto-update? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^auto_update=.*|auto_update=1|" "$CONFIG_FILE"
            echo_safe "${GREEN}Auto-update enabled.${NC}"
            log "INFO" "Auto-update enabled by user" "verbose"
        else
            echo_safe "${YELLOW}No change.${NC}"
        fi
    fi
}
# --- Import/Export submenu ---
import_export_menu() {
    while true; do
        show_banner
        echo_safe "${BLUE}${BOLD}IMPORT / EXPORT${NC}"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        echo_safe "${YELLOW}1.${NC} Import Domains"
        echo_safe "${YELLOW}2.${NC} Export Domains"
        echo_safe "${YELLOW}3.${NC} Import IP Addresses"
        echo_safe "${YELLOW}4.${NC} Export IP Addresses"
        echo_safe "${YELLOW}5.${NC} Export Configuration"
        echo_safe "${YELLOW}6.${NC} Export Firewall Rules"
        echo_safe "${YELLOW}7.${NC} Import Complete Backup"
        echo_safe "${YELLOW}8.${NC} Export Complete Backup"
        echo_safe "${YELLOW}0.${NC} Back to Settings"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        read -rp "Select option: " choice
        case "$choice" in
            1) import_domains ;;
            2) export_domains ;;
            3) import_ips ;;
            4) export_ips ;;
            5) export_config ;;
            6) export_firewall_rules ;;
            7) import_all ;;
            8) export_all ;;
            0) return ;;
            *) echo_safe "${RED}Invalid selection. Please choose 0-8.${NC}" ;;
        esac
        read -rp "Press Enter to continue..."
    done
}
# Import domains
import_domains() {
    echo_safe "${BOLD}=== Import Domains ===${NC}"
    read -rp "Enter path to domains file: " file
    if [[ -f "$file" ]]; then
        local count=0
        while IFS= read -r domain || [[ -n "$domain" ]]; do
            # Skip empty lines and comments
            [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]] && continue
            domain=$(echo "$domain" | tr -d '\r' | tr -d '\n' | xargs)
            # Validate domain format
            if is_valid_domain "$domain"; then
                # Check if domain already exists in add file
                if ! grep -Fxq "$domain" "$ADD_FILE" 2>/dev/null; then
                    echo "$domain" >> "$ADD_FILE"
                    count=$((count + 1))
                fi
            fi
        done < "$file"
        echo_safe "${GREEN}Imported $count new domains.${NC}"
        log "INFO" "Imported $count domains from file: $file" "verbose"
    else
        echo_safe "${RED}File not found: $file${NC}"
    fi
}
# Export domains
export_domains() {
    echo_safe "${BOLD}=== Export Domains ===${NC}"
    read -rp "Enter export path: " file
    if [[ -n "$file" ]]; then
        local domains=()
        mapfile -t domains < <(merge_domains)
        if [[ ${#domains[@]} -gt 0 ]]; then
            # Create export file with header
            {
                echo "# DNSniper Domains Export"
                echo "# Date: $(date)"
                echo "# Total: ${#domains[@]} domains"
                echo ""
                printf "%s\n" "${domains[@]}"
            } > "$file"
            echo_safe "${GREEN}Exported ${#domains[@]} domains to $file.${NC}"
            log "INFO" "Exported ${#domains[@]} domains to file: $file" "verbose"
        else
            echo_safe "${YELLOW}No domains to export.${NC}"
        fi
    else
        echo_safe "${RED}Invalid export path.${NC}"
    fi
}
# Import IPs
import_ips() {
    echo_safe "${BOLD}=== Import IP Addresses ===${NC}"
    read -rp "Enter path to IP list file: " file
    if [[ -f "$file" ]]; then
        local count=0
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            # Skip empty lines and comments
            [[ -z "$ip" || "$ip" =~ ^[[:space:]]*# ]] && continue
            ip=$(echo "$ip" | tr -d '\r' | tr -d '\n' | xargs)
            # Validate IP format
            if is_ipv6 "$ip" || is_valid_ipv4 "$ip"; then
                # Check if IP is critical
                if ! is_critical_ip "$ip"; then
                    # Check if IP already exists in add file
                    if ! grep -Fxq "$ip" "$IP_ADD_FILE" 2>/dev/null; then
                        echo "$ip" >> "$IP_ADD_FILE"
                        count=$((count + 1))
                    fi
                else
                    echo_safe "${YELLOW}Skipped critical IP:${NC} $ip"
                    log "WARNING" "Skipped critical IP during import: $ip" "verbose"
                fi
            else
                echo_safe "${YELLOW}Skipped invalid IP:${NC} $ip"
            fi
        done < "$file"
        echo_safe "${GREEN}Imported $count new IPs.${NC}"
        log "INFO" "Imported $count IPs from file: $file" "verbose"
    else
        echo_safe "${RED}File not found: $file${NC}"
    fi
}
# Export IPs
export_ips() {
    echo_safe "${BOLD}=== Export IP Addresses ===${NC}"
    read -rp "Enter export path: " file
    if [[ -n "$file" ]]; then
        local custom_ips=()
        mapfile -t custom_ips < <(get_custom_ips)
        if [[ ${#custom_ips[@]} -gt 0 ]]; then
            # Create export file with header
            {
                echo "# DNSniper IPs Export"
                echo "# Date: $(date)"
                echo "# Total: ${#custom_ips[@]} IPs"
                echo ""
                printf "%s\n" "${custom_ips[@]}"
            } > "$file"
            echo_safe "${GREEN}Exported ${#custom_ips[@]} IPs to $file.${NC}"
            log "INFO" "Exported ${#custom_ips[@]} IPs to file: $file" "verbose"
        else
            echo_safe "${YELLOW}No custom IPs to export.${NC}"
        fi
    else
        echo_safe "${RED}Invalid export path.${NC}"
    fi
}
# Export config
export_config() {
    echo_safe "${BOLD}=== Export Configuration ===${NC}"
    read -rp "Enter export path: " file
    if [[ -n "$file" ]]; then
        # Export config file with header
        {
            echo "# DNSniper Configuration Export"
            echo "# Date: $(date)"
            echo ""
            cat "$CONFIG_FILE"
        } > "$file"
        echo_safe "${GREEN}Configuration exported to $file.${NC}"
        log "INFO" "Configuration exported to file: $file" "verbose"
    else
        echo_safe "${RED}Invalid export path.${NC}"
    fi
}
# Export firewall rules
export_firewall_rules() {
    echo_safe "${BOLD}=== Export Firewall Rules ===${NC}"
    read -rp "Enter directory path for export: " dir
    if [[ -n "$dir" && -d "$dir" ]]; then
        local ipv4_rules="${dir}/dnsniper-ipv4-rules.txt"
        local ipv6_rules="${dir}/dnsniper-ipv6-rules.txt"
        # Export current rules
        iptables-save | grep -E "(^*|^:|^-A $IPT_CHAIN)" > "$ipv4_rules" 2>/dev/null
        ip6tables-save | grep -E "(^*|^:|^-A $IPT6_CHAIN)" > "$ipv6_rules" 2>/dev/null
        echo_safe "${GREEN}Exported IPv4 rules to:${NC} $ipv4_rules"
        echo_safe "${GREEN}Exported IPv6 rules to:${NC} $ipv6_rules"
        log "INFO" "Exported firewall rules to: $dir" "verbose"
    else
        echo_safe "${RED}Invalid directory.${NC}"
    fi
}
# Import all (complete backup)
import_all() {
    echo_safe "${BOLD}=== Import Complete Backup ===${NC}"
    read -rp "Enter backup directory: " dir
    if [[ -n "$dir" && -d "$dir" ]]; then
        # Check if backup files exist
        if [[ -f "$dir/domains.txt" || -f "$dir/ips.txt" || -f "$dir/config.conf" ]]; then
            # Import domains if exists
            if [[ -f "$dir/domains.txt" ]]; then
                cp "$dir/domains.txt" "$ADD_FILE.tmp"
                mv "$ADD_FILE.tmp" "$ADD_FILE"
                echo_safe "${GREEN}Imported domains from backup.${NC}"
            fi
            # Import IPs if exists
            if [[ -f "$dir/ips.txt" ]]; then
                cp "$dir/ips.txt" "$IP_ADD_FILE.tmp"
                mv "$IP_ADD_FILE.tmp" "$IP_ADD_FILE"
                echo_safe "${GREEN}Imported IPs from backup.${NC}"
            fi
            # Import config if exists
            if [[ -f "$dir/config.conf" ]]; then
                cp "$dir/config.conf" "$CONFIG_FILE.tmp"
                mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
                echo_safe "${GREEN}Imported configuration from backup.${NC}"
            fi
            # Import database if exists
            if [[ -f "$dir/history.db" ]]; then
                cp "$dir/history.db" "$DB_FILE.tmp"
                mv "$DB_FILE.tmp" "$DB_FILE"
                echo_safe "${GREEN}Imported history database from backup.${NC}"
            fi
            # Re-initialize environment with imported settings
            ensure_environment
            echo_safe "${GREEN}Import complete!${NC}"
            log "INFO" "Imported complete backup from: $dir" "verbose"
        else
            echo_safe "${RED}No valid backup files found in directory.${NC}"
        fi
    else
        echo_safe "${RED}Invalid directory.${NC}"
    fi
}
# Export all (complete backup)
export_all() {
    echo_safe "${BOLD}=== Export Complete Backup ===${NC}"
    read -rp "Enter export directory: " dir
    if [[ -n "$dir" && -d "$dir" ]]; then
        # Export directory confirmed
        local export_dir="${dir%/}/dnsniper-backup-$(date +%Y%m%d-%H%M%S)"
        if ! mkdir -p "$export_dir"; then
            echo_safe "${RED}Cannot create export directory.${NC}"
            return 1
        fi
        # Export domains
        local domains=()
        mapfile -t domains < <(merge_domains)
        if [[ ${#domains[@]} -gt 0 ]]; then
            {
                echo "# DNSniper Domains Export"
                echo "# Date: $(date)"
                echo "# Total: ${#domains[@]} domains"
                echo ""
                printf "%s\n" "${domains[@]}"
            } > "$export_dir/domains.txt"
        fi
        # Export custom IPs
        local custom_ips=()
        mapfile -t custom_ips < <(get_custom_ips)
        if [[ ${#custom_ips[@]} -gt 0 ]]; then
            {
                echo "# DNSniper IPs Export"
                echo "# Date: $(date)"
                echo "# Total: ${#custom_ips[@]} IPs"
                echo ""
                printf "%s\n" "${custom_ips[@]}"
            } > "$export_dir/ips.txt"
        fi
        # Export config
        cp "$CONFIG_FILE" "$export_dir/config.conf" 2>/dev/null || true
        # Export current iptables rules
        if command -v iptables-save &>/dev/null; then
            iptables-save | grep -E "(^*|^:|^-A $IPT_CHAIN)" > "$export_dir/iptables-rules.txt" 2>/dev/null || true
            ip6tables-save | grep -E "(^*|^:|^-A $IPT6_CHAIN)" > "$export_dir/ip6tables-rules.txt" 2>/dev/null || true
        fi
        # Export database if available
        if [[ -f "$DB_FILE" ]]; then
            cp "$DB_FILE" "$export_dir/history.db" 2>/dev/null || true
        fi
        # Create README
        {
            echo "DNSniper Backup"
            echo "Date: $(date)"
            echo "Version: $VERSION"
            echo ""
            echo "This backup contains:"
            echo "- Blocked domains"
            echo "- Blocked IP addresses"
            echo "- Configuration settings"
            echo "- Firewall rules"
            echo "- History database"
            echo ""
            echo "To restore, use the 'Import Complete Backup' feature in DNSniper."
        } > "$export_dir/README.txt"
        echo_safe "${GREEN}Complete backup exported to: $export_dir${NC}"
        log "INFO" "Complete backup exported to: $export_dir" "verbose"
    else
        echo_safe "${RED}Invalid directory.${NC}"
    fi
    return 0
}
# --- Block/Unblock Domain/IP Functions ---
# Block domain
block_domain() {
    echo_safe "${BOLD}=== Block Domain ===${NC}"
    read -rp "Domain to block: " domain
    if [[ -z "$domain" ]]; then
        echo_safe "${RED}Domain cannot be empty.${NC}"
        return 1
    fi
    # Validate domain format
    if ! is_valid_domain "$domain"; then
        echo_safe "${RED}Invalid domain format.${NC}"
        return 1
    fi
    # Check if domain already exists in block list
    if grep -Fxq "$domain" "$ADD_FILE" 2>/dev/null; then
        echo_safe "${YELLOW}Domain already in block list.${NC}"
        return 0
    fi
    # Add to custom domains file
    echo "$domain" >> "$ADD_FILE"
    echo_safe "${GREEN}Domain added to block list:${NC} $domain"
    log "INFO" "Domain added to block list: $domain" "verbose"
    # Ask if to block immediately
    read -rp "Block this domain immediately? [y/N]: " block_now
    if [[ "$block_now" =~ ^[Yy] ]]; then
        echo_safe "${BLUE}Resolving and blocking $domain...${NC}"
        local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]]; then
            timeout=$DEFAULT_TIMEOUT
        fi
        # Resolve IPv4 addresses with timeout
        local v4=()
        mapfile -t v4 < <(dig +short +time="$timeout" +tries=2 A "$domain" 2>/dev/null || echo "")
        # Resolve IPv6 addresses with timeout
        local v6=()
        mapfile -t v6 < <(dig +short +time="$timeout" +tries=2 AAAA "$domain" 2>/dev/null || echo "")
        # Combine and deduplicate
        local all=("${v4[@]}" "${v6[@]}")
        local unique=()
        for ip in "${all[@]}"; do
            [[ -z "$ip" ]] && continue
            if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_ipv6 "$ip"; then
                continue
            fi
            # Check if critical IP
            if is_critical_ip "$ip"; then
                echo_safe "  - ${YELLOW}Skipped critical IP${NC}: $ip"
                continue
            fi
            local found=0
            for u in "${unique[@]}"; do
                if [[ "$u" == "$ip" ]]; then
                    found=1
                    break
                fi
            done
            [[ $found -eq 0 ]] && unique+=("$ip")
        done
        if [[ ${#unique[@]} -eq 0 ]]; then
            echo_safe "  ${YELLOW}No valid IP addresses found${NC}"
            return 0
        fi
        # Convert array to CSV for storage
        local ips_csv=$(IFS=,; echo "${unique[*]}")
        # Record in history
        record_history "$domain" "$ips_csv"
        # Block each IP
        for ip in "${unique[@]}"; do
            if block_ip "$ip" "DNSniper: $domain"; then
                echo_safe "  - ${RED}Blocked${NC}: $ip"
            else
                echo_safe "  - ${RED}Error blocking${NC}: $ip"
            fi
        done
        # Make rules persistent
        make_rules_persistent
    fi
    return 0
}
# Unblock domain
unblock_domain() {
    echo_safe "${BOLD}=== Unblock Domain ===${NC}"
    # Get all active domains
    local domains=()
    mapfile -t domains < <(merge_domains)
    if [[ ${#domains[@]} -eq 0 ]]; then
        echo_safe "${YELLOW}No active domains to unblock.${NC}"
        return 0
    fi
    # Display numbered list of domains
    echo_safe "${BLUE}Current blocked domains:${NC}"
    local i=1
    for d in "${domains[@]}"; do
        printf "%3d) %s\n" $i "$d"
        i=$((i+1))
    done
    read -rp "Enter domain number or domain name to unblock: " choice
    local domain_to_unblock=""
    # Check if choice is a number
    if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le ${#domains[@]} ]]; then
        domain_to_unblock="${domains[$((choice-1))]}"
    else
        domain_to_unblock="$choice"
    fi
    if [[ -z "$domain_to_unblock" ]]; then
        echo_safe "${RED}Invalid selection.${NC}"
        return 1
    fi
    # Add to remove file if not already there
    if ! grep -Fxq "$domain_to_unblock" "$REMOVE_FILE" 2>/dev/null; then
        echo "$domain_to_unblock" >> "$REMOVE_FILE"
        echo_safe "${GREEN}Domain unblocked:${NC} $domain_to_unblock"
        log "INFO" "Domain added to whitelist: $domain_to_unblock" "verbose"
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this domain immediately? [y/N]: " unblock_now
        if [[ "$unblock_now" =~ ^[Yy] ]]; then
            echo_safe "${BLUE}Removing firewall rules for $domain_to_unblock...${NC}"
            # Get IPs from history
            local esc_dom=$(sql_escape "$domain_to_unblock")
            local ips
            ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
            if [[ -n "$ips" ]]; then
                IFS=',' read -ra ip_list <<< "$ips"
                for ip in "${ip_list[@]}"; do
                    if unblock_ip "$ip" "DNSniper: $domain_to_unblock"; then
                        echo_safe "  - ${GREEN}Unblocked${NC}: $ip"
                    fi
                done
                # Make rules persistent
                make_rules_persistent
            else
                echo_safe "${YELLOW}No IP records found for this domain.${NC}"
            fi
        fi
    else
        echo_safe "${YELLOW}Domain already in unblock list.${NC}"
    fi
    return 0
}
# Block IP
block_custom_ip() {
    echo_safe "${BOLD}=== Block IP Address ===${NC}"
    read -rp "IP address to block: " ip
    if [[ -z "$ip" ]]; then
        echo_safe "${RED}IP cannot be empty.${NC}"
        return 1
    fi
    # Validate IP format
    if ! is_ipv6 "$ip" && ! is_valid_ipv4 "$ip"; then
        echo_safe "${RED}Invalid IP format.${NC}"
        return 1
    fi
    # Check if it's a critical IP
    if is_critical_ip "$ip"; then
        echo_safe "${RED}Cannot block critical IP address: $ip${NC}"
        log "WARNING" "Attempted to block critical IP: $ip" "verbose"
        return 1
    fi
    # Check if IP already exists in block list
    if grep -Fxq "$ip" "$IP_ADD_FILE" 2>/dev/null; then
        echo_safe "${YELLOW}IP already in block list.${NC}"
        return 0
    fi
    # Add to custom IPs file
    echo "$ip" >> "$IP_ADD_FILE"
    echo_safe "${GREEN}IP added to block list:${NC} $ip"
    log "INFO" "IP added to block list: $ip" "verbose"
    # Ask if to block immediately
    read -rp "Block this IP immediately? [y/N]: " block_now
    if [[ "$block_now" =~ ^[Yy] ]]; then
        if block_ip "$ip" "DNSniper: custom"; then
            echo_safe "${GREEN}Successfully blocked IP:${NC} $ip"
            # Make rules persistent
            make_rules_persistent
        else
            echo_safe "${RED}Error blocking IP:${NC} $ip"
        fi
    fi
    return 0
}
# Unblock IP
unblock_custom_ip() {
    echo_safe "${BOLD}=== Unblock IP Address ===${NC}"
    # Get all custom IPs
    local custom_ips=()
    mapfile -t custom_ips < <(get_custom_ips)
    if [[ ${#custom_ips[@]} -eq 0 ]]; then
        echo_safe "${YELLOW}No custom IPs to unblock.${NC}"
        return 0
    fi
    # Display numbered list of IPs
    echo_safe "${BLUE}Current blocked IPs:${NC}"
    local i=1
    for ip in "${custom_ips[@]}"; do
        printf "%3d) %s\n" $i "$ip"
        i=$((i+1))
    done
    read -rp "Enter IP number or IP address to unblock: " choice
    local ip_to_unblock=""
    # Check if choice is a number
    if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le ${#custom_ips[@]} ]]; then
        ip_to_unblock="${custom_ips[$((choice-1))]}"
    else
        ip_to_unblock="$choice"
    fi
    if [[ -z "$ip_to_unblock" ]]; then
        echo_safe "${RED}Invalid selection.${NC}"
        return 1
    fi
    # Validate IP format
    if ! is_ipv6 "$ip_to_unblock" && ! is_valid_ipv4 "$ip_to_unblock"; then
        echo_safe "${RED}Invalid IP format.${NC}"
        return 1
    fi
    # Add to remove file if not already there
    if ! grep -Fxq "$ip_to_unblock" "$IP_REMOVE_FILE" 2>/dev/null; then
        echo "$ip_to_unblock" >> "$IP_REMOVE_FILE"
        echo_safe "${GREEN}IP unblocked:${NC} $ip_to_unblock"
        log "INFO" "IP added to whitelist: $ip_to_unblock" "verbose"
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this IP immediately? [y/N]: " unblock_now
        if [[ "$unblock_now" =~ ^[Yy] ]]; then
            if unblock_ip "$ip_to_unblock" "DNSniper: custom"; then
                echo_safe "${GREEN}Successfully unblocked IP:${NC} $ip_to_unblock"
                # Make rules persistent
                make_rules_persistent
            else
                echo_safe "${RED}Error unblocking IP:${NC} $ip_to_unblock"
            fi
        fi
    else
        echo_safe "${YELLOW}IP already in unblock list.${NC}"
    fi
    return 0
}
# Show status
display_status() {
    clear
    show_banner
    # Get domains and IPs
    local domains=()
    mapfile -t domains < <(merge_domains)
    local custom_ips=()
    mapfile -t custom_ips < <(get_custom_ips)
    # Get config values
    local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local sched=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local update_url=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_forward=$(grep '^block_forward=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local logging_enabled=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    # Apply defaults if missing or invalid
    [[ -z "$max_ips" || ! "$max_ips" =~ ^[0-9]+$ ]] && max_ips=$DEFAULT_MAX_IPS
    [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]] && timeout=$DEFAULT_TIMEOUT
    [[ -z "$update_url" ]] && update_url=$DEFAULT_URL
    [[ -z "$auto_update" || ! "$auto_update" =~ ^[01]$ ]] && auto_update=$DEFAULT_AUTO_UPDATE
    [[ -z "$expire_enabled" || ! "$expire_enabled" =~ ^[01]$ ]] && expire_enabled=$DEFAULT_EXPIRE_ENABLED
    [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]] && expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
    [[ -z "$block_forward" || ! "$block_forward" =~ ^[01]$ ]] && block_forward=$DEFAULT_BLOCK_FORWARD
    [[ -z "$logging_enabled" || ! "$logging_enabled" =~ ^[01]$ ]] && logging_enabled=$DEFAULT_LOGGING_ENABLED
    # Format auto-update text
    local auto_update_text="${RED}Disabled${NC}"
    [[ "$auto_update" == "1" ]] && auto_update_text="${GREEN}Enabled${NC}"
    # Format expiration text
    local expire_text="${RED}Disabled${NC}"
    [[ "$expire_enabled" == "1" ]] && expire_text="${GREEN}Enabled (${expire_multiplier}x)${NC}"
    # Format schedule text
    local schedule_text="$sched"
    [[ "$sched" == "# DNSniper disabled" ]] && schedule_text="${RED}Disabled${NC}"
    # Format rule types text
    local rule_types=""
    [[ "$block_source" == "1" ]] && rule_types+="Source, "
    [[ "$block_destination" == "1" ]] && rule_types+="Destination, "
    [[ "$block_forward" == "1" ]] && rule_types+="Forward, "
    rule_types=${rule_types%, }
    [[ -z "$rule_types" ]] && rule_types="${RED}None${NC}"
    # Format logging text
    local logging_text="${RED}Disabled${NC}"
    [[ "$logging_enabled" == "1" ]] && logging_text="${GREEN}Enabled${NC}"
    # Count actual blocked IPs
    local actual_blocked_ips=$(count_blocked_ips)
    # Count expired domains pending cleanup
    local expired_count=0
    if [[ "$expire_enabled" == "1" ]]; then
        local cron_expr=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
        local update_minutes=60 # Default to hourly if can't determine
        if [[ "$cron_expr" == "# DNSniper disabled" ]]; then
            update_minutes=60
        elif [[ "$cron_expr" =~ \*/([0-9]+)[[:space:]] ]]; then
            update_minutes="${BASH_REMATCH[1]}"
        elif [[ "$cron_expr" =~ ^[0-9]+[[:space:]]+\*/([0-9]+) ]]; then
            update_minutes=$((${BASH_REMATCH[1]} * 60))
        fi
        local expire_minutes=$((update_minutes * expire_multiplier))
        expired_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM expired_domains
                                          WHERE source='default' AND
                                          datetime(last_seen, '+$expire_minutes minutes') < datetime('now');" 2>/dev/null || echo 0)
    fi
    # Display summary counts
    echo_safe "${CYAN}${BOLD}SYSTEM STATUS${NC}"
    echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
    echo_safe "${BOLD}Blocked Domains:${NC}      ${GREEN}${#domains[@]}${NC}"
    echo_safe "${BOLD}Blocked IPs:${NC}          ${RED}$actual_blocked_ips${NC}"
    echo_safe "${BOLD}Custom IPs:${NC}           ${YELLOW}${#custom_ips[@]}${NC}"
    if [[ $expired_count -gt 0 && "$expire_enabled" == "1" ]]; then
        echo_safe "${BOLD}Pending Expirations:${NC}  ${YELLOW}$expired_count${NC}"
    fi
    # Config section
    echo_safe ""
    echo_safe "${CYAN}${BOLD}CONFIGURATION${NC}"
    echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
    echo_safe "${BOLD}Schedule:${NC}           $schedule_text"
    echo_safe "${BOLD}Max IPs/domain:${NC}     ${YELLOW}$max_ips${NC}"
    echo_safe "${BOLD}Timeout:${NC}            ${YELLOW}$timeout seconds${NC}"
    echo_safe "${BOLD}Auto-update:${NC}        $auto_update_text"
    echo_safe "${BOLD}Rule Expiration:${NC}    $expire_text"
    echo_safe "${BOLD}Rule Types:${NC}         $rule_types"
    echo_safe "${BOLD}Logging:${NC}            $logging_text"
    # Firewall information
    echo_safe ""
    echo_safe "${CYAN}${BOLD}FIREWALL${NC}"
    echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
    echo_safe "${BOLD}IPv4 Chain:${NC}         ${YELLOW}$IPT_CHAIN${NC}"
    echo_safe "${BOLD}IPv6 Chain:${NC}         ${YELLOW}$IPT6_CHAIN${NC}"
    echo_safe "${BOLD}Persistence:${NC}        ${GREEN}$(detect_system)${NC}"
    # System information
    echo_safe ""
    echo_safe "${CYAN}${BOLD}SYSTEM INFO${NC}"
    echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
    local last_run
    if [[ -f "$LOG_FILE" ]]; then
        last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
    else
        last_run="Never"
    fi
    echo_safe "${BOLD}Last Run:${NC}           ${BLUE}$last_run${NC}"
    echo_safe "${BOLD}Version:${NC}            ${GREEN}$VERSION${NC}"
    # Domains section if exists
    if [[ ${#domains[@]} -gt 0 ]]; then
        echo_safe ""
        echo_safe "${CYAN}${BOLD}BLOCKED DOMAINS (TOP 10 OF ${#domains[@]})${NC}"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        local dom_count=0
        for dom in "${domains[@]}"; do
            # Get most recent IP list - Fixed approach
            local esc_dom=$(sql_escape "$dom")
            # Check if there are records for this domain
            local record_count
            record_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM history WHERE domain='$esc_dom';" 2>/dev/null || echo "0")
            if [[ "$record_count" -gt 0 ]]; then
                # Records exist, get the IPs
                local ips
                ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null || echo "")
                if [[ -n "$ips" ]]; then
                    local ip_count
                    # Count the commas and add 1
                    ip_count=$(echo "$ips" | tr -cd ',' | wc -c)
                    ip_count=$((ip_count + 1))
                    # Check if any IPs are actively blocked
                    local active_blocks=0
                    IFS=',' read -ra ip_list <<< "$ips"
                    for ip in "${ip_list[@]}"; do
                        local tbl="iptables"
                        if is_ipv6 "$ip"; then
                            tbl="ip6tables"
                        fi
                        if $tbl-save 2>/dev/null | grep -q "$ip.*$dom"; then
                            active_blocks=1
                            break
                        fi
                    done
                    if [[ $active_blocks -eq 1 ]]; then
                        echo_safe "${GREEN}$dom${NC} (${YELLOW}$ip_count IPs${NC})"
                    else
                        echo_safe "${GREEN}$dom${NC} (${YELLOW}$ip_count IPs ${CYAN}not blocked yet${NC})"
                    fi
                else
                    # Database record exists but IPs field is empty
                    echo_safe "${GREEN}$dom${NC} (${RED}No IPs in database${NC})"
                fi
            else
                # Try to resolve now to show up-to-date info
                local resolved_now
                resolved_now=$(dig +short A "$dom" 2>/dev/null)
                if [[ -n "$resolved_now" ]]; then
                    # We can resolve it, but it's not in the DB yet
                    echo_safe "${GREEN}$dom${NC} (${YELLOW}Resolvable, run 'Run Now' to block${NC})"
                else
                    # Cannot resolve at all
                    echo_safe "${GREEN}$dom${NC} (${RED}No IPs resolved yet${NC})"
                fi
            fi
            dom_count=$((dom_count + 1))
            [[ $dom_count -ge 10 && ${#domains[@]} -gt 10 ]] && {
                echo_safe "${YELLOW}... and $((${#domains[@]} - 10)) more domains${NC}";
                break;
            }
        done
    fi
    # Custom IPs section if exists
    if [[ ${#custom_ips[@]} -gt 0 ]]; then
        echo_safe ""
        echo_safe "${CYAN}${BOLD}BLOCKED IPs (TOP 10 OF ${#custom_ips[@]})${NC}"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        local ip_count=0
        for ip in "${custom_ips[@]}"; do
            echo_safe "${GREEN}$ip${NC}"
            ip_count=$((ip_count + 1))
            [[ $ip_count -ge 10 && ${#custom_ips[@]} -gt 10 ]] && {
                echo_safe "${YELLOW}... and $((${#custom_ips[@]} - 10)) more IPs${NC}";
                break;
            }
        done
    fi
    echo_safe ""
    return 0
}
# Clear rules
clear_rules() {
    echo_safe "${BOLD}=== Clear Firewall Rules ===${NC}"
    read -rp "Clear all DNSniper firewall rules? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy] ]]; then
        echo_safe "${BLUE}Removing DNSniper rules...${NC}"
        local success=0
        # Flush our custom chains
        if iptables -F "$IPT_CHAIN" 2>/dev/null && ip6tables -F "$IPT6_CHAIN" 2>/dev/null; then
            success=1
        fi
        # Make rules persistent
        make_rules_persistent
        if [[ $success -eq 1 ]]; then
            echo_safe "${GREEN}All DNSniper rules cleared.${NC}"
            log "INFO" "All firewall rules cleared" "verbose"
        else
            echo_safe "${RED}Error clearing rules. Check iptables status.${NC}"
            log "ERROR" "Error clearing firewall rules"
            return 1
        fi
    else
        echo_safe "${YELLOW}Operation canceled.${NC}"
    fi
    return 0
}
# Uninstall
uninstall() {
    echo_safe "${RED}${BOLD}Warning: This will completely remove DNSniper.${NC}"
    read -rp "Are you sure you want to proceed? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy] ]]; then
        echo_safe "${BLUE}Uninstalling DNSniper...${NC}"
        # Ask about keeping rules
        read -rp "Keep existing firewall rules? [y/N]: " keep_rules
        if [[ ! "$keep_rules" =~ ^[Yy] ]]; then
            echo_safe "${BLUE}Removing firewall rules...${NC}"
            # Remove references to our chains
            iptables -D INPUT -j "$IPT_CHAIN" 2>/dev/null || true
            iptables -D OUTPUT -j "$IPT_CHAIN" 2>/dev/null || true
            iptables -D FORWARD -j "$IPT_CHAIN" 2>/dev/null || true
            ip6tables -D INPUT -j "$IPT6_CHAIN" 2>/dev/null || true
            ip6tables -D OUTPUT -j "$IPT6_CHAIN" 2>/dev/null || true
            ip6tables -D FORWARD -j "$IPT6_CHAIN" 2>/dev/null || true
            # Flush our chains
            iptables -F "$IPT_CHAIN" 2>/dev/null || true
            ip6tables -F "$IPT6_CHAIN" 2>/dev/null || true
            # Delete our chains
            iptables -X "$IPT_CHAIN" 2>/dev/null || true
            ip6tables -X "$IPT6_CHAIN" 2>/dev/null || true
            # Make changes persistent
            make_rules_persistent
        fi
        # Remove systemd service if we created one
        if [[ -f "/etc/systemd/system/dnsniper-firewall.service" ]]; then
            systemctl disable dnsniper-firewall.service &>/dev/null || true
            rm -f "/etc/systemd/system/dnsniper-firewall.service" &>/dev/null || true
            systemctl daemon-reload &>/dev/null || true
        fi
        # Remove cron job
        crontab -l 2>/dev/null | grep -vF "$BIN_CMD" | crontab - || true
        # Remove binary and directories
        rm -f "$BIN_CMD" 2>/dev/null || true
        rm -rf "$BASE_DIR" 2>/dev/null || true
        echo_safe "${GREEN}DNSniper successfully uninstalled.${NC}"
        exit 0
    else
        echo_safe "${YELLOW}Uninstall canceled.${NC}"
    fi
    return 0
}
# Show help
show_help() {
    show_banner
    echo_safe "${BOLD}=== DNSniper v$VERSION Help ===${NC}"
    echo_safe "${BOLD}Usage:${NC} dnsniper [options]"
    echo_safe ""
    echo_safe "${BOLD}Options:${NC}"
    echo_safe "  ${YELLOW}--run${NC}        Run DNSniper once (non-interactive)"
    echo_safe "  ${YELLOW}--update${NC}     Update default domains list"
    echo_safe "  ${YELLOW}--status${NC}     Display status"
    echo_safe "  ${YELLOW}--block${NC} DOMAIN Add a domain to block list"
    echo_safe "  ${YELLOW}--unblock${NC} DOMAIN Remove a domain from block list"
    echo_safe "  ${YELLOW}--block-ip${NC} IP Add an IP to block list"
    echo_safe "  ${YELLOW}--unblock-ip${NC} IP Remove an IP from block list"
    echo_safe "  ${YELLOW}--check-expired${NC} Check and remove expired rules"
    echo_safe "  ${YELLOW}--version${NC}    Show version"
    echo_safe "  ${YELLOW}--help${NC}       Show this help"
    echo_safe ""
    echo_safe "${BOLD}Interactive Menu:${NC}"
    echo_safe "  Run without arguments to access the interactive menu"
    echo_safe "  which provides all functionality, configuration options,"
    echo_safe "  and maintenance features."
    echo_safe ""
    return 0
}
### 16) Main menu loop
main_menu() {
    while true; do
        show_banner
        echo_safe "${CYAN}${BOLD}MAIN MENU${NC}"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        echo_safe "${YELLOW}1.${NC} Run Now              ${YELLOW}2.${NC} Status"
        echo_safe "${YELLOW}3.${NC} Block Domain         ${YELLOW}4.${NC} Unblock Domain"
        echo_safe "${YELLOW}5.${NC} Block IP Address     ${YELLOW}6.${NC} Unblock IP Address"
        echo_safe "${YELLOW}7.${NC} Settings             ${YELLOW}8.${NC} Update Lists"
        echo_safe "${YELLOW}9.${NC} Clear Rules          ${YELLOW}0.${NC} Exit"
        echo_safe "${YELLOW}U.${NC} Uninstall"
        echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
        read -rp "Select an option: " choice
        case "$choice" in
            1) clear; resolve_block; read -rp "Press Enter to continue..." ;;
            2) display_status; read -rp "Press Enter to continue..." ;;
            3) clear; block_domain; read -rp "Press Enter to continue..." ;;
            4) clear; unblock_domain; read -rp "Press Enter to continue..." ;;
            5) clear; block_custom_ip; read -rp "Press Enter to continue..." ;;
            6) clear; unblock_custom_ip; read -rp "Press Enter to continue..." ;;
            7) settings_menu ;;
            8) clear; update_default; read -rp "Press Enter to continue..." ;;
            9) clear; clear_rules; read -rp "Press Enter to continue..." ;;
            0) echo_safe "${GREEN}Exiting...${NC}"; exit 0 ;;
            [Uu]) clear; uninstall ;;
            *) echo_safe "${RED}Invalid selection. Please choose from the menu.${NC}"; sleep 1 ;;
        esac
    done
}
### 17) Command line arguments handling
handle_args() {
    case "$1" in
        --run)
            resolve_block
            ;;
        --update)
            update_default
            ;;
        --status)
            display_status
            ;;
        --block)
            if [[ -z "$2" ]]; then
                echo_safe "${RED}Error: missing domain parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$ADD_FILE"
            echo_safe "${GREEN}Domain added to block list:${NC} $2"
            log "INFO" "Domain added via CLI: $2" "verbose"
            ;;
        --unblock)
            if [[ -z "$2" ]]; then
                echo_safe "${RED}Error: missing domain parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$REMOVE_FILE"
            echo_safe "${GREEN}Domain added to unblock list:${NC} $2"
            log "INFO" "Domain unblocked via CLI: $2" "verbose"
            ;;
        --block-ip)
            if [[ -z "$2" ]]; then
                echo_safe "${RED}Error: missing IP parameter${NC}"
                show_help
                exit 1
            fi
            if is_critical_ip "$2"; then
                echo_safe "${RED}Cannot block critical IP:${NC} $2"
                exit 1
            fi
            echo "$2" >> "$IP_ADD_FILE"
            echo_safe "${GREEN}IP added to block list:${NC} $2"
            log "INFO" "IP added via CLI: $2" "verbose"
            ;;
        --unblock-ip)
            if [[ -z "$2" ]]; then
                echo_safe "${RED}Error: missing IP parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$IP_REMOVE_FILE"
            echo_safe "${GREEN}IP added to unblock list:${NC} $2"
            log "INFO" "IP unblocked via CLI: $2" "verbose"
            ;;
        --check-expired)
            check_expired_domains
            ;;
        --version)
            echo_safe "DNSniper version $VERSION"
            exit 0
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}
### 18) Entry point
main() {
    # Create log directory if needed
    if [[ ! -d "$(dirname "$LOG_FILE")" ]]; then
        mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    fi
    touch "$LOG_FILE" 2>/dev/null || true
    
    # Initialize logging state
    initialize_logging
    
    # Check running as root
    check_root
    # Check dependencies
    check_dependencies
    # Prepare environment
    ensure_environment
    # Handle arguments if provided
    if [[ $# -gt 0 ]]; then
        if handle_args "$@"; then
            exit 0
        fi
    fi
    # Interactive or non-interactive mode
    if [[ -t 0 && -t 1 ]]; then
        main_menu
    else
        # When run via cron, we should do domain resolution
        resolve_block
    fi
    exit 0
}
# Start the application
main "$@"