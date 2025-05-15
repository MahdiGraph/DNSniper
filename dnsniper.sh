#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 1.3.7

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

# IPSet definitions
IPSET4="dnsniper-ipv4"
IPSET6="dnsniper-ipv6"

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
DEFAULT_LOGGING_ENABLED=0

# Chain names
IPT_CHAIN="DNSniper"
IPT6_CHAIN="DNSniper6"

# Version
VERSION="1.3.7"

# Dependencies
DEPENDENCIES=(iptables ip6tables curl dig sqlite3 crontab)

# Helper functions
log() {
    local level="$1" 
    local message="$2" 
    local verbose="${3:-}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Only write to log file if logging is enabled
    if [[ "$LOGGING_ENABLED" -eq 1 ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    case "$level" in
        ERROR)
            echo -e "${RED}Error:${NC} $message" >&2
            ;;
        WARNING)
            echo -e "${YELLOW}Warning:${NC} $message" >&2
            ;;
        INFO)
            if [[ "$verbose" == "verbose" ]]; then
                echo -e "${BLUE}Info:${NC} $message"
            fi
            ;;
    esac
}

initialize_logging() {
    # Read from config file
    local logging_setting
    logging_setting=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$logging_setting" == "1" ]]; then
        LOGGING_ENABLED=1
    else
        LOGGING_ENABLED=0
    fi
}

echo_safe() {
    echo -e "$1"
}

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

sql_escape() {
    local s="$1"
    s=${s//\'/\'\'}
    printf "%s" "$s"
}

is_ipv6() {
    local ip="$1"
    [[ "$ip" =~ .*:.* ]]  # Simple pattern for IPv6 detection
}

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

is_valid_domain() {
    local domain="$1"
    # Basic domain name validation
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

is_critical_ip() {
    local ip="$1"
    [[ "$ip" == "127.0.0.1" ||
       "$ip" == "0.0.0.0" ||
       "$ip" == "::1" ||
       "$ip" =~ ^169\.254\. ||
       "$ip" =~ ^192\.168\. ||
       "$ip" =~ ^10\. ||
       "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
    
    local server_ip
    server_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || curl -s --max-time 5 icanhazip.com 2>/dev/null || echo "")
    [[ -n "$server_ip" && "$ip" == "$server_ip" ]] && return 0

    if command -v ip &>/dev/null; then
        local gateway
        gateway=$(ip route | grep default | awk '{print $3}' | head -n 1)
        [[ -n "$gateway" && "$ip" == "$gateway" ]] && return 0
    fi
    return 1
}

exit_with_error() {
    log "ERROR" "$1"
    echo -e "${RED}Error:${NC} $1" >&2
    exit "${2:-1}"
}

detect_system() {
    if [[ -f /etc/debian_version ]]; then
        if grep -qi ubuntu /etc/os-release 2>/dev/null; then
            echo "ubuntu"
        else
            echo "debian"
        fi
    elif [[ -f /etc/redhat-release ]]; then
        if grep -qi "centos\|centos linux" /etc/redhat-release 2>/dev/null; then
            echo "centos"
        elif grep -qi "red hat\|redhat" /etc/redhat-release 2>/dev/null; then
            echo "rhel"
        else
            echo "redhat"
        fi
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    elif [[ -f /etc/os-release ]]; then
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

make_rules_persistent() {
    local os_type=$(detect_system)
    if [[ "$os_type" == "debian" || "$os_type" == "ubuntu" ]]; then
        mkdir -p /etc/iptables/ 2>/dev/null || true
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        chmod 644 /etc/iptables/rules.v4 /etc/iptables/rules.v6 2>/dev/null || true
    elif [[ "$os_type" == "centos" || "$os_type" == "rhel" || "$os_type" == "redhat" ]]; then
        if [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
            chmod 600 /etc/sysconfig/iptables /etc/sysconfig/ip6tables 2>/dev/null || true
        fi
    elif [[ "$os_type" == "fedora" ]]; then
        if [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
        fi
    fi
    iptables-save > "$RULES_V4_FILE" 2>/dev/null || true
    ip6tables-save > "$RULES_V6_FILE" 2>/dev/null || true
    if command -v ipset &>/dev/null && ipset list ${IPSET4} >/dev/null 2>&1; then
        ipset save > /etc/ipset.conf 2>/dev/null || true
    fi
}

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

initialize_chains() {
    if ! iptables -L "$IPT_CHAIN" &>/dev/null; then
        iptables -N "$IPT_CHAIN" 2>/dev/null || true
        log "INFO" "Created IPv4 chain $IPT_CHAIN" "verbose"
    fi
    if ! ip6tables -L "$IPT6_CHAIN" &>/dev/null; then
        ip6tables -N "$IPT6_CHAIN" 2>/dev/null || true
        log "INFO" "Created IPv6 chain $IPT6_CHAIN" "verbose"
    fi
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
    make_rules_persistent
}

ensure_environment() {
    mkdir -p "$BASE_DIR" 2>/dev/null || true
    touch "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$IP_ADD_FILE" "$IP_REMOVE_FILE" 2>/dev/null || true
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
# DNSniper Configuration
cron='$DEFAULT_CRON'
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
    for cmd in "${DEPENDENCIES[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Warning: $cmd is not installed. Some features may not work." >&2
        fi
    done
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
        echo "Warning: sqlite3 not found, database functionality disabled." >&2
    fi
    initialize_chains
    if command -v ipset >/dev/null 2>&1; then
        ipset create "$IPSET4" hash:ip family inet -exist 2>/dev/null || true
        ipset create "$IPSET6" hash:ip family inet6 -exist 2>/dev/null || true
    fi
    initialize_logging
    local cron_expr
    cron_expr=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    if [[ -n "$cron_expr" && "$cron_expr" != "# DNSniper disabled" ]]; then
        (crontab -l 2>/dev/null | grep -v "$BIN_CMD"; echo "$cron_expr") | crontab - 2>/dev/null || true
    fi
    return 0
}

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

update_default() {
    log "INFO" "Updating default domains list" "verbose"
    local update_url
    update_url=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local timeout
    timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$update_url" ]]; then
        update_url="$DEFAULT_URL"
    fi
    if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]]; then
        timeout="$DEFAULT_TIMEOUT"
    fi
    echo_safe "${BLUE}Fetching default domains from $update_url...${NC}"
    local expire_enabled
    expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$expire_enabled" == "1" ]]; then
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
        if [[ -s "$DEFAULT_FILE.tmp" ]]; then
            if ! mv "$DEFAULT_FILE.tmp" "$DEFAULT_FILE"; then
                rm -f "$DEFAULT_FILE.tmp" &>/dev/null || true
                log "ERROR" "Failed to update default domains file"
                echo_safe "${RED}Failed to update default domains file${NC}"
                return 1
            fi
            if [[ "$expire_enabled" == "1" ]]; then
                local new_domains=()
                while IFS= read -r d || [[ -n "$d" ]]; do
                    [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
                    d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
                    [[ -z "$d" ]] && continue
                    new_domains+=("$d")
                done < "$DEFAULT_FILE"
                for old_dom in "${old_domains[@]}"; do
                    local found=0
                    for new_dom in "${new_domains[@]}"; do
                        if [[ "$old_dom" == "$new_dom" ]]; then
                            found=1
                            break
                        fi
                    done
                    if [[ $found -eq 0 ]]; then
                        local esc_dom
                        esc_dom=$(sql_escape "$old_dom")
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

check_expired_domains() {
    local expire_enabled
    expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$expire_enabled" != "1" ]]; then
        return 0
    fi
    log "INFO" "Checking for expired domains" "verbose"
    local cron_expr
    cron_expr=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local update_minutes=60
    if [[ "$cron_expr" == "# DNSniper disabled" ]]; then
        update_minutes=60
    elif [[ "$cron_expr" =~ \*/([0-9]+)[[:space:]] ]]; then
        update_minutes="${BASH_REMATCH[1]}"
    elif [[ "$cron_expr" =~ ^[0-9]+[[:space:]]+\*/([0-9]+) ]]; then
        update_minutes=$((${BASH_REMATCH[1]} * 60))
    fi
    local expire_multiplier
    expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]]; then
        expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
    fi
    local expire_minutes=$((update_minutes * expire_multiplier))
    local expired_domains
    expired_domains=$(sqlite3 "$DB_FILE" "SELECT domain FROM expired_domains
                                          WHERE source='default' AND
                                          datetime(last_seen, '+$expire_minutes minutes') < datetime('now');" 2>/dev/null)
    if [[ -n "$expired_domains" ]]; then
        echo_safe "${YELLOW}Found expired domains to clean up...${NC}"
        while IFS= read -r domain; do
            echo_safe "${YELLOW}Removing expired domain:${NC} $domain"
            local esc_dom
            esc_dom=$(sql_escape "$domain")
            local ips
            ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
            if [[ -n "$ips" ]]; then
                IFS=',' read -ra ip_list <<< "$ips"
                for ip in "${ip_list[@]}"; do
                    if unblock_ip "$ip" "DNSniper: $domain"; then
                        echo_safe "  - ${GREEN}Unblocked expired IP:${NC} $ip"
                    fi
                done
            fi
            sqlite3 "$DB_FILE" "DELETE FROM expired_domains WHERE domain='$esc_dom';" 2>/dev/null
            if ! grep -Fxq "$domain" "$REMOVE_FILE" 2>/dev/null; then
                echo "$domain" >> "$REMOVE_FILE"
            fi
            log "INFO" "Removed expired domain: $domain" "verbose"
        done <<< "$expired_domains"
        make_rules_persistent
    fi
}

merge_domains() {
    log "INFO" "Merging domain lists"
    local tmpfile
    tmpfile=$(mktemp)
    if [[ -f "$DEFAULT_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$DEFAULT_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile" || true
    fi
    if [[ -f "$ADD_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$ADD_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | while read -r domain; do
            if ! grep -Fxq "$domain" "$tmpfile"; then
                echo "$domain" >> "$tmpfile"
            fi
        done
    fi
    if [[ -f "$REMOVE_FILE" && -s "$tmpfile" ]]; then
        local tmprm
        tmprm=$(mktemp)
        cp "$tmpfile" "$tmprm"
        grep -v '^[[:space:]]*#' "$REMOVE_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | while read -r domain; do
            if [[ -n "$domain" ]]; then
                grep -Fxv "$domain" "$tmprm" > "$tmpfile" || true
                cp "$tmpfile" "$tmprm"
            fi
        done
        rm -f "$tmprm"
    fi
    cat "$tmpfile"
    rm -f "$tmpfile"
}

get_custom_ips() {
    log "INFO" "Getting custom IP list"
    local tmpfile
    tmpfile=$(mktemp)
    if [[ -f "$IP_ADD_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$IP_ADD_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile" || true
    fi
    if [[ -f "$IP_REMOVE_FILE" && -s "$tmpfile" ]]; then
        local tmprm
        tmprm=$(mktemp)
        cp "$tmpfile" "$tmprm"
        grep -v '^[[:space:]]*#' "$IP_REMOVE_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | while read -r ip; do
            if [[ -n "$ip" ]]; then
                grep -Fxv "$ip" "$tmprm" > "$tmpfile" || true
                cp "$tmpfile" "$tmprm"
            fi
        done
        rm -f "$tmprm"
    fi
    if [[ -s "$tmpfile" ]]; then
        local tmpvalid
        tmpvalid=$(mktemp)
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
    rm -f "$tmpfile"
}

record_history() {
    local domain="$1" 
    local ips_csv="$2"
    domain=$(sql_escape "$domain")
    ips_csv=$(sql_escape "$ips_csv")
    log "INFO" "Recording history for domain: $domain with IPs: $ips_csv"
    local max_ips
    max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
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

detect_cdn() {
    local domains=("$@")
    if [[ ${#domains[@]} -eq 0 ]]; then
        return 0
    fi
    local warnings=()
    log "INFO" "Detecting CDN usage for ${#domains[@]} domains"
    local total_domains=${#domains[@]}
    local batch_size=50

    for ((i=0; i<total_domains; i+=batch_size)); do
        local end=$((i + batch_size))
        [[ $end -gt $total_domains ]] && end=$total_domains

        for ((j=i; j<end; j++)); do
            local dom="${domains[j]}"
            local esc_dom
            esc_dom=$(sql_escape "$dom")
            local rows
            rows=$(sqlite3 -separator '|' "$DB_FILE" \
                "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 2;" 2>/dev/null)
            
            if [[ -z "$rows" || $(echo "$rows" | wc -l) -lt 2 ]]; then
                continue
            fi
            
            local last prev
            IFS='|' read -r last prev <<< "$rows"
            
            [[ -z "$last" || -z "$prev" ]] && continue
            
            local last_ips prev_ips
            IFS=',' read -ra last_ips <<< "$last"
            IFS=',' read -ra prev_ips <<< "$prev"

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

        if [[ ${#warnings[@]} -le 10 ]]; then
            echo_safe "${YELLOW}${warnings[*]}${NC}"
        else
            for ((i=0; i<10; i++)); do
                echo_safe "${YELLOW}${warnings[i]}${NC}"
            done
            echo_safe "${YELLOW}...and $((${#warnings[@]} - 10)) more${NC}"
        fi
        log "WARNING" "Potential CDN domains detected: ${warnings[*]}"
    fi
}

block_ip() {
    local ip="$1"
    local comment="$2"
    local tbl="iptables"
    local chain="$IPT_CHAIN"

    if is_ipv6 "$ip"; then
        tbl="ip6tables"
        chain="$IPT6_CHAIN"
    fi

    local block_source
    block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_destination
    block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)

    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION

    local rules_added=0

    if [[ "$block_source" == "1" ]]; then
        if ! $tbl -C "$chain" -s "$ip" -j DROP -m comment --comment "$comment" &>/dev/null; then
            if $tbl -A "$chain" -s "$ip" -j DROP -m comment --comment "$comment"; then
                rules_added=1
            else
                log "ERROR" "Failed to add source rule for $ip" "verbose"
            fi
        fi
    fi

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

unblock_ip() {
    local ip="$1"
    local comment_pattern="$2"
    local tbl="iptables"
    local chain="$IPT_CHAIN"
    local success=0

    if is_ipv6 "$ip"; then
        tbl="ip6tables"
        chain="$IPT6_CHAIN"
    fi

    local block_source
    block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_destination
    block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)

    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION

    if [[ "$block_source" == "1" ]]; then
        while $tbl -C "$chain" -s "$ip" -j DROP -m comment --comment "$comment_pattern" &>/dev/null 2>&1; do
            $tbl -D "$chain" -s "$ip" -j DROP -m comment --comment "$comment_pattern"
            success=1
        done
    fi

    if [[ "$block_destination" == "1" ]]; then
        while $tbl -C "$chain" -d "$ip" -j DROP -m comment --comment "$comment_pattern" &>/dev/null 2>&1; do
            $tbl -D "$chain" -d "$ip" -j DROP -m comment --comment "$comment_pattern"
            success=1
        done
    fi

    if [[ $success -eq 1 ]]; then
        make_rules_persistent
    fi
    
    return $((1 - success))
}

count_blocked_ips() {
    local v4_rules
    local v6_rules

    v4_rules=$(iptables-save 2>/dev/null | grep -E "$IPT_CHAIN.*DROP" | grep -o -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l)
    v6_rules=$(ip6tables-save 2>/dev/null | grep -E "$IPT6_CHAIN.*DROP" | grep -o -E '([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}' | sort -u | wc -l)

    # Return total
    echo $((v4_rules + v6_rules))
}

has_active_blocks() {
    local domain="$1"
    local esc_dom
    esc_dom=$(sql_escape "$domain")

    local count
    count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM history WHERE domain='$esc_dom';" 2>/dev/null || echo 0)
    if [[ $count -eq 0 ]]; then
        return 1
    fi

    local ips
    ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
    if [[ -z "$ips" ]]; then
        return 1
    fi

    local ip_list
    IFS=',' read -ra ip_list <<< "$ips"

    for ip in "${ip_list[@]}"; do
        local blocked=0
        local tbl="iptables"
        if is_ipv6 "$ip"; then
            tbl="ip6tables"
        fi
        if $tbl-save 2>/dev/null | grep -q "$ip.*DNSniper: $domain"; then
            return 0
        fi
    done

    return 1
}

resolve_block() {
    log "INFO" "Starting domain resolution and blocking" "verbose"

    local auto_update
    auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$auto_update" || ! "$auto_update" =~ ^[0-9]+$ ]]; then
        auto_update=$DEFAULT_AUTO_UPDATE
    fi
    if [[ "$auto_update" -eq 1 ]]; then
        echo_safe "${BLUE}Auto-updating domain lists...${NC}"
        update_default
    fi

    check_expired_domains
    echo_safe "${BLUE}Resolving domains...${NC}"

    local domains=()
    local tmpdomains
    tmpdomains=$(mktemp)
    merge_domains > "$tmpdomains"
    local total
    total=$(wc -l < "$tmpdomains")
    if [[ $total -eq 0 ]]; then
        echo_safe "${YELLOW}No domains to process.${NC}"
        log "INFO" "No domains to process" "verbose"
        rm -f "$tmpdomains"
    else
        echo_safe "${BLUE}Processing ${total} domains...${NC}"
        local timeout
        timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]]; then
            log "WARNING" "Invalid timeout value, using default: $DEFAULT_TIMEOUT"
            timeout=$DEFAULT_TIMEOUT
        fi
        local success_count=0
        local ip_count=0
        local batch_size=50
        local progress=0
        while IFS= read -r dom || [[ -n "$dom" ]]; do
            progress=$((progress + 1))
            if [[ $total -gt 100 && $((progress % 10)) -eq 0 ]]; then
                echo_safe "${BLUE}Progress: $progress/$total domains ($(( (progress * 100) / total ))%)${NC}"
            fi
            if ! is_valid_domain "$dom"; then
                log "WARNING" "Invalid domain format: $dom"
                continue
            fi
            log "INFO" "Processing domain: $dom" "verbose"
            local v4=()
            mapfile -t v4 < <(dig +short +time="$timeout" +tries=2 A "$dom" 2>/dev/null || echo "")
            local v6=()
            mapfile -t v6 < <(dig +short +time="$timeout" +tries=2 AAAA "$dom" 2>/dev/null || echo "")
            local all=("${v4[@]}" "${v6[@]}")
            local unique=()
            for ip in "${all[@]}"; do
                [[ -z "$ip" ]] && continue
                if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_ipv6 "$ip"; then
                    log "WARNING" "Invalid IP format: $ip for domain $dom"
                    continue
                fi
                if is_critical_ip "$ip"; then
                    log "WARNING" "Skipping critical IP: $ip for domain $dom" "verbose"
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
                log "WARNING" "No valid IP addresses found for domain: $dom" "verbose"
                continue
            fi
            local ips_csv
            ips_csv=$(IFS=,; echo "${unique[*]}")
            if record_history "$dom" "$ips_csv"; then
                success_count=$((success_count + 1))
            fi
            for ip in "${unique[@]}"; do
                if block_ip "$ip" "DNSniper: $dom"; then
                    log "INFO" "Successfully blocked IP: $ip for domain: $dom"
                    ip_count=$((ip_count + 1))
                else
                    log "ERROR" "Error blocking IP: $ip for domain: $dom"
                fi
            done
            if [[ $total -gt 100 && $((progress % 50)) -eq 0 ]]; then
                make_rules_persistent
            fi
        done < "$tmpdomains"
        rm -f "$tmpdomains"
        echo_safe "${GREEN}Domain resolution complete. $success_count/$total domains processed, $ip_count new IPs blocked.${NC}"
        log "INFO" "Domain resolution complete. $success_count/$total domains processed, $ip_count new IPs blocked." "verbose"
        if [[ -t 1 || "$1" == "force-cdn-check" ]]; then
            mapfile -t domains < <(merge_domains)
            detect_cdn "${domains[@]}"
        fi
    fi

    local custom_ips=()
    local tmpcustomips
    tmpcustomips=$(mktemp)
    get_custom_ips > "$tmpcustomips"
    local custom_total
    custom_total=$(wc -l < "$tmpcustomips")
    if [[ $custom_total -gt 0 ]]; then
        echo_safe "${BLUE}Processing ${custom_total} custom IPs...${NC}"
        local custom_blocked=0
        while IFS= read -r ip || [[ -n "$ip" ]]; do
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
            if [[ $custom_total -gt 100 && $((custom_blocked % 50)) -eq 0 ]]; then
                make_rules_persistent
            fi
        done < "$tmpcustomips"
        rm -f "$tmpcustomips"
        echo_safe "${GREEN}Custom IP blocking complete. $custom_blocked/$custom_total IPs blocked.${NC}"
        log "INFO" "Custom IP blocking complete. $custom_blocked/$custom_total IPs blocked." "verbose"
    else
        rm -f "$tmpcustomips"
    fi
    make_rules_persistent
    return 0
}

display_status() {
    clear
    echo_safe "${BLUE}Loading DNSniper status, please wait...${NC}"
    local tmpout
    tmpout=$(mktemp)
    
    (
        show_banner > "$tmpout"
        local domain_count
        domain_count=$(merge_domains | wc -l)
        local blocked_ips
        blocked_ips=$(count_blocked_ips)
        local custom_ip_count
        custom_ip_count=$(get_custom_ips | wc -l)
        local max_ips
        max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local timeout
        timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local sched
        sched=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
        local update_url
        update_url=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
        local auto_update
        auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local expire_enabled
        expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local expire_multiplier
        expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local block_source
        block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local block_destination
        block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local logging_enabled
        logging_enabled=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)

        [[ -z "$max_ips" || ! "$max_ips" =~ ^[0-9]+$ ]] && max_ips=$DEFAULT_MAX_IPS
        [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]] && timeout=$DEFAULT_TIMEOUT
        [[ -z "$update_url" ]] && update_url=$DEFAULT_URL
        [[ -z "$auto_update" || ! "$auto_update" =~ ^[01]$ ]] && auto_update=$DEFAULT_AUTO_UPDATE
        [[ -z "$expire_enabled" || ! "$expire_enabled" =~ ^[01]$ ]] && expire_enabled=$DEFAULT_EXPIRE_ENABLED
        [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]] && expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
        [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
        [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
        [[ -z "$logging_enabled" || ! "$logging_enabled" =~ ^[01]$ ]] && logging_enabled=$DEFAULT_LOGGING_ENABLED

        local auto_update_text="${RED}Disabled${NC}"
        [[ "$auto_update" == "1" ]] && auto_update_text="${GREEN}Enabled${NC}"
        local expire_text="${RED}Disabled${NC}"
        [[ "$expire_enabled" == "1" ]] && expire_text="${GREEN}Enabled (${expire_multiplier}x)${NC}"
        local schedule_text="$sched"
        [[ "$sched" == "# DNSniper disabled" ]] && schedule_text="${RED}Disabled${NC}"
        local rule_types=""
        [[ "$block_source" == "1" ]] && rule_types+="Source, "
        [[ "$block_destination" == "1" ]] && rule_types+="Destination"
        rule_types=${rule_types%, }
        [[ -z "$rule_types" ]] && rule_types="${RED}None${NC}"
        local logging_text="${RED}Disabled${NC}"
        [[ "$logging_enabled" == "1" ]] && logging_text="${GREEN}Enabled${NC}"

        local expired_count=0
        if [[ "$expire_enabled" == "1" ]]; then
            local cron_expr
            cron_expr=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
            local update_minutes=60
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

        {
            echo_safe "${CYAN}${BOLD}SYSTEM STATUS${NC}"
            echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
            echo_safe "${BOLD}Blocked Domains:${NC}      ${GREEN}${domain_count}${NC}"
            echo_safe "${BOLD}Blocked IPs:${NC}          ${RED}${blocked_ips}${NC}"
            echo_safe "${BOLD}Custom IPs:${NC}           ${YELLOW}${custom_ip_count}${NC}"
            if [[ $expired_count -gt 0 && "$expire_enabled" == "1" ]]; then
                echo_safe "${BOLD}Pending Expirations:${NC}  ${YELLOW}$expired_count${NC}"
            fi
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
            echo_safe ""
            echo_safe "${CYAN}${BOLD}FIREWALL${NC}"
            echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
            echo_safe "${BOLD}IPv4 Chain:${NC}         ${YELLOW}$IPT_CHAIN${NC}"
            echo_safe "${BOLD}IPv6 Chain:${NC}         ${YELLOW}$IPT6_CHAIN${NC}"
            echo_safe "${BOLD}Persistence:${NC}        ${GREEN}$(detect_system)${NC}"
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

            if [[ $domain_count -gt 0 && $domain_count -le 500 ]]; then
                echo_safe ""
                echo_safe "${CYAN}${BOLD}BLOCKED DOMAINS (TOP 10 OF ${domain_count})${NC}"
                echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
                local tmpdomain
                tmpdomain=$(mktemp)
                merge_domains | head -10 > "$tmpdomain"
                local dom_count=0
                while IFS= read -r dom || [[ -n "$dom" ]]; do
                    local esc_dom
                    esc_dom=$(sql_escape "$dom")
                    local record_count
                    record_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM history WHERE domain='$esc_dom';" 2>/dev/null || echo "0")
                    if [[ "$record_count" -gt 0 ]]; then
                        local ip_count
                        ip_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(distinct ip) FROM (
                                  SELECT value as ip FROM history
                                  JOIN json_each('['||(SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1)||']')
                                  WHERE domain='$esc_dom'
                                  );" 2>/dev/null || echo "0")
                        echo_safe "${GREEN}$dom${NC} (${YELLOW}$ip_count IPs${NC})"
                    else
                        echo_safe "${GREEN}$dom${NC} (${RED}Not resolved yet${NC})"
                    fi
                    dom_count=$((dom_count + 1))
                done < "$tmpdomain"
                if [[ $domain_count -gt 10 ]]; then
                    echo_safe "${YELLOW}... and $((domain_count - 10)) more domains${NC}"
                fi
                rm -f "$tmpdomain"
            elif [[ $domain_count -gt 500 ]]; then
                echo_safe ""
                echo_safe "${CYAN}${BOLD}BLOCKED DOMAINS (SUMMARY)${NC}"
                echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
                echo_safe "${YELLOW}Large domain list detected ($domain_count domains)${NC}"
                echo_safe "${YELLOW}For performance reasons, detailed domain info is hidden.${NC}"
                echo_safe "${YELLOW}Use export features to view complete domain list.${NC}"
            fi

            if [[ $custom_ip_count -gt 0 && $custom_ip_count -le 500 ]]; then
                echo_safe ""
                echo_safe "${CYAN}${BOLD}BLOCKED IPS (TOP 10 OF ${custom_ip_count})${NC}"
                echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
                get_custom_ips | head -10 | while read -r ip; do
                    echo_safe "${GREEN}$ip${NC}"
                done
                if [[ $custom_ip_count -gt 10 ]]; then
                    echo_safe "${YELLOW}... and $((custom_ip_count - 10)) more IPs${NC}"
                fi
            elif [[ $custom_ip_count -gt 500 ]]; then
                echo_safe ""
                echo_safe "${CYAN}${BOLD}BLOCKED IPS (SUMMARY)${NC}"
                echo_safe "${MAGENTA}───────────────────────────────────────${NC}"
                echo_safe "${YELLOW}Large IP list detected ($custom_ip_count IPs)${NC}"
                echo_safe "${YELLOW}For performance reasons, detailed IP info is hidden.${NC}"
                echo_safe "${YELLOW}Use export features to view complete IP list.${NC}"
            fi
            echo_safe ""
        } >> "$tmpout"
    ) &
    wait
    clear
    cat "$tmpout"
    rm -f "$tmpout"
    return 0
}

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
        --version)
            echo_safe "DNSniper version $VERSION"
            exit 0
            ;;
        --help)
            echo_safe "${BOLD}Usage: dnsniper [options]${NC}"
            echo_safe "${BOLD}Options:${NC}"
            echo_safe "  ${YELLOW}--run${NC}        Run DNSniper once (non-interactive)"
            echo_safe "  ${YELLOW}--update${NC}     Update default domains list"
            echo_safe "  ${YELLOW}--status${NC}     Display status"
            echo_safe "  ${YELLOW}--version${NC}    Show version"
            echo_safe "  ${YELLOW}--help${NC}       Show this help"
            echo_safe ""
            exit 0
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

main() {
    check_root
    check_dependencies
    ensure_environment
    initialize_logging
    if [[ $# -gt 0 ]]; then
        if handle_args "$@"; then
            exit 0
        fi
    fi
    display_status
    read -rp "Press Enter to return..."
}

main "$@"