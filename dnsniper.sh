#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 1.1.0

# Strict mode
set -eo pipefail

# ANSI color codes
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
BOLD='\e[1m'
NC='\e[0m'

# Paths
BASE_DIR="/etc/dnsniper"
DEFAULT_FILE="$BASE_DIR/domains-default.txt"
ADD_FILE="$BASE_DIR/domains-add.txt"
REMOVE_FILE="$BASE_DIR/domains-remove.txt"
CONFIG_FILE="$BASE_DIR/config.conf"
DB_FILE="$BASE_DIR/history.db"
BIN_CMD="/usr/local/bin/dnsniper"
LOG_FILE="$BASE_DIR/dnsniper.log"

# Defaults
DEFAULT_CRON="0 * * * * $BIN_CMD --run"
DEFAULT_MAX_IPS=10
DEFAULT_TIMEOUT=30
DEFAULT_UPDATE_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"

# Dependencies
DEPENDENCIES=(iptables ip6tables curl dig sqlite3 crontab)

# Export PATH to ensure commands are found
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

### Helper functions
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    if [[ "$level" == "ERROR" ]]; then
        enhanced_echo "${RED}Error:${NC} $message"
    elif [[ "$level" == "WARNING" ]]; then
        enhanced_echo "${YELLOW}Warning:${NC} $message"
    elif [[ "$level" == "INFO" ]]; then
        enhanced_echo "${BLUE}Info:${NC} $message"
    fi
}

enhanced_echo() {
    printf "%b\n" "$1"
}

escape_sql() {
    local input="$1"
    echo "${input//\'/\'\'}"
}

is_ipv6() {
    [[ "$1" =~ .*:.* ]]
}

exit_with_error() {
    log "ERROR" "$1"
    exit "${2:-1}"
}

### 1) Prepare environment: dirs, files, DB, cron & config
ensure_environment() {
    log "INFO" "Ensuring environment setup"
    mkdir -p "$BASE_DIR" || exit_with_error "Failed to create $BASE_DIR directory"
    
    # Create files if they don't exist
    for file in "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$CONFIG_FILE"; do
        [[ -f "$file" ]] || touch "$file" || exit_with_error "Failed to create $file"
    done
    
    # Set defaults in config file if they don't exist
    grep -q '^cron=' "$CONFIG_FILE" || echo "cron='$DEFAULT_CRON'" >> "$CONFIG_FILE"
    grep -q '^max_ips=' "$CONFIG_FILE" || echo "max_ips=$DEFAULT_MAX_IPS" >> "$CONFIG_FILE"
    grep -q '^timeout=' "$CONFIG_FILE" || echo "timeout=$DEFAULT_TIMEOUT" >> "$CONFIG_FILE"
    grep -q '^update_url=' "$CONFIG_FILE" || echo "update_url='$DEFAULT_UPDATE_URL'" >> "$CONFIG_FILE"
    
    # Initialize SQLite history DB
    if ! sqlite3 "$DB_FILE" <<SQL
CREATE TABLE IF NOT EXISTS history(
  domain TEXT,
  ips TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_domain ON history(domain);
CREATE INDEX IF NOT EXISTS idx_ts ON history(ts);
SQL
    then
        exit_with_error "Failed to initialize SQLite database"
    fi
    
    # Install or update cron job
    local cron_expr=$(grep '^cron=' "$CONFIG_FILE" | cut -d"'" -f2)
    if ! (crontab -l 2>/dev/null | grep -vF "$BIN_CMD" || true; echo "$cron_expr") | crontab -; then
        log "WARNING" "Failed to update crontab"
    else
        log "INFO" "Crontab updated successfully"
    fi
}

### 2) Privilege & dependencies check
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
        exit_with_error "Missing dependencies: ${missing[*]}\nInstall them using your package manager."
    fi
}

### 3) Fetch default domains list from GitHub
update_default() {
    log "INFO" "Fetching default domain list"
    
    local update_url=$(grep '^update_url=' "$CONFIG_FILE" | cut -d"'" -f2)
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" | cut -d= -f2)
    
    enhanced_echo "${BLUE}Fetching defaults from $update_url...${NC}"
    
    if curl -sfL --connect-timeout "$timeout" --max-time "$timeout" "$update_url" -o "$DEFAULT_FILE.tmp"; then
        # Verify the file has content
        if [[ -s "$DEFAULT_FILE.tmp" ]]; then
            mv "$DEFAULT_FILE.tmp" "$DEFAULT_FILE"
            enhanced_echo "${GREEN}Default domains updated successfully${NC}"
            log "INFO" "Default domains updated successfully"
        else
            rm -f "$DEFAULT_FILE.tmp"
            enhanced_echo "${RED}Downloaded file is empty${NC}"
            log "ERROR" "Downloaded file is empty"
        fi
    else
        rm -f "$DEFAULT_FILE.tmp" 2>/dev/null || true
        enhanced_echo "${RED}Failed to download default domains${NC}"
        log "ERROR" "Failed to download default domains from $update_url"
    fi
}

### 4) Merge default + added, minus removed
merge_domains() {
    log "INFO" "Merging domain lists"
    
    local merged_domains=()
    local d
    
    # Read from default file
    while IFS= read -r d || [[ -n "$d" ]]; do
        [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
        d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
        [[ -z "$d" ]] && continue
        merged_domains+=("$d")
    done < "$DEFAULT_FILE"
    
    # Read from add file
    while IFS= read -r d || [[ -n "$d" ]]; do
        [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
        d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
        [[ -z "$d" ]] && continue
        # Check if domain is already in merged_domains
        local found=0
        for existing in "${merged_domains[@]}"; do
            if [[ "$existing" == "$d" ]]; then
                found=1
                break
            fi
        done
        [[ $found -eq 0 ]] && merged_domains+=("$d")
    done < "$ADD_FILE"
    
    # Read from remove file for exclusions
    local remove_domains=()
    while IFS= read -r d || [[ -n "$d" ]]; do
        [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
        d=$(echo "$d" | tr -d '\r' | tr -d '\n' | xargs)
        [[ -z "$d" ]] && continue
        remove_domains+=("$d")
    done < "$REMOVE_FILE"
    
    # Filter out domains in remove list
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
    
    echo "${filtered_domains[@]}"
}

### 5) Record history and trim to max_ips
record_history() {
    local domain="$1"
    local ips_csv="$2"
    
    # Escape SQL special characters
    domain=$(escape_sql "$domain")
    ips_csv=$(escape_sql "$ips_csv")
    
    log "INFO" "Recording history for domain: $domain with IPs: $ips_csv"
    
    local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" | cut -d= -f2)
    
    # Validate max_ips is a number
    if ! [[ "$max_ips" =~ ^[0-9]+$ ]]; then
        log "WARNING" "Invalid max_ips value, using default: $DEFAULT_MAX_IPS"
        max_ips=$DEFAULT_MAX_IPS
    fi
    
    if ! sqlite3 "$DB_FILE" <<SQL
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
        log "ERROR" "Failed to record history for domain: $domain"
        return 1
    fi
    
    return 0
}

### 6) Detect CDN by comparing last two resolves
detect_cdn() {
    local domains=("$@")
    local warnings=()
    
    log "INFO" "Detecting CDN usage for ${#domains[@]} domains"
    
    for dom in "${domains[@]}"; do
        # Escape domain for SQL
        local esc_dom=$(escape_sql "$dom")
        
        # Get last two IP sets for this domain
        local rows
        rows=$(sqlite3 -separator '|' "$DB_FILE" \
            "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 2;")
        
        # Skip if we don't have enough history
        [[ $(wc -l <<<"$rows") -lt 2 ]] && continue
        
        # Parse rows into arrays
        local last prev
        IFS='|' read -r last prev <<< "$rows"
        
        # Convert CSV to arrays
        local last_ips prev_ips
        IFS=',' read -ra last_ips <<< "$last"
        IFS=',' read -ra prev_ips <<< "$prev"
        
        # Compare IP sets
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
        enhanced_echo "${YELLOW}${BOLD}[!] Domains may use CDN:${NC} ${warnings[*]}"
        log "WARNING" "Potential CDN domains detected: ${warnings[*]}"
    fi
}

### 7) Resolve domains and apply iptables/ip6tables rules
resolve_block() {
    enhanced_echo "${BLUE}Resolving domains...${NC}"
    log "INFO" "Starting domain resolution and blocking"
    
    # Get domains
    local merged_domains=($(merge_domains))
    local total=${#merged_domains[@]}
    
    enhanced_echo "${BLUE}Processing ${total} domains...${NC}"
    
    # Get timeout from config
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" | cut -d= -f2)
    if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
        log "WARNING" "Invalid timeout value, using default: $DEFAULT_TIMEOUT"
        timeout=$DEFAULT_TIMEOUT
    fi
    
    local success_count=0
    local ip_count=0
    
    for dom in "${merged_domains[@]}"; do
        enhanced_echo "${BOLD}Domain:${NC} ${GREEN}$dom${NC}"
        
        # Resolve IPv4 addresses with timeout
        local v4=()
        mapfile -t v4 < <(dig +short +time="$timeout" +tries=2 A "$dom" 2>/dev/null || echo "")
        
        # Resolve IPv6 addresses with timeout
        local v6=()
        mapfile -t v6 < <(dig +short +time="$timeout" +tries=2 AAAA "$dom" 2>/dev/null || echo "")
        
        # Combine and deduplicate IPs
        local all=("${v4[@]}" "${v6[@]}")
        local unique=()
        
        # Deduplicate and filter out invalid IPs
        for ip in "${all[@]}"; do
            [[ -z "$ip" ]] && continue
            
            # Skip if not a valid IP
            if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_ipv6 "$ip"; then
                log "WARNING" "Invalid IP format: $ip for domain $dom"
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
            enhanced_echo "  ${YELLOW}No IP addresses found${NC}"
            log "WARNING" "No IP addresses found for domain: $dom"
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
            local tbl="iptables"
            if is_ipv6 "$ip"; then
                tbl="ip6tables"
            fi
            
            if $tbl -C INPUT -s "$ip" -j DROP 2>/dev/null || $tbl -C INPUT -d "$ip" -j DROP 2>/dev/null; then
                enhanced_echo "  - ${YELLOW}Exists${NC}: $ip"
                log "INFO" "Rule already exists for IP: $ip"
            else
                # Block both incoming and outgoing
                if $tbl -A INPUT -s "$ip" -j DROP -m comment --comment "DNSniper: $dom" &&
                   $tbl -A INPUT -d "$ip" -j DROP -m comment --comment "DNSniper: $dom" &&
                   $tbl -A OUTPUT -d "$ip" -j DROP -m comment --comment "DNSniper: $dom"; then
                    enhanced_echo "  - ${RED}Blocked${NC}: $ip"
                    log "INFO" "Successfully blocked IP: $ip for domain: $dom"
                    ip_count=$((ip_count + 1))
                else
                    enhanced_echo "  - ${RED}Failed to block${NC}: $ip"
                    log "ERROR" "Failed to block IP: $ip for domain: $dom"
                fi
            fi
        done
        
        echo
    done
    
    enhanced_echo "${GREEN}Resolution complete. Processed $success_count/$total domains, blocked $ip_count new IPs.${NC}"
    log "INFO" "Resolution complete. Processed $success_count/$total domains, blocked $ip_count new IPs."
    
    # Run CDN detection
    detect_cdn "${merged_domains[@]}"
}

### 8) Interactive menu actions
set_schedule() {
    enhanced_echo "${BLUE}Current schedule:${NC} $(grep '^cron=' "$CONFIG_FILE" | cut -d"'" -f2)"
    
    read -rp "How often to run (in minutes, 0=disable): " m
    
    if [[ "$m" =~ ^[0-9]+$ ]]; then
        if [[ $m -eq 0 ]]; then
            # Disable cron
            sed -i "s|^cron=.*|cron='# DNSniper disabled'|" "$CONFIG_FILE"
            crontab -l | grep -vF "$BIN_CMD" | crontab -
            enhanced_echo "${YELLOW}Scheduled tasks disabled.${NC}"
            log "INFO" "Scheduled tasks disabled by user"
        else
            # Set cron to run every m minutes
            local expr
            if [[ $m -eq 60 ]]; then
                expr="0 * * * * $BIN_CMD --run"
            elif [[ $m -lt 60 ]]; then
                expr="*/$m * * * * $BIN_CMD --run"
            else
                local hours=$((m / 60))
                expr="0 */$hours * * * $BIN_CMD --run"
            fi
            
            sed -i "s|^cron=.*|cron='$expr'|" "$CONFIG_FILE"
            ensure_environment
            enhanced_echo "${GREEN}Scheduled to run every $m minutes.${NC}"
            log "INFO" "Schedule updated to run every $m minutes"
        fi
    else
        enhanced_echo "${RED}Invalid input. Please enter a number.${NC}"
    fi
}

set_max_ips() {
    local current=$(grep '^max_ips=' "$CONFIG_FILE" | cut -d= -f2)
    enhanced_echo "${BLUE}Current max IPs per domain:${NC} $current"
    
    read -rp "New max IPs per domain (5-50): " n
    
    if [[ "$n" =~ ^[0-9]+$ && $n -ge 5 && $n -le 50 ]]; then
        sed -i "s|^max_ips=.*|max_ips=$n|" "$CONFIG_FILE"
        enhanced_echo "${GREEN}Max IPs set to $n.${NC}"
        log "INFO" "Max IPs per domain updated to $n"
    else
        enhanced_echo "${RED}Invalid input. Please enter a number between 5 and 50.${NC}"
    fi
}

set_timeout() {
    local current=$(grep '^timeout=' "$CONFIG_FILE" | cut -d= -f2)
    enhanced_echo "${BLUE}Current timeout:${NC} $current seconds"
    
    read -rp "New timeout in seconds (5-120): " t
    
    if [[ "$t" =~ ^[0-9]+$ && $t -ge 5 && $t -le 120 ]]; then
        sed -i "s|^timeout=.*|timeout=$t|" "$CONFIG_FILE"
        enhanced_echo "${GREEN}Timeout set to $t seconds.${NC}"
        log "INFO" "Timeout updated to $t seconds"
    else
        enhanced_echo "${RED}Invalid input. Please enter a number between 5 and 120.${NC}"
    fi
}

set_update_url() {
    local current=$(grep '^update_url=' "$CONFIG_FILE" | cut -d"'" -f2)
    enhanced_echo "${BLUE}Current update URL:${NC} $current"
    
    read -rp "New URL (leave empty to reset to default): " u
    
    if [[ -z "$u" ]]; then
        u="$DEFAULT_UPDATE_URL"
    fi
    
    if [[ "$u" =~ ^https?:// ]]; then
        sed -i "s|^update_url=.*|update_url='$u'|" "$CONFIG_FILE"
        enhanced_echo "${GREEN}Update URL set to:${NC} $u"
        log "INFO" "Update URL changed to $u"
    else
        enhanced_echo "${RED}Invalid URL. Must start with http:// or https://  ${NC}"
    fi
}

add_domain() {
    read -rp "Domain to add: " d
    
    if [[ -z "$d" ]]; then
        enhanced_echo "${RED}Domain cannot be empty.${NC}"
        return
    fi
    
    # Validate domain format (basic check)
    if ! [[ "$d" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        enhanced_echo "${RED}Invalid domain format.${NC}"
        return
    fi
    
    # Check if domain is already in the add file
    if grep -Fxq "$d" "$ADD_FILE"; then
        enhanced_echo "${YELLOW}Domain already exists in add list.${NC}"
        return
    fi
    
    echo "$d" >> "$ADD_FILE"
    enhanced_echo "${GREEN}Added domain:${NC} $d"
    log "INFO" "Added domain to block list: $d"
    
    # Ask if user wants to block it immediately
    read -rp "Block this domain immediately? [y/N]: " block_now
    if [[ "$block_now" =~ ^[Yy] ]]; then
        enhanced_echo "${BLUE}Resolving and blocking $d...${NC}"
        
        local timeout=$(grep '^timeout=' "$CONFIG_FILE" | cut -d= -f2)
        if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
            timeout=$DEFAULT_TIMEOUT
        fi
        
        # Resolve IPv4 addresses with timeout
        local v4=()
        mapfile -t v4 < <(dig +short +time="$timeout" +tries=2 A "$d" 2>/dev/null || echo "")
        
        # Resolve IPv6 addresses with timeout
        local v6=()
        mapfile -t v6 < <(dig +short +time="$timeout" +tries=2 AAAA "$d" 2>/dev/null || echo "")
        
        # Combine and deduplicate IPs
        local all=("${v4[@]}" "${v6[@]}")
        local unique=()
        
        # Deduplicate and filter out invalid IPs
        for ip in "${all[@]}"; do
            [[ -z "$ip" ]] && continue
            
            # Skip if not a valid IP
            if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_ipv6 "$ip"; then
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
            enhanced_echo "  ${YELLOW}No IP addresses found${NC}"
            log "WARNING" "No IP addresses found for domain: $d"
            return
        fi
        
        # Convert array to CSV for storage
        local ips_csv=$(IFS=,; echo "${unique[*]}")
        
        # Record in history
        record_history "$d" "$ips_csv"
        
        # Block each IP
        for ip in "${unique[@]}"; do
            local tbl="iptables"
            if is_ipv6 "$ip"; then
                tbl="ip6tables"
            fi
            
            if $tbl -C INPUT -s "$ip" -j DROP 2>/dev/null || $tbl -C INPUT -d "$ip" -j DROP 2>/dev/null; then
                enhanced_echo "  - ${YELLOW}Exists${NC}: $ip"
            else
                # Block both incoming and outgoing
                if $tbl -A INPUT -s "$ip" -j DROP -m comment --comment "DNSniper: $d" &&
                   $tbl -A INPUT -d "$ip" -j DROP -m comment --comment "DNSniper: $d" &&
                   $tbl -A OUTPUT -d "$ip" -j DROP -m comment --comment "DNSniper: $d"; then
                    enhanced_echo "  - ${RED}Blocked${NC}: $ip"
                    log "INFO" "Immediately blocked IP: $ip for domain: $d"
                else
                    enhanced_echo "  - ${RED}Failed to block${NC}: $ip"
                    log "ERROR" "Failed to immediately block IP: $ip for domain: $d"
                fi
            fi
        done
    fi
}

remove_domain() {
    # Get all domains
    local merged_domains=($(merge_domains))
    
    # Show numbered list of domains
    enhanced_echo "${BLUE}Current domains:${NC}"
    local i=1
    for d in "${merged_domains[@]}"; do
        printf "%3d) %s\n" $i "$d"
        i=$((i+1))
    done
    
    read -rp "Enter domain number to remove, or enter domain name: " choice
    
    local domain_to_remove=""
    
    # Check if choice is a number
    if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le ${#merged_domains[@]} ]]; then
        domain_to_remove="${merged_domains[$((choice-1))]}"
    else
        domain_to_remove="$choice"
    fi
    
    if [[ -z "$domain_to_remove" ]]; then
        enhanced_echo "${RED}Invalid selection.${NC}"
        return
    fi
    
    # Add to remove file if not already there
    if ! grep -Fxq "$domain_to_remove" "$REMOVE_FILE"; then
        echo "$domain_to_remove" >> "$REMOVE_FILE"
        enhanced_echo "${GREEN}Removed domain:${NC} $domain_to_remove"
        log "INFO" "Added domain to remove list: $domain_to_remove"
        
        # Ask if user wants to unblock it immediately
        read -rp "Unblock this domain immediately? [y/N]: " unblock_now
        if [[ "$unblock_now" =~ ^[Yy] ]]; then
            enhanced_echo "${BLUE}Removing firewall rules for $domain_to_remove...${NC}"
            
            # Get IPs from history
            local esc_dom=$(escape_sql "$domain_to_remove")
            local ips
            ips=$(sqlite3 -separator ',' "$DB_FILE" \
                "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;")
            
            IFS=',' read -ra ip_list <<< "$ips"
            
            for ip in "${ip_list[@]}"; do
                local tbl="iptables"
                if is_ipv6 "$ip"; then
                    tbl="ip6tables"
                fi
                
                # Try to remove the rules
                $tbl -D INPUT -s "$ip" -j DROP -m comment --comment "DNSniper: $domain_to_remove" 2>/dev/null || true
                $tbl -D INPUT -d "$ip" -j DROP -m comment --comment "DNSniper: $domain_to_remove" 2>/dev/null || true
                $tbl -D OUTPUT -d "$ip" -j DROP -m comment --comment "DNSniper: $domain_to_remove" 2>/dev/null || true
                enhanced_echo "  - ${GREEN}Unblocked${NC}: $ip"
                log "INFO" "Removed firewall rules for IP: $ip of domain: $domain_to_remove"
            done
        fi
    else
        enhanced_echo "${YELLOW}Domain was already in the remove list.${NC}"
    fi
}

display_status() {
    local merged_domains=($(merge_domains))
    local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" | cut -d= -f2)
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" | cut -d= -f2)
    local sched=$(grep '^cron=' "$CONFIG_FILE" | cut -d"'" -f2)
    local update_url=$(grep '^update_url=' "$CONFIG_FILE" | cut -d"'" -f2)
    
    enhanced_echo "\n${BOLD}=== DNSniper Status ===${NC}"
    enhanced_echo "${BOLD}Blocked Domains:${NC} ${#merged_domains[@]}"
    
    if [[ ${#merged_domains[@]} -gt 0 ]]; then
        enhanced_echo "\n${BOLD}Domains:${NC}"
        for dom in "${merged_domains[@]}"; do
            # Get most recent IP list
            local esc_dom=$(escape_sql "$dom")
            local ips
            ips=$(sqlite3 -separator ',' "$DB_FILE" \
                "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;")
            
            if [[ -n "$ips" ]]; then
                local ip_count=$(echo "$ips" | tr -cd ',' | wc -c)
                ip_count=$((ip_count + 1))
                enhanced_echo "  - ${GREEN}$dom${NC} (${YELLOW}$ip_count IPs${NC})"
            else
                enhanced_echo "  - ${GREEN}$dom${NC} (${RED}No IPs resolved yet${NC})"
            fi
        done
    fi
    
    enhanced_echo "\n${BOLD}Configuration:${NC}"
    enhanced_echo "  - ${BLUE}Schedule:${NC} $sched"
    enhanced_echo "  - ${BLUE}Max IPs per domain:${NC} $max_ips"
    enhanced_echo "  - ${BLUE}Timeout:${NC} $timeout seconds"
    enhanced_echo "  - ${BLUE}Update URL:${NC} $update_url"
    
    # Count active rules
    local v4_rules
    v4_rules=$(iptables-save | grep -c 'DNSniper' || echo 0)
    local v6_rules
    v6_rules=$(ip6tables-save | grep -c 'DNSniper' || echo 0)
    
    enhanced_echo "\n${BOLD}Firewall Rules:${NC}"
    enhanced_echo "  - ${BLUE}IPv4 Rules:${NC} $v4_rules"
    enhanced_echo "  - ${BLUE}IPv6 Rules:${NC} $v6_rules"
    
    enhanced_echo "\n${BOLD}Last Run:${NC}"
    local last_run
    last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
    enhanced_echo "  - ${BLUE}$last_run${NC}\n"
}

view_logs() {
    if [[ ! -f "$LOG_FILE" ]]; then
        enhanced_echo "${YELLOW}No logs available yet.${NC}"
        return
    fi
    
    read -rp "Number of lines to view (default 20): " lines
    lines=${lines:-20}
    
    if [[ "$lines" =~ ^[0-9]+$ ]]; then
        enhanced_echo "${BOLD}Last $lines log entries:${NC}"
        tail -n "$lines" "$LOG_FILE"
    else
        enhanced_echo "${RED}Invalid input. Please enter a number.${NC}"
    fi
}

clear_rules() {
    read -rp "Clear all DNSniper firewall rules? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy] ]]; then
        enhanced_echo "${BLUE}Removing DNSniper rules...${NC}"
        
        # Save current rules without DNSniper entries
        if iptables-save | grep -v 'DNSniper' | iptables-restore && 
           ip6tables-save | grep -v 'DNSniper' | ip6tables-restore; then
            enhanced_echo "${GREEN}All DNSniper rules cleared.${NC}"
            log "INFO" "All firewall rules cleared"
        else
            enhanced_echo "${RED}Error clearing rules. Check iptables status.${NC}"
            log "ERROR" "Failed to clear firewall rules"
        fi
    else
        enhanced_echo "${YELLOW}Operation cancelled.${NC}"
    fi
}

export_data() {
    local export_file="$HOME/dnsniper_export_$(date +%Y%m%d).tar.gz"
    
    enhanced_echo "${BLUE}Exporting DNSniper data to $export_file...${NC}"
    
    if tar -czf "$export_file" -C "$(dirname "$BASE_DIR")" "$(basename "$BASE_DIR")"; then
        enhanced_echo "${GREEN}Data exported successfully to:${NC} $export_file"
        log "INFO" "Data exported to $export_file"
    else
        enhanced_echo "${RED}Failed to export data.${NC}"
        log "ERROR" "Failed to export data"
    fi
}

import_data() {
    read -rp "Enter path to import file (.tar.gz): " import_file
    
    if [[ ! -f "$import_file" ]]; then
        enhanced_echo "${RED}File not found: $import_file${NC}"
        return
    fi
    
    if [[ "$import_file" != *.tar.gz ]]; then
        enhanced_echo "${RED}Invalid file format. Must be a .tar.gz file.${NC}"
        return
    fi
    
    enhanced_echo "${YELLOW}Warning: This will overwrite current configuration.${NC}"
    read -rp "Continue? [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy] ]]; then
        enhanced_echo "${BLUE}Importing data...${NC}"
        
        # Create backup first
        local backup_file="$HOME/dnsniper_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$backup_file" -C "$(dirname "$BASE_DIR")" "$(basename "$BASE_DIR")" || true
        
        # Extract to temp and move
        local temp_dir=$(mktemp -d)
        if tar -xzf "$import_file" -C "$temp_dir"; then
            # Stop services temporarily
            crontab -l | grep -vF "$BIN_CMD" | crontab -
            
            # Move files
            cp -rf "$temp_dir/$(basename "$BASE_DIR")"/* "$BASE_DIR"/
            
            # Clean up
            rm -rf "$temp_dir"
            
            # Reinitialize
            ensure_environment
            
            enhanced_echo "${GREEN}Data imported successfully.${NC}"
            enhanced_echo "${GREEN}Backup saved to:${NC} $backup_file"
            log "INFO" "Data imported from $import_file"
        else
            enhanced_echo "${RED}Import failed.${NC}"
            log "ERROR" "Failed to import data from $import_file"
        fi
    else
        enhanced_echo "${YELLOW}Import cancelled.${NC}"
    fi
}

uninstall() {
    enhanced_echo "${RED}${BOLD}Warning: This will uninstall DNSniper completely.${NC}"
    read -rp "Are you sure you want to continue? [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy] ]]; then
        enhanced_echo "${BLUE}Uninstalling DNSniper...${NC}"
        
        # Ask about keeping rules
        read -rp "Keep existing firewall rules? [y/N]: " keep_rules
        
        if [[ ! "$keep_rules" =~ ^[Yy] ]]; then
            enhanced_echo "${BLUE}Removing firewall rules...${NC}"
            iptables-save | grep -v 'DNSniper' | iptables-restore
            ip6tables-save | grep -v 'DNSniper' | ip6tables-restore
        fi
        
        # Remove cron job
        crontab -l 2>/dev/null | grep -vF "$BIN_CMD" | crontab -
        
        # Ask about data backup
        read -rp "Create backup of configuration? [Y/n]: " backup
        
        if [[ ! "$backup" =~ ^[Nn] ]]; then
            local backup_file="$HOME/dnsniper_backup_uninstall_$(date +%Y%m%d).tar.gz"
            tar -czf "$backup_file" -C "$(dirname "$BASE_DIR")" "$(basename "$BASE_DIR")" || true
            enhanced_echo "${GREEN}Backup created at:${NC} $backup_file"
        fi
        
        # Remove binary and directories
        rm -f /usr/local/bin/dnsniper
        rm -rf "$BASE_DIR"
        
        enhanced_echo "${GREEN}DNSniper uninstalled successfully.${NC}"
        exit 0
    else
        enhanced_echo "${YELLOW}Uninstall cancelled.${NC}"
    fi
}

show_help() {
    enhanced_echo "\n${BOLD}=== DNSniper Help ===${NC}"
    enhanced_echo "${BOLD}Usage:${NC} dnsniper [OPTIONS]"
    enhanced_echo "\n${BOLD}Options:${NC}"
    enhanced_echo "  ${YELLOW}--run${NC}        Run DNSniper once (non-interactive)"
    enhanced_echo "  ${YELLOW}--update${NC}     Update default domains list"
    enhanced_echo "  ${YELLOW}--status${NC}     Show status"
    enhanced_echo "  ${YELLOW}--add${NC} DOMAIN Add a domain to the block list"
    enhanced_echo "  ${YELLOW}--remove${NC} DOMAIN Remove a domain from the block list"
    enhanced_echo "  ${YELLOW}--version${NC}    Show version"
    enhanced_echo "  ${YELLOW}--help${NC}       Show this help\n"
    enhanced_echo "${BOLD}Interactive Menu:${NC}"
    enhanced_echo "  Run without arguments to access the interactive menu"
    enhanced_echo "  which provides all functionality, configuration options,"
    enhanced_echo "  import/export, logs viewing, and maintenance.\n"
}

### 9) Main menu loop
main_menu() {
    while true; do
        enhanced_echo "\n${BOLD}=== DNSniper Menu ===${NC}"
        echo -e "${YELLOW}1)${NC} Run now        ${YELLOW}2)${NC} Update domains"
        echo -e "${YELLOW}3)${NC} Set schedule   ${YELLOW}4)${NC} Set max IPs"
        echo -e "${YELLOW}5)${NC} Set timeout    ${YELLOW}6)${NC} Set update URL"
        echo -e "${YELLOW}7)${NC} Add domain     ${YELLOW}8)${NC} Remove domain"
        echo -e "${YELLOW}9)${NC} Status         ${YELLOW}10)${NC} View logs"
        echo -e "${YELLOW}11)${NC} Clear rules   ${YELLOW}12)${NC} Export data"
        echo -e "${YELLOW}13)${NC} Import data   ${YELLOW}14)${NC} Uninstall"
        echo -e "${YELLOW}0)${NC} Exit"
        
        read -rp "Choice (0-14): " choice
        
        case "$choice" in
            1) resolve_block ;;
            2) update_default ;;
            3) set_schedule ;;
            4) set_max_ips ;;
            5) set_timeout ;;
            6) set_update_url ;;
            7) add_domain ;;
            8) remove_domain ;;
            9) display_status ;;
            10) view_logs ;;
            11) clear_rules ;;
            12) export_data ;;
            13) import_data ;;
            14) uninstall ;;
            0) enhanced_echo "${GREEN}Exiting...${NC}"; exit 0 ;;
            *) enhanced_echo "${RED}Invalid choice. Please select 0-14.${NC}" ;;
        esac
    done
}

### 10) Command line argument handling
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
        --add)
            if [[ -z "$2" ]]; then
                enhanced_echo "${RED}Error: Missing domain parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$ADD_FILE"
            enhanced_echo "${GREEN}Added domain:${NC} $2"
            log "INFO" "Added domain via CLI: $2"
            ;;
        --remove)
            if [[ -z "$2" ]]; then
                enhanced_echo "${RED}Error: Missing domain parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$REMOVE_FILE"
            enhanced_echo "${GREEN}Removed domain:${NC} $2"
            log "INFO" "Removed domain via CLI: $2"
            ;;
        --version)
            enhanced_echo "DNSniper v1.1.0"
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

### 11) Entrypoint
# Create log directory if needed
touch "$LOG_FILE" 2>/dev/null || mkdir -p "$(dirname "$LOG_FILE")" && touch "$LOG_FILE"

# Check if running as root
check_root

# Check dependencies
check_dependencies

# Initialize environment
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
    # When run via cron, we should run resolution
    resolve_block
fi

exit 0