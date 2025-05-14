#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 1.1.0

# ANSI color codes
RED='\e[31m' GREEN='\e[32m' YELLOW='\e[33m' BLUE='\e[34m' CYAN='\e[36m' BOLD='\e[1m' NC='\e[0m'

# Paths
BASE_DIR="/etc/dnsniper"
DEFAULT_FILE="$BASE_DIR/domains-default.txt"
ADD_FILE="$BASE_DIR/domains-add.txt"
REMOVE_FILE="$BASE_DIR/domains-remove.txt"
IP_ADD_FILE="$BASE_DIR/ips-add.txt"
IP_REMOVE_FILE="$BASE_DIR/ips-remove.txt"
CONFIG_FILE="$BASE_DIR/config.conf"
DB_FILE="$BASE_DIR/history.db"
BIN_CMD="/usr/local/bin/dnsniper"
LOG_FILE="$BASE_DIR/dnsniper.log"

# Defaults
DEFAULT_CRON="0 * * * * $BIN_CMD --run >/dev/null 2>&1"
DEFAULT_MAX_IPS=10
DEFAULT_TIMEOUT=30
DEFAULT_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"

# Version
VERSION="1.1.0"

# Dependencies
DEPENDENCIES=(iptables ip6tables curl dig sqlite3 crontab)

# Helper functions
log() {
    local level="$1" message="$2" verbose="${3:-}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${RED}Error:${NC} $message" >&2
    elif [[ "$level" == "WARNING" ]]; then
        echo -e "${YELLOW}Warning:${NC} $message" >&2
    elif [[ "$level" == "INFO" && "$verbose" == "verbose" ]]; then
        echo -e "${BLUE}Info:${NC} $message"
    fi
}

# Enhanced echo with error checking
echo_safe() {
    echo -e "$1"
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

### 1) Prepare environment: dirs, files, DB, cron
ensure_environment() {
    log "INFO" "Setting up environment" "verbose"
    
    # Create base directory if it doesn't exist
    if [[ ! -d "$BASE_DIR" ]]; then
        if ! mkdir -p "$BASE_DIR"; then
            exit_with_error "Cannot create directory $BASE_DIR"
        fi
    fi
    
    # Create required files if they don't exist
    for file in "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$IP_ADD_FILE" "$IP_REMOVE_FILE" "$CONFIG_FILE"; do
        if [[ ! -f "$file" ]]; then
            if ! touch "$file"; then
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
    
    # Initialize SQLite history DB
    if ! sqlite3 "$DB_FILE" <<SQL 2>/dev/null
CREATE TABLE IF NOT EXISTS history(
  domain TEXT,
  ips TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_domain ON history(domain);
CREATE INDEX IF NOT EXISTS idx_ts ON history(ts);
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
    
    if curl -sfL --connect-timeout "$timeout" --max-time "$timeout" "$update_url" -o "$DEFAULT_FILE.tmp"; then
        # Verify the downloaded file has content
        if [[ -s "$DEFAULT_FILE.tmp" ]]; then
            if ! mv "$DEFAULT_FILE.tmp" "$DEFAULT_FILE"; then
                rm -f "$DEFAULT_FILE.tmp" 2>/dev/null || true
                log "ERROR" "Failed to update default domains file"
                echo_safe "${RED}Failed to update default domains file${NC}"
                return 1
            fi
            log "INFO" "Default domains successfully updated" "verbose"
            echo_safe "${GREEN}Default domains successfully updated${NC}"
        else
            rm -f "$DEFAULT_FILE.tmp" 2>/dev/null || true
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

### 4) Merge default + added, minus removed domains
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
    
    for domain in "${filtered_domains[@]}"; do
        echo "$domain"
    done
}

### 5) Get list of custom IPs to block
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
    
    for ip in "${filtered_ips[@]}"; do
        echo "$ip"
    done
}

### 6) Record history and trim to max_ips
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

### 7) Detect CDN by comparing last two resolves
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

### 8) Block a specific IP with iptables/ip6tables
block_ip() {
    local ip="$1" comment="$2"
    local tbl="iptables"
    
    # Use correct iptables command based on IP type
    if is_ipv6 "$ip"; then
        tbl="ip6tables"
    fi
    
    # Block IP in INPUT chain (traffic to server)
    if ! $tbl -C INPUT -s "$ip" -j DROP -m comment --comment "$comment" 2>/dev/null; then
        if ! $tbl -A INPUT -s "$ip" -j DROP -m comment --comment "$comment"; then
            return 1
        fi
    fi
    
    # Block IP in INPUT chain (traffic to server, destination IP)
    if ! $tbl -C INPUT -d "$ip" -j DROP -m comment --comment "$comment" 2>/dev/null; then
        if ! $tbl -A INPUT -d "$ip" -j DROP -m comment --comment "$comment"; then
            return 1
        fi
    fi
    
    # Block IP in OUTPUT chain (traffic from server)
    if ! $tbl -C OUTPUT -d "$ip" -j DROP -m comment --comment "$comment" 2>/dev/null; then
        if ! $tbl -A OUTPUT -d "$ip" -j DROP -m comment --comment "$comment"; then
            return 1
        fi
    fi
    
    return 0
}

### 9) Unblock a specific IP from iptables/ip6tables
unblock_ip() {
    local ip="$1" comment_pattern="$2"
    local tbl="iptables"
    local success=0
    
    # Use correct iptables command based on IP type
    if is_ipv6 "$ip"; then
        tbl="ip6tables"
    fi
    
    # Try to remove rule from INPUT chain (source)
    if $tbl -C INPUT -s "$ip" -j DROP -m comment --comment "$comment_pattern" 2>/dev/null; then
        $tbl -D INPUT -s "$ip" -j DROP -m comment --comment "$comment_pattern"
        success=1
    fi
    
    # Try to remove rule from INPUT chain (destination)
    if $tbl -C INPUT -d "$ip" -j DROP -m comment --comment "$comment_pattern" 2>/dev/null; then
        $tbl -D INPUT -d "$ip" -j DROP -m comment --comment "$comment_pattern"
        success=1
    fi
    
    # Try to remove rule from OUTPUT chain
    if $tbl -C OUTPUT -d "$ip" -j DROP -m comment --comment "$comment_pattern" 2>/dev/null; then
        $tbl -D OUTPUT -d "$ip" -j DROP -m comment --comment "$comment_pattern"
        success=1
    fi
    
    return $((1 - success))
}

### 10) Resolve domains and apply iptables/ip6tables rules
resolve_block() {
    log "INFO" "Starting domain resolution and blocking" "verbose"
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
    
    return 0
}

### 11) Interactive menu functions

# --- Settings submenu ---
settings_menu() {
    while true; do
        clear
        echo_safe "${BLUE}${BOLD}===== DNSniper Settings =====${NC}\n"
        echo_safe "${YELLOW}1)${NC} Set Schedule"
        echo_safe "${YELLOW}2)${NC} Set Max IPs Per Domain"
        echo_safe "${YELLOW}3)${NC} Set Timeout"
        echo_safe "${YELLOW}4)${NC} Set Update URL"
        echo_safe "${YELLOW}0)${NC} Back to Main Menu"
        
        read -rp "Select (0-4): " choice
        
        case "$choice" in
            1) set_schedule ;;
            2) set_max_ips ;;
            3) set_timeout ;;
            4) set_update_url ;;
            0) return ;;
            *) echo_safe "${RED}Invalid selection. Please choose 0-4.${NC}" ;;
        esac
        
        read -rp "Press Enter to continue..."
    done
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

# --- Import/Export submenu ---
import_export_menu() {
    while true; do
        clear
        echo_safe "${BLUE}${BOLD}===== Import/Export =====${NC}\n"
        echo_safe "${YELLOW}1)${NC} Import Domains List"
        echo_safe "${YELLOW}2)${NC} Export Domains List"
        echo_safe "${YELLOW}3)${NC} Import IP List"
        echo_safe "${YELLOW}4)${NC} Export IP List"
        echo_safe "${YELLOW}5)${NC} Export All Config"
        echo_safe "${YELLOW}0)${NC} Back to Main Menu"
        
        read -rp "Select (0-5): " choice
        
        case "$choice" in
            1) import_domains ;;
            2) export_domains ;;
            3) import_ips ;;
            4) export_ips ;;
            5) export_all ;;
            0) return ;;
            *) echo_safe "${RED}Invalid selection. Please choose 0-5.${NC}" ;;
        esac
        
        read -rp "Press Enter to continue..."
    done
}

# Import domains
import_domains() {
    echo_safe "${BOLD}=== Import Domains List ===${NC}"
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
    echo_safe "${BOLD}=== Export Domains List ===${NC}"
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
    echo_safe "${BOLD}=== Import IP List ===${NC}"
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
    echo_safe "${BOLD}=== Export IP List ===${NC}"
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

# Export all config
export_all() {
    echo_safe "${BOLD}=== Export All Configuration ===${NC}"
    read -rp "Enter export directory: " dir
    
    if [[ -n "$dir" && -d "$dir" ]]; then
        # Export directory confirmed
        local export_dir="${dir%/}/dnsniper-export-$(date +%Y%m%d-%H%M%S)"
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
            iptables-save | grep 'DNSniper' > "$export_dir/iptables-rules.txt" 2>/dev/null || true
            ip6tables-save | grep 'DNSniper' >> "$export_dir/iptables-rules.txt" 2>/dev/null || true
        fi
        
        echo_safe "${GREEN}All configuration exported to $export_dir.${NC}"
        log "INFO" "All configuration exported to: $export_dir" "verbose"
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
    echo_safe "${BLUE}Current domains:${NC}"
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
        log "INFO" "Domain added to unblock list: $domain_to_unblock" "verbose"
        
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this domain immediately? [y/N]: " unblock_now
        if [[ "$unblock_now" =~ ^[Yy] ]]; then
            echo_safe "${BLUE}Removing firewall rules for $domain_to_unblock...${NC}"
            
            # Get IPs from history
            local esc_dom=$(sql_escape "$domain_to_unblock")
            local ips
            ips=$(sqlite3 -separator ',' "$DB_FILE" \
                "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
            
            if [[ -n "$ips" ]]; then
                IFS=',' read -ra ip_list <<< "$ips"
                
                for ip in "${ip_list[@]}"; do
                    if unblock_ip "$ip" "DNSniper: $domain_to_unblock"; then
                        echo_safe "  - ${GREEN}Unblocked${NC}: $ip"
                    fi
                done
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
    echo_safe "${BLUE}Current custom IPs:${NC}"
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
        log "INFO" "IP added to unblock list: $ip_to_unblock" "verbose"
        
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this IP immediately? [y/N]: " unblock_now
        if [[ "$unblock_now" =~ ^[Yy] ]]; then
            if unblock_ip "$ip_to_unblock" "DNSniper: custom"; then
                echo_safe "${GREEN}Successfully unblocked IP:${NC} $ip_to_unblock"
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
    local domains=()
    mapfile -t domains < <(merge_domains)
    
    local custom_ips=()
    mapfile -t custom_ips < <(get_custom_ips)
    
    local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local sched=$(grep '^cron=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    local update_url=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    
    if [[ -z "$max_ips" || ! "$max_ips" =~ ^[0-9]+$ ]]; then
        max_ips=$DEFAULT_MAX_IPS
    fi
    
    if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]]; then
        timeout=$DEFAULT_TIMEOUT
    fi
    
    if [[ -z "$update_url" ]]; then
        update_url=$DEFAULT_URL
    fi
    
    echo_safe "${BLUE}${BOLD}====== DNSniper Status ======${NC}\n"
    
    echo_safe "${BOLD}Blocked Domains:${NC} ${#domains[@]}"
    echo_safe "${BOLD}Blocked Custom IPs:${NC} ${#custom_ips[@]}"
    
    if [[ ${#domains[@]} -gt 0 ]]; then
        echo_safe "\n${BOLD}Domains:${NC}"
        for dom in "${domains[@]}"; do
            # Get most recent IP list
            local esc_dom=$(sql_escape "$dom")
            local ips
            ips=$(sqlite3 -separator ',' "$DB_FILE" \
                "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
            
            if [[ -n "$ips" ]]; then
                local ip_count=$(echo "$ips" | tr -cd ',' | wc -c)
                ip_count=$((ip_count + 1))
                echo_safe "  - ${GREEN}$dom${NC} (${YELLOW}$ip_count IPs${NC})"
            else
                echo_safe "  - ${GREEN}$dom${NC} (${RED}No IPs resolved yet${NC})"
            fi
        done
    fi
    
    if [[ ${#custom_ips[@]} -gt 0 ]]; then
        echo_safe "\n${BOLD}Custom IPs:${NC}"
        local ip_count=0
        for ip in "${custom_ips[@]}"; do
            if [ $ip_count -lt 10 ]; then
                echo_safe "  - ${GREEN}$ip${NC}"
                ip_count=$((ip_count + 1))
            else
                echo_safe "  - ${YELLOW}...and $((${#custom_ips[@]} - 10)) more${NC}"
                break
            fi
        done
    fi
    
    echo_safe "\n${BOLD}Configuration:${NC}"
    echo_safe "  - ${BLUE}Schedule:${NC} $sched"
    echo_safe "  - ${BLUE}Max IPs per domain:${NC} $max_ips"
    echo_safe "  - ${BLUE}Timeout:${NC} $timeout seconds"
    echo_safe "  - ${BLUE}Update URL:${NC} $update_url"
    
    # Count active rules
    local v4_rules=0
    local v6_rules=0
    
    if command -v iptables-save &>/dev/null; then
        v4_rules=$(iptables-save 2>/dev/null | grep -c 'DNSniper' || echo 0)
        v6_rules=$(ip6tables-save 2>/dev/null | grep -c 'DNSniper' || echo 0)
    fi
    
    echo_safe "\n${BOLD}Firewall Rules:${NC}"
    echo_safe "  - ${BLUE}IPv4 Rules:${NC} $v4_rules"
    echo_safe "  - ${BLUE}IPv6 Rules:${NC} $v6_rules"
    
    echo_safe "\n${BOLD}Last Run:${NC}"
    local last_run
    if [[ -f "$LOG_FILE" ]]; then
        last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
    else
        last_run="Never"
    fi
    echo_safe "  - ${BLUE}$last_run${NC}\n"
    
    return 0
}

# Clear rules
clear_rules() {
    echo_safe "${BOLD}=== Clear Firewall Rules ===${NC}"
    read -rp "Clear all DNSniper firewall rules? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy] ]]; then
        echo_safe "${BLUE}Removing DNSniper rules...${NC}"
        
        local success=0
        # Save current rules without DNSniper entries
        if iptables-save 2>/dev/null | grep -v 'DNSniper' | iptables-restore 2>/dev/null && 
           ip6tables-save 2>/dev/null | grep -v 'DNSniper' | ip6tables-restore 2>/dev/null; then
            echo_safe "${GREEN}All DNSniper rules cleared.${NC}"
            log "INFO" "All firewall rules cleared" "verbose"
            success=1
        fi
        
        if [[ $success -eq 0 ]]; then
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
            iptables-save 2>/dev/null | grep -v 'DNSniper' | iptables-restore 2>/dev/null || true
            ip6tables-save 2>/dev/null | grep -v 'DNSniper' | ip6tables-restore 2>/dev/null || true
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
    echo_safe "\n${BOLD}=== DNSniper v$VERSION Help ===${NC}"
    echo_safe "${BOLD}Usage:${NC} dnsniper [options]"
    echo_safe "\n${BOLD}Options:${NC}"
    echo_safe "  ${YELLOW}--run${NC}        Run DNSniper once (non-interactive)"
    echo_safe "  ${YELLOW}--update${NC}     Update default domains list"
    echo_safe "  ${YELLOW}--status${NC}     Display status"
    echo_safe "  ${YELLOW}--block${NC} DOMAIN Add a domain to block list"
    echo_safe "  ${YELLOW}--unblock${NC} DOMAIN Remove a domain from block list"
    echo_safe "  ${YELLOW}--block-ip${NC} IP Add an IP to block list"
    echo_safe "  ${YELLOW}--unblock-ip${NC} IP Remove an IP from block list"
    echo_safe "  ${YELLOW}--version${NC}    Show version"
    echo_safe "  ${YELLOW}--help${NC}       Show this help\n"
    echo_safe "${BOLD}Interactive Menu:${NC}"
    echo_safe "  Run without arguments to access the interactive menu"
    echo_safe "  which provides all functionality, configuration options,"
    echo_safe "  and maintenance features.\n"
    
    return 0
}

### 12) Main menu loop
main_menu() {
    while true; do
        clear
        echo_safe "${BLUE}${BOLD}====== DNSniper v$VERSION ======${NC}"
        echo_safe "${YELLOW}1)${NC} Run Now         ${YELLOW}2)${NC} Status"
        echo_safe "${YELLOW}3)${NC} Block Domain    ${YELLOW}4)${NC} Unblock Domain"
        echo_safe "${YELLOW}5)${NC} Block IP        ${YELLOW}6)${NC} Unblock IP"
        echo_safe "${YELLOW}7)${NC} Settings        ${YELLOW}8)${NC} Import/Export"
        echo_safe "${YELLOW}9)${NC} Update Lists    ${YELLOW}0)${NC} Exit"
        echo_safe "${YELLOW}C)${NC} Clear Rules     ${YELLOW}U)${NC} Uninstall"
        
        read -rp "Select: " choice
        
        case "$choice" in
            1) clear; resolve_block; read -rp "Press Enter to continue..." ;;
            2) display_status; read -rp "Press Enter to continue..." ;;
            3) clear; block_domain; read -rp "Press Enter to continue..." ;;
            4) clear; unblock_domain; read -rp "Press Enter to continue..." ;;
            5) clear; block_custom_ip; read -rp "Press Enter to continue..." ;;
            6) clear; unblock_custom_ip; read -rp "Press Enter to continue..." ;;
            7) settings_menu ;;
            8) import_export_menu ;;
            9) clear; update_default; read -rp "Press Enter to continue..." ;;
            0) echo_safe "${GREEN}Exiting...${NC}"; exit 0 ;;
            [Cc]) clear; clear_rules; read -rp "Press Enter to continue..." ;;
            [Uu]) clear; uninstall ;;
            *) echo_safe "${RED}Invalid selection. Please choose from the menu.${NC}"; sleep 1 ;;
        esac
    done
}

### 13) Command line arguments handling
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

### 14) Entry point
main() {
    # Create log directory if needed
    if [[ ! -d "$(dirname "$LOG_FILE")" ]]; then
        mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    fi
    touch "$LOG_FILE" 2>/dev/null || true
    
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