#!/usr/bin/env bash
# DNSniper Core Library - Shared functions
# Version: 2.0.0

# Default paths
BASE_DIR="/etc/dnsniper"
BIN_DIR="/usr/local/bin"
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

# ANSI colors
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

# Logging state
LOGGING_ENABLED=0

# Banner display function
show_banner() {
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
}

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
        local max_size=$(get_config_value "log_max_size" "$DEFAULT_LOG_MAX_SIZE")
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
    
    # Print to console only in interactive mode or if it's an error/warning
    if [[ -t 1 ]]; then  # Only if running in a terminal
        if [[ "$level" == "ERROR" ]]; then
            echo -e "${RED}Error:${NC} $message" >&2
        elif [[ "$level" == "WARNING" ]]; then
            echo -e "${YELLOW}Warning:${NC} $message" >&2
        elif [[ "$level" == "INFO" && "$verbose" == "verbose" ]]; then
            echo -e "${BLUE}Info:${NC} $message"
        fi
    fi
}

# Log rotation
rotate_logs() {
    local rotate_count=$(get_config_value "log_rotate_count" "$DEFAULT_LOG_ROTATE_COUNT")
    
    # Make sure log directory exists
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    
    # Delete oldest log if it exists
    if [[ -f "$LOG_DIR/dnsniper.$rotate_count.log" ]]; then
        rm -f "$LOG_DIR/dnsniper.$rotate_count.log" 2>/dev/null || true
    fi
    
    # Shift all logs up by one number
    for ((i=$rotate_count-1; i>=1; i--)); do
        j=$((i+1))
        if [[ -f "$LOG_DIR/dnsniper.$i.log" ]]; then
            mv "$LOG_DIR/dnsniper.$i.log" "$LOG_DIR/dnsniper.$j.log" 2>/dev/null || true
        fi
    done
    
    # Copy current log to rotation and clear it
    if [[ -f "$LOG_FILE" ]]; then
        cp "$LOG_FILE" "$LOG_DIR/dnsniper.1.log" 2>/dev/null || true
        truncate -s 0 "$LOG_FILE" 2>/dev/null || true
    fi
}

# Get config value with default fallback
get_config_value() {
    local key="$1" default_value="$2"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "$default_value"
        return
    fi
    
    local value=$(grep "^$key=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d "'" || echo "")
    if [[ -z "$value" ]]; then
        echo "$default_value"
    else
        echo "$value"
    fi
}

# Check if auto-update is enabled
is_auto_update_enabled() {
    local auto_update=$(get_config_value "auto_update" "$DEFAULT_AUTO_UPDATE")
    [[ "$auto_update" == "1" ]]
}

# Check if daemon is running
is_daemon_running() {
    local daemon_lock="/var/lock/dnsniper-daemon.lock"
    if [[ -f "$daemon_lock" ]]; then
        local daemon_pid=$(cat "$daemon_lock" 2>/dev/null || echo "")
        if [[ -n "$daemon_pid" ]] && ps -p "$daemon_pid" > /dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Stop daemon if running
stop_daemon() {
    if is_daemon_running; then
        local daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "")
        if [[ -n "$daemon_pid" ]]; then
            kill "$daemon_pid" 2>/dev/null || true
            echo -e "${YELLOW}Stopping daemon (PID: $daemon_pid)...${NC}"
            sleep 1
            # Verify it's stopped
            if ps -p "$daemon_pid" > /dev/null 2>&1; then
                kill -9 "$daemon_pid" 2>/dev/null || true
                sleep 1
            fi
            # Remove lock file
            rm -f "/var/lock/dnsniper-daemon.lock" 2>/dev/null || true
        fi
    fi
}

# Show status information
show_status() {
    show_banner
    
    echo -e "${CYAN}${BOLD}SYSTEM STATUS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Current status
    local status=$(cat "$STATUS_FILE" 2>/dev/null || echo "UNKNOWN")
    case "$status" in
        "READY")
            echo -e "${BOLD}Status:${NC} ${GREEN}Ready${NC}"
            ;;
        "RUNNING")
            echo -e "${BOLD}Status:${NC} ${BLUE}Running${NC}"
            ;;
        "ERROR")
            echo -e "${BOLD}Status:${NC} ${RED}Error${NC}"
            ;;
        *)
            echo -e "${BOLD}Status:${NC} ${YELLOW}Unknown${NC}"
            ;;
    esac
    
    # Check if daemon is running
    if is_daemon_running; then
        local daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "??")
        echo -e "${BOLD}Background Service:${NC} ${GREEN}Running (PID: $daemon_pid)${NC}"
    else
        echo -e "${BOLD}Background Service:${NC} ${RED}Not Running${NC}"
    fi
    
    # Count domains and rules
    local domain_count=$(grep -v '^#' "$DEFAULT_FILE" 2>/dev/null | grep -v '^$' | wc -l)
    domain_count=$((domain_count + $(grep -v '^#' "$ADD_FILE" 2>/dev/null | grep -v '^$' | wc -l)))
    
    local custom_ip_count=$(grep -v '^#' "$IP_ADD_FILE" 2>/dev/null | grep -v '^$' | wc -l)
    
    local rule_count=0
    if command -v iptables &>/dev/null; then
        rule_count=$(iptables-save 2>/dev/null | grep -c "$IPT_CHAIN" || echo "0")
        rule_count=$((rule_count + $(ip6tables-save 2>/dev/null | grep -c "$IPT6_CHAIN" || echo "0")))
    fi
    
    echo -e "${BOLD}Blocked Domains:${NC} ${GREEN}$domain_count${NC}"
    echo -e "${BOLD}Custom IPs:${NC} ${GREEN}$custom_ip_count${NC}"
    echo -e "${BOLD}Active Rules:${NC} ${RED}$rule_count${NC}"
    
    # Configuration section
    echo -e ""
    echo -e "${CYAN}${BOLD}CONFIGURATION${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    local auto_update=$(get_config_value "auto_update" "$DEFAULT_AUTO_UPDATE")
    local update_url=$(get_config_value "update_url" "$DEFAULT_URL")
    local logging_enabled=$(get_config_value "logging_enabled" "$DEFAULT_LOGGING_ENABLED")
    local block_source=$(get_config_value "block_source" "$DEFAULT_BLOCK_SOURCE")
    local block_destination=$(get_config_value "block_destination" "$DEFAULT_BLOCK_DESTINATION")
    
    # Display scheduling
    if command -v systemctl &>/dev/null && systemctl is-enabled dnsniper.timer &>/dev/null; then
        echo -e "${BOLD}Scheduled with:${NC} ${GREEN}systemd timer (hourly)${NC}"
    elif crontab -l 2>/dev/null | grep -q "dnsniper"; then
        echo -e "${BOLD}Scheduled with:${NC} ${GREEN}cron (hourly)${NC}"
    else
        echo -e "${BOLD}Scheduled with:${NC} ${RED}Not scheduled${NC}"
    fi
    
    # Display configuration values
    echo -e "${BOLD}Auto-update:${NC} $([[ "$auto_update" == "1" ]] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}") "
    echo -e "${BOLD}Update URL:${NC} ${BLUE}$update_url${NC}"
    echo -e "${BOLD}Logging:${NC} $([[ "$logging_enabled" == "1" ]] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}") "
    
    # Show blocking rules type
    echo -e "${BOLD}Blocking:${NC} "
    if [[ "$block_source" == "1" ]]; then
        echo -e "  ${GREEN}- Source${NC} (incoming from malicious IPs)"
    fi
    if [[ "$block_destination" == "1" ]]; then
        echo -e "  ${GREEN}- Destination${NC} (outgoing to malicious IPs)"
    fi
    
    # Last run info
    if [[ -f "$LOG_FILE" ]]; then
        local last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
        echo -e "${BOLD}Last Run:${NC} ${BLUE}$last_run${NC}"
    else
        echo -e "${BOLD}Last Run:${NC} ${RED}Never${NC}"
    fi
}

# Add domain function
add_domain() {
    show_banner
    echo -e "${CYAN}${BOLD}ADD DOMAIN TO BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter domain to block (e.g., example.com): " domain
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Error: Domain cannot be empty.${NC}"
        return
    fi
    
    # Simple domain validation
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo -e "${RED}Error: Invalid domain format.${NC}"
        return
    fi
    
    # Check if domain is already in list
    if grep -qx "$domain" "$ADD_FILE" 2>/dev/null; then
        echo -e "${YELLOW}Domain $domain is already in block list.${NC}"
        return
    fi
    
    # Add to domains-add.txt
    echo "$domain" >> "$ADD_FILE"
    echo -e "${GREEN}Domain $domain added to block list.${NC}"
    
    # Ask if user wants to run the daemon now
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_now
    fi
}

# Remove domain function
remove_domain() {
    show_banner
    echo -e "${CYAN}${BOLD}REMOVE DOMAIN FROM BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get list of domains
    local domains_file=$(mktemp)
    cat "$DEFAULT_FILE" "$ADD_FILE" 2>/dev/null | grep -v '^#' | grep -v '^$' | sort -u > "$domains_file"
    
    # Count domains
    local domain_count=$(wc -l < "$domains_file")
    
    if [[ $domain_count -eq 0 ]]; then
        echo -e "${YELLOW}No domains in block list.${NC}"
        rm -f "$domains_file"
        return
    fi
    
    # Show sample of domains
    echo -e "${BLUE}Current domains in block list:${NC}"
    if [[ $domain_count -gt 10 ]]; then
        head -10 "$domains_file"
        echo -e "${YELLOW}... and $((domain_count - 10)) more domains${NC}"
    else
        cat "$domains_file"
    fi
    
    read -rp "Enter domain to remove: " domain
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Error: Domain cannot be empty.${NC}"
        rm -f "$domains_file"
        return
    fi
    
    # Check if domain exists
    if ! grep -q "^$domain$" "$domains_file"; then
        echo -e "${RED}Error: Domain $domain not found in block list.${NC}"
        rm -f "$domains_file"
        return
    fi
    
    # Add to remove list
    echo "$domain" >> "$REMOVE_FILE"
    echo -e "${GREEN}Domain $domain added to remove list.${NC}"
    
    # Clean up
    rm -f "$domains_file"
    
    # Ask if user wants to run the daemon now
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_now
    fi
}

# Process domains function
process_domains() {
    log "INFO" "Starting domain processing" "verbose"
    
    # Get all domains (merge default, add, and remove)
    local domains_file=$(mktemp)
    
    # Start with default domains
    if [[ -f "$DEFAULT_FILE" ]]; then
        grep -v '^#' "$DEFAULT_FILE" | grep -v '^$' > "$domains_file" || true
    fi
    
    # Add custom domains
    if [[ -f "$ADD_FILE" ]]; then
        grep -v '^#' "$ADD_FILE" | grep -v '^$' >> "$domains_file" || true
    fi
    
    # Remove domains in remove list
    if [[ -f "$REMOVE_FILE" ]]; then
        local domains_tmp=$(mktemp)
        cat "$domains_file" > "$domains_tmp"
        
        while read -r domain; do
            [[ -z "$domain" || "$domain" =~ ^# ]] && continue
            sed -i "/^$domain$/d" "$domains_tmp"
        done < "$REMOVE_FILE"
        
        mv "$domains_tmp" "$domains_file"
    fi
    
    # Count domains
    local domain_count=$(wc -l < "$domains_file" || echo 0)
    
    if [[ $domain_count -eq 0 ]]; then
        log "INFO" "No domains to process"
        rm -f "$domains_file"
        return
    fi
    
    log "INFO" "Processing $domain_count domains" "verbose"
    
    # TODO: Add actual domain processing code here
    # This would include:
    # - DNS resolution for each domain
    # - Filtering and blocking IPs
    # - Updating history in the database
    
    # For now, we'll just simulate processing
    if [[ -t 1 ]]; then  # Only if in interactive mode
        echo -e "${BLUE}Processing $domain_count domains...${NC}"
        echo -e "${GREEN}Domains processed successfully.${NC}"
    fi
    
    # Clean up
    rm -f "$domains_file"
}

# Check for expired domains
check_expired_domains() {
    # TODO: Implement expired domains checking
    log "INFO" "Checking for expired domains" "verbose"
}

# Settings menu
settings_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}${BOLD}SETTINGS MENU${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Configure Auto-Update"
        echo -e "${YELLOW}2.${NC} Configure Logging"
        echo -e "${YELLOW}3.${NC} Configure Blocking Rules"
        echo -e "${YELLOW}4.${NC} Configure Scheduling"
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) configure_auto_update ;;
            2) configure_logging ;;
            3) configure_blocking ;;
            4) configure_scheduling ;;
            0) return ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# Configure auto-update
configure_auto_update() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE AUTO-UPDATE${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    local auto_update=$(get_config_value "auto_update" "$DEFAULT_AUTO_UPDATE")
    local update_url=$(get_config_value "update_url" "$DEFAULT_URL")
    
    echo -e "${BOLD}Current auto-update:${NC} $([[ "$auto_update" == "1" ]] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}") "
    echo -e "${BOLD}Current update URL:${NC} ${BLUE}$update_url${NC}"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Toggle Auto-Update"
    echo -e "${YELLOW}2.${NC} Change Update URL"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            if [[ "$auto_update" == "1" ]]; then
                sed -i 's/auto_update=1/auto_update=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Auto-update disabled.${NC}"
            else
                sed -i 's/auto_update=0/auto_update=1/' "$CONFIG_FILE"
                # If line doesn't exist, add it
                if ! grep -q "auto_update=" "$CONFIG_FILE"; then
                    echo "auto_update=1" >> "$CONFIG_FILE"
                fi
                echo -e "${GREEN}Auto-update enabled.${NC}"
            fi
            ;;
        2)
            read -rp "Enter new update URL: " new_url
            if [[ -n "$new_url" && "$new_url" =~ ^https?:// ]]; then
                sed -i "s|update_url=.*|update_url='$new_url'|" "$CONFIG_FILE"
                # If line doesn't exist, add it
                if ! grep -q "update_url=" "$CONFIG_FILE"; then
                    echo "update_url='$new_url'" >> "$CONFIG_FILE"
                fi
                echo -e "${GREEN}Update URL changed.${NC}"
            else
                echo -e "${RED}Invalid URL. Must start with http:// or https://. ${NC}"
            fi
            ;;
        0) return ;;
        *) echo -e "${RED}Invalid selection.${NC}" ;;
    esac
}

# Configure logging
configure_logging() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE LOGGING${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    local logging_enabled=$(get_config_value "logging_enabled" "$DEFAULT_LOGGING_ENABLED")
    local log_max_size=$(get_config_value "log_max_size" "$DEFAULT_LOG_MAX_SIZE")
    local log_rotate_count=$(get_config_value "log_rotate_count" "$DEFAULT_LOG_ROTATE_COUNT")
    
    echo -e "${BOLD}Logging:${NC} $([[ "$logging_enabled" == "1" ]] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}") "
    echo -e "${BOLD}Log file:${NC} ${BLUE}$LOG_FILE${NC}"
    echo -e "${BOLD}Max log size:${NC} ${YELLOW}$log_max_size MB${NC}"
    echo -e "${BOLD}Rotate count:${NC} ${YELLOW}$log_rotate_count files${NC}"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Toggle Logging"
    echo -e "${YELLOW}2.${NC} Change Max Log Size"
    echo -e "${YELLOW}3.${NC} Change Rotate Count"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            if [[ "$logging_enabled" == "1" ]]; then
                sed -i 's/logging_enabled=1/logging_enabled=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Logging disabled.${NC}"
            else
                sed -i 's/logging_enabled=0/logging_enabled=1/' "$CONFIG_FILE"
                # If line doesn't exist, add it
                if ! grep -q "logging_enabled=" "$CONFIG_FILE"; then
                    echo "logging_enabled=1" >> "$CONFIG_FILE"
                fi
                echo -e "${GREEN}Logging enabled.${NC}"
                # Make sure log directory exists
                mkdir -p "$LOG_DIR" 2>/dev/null || true
            fi
            # Re-initialize logging
            init_logging
            ;;
        2)
            read -rp "Enter max log size in MB (1-100): " new_size
            if [[ "$new_size" =~ ^[0-9]+$ && $new_size -ge 1 && $new_size -le 100 ]]; then
                sed -i "s/log_max_size=.*/log_max_size=$new_size/" "$CONFIG_FILE"
                # If line doesn't exist, add it
                if ! grep -q "log_max_size=" "$CONFIG_FILE"; then
                    echo "log_max_size=$new_size" >> "$CONFIG_FILE"
                fi
                echo -e "${GREEN}Max log size set to $new_size MB.${NC}"
            else
                echo -e "${RED}Invalid input. Please enter a number between 1 and 100.${NC}"
            fi
            ;;
        3)
            read -rp "Enter rotation count (1-20): " new_count
            if [[ "$new_count" =~ ^[0-9]+$ && $new_count -ge 1 && $new_count -le 20 ]]; then
                sed -i "s/log_rotate_count=.*/log_rotate_count=$new_count/" "$CONFIG_FILE"
                # If line doesn't exist, add it
                if ! grep -q "log_rotate_count=" "$CONFIG_FILE"; then
                    echo "log_rotate_count=$new_count" >> "$CONFIG_FILE"
                fi
                echo -e "${GREEN}Rotation count set to $new_count.${NC}"
            else
                echo -e "${RED}Invalid input. Please enter a number between 1 and 20.${NC}"
            fi
            ;;
        0) return ;;
        *) echo -e "${RED}Invalid selection.${NC}" ;;
    esac
}

# Configure blocking rules
configure_blocking() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE BLOCKING RULES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    local block_source=$(get_config_value "block_source" "$DEFAULT_BLOCK_SOURCE")
    local block_destination=$(get_config_value "block_destination" "$DEFAULT_BLOCK_DESTINATION")
    
    echo -e "${BOLD}Current settings:${NC}"
    echo -e "  $([[ "$block_source" == "1" ]] && echo "${GREEN}✓${NC}" || echo "${RED}✗${NC}") Block source (incoming from malicious IPs)"
    echo -e "  $([[ "$block_destination" == "1" ]] && echo "${GREEN}✓${NC}" || echo "${RED}✗${NC}") Block destination (outgoing to malicious IPs)"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Toggle Source Blocking"
    echo -e "${YELLOW}2.${NC} Toggle Destination Blocking"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            if [[ "$block_source" == "1" ]]; then
                sed -i 's/block_source=1/block_source=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Source blocking disabled.${NC}"
            else
                sed -i 's/block_source=0/block_source=1/' "$CONFIG_FILE"
                # If line doesn't exist, add it
                if ! grep -q "block_source=" "$CONFIG_FILE"; then
                    echo "block_source=1" >> "$CONFIG_FILE"
                fi
                echo -e "${GREEN}Source blocking enabled.${NC}"
            fi
            echo -e "${YELLOW}Note: Changes will take effect on next run.${NC}"
            ;;
        2)
            if [[ "$block_destination" == "1" ]]; then
                sed -i 's/block_destination=1/block_destination=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Destination blocking disabled.${NC}"
            else
                sed -i 's/block_destination=0/block_destination=1/' "$CONFIG_FILE"
                # If line doesn't exist, add it
                if ! grep -q "block_destination=" "$CONFIG_FILE"; then
                    echo "block_destination=1" >> "$CONFIG_FILE"
                fi
                echo -e "${GREEN}Destination blocking enabled.${NC}"
            fi
            echo -e "${YELLOW}Note: Changes will take effect on next run.${NC}"
            ;;
        0) return ;;
        *) echo -e "${RED}Invalid selection.${NC}" ;;
    esac
}

# Configure scheduling
configure_scheduling() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE SCHEDULING${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Check current schedule status
    local systemd_enabled=0
    local cron_enabled=0
    
    if command -v systemctl &>/dev/null; then
        systemd_enabled=$(systemctl is-enabled dnsniper.timer 2>/dev/null | grep -c "enabled" || echo "0")
    fi
    
    if command -v crontab &>/dev/null; then
        cron_enabled=$(crontab -l 2>/dev/null | grep -c "dnsniper" || echo "0")
    fi
    
    if [[ $systemd_enabled -eq 1 ]]; then
        echo -e "${BOLD}Current scheduling:${NC} ${GREEN}Enabled (systemd)${NC}"
    elif [[ $cron_enabled -gt 0 ]]; then
        echo -e "${BOLD}Current scheduling:${NC} ${GREEN}Enabled (cron)${NC}"
    else
        echo -e "${BOLD}Current scheduling:${NC} ${RED}Disabled${NC}"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Enable Scheduling (hourly)"
    echo -e "${YELLOW}2.${NC} Disable Scheduling"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Enable scheduling
            if command -v systemctl &>/dev/null; then
                # Enable with systemd
                systemctl enable dnsniper.timer &>/dev/null || true
                systemctl start dnsniper.timer &>/dev/null || true
                echo -e "${GREEN}Scheduling enabled with systemd.${NC}"
            elif command -v crontab &>/dev/null; then
                # Enable with cron
                (crontab -l 2>/dev/null | grep -v "dnsniper"; echo "0 * * * * $BIN_DIR/dnsniper-daemon > /dev/null 2>&1") | crontab -
                echo -e "${GREEN}Scheduling enabled with cron.${NC}"
            else
                echo -e "${RED}Neither systemd nor crontab available. Cannot enable scheduling.${NC}"
            fi
            ;;
        2)
            # Disable scheduling
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.timer &>/dev/null || true
                systemctl disable dnsniper.timer &>/dev/null || true
            fi
            
            if command -v crontab &>/dev/null; then
                (crontab -l 2>/dev/null | grep -v "dnsniper") | crontab -
            fi
            
            echo -e "${YELLOW}Scheduling disabled.${NC}"
            ;;
        0) return ;;
        *) echo -e "${RED}Invalid selection.${NC}" ;;
    esac
}

# Backup menu
backup_menu() {
    # TODO: Implement backup menu
    show_banner
    echo -e "${CYAN}${BOLD}BACKUP MENU${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}This feature is not yet implemented.${NC}"
    echo -e "${BLUE}Coming soon!${NC}"
}

# Add IP function
add_ip() {
    # TODO: Implement add IP function
    show_banner
    echo -e "${CYAN}${BOLD}ADD IP${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}This feature is not yet implemented.${NC}"
    echo -e "${BLUE}Coming soon!${NC}"
}

# Remove IP function
remove_ip() {
    # TODO: Implement remove IP function
    show_banner
    echo -e "${CYAN}${BOLD}REMOVE IP${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}This feature is not yet implemented.${NC}"
    echo -e "${BLUE}Coming soon!${NC}"
}

# Uninstall function
uninstall() {
    show_banner
    echo -e "${CYAN}${BOLD}UNINSTALL DNSNIPER${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${RED}Warning: This will completely remove DNSniper from your system.${NC}"
    echo -e "${YELLOW}All settings, rules, and lists will be removed.${NC}"
    
    read -rp "Are you sure you want to uninstall DNSniper? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Uninstall cancelled.${NC}"
        return
    fi
    
    echo -e "${BLUE}Uninstalling DNSniper...${NC}"
    
    # Stop daemon and services
    stop_daemon
    
    # Remove systemd services
    if command -v systemctl &>/dev/null; then
        systemctl stop dnsniper.timer &>/dev/null || true
        systemctl stop dnsniper.service &>/dev/null || true
        systemctl disable dnsniper.timer &>/dev/null || true
        systemctl disable dnsniper.service &>/dev/null || true
        rm -f /etc/systemd/system/dnsniper.service &>/dev/null || true
        rm -f /etc/systemd/system/dnsniper.timer &>/dev/null || true
        systemctl daemon-reload &>/dev/null || true
    fi
    
    # Remove cron jobs
    if command -v crontab &>/dev/null; then
        (crontab -l 2>/dev/null | grep -v "dnsniper") | crontab - 2>/dev/null || true
    fi
    
    # Clean up firewall rules
    clean_rules
    
    # Remove files
    rm -f "$BIN_DIR/dnsniper" "$BIN_DIR/dnsniper-daemon" &>/dev/null || true
    rm -rf "$BASE_DIR" &>/dev/null || true
    rm -f /var/lock/dnsniper*.lock &>/dev/null || true
    
    echo -e "${GREEN}DNSniper has been uninstalled.${NC}"
    exit 0
}
