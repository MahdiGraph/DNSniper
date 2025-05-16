#!/usr/bin/env bash
# DNSniper - Domain-based Network Threat Mitigation
# Version: 2.0.0

# UI lock file
LOCK_FILE="/var/lock/dnsniper-ui.lock"

# Check if another instance is already running
if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
        echo "Another DNSniper UI session is running (PID: $pid)."
        exit 1
    else
        # Stale lock file
        rm -f "$LOCK_FILE"
    fi
fi

# Create lock file
echo $$ > "$LOCK_FILE"

# Paths
BASE_DIR="/etc/dnsniper"
CORE_LIB="$BASE_DIR/dnsniper-core.sh"
DAEMON_PATH="/usr/local/bin/dnsniper-daemon"

# Cleanup handler
cleanup() {
    rm -f "$LOCK_FILE" 2>/dev/null || true
    exit "${1:-0}"
}

# Set up traps
trap 'cleanup 1' INT TERM
trap 'cleanup 0' EXIT

# Import core library
if [ -f "$CORE_LIB" ]; then
    . "$CORE_LIB"
else
    echo "Error: Core library not found: $CORE_LIB"
    exit 1
fi

# Check if systemd is available
has_systemd() {
    command -v systemctl >/dev/null 2>&1
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

# Check if daemon is running
is_daemon_running() {
    if [ -f "/var/lock/dnsniper-daemon.lock" ]; then
        daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "")
        if [ -n "$daemon_pid" ] && ps -p "$daemon_pid" > /dev/null 2>&1; then
            return 0  # Daemon is running
        fi
    fi
    
    # Also check systemd status if available
    if has_systemd; then
        systemctl is-active --quiet dnsniper.service && return 0
    fi
    
    return 1  # Daemon is not running
}

# Check if service is enabled
is_service_enabled() {
    if has_systemd; then
        systemctl is-enabled --quiet dnsniper.timer && return 0
    fi
    return 1
}

# Run daemon manually (triggered by user)
run_daemon() {
    echo -e "${BLUE}${BOLD}Starting DNSniper daemon...${NC}"
    
    if is_daemon_running; then
        echo -e "${YELLOW}DNSniper daemon is already running.${NC}"
        read -rp "Do you want to restart it? [y/N]: " restart
        
        if [[ "$restart" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Stopping the current daemon...${NC}"
            if has_systemd; then
                systemctl stop dnsniper.service
            else
                daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "")
                [ -n "$daemon_pid" ] && kill $daemon_pid 2>/dev/null
            fi
            sleep 1
        else
            echo -e "${YELLOW}Canceled. Daemon continues to run.${NC}"
            return
        fi
    fi
    
    # Start the daemon process
    echo -e "${GREEN}Starting DNSniper daemon...${NC}"
    
    if has_systemd; then
        systemctl start dnsniper.service
        echo -e "${GREEN}DNSniper daemon started via systemd.${NC}"
        echo -e "${YELLOW}You can check its status with:${NC} sudo systemctl status dnsniper.service"
    elif [ -x "$DAEMON_PATH" ]; then
        nohup "$DAEMON_PATH" > /dev/null 2>&1 &
        bg_pid=$!
        echo -e "${GREEN}DNSniper daemon started with PID: $bg_pid${NC}"
    else
        echo -e "${RED}Error: DNSniper daemon executable not found.${NC}"
    fi
}

# Show current status
show_status() {
    show_banner
    
    echo -e "${CYAN}${BOLD}SYSTEM STATUS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get current status
    local status=$(get_status)
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
        daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "")
        echo -e "${BOLD}Background Service:${NC} ${GREEN}Running${NC}${daemon_pid:+ (PID: $daemon_pid)}"
    else
        echo -e "${BOLD}Background Service:${NC} ${RED}Not Running${NC}"
    fi
    
    # Check if service is enabled
    if is_service_enabled; then
        echo -e "${BOLD}Scheduled Service:${NC} ${GREEN}Enabled (hourly)${NC}"
    else
        echo -e "${BOLD}Scheduled Service:${NC} ${RED}Disabled${NC}"
    fi
    
    # Count domains and IPs
    local domain_count=0
    local ip_count=0
    
    if [ -f "$BASE_DIR/domains-default.txt" ]; then
        domain_count=$(grep -v '^#' "$BASE_DIR/domains-default.txt" | grep -v '^$' | wc -l)
    fi
    
    if [ -f "$BASE_DIR/domains-add.txt" ]; then
        domain_count=$((domain_count + $(grep -v '^#' "$BASE_DIR/domains-add.txt" | grep -v '^$' | wc -l)))
    fi
    
    if [ -f "$BASE_DIR/ips-add.txt" ]; then
        ip_count=$(grep -v '^#' "$BASE_DIR/ips-add.txt" | grep -v '^$' | wc -l)
    fi
    
    # Get current blocked IPs count
    local blocked_ips=$(count_blocked_ips)
    
    echo -e "${BOLD}Domains Monitored:${NC} ${GREEN}${domain_count}${NC}"
    echo -e "${BOLD}Custom IPs:${NC} ${GREEN}${ip_count}${NC}"
    echo -e "${BOLD}Active Rules:${NC} ${RED}${blocked_ips}${NC}"
    
    # Get configuration values
    local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_MAX_IPS")
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_TIMEOUT")
    local auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_AUTO_UPDATE")
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_EXPIRE_ENABLED")
    local logging_enabled=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_LOGGING_ENABLED")
    
    echo -e ""
    echo -e "${CYAN}${BOLD}CONFIGURATION${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${BOLD}Max IPs/domain:${NC} ${YELLOW}$max_ips${NC}"
    echo -e "${BOLD}Timeout:${NC} ${YELLOW}$timeout seconds${NC}"
    echo -e "${BOLD}Auto-update:${NC} $([ "$auto_update" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BOLD}Rule Expiration:${NC} $([ "$expire_enabled" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BOLD}Logging:${NC} $([ "$logging_enabled" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    
    # Show log file info
    if [ -f "$LOG_FILE" ]; then
        local last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
        local log_size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)
        echo -e "${BOLD}Last Run:${NC} ${BLUE}$last_run${NC}"
        echo -e "${BOLD}Log Size:${NC} ${YELLOW}${log_size:-Unknown}${NC}"
    else
        echo -e "${BOLD}Last Run:${NC} ${RED}Never${NC}"
    fi
    
    echo -e ""
    echo -e "${YELLOW}To start the daemon manually:${NC} sudo systemctl start dnsniper.service"
    echo -e "${YELLOW}To view its logs:${NC} sudo journalctl -u dnsniper.service"
}

# Main menu
main_menu() {
    while true; do
        show_banner
        
        # Show current status in main menu
        local status=$(get_status)
        local status_text="${YELLOW}Unknown${NC}"
        
        case "$status" in
            "READY")
                status_text="${GREEN}Ready${NC}"
                ;;
            "RUNNING")
                status_text="${BLUE}Running${NC}"
                ;;
            "ERROR")
                status_text="${RED}Error${NC}"
                ;;
        esac
        
        # Check if daemon is running
        if is_daemon_running; then
            daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "")
            daemon_text="${GREEN}Running${NC}${daemon_pid:+ (PID: $daemon_pid)}"
        else
            daemon_text="${RED}Not Running${NC}"
        fi
        
        # Check if service is enabled
        if is_service_enabled; then
            sched_text="${GREEN}Enabled (hourly)${NC}"
        else
            sched_text="${RED}Disabled${NC}"
        fi
        
        echo -e "${CYAN}${BOLD}Status:${NC} $status_text | ${CYAN}${BOLD}Service:${NC} $daemon_text | ${CYAN}${BOLD}Schedule:${NC} $sched_text"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        echo -e "${YELLOW}1.${NC} Run Now               ${YELLOW}2.${NC} Show Status"
        echo -e "${YELLOW}3.${NC} Add Domain            ${YELLOW}4.${NC} Remove Domain"
        echo -e "${YELLOW}5.${NC} Add IP Address        ${YELLOW}6.${NC} Remove IP Address"
        echo -e "${YELLOW}7.${NC} Manage Lists          ${YELLOW}8.${NC} Settings"
        echo -e "${YELLOW}9.${NC} Backup/Restore        ${YELLOW}0.${NC} Exit"
        echo -e "${YELLOW}U.${NC} Uninstall"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) run_daemon; read -rp "Press Enter to continue..." ;;
            2) show_status; read -rp "Press Enter to continue..." ;;
            3) add_domain; read -rp "Press Enter to continue..." ;;
            4) remove_domain; read -rp "Press Enter to continue..." ;;
            5) add_ip; read -rp "Press Enter to continue..." ;;
            6) remove_ip; read -rp "Press Enter to continue..." ;;
            7) manage_lists; read -rp "Press Enter to continue..." ;;
            8) settings_menu; read -rp "Press Enter to continue..." ;;
            9) backup_menu; read -rp "Press Enter to continue..." ;;
            0) exit 0 ;;
            [Uu]) uninstall; read -rp "Press Enter to continue..." ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# Add domain to block list
add_domain() {
    show_banner
    echo -e "${CYAN}${BOLD}ADD DOMAIN TO BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter domain to block (e.g., example.com): " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}Error: Domain cannot be empty.${NC}"
        return
    fi
    
    # Validate domain
    if ! is_valid_domain "$domain"; then
        echo -e "${RED}Error: Invalid domain format.${NC}"
        return
    fi
    
    # Check if already in block list
    if grep -Fxq "$domain" "$ADD_FILE" 2>/dev/null; then
        echo -e "${YELLOW}Domain $domain is already in block list.${NC}"
        return
    fi
    
    # Add to domains-add.txt
    echo "$domain" >> "$ADD_FILE"
    echo -e "${GREEN}Domain $domain added to block list.${NC}"
    
    # Ask if to apply immediately
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_daemon
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Remove domain from block list
remove_domain() {
    show_banner
    echo -e "${CYAN}${BOLD}REMOVE DOMAIN FROM BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get all active domains
    local tmpdomains=$(mktemp)
    merge_domains > "$tmpdomains"
    local total=$(wc -l < "$tmpdomains")
    
    if [ "$total" -eq 0 ]; then
        echo -e "${YELLOW}No domains in block list.${NC}"
        rm -f "$tmpdomains"
        return
    fi
    
    # Display domains
    echo -e "${BLUE}Current domains in block list:${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Only show first 20 domains if there are too many
    if [ "$total" -gt 20 ]; then
        head -20 "$tmpdomains"
        echo -e "${YELLOW}... and $((total - 20)) more domains${NC}"
    else
        cat "$tmpdomains"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Enter domain to remove: " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}Error: Domain cannot be empty.${NC}"
        rm -f "$tmpdomains"
        return
    fi
    
    # Check if domain exists
    if ! grep -Fxq "$domain" "$tmpdomains"; then
        echo -e "${RED}Error: Domain $domain is not in block list.${NC}"
        rm -f "$tmpdomains"
        return
    fi
    
    rm -f "$tmpdomains"
    
    # Add to remove list
    echo "$domain" >> "$REMOVE_FILE"
    echo -e "${GREEN}Domain $domain added to remove list.${NC}"
    
    # Ask if to apply immediately
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_daemon
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Add IP to block list
add_ip() {
    show_banner
    echo -e "${CYAN}${BOLD}ADD IP ADDRESS TO BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter IP address to block: " ip
    
    if [ -z "$ip" ]; then
        echo -e "${RED}Error: IP address cannot be empty.${NC}"
        return
    fi
    
    # Validate IP
    if ! is_ipv6 "$ip" && ! is_valid_ipv4 "$ip"; then
        echo -e "${RED}Error: Invalid IP format.${NC}"
        return
    fi
    
    # Check if critical IP
    if is_critical_ip "$ip"; then
        echo -e "${RED}Error: Cannot block critical IP address: $ip${NC}"
        return
    fi
    
    # Check if already in block list
    if grep -Fxq "$ip" "$IP_ADD_FILE" 2>/dev/null; then
        echo -e "${YELLOW}IP $ip is already in block list.${NC}"
        return
    fi
    
    # Add to IP add file
    echo "$ip" >> "$IP_ADD_FILE"
    echo -e "${GREEN}IP $ip added to block list.${NC}"
    
    # Ask if to apply immediately
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_daemon
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Remove IP from block list
remove_ip() {
    show_banner
    echo -e "${CYAN}${BOLD}REMOVE IP ADDRESS FROM BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get all custom IPs
    local tmpips=$(mktemp)
    get_custom_ips > "$tmpips"
    local total=$(wc -l < "$tmpips")
    
    if [ "$total" -eq 0 ]; then
        echo -e "${YELLOW}No custom IPs in block list.${NC}"
        rm -f "$tmpips"
        return
    fi
    
    # Display IPs
    echo -e "${BLUE}Current IPs in block list:${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Only show first 20 IPs if there are too many
    if [ "$total" -gt 20 ]; then
        head -20 "$tmpips"
        echo -e "${YELLOW}... and $((total - 20)) more IPs${NC}"
    else
        cat "$tmpips"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Enter IP to remove: " ip
    
    if [ -z "$ip" ]; then
        echo -e "${RED}Error: IP address cannot be empty.${NC}"
        rm -f "$tmpips"
        return
    fi
    
    # Check if IP exists
    if ! grep -Fxq "$ip" "$tmpips"; then
        echo -e "${RED}Error: IP $ip is not in block list.${NC}"
        rm -f "$tmpips"
        return
    fi
    
    rm -f "$tmpips"
    
    # Add to IP remove file
    echo "$ip" >> "$IP_REMOVE_FILE"
    echo -e "${GREEN}IP $ip added to remove list.${NC}"
    
    # Ask if to apply immediately
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_daemon
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Manage settings menu
settings_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}${BOLD}SETTINGS${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Schedule Settings"
        echo -e "${YELLOW}2.${NC} Connection Settings"
        echo -e "${YELLOW}3.${NC} Update Settings"
        echo -e "${YELLOW}4.${NC} Rule Settings"
        echo -e "${YELLOW}5.${NC} Logging Settings"
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) schedule_settings ;;
            2) connection_settings ;;
            3) update_settings ;;
            4) rule_settings ;;
            5) logging_settings ;;
            0) return ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# Schedule settings
schedule_settings() {
    show_banner
    echo -e "${CYAN}${BOLD}SCHEDULE SETTINGS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Check current schedule status
    if is_service_enabled; then
        echo -e "${BOLD}Current Schedule:${NC} ${GREEN}Enabled (hourly)${NC}"
    else
        echo -e "${BOLD}Current Schedule:${NC} ${RED}Disabled${NC}"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Enable Scheduling (Hourly)"
    echo -e "${YELLOW}2.${NC} Disable Scheduling"
    echo -e "${YELLOW}0.${NC} Back"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Enable scheduling
            if has_systemd; then
                systemctl enable dnsniper.timer
                systemctl start dnsniper.timer
                echo -e "${GREEN}Scheduling enabled (hourly via systemd).${NC}"
                
                # Update config
                sed -i '/^automatic_execution=/d' "$CONFIG_FILE" 2>/dev/null || true
                echo "automatic_execution=1" >> "$CONFIG_FILE"
            else
                echo -e "${RED}Error: Systemd not available on this system.${NC}"
            fi
            ;;
        2)
            # Disable scheduling
            if has_systemd; then
                systemctl stop dnsniper.timer
                systemctl disable dnsniper.timer
                echo -e "${YELLOW}Scheduling disabled.${NC}"
                
                # Update config
                sed -i '/^automatic_execution=/d' "$CONFIG_FILE" 2>/dev/null || true
                echo "automatic_execution=0" >> "$CONFIG_FILE"
            else
                echo -e "${RED}Error: Systemd not available on this system.${NC}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
}

# Connection settings
connection_settings() {
    show_banner
    echo -e "${CYAN}${BOLD}CONNECTION SETTINGS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get current timeout
    local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_TIMEOUT")
    echo -e "${BOLD}Current Timeout:${NC} ${YELLOW}$timeout seconds${NC}"
    
    read -rp "Enter new timeout in seconds (5-60, 0 to cancel): " new_timeout
    
    if [[ "$new_timeout" =~ ^[0-9]+$ ]]; then
        if [ "$new_timeout" -eq 0 ]; then
            echo -e "${YELLOW}No changes made.${NC}"
            return
        elif [ "$new_timeout" -ge 5 ] && [ "$new_timeout" -le 60 ]; then
            sed -i "s/^timeout=.*/timeout=$new_timeout/" "$CONFIG_FILE"
            echo -e "${GREEN}Timeout set to $new_timeout seconds.${NC}"
        else
            echo -e "${RED}Invalid value. Timeout must be between 5 and 60 seconds.${NC}"
        fi
    else
        echo -e "${RED}Invalid input. Please enter a number.${NC}"
    fi
}

# Update settings
update_settings() {
    show_banner
    echo -e "${CYAN}${BOLD}UPDATE SETTINGS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get current settings
    local auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_AUTO_UPDATE")
    local update_url=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d "'" || echo "$DEFAULT_URL")
    
    echo -e "${BOLD}Auto-Update:${NC} $([ "$auto_update" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BOLD}Update URL:${NC} ${BLUE}$update_url${NC}"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Toggle Auto-Update"
    echo -e "${YELLOW}2.${NC} Change Update URL"
    echo -e "${YELLOW}3.${NC} Update Now"
    echo -e "${YELLOW}0.${NC} Back"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Toggle auto-update
            if [ "$auto_update" -eq 1 ]; then
                sed -i 's/^auto_update=1/auto_update=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Auto-update disabled.${NC}"
            else
                sed -i 's/^auto_update=0/auto_update=1/' "$CONFIG_FILE"
                echo -e "${GREEN}Auto-update enabled.${NC}"
            fi
            ;;
        2)
            # Change update URL
            read -rp "Enter new update URL: " new_url
            
            if [[ "$new_url" =~ ^https?:// ]]; then
                sed -i "s|^update_url=.*|update_url='$new_url'|" "$CONFIG_FILE"
                echo -e "${GREEN}Update URL set to: $new_url${NC}"
            else
                echo -e "${RED}Invalid URL. Must start with http:// or https://${NC}"
            fi
            ;;
        3)
            # Update now
            echo -e "${BLUE}Updating domains list...${NC}"
            if update_default; then
                echo -e "${GREEN}Update successful.${NC}"
                
                # Ask if to apply changes
                read -rp "Apply changes immediately? [y/N]: " apply_now
                if [[ "$apply_now" =~ ^[Yy]$ ]]; then
                    run_daemon
                fi
            else
                echo -e "${RED}Update failed.${NC}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
}

# Rule settings
rule_settings() {
    show_banner
    echo -e "${CYAN}${BOLD}RULE SETTINGS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get current settings
    local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_MAX_IPS")
    local block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_BLOCK_SOURCE")
    local block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_BLOCK_DESTINATION")
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_EXPIRE_ENABLED")
    local expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_EXPIRE_MULTIPLIER")
    
    echo -e "${BOLD}Max IPs per Domain:${NC} ${YELLOW}$max_ips${NC}"
    echo -e "${BOLD}Block Source Traffic:${NC} $([ "$block_source" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BOLD}Block Destination Traffic:${NC} $([ "$block_destination" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BOLD}Rule Expiration:${NC} $([ "$expire_enabled" -eq 1 ] && echo "${GREEN}Enabled (${expire_multiplier}x)${NC}" || echo "${RED}Disabled${NC}")"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Change Max IPs"
    echo -e "${YELLOW}2.${NC} Toggle Source Blocking"
    echo -e "${YELLOW}3.${NC} Toggle Destination Blocking"
    echo -e "${YELLOW}4.${NC} Toggle Rule Expiration"
    echo -e "${YELLOW}5.${NC} Clear All Rules"
    echo -e "${YELLOW}0.${NC} Back"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Change max IPs
            read -rp "Enter new max IPs per domain (5-50): " new_max
            
            if [[ "$new_max" =~ ^[0-9]+$ && "$new_max" -ge 5 && "$new_max" -le 50 ]]; then
                sed -i "s/^max_ips=.*/max_ips=$new_max/" "$CONFIG_FILE"
                echo -e "${GREEN}Max IPs per domain set to $new_max.${NC}"
            else
                echo -e "${RED}Invalid value. Must be between 5 and 50.${NC}"
            fi
            ;;
        2)
            # Toggle source blocking
            if [ "$block_source" -eq 1 ]; then
                sed -i 's/^block_source=1/block_source=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Source traffic blocking disabled.${NC}"
            else
                sed -i 's/^block_source=0/block_source=1/' "$CONFIG_FILE"
                echo -e "${GREEN}Source traffic blocking enabled.${NC}"
            fi
            
            echo -e "${YELLOW}Note: Changes will apply to new rules. Consider clearing and rebuilding all rules.${NC}"
            ;;
        3)
            # Toggle destination blocking
            if [ "$block_destination" -eq 1 ]; then
                sed -i 's/^block_destination=1/block_destination=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Destination traffic blocking disabled.${NC}"
            else
                sed -i 's/^block_destination=0/block_destination=1/' "$CONFIG_FILE"
                echo -e "${GREEN}Destination traffic blocking enabled.${NC}"
            fi
            
            echo -e "${YELLOW}Note: Changes will apply to new rules. Consider clearing and rebuilding all rules.${NC}"
            ;;
        4)
            # Toggle rule expiration
            if [ "$expire_enabled" -eq 1 ]; then
                sed -i 's/^expire_enabled=1/expire_enabled=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Rule expiration disabled.${NC}"
            else
                sed -i 's/^expire_enabled=0/expire_enabled=1/' "$CONFIG_FILE"
                
                # Ask for multiplier
                read -rp "Enter expiration multiplier (1-24, default is 5): " new_mult
                
                if [[ "$new_mult" =~ ^[0-9]+$ && "$new_mult" -ge 1 && "$new_mult" -le 24 ]]; then
                    sed -i "s/^expire_multiplier=.*/expire_multiplier=$new_mult/" "$CONFIG_FILE"
                    echo -e "${GREEN}Rule expiration enabled with multiplier $new_mult.${NC}"
                else
                    echo -e "${YELLOW}Using default multiplier of 5.${NC}"
                    sed -i "s/^expire_multiplier=.*/expire_multiplier=5/" "$CONFIG_FILE"
                    echo -e "${GREEN}Rule expiration enabled.${NC}"
                fi
            fi
            ;;
        5)
            # Clear all rules
            read -rp "Are you sure you want to clear all rules? [y/N]: " confirm
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}Clearing all rules...${NC}"
                if clean_rules; then
                    echo -e "${GREEN}All rules cleared.${NC}"
                else
                    echo -e "${RED}Error clearing rules.${NC}"
                fi
                
                # Ask if to rebuild
                read -rp "Rebuild rules now? [y/N]: " rebuild
                if [[ "$rebuild" =~ ^[Yy]$ ]]; then
                    run_daemon
                fi
            else
                echo -e "${YELLOW}Operation cancelled.${NC}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
}

# Logging settings
logging_settings() {
    show_banner
    echo -e "${CYAN}${BOLD}LOGGING SETTINGS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get current settings
    local logging_enabled=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_LOGGING_ENABLED")
    local log_max_size=$(grep '^log_max_size=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_LOG_MAX_SIZE")
    local log_rotate_count=$(grep '^log_rotate_count=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_LOG_ROTATE_COUNT")
    
    echo -e "${BOLD}Logging:${NC} $([ "$logging_enabled" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BOLD}Log File:${NC} ${BLUE}$LOG_FILE${NC}"
    echo -e "${BOLD}Max Log Size:${NC} ${YELLOW}${log_max_size}MB${NC}"
    echo -e "${BOLD}Rotation Count:${NC} ${YELLOW}${log_rotate_count} files${NC}"
    
    if [ -f "$LOG_FILE" ]; then
        local log_size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)
        echo -e "${BOLD}Current Log Size:${NC} ${YELLOW}${log_size:-Unknown}${NC}"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Toggle Logging"
    echo -e "${YELLOW}2.${NC} Change Max Log Size"
    echo -e "${YELLOW}3.${NC} Change Rotation Count"
    echo -e "${YELLOW}4.${NC} View Log"
    echo -e "${YELLOW}5.${NC} Clear Log"
    echo -e "${YELLOW}0.${NC} Back"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Toggle logging
            if [ "$logging_enabled" -eq 1 ]; then
                sed -i 's/^logging_enabled=1/logging_enabled=0/' "$CONFIG_FILE"
                echo -e "${YELLOW}Logging disabled.${NC}"
            else
                sed -i 's/^logging_enabled=0/logging_enabled=1/' "$CONFIG_FILE"
                echo -e "${GREEN}Logging enabled.${NC}"
            fi
            
            # Refresh logging state
            init_logging
            ;;
        2)
            # Change max log size
            read -rp "Enter max log size in MB (1-100): " new_size
            
            if [[ "$new_size" =~ ^[0-9]+$ && "$new_size" -ge 1 && "$new_size" -le 100 ]]; then
                sed -i "s/^log_max_size=.*/log_max_size=$new_size/" "$CONFIG_FILE"
                echo -e "${GREEN}Max log size set to ${new_size}MB.${NC}"
            else
                echo -e "${RED}Invalid value. Must be between 1 and 100.${NC}"
            fi
            ;;
        3)
            # Change rotation count
            read -rp "Enter log rotation count (1-20): " new_count
            
            if [[ "$new_count" =~ ^[0-9]+$ && "$new_count" -ge 1 && "$new_count" -le 20 ]]; then
                sed -i "s/^log_rotate_count=.*/log_rotate_count=$new_count/" "$CONFIG_FILE"
                echo -e "${GREEN}Log rotation count set to $new_count.${NC}"
            else
                echo -e "${RED}Invalid value. Must be between 1 and 20.${NC}"
            fi
            ;;
        4)
            # View log
            if [ -f "$LOG_FILE" ]; then
                echo -e "${CYAN}${BOLD}LOG FILE (last 20 lines):${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                tail -n 20 "$LOG_FILE"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
            else
                echo -e "${YELLOW}No log file exists yet.${NC}"
            fi
            ;;
        5)
            # Clear log
            if [ -f "$LOG_FILE" ]; then
                read -rp "Are you sure you want to clear the log? [y/N]: " confirm
                
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    > "$LOG_FILE"
                    echo -e "${GREEN}Log file cleared.${NC}"
                else
                    echo -e "${YELLOW}Operation cancelled.${NC}"
                fi
            else
                echo -e "${YELLOW}No log file exists yet.${NC}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
}

# List management
manage_lists() {
    while true; do
        show_banner
        echo -e "${CYAN}${BOLD}MANAGE LISTS${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} View Domain Lists"
        echo -e "${YELLOW}2.${NC} View IP Lists"
        echo -e "${YELLOW}3.${NC} Import Domains"
        echo -e "${YELLOW}4.${NC} Export Domains"
        echo -e "${YELLOW}5.${NC} Import IPs"
        echo -e "${YELLOW}6.${NC} Export IPs"
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) view_domains ;;
            2) view_ips ;;
            3) import_domains ;;
            4) export_domains ;;
            5) import_ips ;;
            6) export_ips ;;
            0) return ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# View domains
view_domains() {
    show_banner
    echo -e "${CYAN}${BOLD}DOMAIN LISTS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get domain counts
    local default_count=0
    local add_count=0
    local remove_count=0
    local active_count=0
    
    if [ -f "$DEFAULT_FILE" ]; then
        default_count=$(grep -v '^#' "$DEFAULT_FILE" | grep -v '^$' | wc -l)
    fi
    
    if [ -f "$ADD_FILE" ]; then
        add_count=$(grep -v '^#' "$ADD_FILE" | grep -v '^$' | wc -l)
    fi
    
    if [ -f "$REMOVE_FILE" ]; then
        remove_count=$(grep -v '^#' "$REMOVE_FILE" | grep -v '^$' | wc -l)
    fi
    
    # Get active domains using merge_domains
    local tmpdomains=$(mktemp)
    merge_domains > "$tmpdomains"
    active_count=$(wc -l < "$tmpdomains")
    
    # Display counts
    echo -e "${BOLD}Default Domains:${NC} ${BLUE}$default_count${NC}"
    echo -e "${BOLD}Added Domains:${NC} ${GREEN}$add_count${NC}"
    echo -e "${BOLD}Removed Domains:${NC} ${RED}$remove_count${NC}"
    echo -e "${BOLD}Active Domains:${NC} ${YELLOW}$active_count${NC}"
    
    # Ask which list to view
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} View Active Domains"
    echo -e "${YELLOW}2.${NC} View Default Domains"
    echo -e "${YELLOW}3.${NC} View Added Domains"
    echo -e "${YELLOW}4.${NC} View Removed Domains"
    echo -e "${YELLOW}0.${NC} Back"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # View active domains
            if [ "$active_count" -eq 0 ]; then
                echo -e "${YELLOW}No active domains.${NC}"
            else
                echo -e "${CYAN}${BOLD}ACTIVE DOMAINS:${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Show first 50 domains to prevent overflow
                if [ "$active_count" -gt 50 ]; then
                    head -50 "$tmpdomains"
                    echo -e "${YELLOW}... and $((active_count - 50)) more domains${NC}"
                else
                    cat "$tmpdomains"
                fi
            fi
            ;;
        2)
            # View default domains
            if [ "$default_count" -eq 0 ]; then
                echo -e "${YELLOW}No default domains.${NC}"
            else
                echo -e "${CYAN}${BOLD}DEFAULT DOMAINS:${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Show first 50 domains to prevent overflow
                if [ "$default_count" -gt 50 ]; then
                    grep -v '^#' "$DEFAULT_FILE" | grep -v '^$' | head -50
                    echo -e "${YELLOW}... and $((default_count - 50)) more domains${NC}"
                else
                    grep -v '^#' "$DEFAULT_FILE" | grep -v '^$'
                fi
            fi
            ;;
        3)
            # View added domains
            if [ "$add_count" -eq 0 ]; then
                echo -e "${YELLOW}No added domains.${NC}"
            else
                echo -e "${CYAN}${BOLD}ADDED DOMAINS:${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Show all added domains (usually not too many)
                grep -v '^#' "$ADD_FILE" | grep -v '^$'
            fi
            ;;
        4)
            # View removed domains
            if [ "$remove_count" -eq 0 ]; then
                echo -e "${YELLOW}No removed domains.${NC}"
            else
                echo -e "${CYAN}${BOLD}REMOVED DOMAINS:${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Show all removed domains (usually not too many)
                grep -v '^#' "$REMOVE_FILE" | grep -v '^$'
            fi
            ;;
        0)
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
    
    # Clean up
    rm -f "$tmpdomains"
}

# View IPs
view_ips() {
    show_banner
    echo -e "${CYAN}${BOLD}IP LISTS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get IP counts
    local add_count=0
    local remove_count=0
    local active_count=0
    
    if [ -f "$IP_ADD_FILE" ]; then
        add_count=$(grep -v '^#' "$IP_ADD_FILE" | grep -v '^$' | wc -l)
    fi
    
    if [ -f "$IP_REMOVE_FILE" ]; then
        remove_count=$(grep -v '^#' "$IP_REMOVE_FILE" | grep -v '^$' | wc -l)
    fi
    
    # Get active IPs using get_custom_ips
    local tmpips=$(mktemp)
    get_custom_ips > "$tmpips"
    active_count=$(wc -l < "$tmpips")
    
    # Display counts
    echo -e "${BOLD}Added IPs:${NC} ${GREEN}$add_count${NC}"
    echo -e "${BOLD}Removed IPs:${NC} ${RED}$remove_count${NC}"
    echo -e "${BOLD}Active IPs:${NC} ${YELLOW}$active_count${NC}"
    
    # Ask which list to view
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} View Active IPs"
    echo -e "${YELLOW}2.${NC} View Added IPs"
    echo -e "${YELLOW}3.${NC} View Removed IPs"
    echo -e "${YELLOW}0.${NC} Back"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # View active IPs
            if [ "$active_count" -eq 0 ]; then
                echo -e "${YELLOW}No active IPs.${NC}"
            else
                echo -e "${CYAN}${BOLD}ACTIVE IPs:${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Show all active IPs
                cat "$tmpips"
            fi
            ;;
        2)
            # View added IPs
            if [ "$add_count" -eq 0 ]; then
                echo -e "${YELLOW}No added IPs.${NC}"
            else
                echo -e "${CYAN}${BOLD}ADDED IPs:${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Show all added IPs
                grep -v '^#' "$IP_ADD_FILE" | grep -v '^$'
            fi
            ;;
        3)
            # View removed IPs
            if [ "$remove_count" -eq 0 ]; then
                echo -e "${YELLOW}No removed IPs.${NC}"
            else
                echo -e "${CYAN}${BOLD}REMOVED IPs:${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Show all removed IPs
                grep -v '^#' "$IP_REMOVE_FILE" | grep -v '^$'
            fi
            ;;
        0)
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
    
    # Clean up
    rm -f "$tmpips"
}

# Import domains
import_domains() {
    show_banner
    echo -e "${CYAN}${BOLD}IMPORT DOMAINS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter path to domains file: " file
    
    if [ -z "$file" ]; then
        echo -e "${RED}Error: File path cannot be empty.${NC}"
        return
    fi
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: File does not exist.${NC}"
        return
    fi
    
    if [ ! -r "$file" ]; then
        echo -e "${RED}Error: Cannot read file (permission denied).${NC}"
        return
    fi
    
    # Count lines in file
    local total=$(grep -v '^#' "$file" | grep -v '^$' | wc -l)
    
    if [ "$total" -eq 0 ]; then
        echo -e "${YELLOW}File contains no domains.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Processing $total domains...${NC}"
    
    # Use temp files for better performance
    local tmpfile=$(mktemp)
    local validfile=$(mktemp)
    
    # First pass: Filter comments and empty lines
    grep -v '^#' "$file" | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile"
    
    # Second pass: Validate domains
    local valid_count=0
    local duplicate_count=0
    
    while IFS= read -r domain; do
        if is_valid_domain "$domain"; then
            # Check if already in domain lists
            if ! grep -Fxq "$domain" "$ADD_FILE" 2>/dev/null; then
                echo "$domain" >> "$validfile"
                valid_count=$((valid_count + 1))
            else
                duplicate_count=$((duplicate_count + 1))
            fi
        fi
    done < "$tmpfile"
    
    # Append valid domains to ADD_FILE
    if [ "$valid_count" -gt 0 ]; then
        cat "$validfile" >> "$ADD_FILE"
    fi
    
    # Clean up
    rm -f "$tmpfile" "$validfile"
    
    echo -e "${GREEN}Import complete: $valid_count domains added, $duplicate_count duplicates skipped.${NC}"
    
    # Ask if to apply immediately
    if [ "$valid_count" -gt 0 ]; then
        read -rp "Do you want to apply changes now? [y/N]: " run_now
        
        if [[ "$run_now" =~ ^[Yy]$ ]]; then
            run_daemon
        else
            echo -e "${YELLOW}Changes will be applied during the next scheduled run.${NC}"
        fi
    fi
}

# Export domains
export_domains() {
    show_banner
    echo -e "${CYAN}${BOLD}EXPORT DOMAINS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter export file path: " file
    
    if [ -z "$file" ]; then
        echo -e "${RED}Error: File path cannot be empty.${NC}"
        return
    fi
    
    # Check if directory exists
    local dir=$(dirname "$file")
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Error: Directory does not exist: $dir${NC}"
        return
    fi
    
    # Check if directory is writable
    if [ ! -w "$dir" ]; then
        echo -e "${RED}Error: Cannot write to directory: $dir (permission denied)${NC}"
        return
    fi
    
    # Get domains
    local tmpdomains=$(mktemp)
    merge_domains > "$tmpdomains"
    local count=$(wc -l < "$tmpdomains")
    
    if [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}No domains to export.${NC}"
        rm -f "$tmpdomains"
        return
    fi
    
    # Create export file with header
    {
        echo "# DNSniper Domains Export"
        echo "# Date: $(date)"
        echo "# Total: $count domains"
        echo ""
        cat "$tmpdomains"
    } > "$file"
    
    # Clean up
    rm -f "$tmpdomains"
    
    echo -e "${GREEN}Exported $count domains to: $file${NC}"
}

# Import IPs
import_ips() {
    show_banner
    echo -e "${CYAN}${BOLD}IMPORT IPs${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter path to IPs file: " file
    
    if [ -z "$file" ]; then
        echo -e "${RED}Error: File path cannot be empty.${NC}"
        return
    fi
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: File does not exist.${NC}"
        return
    fi
    
    if [ ! -r "$file" ]; then
        echo -e "${RED}Error: Cannot read file (permission denied).${NC}"
        return
    fi
    
    # Count lines in file
    local total=$(grep -v '^#' "$file" | grep -v '^$' | wc -l)
    
    if [ "$total" -eq 0 ]; then
        echo -e "${YELLOW}File contains no IPs.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Processing $total IPs...${NC}"
    
    # Use temp files for better performance
    local tmpfile=$(mktemp)
    local validfile=$(mktemp)
    
    # First pass: Filter comments and empty lines
    grep -v '^#' "$file" | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile"
    
    # Second pass: Validate IPs
    local valid_count=0
    local duplicate_count=0
    local critical_count=0
    
    while IFS= read -r ip; do
        if is_ipv6 "$ip" || is_valid_ipv4 "$ip"; then
            # Check if it's a critical IP
            if ! is_critical_ip "$ip"; then
                # Check if already in IP lists
                if ! grep -Fxq "$ip" "$IP_ADD_FILE" 2>/dev/null; then
                    echo "$ip" >> "$validfile"
                    valid_count=$((valid_count + 1))
                else
                    duplicate_count=$((duplicate_count + 1))
                fi
            else
                critical_count=$((critical_count + 1))
            fi
        fi
    done < "$tmpfile"
    
    # Append valid IPs to IP_ADD_FILE
    if [ "$valid_count" -gt 0 ]; then
        cat "$validfile" >> "$IP_ADD_FILE"
    fi
    
    # Clean up
    rm -f "$tmpfile" "$validfile"
    
    echo -e "${GREEN}Import complete: $valid_count IPs added, $duplicate_count duplicates and $critical_count critical IPs skipped.${NC}"
    
    # Ask if to apply immediately
    if [ "$valid_count" -gt 0 ]; then
        read -rp "Do you want to apply changes now? [y/N]: " run_now
        
        if [[ "$run_now" =~ ^[Yy]$ ]]; then
            run_daemon
        else
            echo -e "${YELLOW}Changes will be applied during the next scheduled run.${NC}"
        fi
    fi
}

# Export IPs
export_ips() {
    show_banner
    echo -e "${CYAN}${BOLD}EXPORT IPs${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter export file path: " file
    
    if [ -z "$file" ]; then
        echo -e "${RED}Error: File path cannot be empty.${NC}"
        return
    fi
    
    # Check if directory exists
    local dir=$(dirname "$file")
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Error: Directory does not exist: $dir${NC}"
        return
    fi
    
    # Check if directory is writable
    if [ ! -w "$dir" ]; then
        echo -e "${RED}Error: Cannot write to directory: $dir (permission denied)${NC}"
        return
    fi
    
    # Get IPs
    local tmpips=$(mktemp)
    get_custom_ips > "$tmpips"
    local count=$(wc -l < "$tmpips")
    
    if [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}No IPs to export.${NC}"
        rm -f "$tmpips"
        return
    fi
    
    # Create export file with header
    {
        echo "# DNSniper IPs Export"
        echo "# Date: $(date)"
        echo "# Total: $count IPs"
        echo ""
        cat "$tmpips"
    } > "$file"
    
    # Clean up
    rm -f "$tmpips"
    
    echo -e "${GREEN}Exported $count IPs to: $file${NC}"
}

# Backup/restore menu
backup_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}${BOLD}BACKUP & RESTORE${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Create Backup"
        echo -e "${YELLOW}2.${NC} Restore Backup"
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) create_backup ;;
            2) restore_backup ;;
            0) return ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# Create backup
create_backup() {
    show_banner
    echo -e "${CYAN}${BOLD}CREATE BACKUP${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter backup directory: " dir
    
    if [ -z "$dir" ]; then
        echo -e "${RED}Error: Directory path cannot be empty.${NC}"
        return
    fi
    
    # Check if directory exists
    if [ ! -d "$dir" ]; then
        read -rp "Directory does not exist. Create it? [Y/n]: " create_dir
        
        if [[ ! "$create_dir" =~ ^[Nn]$ ]]; then
            mkdir -p "$dir" || {
                echo -e "${RED}Error: Could not create directory.${NC}"
                return
            }
        else
            echo -e "${YELLOW}Operation cancelled.${NC}"
            return
        fi
    fi
    
    # Check if directory is writable
    if [ ! -w "$dir" ]; then
        echo -e "${RED}Error: Cannot write to directory: $dir (permission denied)${NC}"
        return
    fi
    
    # Create backup directory
    local backup_dir="${dir%/}/dnsniper-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir" || {
        echo -e "${RED}Error: Could not create backup directory.${NC}"
        return
    }
    
    echo -e "${YELLOW}Creating backup...${NC}"
    
    # Copy configuration files
    cp "$CONFIG_FILE" "$backup_dir/" 2>/dev/null || true
    
    # Copy domain lists
    for file in domains-default.txt domains-add.txt domains-remove.txt; do
        if [ -f "$BASE_DIR/$file" ]; then
            cp "$BASE_DIR/$file" "$backup_dir/" 2>/dev/null || true
        fi
    done
    
    # Copy IP lists
    for file in ips-add.txt ips-remove.txt; do
        if [ -f "$BASE_DIR/$file" ]; then
            cp "$BASE_DIR/$file" "$backup_dir/" 2>/dev/null || true
        fi
    done
    
    # Copy database
    if [ -f "$DB_FILE" ]; then
        # Use sqlite3 to create a clean backup
        if command -v sqlite3 &>/dev/null; then
            sqlite3 "$DB_FILE" ".backup '$backup_dir/history.db'" 2>/dev/null || cp "$DB_FILE" "$backup_dir/" 2>/dev/null || true
        else
            cp "$DB_FILE" "$backup_dir/" 2>/dev/null || true
        fi
    fi
    
    # Export current rules
    if command -v iptables-save &>/dev/null; then
        iptables-save > "$backup_dir/iptables.rules" 2>/dev/null || true
        ip6tables-save > "$backup_dir/ip6tables.rules" 2>/dev/null || true
    fi
    
    # Create README file
    cat > "$backup_dir/README.txt" << EOF
DNSniper Backup
Date: $(date)
Version: $VERSION

This backup contains:
- Configuration settings
- Domain lists
- IP lists
- History database
- Firewall rules

To restore this backup, use the Restore Backup option in DNSniper.
EOF
    
    echo -e "${GREEN}Backup created successfully at: $backup_dir${NC}"
}

# Restore backup
restore_backup() {
    show_banner
    echo -e "${CYAN}${BOLD}RESTORE BACKUP${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter backup directory: " dir
    
    if [ -z "$dir" ]; then
        echo -e "${RED}Error: Directory path cannot be empty.${NC}"
        return
    fi
    
    # Check if directory exists
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Error: Directory does not exist: $dir${NC}"
        return
    fi
    
    # Check if directory is readable
    if [ ! -r "$dir" ]; then
        echo -e "${RED}Error: Cannot read from directory: $dir (permission denied)${NC}"
        return
    fi
    
    # Check for required backup files
    local has_config=0
    local has_domains=0
    local has_ips=0
    local has_db=0
    
    [ -f "$dir/config.conf" ] && has_config=1
    [ -f "$dir/domains-default.txt" ] || [ -f "$dir/domains-add.txt" ] || [ -f "$dir/domains-remove.txt" ] && has_domains=1
    [ -f "$dir/ips-add.txt" ] || [ -f "$dir/ips-remove.txt" ] && has_ips=1
    [ -f "$dir/history.db" ] && has_db=1
    
    if [[ $has_config -eq 0 && $has_domains -eq 0 && $has_ips -eq 0 && $has_db -eq 0 ]]; then
        echo -e "${RED}Error: No valid backup files found in directory.${NC}"
        return
    fi
    
    # Confirm restore
    echo -e "${YELLOW}Found the following backup components:${NC}"
    [ $has_config -eq 1 ] && echo -e "- ${GREEN}Configuration${NC}"
    [ $has_domains -eq 1 ] && echo -e "- ${GREEN}Domain lists${NC}"
    [ $has_ips -eq 1 ] && echo -e "- ${GREEN}IP lists${NC}"
    [ $has_db -eq 1 ] && echo -e "- ${GREEN}History database${NC}"
    
    echo -e "${RED}WARNING: Restoring will overwrite current settings.${NC}"
    read -rp "Do you want to continue? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Restore cancelled.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Restoring backup...${NC}"
    
    # Stop any running process
    if is_daemon_running; then
        if has_systemd; then
            systemctl stop dnsniper.service 2>/dev/null || true
        else
            daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "")
            [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null || true
        fi
        sleep 1
    fi
    
    # Restore configuration
    if [ $has_config -eq 1 ]; then
        cp "$dir/config.conf" "$CONFIG_FILE" 2>/dev/null || true
        echo -e "- ${GREEN}Configuration restored${NC}"
    fi
    
    # Restore domain lists
    if [ $has_domains -eq 1 ]; then
        for file in domains-default.txt domains-add.txt domains-remove.txt; do
            if [ -f "$dir/$file" ]; then
                cp "$dir/$file" "$BASE_DIR/$file" 2>/dev/null || true
            fi
        done
        echo -e "- ${GREEN}Domain lists restored${NC}"
    fi
    
    # Restore IP lists
    if [ $has_ips -eq 1 ]; then
        for file in ips-add.txt ips-remove.txt; do
            if [ -f "$dir/$file" ]; then
                cp "$dir/$file" "$BASE_DIR/$file" 2>/dev/null || true
            fi
        done
        echo -e "- ${GREEN}IP lists restored${NC}"
    fi
    
    # Restore database
    if [ $has_db -eq 1 ]; then
        # Stop any process that might be using the database
        if command -v sqlite3 &>/dev/null; then
            # Close database connections and recreate
            rm -f "$DB_FILE" "$DB_FILE-shm" "$DB_FILE-wal" 2>/dev/null || true
            # Copy the database file
            cp "$dir/history.db" "$DB_FILE" 2>/dev/null || true
        else
            cp "$dir/history.db" "$DB_FILE" 2>/dev/null || true
        fi
        echo -e "- ${GREEN}History database restored${NC}"
    fi
    
    # Restore firewall rules if available
    if [ -f "$dir/iptables.rules" ] && [ -f "$dir/ip6tables.rules" ]; then
        # Ask if user wants to restore firewall rules
        read -rp "Restore firewall rules too? [y/N]: " restore_rules
        
        if [[ "$restore_rules" =~ ^[Yy]$ ]]; then
            iptables-restore < "$dir/iptables.rules" 2>/dev/null || true
            ip6tables-restore < "$dir/ip6tables.rules" 2>/dev/null || true
            echo -e "- ${GREEN}Firewall rules restored${NC}"
        fi
    fi
    
    # Make settings effective
    ensure_environment
    
    echo -e "${GREEN}Backup restored successfully!${NC}"
    
    # Ask if to run daemon immediately
    read -rp "Run DNSniper daemon now to apply changes? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_daemon
    else
        echo -e "${YELLOW}Changes will be applied during the next scheduled run.${NC}"
    fi
}

# Uninstall function
uninstall() {
    show_banner
    echo -e "${CYAN}${BOLD}UNINSTALL DNSNIPER${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    echo -e "${RED}WARNING: This will completely remove DNSniper from your system.${NC}"
    echo -e "${RED}All configurations, rules, and history will be deleted.${NC}"
    echo -e "${YELLOW}This action cannot be undone!${NC}"
    
    read -rp "Are you SURE you want to uninstall DNSniper? (Type 'yes' to confirm): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${YELLOW}Uninstall cancelled.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Beginning uninstall process...${NC}"
    
    # Stop systemd services if available
    if has_systemd; then
        echo -e "- ${YELLOW}Stopping and disabling systemd services...${NC}"
        systemctl stop dnsniper.timer 2>/dev/null || true
        systemctl disable dnsniper.timer 2>/dev/null || true
        systemctl stop dnsniper.service 2>/dev/null || true
        systemctl disable dnsniper.service 2>/dev/null || true
        
        # Remove systemd files
        rm -f /etc/systemd/system/dnsniper.service 2>/dev/null || true
        rm -f /etc/systemd/system/dnsniper.timer 2>/dev/null || true
        
        # Reload systemd
        systemctl daemon-reload 2>/dev/null || true
    fi
    
    # Kill any running processes
    echo -e "- ${YELLOW}Terminating any running processes...${NC}"
    pkill -f "dnsniper" 2>/dev/null || true
    
    # Clear firewall rules
    echo -e "- ${YELLOW}Cleaning firewall rules...${NC}"
    clean_rules >/dev/null 2>&1 || true
    
    # Remove files
    echo -e "- ${YELLOW}Removing files...${NC}"
    rm -f "/usr/local/bin/dnsniper" 2>/dev/null || true
    rm -f "/usr/local/bin/dnsniper-daemon" 2>/dev/null || true
    rm -rf "/etc/dnsniper" 2>/dev/null || true
    
    # Remove lock files
    rm -f "/var/lock/dnsniper-*.lock" 2>/dev/null || true
    
    echo -e ""
    echo -e "${GREEN}${BOLD}DNSniper has been successfully uninstalled.${NC}"
    echo -e "${YELLOW}Thank you for trying DNSniper.${NC}"
    
    # Optional: Create uninstall log
    local uninstall_log="/tmp/dnsniper-uninstall-$(date +%Y%m%d-%H%M%S).log"
    echo "DNSniper uninstalled at $(date)" > "$uninstall_log"
    echo "Uninstall log saved to: $uninstall_log"
    
    exit 0
}

# Show help message
show_help() {
    echo "DNSniper - Domain-based network threat mitigation tool"
    echo "Version: $VERSION"
    echo ""
    echo "Usage: dnsniper [OPTION]"
    echo ""
    echo "Options:"
    echo "  --run               Run DNSniper daemon (manual execution)"
    echo "  --status            Show current status"
    echo "  --update            Update domain lists"
    echo "  --clean-rules       Clear all firewall rules"
    echo "  --run-silent        Run in silent mode (for systemd service)"
    echo "  --version           Show version information"
    echo "  --help              Show this help message"
    echo ""
    echo "When run without options, starts the interactive menu."
    echo ""
}

# Handle command line arguments
handle_args() {
    case "$1" in
        --run)
            # Run daemon manually
            run_daemon
            return 0
            ;;
        --status)
            # Show status
            show_status
            return 0
            ;;
        --update)
            # Update domains list
            if update_default; then
                echo -e "${GREEN}Domain list updated successfully.${NC}"
            else
                echo -e "${RED}Failed to update domain list.${NC}"
                return 1
            fi
            return 0
            ;;
        --clean-rules)
            # Clean all rules
            if clean_rules; then
                echo -e "${GREEN}All rules cleared successfully.${NC}"
            else
                echo -e "${RED}Failed to clear rules.${NC}"
                return 1
            fi
            return 0
            ;;
        --run-silent)
            # This mode is used by the daemon via systemd/cron
            # Run core functions directly
            ensure_environment
            init_logging
            
            if resolve_and_block; then
                return 0
            else
                return 1
            fi
            ;;
        --version)
            echo "DNSniper version $VERSION"
            return 0
            ;;
        --help)
            show_help
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Main function
main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${BOLD}Error:${NC} This script must be run as root (sudo)."
        exit 1
    fi
    
    # Create base directory if it doesn't exist
    mkdir -p "$BASE_DIR" 2>/dev/null || true
    
    # Process command line arguments
    if [[ $# -gt 0 ]]; then
        if handle_args "$@"; then
            exit 0
        else
            if [[ "$1" != "--help" && "$1" != "--version" ]]; then
                echo -e "${RED}Unknown or invalid command: $1${NC}"
                echo "Try 'dnsniper --help' for more information."
            fi
            exit 1
        fi
    fi
    
    # No arguments, start interactive menu
    ensure_environment
    init_logging
    
    # Run main menu
    main_menu
    
    exit 0
}

# Call main function with all arguments
main "$@"