#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Version: 1.4.0

# Paths
BASE_DIR="/etc/dnsniper"
CONFIG_FILE="$BASE_DIR/config.conf"
STATUS_FILE="$BASE_DIR/status.txt"
LOG_FILE="$BASE_DIR/dnsniper.log"
LOCK_FILE="/var/lock/dnsniper-ui.lock"

# ANSI color codes
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
MAGENTA='\e[35m'
BOLD='\e[1m'
NC='\e[0m'

# Check if lock file exists (another UI process is running)
acquire_ui_lock() {
    if [ -f "$LOCK_FILE" ]; then
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ] && ps -p "$pid" > /dev/null; then
            echo -e "${YELLOW}Another DNSniper UI session is running (PID: $pid).${NC}"
            return 1
        else
            # Stale lock file, remove it
            rm -f "$LOCK_FILE"
        fi
    fi
    
    # Create lock file
    echo $$ > "$LOCK_FILE"
    
    # Set up trap to remove lock file on exit
    trap 'rm -f "$LOCK_FILE"' EXIT
    return 0
}

# Function to get current status
get_status() {
    if [ -f "$STATUS_FILE" ]; then
        cat "$STATUS_FILE"
    else
        echo "UNKNOWN"
    fi
}

# Function to check if daemon is running
is_daemon_running() {
    if [ -f "/var/lock/dnsniper-daemon.lock" ]; then
        daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "")
        if [ -n "$daemon_pid" ] && ps -p "$daemon_pid" > /dev/null; then
            return 0  # Daemon is running
        fi
    fi
    return 1  # Daemon is not running
}

# Display banner
show_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo -e "    ____  _   _ ____       _                 "
    echo -e "   |   _\\| \\ | /_ __|_ __ (_)_ __   ___ _ __ "
    echo -e "   | | | |  \\| \\___ \\ '_ \\| | '_ \\ / _\\ '__|"
    echo -e "   | |_| | |\\  |___) | | | | | |_) |  __/ |  "
    echo -e "   |____/|_| \\_|____/|_| |_|_| .__/ \\___|_|  "
    echo -e "                             |_|              "
    echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v1.4.0 ${NC}"
    echo -e ""
}

# Check if root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${BOLD}Error:${NC} Must run as root (sudo)."
        exit 1
    fi
}

# Show status
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
        daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null)
        echo -e "${BOLD}Background Service:${NC} ${GREEN}Running (PID: $daemon_pid)${NC}"
    else
        echo -e "${BOLD}Background Service:${NC} ${RED}Not Running${NC}"
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

    # Count rules
    local rule_count=$(iptables-save 2>/dev/null | grep -c "DNSniper")
    rule_count=$((rule_count + $(ip6tables-save 2>/dev/null | grep -c "DNSniper")))
    
    echo -e "${BOLD}Domains Monitored:${NC} ${GREEN}${domain_count}${NC}"
    echo -e "${BOLD}Custom IPs:${NC} ${GREEN}${ip_count}${NC}"
    echo -e "${BOLD}Active Rules:${NC} ${RED}${rule_count}${NC}"
    
    # Check scheduling
    local cron_enabled=$(grep -c "dnsniper" /etc/crontab 2>/dev/null || echo "0")
    local systemd_enabled=0
    
    if command -v systemctl &>/dev/null; then
        systemd_enabled=$(systemctl is-enabled dnsniper.timer 2>/dev/null | grep -c "enabled" || echo "0")
    fi
    
    echo -e ""
    echo -e "${CYAN}${BOLD}SCHEDULING${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    if [ "$systemd_enabled" -eq 1 ]; then
        echo -e "${BOLD}Schedule:${NC} ${GREEN}Enabled (systemd timer)${NC}"
        echo -e "${BOLD}Frequency:${NC} ${GREEN}Hourly${NC}"
    elif [ "$cron_enabled" -gt 0 ]; then
        echo -e "${BOLD}Schedule:${NC} ${GREEN}Enabled (cron)${NC}"
        echo -e "${BOLD}Frequency:${NC} ${GREEN}Hourly${NC}"
    else
        echo -e "${BOLD}Schedule:${NC} ${RED}Disabled${NC}"
        echo -e "${BOLD}Frequency:${NC} ${RED}Manual only${NC}"
    fi
    
    # Show last run info
    if [ -f "$LOG_FILE" ]; then
        local last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
        echo -e "${BOLD}Last Run:${NC} ${BLUE}$last_run${NC}"
    else
        echo -e "${BOLD}Last Run:${NC} ${RED}Never${NC}"
    fi
    
    echo -e ""
    echo -e "${YELLOW}To start the daemon manually:${NC} sudo dnsniper-daemon"
    echo -e "${YELLOW}To view the settings menu:${NC} sudo dnsniper"
}

# Run now (manually)
run_now() {
    echo -e "${BLUE}${BOLD}Launching DNSniper daemon...${NC}"
    
    if is_daemon_running; then
        echo -e "${YELLOW}DNSniper daemon is already running.${NC}"
        read -rp "Do you want to restart it? [y/N]: " restart
        
        if [[ "$restart" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Stopping the current daemon...${NC}"
            
            daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null)
            kill $daemon_pid 2>/dev/null
            sleep 1
        else
            echo -e "${YELLOW}Cancelled. Daemon continues to run.${NC}"
            return
        fi
    fi
    
    # Start the daemon process
    echo -e "${GREEN}Starting DNSniper daemon in background...${NC}"
    
    if [ -x /usr/local/bin/dnsniper-daemon ]; then
        nohup /usr/local/bin/dnsniper-daemon > /dev/null 2>&1 &
        bg_pid=$!
        echo -e "${GREEN}DNSniper daemon started with PID: $bg_pid${NC}"
    else
        echo -e "${RED}Error: DNSniper daemon executable not found.${NC}"
    fi
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
            daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null)
            daemon_text="${GREEN}Running (PID: $daemon_pid)${NC}"
        else
            daemon_text="${RED}Not Running${NC}"
        fi
        
        echo -e "${CYAN}${BOLD}Status:${NC} $status_text | ${CYAN}${BOLD}Service:${NC} $daemon_text"
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
            1) run_now; read -rp "Press Enter to continue..." ;;
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

# Add domain
add_domain() {
    show_banner
    echo -e "${CYAN}${BOLD}ADD DOMAIN TO BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter domain to block (e.g., example.com): " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}Error: Domain cannot be empty.${NC}"
        return
    fi
    
    # Simple domain validation
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo -e "${RED}Error: Invalid domain format.${NC}"
        return
    fi
    
    # Check if domain is already in list
    if grep -qx "$domain" "$BASE_DIR/domains-add.txt" 2>/dev/null; then
        echo -e "${YELLOW}Domain $domain is already in block list.${NC}"
        return
    fi
    
    # Add to domains-add.txt
    echo "$domain" >> "$BASE_DIR/domains-add.txt"
    echo -e "${GREEN}Domain $domain added to block list.${NC}"
    
    # Ask if user wants to run the daemon now
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_now
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Remove domain
remove_domain() {
    show_banner
    echo -e "${CYAN}${BOLD}REMOVE DOMAIN FROM BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get list of domains
    local domains_list=$(mktemp)
    
    if [ -f "$BASE_DIR/domains-default.txt" ]; then
        grep -v '^#' "$BASE_DIR/domains-default.txt" | grep -v '^$' >> "$domains_list"
    fi
    
    if [ -f "$BASE_DIR/domains-add.txt" ]; then
        grep -v '^#' "$BASE_DIR/domains-add.txt" | grep -v '^$' >> "$domains_list"
    fi
    
    # Remove any domains that are in the remove list
    if [ -f "$BASE_DIR/domains-remove.txt" ]; then
        local domains_filtered=$(mktemp)
        cat "$domains_list" > "$domains_filtered"
        
        while read -r domain; do
            [ -z "$domain" ] && continue
            sed -i "\|^$domain$|d" "$domains_filtered"
        done < "$BASE_DIR/domains-remove.txt"
        
        mv "$domains_filtered" "$domains_list"
    fi
    
    # Count domains
    local domain_count=$(wc -l < "$domains_list")
    
    if [ "$domain_count" -eq 0 ]; then
        echo -e "${YELLOW}No domains in block list.${NC}"
        rm -f "$domains_list"
        return
    fi
    
    # Show domains
    echo -e "${BLUE}Current domains in block list:${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Only show first 20 domains if there are too many
    if [ "$domain_count" -gt 20 ]; then
        head -20 "$domains_list"
        echo -e "${YELLOW}... and $((domain_count - 20)) more domains${NC}"
    else
        cat "$domains_list"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Enter domain to remove: " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}Error: Domain cannot be empty.${NC}"
        rm -f "$domains_list"
        return
    fi
    
    # Check if domain is in list
    if ! grep -qx "$domain" "$domains_list"; then
        echo -e "${RED}Error: Domain $domain is not in block list.${NC}"
        rm -f "$domains_list"
        return
    fi
    
    # Add to domains-remove.txt
    echo "$domain" >> "$BASE_DIR/domains-remove.txt"
    echo -e "${GREEN}Domain $domain added to remove list.${NC}"
    
    # Clean up
    rm -f "$domains_list"
    
    # Ask if user wants to run the daemon now
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_now
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Add IP
add_ip() {
    show_banner
    echo -e "${CYAN}${BOLD}ADD IP ADDRESS TO BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    read -rp "Enter IP address to block: " ip
    
    if [ -z "$ip" ]; then
        echo -e "${RED}Error: IP address cannot be empty.${NC}"
        return
    fi
    
    # Simple IP validation
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
        echo -e "${RED}Error: Invalid IP format.${NC}"
        return
    fi
    
    # Check if IP is already in list
    if grep -qx "$ip" "$BASE_DIR/ips-add.txt" 2>/dev/null; then
        echo -e "${YELLOW}IP $ip is already in block list.${NC}"
        return
    fi
    
    # Add to ips-add.txt
    echo "$ip" >> "$BASE_DIR/ips-add.txt"
    echo -e "${GREEN}IP $ip added to block list.${NC}"
    
    # Ask if user wants to run the daemon now
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_now
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Remove IP
remove_ip() {
    show_banner
    echo -e "${CYAN}${BOLD}REMOVE IP ADDRESS FROM BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Get list of IPs
    local ips_list=$(mktemp)
    
    if [ -f "$BASE_DIR/ips-add.txt" ]; then
        grep -v '^#' "$BASE_DIR/ips-add.txt" | grep -v '^$' >> "$ips_list"
    fi
    
    # Remove any IPs that are in the remove list
    if [ -f "$BASE_DIR/ips-remove.txt" ]; then
        local ips_filtered=$(mktemp)
        cat "$ips_list" > "$ips_filtered"
        
        while read -r ip; do
            [ -z "$ip" ] && continue
            sed -i "\|^$ip$|d" "$ips_filtered"
        done < "$BASE_DIR/ips-remove.txt"
        
        mv "$ips_filtered" "$ips_list"
    fi
    
    # Count IPs
    local ip_count=$(wc -l < "$ips_list")
    
    if [ "$ip_count" -eq 0 ]; then
        echo -e "${YELLOW}No IPs in block list.${NC}"
        rm -f "$ips_list"
        return
    fi
    
    # Show IPs
    echo -e "${BLUE}Current IPs in block list:${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Only show first 20 IPs if there are too many
    if [ "$ip_count" -gt 20 ]; then
        head -20 "$ips_list"
        echo -e "${YELLOW}... and $((ip_count - 20)) more IPs${NC}"
    else
        cat "$ips_list"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Enter IP to remove: " ip
    
    if [ -z "$ip" ]; then
        echo -e "${RED}Error: IP cannot be empty.${NC}"
        rm -f "$ips_list"
        return
    fi
    
    # Check if IP is in list
    if ! grep -qx "$ip" "$ips_list"; then
        echo -e "${RED}Error: IP $ip is not in block list.${NC}"
        rm -f "$ips_list"
        return
    fi
    
    # Add to ips-remove.txt
    echo "$ip" >> "$BASE_DIR/ips-remove.txt"
    echo -e "${GREEN}IP $ip added to remove list.${NC}"
    
    # Clean up
    rm -f "$ips_list"
    
    # Ask if user wants to run the daemon now
    read -rp "Do you want to apply this change now? [y/N]: " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        run_now
    else
        echo -e "${YELLOW}Change will be applied during the next scheduled run.${NC}"
    fi
}

# Settings menu
settings_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}${BOLD}SETTINGS MENU${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Configure Scheduling"
        echo -e "${YELLOW}2.${NC} Configure Logging"
        echo -e "${YELLOW}3.${NC} Configure Blocking Rules"
        echo -e "${YELLOW}4.${NC} Configure Update Sources"
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) configure_scheduling ;;
            2) configure_logging ;;
            3) configure_rules ;;
            4) configure_sources ;;
            0) return ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# Configure scheduling
configure_scheduling() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE SCHEDULING${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Check current schedule
    local systemd_enabled=0
    local cron_enabled=0
    
    if command -v systemctl &>/dev/null; then
        systemd_enabled=$(systemctl is-enabled dnsniper.timer 2>/dev/null | grep -c "enabled" || echo "0")
    fi
    
    cron_enabled=$(crontab -l 2>/dev/null | grep -c "dnsniper" || echo "0")
    
    if [ "$systemd_enabled" -eq 1 ]; then
        echo -e "${BOLD}Current Schedule:${NC} ${GREEN}Enabled (systemd timer)${NC}"
        echo -e "${BOLD}Frequency:${NC} ${GREEN}Hourly${NC}"
    elif [ "$cron_enabled" -gt 0 ]; then
        echo -e "${BOLD}Current Schedule:${NC} ${GREEN}Enabled (cron)${NC}"
        echo -e "${BOLD}Frequency:${NC} ${GREEN}Hourly${NC}"
    else
        echo -e "${BOLD}Current Schedule:${NC} ${RED}Disabled${NC}"
    fi
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Enable Scheduling (Hourly)"
    echo -e "${YELLOW}2.${NC} Disable Scheduling"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Enable scheduling
            if command -v systemctl &>/dev/null; then
                # Create systemd service and timer
                echo -e "${YELLOW}Setting up systemd timer...${NC}"
                
                # Create systemd service file
                cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dnsniper-daemon
User=root
Group=root
IOSchedulingClass=best-effort
CPUSchedulingPolicy=batch
Nice=19

[Install]
WantedBy=multi-user.target
EOF
                
                # Create systemd timer file
                cat > /etc/systemd/system/dnsniper.timer << EOF
[Unit]
Description=Run DNSniper hourly
Requires=dnsniper.service

[Timer]
Unit=dnsniper.service
OnBootSec=60
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF
                
                # Reload systemd and enable timer
                systemctl daemon-reload
                systemctl enable dnsniper.timer
                systemctl start dnsniper.timer
                
                echo -e "${GREEN}DNSniper scheduled with systemd timer (runs hourly)${NC}"
                
                # Remove any cron jobs
                crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            else
                # Fallback to cron if systemd not available
                echo -e "${YELLOW}Systemd not available, using cron instead...${NC}"
                
                # Create cron job for hourly execution
                (crontab -l 2>/dev/null | grep -v "dnsniper"; echo "0 * * * * /usr/local/bin/dnsniper-daemon >/dev/null 2>&1") | crontab - 2>/dev/null || true
                
                echo -e "${GREEN}DNSniper scheduled with cron (runs hourly)${NC}"
            fi
            
            # Update config file
            sed -i '/^cron=/d' "$CONFIG_FILE" 2>/dev/null || true
            echo "cron='0 * * * * /usr/local/bin/dnsniper-daemon >/dev/null 2>&1'" >> "$CONFIG_FILE"
            ;;
        2)
            # Disable scheduling
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.timer 2>/dev/null || true
                systemctl disable dnsniper.timer 2>/dev/null || true
            fi
            
            # Remove cron jobs
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Update config file
            sed -i '/^cron=/d' "$CONFIG_FILE" 2>/dev/null || true
            echo "cron='# DNSniper disabled'" >> "$CONFIG_FILE"
            
            echo -e "${YELLOW}Automatic scheduling disabled.${NC}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
}

# Configure logging
configure_logging() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE LOGGING${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Check current logging settings
    local logging_enabled=$(grep -c "logging_enabled=1" "$CONFIG_FILE" 2>/dev/null || echo "0")
    local log_max_size=$(grep "log_max_size=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "10")
    local log_rotate_count=$(grep "log_rotate_count=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "5")
    
    if [ "$logging_enabled" -eq 1 ]; then
        echo -e "${BOLD}Logging:${NC} ${GREEN}Enabled${NC}"
    else
        echo -e "${BOLD}Logging:${NC} ${RED}Disabled${NC}"
    fi
    
    echo -e "${BOLD}Log File:${NC} ${BLUE}$LOG_FILE${NC}"
    echo -e "${BOLD}Max Log Size:${NC} ${YELLOW}${log_max_size}MB${NC}"
    echo -e "${BOLD}Rotation Count:${NC} ${YELLOW}${log_rotate_count} files${NC}"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Toggle Logging"
    echo -e "${YELLOW}2.${NC} Change Max Log Size"
    echo -e "${YELLOW}3.${NC} Change Rotation Count"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Toggle logging
            if [ "$logging_enabled" -eq 1 ]; then
                sed -i 's/logging_enabled=1/logging_enabled=0/g' "$CONFIG_FILE"
                echo -e "${YELLOW}Logging disabled.${NC}"
            else
                sed -i 's/logging_enabled=0/logging_enabled=1/g' "$CONFIG_FILE"
                
                # If the line doesn't exist, add it
                if ! grep -q "logging_enabled=" "$CONFIG_FILE"; then
                    echo "logging_enabled=1" >> "$CONFIG_FILE"
                fi
                
                echo -e "${GREEN}Logging enabled.${NC}"
            fi
            ;;
        2)
            # Change max log size
            read -rp "Enter max log size in MB (1-100): " new_size
            
            if [[ "$new_size" =~ ^[0-9]+$ && "$new_size" -ge 1 && "$new_size" -le 100 ]]; then
                sed -i "s/log_max_size=.*/log_max_size=$new_size/g" "$CONFIG_FILE"
                
                # If the line doesn't exist, add it
                if ! grep -q "log_max_size=" "$CONFIG_FILE"; then
                    echo "log_max_size=$new_size" >> "$CONFIG_FILE"
                fi
                
                echo -e "${GREEN}Max log size set to ${new_size}MB.${NC}"
            else
                echo -e "${RED}Invalid input. Please enter a number between 1 and 100.${NC}"
            fi
            ;;
        3)
            # Change rotation count
            read -rp "Enter rotation count (1-20): " new_count
            
            if [[ "$new_count" =~ ^[0-9]+$ && "$new_count" -ge 1 && "$new_count" -le 20 ]]; then
                sed -i "s/log_rotate_count=.*/log_rotate_count=$new_count/g" "$CONFIG_FILE"
                
                # If the line doesn't exist, add it
                if ! grep -q "log_rotate_count=" "$CONFIG_FILE"; then
                    echo "log_rotate_count=$new_count" >> "$CONFIG_FILE"
                fi
                
                echo -e "${GREEN}Rotation count set to $new_count.${NC}"
            else
                echo -e "${RED}Invalid input. Please enter a number between 1 and 20.${NC}"
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

# Configure blocking rules
configure_rules() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE BLOCKING RULES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Check current rule settings
    local block_source=$(grep "block_source=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "1")
    local block_destination=$(grep "block_destination=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "1")
    
    echo -e "${BOLD}Block Source Traffic:${NC} $([ "$block_source" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BOLD}Block Destination Traffic:${NC} $([ "$block_destination" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Toggle Source Blocking"
    echo -e "${YELLOW}2.${NC} Toggle Destination Blocking"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Toggle source blocking
            if [ "$block_source" -eq 1 ]; then
                sed -i 's/block_source=1/block_source=0/g' "$CONFIG_FILE"
                echo -e "${YELLOW}Source traffic blocking disabled.${NC}"
            else
                sed -i 's/block_source=0/block_source=1/g' "$CONFIG_FILE"
                
                # If the line doesn't exist, add it
                if ! grep -q "block_source=" "$CONFIG_FILE"; then
                    echo "block_source=1" >> "$CONFIG_FILE"
                fi
                
                echo -e "${GREEN}Source traffic blocking enabled.${NC}"
            fi
            
            # Warn about needing to run to apply changes
            echo -e "${YELLOW}Note: You need to run DNSniper for changes to take effect.${NC}"
            ;;
        2)
            # Toggle destination blocking
            if [ "$block_destination" -eq 1 ]; then
                sed -i 's/block_destination=1/block_destination=0/g' "$CONFIG_FILE"
                echo -e "${YELLOW}Destination traffic blocking disabled.${NC}"
            else
                sed -i 's/block_destination=0/block_destination=1/g' "$CONFIG_FILE"
                
                # If the line doesn't exist, add it
                if ! grep -q "block_destination=" "$CONFIG_FILE"; then
                    echo "block_destination=1" >> "$CONFIG_FILE"
                fi
                
                echo -e "${GREEN}Destination traffic blocking enabled.${NC}"
            fi
            
            # Warn about needing to run to apply changes
            echo -e "${YELLOW}Note: You need to run DNSniper for changes to take effect.${NC}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
}

# Configure update sources
configure_sources() {
    show_banner
    echo -e "${CYAN}${BOLD}CONFIGURE UPDATE SOURCES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Check current settings
    local update_url=$(grep "update_url=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d "'" || echo "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt")
    local auto_update=$(grep "auto_update=" "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "1")
    
    echo -e "${BOLD}Update URL:${NC} ${BLUE}$update_url${NC}"
    echo -e "${BOLD}Auto Update:${NC} $([ "$auto_update" -eq 1 ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}1.${NC} Change Update URL"
    echo -e "${YELLOW}2.${NC} Toggle Auto Update"
    echo -e "${YELLOW}3.${NC} Update Now"
    echo -e "${YELLOW}0.${NC} Back to Settings"
    
    read -rp "Select an option: " choice
    
    case "$choice" in
        1)
            # Change update URL
            read -rp "Enter new update URL: " new_url
            
            if [[ "$new_url" =~ ^https?:// ]]; then
                sed -i "s|update_url=.*|update_url='$new_url'|g" "$CONFIG_FILE"
                
                # If the line doesn't exist, add it
                if ! grep -q "update_url=" "$CONFIG_FILE"; then
                    echo "update_url='$new_url'" >> "$CONFIG_FILE"
                fi
                
                echo -e "${GREEN}Update URL changed to: $new_url${NC}"
            else
                echo -e "${RED}Invalid URL. Must start with http:// or https://${NC}"
            fi
            ;;
        2)
            # Toggle auto update
            if [ "$auto_update" -eq 1 ]; then
                sed -i 's/auto_update=1/auto_update=0/g' "$CONFIG_FILE"
                echo -e "${YELLOW}Auto update disabled.${NC}"
            else
                sed -i 's/auto_update=0/auto_update=1/g' "$CONFIG_FILE"
                
                # If the line doesn't exist, add it
                if ! grep -q "auto_update=" "$CONFIG_FILE"; then
                    echo "auto_update=1" >> "$CONFIG_FILE"
                fi
                
                echo -e "${GREEN}Auto update enabled.${NC}"
            fi
            ;;
        3)
            # Update now
            echo -e "${BLUE}Updating domain list from: $update_url${NC}"
            
            # Use curl to download the list
            local temp_file=$(mktemp)
            
            if curl -sfL --connect-timeout 30 --max-time 60 "$update_url" -o "$temp_file"; then
                # Check if file is not empty
                if [ -s "$temp_file" ]; then
                    cp "$temp_file" "$BASE_DIR/domains-default.txt"
                    echo -e "${GREEN}Domain list updated successfully.${NC}"
                    
                    # Ask if user wants to run the daemon now
                    read -rp "Do you want to apply this update now? [y/N]: " run_now
                    
                    if [[ "$run_now" =~ ^[Yy]$ ]]; then
                        run_now
                    else
                        echo -e "${YELLOW}Update will be applied during the next scheduled run.${NC}"
                    fi
                else
                    echo -e "${RED}Downloaded file is empty.${NC}"
                fi
            else
                echo -e "${RED}Failed to download from: $update_url${NC}"
            fi
            
            # Clean up
            rm -f "$temp_file"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid selection.${NC}"
            ;;
    esac
}

# Lists management menu
manage_lists() {
    while true; do
        show_banner
        echo -e "${CYAN}${BOLD}MANAGE LISTS${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} View Domain Lists"
        echo -e "${YELLOW}2.${NC} View IP Lists"
        echo -e "${YELLOW}3.${NC} Import Domains"
        echo -e "${YELLOW}4.${NC} Import IPs"
        echo -e "${YELLOW}5.${NC} Export Domains"
        echo -e "${YELLOW}6.${NC} Export IPs"
        echo -e "${YELLOW}7.${NC} Clear All Lists"
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) view_domains ;;
            2) view_ips ;;
            3) import_domains ;;
            4) import_ips ;;
            5) export_domains ;;
            6) export_ips ;;
            7) clear_lists ;;
            0) return ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
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

# Uninstall
uninstall() {
    show_banner
    echo -e "${RED}${BOLD}UNINSTALL DNSNIPER${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${RED}WARNING: This will completely remove DNSniper from your system.${NC}"
    echo -e "${YELLOW}All configurations and rules will be removed.${NC}"
    
    read -rp "Are you sure you want to uninstall DNSniper? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Uninstall cancelled.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Uninstalling DNSniper...${NC}"
    
    # Kill any running processes
    pkill -f "dnsniper" 2>/dev/null || true
    
    # Remove systemd services
    if command -v systemctl &>/dev/null; then
        systemctl stop dnsniper.timer 2>/dev/null || true
        systemctl disable dnsniper.timer 2>/dev/null || true
        systemctl disable dnsniper.service 2>/dev/null || true
        
        rm -f /etc/systemd/system/dnsniper.service 2>/dev/null || true
        rm -f /etc/systemd/system/dnsniper.timer 2>/dev/null || true
        
        # Also remove old style services if they exist
        systemctl stop dnsniper-firewall.service 2>/dev/null || true
        systemctl disable dnsniper-firewall.service 2>/dev/null || true
        rm -f /etc/systemd/system/dnsniper-firewall.service 2>/dev/null || true
        
        systemctl daemon-reload 2>/dev/null || true
    fi
    
    # Remove cron jobs
    crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
    
    # Clean up firewall rules
    echo -e "${YELLOW}Cleaning firewall rules...${NC}"
    
    # Remove DNSniper chains from iptables
    iptables -D INPUT -j DNSniper 2>/dev/null || true
    iptables -D OUTPUT -j DNSniper 2>/dev/null || true
    ip6tables -D INPUT -j DNSniper6 2>/dev/null || true
    ip6tables -D OUTPUT -j DNSniper6 2>/dev/null || true
    
    # Flush and delete chains
    iptables -F DNSniper 2>/dev/null || true
    iptables -X DNSniper 2>/dev/null || true
    ip6tables -F DNSniper6 2>/dev/null || true
    ip6tables -X DNSniper6 2>/dev/null || true
    
    # Make rules persistent
    if [[ -f /etc/debian_version ]]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    elif [[ -f /etc/redhat-release || -f /etc/fedora-release ]]; then
        if [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
        fi
    fi
    
    # Remove binaries and directories
    rm -f /usr/local/bin/dnsniper /usr/local/bin/dnsniper-daemon 2>/dev/null || true
    rm -rf /etc/dnsniper 2>/dev/null || true
    
    # Remove lock files
    rm -f /var/lock/dnsniper-*.lock 2>/dev/null || true
    
    echo -e "${GREEN}DNSniper has been successfully uninstalled.${NC}"
    echo -e "${YELLOW}Thank you for using DNSniper!${NC}"
    
    # Exit immediately after uninstall
    exit 0
}

# Command line arguments handling
handle_cli_args() {
    case "$1" in
        --help)
            show_help
            exit 0
            ;;
        --version)
            echo "DNSniper version 1.4.0"
            exit 0
            ;;
        --status)
            check_root
            show_status
            exit 0
            ;;
        --run)
            check_root
            run_now
            exit 0
            ;;
        --run-silent)
            # This is used by the daemon and should not be called directly
            check_root
            # Code for silent run would be here in the real implementation
            exit 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Show help
show_help() {
    echo "DNSniper - Domain-based threat mitigation via iptables"
    echo "Version: 1.4.0"
    echo ""
    echo "Usage: dnsniper [OPTION]"
    echo ""
    echo "Options:"
    echo "  --help        Show this help message"
    echo "  --version     Show version information"
    echo "  --status      Show current status"
    echo "  --run         Run the daemon manually"
    echo ""
    echo "With no options, starts the interactive menu."
}

# Main function
main() {
    # Check if running as root
    check_root
    
    # Handle command line arguments if provided
    if [ $# -gt 0 ]; then
        if handle_cli_args "$@"; then
            exit 0
        fi
    fi
    
    # Try to acquire the UI lock
    if ! acquire_ui_lock; then
        echo -e "${RED}Another DNSniper UI session is already running.${NC}"
        exit 1
    fi
    
    # Start interactive menu
    main_menu
}

# Call main with all arguments
main "$@"