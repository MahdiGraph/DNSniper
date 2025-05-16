#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Version: 2.0.0

# Base paths 
BASE_DIR="/etc/dnsniper"
CORE_SCRIPT="$BASE_DIR/dnsniper-core.sh"
STATUS_FILE="$BASE_DIR/status.txt"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31mError: This script must be run as root (sudo).\e[0m"
    exit 1
fi

# Check if core script exists
if [[ ! -f "$CORE_SCRIPT" ]]; then
    echo -e "\e[31mError: Core script not found at $CORE_SCRIPT\e[0m"
    echo -e "\e[33mDNSniper may not be properly installed. Please reinstall.\e[0m"
    exit 1
fi

# Source core functions
source "$CORE_SCRIPT"

# UI Lock file
UI_LOCK_FILE="/var/lock/dnsniper-ui.lock"

# Check if another UI session is running
if [[ -f "$UI_LOCK_FILE" ]]; then
    pid=$(cat "$UI_LOCK_FILE" 2>/dev/null || echo "")
    if [[ -n "$pid" ]] && ps -p "$pid" > /dev/null 2>&1; then
        echo -e "${YELLOW}Another DNSniper UI session is running (PID: $pid).${NC}"
        exit 1
    else
        # Stale lock file, remove it
        rm -f "$UI_LOCK_FILE"
    fi
fi

# Create UI lock file and set up cleanup
echo $$ > "$UI_LOCK_FILE"
trap 'rm -f "$UI_LOCK_FILE"' EXIT

# Process command-line arguments
process_args() {
    case "$1" in
        --help)
            show_help
            exit 0
            ;;
        --version)
            echo "DNSniper version $VERSION"
            exit 0
            ;;
        --status)
            show_status
            exit 0
            ;;
        --run)
            run_now
            exit 0
            ;;
        --run-silent)
            # Used by systemd service - direct execution of blocking functionality
            run_dnsniper
            exit $?
            ;;
        --clean-rules)
            clean_rules
            exit 0
            ;;
        --update)
            update_domains
            exit 0
            ;;
        *)
            # No arguments or unknown argument, show menu
            return 1
            ;;
    esac
}

# Show help
show_help() {
    echo "DNSniper - Domain-based Network Threat Mitigation"
    echo "Version: $VERSION"
    echo ""
    echo "Usage: dnsniper [OPTION]"
    echo ""
    echo "Options:"
    echo "  --help           Show this help message"
    echo "  --version        Show version information"
    echo "  --status         Show current status"
    echo "  --run            Run DNSniper once"
    echo "  --clean-rules    Remove all DNSniper firewall rules"
    echo "  --update         Update domains list only"
    echo ""
    echo "When run without options, the interactive menu will be shown."
}

# Run DNSniper function
run_dnsniper() {
    # Set status to running
    echo "RUNNING" > "$STATUS_FILE"
    
    # Update domains if auto-update is enabled
    if is_auto_update_enabled; then
        update_domains
    fi
    
    # Check for expired domains
    check_expired_domains
    
    # Process domains
    process_domains
    
    # Set status to ready
    echo "READY" > "$STATUS_FILE"
    
    return 0
}

# Run now function (manually triggered)
run_now() {
    echo -e "${BLUE}Starting DNSniper in background...${NC}"
    
    # Check if daemon is already running
    if is_daemon_running; then
        echo -e "${YELLOW}DNSniper is already running.${NC}"
        read -rp "Do you want to restart it? [y/N]: " restart
        
        if [[ "$restart" =~ ^[Yy]$ ]]; then
            stop_daemon
            sleep 1
        else
            echo -e "${YELLOW}Operation cancelled. DNSniper will continue its current run.${NC}"
            return
        fi
    fi
    
    # Launch daemon
    echo -e "${GREEN}Starting DNSniper daemon...${NC}"
    nohup "$BIN_DIR/dnsniper-daemon" >/dev/null 2>&1 &
    echo -e "${GREEN}DNSniper started in background.${NC}"
    echo -e "${YELLOW}You can check status with:${NC} sudo dnsniper --status"
}

# Update domains function
update_domains() {
    echo -e "${BLUE}Updating domains list...${NC}"
    
    local update_url=$(get_config_value "update_url" "$DEFAULT_URL")
    local timeout=$(get_config_value "timeout" "$DEFAULT_TIMEOUT")
    
    # Create a temporary file
    local temp_file=$(mktemp)
    
    echo -e "${YELLOW}Downloading from: $update_url${NC}"
    
    # Download with retry logic
    local max_retries=3
    local retry_count=0
    local success=false
    
    while [[ $retry_count -lt $max_retries && $success == false ]]; do
        if curl -sfL --connect-timeout "$timeout" --max-time "$timeout" "$update_url" -o "$temp_file"; then
            success=true
        else
            retry_count=$((retry_count + 1))
            
            if [[ $retry_count -lt $max_retries ]]; then
                echo -e "${YELLOW}Download attempt $retry_count failed, retrying...${NC}"
                sleep 2
            else
                echo -e "${RED}Failed to download domains list after $max_retries attempts.${NC}"
                rm -f "$temp_file"
                return 1
            fi
        fi
    done
    
    # Check if file is not empty
    if [[ -s "$temp_file" ]]; then
        # Move to final location
        mv "$temp_file" "$DEFAULT_FILE"
        echo -e "${GREEN}Domains list updated successfully.${NC}"
        return 0
    else
        echo -e "${RED}Downloaded file is empty.${NC}"
        rm -f "$temp_file"
        return 1
    fi
}

# Clean rules function
clean_rules() {
    echo -e "${BLUE}Cleaning firewall rules...${NC}"
    
    # Clean IPv4 rules
    iptables -D INPUT -j "$IPT_CHAIN" 2>/dev/null || true
    iptables -D OUTPUT -j "$IPT_CHAIN" 2>/dev/null || true
    iptables -F "$IPT_CHAIN" 2>/dev/null || true
    iptables -X "$IPT_CHAIN" 2>/dev/null || true
    
    # Clean IPv6 rules
    ip6tables -D INPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    ip6tables -D OUTPUT -j "$IPT6_CHAIN" 2>/dev/null || true
    ip6tables -F "$IPT6_CHAIN" 2>/dev/null || true
    ip6tables -X "$IPT6_CHAIN" 2>/dev/null || true
    
    # Clean up ipsets if they exist
    if command -v ipset &>/dev/null; then
        ipset destroy "$IPSET4" 2>/dev/null || true
        ipset destroy "$IPSET6" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}Firewall rules cleaned successfully.${NC}"
    return 0
}

# Main menu function
main_menu() {
    while true; do
        show_banner
        
        # Display current status
        local status=$(cat "$STATUS_FILE" 2>/dev/null || echo "UNKNOWN")
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
        local daemon_text="${RED}Not Running${NC}"
        if is_daemon_running; then
            daemon_pid=$(cat "/var/lock/dnsniper-daemon.lock" 2>/dev/null || echo "??")
            daemon_text="${GREEN}Running (PID: $daemon_pid)${NC}"
        fi
        
        # Show status
        echo -e "${CYAN}${BOLD}MAIN MENU${NC} | Status: $status_text | Daemon: $daemon_text"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        echo -e "${YELLOW}1.${NC} Run Now               ${YELLOW}2.${NC} Status"
        echo -e "${YELLOW}3.${NC} Add Domain            ${YELLOW}4.${NC} Remove Domain"
        echo -e "${YELLOW}5.${NC} Add IP Address        ${YELLOW}6.${NC} Remove IP Address"
        echo -e "${YELLOW}7.${NC} Settings              ${YELLOW}8.${NC} Update Lists"
        echo -e "${YELLOW}9.${NC} Backup/Restore        ${YELLOW}0.${NC} Exit"
        echo -e "${YELLOW}C.${NC} Clean Rules           ${YELLOW}U.${NC} Uninstall"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        read -rp "Select an option: " choice
        
        case "$choice" in
            1) run_now; read -rp "Press Enter to continue..." ;;
            2) show_status; read -rp "Press Enter to continue..." ;;
            3) add_domain; read -rp "Press Enter to continue..." ;;
            4) remove_domain; read -rp "Press Enter to continue..." ;;
            5) add_ip; read -rp "Press Enter to continue..." ;;
            6) remove_ip; read -rp "Press Enter to continue..." ;;
            7) settings_menu; read -rp "Press Enter to continue..." ;;
            8) update_domains; read -rp "Press Enter to continue..." ;;
            9) backup_menu; read -rp "Press Enter to continue..." ;;
            0) exit 0 ;;
            [Cc]) clean_rules; read -rp "Press Enter to continue..." ;;
            [Uu]) uninstall; read -rp "Press Enter to continue..." ;;
            *) echo -e "${RED}Invalid selection.${NC}"; sleep 1 ;;
        esac
    done
}

# Main entry point
main() {
    # Initialize logging
    init_logging
    
    # Check if we have command line arguments
    if [[ $# -gt 0 ]]; then
        if process_args "$@"; then
            exit 0
        fi
    fi
    
    # No or invalid arguments, show menu
    main_menu
}

# Run main function
main "$@"
