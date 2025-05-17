#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.2

# Source the core and daemon functionality
if [[ -f /etc/dnsniper/dnsniper-core.sh ]]; then
    source /etc/dnsniper/dnsniper-core.sh
else
    echo "Error: Core DNSniper functionality not found" >&2
    exit 1
fi

if [[ -f /etc/dnsniper/dnsniper-daemon.sh ]]; then
    source /etc/dnsniper/dnsniper-daemon.sh
else
    echo "Error: DNSniper daemon functionality not found" >&2
    exit 1
fi

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

# IMPROVED: Non-blocking background process check
check_background_process() {
    # Check for running background process without blocking the UI
    local bg_status=$(is_background_process_running)
    local IFS="|"
    read -r is_running pid start_time cmd <<< "$bg_status"
    
    if [[ "$is_running" == "1" ]]; then
        # Show a notification but always continue with menu
        echo -e "${YELLOW}${BOLD}Note:${NC} A DNSniper process (PID: $pid) is running in the background."
        echo -e "Started: ${YELLOW}$start_time${NC}"
        
        # Check if we have status information
        if [[ -f "$STATUS_FILE" ]]; then
            local status_data=$(get_status)
            local status=$(echo "$status_data" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            local message=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            local progress=$(echo "$status_data" | grep -o '"progress":[^,}]*' | cut -d':' -f2)
            local eta=$(echo "$status_data" | grep -o '"eta":[^,}]*' | cut -d':' -f2)
            
            # Format ETA if available
            local eta_text=""
            if [[ $eta -gt 0 ]]; then
                if [[ $eta -gt 3600 ]]; then
                    eta_text="$(($eta / 3600))h $(($eta % 3600 / 60))m"
                elif [[ $eta -gt 60 ]]; then
                    eta_text="$(($eta / 60))m $(($eta % 60))s"
                else
                    eta_text="${eta}s"
                fi
                eta_text=" (ETA: ${eta_text})"
            fi
            
            echo -e "Status: ${CYAN}${status}${NC} - ${YELLOW}${message}${NC} - ${GREEN}${progress}%${YELLOW}${eta_text}${NC}"
        fi
        
        echo -e "${BLUE}You can use the menu while the process is running.${NC}"
        echo -e "${BLUE}Some operations will be limited until the background process completes.${NC}"
        echo -e "${BLUE}Choose '2' to view detailed status.${NC}"
        echo -e ""
        
        # Return true to indicate a background process is running
        return 0
    fi
    
    # Return false to indicate no background process is running
    return 1
}

# IMPROVED MENU: Always responsive and more intuitive
main_menu() {
    local bg_running=false
    
    while true; do
        show_banner
        
        # Check if a background process is running
        if check_background_process; then
            bg_running=true
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        else
            bg_running=false
        fi
        
        echo -e "${CYAN}${BOLD}MAIN MENU${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Run Now              ${YELLOW}2.${NC} Status"
        echo -e "${YELLOW}3.${NC} Block Domain         ${YELLOW}4.${NC} Add Domain to Whitelist"
        echo -e "${YELLOW}5.${NC} Block IP Address     ${YELLOW}6.${NC} Add IP to Whitelist"
        echo -e "${YELLOW}7.${NC} Settings             ${YELLOW}8.${NC} Update Lists"
        echo -e "${YELLOW}9.${NC} Clear Rules          ${YELLOW}0.${NC} Exit"
        echo -e "${YELLOW}U.${NC} Uninstall"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        # Use read with timeout to make menu more responsive
        read -t 2 -rp "Select an option: " choice
        
        # If read timed out, check if background process finished and refresh
        if [[ $? -gt 128 ]]; then
            if $bg_running; then
                # Check if process is still running
                if ! is_background_process_running | grep -q "^1|"; then
                    clear
                    echo -e "${GREEN}Background process completed.${NC}"
                    sleep 1
                fi
            fi
            continue
        fi
        
        case "$choice" in
            1)
                clear
                if $bg_running; then
                    echo -e "${YELLOW}A background process is already running.${NC}"
                    echo -e "${YELLOW}Please wait for it to complete or check status.${NC}"
                else
                    echo -e "${BLUE}Starting DNSniper...${NC}"
                    # Run in background to avoid hanging the menu
                    nohup bash -c 'source /etc/dnsniper/dnsniper-daemon.sh && run_with_lock' >/dev/null 2>&1 &
                    echo -e "${GREEN}DNSniper is now running in the background.${NC}"
                    echo -e "${GREEN}You can continue using the menu or check status.${NC}"
                fi
                read -rp "Press Enter to continue..."
                ;;
                
            2) 
                display_status
                read -rp "Press Enter to continue..."
                ;;
                
            3) 
                clear
                block_domain
                read -rp "Press Enter to continue..."
                ;;
                
            4) 
                clear
                whitelist_domain 
                read -rp "Press Enter to continue..."
                ;;
                
            5) 
                clear
                block_custom_ip
                read -rp "Press Enter to continue..."
                ;;
                
            6) 
                clear
                whitelist_custom_ip
                read -rp "Press Enter to continue..."
                ;;
                
            7) 
                settings_menu
                ;;
                
            8)
                clear
                if $bg_running; then
                    echo -e "${YELLOW}A background process is already running.${NC}"
                    echo -e "${YELLOW}Please wait for it to complete before updating lists.${NC}"
                else
                    echo -e "${BLUE}Updating default domain lists...${NC}"
                    # Run in background with non-blocking behavior
                    nohup bash -c 'source /etc/dnsniper/dnsniper-core.sh && nice -n 10 update_default' >/dev/null 2>&1 &
                    echo -e "${GREEN}Update started in background.${NC}"
                    echo -e "${GREEN}You can check status to monitor progress.${NC}"
                fi
                read -rp "Press Enter to continue..."
                ;;
                
            9)
                clear
                if $bg_running; then
                    echo -e "${YELLOW}A background process is already running.${NC}"
                    echo -e "${YELLOW}Please wait for it to complete before clearing rules.${NC}"
                else
                    clear_rules
                fi
                read -rp "Press Enter to continue..."
                ;;
                
            0) 
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
                
            [Uu]) 
                clear
                uninstall
                ;;
                
            *) 
                echo -e "${RED}Invalid selection. Please choose from the menu.${NC}"
                sleep 1
                ;;
        esac
    done
}

### Interactive menu functions
# --- Settings submenu ---
settings_menu() {
    while true; do
        show_banner
        
        # Check if a background process is running
        local bg_running=false
        if check_background_process; then
            bg_running=true
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        fi
        
        echo -e "${BLUE}${BOLD}SETTINGS${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Set Schedule"
        echo -e "${YELLOW}2.${NC} Set Max IPs Per Domain"
        echo -e "${YELLOW}3.${NC} Set Timeout"
        echo -e "${YELLOW}4.${NC} Set Update URL"
        echo -e "${YELLOW}5.${NC} Toggle Auto-Update"
        echo -e "${YELLOW}6.${NC} Import/Export"
        echo -e "${YELLOW}7.${NC} Rule Expiration Settings"
        echo -e "${YELLOW}8.${NC} Block Rule Types"
        echo -e "${YELLOW}9.${NC} Toggle Logging"
        echo -e "${YELLOW}S.${NC} Service Management"
        echo -e "${YELLOW}P.${NC} Process Management"
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        # Use read with timeout to make menu more responsive
        read -t 2 -rp "Select option: " choice
        
        # If read timed out, check if background process finished and refresh
        if [[ $? -gt 128 ]]; then
            if $bg_running; then
                # Check if process is still running
                if ! is_background_process_running | grep -q "^1|"; then
                    clear
                    echo -e "${GREEN}Background process completed.${NC}"
                    sleep 1
                fi
            fi
            continue
        fi
        
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
            [Ss]) service_management_menu ;;
            [Pp]) process_management ;;
            0) return ;;
            *)
                if [[ -n "$choice" ]]; then
                    echo -e "${RED}Invalid selection. Please choose 0-9, S, or P.${NC}"
                    sleep 1
                fi
                ;;
        esac
    done
}

# IMPROVED Process management function with better handling
process_management() {
    echo -e "${BOLD}=== Process Management ===${NC}"
    # Check for running background process
    local bg_status=$(is_background_process_running)
    local IFS="|"
    read -r is_running pid start_time cmd <<< "$bg_status"
    
    if [[ "$is_running" == "1" ]]; then
        echo -e "${YELLOW}Background process is running:${NC}"
        echo -e "  ${BOLD}PID:${NC} $pid"
        echo -e "  ${BOLD}Started:${NC} $start_time"
        echo -e "  ${BOLD}Command:${NC} $cmd"
        
        # Show status if available
        if [[ -f "$STATUS_FILE" ]]; then
            local status_data=$(get_status)
            local status=$(echo "$status_data" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            local message=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            local progress=$(echo "$status_data" | grep -o '"progress":[^,}]*' | cut -d':' -f2)
            
            echo -e "  ${BOLD}Status:${NC} $status"
            echo -e "  ${BOLD}Progress:${NC} ${progress}%"
            echo -e "  ${BOLD}Message:${NC} $message"
        fi
        
        echo -e ""
        echo -e "What would you like to do?"
        echo -e "1. ${BOLD}Monitor${NC} process progress"
        echo -e "2. ${BOLD}Terminate${NC} process"
        echo -e "3. ${BOLD}Back${NC} to settings menu"
        
        read -rp "Choice (1-3): " proc_choice
        
        case "$proc_choice" in
            1)
                echo -e "${BLUE}Monitoring process progress (Press Ctrl+C to stop monitoring)...${NC}"
                # Monitor progress in a loop until user presses Ctrl+C
                trap 'break' INT
                
                while kill -0 "$pid" 2>/dev/null; do
                    if [[ -f "$PROGRESS_FILE" ]]; then
                        clear
                        echo -e "${CYAN}${BOLD}DNSniper Process Monitor${NC}"
                        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                        echo -e "${BOLD}PID:${NC} $pid"
                        echo -e "${BOLD}Started:${NC} $start_time"
                        echo -e "${BOLD}Status:${NC}"
                        cat "$PROGRESS_FILE"
                        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                        echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
                    else
                        echo -e "${YELLOW}Waiting for status update...${NC}"
                    fi
                    sleep 0.5
                done
                
                trap - INT
                echo -e "${GREEN}Process completed or no longer running.${NC}"
                ;;
                
            2)
                echo -e "${YELLOW}Terminating process $pid...${NC}"
                # Try SIGTERM first (more graceful)
                kill "$pid" 2>/dev/null
                
                # Wait up to 5 seconds for process to terminate
                for i in {1..10}; do
                    if ! kill -0 "$pid" 2>/dev/null; then
                        break
                    fi
                    sleep 0.5
                done
                
                # If still running, try stronger signal
                if kill -0 "$pid" 2>/dev/null; then
                    echo -e "${YELLOW}Still running, using SIGKILL...${NC}"
                    kill -9 "$pid" 2>/dev/null
                    sleep 1
                fi
                
                if ! kill -0 "$pid" 2>/dev/null; then
                    rm -f "$LOCK_FILE" 2>/dev/null || true
                    echo -e "${GREEN}Process terminated successfully.${NC}"
                    update_status "terminated" "Process terminated by user" "0" "0"
                else
                    echo -e "${RED}Failed to terminate process.${NC}"
                fi
                ;;
                
            3|*)
                echo -e "${YELLOW}Returning to settings menu.${NC}"
                ;;
        esac
    else
        echo -e "${GREEN}No background processes are currently running.${NC}"
        
        # Check for stale lock file
        if [[ -f "$LOCK_FILE" ]]; then
            local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "Unknown")
            echo -e "${YELLOW}Found stale lock file for PID: $lock_pid${NC}"
            read -rp "Remove stale lock file? [Y/n]: " remove_lock
            
            if [[ ! "$remove_lock" =~ ^[Nn] ]]; then
                rm -f "$LOCK_FILE" 2>/dev/null || true
                echo -e "${GREEN}Stale lock file removed.${NC}"
            fi
        fi
        
        # Show recent status if available
        if [[ -f "$STATUS_FILE" ]]; then
            local status_data=$(get_status)
            local status=$(echo "$status_data" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            local message=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            local timestamp=$(echo "$status_data" | grep -o '"formatted_time":"[^"]*"' | cut -d'"' -f4)
            
            echo -e "${BLUE}Last process status:${NC}"
            echo -e "  ${BOLD}Status:${NC} $status"
            echo -e "  ${BOLD}Message:${NC} $message"
            echo -e "  ${BOLD}Time:${NC} $timestamp"
        fi
    fi
    
    read -rp "Press Enter to continue..."
}

service_management_menu() {
    while true; do
        show_banner
        
        # Check if a background process is running
        local bg_running=false
        if check_background_process; then
            bg_running=true
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        fi
        
        echo -e "${BLUE}${BOLD}SERVICE MANAGEMENT${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        # Get service status
        local service_status=$(get_service_status)
        echo -e "${service_status}"
        echo -e ""
        
        echo -e "${YELLOW}1.${NC} Restart Firewall Service"
        echo -e "${YELLOW}2.${NC} Restart Timer Service"
        echo -e "${YELLOW}3.${NC} Reload Rules Files"
        echo -e "${YELLOW}4.${NC} Enable/Start All Services"
        echo -e "${YELLOW}5.${NC} Clean Stale Lock Files"
        echo -e "${YELLOW}0.${NC} Back to Settings"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        # Use read with timeout to make menu more responsive
        read -t 2 -rp "Select option: " choice
        
        # If read timed out, check if background process finished and refresh
        if [[ $? -gt 128 ]]; then
            if $bg_running; then
                # Check if process is still running
                if ! is_background_process_running | grep -q "^1|"; then
                    clear
                    echo -e "${GREEN}Background process completed.${NC}"
                    sleep 1
                fi
            fi
            continue
        fi
        
        case "$choice" in
            1)
                echo -e "${BLUE}Restarting Firewall Service...${NC}"
                systemctl restart dnsniper-firewall.service
                echo -e "${GREEN}Done!${NC}"
                read -rp "Press Enter to continue..."
                ;;
                
            2)
                echo -e "${BLUE}Restarting Timer Service...${NC}"
                systemctl restart dnsniper.timer
                echo -e "${GREEN}Done!${NC}"
                read -rp "Press Enter to continue..."
                ;;
                
            3)
                echo -e "${BLUE}Ensuring rules files exist...${NC}"
                # Make sure rules files exist with minimum valid content
                echo "*filter" > "$RULES_V4_FILE"
                echo ":INPUT ACCEPT [0:0]" >> "$RULES_V4_FILE"
                echo ":FORWARD ACCEPT [0:0]" >> "$RULES_V4_FILE"
                echo ":OUTPUT ACCEPT [0:0]" >> "$RULES_V4_FILE"
                echo ":$IPT_CHAIN - [0:0]" >> "$RULES_V4_FILE"
                echo "COMMIT" >> "$RULES_V4_FILE"
                
                echo "*filter" > "$RULES_V6_FILE"
                echo ":INPUT ACCEPT [0:0]" >> "$RULES_V6_FILE"
                echo ":FORWARD ACCEPT [0:0]" >> "$RULES_V6_FILE"
                echo ":OUTPUT ACCEPT [0:0]" >> "$RULES_V6_FILE"
                echo ":$IPT6_CHAIN - [0:0]" >> "$RULES_V6_FILE"
                echo "COMMIT" >> "$RULES_V6_FILE"
                
                echo -e "${BLUE}Saving current firewall rules...${NC}"
                make_rules_persistent
                
                echo -e "${BLUE}Restarting Firewall Service...${NC}"
                systemctl restart dnsniper-firewall.service
                echo -e "${GREEN}Done!${NC}"
                read -rp "Press Enter to continue..."
                ;;
                
            4)
                echo -e "${BLUE}Enabling and starting all services...${NC}"
                systemctl enable dnsniper-firewall.service
                systemctl start dnsniper-firewall.service
                systemctl enable dnsniper.service
                
                local scheduler_enabled=$(grep '^scheduler_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
                if [[ "$scheduler_enabled" == "1" ]]; then
                    systemctl enable dnsniper.timer
                    systemctl start dnsniper.timer
                fi
                
                echo -e "${GREEN}All services enabled and started!${NC}"
                read -rp "Press Enter to continue..."
                ;;
                
            5)
                echo -e "${BLUE}Checking for stale lock files...${NC}"
                if [[ -f "$LOCK_FILE" ]]; then
                    local pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
                    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
                        rm -f "$LOCK_FILE"
                        echo -e "${GREEN}Removed stale lock file.${NC}"
                    else
                        echo -e "${YELLOW}Lock file belongs to active process $pid. Not removing.${NC}"
                    fi
                else
                    echo -e "${GREEN}No lock files found.${NC}"
                fi
                read -rp "Press Enter to continue..."
                ;;
                
            0)
                return
                ;;
                
            *)
                if [[ -n "$choice" ]]; then
                    echo -e "${RED}Invalid selection. Please choose 0-5.${NC}"
                    sleep 1
                fi
                ;;
        esac
    done
}

# Toggle logging function
toggle_logging() {
    echo -e "${BOLD}=== Toggle Logging ===${NC}"
    if [[ $LOGGING_ENABLED -eq 1 ]]; then
        echo -e "${BLUE}Logging is currently:${NC} ${GREEN}Enabled${NC}"
        echo -e "${YELLOW}Note:${NC} Logs are stored in $LOG_FILE"
        read -rp "Disable logging? [y/N]: " choice
        
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^logging_enabled=.*|logging_enabled=0|" "$CONFIG_FILE"
            LOGGING_ENABLED=0
            echo -e "${YELLOW}Logging disabled.${NC}"
            log "INFO" "Logging disabled by user"
        else
            echo -e "${YELLOW}No change.${NC}"
        fi
    else
        echo -e "${BLUE}Logging is currently:${NC} ${RED}Disabled${NC}"
        echo -e "${YELLOW}Note:${NC} Logs will be stored in $LOG_FILE when enabled"
        read -rp "Enable logging? [y/N]: " choice
        
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^logging_enabled=.*|logging_enabled=1|" "$CONFIG_FILE"
            LOGGING_ENABLED=1
            echo -e "${GREEN}Logging enabled.${NC}"
            log "INFO" "Logging enabled by user"
        else
            echo -e "${YELLOW}No change.${NC}"
        fi
    fi
    
    # Check log rotation
    echo -e ""
    if [[ $LOGGING_ENABLED -eq 1 ]]; then
        echo -e "${BLUE}Log rotation:${NC}"
        if [[ -f "$LOG_FILE" ]]; then
            local log_size=$(du -h "$LOG_FILE" | cut -f1)
            echo -e "Current log size: ${YELLOW}$log_size${NC}"
            
            if [[ $(du -b "$LOG_FILE" | cut -f1) -gt 1048576 ]]; then # 1MB
                read -rp "Log file is large. Rotate it now? [y/N]: " rotate
                if [[ "$rotate" =~ ^[Yy] ]]; then
                    # Create backup with timestamp
                    local backup="$LOG_FILE.$(date +%Y%m%d-%H%M%S)"
                    cp "$LOG_FILE" "$backup"
                    echo "" > "$LOG_FILE"
                    log "INFO" "Log rotated. Previous log saved as $backup"
                    echo -e "${GREEN}Log rotated. Backup saved as $backup${NC}"
                fi
            fi
        else
            echo -e "No log file exists yet."
        fi
    fi
}

# Rule expiration settings
expiration_settings() {
    echo -e "${BOLD}=== Rule Expiration Settings ===${NC}"
    # Get current settings
    local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    
    # Validate settings, use defaults if invalid
    [[ -z "$expire_enabled" || ! "$expire_enabled" =~ ^[01]$ ]] && expire_enabled=$DEFAULT_EXPIRE_ENABLED
    [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]] && expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
    
    # Get schedule to determine update frequency
    local schedule_minutes=$(grep '^schedule_minutes=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    [[ -z "$schedule_minutes" || ! "$schedule_minutes" =~ ^[0-9]+$ ]] && schedule_minutes=$DEFAULT_SCHEDULE_MINUTES
    
    # Calculate actual expiration time
    local expire_minutes=$((schedule_minutes * expire_multiplier))
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
        echo -e "${BLUE}Rule expiration:${NC} ${GREEN}Enabled${NC}"
        echo -e "${BLUE}Current expiration time:${NC} ${YELLOW}$expire_display${NC} ($expire_multiplier x update frequency)"
        echo -e "\n${YELLOW}Note:${NC} Rule expiration only applies to domains from the default list, not custom domains."
        echo -e "Expired rules are automatically removed after the specified time."
        
        # Ask to toggle
        read -rp "Disable rule expiration? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^expire_enabled=.*|expire_enabled=0|" "$CONFIG_FILE"
            echo -e "${YELLOW}Rule expiration disabled.${NC}"
            log "INFO" "Rule expiration disabled by user" "verbose"
        else
            # If not disabling, ask to change multiplier
            read -rp "Change expiration multiplier? (current: $expire_multiplier) [y/N]: " change_mult
            if [[ "$change_mult" =~ ^[Yy] ]]; then
                read -rp "New multiplier (1-100): " new_mult
                if [[ "$new_mult" =~ ^[0-9]+$ && $new_mult -ge 1 && $new_mult -le 100 ]]; then
                    sed -i "s|^expire_multiplier=.*|expire_multiplier=$new_mult|" "$CONFIG_FILE"
                    
                    # Calculate new expiration time
                    local new_expire_minutes=$((schedule_minutes * new_mult))
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
                    
                    echo -e "${GREEN}Expiration multiplier set to $new_mult (${new_expire_display}).${NC}"
                    log "INFO" "Expiration multiplier updated to $new_mult" "verbose"
                else
                    echo -e "${RED}Invalid input. Please enter a number between 1 and 100.${NC}"
                fi
            else
                echo -e "${YELLOW}No change.${NC}"
            fi
        fi
    else
        echo -e "${BLUE}Rule expiration:${NC} ${RED}Disabled${NC}"
        echo -e "${BLUE}Default expiration time:${NC} ${YELLOW}$expire_display${NC} ($expire_multiplier x update frequency)"
        echo -e "\n${YELLOW}Note:${NC} When enabled, rule expiration only applies to domains from the default list."
        read -rp "Enable rule expiration? [y/N]: " choice
        
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^expire_enabled=.*|expire_enabled=1|" "$CONFIG_FILE"
            echo -e "${GREEN}Rule expiration enabled.${NC}"
            log "INFO" "Rule expiration enabled by user" "verbose"
            
            # Ask to change multiplier
            read -rp "Change expiration multiplier? (current: $expire_multiplier) [y/N]: " change_mult
            if [[ "$change_mult" =~ ^[Yy] ]]; then
                read -rp "New multiplier (1-100): " new_mult
                if [[ "$new_mult" =~ ^[0-9]+$ && $new_mult -ge 1 && $new_mult -le 100 ]]; then
                    sed -i "s|^expire_multiplier=.*|expire_multiplier=$new_mult|" "$CONFIG_FILE"
                    
                    # Calculate new expiration time
                    local new_expire_minutes=$((schedule_minutes * new_mult))
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
                    
                    echo -e "${GREEN}Expiration multiplier set to $new_mult (${new_expire_display}).${NC}"
                    log "INFO" "Expiration multiplier updated to $new_mult" "verbose"
                else
                    echo -e "${RED}Invalid input. Please enter a number between 1 and 100.${NC}"
                fi
            fi
        else
            echo -e "${YELLOW}No change.${NC}"
        fi
    fi
}

# Rule types settings
rule_types_settings() {
    local need_apply=0
    echo -e "${BOLD}=== Block Rule Types ===${NC}"
    
    # Get current settings
    local block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    
    # Validate settings, use defaults if invalid
    [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
    [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
    
    # Display current settings
    echo -e "${BLUE}Current rule types:${NC}"
    echo -e "  ${block_source:+${GREEN}✓${NC}}${block_source:=${RED}✗${NC}} Source IPs      (block traffic FROM malicious IPs)"
    echo -e "  ${block_destination:+${GREEN}✓${NC}}${block_destination:=${RED}✗${NC}} Destination IPs (block traffic TO malicious IPs)"
    echo -e "\n${YELLOW}Note:${NC} Changing these settings will affect all existing and future blocking rules."
    
    # Allow toggles
    read -rp "Toggle Source blocking? [y/N]: " toggle_source
    if [[ "$toggle_source" =~ ^[Yy] ]]; then
        block_source=$((1 - block_source))
        sed -i "s|^block_source=.*|block_source=$block_source|" "$CONFIG_FILE"
        
        if [[ $block_source -eq 1 ]]; then
            echo -e "${GREEN}Source IP blocking enabled.${NC}"
        else
            echo -e "${RED}Source IP blocking disabled.${NC}"
        fi
        
        need_apply=1
    fi
    
    read -rp "Toggle Destination blocking? [y/N]: " toggle_dest
    if [[ "$toggle_dest" =~ ^[Yy] ]]; then
        block_destination=$((1 - block_destination))
        sed -i "s|^block_destination=.*|block_destination=$block_destination|" "$CONFIG_FILE"
        
        if [[ $block_destination -eq 1 ]]; then
            echo -e "${GREEN}Destination IP blocking enabled.${NC}"
        else
            echo -e "${RED}Destination IP blocking disabled.${NC}"
        fi
        
        need_apply=1
    fi
    
    # If changes were made, apply them immediately
    if [[ $need_apply -eq 1 ]]; then
        echo -e "\n${YELLOW}Applying changes...${NC}"
        
        # Check if a background process is running
        local bg_status=$(is_background_process_running)
        local IFS="|"
        read -r is_running pid start_time cmd <<< "$bg_status"
        
        if [[ "$is_running" == "1" ]]; then
            echo -e "${RED}Cannot apply rule type changes while a background process is running.${NC}"
            echo -e "${YELLOW}Changes will take effect on the next run.${NC}"
        else
            # Clear all rules
            echo -e "${BLUE}Clearing existing rules...${NC}"
            iptables -F "$IPT_CHAIN" 2>/dev/null && ip6tables -F "$IPT6_CHAIN" 2>/dev/null
            log "INFO" "Cleared rules for rule type changes" "verbose"
            
            # Run a full resolve_block to rebuild the rules with new settings in background
            echo -e "${BLUE}Rebuilding rules with new settings...${NC}"
            nohup bash -c 'source /etc/dnsniper/dnsniper-daemon.sh && nice -n 10 run_with_lock' >/dev/null 2>&1 &
            echo -e "${GREEN}Rule rebuilding started in background.${NC}"
            echo -e "${GREEN}You can check status to monitor progress.${NC}"
        fi
    else
        echo -e "${YELLOW}No changes made.${NC}"
    fi
}

# Set schedule
set_schedule() {
    echo -e "${BOLD}=== Set Schedule ===${NC}"
    
    # Get current settings
    local scheduler_enabled=$(grep '^scheduler_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    local schedule_minutes=$(grep '^schedule_minutes=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    
    # Validate settings, use defaults if invalid
    [[ -z "$scheduler_enabled" || ! "$scheduler_enabled" =~ ^[01]$ ]] && scheduler_enabled=$DEFAULT_SCHEDULER_ENABLED
    [[ -z "$schedule_minutes" || ! "$schedule_minutes" =~ ^[0-9]+$ ]] && schedule_minutes=$DEFAULT_SCHEDULE_MINUTES
    
    # Display current status
    if [[ "$scheduler_enabled" == "1" ]]; then
        echo -e "${BLUE}Scheduler is currently:${NC} ${GREEN}Enabled${NC}"
        echo -e "${BLUE}Schedule:${NC} Every ${YELLOW}$schedule_minutes${NC} minutes"
    else
        echo -e "${BLUE}Scheduler is currently:${NC} ${RED}Disabled${NC}"
        echo -e "${BLUE}Default schedule:${NC} Every ${YELLOW}$schedule_minutes${NC} minutes (inactive)"
    fi
    
    # Ask what to change
    echo -e "\n${YELLOW}What would you like to change?${NC}"
    echo -e "1. ${BOLD}Enable/Disable${NC} scheduler"
    echo -e "2. Change ${BOLD}schedule interval${NC}"
    echo -e "3. ${BOLD}Back${NC} without changes"
    
    read -rp "Choice (1-3): " schedule_choice
    case "$schedule_choice" in
        1)
            # Toggle scheduler state
            if [[ "$scheduler_enabled" == "1" ]]; then
                read -rp "Disable scheduler? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy] ]]; then
                    sed -i "s|^scheduler_enabled=.*|scheduler_enabled=0|" "$CONFIG_FILE"
                    echo -e "${YELLOW}Scheduler disabled.${NC}"
                    log "INFO" "Scheduler disabled by user" "verbose"
                    # Update systemd timer
                    update_systemd_timer
                else
                    echo -e "${YELLOW}No change.${NC}"
                fi
            else
                read -rp "Enable scheduler? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy] ]]; then
                    sed -i "s|^scheduler_enabled=.*|scheduler_enabled=1|" "$CONFIG_FILE"
                    echo -e "${GREEN}Scheduler enabled.${NC}"
                    log "INFO" "Scheduler enabled by user" "verbose"
                    # Update systemd timer
                    update_systemd_timer
                else
                    echo -e "${YELLOW}No change.${NC}"
                fi
            fi
            ;;
            
        2)
            # Change interval
            read -rp "Run every how many minutes (15-1440): " m
            if [[ "$m" =~ ^[0-9]+$ && $m -ge 15 && $m -le 1440 ]]; then
                sed -i "s|^schedule_minutes=.*|schedule_minutes=$m|" "$CONFIG_FILE"
                echo -e "${GREEN}Schedule interval set to $m minutes.${NC}"
                log "INFO" "Schedule interval updated to $m minutes" "verbose"
                # Update systemd timer
                update_systemd_timer
            else
                echo -e "${RED}Invalid input. Please enter a number between 15 and 1440.${NC}"
            fi
            ;;
            
        3|*)
            echo -e "${YELLOW}No changes made to scheduler.${NC}"
            ;;
    esac
}

# Set max IPs
set_max_ips() {
    echo -e "${BOLD}=== Set Max IPs Per Domain ===${NC}"
    local current=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    echo -e "${BLUE}Current max IPs per domain:${NC} $current"
    read -rp "New max IPs per domain (5-50): " n
    
    if [[ "$n" =~ ^[0-9]+$ && $n -ge 5 && $n -le 50 ]]; then
        sed -i "s|^max_ips=.*|max_ips=$n|" "$CONFIG_FILE"
        echo -e "${GREEN}Max IPs per domain set to $n.${NC}"
        log "INFO" "Max IPs per domain updated to $n" "verbose"
    else
        echo -e "${RED}Invalid input. Please enter a number between 5 and 50.${NC}"
    fi
}

# Set timeout
set_timeout() {
    echo -e "${BOLD}=== Set Timeout ===${NC}"
    local current=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    echo -e "${BLUE}Current timeout:${NC} $current seconds"
    read -rp "New timeout in seconds (5-60): " t
    
    if [[ "$t" =~ ^[0-9]+$ && $t -ge 5 && $t -le 60 ]]; then
        sed -i "s|^timeout=.*|timeout=$t|" "$CONFIG_FILE"
        echo -e "${GREEN}Timeout set to $t seconds.${NC}"
        log "INFO" "Timeout updated to $t seconds" "verbose"
    else
        echo -e "${RED}Invalid input. Please enter a number between 5 and 60.${NC}"
    fi
}

# Set update URL
set_update_url() {
    echo -e "${BOLD}=== Set Update URL ===${NC}"
    local current=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
    echo -e "${BLUE}Current update URL:${NC} $current"
    read -rp "New update URL: " url
    
    if [[ -n "$url" ]]; then
        # Basic URL validation
        if [[ "$url" =~ ^https?:// ]]; then
            sed -i "s|^update_url=.*|update_url='$url'|" "$CONFIG_FILE"
            echo -e "${GREEN}Update URL set to $url.${NC}"
            log "INFO" "Update URL changed to: $url" "verbose"
        else
            echo -e "${RED}Invalid URL. Must start with http:// or https://.${NC}"
        fi
    else
        echo -e "${YELLOW}No change.${NC}"
    fi
}

# Toggle auto-update
toggle_auto_update() {
    echo -e "${BOLD}=== Toggle Auto-Update ===${NC}"
    local current=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$current" || ! "$current" =~ ^[0-9]+$ ]]; then
        current=$DEFAULT_AUTO_UPDATE
    fi
    
    if [[ $current -eq 1 ]]; then
        echo -e "${BLUE}Auto-update is currently:${NC} ${GREEN}Enabled${NC}"
        read -rp "Disable auto-update? [y/N]: " choice
        
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^auto_update=.*|auto_update=0|" "$CONFIG_FILE"
            echo -e "${YELLOW}Auto-update disabled.${NC}"
            log "INFO" "Auto-update disabled by user" "verbose"
        else
            echo -e "${YELLOW}No change.${NC}"
        fi
    else
        echo -e "${BLUE}Auto-update is currently:${NC} ${RED}Disabled${NC}"
        read -rp "Enable auto-update? [y/N]: " choice
        
        if [[ "$choice" =~ ^[Yy] ]]; then
            sed -i "s|^auto_update=.*|auto_update=1|" "$CONFIG_FILE"
            echo -e "${GREEN}Auto-update enabled.${NC}"
            log "INFO" "Auto-update enabled by user" "verbose"
        else
            echo -e "${YELLOW}No change.${NC}"
        fi
    fi
}

# --- Import/Export submenu ---
import_export_menu() {
    while true; do
        show_banner
        
        # Check if a background process is running
        local bg_running=false
        if check_background_process; then
            bg_running=true
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        fi
        
        echo -e "${BLUE}${BOLD}IMPORT / EXPORT${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Import Domains"
        echo -e "${YELLOW}2.${NC} Export Domains"
        echo -e "${YELLOW}3.${NC} Import IP Addresses"
        echo -e "${YELLOW}4.${NC} Export IP Addresses"
        echo -e "${YELLOW}5.${NC} Export Configuration"
        echo -e "${YELLOW}6.${NC} Export Firewall Rules"
        echo -e "${YELLOW}7.${NC} Import Complete Backup"
        echo -e "${YELLOW}8.${NC} Export Complete Backup"
        echo -e "${YELLOW}0.${NC} Back to Settings"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        # Use read with timeout to make menu more responsive
        read -t 2 -rp "Select option: " choice
        
        # If read timed out, check if background process finished and refresh
        if [[ $? -gt 128 ]]; then
            if $bg_running; then
                # Check if process is still running
                if ! is_background_process_running | grep -q "^1|"; then
                    clear
                    echo -e "${GREEN}Background process completed.${NC}"
                    sleep 1
                fi
            fi
            continue
        fi
        
        case "$choice" in
            1) import_domains; read -rp "Press Enter to continue..." ;;
            2) export_domains; read -rp "Press Enter to continue..." ;;
            3) import_ips; read -rp "Press Enter to continue..." ;;
            4) export_ips; read -rp "Press Enter to continue..." ;;
            5) export_config; read -rp "Press Enter to continue..." ;;
            6) export_firewall_rules; read -rp "Press Enter to continue..." ;;
            7) import_all; read -rp "Press Enter to continue..." ;;
            8) export_all; read -rp "Press Enter to continue..." ;;
            0) return ;;
            *)
                if [[ -n "$choice" ]]; then
                    echo -e "${RED}Invalid selection. Please choose 0-8.${NC}"
                    sleep 1
                fi
                ;;
        esac
    done
}

# Import domains
import_domains() {
    echo -e "${BOLD}=== Import Domains ===${NC}"
    read -rp "Enter path to domains file: " file
    
    # Validate file exists
    if [[ ! -f "$file" ]]; then
        echo -e "${RED}File not found: $file${NC}"
        return 1
    fi
    
    # Validate file is readable
    if [[ ! -r "$file" ]]; then
        echo -e "${RED}Cannot read file: $file (permission denied)${NC}"
        return 1
    fi
    
    # Performance optimized import for large files
    local tmpfile=$(mktemp)
    local count=0
    
    # Filter valid domains in one pass
    grep -v '^[[:space:]]*#' "$file" | \
    grep -v '^[[:space:]]*$' | \
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile"
    
    # Get existing domains to avoid duplicates
    local existing_domains=$(mktemp)
    if [[ -f "$ADD_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$ADD_FILE" | \
        grep -v '^[[:space:]]*$' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$existing_domains"
    else
        touch "$existing_domains"
    fi
    
    # Process the filtered domains in batches for large files
    local total=$(wc -l < "$tmpfile")
    local processed=0
    local batch_size=1000  # Process in batches of 1000 domains
    
    echo -e "${BLUE}Processing $total domains...${NC}"
    
    while [[ $processed -lt $total ]]; do
        local end=$((processed + batch_size))
        [[ $end -gt $total ]] && end=$total
        
        # Extract this batch
        sed -n "$((processed+1)),${end}p" "$tmpfile" | while IFS= read -r domain; do
            # Validate domain format
            if is_valid_domain "$domain"; then
                # Check if domain already exists
                if ! grep -Fxq "$domain" "$existing_domains"; then
                    echo "$domain" >> "$ADD_FILE"
                    count=$((count + 1))
                fi
            fi
        done
        
        processed=$end
        echo -e "${GREEN}Processed $processed/$total domains...${NC}"
        
        # Brief pause to keep UI responsive
        sleep 0.1
    done
    
    # Clean up
    rm -f "$tmpfile" "$existing_domains"
    
    echo -e "${GREEN}Imported $count new domains.${NC}"
    log "INFO" "Imported $count domains from file: $file" "verbose"
    return 0
}

# Export domains
export_domains() {
    echo -e "${BOLD}=== Export Domains ===${NC}"
    read -rp "Enter export path: " file
    
    if [[ -z "$file" ]]; then
        echo -e "${RED}Invalid export path.${NC}"
        return 1
    fi
    
    # Check if directory exists
    local dir=$(dirname "$file")
    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Directory does not exist: $dir${NC}"
        return 1
    fi
    
    # Check if directory is writable
    if [[ ! -w "$dir" ]]; then
        echo -e "${RED}Cannot write to directory: $dir (permission denied)${NC}"
        return 1
    fi
    
    # Export domains
    local tmpfile=$(mktemp)
    echo -e "${BLUE}Merging domains, please wait...${NC}"
    
    # Run merge_domains in background with low priority to avoid UI blocking
    (nice -n 10 merge_domains > "$tmpfile") &
    local merge_pid=$!
    
    # Show a spinner while processing
    local chars="/-\|"
    local i=0
    while kill -0 $merge_pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Processing domains... %c${NC}" "${chars:$i:1}"
        sleep 0.1
    done
    printf "\r                            \r"
    
    local count=$(wc -l < "$tmpfile")
    if [[ $count -gt 0 ]]; then
        # Create export file with header
        {
            echo "# DNSniper Domains Export"
            echo "# Date: $(date)"
            echo "# Total: $count domains"
            echo ""
            cat "$tmpfile"
        } > "$file"
        
        echo -e "${GREEN}Exported $count domains to $file.${NC}"
        log "INFO" "Exported $count domains to file: $file" "verbose"
    else
        echo -e "${YELLOW}No domains to export.${NC}"
    fi
    
    # Clean up
    rm -f "$tmpfile"
    return 0
}

# Import IPs with improved range handling
import_ips() {
    echo -e "${BOLD}=== Import IP Addresses ===${NC}"
    read -rp "Enter path to IP list file: " file
    
    # Validate file exists
    if [[ ! -f "$file" ]]; then
        echo -e "${RED}File not found: $file${NC}"
        return 1
    fi
    
    # Validate file is readable
    if [[ ! -r "$file" ]]; then
        echo -e "${RED}Cannot read file: $file (permission denied)${NC}"
        return 1
    fi
    
    # Performance optimized import for large files
    local tmpfile=$(mktemp)
    local validips=$(mktemp)
    local count=0
    
    # Filter comments and empty lines
    grep -v '^[[:space:]]*#' "$file" | \
    grep -v '^[[:space:]]*$' | \
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$tmpfile"
    
    # Get existing IPs to avoid duplicates
    local existing_ips=$(mktemp)
    if [[ -f "$IP_ADD_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$IP_ADD_FILE" | \
        grep -v '^[[:space:]]*$' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$existing_ips"
    else
        touch "$existing_ips"
    fi
    
    # Process and validate IPs in batches for large files
    local total=$(wc -l < "$tmpfile")
    local processed=0
    local batch_size=500  # Process in batches of 500 IPs
    
    echo -e "${BLUE}Processing $total IP addresses...${NC}"
    
    while [[ $processed -lt $total ]]; then
        local end=$((processed + batch_size))
        [[ $end -gt $total ]] && end=$total
        
        # Extract this batch
        sed -n "$((processed+1)),${end}p" "$tmpfile" | while IFS= read -r ip; do
            # Enhanced validation with range support
            if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})-([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] ||
               [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$ ]] ||
               is_ipv6 "$ip" || 
               is_valid_ipv4 "$ip"; then
                
                # Check if IP is critical
                if ! is_critical_ip "$ip"; then
                    # Check if IP already exists
                    if ! grep -Fxq "$ip" "$existing_ips"; then
                        echo "$ip" >> "$validips"
                        count=$((count + 1))
                    fi
                else
                    echo -e "${YELLOW}Skipped critical IP:${NC} $ip"
                    log "WARNING" "Skipped critical IP during import: $ip" "verbose"
                fi
            else
                echo -e "${YELLOW}Skipped invalid IP format:${NC} $ip"
            fi
        done
        
        processed=$end
        echo -e "${GREEN}Processed $processed/$total IPs...${NC}"
        
        # Brief pause to keep UI responsive
        sleep 0.1
    done
    
    # Append valid IPs to the add file
    if [[ -s "$validips" ]]; then
        cat "$validips" >> "$IP_ADD_FILE"
    fi
    
    # Clean up
    rm -f "$tmpfile" "$validips" "$existing_ips"
    
    echo -e "${GREEN}Imported $count new IPs.${NC}"
    log "INFO" "Imported $count IPs from file: $file" "verbose"
    return 0
}

# Export IPs
export_ips() {
    echo -e "${BOLD}=== Export IP Addresses ===${NC}"
    read -rp "Enter export path: " file
    
    if [[ -z "$file" ]]; then
        echo -e "${RED}Invalid export path.${NC}"
        return 1
    fi
    
    # Check if directory exists
    local dir=$(dirname "$file")
    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Directory does not exist: $dir${NC}"
        return 1
    fi
    
    # Check if directory is writable
    if [[ ! -w "$dir" ]]; then
        echo -e "${RED}Cannot write to directory: $dir (permission denied)${NC}"
        return 1
    fi
    
    # Export IPs
    local tmpfile=$(mktemp)
    echo -e "${BLUE}Getting custom IPs, please wait...${NC}"
    
    # Run get_custom_ips in background with low priority to avoid UI blocking
    (nice -n 10 get_custom_ips > "$tmpfile") &
    local ips_pid=$!
    
    # Show a spinner while processing
    local chars="/-\|"
    local i=0
    while kill -0 $ips_pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Processing IPs... %c${NC}" "${chars:$i:1}"
        sleep 0.1
    done
    printf "\r                        \r"
    
    local count=$(wc -l < "$tmpfile")
    if [[ $count -gt 0 ]]; then
        # Create export file with header
        {
            echo "# DNSniper IPs Export"
            echo "# Date: $(date)"
            echo "# Total: $count IPs"
            echo ""
            cat "$tmpfile"
        } > "$file"
        
        echo -e "${GREEN}Exported $count IPs to $file.${NC}"
        log "INFO" "Exported $count IPs to file: $file" "verbose"
    else
        echo -e "${YELLOW}No custom IPs to export.${NC}"
    fi
    
    # Clean up
    rm -f "$tmpfile"
    return 0
}

# Export config
export_config() {
    echo -e "${BOLD}=== Export Configuration ===${NC}"
    read -rp "Enter export path: " file
    
    if [[ -z "$file" ]]; then
        echo -e "${RED}Invalid export path.${NC}"
        return 1
    fi
    
    # Check if directory exists
    local dir=$(dirname "$file")
    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Directory does not exist: $dir${NC}"
        return 1
    fi
    
    # Check if directory is writable
    if [[ ! -w "$dir" ]]; then
        echo -e "${RED}Cannot write to directory: $dir (permission denied)${NC}"
        return 1
    fi
    
    # Export config file with header
    {
        echo "# DNSniper Configuration Export"
        echo "# Date: $(date)"
        echo ""
        cat "$CONFIG_FILE"
    } > "$file"
    
    echo -e "${GREEN}Configuration exported to $file.${NC}"
    log "INFO" "Configuration exported to file: $file" "verbose"
    return 0
}

# Export firewall rules
export_firewall_rules() {
    echo -e "${BOLD}=== Export Firewall Rules ===${NC}"
    read -rp "Enter directory path for export: " dir
    
    if [[ -z "$dir" ]]; then
        echo -e "${RED}Invalid directory path.${NC}"
        return 1
    fi
    
    # Check if directory exists
    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Directory does not exist: $dir${NC}"
        return 1
    fi
    
    # Check if directory is writable
    if [[ ! -w "$dir" ]]; then
        echo -e "${RED}Cannot write to directory: $dir (permission denied)${NC}"
        return 1
    fi
    
    local ipv4_rules="${dir}/dnsniper-ipv4-rules.txt"
    local ipv6_rules="${dir}/dnsniper-ipv6-rules.txt"
    
    # Process export in background to avoid UI blocking
    echo -e "${BLUE}Exporting firewall rules...${NC}"
    
    (
        # Export current rules
        iptables-save | grep -E "(^*|^:|^-A $IPT_CHAIN)" > "$ipv4_rules" 2>/dev/null
        ip6tables-save | grep -E "(^*|^:|^-A $IPT6_CHAIN)" > "$ipv6_rules" 2>/dev/null
    ) &
    
    # Show spinner while processing
    local export_pid=$!
    local chars="/-\|"
    local i=0
    while kill -0 $export_pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Exporting rules... %c${NC}" "${chars:$i:1}"
        sleep 0.1
    done
    printf "\r                        \r"
    
    echo -e "${GREEN}Exported IPv4 rules to:${NC} $ipv4_rules"
    echo -e "${GREEN}Exported IPv6 rules to:${NC} $ipv6_rules"
    log "INFO" "Exported firewall rules to: $dir" "verbose"
    return 0
}

# Import all (complete backup)
import_all() {
    echo -e "${BOLD}=== Import Complete Backup ===${NC}"
    read -rp "Enter backup directory: " dir
    
    if [[ -z "$dir" ]]; then
        echo -e "${RED}Invalid directory path.${NC}"
        return 1
    fi
    
    # Check if directory exists
    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Directory does not exist: $dir${NC}"
        return 1
    fi
    
    # Check if directory is readable
    if [[ ! -r "$dir" ]]; then
        echo -e "${RED}Cannot read from directory: $dir (permission denied)${NC}"
        return 1
    fi
    
    # Check if backup files exist
    if [[ -f "$dir/domains.txt" || -f "$dir/ips.txt" || -f "$dir/config.conf" ]]; then
        # Import domains if exists
        if [[ -f "$dir/domains.txt" && -r "$dir/domains.txt" ]]; then
            echo -e "${BLUE}Importing domains...${NC}"
            cp "$dir/domains.txt" "$ADD_FILE.tmp"
            mv "$ADD_FILE.tmp" "$ADD_FILE"
            echo -e "${GREEN}Imported domains from backup.${NC}"
        fi
        
        # Import IPs if exists
        if [[ -f "$dir/ips.txt" && -r "$dir/ips.txt" ]]; then
            echo -e "${BLUE}Importing IPs...${NC}"
            cp "$dir/ips.txt" "$IP_ADD_FILE.tmp"
            mv "$IP_ADD_FILE.tmp" "$IP_ADD_FILE"
            echo -e "${GREEN}Imported IPs from backup.${NC}"
        fi
        
        # Import config if exists
        if [[ -f "$dir/config.conf" && -r "$dir/config.conf" ]]; then
            echo -e "${BLUE}Importing configuration...${NC}"
            cp "$dir/config.conf" "$CONFIG_FILE.tmp"
            mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
            echo -e "${GREEN}Imported configuration from backup.${NC}"
        fi
        
        # Import history files if exist
        if [[ -d "$dir/history" && -r "$dir/history" ]]; then
            echo -e "${BLUE}Importing history files...${NC}"
            mkdir -p "$HISTORY_DIR" 2>/dev/null
            cp -R "$dir/history/"* "$HISTORY_DIR/" 2>/dev/null
            echo -e "${GREEN}Imported history files from backup.${NC}"
        fi
        
        # Import data files if exist
        if [[ -d "$dir/data" && -r "$dir/data" ]]; then
            echo -e "${BLUE}Importing data files...${NC}"
            mkdir -p "$DATA_DIR" 2>/dev/null
            cp -R "$dir/data/"* "$DATA_DIR/" 2>/dev/null
            echo -e "${GREEN}Imported data files from backup.${NC}"
        fi
        
        # Re-initialize environment with imported settings
        echo -e "${BLUE}Reinitializing with imported settings...${NC}"
        ensure_environment
        echo -e "${GREEN}Import complete!${NC}"
        log "INFO" "Imported complete backup from: $dir" "verbose"
    else
        echo -e "${RED}No valid backup files found in directory.${NC}"
    fi
    
    return 0
}

# Export all (complete backup)
export_all() {
    echo -e "${BOLD}=== Export Complete Backup ===${NC}"
    read -rp "Enter export directory: " dir
    
    if [[ -z "$dir" ]]; then
        echo -e "${RED}Invalid directory path.${NC}"
        return 1
    fi
    
    # Check if directory exists
    if [[ ! -d "$dir" ]]; then
        echo -e "${RED}Directory does not exist: $dir${NC}"
        return 1
    fi
    
    # Check if directory is writable
    if [[ ! -w "$dir" ]]; then
        echo -e "${RED}Cannot write to directory: $dir (permission denied)${NC}"
        return 1
    fi
    
    # Export directory confirmed
    local export_dir="${dir%/}/dnsniper-backup-$(date +%Y%m%d-%H%M%S)"
    if ! mkdir -p "$export_dir"; then
        echo -e "${RED}Cannot create export directory.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Preparing backup in ${export_dir}...${NC}"
    
    # Create subdirectories
    mkdir -p "$export_dir/history" "$export_dir/data" "$export_dir/status" 2>/dev/null
    
    # Process exports in background to avoid UI blocking
    (
        # Export domains
        echo "Creating domains export..."
        local tmpdomains=$(mktemp)
        merge_domains > "$tmpdomains"
        if [[ -s "$tmpdomains" ]]; then
            {
                echo "# DNSniper Domains Export"
                echo "# Date: $(date)"
                echo "# Total: $(wc -l < "$tmpdomains") domains"
                echo ""
                cat "$tmpdomains"
            } > "$export_dir/domains.txt"
        fi
        rm -f "$tmpdomains"
        
        # Export custom IPs
        echo "Creating IPs export..."
        local tmpips=$(mktemp)
        get_custom_ips > "$tmpips"
        if [[ -s "$tmpips" ]]; then
            {
                echo "# DNSniper IPs Export"
                echo "# Date: $(date)"
                echo "# Total: $(wc -l < "$tmpips") IPs"
                echo ""
                cat "$tmpips"
            } > "$export_dir/ips.txt"
        fi
        rm -f "$tmpips"
        
        # Export config
        echo "Exporting configuration..."
        cp "$CONFIG_FILE" "$export_dir/config.conf" 2>/dev/null || true
        
        # Export current iptables rules
        echo "Exporting firewall rules..."
        if command -v iptables-save &>/dev/null; then
            iptables-save | grep -E "(^*|^:|^-A $IPT_CHAIN)" > "$export_dir/iptables-rules.txt" 2>/dev/null || true
            ip6tables-save | grep -E "(^*|^:|^-A $IPT6_CHAIN)" > "$export_dir/ip6tables-rules.txt" 2>/dev/null || true
        fi
        
        # Export history files
        echo "Exporting history files..."
        if [[ -d "$HISTORY_DIR" ]]; then
            cp -R "$HISTORY_DIR/"* "$export_dir/history/" 2>/dev/null || true
        fi
        
        # Export data files
        echo "Exporting data files..."
        if [[ -d "$DATA_DIR" ]]; then
            cp -R "$DATA_DIR/"* "$export_dir/data/" 2>/dev/null || true
        fi
        
        # Export status files
        echo "Exporting status files..."
        if [[ -d "$STATUS_DIR" ]]; then
            cp -R "$STATUS_DIR/"* "$export_dir/status/" 2>/dev/null || true
        fi
        
        # Create README
        echo "Creating documentation..."
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
            echo "- Domain history data"
            echo "- Status information"
            echo ""
            echo "To restore, use the 'Import Complete Backup' feature in DNSniper."
        } > "$export_dir/README.txt"
        
        echo "Backup complete!"
    ) &
    
    # Show progress spinner while backup is running
    local backup_pid=$!
    local chars="/-\|"
    local i=0
    while kill -0 $backup_pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Creating backup... %c${NC}" "${chars:$i:1}"
        sleep 0.2
    done
    printf "\r                          \r"
    
    echo -e "${GREEN}Complete backup exported to: $export_dir${NC}"
    log "INFO" "Complete backup exported to: $export_dir" "verbose"
    return 0
}

# --- Block/Whitelist Domain/IP Functions ---
# Block domain
block_domain() {
    echo -e "${BOLD}=== Block Domain ===${NC}"
    read -rp "Domain to block: " domain
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Domain cannot be empty.${NC}"
        return 1
    fi
    
    # Validate domain format
    if ! is_valid_domain "$domain"; then
        echo -e "${RED}Invalid domain format.${NC}"
        return 1
    fi
    
    # Check if domain already exists in block list
    if grep -Fxq "$domain" "$ADD_FILE" 2>/dev/null; then
        echo -e "${YELLOW}Domain already in block list.${NC}"
        return 0
    fi
    
    # Add to custom domains file
    echo "$domain" >> "$ADD_FILE"
    echo -e "${GREEN}Domain added to block list:${NC} $domain"
    log "INFO" "Domain added to block list: $domain" "verbose"
    
    # Ask if to block immediately
    read -rp "Block this domain immediately? [y/N]: " block_now
    if [[ "$block_now" =~ ^[Yy] ]]; then
        # Check if a background process is running
        local bg_status=$(is_background_process_running)
        local IFS="|"
        read -r is_running pid start_time cmd <<< "$bg_status"
        
        if [[ "$is_running" == "1" ]]; then
            echo -e "${YELLOW}A background process is already running.${NC}"
            echo -e "${YELLOW}The domain will be blocked on the next run or when the current process completes.${NC}"
        else
            echo -e "${BLUE}Resolving and blocking $domain...${NC}"
            
            local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
            if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]]; then
                timeout=$DEFAULT_TIMEOUT
            fi
            
            # Use improved resolve_domain function
            local unique=()
            mapfile -t unique < <(resolve_domain "$domain" "$timeout")
            
            if [[ ${#unique[@]} -eq 0 ]]; then
                echo -e "  ${YELLOW}No valid IP addresses found${NC}"
                return 0
            fi
            
            # Convert array to CSV for storage
            local ips_csv=$(IFS=,; echo "${unique[*]}")
            
            # Record in history
            record_history "$domain" "$ips_csv"
            
            # Block each IP
            for ip in "${unique[@]}"; do
                # Skip critical IPs
                if is_critical_ip "$ip"; then
                    echo -e "  - ${YELLOW}Skipped critical IP${NC}: $ip"
                    continue
                fi
                
                if block_ip "$ip" "DNSniper: $domain"; then
                    echo -e "  - ${RED}Blocked${NC}: $ip"
                else
                    echo -e "  - ${RED}Error blocking${NC}: $ip"
                fi
            done
            
            # Make rules persistent
            make_rules_persistent
        fi
    fi
    
    return 0
}

# Whitelist domain (renamed from unblock_domain for clarity)
whitelist_domain() {
    echo -e "${BOLD}=== Add Domain to Whitelist ===${NC}"
    
    # Get all active domains in background to avoid UI blocking
    echo -e "${BLUE}Loading domain list...${NC}"
    
    local tmpdomains=$(mktemp)
    (nice -n 10 merge_domains > "$tmpdomains") &
    local merge_pid=$!
    
    # Show a spinner while loading domains
    local chars="/-\|"
    local i=0
    while kill -0 $merge_pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Loading domains... %c${NC}" "${chars:$i:1}"
        sleep 0.1
    done
    printf "\r                        \r"
    
    local total=$(wc -l < "$tmpdomains")
    if [[ $total -eq 0 ]]; then
        echo -e "${YELLOW}No active domains to whitelist.${NC}"
        rm -f "$tmpdomains"
        return 0
    fi
    
    # Display domains in a paginated way for large lists
    echo -e "${BLUE}Current blocked domains:${NC}"
    if [[ $total -gt 20 ]]; then
        echo -e "${YELLOW}Too many domains to display ($total). Please enter domain name directly.${NC}"
    else
        # Small enough to display all
        local i=1
        while IFS= read -r d || [[ -n "$d" ]]; do
            printf "%3d) %s\n" $i "$d"
            i=$((i+1))
        done < "$tmpdomains"
    fi
    
    read -rp "Enter domain number or domain name to add to whitelist: " choice
    local domain_to_whitelist=""
    
    # Check if choice is a number and within range
    if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le $total ]]; then
        domain_to_whitelist=$(sed -n "${choice}p" "$tmpdomains")
    else
        domain_to_whitelist="$choice"
    fi
    
    rm -f "$tmpdomains"
    
    if [[ -z "$domain_to_whitelist" ]]; then
        echo -e "${RED}Invalid selection.${NC}"
        return 1
    fi
    
    # Validate domain format
    if ! is_valid_domain "$domain_to_whitelist"; then
        echo -e "${RED}Invalid domain format: $domain_to_whitelist${NC}"
        return 1
    fi
    
    # Add to remove file if not already there
    if ! grep -Fxq "$domain_to_whitelist" "$REMOVE_FILE" 2>/dev/null; then
        echo "$domain_to_whitelist" >> "$REMOVE_FILE"
        echo -e "${GREEN}Domain added to whitelist:${NC} $domain_to_whitelist"
        log "INFO" "Domain added to whitelist: $domain_to_whitelist" "verbose"
        
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this domain immediately? [y/N]: " whitelist_now
        if [[ "$whitelist_now" =~ ^[Yy] ]]; then
            # Check if a background process is running
            local bg_status=$(is_background_process_running)
            local IFS="|"
            read -r is_running pid start_time cmd <<< "$bg_status"
            
            if [[ "$is_running" == "1" ]]; then
                echo -e "${YELLOW}A background process is already running.${NC}"
                echo -e "${YELLOW}The domain will be whitelisted on the next run or when the current process completes.${NC}"
            else
                echo -e "${BLUE}Removing firewall rules for $domain_to_whitelist...${NC}"
                
                # Get IPs from history file
                local safe_domain="${domain_to_whitelist//\//_}"
                local history_file="$HISTORY_DIR/${safe_domain}.txt"
                if [[ -f "$history_file" && -s "$history_file" ]]; then
                    # Get the most recent entry (first line)
                    local latest_entry=$(head -n 1 "$history_file" 2>/dev/null)
                    if [[ -n "$latest_entry" ]]; then
                        # Format is: timestamp,ip1,ip2,...
                        local ips=${latest_entry#*,}  # Remove timestamp
                        IFS=',' read -ra ip_list <<< "$ips"
                        for ip in "${ip_list[@]}"; do
                            if whitelist_ip "$ip" "DNSniper: $domain_to_whitelist"; then
                                echo -e "  - ${GREEN}Added to whitelist:${NC} $ip"
                            fi
                        done
                        # Make rules persistent
                        make_rules_persistent
                    else
                        echo -e "${YELLOW}No IP records found for this domain.${NC}"
                    fi
                else
                    echo -e "${YELLOW}No history found for this domain.${NC}"
                fi
            fi
        fi
    else
        echo -e "${YELLOW}Domain already in whitelist.${NC}"
    fi
    
    return 0
}

# Block IP with enhanced range support
block_custom_ip() {
    echo -e "${BOLD}=== Block IP Address ===${NC}"
    echo -e "${YELLOW}Supported formats:${NC}"
    echo -e "- Single IP: 192.168.1.1"
    echo -e "- CIDR range: 192.168.1.0/24"
    echo -e "- IP range: 192.168.1.1-192.168.1.10"
    echo -e "- IPv6: 2001:db8::1"
    echo -e ""
    
    read -rp "IP address or range to block: " ip
    
    if [[ -z "$ip" ]]; then
        echo -e "${RED}IP cannot be empty.${NC}"
        return 1
    fi
    
    # Validate IP format with range support
    if ! is_ipv6 "$ip" && ! is_valid_ipv4 "$ip"; then
        echo -e "${RED}Invalid IP format.${NC}"
        return 1
    fi
    
    # Check if it's a critical IP
    if is_critical_ip "$ip"; then
        echo -e "${RED}Cannot block critical IP address or range: $ip${NC}"
        log "WARNING" "Attempted to block critical IP: $ip" "verbose"
        return 1
    fi
    
    # Check if IP already exists in block list
    if grep -Fxq "$ip" "$IP_ADD_FILE" 2>/dev/null; then
        echo -e "${YELLOW}IP already in block list.${NC}"
        return 0
    fi
    
    # Add to custom IPs file
    echo "$ip" >> "$IP_ADD_FILE"
    echo -e "${GREEN}IP added to block list:${NC} $ip"
    log "INFO" "IP added to block list: $ip" "verbose"
    
    # Ask if to block immediately
    read -rp "Block this IP immediately? [y/N]: " block_now
    if [[ "$block_now" =~ ^[Yy] ]]; then
        # Check if a background process is running
        local bg_status=$(is_background_process_running)
        local IFS="|"
        read -r is_running pid start_time cmd <<< "$bg_status"
        
        if [[ "$is_running" == "1" ]]; then
            echo -e "${YELLOW}A background process is already running.${NC}"
            echo -e "${YELLOW}The IP will be blocked on the next run or when the current process completes.${NC}"
        else
            if block_ip "$ip" "DNSniper: custom"; then
                echo -e "${GREEN}Successfully blocked:${NC} $ip"
                # Make rules persistent
                make_rules_persistent
            else
                echo -e "${RED}Error blocking IP:${NC} $ip"
            fi
        fi
    fi
    
    return 0
}

# Whitelist IP with range support
whitelist_custom_ip() {
    echo -e "${BOLD}=== Add IP Address to Whitelist ===${NC}"
    
    # Get all custom IPs in background
    echo -e "${BLUE}Loading IP list...${NC}"
    
    local tmpips=$(mktemp)
    (nice -n 10 get_custom_ips > "$tmpips") &
    local ips_pid=$!
    
    # Show a spinner while loading IPs
    local chars="/-\|"
    local i=0
    while kill -0 $ips_pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Loading IPs... %c${NC}" "${chars:$i:1}"
        sleep 0.1
    done
    printf "\r                    \r"
    
    local total=$(wc -l < "$tmpips")
    if [[ $total -eq 0 ]]; then
        echo -e "${YELLOW}No custom IPs to whitelist.${NC}"
        rm -f "$tmpips"
        return 0
    fi
    
    # Display IPs in a paginated way for large lists
    echo -e "${BLUE}Current blocked IPs:${NC}"
    if [[ $total -gt 20 ]]; then
        echo -e "${YELLOW}Too many IPs to display ($total). Please enter IP address directly.${NC}"
    else
        # Small enough to display all
        local i=1
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            printf "%3d) %s\n" $i "$ip"
            i=$((i+1))
        done < "$tmpips"
    fi
    
    echo -e "${YELLOW}You can also enter an IP range (e.g., 192.168.1.1-192.168.1.10) or CIDR notation (e.g., 192.168.1.0/24).${NC}"
    read -rp "Enter IP number or IP address to add to whitelist: " choice
    local ip_to_whitelist=""
    
    # Check if choice is a number and within range
    if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le $total ]]; then
        ip_to_whitelist=$(sed -n "${choice}p" "$tmpips")
    else
        ip_to_whitelist="$choice"
    fi
    
    rm -f "$tmpips"
    
    if [[ -z "$ip_to_whitelist" ]]; then
        echo -e "${RED}Invalid selection.${NC}"
        return 1
    fi
    
    # Validate IP format with range support
    if ! is_ipv6 "$ip_to_whitelist" && ! is_valid_ipv4 "$ip_to_whitelist"; then
        echo -e "${RED}Invalid IP format.${NC}"
        return 1
    fi
    
    # Add to remove file if not already there
    if ! grep -Fxq "$ip_to_whitelist" "$IP_REMOVE_FILE" 2>/dev/null; then
        echo "$ip_to_whitelist" >> "$IP_REMOVE_FILE"
        echo -e "${GREEN}IP added to whitelist:${NC} $ip_to_whitelist"
        log "INFO" "IP added to whitelist: $ip_to_whitelist" "verbose"
        
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this IP immediately? [y/N]: " whitelist_now
        if [[ "$whitelist_now" =~ ^[Yy] ]]; then
            # Check if a background process is running
            local bg_status=$(is_background_process_running)
            local IFS="|"
            read -r is_running pid start_time cmd <<< "$bg_status"
            
            if [[ "$is_running" == "1" ]]; then
                echo -e "${YELLOW}A background process is already running.${NC}"
                echo -e "${YELLOW}The IP will be whitelisted on the next run or when the current process completes.${NC}"
            else
                if whitelist_ip "$ip_to_whitelist" "DNSniper: custom"; then
                    echo -e "${GREEN}Successfully added IP to whitelist:${NC} $ip_to_whitelist"
                    # Make rules persistent
                    make_rules_persistent
                else
                    echo -e "${RED}Error adding IP to whitelist:${NC} $ip_to_whitelist"
                fi
            fi
        fi
    else
        echo -e "${YELLOW}IP already in whitelist.${NC}"
    fi
    
    return 0
}

# Enhanced status display with comprehensive information
display_status() {
    # Start processing in background for better UI responsiveness
    clear
    echo -e "${BLUE}Loading DNSniper status, please wait...${NC}"
    
    # Create a temp file for processing
    local tmpout=$(mktemp)
    
    # Run analysis and data gathering in background
    (
        show_banner > "$tmpout"
        
        # Check for running background process
        local bg_status=$(is_background_process_running)
        local IFS="|"
        read -r is_running pid start_time cmd <<< "$bg_status"
        
        if [[ "$is_running" == "1" ]]; then
            echo -e "${YELLOW}${BOLD}Background Process Running${NC}" >> "$tmpout"
            echo -e "${MAGENTA}───────────────────────────────────────${NC}" >> "$tmpout"
            echo -e "${BOLD}PID:${NC} $pid" >> "$tmpout"
            echo -e "${BOLD}Started:${NC} $start_time" >> "$tmpout"
            
            # Show status if available
            if [[ -f "$STATUS_FILE" ]]; then
                local status_data=$(get_status)
                local status=$(echo "$status_data" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
                local message=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
                local progress=$(echo "$status_data" | grep -o '"progress":[^,}]*' | cut -d':' -f2)
                local eta=$(echo "$status_data" | grep -o '"eta":[^,}]*' | cut -d':' -f2)
                
                # Format ETA if available
                local eta_text=""
                if [[ $eta -gt 0 ]]; then
                    if [[ $eta -gt 3600 ]]; then
                        eta_text="$(($eta / 3600))h $(($eta % 3600 / 60))m"
                    elif [[ $eta -gt 60 ]]; then
                        eta_text="$(($eta / 60))m $(($eta % 60))s"
                    else
                        eta_text="${eta}s"
                    fi
                    eta_text=" (ETA: ${eta_text})"
                fi
                
                echo -e "${BOLD}Status:${NC} ${CYAN}$status${NC}" >> "$tmpout"
                echo -e "${BOLD}Progress:${NC} ${GREEN}$progress%${NC}${YELLOW}$eta_text${NC}" >> "$tmpout"
                echo -e "${BOLD}Message:${NC} $message" >> "$tmpout"
            fi
            
            echo -e "${MAGENTA}───────────────────────────────────────${NC}" >> "$tmpout"
        fi
        
        # Get domains and IPs with nice to reduce system load
        echo -e "${BOLD}Calculating stats...${NC}" >> "$tmpout"
        
        # Use background processing for these expensive operations
        local domain_count_file=$(mktemp)
        local blocked_ips_file=$(mktemp)
        local custom_ip_count_file=$(mktemp)
        
        # Run these in parallel to speed things up
        (nice -n 10 merge_domains | wc -l > "$domain_count_file") &
        (nice -n 10 count_blocked_ips > "$blocked_ips_file") &
        (nice -n 10 get_custom_ips | wc -l > "$custom_ip_count_file") &
        
        # Wait for all processes to complete
        wait
        
        # Read results
        local domain_count=$(cat "$domain_count_file")
        local blocked_ips=$(cat "$blocked_ips_file")
        local custom_ip_count=$(cat "$custom_ip_count_file")
        
        # Cleanup temp files
        rm -f "$domain_count_file" "$blocked_ips_file" "$custom_ip_count_file"
        
        # Get config values
        local scheduler_enabled=$(grep '^scheduler_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local schedule_minutes=$(grep '^schedule_minutes=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local max_ips=$(grep '^max_ips=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local timeout=$(grep '^timeout=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local update_url=$(grep '^update_url=' "$CONFIG_FILE" 2>/dev/null | cut -d"'" -f2)
        local auto_update=$(grep '^auto_update=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local expire_enabled=$(grep '^expire_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local expire_multiplier=$(grep '^expire_multiplier=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local block_source=$(grep '^block_source=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local block_destination=$(grep '^block_destination=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local logging_enabled=$(grep '^logging_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        local status_enabled=$(grep '^status_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
        
        # Apply defaults if missing or invalid
        [[ -z "$scheduler_enabled" || ! "$scheduler_enabled" =~ ^[01]$ ]] && scheduler_enabled=$DEFAULT_SCHEDULER_ENABLED
        [[ -z "$schedule_minutes" || ! "$schedule_minutes" =~ ^[0-9]+$ ]] && schedule_minutes=$DEFAULT_SCHEDULE_MINUTES
        [[ -z "$max_ips" || ! "$max_ips" =~ ^[0-9]+$ ]] && max_ips=$DEFAULT_MAX_IPS
        [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+$ ]] && timeout=$DEFAULT_TIMEOUT
        [[ -z "$update_url" ]] && update_url=$DEFAULT_URL
        [[ -z "$auto_update" || ! "$auto_update" =~ ^[01]$ ]] && auto_update=$DEFAULT_AUTO_UPDATE
        [[ -z "$expire_enabled" || ! "$expire_enabled" =~ ^[01]$ ]] && expire_enabled=$DEFAULT_EXPIRE_ENABLED
        [[ -z "$expire_multiplier" || ! "$expire_multiplier" =~ ^[0-9]+$ ]] && expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
        [[ -z "$block_source" || ! "$block_source" =~ ^[01]$ ]] && block_source=$DEFAULT_BLOCK_SOURCE
        [[ -z "$block_destination" || ! "$block_destination" =~ ^[01]$ ]] && block_destination=$DEFAULT_BLOCK_DESTINATION
        [[ -z "$logging_enabled" || ! "$logging_enabled" =~ ^[01]$ ]] && logging_enabled=$DEFAULT_LOGGING_ENABLED
        [[ -z "$status_enabled" || ! "$status_enabled" =~ ^[01]$ ]] && status_enabled=$DEFAULT_STATUS_ENABLED
        
        # Format auto-update text
        local auto_update_text="${RED}Disabled${NC}"
        [[ "$auto_update" == "1" ]] && auto_update_text="${GREEN}Enabled${NC}"
        
        # Format expiration text
        local expire_text="${RED}Disabled${NC}"
        [[ "$expire_enabled" == "1" ]] && expire_text="${GREEN}Enabled (${expire_multiplier}x)${NC}"
        
        # Format scheduler text
        local scheduler_text="${RED}Disabled${NC}"
        if [[ "$scheduler_enabled" == "1" ]]; then
            scheduler_text="${GREEN}Enabled${NC} (Every ${YELLOW}$schedule_minutes${NC} minutes)"
        fi
        
        # Format rule types text
        local rule_types=""
        [[ "$block_source" == "1" ]] && rule_types+="Source, "
        [[ "$block_destination" == "1" ]] && rule_types+="Destination"
        rule_types=${rule_types%, }
        [[ -z "$rule_types" ]] && rule_types="${RED}None${NC}"
        
        # Format logging text
        local logging_text="${RED}Disabled${NC}"
        [[ "$logging_enabled" == "1" ]] && logging_text="${GREEN}Enabled${NC}"
        
        # Format status tracking text
        local status_text="${RED}Disabled${NC}"
        [[ "$status_enabled" == "1" ]] && status_text="${GREEN}Enabled${NC}"
        
        # Get service status
        local service_status=$(get_service_status)
        
        # Count expired domains pending cleanup
        local expired_count=0
        if [[ "$expire_enabled" == "1" && -f "$EXPIRED_DOMAINS_FILE" ]]; then
            local expire_seconds=$((schedule_minutes * expire_multiplier * 60))
            local current_time=$(date +%s)
            
            # Use grep to count expired domains efficiently
            expired_count=$(grep -v "^#" "$EXPIRED_DOMAINS_FILE" | awk -F, -v now="$current_time" -v exp="$expire_seconds" '
                $2+exp<now && $3=="default" {count++}
                END {print count}
            ')
        fi
        
        # Count CDN domains
        local cdn_count=0
        if [[ -f "$CDN_DOMAINS_FILE" ]]; then
            cdn_count=$(grep -v '^#' "$CDN_DOMAINS_FILE" | grep -v '^$' | wc -l)
        fi
        
        # Display summary counts
        {
            echo -e "${CYAN}${BOLD}SYSTEM STATUS${NC}"
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
            echo -e "${BOLD}Blocked Domains:${NC}      ${GREEN}${domain_count}${NC}"
            echo -e "${BOLD}Blocked IPs:${NC}          ${RED}${blocked_ips}${NC}"
            echo -e "${BOLD}Custom IPs:${NC}           ${YELLOW}${custom_ip_count}${NC}"
            
            if [[ $expired_count -gt 0 ]]; then
                echo -e "${BOLD}Pending Expirations:${NC}  ${YELLOW}$expired_count${NC}"
            fi
            
            if [[ $cdn_count -gt 0 ]]; then
                echo -e "${BOLD}Detected CDN Domains:${NC} ${YELLOW}$cdn_count${NC}"
            fi
            
            # Config section
            echo -e ""
            echo -e "${CYAN}${BOLD}CONFIGURATION${NC}"
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
            echo -e "${BOLD}Scheduler:${NC}          $scheduler_text"
            echo -e "${BOLD}Max IPs/domain:${NC}     ${YELLOW}$max_ips${NC}"
            echo -e "${BOLD}Timeout:${NC}            ${YELLOW}$timeout seconds${NC}"
            echo -e "${BOLD}Auto-update:${NC}        $auto_update_text"
            echo -e "${BOLD}Rule Expiration:${NC}    $expire_text"
            echo -e "${BOLD}Rule Types:${NC}         $rule_types"
            echo -e "${BOLD}Logging:${NC}            $logging_text"
            echo -e "${BOLD}Status Tracking:${NC}    $status_text"
            
            # Service information
            echo -e ""
            echo -e "${CYAN}${BOLD}SERVICES${NC}"
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
            echo -e "$service_status"
            
            # Firewall information
            echo -e ""
            echo -e "${CYAN}${BOLD}FIREWALL${NC}"
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
            echo -e "${BOLD}IPv4 Chain:${NC}         ${YELLOW}$IPT_CHAIN${NC}"
            echo -e "${BOLD}IPv6 Chain:${NC}         ${YELLOW}$IPT6_CHAIN${NC}"
            echo -e "${BOLD}Persistence:${NC}        ${GREEN}$(detect_system)${NC}"
            
            # System information
            echo -e ""
            echo -e "${CYAN}${BOLD}SYSTEM INFO${NC}"
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
            
            local last_run="Never"
            if [[ -f "$STATUS_FILE" ]]; then
                local status_data=$(get_status)
                local timestamp=$(echo "$status_data" | grep -o '"formatted_time":"[^"]*"' | cut -d'"' -f4)
                if [[ -n "$timestamp" && "$timestamp" != "unknown" ]]; then
                    last_run="$timestamp"
                fi
            elif [[ -f "$LOG_FILE" ]]; then
                last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
            elif [[ -d "$HISTORY_DIR" ]]; then
                # Check if there are any history files
                local newest_file=$(find "$HISTORY_DIR" -type f -name "*.txt" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | head -n 1)
                if [[ -n "$newest_file" ]]; then
                    last_run=$(stat -c %y "$newest_file" 2>/dev/null || echo "Never")
                fi
            fi
            
            echo -e "${BOLD}Last Run:${NC}           ${BLUE}$last_run${NC}"
            echo -e "${BOLD}Version:${NC}            ${GREEN}$VERSION${NC}"
            
            # Check for CDN domains
            if [[ $cdn_count -gt 0 ]]; then
                echo -e ""
                echo -e "${CYAN}${BOLD}CDN DOMAINS ${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                echo -e "${YELLOW}${BOLD}$cdn_count domains detected as possibly using CDN services.${NC}"
                echo -e "${YELLOW}It's recommended to whitelist these domains to avoid excessive blocking.${NC}"
                
                # Display top CDN domains if number is reasonable
                if [[ $cdn_count -le 10 ]]; then
                    echo -e ""
                    echo -e "${BOLD}Detected CDN domains:${NC}"
                    local count=0
                    while IFS=, read -r dom timestamp || [[ -n "$dom" ]]; do
                        [[ -z "$dom" || "$dom" =~ ^# ]] && continue
                        count=$((count + 1))
                        [[ $count -gt 10 ]] && break
                        echo -e "${YELLOW}- $dom${NC}"
                    done < "$CDN_DOMAINS_FILE"
                fi
            fi
            
            # Domain and IP sections only for moderate list sizes
            if [[ $domain_count -gt 0 && $domain_count -le 500 ]]; then
                echo -e ""
                echo -e "${CYAN}${BOLD}BLOCKED DOMAINS (TOP 10 OF ${domain_count})${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Get top 10 domains
                local tmpdomain=$(mktemp)
                merge_domains | head -10 > "$tmpdomain"
                
                while IFS= read -r dom || [[ -n "$dom" ]]; do
                    local safe_dom="${dom//\//_}"
                    local history_file="$HISTORY_DIR/${safe_dom}.txt"
                    
                    if [[ -f "$history_file" && -s "$history_file" ]]; then
                        # Count IPs from history file
                        local first_line=$(head -n 1 "$history_file" 2>/dev/null)
                        if [[ -n "$first_line" ]]; then
                            local ips=${first_line#*,}  # Remove timestamp
                            IFS=',' read -ra ip_array <<< "$ips"
                            echo -e "${GREEN}$dom${NC} (${YELLOW}${#ip_array[@]} IPs${NC})"
                        else
                            echo -e "${GREEN}$dom${NC} (${RED}No IP data${NC})"
                        fi
                    else
                        echo -e "${GREEN}$dom${NC} (${RED}Not resolved yet${NC})"
                    fi
                done < "$tmpdomain"
                
                if [[ $domain_count -gt 10 ]]; then
                    echo -e "${YELLOW}... and $((domain_count - 10)) more domains${NC}"
                fi
                
                rm -f "$tmpdomain"
            elif [[ $domain_count -gt 500 ]]; then
                echo -e ""
                echo -e "${CYAN}${BOLD}BLOCKED DOMAINS (SUMMARY)${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                echo -e "${YELLOW}Large domain list detected ($domain_count domains)${NC}"
                echo -e "${YELLOW}For performance reasons, detailed domain info is hidden.${NC}"
                echo -e "${YELLOW}Use export features to view complete domain list.${NC}"
            fi
            
            # Custom IPs section if exists and not too large
            if [[ $custom_ip_count -gt 0 && $custom_ip_count -le 500 ]]; then
                echo -e ""
                echo -e "${CYAN}${BOLD}BLOCKED IPs (TOP 10 OF ${custom_ip_count})${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                
                # Only process top 10 IPs for performance
                get_custom_ips | head -10 | while read -r ip; do
                    echo -e "${GREEN}$ip${NC}"
                done
                
                if [[ $custom_ip_count -gt 10 ]]; then
                    echo -e "${YELLOW}... and $((custom_ip_count - 10)) more IPs${NC}"
                fi
            elif [[ $custom_ip_count -gt 500 ]]; then
                echo -e ""
                echo -e "${CYAN}${BOLD}BLOCKED IPs (SUMMARY)${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                echo -e "${YELLOW}Large IP list detected ($custom_ip_count IPs)${NC}"
                echo -e "${YELLOW}For performance reasons, detailed IP info is hidden.${NC}"
                echo -e "${YELLOW}Use export features to view complete IP list.${NC}"
            fi
            
            echo -e ""
        } >> "$tmpout"
    ) &
    
    # Wait for analysis to complete with spinner animation
    local pid=$!
    local chars="/-\|"
    local i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Loading stats... %c${NC}" "${chars:$i:1}"
        sleep 0.2
    done
    printf "\r                      \r"
    
    # Display the output
    clear
    cat "$tmpout"
    
    # Clean up
    rm -f "$tmpout"
    
    return 0
}

# Clear rules
clear_rules() {
    echo -e "${BOLD}=== Clear Firewall Rules ===${NC}"
    read -rp "Clear all DNSniper firewall rules? [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy] ]]; then
        echo -e "${BLUE}Removing DNSniper rules...${NC}"
        local success=0
        
        # Flush our custom chains
        if iptables -F "$IPT_CHAIN" 2>/dev/null && ip6tables -F "$IPT6_CHAIN" 2>/dev/null; then
            success=1
        fi
        
        # Make rules persistent
        make_rules_persistent
        
        if [[ $success -eq 1 ]]; then
            echo -e "${GREEN}All DNSniper rules cleared.${NC}"
            log "INFO" "All firewall rules cleared" "verbose"
        else
            echo -e "${RED}Error clearing rules. Check iptables status.${NC}"
            log "ERROR" "Error clearing firewall rules"
            return 1
        fi
    else
        echo -e "${YELLOW}Operation canceled.${NC}"
    fi
    
    return 0
}

# Improved: Uninstall with better cleanup
uninstall() {
    echo -e "${RED}${BOLD}Warning: This will completely remove DNSniper.${NC}"
    read -rp "Are you sure you want to proceed? [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy] ]]; then
        echo -e "${BLUE}Uninstalling DNSniper...${NC}"
        
        # Ask about removing DNSniper firewall rules
        read -rp "Remove DNSniper firewall rules? [Y/n]: " remove_rules
        if [[ ! "$remove_rules" =~ ^[Nn] ]]; then
            echo -e "${BLUE}Removing DNSniper firewall rules...${NC}"
            
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
        else
            echo -e "${YELLOW}Keeping DNSniper firewall rules.${NC}"
        fi
        
        # Stop and remove systemd services
        echo -e "${BLUE}Removing system services...${NC}"
        
        if systemctl list-unit-files dnsniper.service &>/dev/null; then
            systemctl stop dnsniper.timer &>/dev/null || true
            systemctl disable dnsniper.timer &>/dev/null || true
            systemctl disable dnsniper.service &>/dev/null || true
            rm -f /etc/systemd/system/dnsniper.service &>/dev/null || true
            rm -f /etc/systemd/system/dnsniper.timer &>/dev/null || true
        fi
        
        if systemctl list-unit-files dnsniper-firewall.service &>/dev/null; then
            systemctl disable dnsniper-firewall.service &>/dev/null || true
            rm -f /etc/systemd/system/dnsniper-firewall.service &>/dev/null || true
        fi
        
        # Reload systemd
        systemctl daemon-reload &>/dev/null || true
        
        # Remove cron job if any
        cleanup_cron_jobs
        
        # Remove binary and directories
        echo -e "${BLUE}Removing files and directories...${NC}"
        rm -f "$BIN_CMD" 2>/dev/null || true
        rm -f "/etc/dnsniper/dnsniper-core.sh" 2>/dev/null || true
        rm -f "/etc/dnsniper/dnsniper-daemon.sh" 2>/dev/null || true
        rm -f "/etc/dnsniper/dnsniper.sh" 2>/dev/null || true
        
        # Ask about removing data
        read -rp "Remove all DNSniper data (domains, IPs, history)? [y/N]: " remove_data
        if [[ "$remove_data" =~ ^[Yy] ]]; then
            rm -rf "$BASE_DIR" 2>/dev/null || true
            echo -e "${GREEN}All DNSniper data removed.${NC}"
        else
            # Remove just the scripts but keep data
            echo -e "${YELLOW}Keeping DNSniper data at $BASE_DIR${NC}"
        fi
        
        echo -e "${GREEN}DNSniper successfully uninstalled.${NC}"
        exit 0
    else
        echo -e "${YELLOW}Uninstall canceled.${NC}"
    fi
    
    return 0
}

# Show help - updated with new option names
show_help() {
    show_banner
    echo -e "${BOLD}=== DNSniper v$VERSION Help ===${NC}"
    echo -e "${BOLD}Usage:${NC} dnsniper [options]"
    echo -e ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  ${YELLOW}--run${NC}           Run DNSniper once (blocks terminal)"
    echo -e "  ${YELLOW}--run-background${NC} Run DNSniper in background (non-blocking)"
    echo -e "  ${YELLOW}--update${NC}        Update default domains list"
    echo -e "  ${YELLOW}--status${NC}        Display status"
    echo -e "  ${YELLOW}--block${NC} DOMAIN  Add a domain to block list"
    echo -e "  ${YELLOW}--whitelist${NC} DOMAIN Add a domain to whitelist"
    echo -e "  ${YELLOW}--block-ip${NC} IP   Add an IP to block list"
    echo -e "  ${YELLOW}--whitelist-ip${NC} IP Add an IP to whitelist"
    echo -e "  ${YELLOW}--check-expired${NC} Check and remove expired rules"
    echo -e "  ${YELLOW}--monitor${NC}       Monitor background process status"
    echo -e "  ${YELLOW}--version${NC}       Show version"
    echo -e "  ${YELLOW}--help${NC}          Show this help"
    echo -e ""
    echo -e "${BOLD}Interactive Menu:${NC}"
    echo -e "  Run without arguments to access the interactive menu"
    echo -e "  which provides all functionality, configuration options,"
    echo -e "  and maintenance features."
    echo -e ""
    return 0
}

# NEW: Monitor background process
monitor_background_process() {
    echo -e "${BOLD}Monitoring DNSniper Background Process${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    
    # Trap Ctrl+C to exit cleanly
    trap 'echo -e "\n${BLUE}Monitoring stopped by user.${NC}"; exit 0' INT
    
    while true; do
        clear
        echo -e "${CYAN}${BOLD}DNSniper Process Monitor${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        # Check for running background process
        local bg_status=$(is_background_process_running)
        local IFS="|"
        read -r is_running pid start_time cmd <<< "$bg_status"
        
        if [[ "$is_running" == "1" ]]; then
            echo -e "${GREEN}Process running:${NC} PID $pid"
            echo -e "${GREEN}Started:${NC} $start_time"
            
            # Get status information
            if [[ -f "$STATUS_FILE" ]]; then
                local status_data=$(get_status)
                local status=$(echo "$status_data" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
                local message=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
                local progress=$(echo "$status_data" | grep -o '"progress":[^,}]*' | cut -d':' -f2)
                local eta=$(echo "$status_data" | grep -o '"eta":[^,}]*' | cut -d':' -f2)
                
                # Format ETA if available
                local eta_text=""
                if [[ $eta -gt 0 ]]; then
                    if [[ $eta -gt 3600 ]]; then
                        eta_text="$(($eta / 3600))h $(($eta % 3600 / 60))m"
                    elif [[ $eta -gt 60 ]]; then
                        eta_text="$(($eta / 60))m $(($eta % 60))s"
                    else
                        eta_text="${eta}s"
                    fi
                    eta_text=" (ETA: ${eta_text})"
                fi
                
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                echo -e "${BOLD}Status:${NC} $status"
                echo -e "${BOLD}Message:${NC} $message"
                echo -e "${BOLD}Progress:${NC} "
                
                # Draw a progress bar
                local bar_width=50
                local filled_width=$((progress * bar_width / 100))
                local empty_width=$((bar_width - filled_width))
                printf "[%${filled_width}s%${empty_width}s] %d%%${YELLOW}%s${NC}\n" | sed "s/ /=/g; s/\-/ /g" "" "$progress" "$eta_text"
            else
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                echo -e "${YELLOW}Status information not available${NC}"
            fi
        else
            echo -e "${RED}No background process is currently running.${NC}"
            
            if [[ -f "$STATUS_FILE" ]]; then
                local status_data=$(get_status)
                local status=$(echo "$status_data" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
                local message=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
                local timestamp=$(echo "$status_data" | grep -o '"formatted_time":"[^"]*"' | cut -d'"' -f4)
                
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                echo -e "${BOLD}Last known status:${NC} $status"
                echo -e "${BOLD}Last message:${NC} $message"
                echo -e "${BOLD}Time:${NC} $timestamp"
            fi
            
            echo -e "${YELLOW}Waiting for process to start...${NC}"
        fi
        
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
        sleep 1
    done
}

# Updated argument handling with new option names
handle_args() {
    case "$1" in
        --run)
            # Run in foreground
            run_with_lock
            ;;
            
        --run-background)
            # Non-interactive run for background operation
            export DNSniper_NONINTERACTIVE=1
            run_background
            ;;
            
        --update)
            update_default
            ;;
            
        --status)
            display_status
            ;;
            
        --monitor)
            monitor_background_process
            ;;
            
        --block)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: missing domain parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$ADD_FILE"
            echo -e "${GREEN}Domain added to block list:${NC} $2"
            log "INFO" "Domain added via CLI: $2" "verbose"
            ;;
            
        --whitelist|--unblock)  # Support both names for backward compatibility
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: missing domain parameter${NC}"
                show_help
                exit 1
            }
            echo "$2" >> "$REMOVE_FILE"
            echo -e "${GREEN}Domain added to whitelist:${NC} $2" # Updated terminology
            log "INFO" "Domain added to whitelist via CLI: $2" "verbose"
            ;;
            
        --block-ip)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: missing IP parameter${NC}"
                show_help
                exit 1
            fi
            if is_critical_ip "$2"; then
                echo -e "${RED}Cannot block critical IP:${NC} $2"
                exit 1
            fi
            echo "$2" >> "$IP_ADD_FILE"
            echo -e "${GREEN}IP added to block list:${NC} $2"
            log "INFO" "IP added via CLI: $2" "verbose"
            ;;
            
        --whitelist-ip|--unblock-ip)  # Support both names for backward compatibility
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: missing IP parameter${NC}"
                show_help
                exit 1
            }
            echo "$2" >> "$IP_REMOVE_FILE"
            echo -e "${GREEN}IP added to whitelist:${NC} $2"  # Updated terminology
            log "INFO" "IP added to whitelist via CLI: $2" "verbose"
            ;;
            
        --check-expired)
            check_expired_domains
            ;;
            
        --version)
            echo -e "DNSniper version $VERSION"
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

# Entry point
main() {
    # Check if running as root
    check_root
    
    # Check for dependencies
    check_dependencies
    
    # Ensure environment is prepared
    ensure_environment
    
    # Initialize logging and status tracking
    initialize_logging
    initialize_status_tracking
    
    # Handle command line arguments if provided
    if [[ $# -gt 0 ]]; then
        if handle_args "$@"; then
            exit 0
        fi
    fi
    
    # No valid arguments provided, start interactive menu
    main_menu
}

# Execute main function with all arguments
main "$@"