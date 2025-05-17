#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.3

# Source the core and daemon functionality
# It's good practice to check for existence and executability
if [[ -f /etc/dnsniper/dnsniper-core.sh && -x /etc/dnsniper/dnsniper-core.sh ]]; then
    source /etc/dnsniper/dnsniper-core.sh
else
    echo "CRITICAL Error: Core DNSniper functionality not found or not executable at /etc/dnsniper/dnsniper-core.sh" >&2
    exit 1
fi
if [[ -f /etc/dnsniper/dnsniper-daemon.sh && -x /etc/dnsniper/dnsniper-daemon.sh ]]; then
    source /etc/dnsniper/dnsniper-daemon.sh
else
    echo "CRITICAL Error: DNSniper daemon functionality not found or not executable at /etc/dnsniper/dnsniper-daemon.sh" >&2
    exit 1
fi

# Display banner for interactive sessions
_show_banner_if_interactive() {
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
# Check for running background process
_check_background_process_status() {
    local bg_status
    bg_status=$(is_background_process_running) # Sourced from daemon script
    local IFS="|"
    read -r is_running pid start_time cmd <<< "$bg_status"

    if [[ "$is_running" == "1" ]]; then
        echo -e "${YELLOW}${BOLD}Note:${NC} A DNSniper process (PID: ${pid}) is currently running."
        echo -e "       Started: ${YELLOW}${start_time}${NC}"
        if [[ -f "$STATUS_FILE" ]]; then
            local status_data status_message progress eta eta_text
            status_data=$(get_status) # Sourced from core script
            status_message=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            progress=$(echo "$status_data" | grep -o '"progress":[^,}]*' | cut -d':' -f2)
            eta=$(echo "$status_data" | grep -o '"eta":[^,}]*' | cut -d':' -f2)
            
            eta_text=""
            if [[ -n "$eta" && "$eta" -gt 0 ]]; then
                if [[ $eta -gt 3600 ]]; then eta_text="$(($eta / 3600))h $(($eta % 3600 / 60))m";
                elif [[ $eta -gt 60 ]]; then eta_text="$(($eta / 60))m $(($eta % 60))s";
                else eta_text="${eta}s"; fi
                eta_text=" (ETA: ${eta_text})"
            fi
            echo -e "       Status: ${CYAN}${status_message}${NC} - ${GREEN}${progress:-0}%${YELLOW}${eta_text}${NC}"
        fi
        echo -e "${BLUE}       Some operations may be limited. Check 'Status' or 'Process Management'.${NC}"
        echo
        return 0 # true, background process is running
    fi
    return 1 # false, no background process
}

# Main Menu
main_menu() {
    local bg_is_running=false # Renamed to avoid conflict
    while true; do
        _show_banner_if_interactive
        if _check_background_process_status; then
             bg_is_running=true
             echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        else
            bg_is_running=false
        fi
        echo -e "${CYAN}${BOLD}MAIN MENU${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Run DNSniper Now     ${YELLOW}2.${NC} View Status"
        echo -e "${YELLOW}3.${NC} Block Domain         ${YELLOW}4.${NC} Whitelist Domain"
        echo -e "${YELLOW}5.${NC} Block IP Address     ${YELLOW}6.${NC} Whitelist IP Address"
        echo -e "${YELLOW}7.${NC} Settings             ${YELLOW}8.${NC} Update Domain Lists"
        echo -e "${YELLOW}9.${NC} Clear DNSniper Rules ${YELLOW}0.${NC} Exit"
        echo -e "${YELLOW}U.${NC} Uninstall DNSniper"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        
        local choice_input=""
        # Read with timeout, single character
        read -t 2 -N 1 -p "Select an option: " choice_input 
        echo # Newline after input for clarity

        if [[ -z "$choice_input" ]]; then # Timeout
            if $bg_is_running; then
                # If a bg process was running, check if it finished during the timeout
                if ! is_background_process_running | grep -q "^1|"; then
                    _show_banner_if_interactive # Refresh screen
                    echo -e "${GREEN}Background process appears to have completed.${NC}"
                    sleep 1.5
                fi
            fi
            continue # Refresh menu
        fi

        case "$choice_input" in
            1)
                _show_banner_if_interactive # Clear screen
                if $bg_is_running; then
                    echo -e "${YELLOW}A background process is already running. Please wait or check status.${NC}"
                else
                    echo -e "${BLUE}Attempting to start DNSniper in the background...${NC}"
                    nohup bash -c 'source /etc/dnsniper/dnsniper-core.sh && source /etc/dnsniper/dnsniper-daemon.sh && run_background' >/dev/null 2>&1 &
                    # run_background (from daemon.sh) handles locking
                    sleep 0.5 # Give it a moment to start
                    if is_background_process_running | grep -q "^1|"; then
                        echo -e "${GREEN}DNSniper started in the background.${NC}"
                        echo -e "${GREEN}You can monitor its progress via 'Status' or 'Process Management'.${NC}"
                    else
                        echo -e "${RED}Failed to start DNSniper in background. Check logs or if another instance is running.${NC}"
                    fi
                fi
                read -rp "Press Enter to continue..."
                ;;
            2) display_status; read -rp "Press Enter to return to menu..." ;; # display_status clears screen
            3) _show_banner_if_interactive; block_domain; read -rp "Press Enter..." ;;
            4) _show_banner_if_interactive; whitelist_domain; read -rp "Press Enter..." ;;
            5) _show_banner_if_interactive; block_custom_ip; read -rp "Press Enter..." ;;
            6) _show_banner_if_interactive; whitelist_custom_ip; read -rp "Press Enter..." ;;
            7) settings_menu ;; # This function handles its own screen clearing/banner
            8)
                _show_banner_if_interactive
                if $bg_is_running; then
                    echo -e "${YELLOW}Background process running. Please wait before updating lists.${NC}"
                else
                    echo -e "${BLUE}Starting domain list update in the background...${NC}"
                    nohup bash -c 'source /etc/dnsniper/dnsniper-core.sh && nice -n 10 update_default' >/dev/null 2>&1 &
                    echo -e "${GREEN}Update started. Monitor progress via 'Status'.${NC}"
                fi
                read -rp "Press Enter to continue..."
                ;;
            9)
                _show_banner_if_interactive
                if $bg_is_running; then
                    echo -e "${YELLOW}Background process running. Please wait before clearing rules.${NC}"
                else
                    clear_rules
                fi
                read -rp "Press Enter to continue..."
                ;;
            0) echo -e "${GREEN}Exiting DNSniper...${NC}"; exit 0 ;;
            [Uu]) _show_banner_if_interactive; uninstall ;;
            *) echo -e "${RED}Invalid selection. Please try again.${NC}"; sleep 1 ;;
        esac
    done
}

# Settings Submenu
settings_menu() {
    local bg_is_running_settings=false
    while true; do
        _show_banner_if_interactive
        if _check_background_process_status; then
             bg_is_running_settings=true
             echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        else
            bg_is_running_settings=false
        fi
        echo -e "${BLUE}${BOLD}SETTINGS MENU${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Set Schedule             ${YELLOW}2.${NC} Set Max IPs Per Domain"
        echo -e "${YELLOW}3.${NC} Set DNS Timeout          ${YELLOW}4.${NC} Set Update URL"
        echo -e "${YELLOW}5.${NC} Toggle Auto-Update       ${YELLOW}6.${NC} Import / Export Data"
        echo -e "${YELLOW}7.${NC} Rule Expiration Config ${YELLOW}8.${NC} Block Rule Types Config"
        echo -e "${YELLOW}9.${NC} Toggle Logging           ${YELLOW}S.${NC} Service Management"
        echo -e "${YELLOW}P.${NC} Process Management       ${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        local choice_settings=""
        read -t 2 -N 1 -p "Select option: " choice_settings
        echo

        if [[ -z "$choice_settings" ]]; then
             if $bg_is_running_settings; then
                if ! is_background_process_running | grep -q "^1|"; then
                    _show_banner_if_interactive
                    echo -e "${GREEN}Background process completed.${NC}"
                    sleep 1.5
                fi
            fi
            continue
        fi
        
        # All sub-functions should handle their own screen clearing/banner
        case "$choice_settings" in
            1) set_schedule ;; 2) set_max_ips ;; 3) set_timeout ;;
            4) set_update_url ;; 5) toggle_auto_update ;; 6) import_export_menu ;;
            7) expiration_settings ;; 8) rule_types_settings ;; 9) toggle_logging ;;
            [Ss]) service_management_menu ;; [Pp]) process_management ;;
            0) return ;;
            *) if [[ -n "$choice_settings" ]]; then echo -e "${RED}Invalid selection.${NC}"; sleep 1; fi ;;
        esac
    done
}

# Process Management
process_management() {
    _show_banner_if_interactive
    echo -e "${BLUE}${BOLD}PROCESS MANAGEMENT${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    local bg_status pid start_time cmd is_running
    bg_status=$(is_background_process_running)
    IFS="|" read -r is_running pid start_time cmd <<< "$bg_status"

    if [[ "$is_running" == "1" ]];then
        echo -e "${YELLOW}A DNSniper background process is currently running:${NC}"
        echo -e "  ${BOLD}PID:${NC} $pid"
        echo -e "  ${BOLD}Started:${NC} $start_time"
        # CMD can be long        echo -e "  ${BOLD}Command:${NC} $(echo "$cmd" | cut -c 1-70)..." 
        if [[ -f "$STATUS_FILE" ]]; then
            local status_data status_msg progress_val
            status_data=$(get_status)
            status_msg=$(echo "$status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            progress_val=$(echo "$status_data" | grep -o '"progress":[^,}]*' | cut -d':' -f2)
            echo -e "  ${BOLD}Current Status:${NC} ${CYAN}$status_msg${NC} (${GREEN}${progress_val:-0}%${NC})"
        fi
        echo -e "\nWhat would you like to do?"
        echo -e "1. ${BOLD}Monitor${NC} process (live progress)"
        echo -e "2. ${BOLD}Terminate${NC} process (SIGTERM, then SIGKILL if needed)"
        echo -e "3. ${BOLD}Back${NC} to Settings Menu"
        read -rp "Choice (1-3): " proc_choice

        case "$proc_choice" in
            1) monitor_background_process ;; # This takes over the screen
            2)
                echo -e "${YELLOW}Attempting to terminate process PID $pid...${NC}"
                kill "$pid" 2>/dev/null # SIGTERM
                sleep 2
                if kill -0 "$pid" 2>/dev/null; then
                    echo -e "${YELLOW}Process still running. Sending SIGKILL...${NC}"
                    kill -9 "$pid" 2>/dev/null
                    sleep 1
                fi
                if ! kill -0 "$pid" 2>/dev/null; then
                    rm -f "$LOCK_FILE" 2>/dev/null || true # Clean lock if we killed it
                    update_status "terminated" "Process PID $pid terminated by user" "0" "0"
                    echo -e "${GREEN}Process PID $pid terminated successfully.${NC}"
                else
                    echo -e "${RED}Failed to terminate process PID $pid. It might be stuck or require manual intervention.${NC}"
                fi
                ;;
            3|*) echo -e "${YELLOW}Returning to settings menu...${NC}" ;;
        esac
    else
        echo -e "${GREEN}No DNSniper background processes are currently running.${NC}"
        if [[ -f "$LOCK_FILE" ]]; then
            local lock_pid_val
            lock_pid_val=$(cat "$LOCK_FILE" 2>/dev/null || echo "Unknown")
            echo -e "${YELLOW}Note: A lock file exists for PID $lock_pid_val. If no process is running, this might be a stale lock.${NC}"
            echo -e "${YELLOW}You can try to clean stale locks from 'Service Management' menu.${NC}"
        fi
        if [[ -f "$STATUS_FILE" ]]; then
            local last_status_data last_status_msg last_timestamp
            last_status_data=$(get_status)
            last_status_msg=$(echo "$last_status_data" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            last_timestamp=$(echo "$last_status_data" | grep -o '"formatted_time":"[^"]*"' | cut -d'"' -f4)
            echo -e "\n${BLUE}Last known status (from $last_timestamp):${NC} ${CYAN}$last_status_msg${NC}"
        fi
    fi
    read -rp "Press Enter to continue..."
}

# Service Management Menu
service_management_menu() {
    while true; do
        _show_banner_if_interactive
        # No need to check background process here as it's informational / service control
        echo -e "${BLUE}${BOLD}SERVICE MANAGEMENT (systemd)${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        if ! command -v systemctl &>/dev/null; then
            echo -e "${RED}systemctl command not found. This menu is for systemd-based systems.${NC}"
            echo -e "${YELLOW}DNSniper services cannot be managed through this menu.${NC}"
            read -rp "Press Enter to return to Settings..."
            return
        fi
        
        local service_status_output
        service_status_output=$(get_service_status) # From daemon.sh
        echo -e "${service_status_output}"
        echo -e "\n${YELLOW}1.${NC} (Re)Start Firewall Service  ${YELLOW}2.${NC} (Re)Start Timer Service"
        echo -e "${YELLOW}3.${NC} Reload Service Configs     ${YELLOW}4.${NC} Enable All Services"
        echo -e "${YELLOW}5.${NC} Disable Timer Service      ${YELLOW}6.${NC} Clean Stale Lock File"
        echo -e "${YELLOW}0.${NC} Back to Settings"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        local choice_svc=""
        read -t 5 -N 1 -p "Select option: " choice_svc # Longer timeout for reading status
        echo

        # No need for bg process check here, just refresh menu on timeout
        if [[ -z "$choice_svc" ]]; then continue; fi 

        case "$choice_svc" in
            1) echo -e "${BLUE}Restarting dnsniper-firewall.service...${NC}"; systemctl restart dnsniper-firewall.service && echo -e "${GREEN}Done.${NC}" || echo -e "${RED}Failed.${NC}"; sleep 0.5 ;;
            2) echo -e "${BLUE}Restarting dnsniper.timer...${NC}"; systemctl restart dnsniper.timer && echo -e "${GREEN}Done.${NC}" || echo -e "${RED}Failed.${NC}"; sleep 0.5 ;;
            3) echo -e "${BLUE}Reloading systemd daemon and restarting timer...${NC}"; systemctl daemon-reload && systemctl try-restart dnsniper.timer && echo -e "${GREEN}Done.${NC}" || echo -e "${RED}Failed.${NC}"; sleep 0.5 ;;
            4)
                echo -e "${BLUE}Enabling all DNSniper services...${NC}"
                systemctl enable dnsniper-firewall.service &>/dev/null
                systemctl enable dnsniper.service &>/dev/null
                systemctl enable dnsniper.timer &>/dev/null 
                echo -e "${GREEN}Services enabled. Timer will start on next boot or if started manually.${NC}"
                read -rp "Start timer now? [Y/n]: " start_timer_now
                if [[ ! "$start_timer_now" =~ ^[Nn]$ ]]; then
                    systemctl start dnsniper.timer && echo "${GREEN}Timer started.${NC}" || echo "${RED}Failed to start timer.${NC}"
                fi
                sleep 0.5
                ;;
            5) echo -e "${BLUE}Disabling and stopping dnsniper.timer...${NC}"; systemctl disable dnsniper.timer &>/dev/null; systemctl stop dnsniper.timer &>/dev/null; echo -e "${GREEN}Timer disabled and stopped.${NC}"; sleep 0.5 ;;
            6)
                echo -e "${BLUE}Checking for stale lock file...${NC}"
                if [[ -f "$LOCK_FILE" ]]; then
                    local locked_pid
                    locked_pid=$(cat "$LOCK_FILE" 2>/dev/null)
                    if [[ -n "$locked_pid" ]] && ! kill -0 "$locked_pid" 2>/dev/null; then
                        rm -f "$LOCK_FILE"
                        echo -e "${GREEN}Removed stale lock file for PID $locked_pid.${NC}"
                    elif [[ -n "$locked_pid" ]]; then
                        echo -e "${YELLOW}Lock file $LOCK_FILE exists for active process PID $locked_pid. Not removing.${NC}"
                    else
                        echo -e "${YELLOW}Lock file $LOCK_FILE exists but PID is unreadable. Consider manual removal if sure.${NC}"
                    fi
                else
                    echo -e "${GREEN}No lock file ($LOCK_FILE) found.${NC}"
                fi
                sleep 0.5
                ;;
            0) return ;;
            *) if [[ -n "$choice_svc" ]]; then echo -e "${RED}Invalid selection.${NC}"; sleep 1; fi ;;
        esac
        # Pause to see output if not returning
        if [[ "$choice_svc" != "0" ]]; then
            read -rp "Press Enter to continue..."
        fi
    done
}

# Toggle Logging
toggle_logging() {
    _show_banner_if_interactive
    echo -e "${BLUE}${BOLD}LOGGING SETTINGS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    local current_logging_enabled
    current_logging_enabled=$(get_config_value "logging_enabled" "$DEFAULT_LOGGING_ENABLED")

    if [[ "$current_logging_enabled" == "1" ]]; then
        echo -e "${BLUE}Logging is currently: ${GREEN}Enabled${NC}"
        echo -e "${DIM}Logs are written to: $LOG_FILE${NC}"
        read -rp "Disable logging? [y/N]: " confirm_disable
        if [[ "$confirm_disable" =~ ^[Yy]$ ]]; then
            sed -i "s|^logging_enabled=.*|logging_enabled=0|" "$CONFIG_FILE"
            LOGGING_ENABLED=0 # Update live variable
            echo -e "${YELLOW}Logging disabled.${NC}"
            log "INFO" "Logging was disabled by user." # This log might not write if LOGGING_ENABLED was just turned off
        fi
    else
        echo -e "${BLUE}Logging is currently: ${RED}Disabled${NC}"
        read -rp "Enable logging? [y/N]: " confirm_enable
        if [[ "$confirm_enable" =~ ^[Yy]$ ]]; then
            sed -i "s|^logging_enabled=.*|logging_enabled=1|" "$CONFIG_FILE"
            LOGGING_ENABLED=1 # Update live variable
            echo -e "${GREEN}Logging enabled. Logs will be written to: $LOG_FILE${NC}"
            log "INFO" "Logging was enabled by user." "verbose" # This will write
        fi
    fi
    # Log file size and rotation prompt
    if [[ "$LOGGING_ENABLED" == "1" && -f "$LOG_FILE" ]]; then
        local log_size_bytes log_size_human
        log_size_bytes=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        log_size_human=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo "N/A")
        echo -e "\nCurrent log_file file size: ${YELLOW}$log_size_human${NC}"
        if [[ "$log_size_bytes" -gt 1048576 ]]; then # 1MB
            read -rp "Log file is >1MB. Rotate (archive and clear) it now? [y/N]: " rotate_log
            if [[ "$rotate_log" =~ ^[Yy]$ ]]; then
                local backup_log_file="$LOG_FILE.$(date +%Y%m%d-%H%M%S).bak"
                cp "$LOG_FILE" "$backup_log_file" && > "$LOG_FILE" # cp then truncate
                echo -e "${GREEN}Log file rotated. Backup: $backup_log_file${NC}"
                log "INFO" "Log file rotated by user. Backup: $backup_log_file" "verbose"
            fi
        fi
    fi
    read -rp "Press Enter to continue..."
}


# Rule Expiration Settings
expiration_settings() {
    _show_banner_if_interactive
    echo -e "${BLUE}${BOLD}RULE EXPIRATION SETTINGS${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    local current_expire_enabled current_expire_multiplier current_schedule_minutes
    current_expire_enabled=$(get_config_value "expire_enabled" "$DEFAULT_EXPIRE_ENABLED")
    current_expire_multiplier=$(get_config_value "expire_multiplier" "$DEFAULT_EXPIRE_MULTIPLIER")
    current_schedule_minutes=$(get_config_value "schedule_minutes" "$DEFAULT_SCHEDULE_MINUTES")

    local expire_minutes=$((current_schedule_minutes * current_expire_multiplier))
    local expire_display
    if [[ $expire_minutes -ge 1440 ]]; then expire_display="$((expire_minutes / 1440)) days";
    elif [[ $expire_minutes -ge 60 ]]; then expire_display="$((expire_minutes / 60)) hours";
    else expire_display="$expire_minutes minutes"; fi

    if [[ "$current_expire_enabled" == "1" ]]; then
        echo -e "${BLUE}Rule expiration for default list domains is: ${GREEN}Enabled${NC}"
        echo -e "${BLUE}Current expiration time after removal from default list: ${YELLOW}$expire_display${NC}"
        echo -e "${DIM}(Based on $current_expire_multiplier x $current_schedule_minutes min schedule interval)${NC}"
        read -rp "Disable rule expiration? [y/N]: " choice_exp
        if [[ "$choice_exp" =~ ^[Yy]$ ]]; then
            sed -i "s|^expire_enabled=.*|expire_enabled=0|" "$CONFIG_FILE"
            echo -e "${YELLOW}Rule expiration disabled.${NC}"
        else
            read -rp "Change expiration multiplier (currently $current_expire_multiplier)? [y/N]: " change_mult
            if [[ "$change_mult" =~ ^[Yy]$ ]]; then
                read -rp "New multiplier (e.g., 1-100, defines how many schedule cycles): " new_mult
                if [[ "$new_mult" =~ ^[0-9]+$ && "$new_mult" -ge 1 && "$new_mult" -le 100 ]]; then
                    sed -i "s|^expire_multiplier=.*|expire_multiplier=$new_mult|" "$CONFIG_FILE"
                    echo -e "${GREEN}Expiration multiplier set to $new_mult.${NC}"
                else echo -e "${RED}Invalid input. Must be a number 1-100.${NC}"; fi
            fi
        fi
    else
        echo -e "${BLUE}Rule expiration for default list domains is: ${RED}Disabled${NC}"
        echo -e "${DIM}(If enabled, default effective time would be $expire_display based on current settings)${NC}"
        read -rp "Enable rule expiration? [y/N]: " choice_exp
        if [[ "$choice_exp" =~ ^[Yy]$ ]]; then
            sed -i "s|^expire_enabled=.*|expire_enabled=1|" "$CONFIG_FILE"
            echo -e "${GREEN}Rule expiration enabled.${NC}"
        fi
    fi
    read -rp "Press Enter to continue..."
}

# --- Import/Export submenu --- (Functions like import_domains should use `tr -d '\r'` for robustness)
import_domains() {
    _show_banner_if_interactive
    echo -e "${BLUE}${BOLD}IMPORT DOMAINS TO BLOCK LIST${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Enter full path to the file containing domains to import: " import_file_path
    if [[ ! -f "$import_file_path" ]]; then echo -e "${RED}File not found: $import_file_path${NC}"; read -rp "Enter..."; return 1; fi
    if [[ ! -r "$import_file_path" ]]; then echo -e "${RED}Cannot read file: $import_file_path${NC}"; read -rp "Enter..."; return 1; fi
    
    local temp_import_normalized existing_add_normalized new_to_add_temp
    temp_import_normalized=$(mktemp)
    existing_add_normalized=$(mktemp)
    new_to_add_temp=$(mktemp)

    # Normalize imported file
    grep -v '^[[:space:]]*#' "$import_file_path" | grep -v '^[[:space:]]*$' | tr -d '\r' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$temp_import_normalized"

    # Normalize existing add file
    if [[ -f "$ADD_FILE" ]]; then
        grep -v '^[[:space:]]*#' "$ADD_FILE" | grep -v '^[[:space:]]*$' | tr -d '\r' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$existing_add_normalized"
    fi
    
    # Find domains in import file that are not in existing add file
    comm -23 "$temp_import_normalized" "$existing_add_normalized" > "$new_to_add_temp"
    
    local added_count=0
    while IFS= read -r domain_to_add; do
        if is_valid_domain "$domain_to_add"; then
            echo "$domain_to_add" >> "$ADD_FILE" # Appending a validated domain
            added_count=$((added_count + 1))
        else
            log "WARNING" "Skipping invalid domain format during import: $domain_to_add"
            echo -e "${YELLOW}Skipped invalid domain: $domain_to_add${NC}"
        fi
    done < "$new_to_add_temp"

    if [[ $added_count -gt 0 ]]; then
        # Ensure ADD_FILE is sorted and unique after additions
        local sorted_add_content=$(mktemp)
        sort -u "$ADD_FILE" > "$sorted_add_content"
        mv "$sorted_add_content" "$ADD_FILE"
        echo -e "${GREEN}Added $added_count new unique, valid domains to $ADD_FILE.${NC}"
    else
        echo -e "${YELLOW}No new valid domains found to add from $import_file_path.${NC}"
    fi
    
    rm -f "$temp_import_normalized" "$existing_add_normalized" "$new_to_add_temp"
    read -rp "Press Enter to continue..."
}

# (Other import/export functions would be similar to above, using _show_banner_if_interactive and robust file handling)
# (block_domain, whitelist_domain, block_custom_ip, whitelist_custom_ip, display_status, clear_rules, uninstall functions as previously detailed, using get_config_value and robust checks.)
# Example for block_domain
block_domain() {
    _show_banner_if_interactive
    echo -e "${BLUE}${BOLD}BLOCK DOMAIN${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Enter domain to block: " domain_input
    if [[ -z "$domain_input" ]]; then echo -e "${RED}Domain cannot be empty.${NC}"; return 1; fi
    if ! is_valid_domain "$domain_input"; then echo -e "${RED}Invalid domain format: $domain_input${NC}"; return 1; fi

    # Check if already in ADD_FILE (main block list)
    if grep -Fxq "$domain_input" "$ADD_FILE" 2>/dev/null; then
        echo -e "${YELLOW}Domain '$domain_input' is already in the block list ($ADD_FILE).${NC}"
    else
        echo "$domain_input" >> "$ADD_FILE"
        # Optional: sort -u ADD_FILE
        local sorted_add=$(mktemp); sort -u "$ADD_FILE" > "$sorted_add"; mv "$sorted_add" "$ADD_FILE";
        echo -e "${GREEN}Domain '$domain_input' added to block list ($ADD_FILE).${NC}"
        log "INFO" "Domain added to block list via UI: $domain_input" "verbose"
    fi
    
    # Remove from whitelist if it exists there
    if grep -Fxq "$domain_input" "$REMOVE_FILE" 2>/dev/null; then
        local temp_remove=$(mktemp)
        grep -Fxv "$domain_input" "$REMOVE_FILE" > "$temp_remove"
        mv "$temp_remove" "$REMOVE_FILE"
        echo -e "${YELLOW}Domain '$domain_input' removed from whitelist ($REMOVE_FILE).${NC}"
    fi

    read -rp "Apply changes and block this domain immediately (runs DNS resolve & firewall update)? [y/N]: " block_now
    if [[ "$block_now" =~ ^[Yy]$ ]]; then
        if is_background_process_running | grep -q "^1|"; then
            echo -e "${YELLOW}A background process is running. Domain will be processed on the next scheduled run or when current process completes.${NC}"
        else
            echo -e "${BLUE}Attempting to resolve and block '$domain_input' immediately...${NC}"
            # This is a simplified immediate block for a single domain.
            # A full 'run_with_lock' might be too heavy.
            local current_timeout_val
            current_timeout_val=$(get_config_value "timeout" "$DEFAULT_TIMEOUT")
            local -a resolved_ips_now=()
            mapfile -t resolved_ips_now < <(resolve_domain "$domain_input" "$current_timeout_val")

            if [[ ${#resolved_ips_now[@]} -eq 0 ]]; then
                echo -e "${YELLOW}No IP addresses found for '$domain_input'. It will be processed during the next full run.${NC}"
            else
                local ips_blocked_count_now=0
                local ips_csv_now; ips_csv_now=$(IFS=,; echo "${resolved_ips_now[*]}")
                record_history "$domain_input" "$ips_csv_now" # Record history

                for ip_to_block_now in "${resolved_ips_now[@]}"; do
                    if is_critical_ip "$ip_to_block_now"; then
                        echo -e "  - ${YELLOW}Skipped critical IP:${NC} $ip_to_block_now"
                        continue
                    fi
                    if block_ip "$ip_to_block_now" "DNSniper: $domain_input (manual)"; then
                        echo -e "  - ${GREEN}Blocked IP:${NC} $ip_to_block_now"
                        ips_blocked_count_now=$((ips_blocked_count_now + 1))
                    else
                        echo -e "  - ${YELLOW}IP $ip_to_block_now already blocked or error.${NC}"
                    fi
                done
                if [[ $ips_blocked_count_now -gt 0 ]]; then
                    make_rules_persistent
                    echo -e "${GREEN}Firewall rules updated for '$domain_input'.${NC}"
                else
                    echo -e "${YELLOW}No new IP rules were added for '$domain_input'.${NC}"
                fi
            fi
        fi
    fi
}

# Show help menu
show_help() {
    _show_banner_if_interactive # Or just `clear` if banner is too much for help
    echo -e "${BOLD}DNSniper v$VERSION - Domain-based Network Threat Mitigation${NC}"
    echo -e "Repository: https://github.com/MahdiGraph/DNSniper"
    echo -e "\n${BOLD}Usage:${NC} sudo dnsniper [option]"
    echo -e "\n  Running 'sudo dnsniper' without options starts the interactive menu."
    echo -e "\n${BOLD}Command-line Options:${NC}"
    echo -e "  ${YELLOW}--run${NC}                 Run DNSniper once in the foreground (resolves, blocks, updates lists if configured)."
    echo -e "  ${YELLOW}--run-background${NC}      Run DNSniper once in the background. Use for scheduled tasks (e.g., cron)."
    echo -e "  ${YELLOW}--update${NC}              Update the default domain blocklist from the configured URL."
    echo -e "  ${YELLOW}--status${NC}              Display current operational status, statistics, and service info."
    echo -e "  ${YELLOW}--monitor${NC}             Live monitor the progress of a background DNSniper process."
    echo -e "  ${YELLOW}--block${NC} <DOMAIN>      Add <DOMAIN> to the block list (${ADD_FILE})."
    echo -e "  ${YELLOW}--whitelist${NC} <DOMAIN>  Add <DOMAIN> to the whitelist (${REMOVE_FILE}). Removes active blocks if rules exist."
    echo -e "  ${YELLOW}--block-ip${NC} <IP/CIDR> Add <IP/CIDR> to the custom IP block list (${IP_ADD_FILE})."
    echo -e "  ${YELLOW}--whitelist-ip${NC} <IP>  Add <IP/CIDR> to the custom IP whitelist (${IP_REMOVE_FILE}). Removes active blocks."
    echo -e "  ${YELLOW}--check-expired${NC}    Manually trigger a check for expired domain rules."
    echo -e "  ${YELLOW}--version${NC}             Show DNSniper version."
    echo -e "  ${YELLOW}--help${NC}               Show this help message."
    echo -e "\n${DIM}Configuration file: $CONFIG_FILE${NC}"
    echo -e "${DIM}Log file (if enabled): $LOG_FILE${NC}"
    echo -e ""
}


# Argument Handling
handle_args() {
    # Ensure core environment is set up for CLI operations too
    # ensure_environment is called in main, so it should be fine here.

    case "$1" in
        --run)
            # run_with_lock ensures only one instance runs and handles errors/logging.
            # It should not produce much stdout other than progress if interactive.
            # For CLI --run, we might want less verbose output than menu driven.
            echo -e "${BLUE}Starting DNSniper run (foreground)...${NC}"
            export DNSniper_NONINTERACTIVE=0 # Treat as somewhat interactive
            if ! run_with_lock; then
                echo -e "${RED}DNSniper run failed or was locked. Check logs.${NC}" >&2
                exit 1
            fi
            echo -e "${GREEN}DNSniper run completed.${NC}"
            ;;
        --run-background)
            echo -e "${BLUE}Attempting to start DNSniper in background...${NC}"
            # run_background handles locking and sets DNSniper_NONINTERACTIVE
            if run_background; then # This function will output its own success/failure or log it.
                 echo -e "${GREEN}DNSniper started in background. Check 'dnsniper --status' or logs.${NC}"
            else
                 echo -e "${RED}Failed to start DNSniper in background. Another instance might be running or an error occurred.${NC}" >&2
                 exit 1 # Explicitly exit with error if run_background indicated failure
            fi
            ;;
        --update)
            echo -e "${BLUE}Updating default domain list...${NC}"
            export DNSniper_NONINTERACTIVE=1
            if update_default; then echo -e "${GREEN}Update process completed.${NC}"; else echo -e "${RED}Update failed.${NC}" >&2; exit 1; fi
            ;;
        --status) export DNSniper_NONINTERACTIVE=0; display_status ;; # display_status will clear and show full status
        --monitor) export DNSniper_NONINTERACTIVE=0; monitor_background_process ;;
        --block)
            if [[ -z "$2" ]]; then echo -e "${RED}Error: Missing domain for --block${NC}"; show_help; exit 1; fi
            if ! is_valid_domain "$2"; then echo -e "${RED}Error: Invalid domain format '$2'${NC}"; exit 1; fi
            echo "$2" >> "$ADD_FILE"; sort -u -o "$ADD_FILE" "$ADD_FILE" # Add and ensure uniqueness
            grep -Fxv "$2" "$REMOVE_FILE" > "${REMOVE_FILE}.tmp" && mv "${REMOVE_FILE}.tmp" "$REMOVE_FILE" # Remove from whitelist
            echo -e "${GREEN}Domain '$2' added to block list and removed from whitelist.${NC}"
            log "INFO" "Domain '$2' added to block list via CLI." "verbose"
            ;;
        --whitelist)
            if [[ -z "$2" ]]; then echo -e "${RED}Error: Missing domain for --whitelist${NC}"; show_help; exit 1; fi
            if ! is_valid_domain "$2"; then echo -e "${RED}Error: Invalid domain format '$2'${NC}"; exit 1; fi
            echo "$2" >> "$REMOVE_FILE"; sort -u -o "$REMOVE_FILE" "$REMOVE_FILE"
            grep -Fxv "$2" "$ADD_FILE" > "${ADD_FILE}.tmp" && mv "${ADD_FILE}.tmp" "$ADD_FILE" # Remove from blocklist
            echo -e "${GREEN}Domain '$2' added to whitelist and removed from block list.${NC}"
            # Implement immediate unblocking logic if desired, or tell user to run main process
            read -rp "Unblock related IPs from firewall now? [y/N]: " unblock_now_cli
            if [[ "$unblock_now_cli" =~ ^[Yy]$ ]]; then
                # Simplified unblock for CLI
                local domain_to_unblock_cli="$2"
                local history_ips_cli; history_ips_cli=$(get_domain_ips "$domain_to_unblock_cli")
                if [[ -n "$history_ips_cli" ]]; then
                    IFS=',' read -ra ip_array_cli <<< "$history_ips_cli"
                    for ip_cli in "${ip_array_cli[@]}"; do
                        whitelist_ip "$ip_cli" "DNSniper: $domain_to_unblock_cli" && echo "Unblocked $ip_cli for $domain_to_unblock_cli"
                    done
                    make_rules_persistent
                else echo "No IP history for $domain_to_unblock_cli to unblock immediately."; fi
            fi
            log "INFO" "Domain '$2' added to whitelist via CLI." "verbose"
            ;;
        # ... similar logic for --block-ip and --whitelist-ip ...
        --check-expired)
            echo -e "${BLUE}Checking for expired domain rules...${NC}"
            export DNSniper_NONINTERACTIVE=1
            check_expired_domains && echo -e "${GREEN}Expired domain check complete.${NC}" || echo -e "${RED}Expired domain check failed.${NC}" >&2 exit 1;
            ;;
        --version) echo "DNSniper version $VERSION"; ;;
        --help) show_help ;;
        *) return 1 ;; # Indicates argument not handled, main will show help
    esac
    return 0 # Argument handled
}

# Entry point
main() {
    # Check if running as root
    check_root # Exits if not root

    # Ensure environment is prepared (creates files/dirs, loads config, initializes logging)
    # This function uses defaults from core.sh if config is missing/new
    ensure_environment
    
    # Handle command line arguments if provided
    if [[ $# -gt 0 ]]; then
        if handle_args "$@"; then # handle_args will exit 0 if it successfully handled the arg
            exit 0
        else # Argument was not recognized by handle_args
            show_help
            exit 1
        fi
    fi
    # No arguments, or unhandled argument: start interactive menu
    main_menu
}

# Execute main function with all arguments passed to it
main "$@"