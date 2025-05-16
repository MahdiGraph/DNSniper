#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.0

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

### Interactive menu functions
# --- Settings submenu ---
settings_menu() {
    while true; do
        show_banner
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
        echo -e "${YELLOW}0.${NC} Back to Main Menu"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
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
            *) echo -e "${RED}Invalid selection. Please choose 0-9.${NC}" ;;
        esac
        read -rp "Press Enter to continue..."
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
        # Clear all rules
        echo -e "${BLUE}Clearing existing rules...${NC}"
        iptables -F "$IPT_CHAIN" 2>/dev/null && ip6tables -F "$IPT6_CHAIN" 2>/dev/null
        log "INFO" "Cleared rules for rule type changes" "verbose"
        # Run a full resolve_block to rebuild the rules with new settings
        echo -e "${BLUE}Rebuilding rules with new settings...${NC}"
        resolve_block
        echo -e "${GREEN}Rule type changes applied successfully.${NC}"
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
            *) echo -e "${RED}Invalid selection. Please choose 0-8.${NC}" ;;
        esac
        read -rp "Press Enter to continue..."
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
    # Process the filtered domains
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        # Validate domain format
        if is_valid_domain "$domain"; then
            # Check if domain already exists
            if ! grep -Fxq "$domain" "$existing_domains"; then
                echo "$domain" >> "$ADD_FILE"
                count=$((count + 1))
            fi
        fi
    done < "$tmpfile"
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
    merge_domains > "$tmpfile"
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

# Import IPs
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
    # Process and validate IPs
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        # Validate IP format
        if is_ipv6 "$ip" || is_valid_ipv4 "$ip"; then
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
            echo -e "${YELLOW}Skipped invalid IP:${NC} $ip"
        fi
    done < "$tmpfile"
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
    get_custom_ips > "$tmpfile"
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
    # Export current rules
    iptables-save | grep -E "(^*|^:|^-A $IPT_CHAIN)" > "$ipv4_rules" 2>/dev/null
    ip6tables-save | grep -E "(^*|^:|^-A $IPT6_CHAIN)" > "$ipv6_rules" 2>/dev/null
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
    if [[ -f "$dir/domains.txt" || -f "$dir/ips.txt" || -f "$dir/config.conf" || -f "$dir/history.db" ]]; then
        # Import domains if exists
        if [[ -f "$dir/domains.txt" && -r "$dir/domains.txt" ]]; then
            cp "$dir/domains.txt" "$ADD_FILE.tmp"
            mv "$ADD_FILE.tmp" "$ADD_FILE"
            echo -e "${GREEN}Imported domains from backup.${NC}"
        fi
        # Import IPs if exists
        if [[ -f "$dir/ips.txt" && -r "$dir/ips.txt" ]]; then
            cp "$dir/ips.txt" "$IP_ADD_FILE.tmp"
            mv "$IP_ADD_FILE.tmp" "$IP_ADD_FILE"
            echo -e "${GREEN}Imported IPs from backup.${NC}"
        fi
        # Import config if exists
        if [[ -f "$dir/config.conf" && -r "$dir/config.conf" ]]; then
            cp "$dir/config.conf" "$CONFIG_FILE.tmp"
            mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
            echo -e "${GREEN}Imported configuration from backup.${NC}"
        fi
        # Import database if exists
        if [[ -f "$dir/history.db" && -r "$dir/history.db" ]]; then
            cp "$dir/history.db" "$DB_FILE.tmp"
            mv "$DB_FILE.tmp" "$DB_FILE"
            echo -e "${GREEN}Imported history database from backup.${NC}"
        fi
        # Re-initialize environment with imported settings
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
    # Export domains
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
    cp "$CONFIG_FILE" "$export_dir/config.conf" 2>/dev/null || true
    # Export current iptables rules
    if command -v iptables-save &>/dev/null; then
        iptables-save | grep -E "(^*|^:|^-A $IPT_CHAIN)" > "$export_dir/iptables-rules.txt" 2>/dev/null || true
        ip6tables-save | grep -E "(^*|^:|^-A $IPT6_CHAIN)" > "$export_dir/ip6tables-rules.txt" 2>/dev/null || true
    fi
    # Export database if available
    if [[ -f "$DB_FILE" ]]; then
        # Use a more reliable approach for SQLite DB copying
        if command -v sqlite3 &>/dev/null; then
            # Create a backup of the database
            sqlite3 "$DB_FILE" ".backup '$export_dir/history.db'" 2>/dev/null || cp "$DB_FILE" "$export_dir/history.db" 2>/dev/null || true
        else
            # Fallback to direct copy if sqlite3 is not available
            cp "$DB_FILE" "$export_dir/history.db" 2>/dev/null || true
        fi
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
    echo -e "${GREEN}Complete backup exported to: $export_dir${NC}"
    log "INFO" "Complete backup exported to: $export_dir" "verbose"
    return 0
}

# --- Block/Unblock Domain/IP Functions ---
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
        echo -e "${BLUE}Resolving and blocking $domain...${NC}"
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
                echo -e "  - ${YELLOW}Skipped critical IP${NC}: $ip"
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
            echo -e "  ${YELLOW}No valid IP addresses found${NC}"
            return 0
        fi
        # Convert array to CSV for storage
        local ips_csv=$(IFS=,; echo "${unique[*]}")
        # Record in history
        record_history "$domain" "$ips_csv"
        # Block each IP
        for ip in "${unique[@]}"; do
            if block_ip "$ip" "DNSniper: $domain"; then
                echo -e "  - ${RED}Blocked${NC}: $ip"
            else
                echo -e "  - ${RED}Error blocking${NC}: $ip"
            fi
        done
        # Make rules persistent
        make_rules_persistent
    fi
    return 0
}

# Unblock domain
unblock_domain() {
    echo -e "${BOLD}=== Unblock Domain ===${NC}"
    # Get all active domains
    local tmpdomains=$(mktemp)
    merge_domains > "$tmpdomains"
    local total=$(wc -l < "$tmpdomains")
    if [[ $total -eq 0 ]]; then
        echo -e "${YELLOW}No active domains to unblock.${NC}"
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
    read -rp "Enter domain number or domain name to unblock: " choice
    local domain_to_unblock=""
    # Check if choice is a number and within range
    if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le $total ]]; then
        domain_to_unblock=$(sed -n "${choice}p" "$tmpdomains")
    else
        domain_to_unblock="$choice"
    fi
    rm -f "$tmpdomains"
    if [[ -z "$domain_to_unblock" ]]; then
        echo -e "${RED}Invalid selection.${NC}"
        return 1
    fi
    # Validate domain format
    if ! is_valid_domain "$domain_to_unblock"; then
        echo -e "${RED}Invalid domain format: $domain_to_unblock${NC}"
        return 1
    fi
    # Add to remove file if not already there
    if ! grep -Fxq "$domain_to_unblock" "$REMOVE_FILE" 2>/dev/null; then
        echo "$domain_to_unblock" >> "$REMOVE_FILE"
        echo -e "${GREEN}Domain unblocked:${NC} $domain_to_unblock"
        log "INFO" "Domain added to unblock list: $domain_to_unblock" "verbose"
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this domain immediately? [y/N]: " unblock_now
        if [[ "$unblock_now" =~ ^[Yy] ]]; then
            echo -e "${BLUE}Removing firewall rules for $domain_to_unblock...${NC}"
            # Get IPs from history
            local esc_dom=$(sql_escape "$domain_to_unblock")
            local ips
            ips=$(sqlite3 "$DB_FILE" "SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1;" 2>/dev/null)
            if [[ -n "$ips" ]]; then
                IFS=',' read -ra ip_list <<< "$ips"
                for ip in "${ip_list[@]}"; do
                    if unblock_ip "$ip" "DNSniper: $domain_to_unblock"; then
                        echo -e "  - ${GREEN}Unblocked${NC}: $ip"
                    fi
                done
                # Make rules persistent
                make_rules_persistent
            else
                echo -e "${YELLOW}No IP records found for this domain.${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}Domain already in unblock list.${NC}"
    fi
    return 0
}

# Block IP
block_custom_ip() {
    echo -e "${BOLD}=== Block IP Address ===${NC}"
    read -rp "IP address to block: " ip
    if [[ -z "$ip" ]]; then
        echo -e "${RED}IP cannot be empty.${NC}"
        return 1
    fi
    # Validate IP format
    if ! is_ipv6 "$ip" && ! is_valid_ipv4 "$ip"; then
        echo -e "${RED}Invalid IP format.${NC}"
        return 1
    fi
    # Check if it's a critical IP
    if is_critical_ip "$ip"; then
        echo -e "${RED}Cannot block critical IP address: $ip${NC}"
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
        if block_ip "$ip" "DNSniper: custom"; then
            echo -e "${GREEN}Successfully blocked IP:${NC} $ip"
            # Make rules persistent
            make_rules_persistent
        else
            echo -e "${RED}Error blocking IP:${NC} $ip"
        fi
    fi
    return 0
}

# Unblock IP
unblock_custom_ip() {
    echo -e "${BOLD}=== Unblock IP Address ===${NC}"
    # Get all custom IPs
    local tmpips=$(mktemp)
    get_custom_ips > "$tmpips"
    local total=$(wc -l < "$tmpips")
    if [[ $total -eq 0 ]]; then
        echo -e "${YELLOW}No custom IPs to unblock.${NC}"
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
    read -rp "Enter IP number or IP address to unblock: " choice
    local ip_to_unblock=""
    # Check if choice is a number and within range
    if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le $total ]]; then
        ip_to_unblock=$(sed -n "${choice}p" "$tmpips")
    else
        ip_to_unblock="$choice"
    fi
    rm -f "$tmpips"
    if [[ -z "$ip_to_unblock" ]]; then
        echo -e "${RED}Invalid selection.${NC}"
        return 1
    fi
    # Validate IP format
    if ! is_ipv6 "$ip_to_unblock" && ! is_valid_ipv4 "$ip_to_unblock"; then
        echo -e "${RED}Invalid IP format.${NC}"
        return 1
    fi
    # Add to remove file if not already there
    if ! grep -Fxq "$ip_to_unblock" "$IP_REMOVE_FILE" 2>/dev/null; then
        echo "$ip_to_unblock" >> "$IP_REMOVE_FILE"
        echo -e "${GREEN}IP unblocked:${NC} $ip_to_unblock"
        log "INFO" "IP added to unblock list: $ip_to_unblock" "verbose"
        # Ask if to remove firewall rules immediately
        read -rp "Remove firewall rules for this IP immediately? [y/N]: " unblock_now
        if [[ "$unblock_now" =~ ^[Yy] ]]; then
            if unblock_ip "$ip_to_unblock" "DNSniper: custom"; then
                echo -e "${GREEN}Successfully unblocked IP:${NC} $ip_to_unblock"
                # Make rules persistent
                make_rules_persistent
            else
                echo -e "${RED}Error unblocking IP:${NC} $ip_to_unblock"
            fi
        fi
    else
        echo -e "${YELLOW}IP already in unblock list.${NC}"
    fi
    return 0
}

# Show status - Performance optimized
display_status() {
    # Start processing in background for better UI responsiveness
    clear
    echo -e "${BLUE}Loading DNSniper status, please wait...${NC}"
    # Create a temp file for processing
    local tmpout=$(mktemp)
    # Run analysis and data gathering in background
    (
        show_banner > "$tmpout"
        # Get domains and IPs in a more efficient way
        local domain_count=$(merge_domains | wc -l)
        local blocked_ips=$(count_blocked_ips)
        local custom_ip_count=$(get_custom_ips | wc -l)
        
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
        
        # Get service status
        local service_status=$(get_service_status)
        
        # Count expired domains pending cleanup - only if feature is enabled
        local expired_count=0
        if [[ "$expire_enabled" == "1" ]]; then
            local expire_minutes=$((schedule_minutes * expire_multiplier))
            expired_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM expired_domains
                                              WHERE source='default' AND
                                              datetime(last_seen, '+$expire_minutes minutes') < datetime('now');" 2>/dev/null || echo 0)
        fi
        
        # Display summary counts
        {
            echo -e "${CYAN}${BOLD}SYSTEM STATUS${NC}"
            echo -e "${MAGENTA}───────────────────────────────────────${NC}"
            echo -e "${BOLD}Blocked Domains:${NC}      ${GREEN}${domain_count}${NC}"
            echo -e "${BOLD}Blocked IPs:${NC}          ${RED}${blocked_ips}${NC}"
            echo -e "${BOLD}Custom IPs:${NC}           ${YELLOW}${custom_ip_count}${NC}"
            if [[ $expired_count -gt 0 && "$expire_enabled" == "1" ]]; then
                echo -e "${BOLD}Pending Expirations:${NC}  ${YELLOW}$expired_count${NC}"
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
            local last_run
            if [[ -f "$LOG_FILE" ]]; then
                last_run=$(stat -c %y "$LOG_FILE" 2>/dev/null || echo "Never")
            else
                last_run="Never"
            fi
            echo -e "${BOLD}Last Run:${NC}           ${BLUE}$last_run${NC}"
            echo -e "${BOLD}Version:${NC}            ${GREEN}$VERSION${NC}"
            
            # Domain and IP sections only for moderate list sizes
            if [[ $domain_count -gt 0 && $domain_count -le 500 ]]; then
                echo -e ""
                echo -e "${CYAN}${BOLD}BLOCKED DOMAINS (TOP 10 OF ${domain_count})${NC}"
                echo -e "${MAGENTA}───────────────────────────────────────${NC}"
                # Only process top 10 domains for performance
                local tmpdomain=$(mktemp)
                merge_domains | head -10 > "$tmpdomain"
                local dom_count=0
                while IFS= read -r dom || [[ -n "$dom" ]]; do
                    # Check if there are records for this domain
                    local esc_dom=$(sql_escape "$dom")
                    local record_count
                    record_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM history WHERE domain='$esc_dom';" 2>/dev/null || echo "0")
                    if [[ "$record_count" -gt 0 ]]; then
                        # Records exist, get IP count
                        local ip_count
                        ip_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(distinct ip) FROM (
                                  SELECT value as ip FROM history
                                  JOIN json_each('['||(SELECT ips FROM history WHERE domain='$esc_dom' ORDER BY ts DESC LIMIT 1)||']')
                                  WHERE domain='$esc_dom'
                                  );" 2>/dev/null || echo "0")
                        echo -e "${GREEN}$dom${NC} (${YELLOW}$ip_count IPs${NC})"
                    else
                        # No record in database
                        echo -e "${GREEN}$dom${NC} (${RED}Not resolved yet${NC})"
                    fi
                    dom_count=$((dom_count + 1))
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
    # Wait for analysis to complete
    wait
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

# Uninstall
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
        rm -f "$BIN_CMD" 2>/dev/null || true
        rm -f "/etc/dnsniper/dnsniper-core.sh" 2>/dev/null || true
        rm -f "/etc/dnsniper/dnsniper-daemon.sh" 2>/dev/null || true
        rm -f "/etc/dnsniper/dnsniper.sh" 2>/dev/null || true
        rm -rf "$BASE_DIR" 2>/dev/null || true
        
        echo -e "${GREEN}DNSniper successfully uninstalled.${NC}"
        exit 0
    else
        echo -e "${YELLOW}Uninstall canceled.${NC}"
    fi
    return 0
}

# Show help
show_help() {
    show_banner
    echo -e "${BOLD}=== DNSniper v$VERSION Help ===${NC}"
    echo -e "${BOLD}Usage:${NC} dnsniper [options]"
    echo -e ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  ${YELLOW}--run${NC}        Run DNSniper once (non-interactive)"
    echo -e "  ${YELLOW}--update${NC}     Update default domains list"
    echo -e "  ${YELLOW}--status${NC}     Display status"
    echo -e "  ${YELLOW}--block${NC} DOMAIN Add a domain to block list"
    echo -e "  ${YELLOW}--unblock${NC} DOMAIN Remove a domain from block list"
    echo -e "  ${YELLOW}--block-ip${NC} IP Add an IP to block list"
    echo -e "  ${YELLOW}--unblock-ip${NC} IP Remove an IP from block list"
    echo -e "  ${YELLOW}--check-expired${NC} Check and remove expired rules"
    echo -e "  ${YELLOW}--version${NC}    Show version"
    echo -e "  ${YELLOW}--help${NC}       Show this help"
    echo -e ""
    echo -e "${BOLD}Interactive Menu:${NC}"
    echo -e "  Run without arguments to access the interactive menu"
    echo -e "  which provides all functionality, configuration options,"
    echo -e "  and maintenance features."
    echo -e ""
    return 0
}

# Main menu loop
main_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}${BOLD}MAIN MENU${NC}"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        echo -e "${YELLOW}1.${NC} Run Now              ${YELLOW}2.${NC} Status"
        echo -e "${YELLOW}3.${NC} Block Domain         ${YELLOW}4.${NC} Unblock Domain"
        echo -e "${YELLOW}5.${NC} Block IP Address     ${YELLOW}6.${NC} Unblock IP Address"
        echo -e "${YELLOW}7.${NC} Settings             ${YELLOW}8.${NC} Update Lists"
        echo -e "${YELLOW}9.${NC} Clear Rules          ${YELLOW}0.${NC} Exit"
        echo -e "${YELLOW}U.${NC} Uninstall"
        echo -e "${MAGENTA}───────────────────────────────────────${NC}"
        read -rp "Select an option: " choice
        case "$choice" in
            1) clear; run_with_lock; read -rp "Press Enter to continue..." ;;
            2) display_status; read -rp "Press Enter to continue..." ;;
            3) clear; block_domain; read -rp "Press Enter to continue..." ;;
            4) clear; unblock_domain; read -rp "Press Enter to continue..." ;;
            5) clear; block_custom_ip; read -rp "Press Enter to continue..." ;;
            6) clear; unblock_custom_ip; read -rp "Press Enter to continue..." ;;
            7) settings_menu ;;
            8) clear; update_default; read -rp "Press Enter to continue..." ;;
            9) clear; clear_rules; read -rp "Press Enter to continue..." ;;
            0) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
            [Uu]) clear; uninstall ;;
            *) echo -e "${RED}Invalid selection. Please choose from the menu.${NC}"; sleep 1 ;;
        esac
    done
}

handle_args() {
    case "$1" in
        --run)
            run_with_lock
            ;;
        --update)
            update_default
            ;;
        --status)
            display_status
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
        --unblock)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: missing domain parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$REMOVE_FILE"
            echo -e "${GREEN}Domain added to unblock list:${NC} $2"
            log "INFO" "Domain unblocked via CLI: $2" "verbose"
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
        --unblock-ip)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: missing IP parameter${NC}"
                show_help
                exit 1
            fi
            echo "$2" >> "$IP_REMOVE_FILE"
            echo -e "${GREEN}IP added to unblock list:${NC} $2"
            log "INFO" "IP unblocked via CLI: $2" "verbose"
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
    
    # Initialize logging
    initialize_logging
    
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