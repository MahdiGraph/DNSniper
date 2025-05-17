#!/usr/bin/env bash
# DNSniper Service Functions - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.3

# Define fallback log function in case sourcing fails
log() {
    local level="$1" message="$2" verbose="${3:-}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # If we're running standalone, log to stderr
    echo "[$timestamp] [$level] $message" >&2
    
    # If we have a LOG_FILE and LOGGING_ENABLED variables (from core script)
    if [[ -n "${LOG_FILE:-}" && "${LOGGING_ENABLED:-0}" -eq 1 ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Now source the core functionality
if [[ -f /etc/dnsniper/dnsniper-core.sh ]]; then
    source /etc/dnsniper/dnsniper-core.sh
else
    echo "Error: Core DNSniper functionality not found" >&2
    exit 1
fi

# Improved atomic process locking mechanism with better error handling
acquire_lock() {
    # Check for stale lock first
    if [[ -f "$LOCK_FILE" ]]; then
        local existing_pid
        existing_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$existing_pid" ]]; then
            # Check if process is still running
            if kill -0 "$existing_pid" 2>/dev/null; then
                # Verify it's actually a DNSniper process
                if ps -p "$existing_pid" -o cmd= 2>/dev/null | grep -q "dnsniper"; then
                    log "WARNING" "Another DNSniper process is already running (PID: $existing_pid)" "verbose"
                    return 1
                else
                    log "INFO" "Found stale lock file with PID $existing_pid (not DNSniper), removing it" "verbose"
                    rm -f "$LOCK_FILE" 2>/dev/null || true
                fi
            else
                log "INFO" "Found stale lock file for PID $existing_pid, removing it" "verbose"
                rm -f "$LOCK_FILE" 2>/dev/null || true
            fi
        else
            # Lock file exists but can't read PID
            log "WARNING" "Found lock file but couldn't read PID, removing it" "verbose"
            rm -f "$LOCK_FILE" 2>/dev/null || true
        fi
    fi
    
    # Try to acquire lock with atomic operation using flock if available
    if command -v flock &>/dev/null; then
        # Create a file descriptor for the lock file
        exec 9>"$LOCK_FILE"
        if flock -n 9; then
            # Lock acquired, write PID to lock file
            echo "$$" >&9
            log "INFO" "Lock acquired for process $$ (using flock)" "verbose"
            # Set trap to remove lock file on exit
            trap 'release_lock' EXIT HUP INT QUIT TERM
            return 0
        else
            exec 9>&- # Close file descriptor
            log "WARNING" "Another DNSniper process is already running (flock)" "verbose"
            return 1
        fi
    else
        # Fallback to traditional method if flock not available
        if ( set -o noclobber; echo "$$" > "$LOCK_FILE") 2> /dev/null; then
            # Lock successfully acquired
            log "INFO" "Lock acquired for process $$" "verbose"
            # Set trap to remove lock file on exit
            trap 'release_lock' EXIT HUP INT QUIT TERM
            return 0
        else
            # Failed to acquire lock
            local pid
            pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
            # Double-check if process is active
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                # Process is still running
                log "WARNING" "Another DNSniper process is already running (PID: $pid)" "verbose"
                return 1
            else
                # Stale lock file that wasn't caught earlier, remove and retry
                rm -f "$LOCK_FILE" 2>/dev/null || true
                if ( set -o noclobber; echo "$$" > "$LOCK_FILE") 2> /dev/null; then
                    # Lock acquired on second attempt
                    log "INFO" "Lock acquired for process $$ (after removing stale lock)" "verbose"
                    # Set trap to remove lock file on exit
                    trap 'release_lock' EXIT HUP INT QUIT TERM
                    return 0
                else
                    # Still failed to acquire lock - possible filesystem or permission issue
                    log "WARNING" "Failed to acquire lock after removing stale lock file" "verbose"
                    return 1
                fi
            fi
        fi
    fi
}

# Check if a background process is running without blocking
is_background_process_running() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            # Verify it's actually a DNSniper process
            if ! ps -p "$pid" -o cmd= 2>/dev/null | grep -q "dnsniper"; then
                # Not a DNSniper process, return false
                echo "0|0|None|None"
                return 1
            fi
            
            # Get info about the process
            local process_start=$(ps -p "$pid" -o lstart= 2>/dev/null || echo "Unknown")
            local process_cmd=$(ps -p "$pid" -o cmd= 2>/dev/null || echo "Unknown")
            
            # Return process info
            echo "1|$pid|$process_start|$process_cmd"
            return 0
        fi
    fi
    
    # No active process
    echo "0|0|None|None"
    return 1
}

# Improved lock release mechanism
release_lock() {
    # Only remove lock if it belongs to current process
    local pid
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [[ "$pid" == "$$" ]]; then
        rm -f "$LOCK_FILE" 2>/dev/null || true
        log "INFO" "Lock released for process $$" "verbose"
        # Remove trap
        trap - EXIT HUP INT QUIT TERM
        return 0
    elif [[ -n "$pid" ]]; then
        log "WARNING" "Not removing lock file: belongs to PID $pid, not $$" "verbose"
    fi
    return 0
}

# Create systemd service and timer with better defaults for system impact
create_systemd_service() {
    log "INFO" "Creating systemd services for DNSniper" "verbose"
    
    # Main service with resource limits and proper error handling
    cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dnsniper --run-background
RemainAfterExit=no
TimeoutStartSec=1800
TimeoutStopSec=90
KillMode=process

# Resource limits to prevent system overload
CPUQuota=40%
IOWeight=40
Nice=10
MemoryMax=512M

# Restart handling
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
EOF

    # Create the timer with randomized delay
    local schedule_minutes=$(grep '^schedule_minutes=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$schedule_minutes" || ! "$schedule_minutes" =~ ^[0-9]+$ ]]; then
        schedule_minutes=$DEFAULT_SCHEDULE_MINUTES
    fi
    
    cat > /etc/systemd/system/dnsniper.timer << EOF
[Unit]
Description=Run DNSniper periodically
Requires=dnsniper.service

[Timer]
Unit=dnsniper.service
OnBootSec=120s
OnUnitActiveSec=${schedule_minutes}m
AccuracySec=60s
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOF

    # Create firewall persistence service with proper failure handling
    cat > /etc/systemd/system/dnsniper-firewall.service << EOF
[Unit]
Description=DNSniper Firewall Rules
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
ExecStart=/bin/bash -c "if [ -f $RULES_V4_FILE ]; then /sbin/iptables-restore $RULES_V4_FILE; else echo 'IPv4 rules file not found'; exit 0; fi"
ExecStart=/bin/bash -c "if [ -f $RULES_V6_FILE ]; then /sbin/ip6tables-restore $RULES_V6_FILE; else echo 'IPv6 rules file not found'; exit 0; fi"
RemainAfterExit=yes
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    if ! systemctl daemon-reload; then
        log "WARNING" "Failed to reload systemd. Services may not be properly registered."
        echo -e "${YELLOW}Warning: Failed to reload systemd. Services may not be properly registered.${NC}" >&2
        return 1
    fi
    
    # Enable firewall persistence service
    systemctl enable dnsniper-firewall.service &>/dev/null || {
        log "WARNING" "Failed to enable dnsniper-firewall.service"
        echo -e "${YELLOW}Warning: Failed to enable dnsniper-firewall.service${NC}" >&2
    }
    
    # Enable timer if scheduler is enabled
    local scheduler_enabled=$(grep '^scheduler_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$scheduler_enabled" == "1" ]]; then
        systemctl enable dnsniper.service &>/dev/null || log "WARNING" "Failed to enable dnsniper.service"
        systemctl enable dnsniper.timer &>/dev/null || log "WARNING" "Failed to enable dnsniper.timer"
        
        if ! systemctl start dnsniper.timer &>/dev/null; then
            log "WARNING" "Failed to start dnsniper.timer"
            echo -e "${YELLOW}Warning: Failed to start timer. Please check systemctl status dnsniper.timer${NC}" >&2
        else
            log "INFO" "DNSniper scheduler enabled to run every $schedule_minutes minutes" "verbose"
        fi
    else
        systemctl disable dnsniper.timer &>/dev/null || true
        systemctl stop dnsniper.timer &>/dev/null || true
        log "INFO" "DNSniper scheduler disabled" "verbose"
    fi
    
    log "INFO" "DNSniper systemd services created" "verbose"
    
    # Ensure rules files exist with minimum content before starting service
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
    
    # Always enable and start firewall service
    systemctl enable dnsniper-firewall.service &>/dev/null
    if ! systemctl restart dnsniper-firewall.service &>/dev/null; then
        log "WARNING" "Failed to start firewall service. Trying to initialize firewall chains."
        
        # Try to initialize firewall chains
        initialize_chains
        
        # Try starting the service again
        if ! systemctl restart dnsniper-firewall.service &>/dev/null; then
            log "ERROR" "Failed to start firewall service after initializing chains."
            echo -e "${RED}Error: Failed to start firewall service.${NC}" >&2
        else
            log "INFO" "Successfully started firewall service after initializing chains."
        fi
    else
        log "INFO" "Created initial rules files and started firewall service" "verbose"
    fi
    
    return 0
}

# Update systemd timer settings
update_systemd_timer() {
    log "INFO" "Updating systemd timer settings" "verbose"
    
    # Get current settings
    local schedule_minutes=$(grep '^schedule_minutes=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$schedule_minutes" || ! "$schedule_minutes" =~ ^[0-9]+$ ]]; then
        schedule_minutes=$DEFAULT_SCHEDULE_MINUTES
    fi
    
    local scheduler_enabled=$(grep '^scheduler_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -z "$scheduler_enabled" || ! "$scheduler_enabled" =~ ^[01]$ ]]; then
        scheduler_enabled=$DEFAULT_SCHEDULER_ENABLED
    fi
    
    # Update timer file with new interval
    if [[ -f /etc/systemd/system/dnsniper.timer ]]; then
        sed -i "s/OnUnitActiveSec=.*m/OnUnitActiveSec=${schedule_minutes}m/" /etc/systemd/system/dnsniper.timer
    else
        # If timer doesn't exist, create services
        create_systemd_service
        return
    fi
    
    # Reload systemd
    if ! systemctl daemon-reload &>/dev/null; then
        log "WARNING" "Failed to reload systemd after updating timer settings."
        echo -e "${YELLOW}Warning: Failed to reload systemd after updating timer.${NC}" >&2
    fi
    
    # Enable or disable timer based on settings
    if [[ "$scheduler_enabled" == "1" ]]; then
        systemctl enable dnsniper.service &>/dev/null || log "WARNING" "Failed to enable dnsniper.service"
        systemctl enable dnsniper.timer &>/dev/null || log "WARNING" "Failed to enable dnsniper.timer"
        
        if ! systemctl restart dnsniper.timer &>/dev/null; then
            log "WARNING" "Failed to restart timer after updating settings."
            echo -e "${YELLOW}Warning: Failed to restart timer. Please check systemctl status dnsniper.timer${NC}" >&2
        else
            log "INFO" "DNSniper scheduler updated to run every $schedule_minutes minutes" "verbose"
        fi
    else
        systemctl disable dnsniper.timer &>/dev/null || true
        systemctl stop dnsniper.timer &>/dev/null || true
        log "INFO" "DNSniper scheduler disabled" "verbose"
    fi
}

# Check systemd service and timer status
get_service_status() {
    local timer_status="Not installed"
    local service_status="Not installed"
    local firewall_status="Not installed"
    
    # Check timer status
    if systemctl list-unit-files dnsniper.timer &>/dev/null; then
        if systemctl is-enabled dnsniper.timer &>/dev/null; then
            if systemctl is-active dnsniper.timer &>/dev/null; then
                local next_run=$(systemctl show -p NextElopement --value dnsniper.timer 2>/dev/null || echo "Unknown")
                timer_status="${GREEN}Active (Next run: ${next_run})${NC}"
            else
                timer_status="${RED}Disabled${NC}"
            fi
        else
            timer_status="${RED}Disabled${NC}"
        fi
    fi
    
    # Check service status
    if systemctl list-unit-files dnsniper.service &>/dev/null; then
        if systemctl is-enabled dnsniper.service &>/dev/null; then
            service_status="${GREEN}Enabled${NC}"
        else
            service_status="${YELLOW}Installed but not enabled${NC}"
        fi
        
        # Check last run
        local last_run=$(systemctl show dnsniper.service -p ActiveEnterTimestamp --value 2>/dev/null || echo "Never")
        if [[ -n "$last_run" && "$last_run" != "n/a" ]]; then
            service_status="$service_status, Last run: $last_run"
        fi
    fi
    
    # Check firewall service status
    if systemctl list-unit-files dnsniper-firewall.service &>/dev/null; then
        if systemctl is-enabled dnsniper-firewall.service &>/dev/null; then
            if systemctl is-active dnsniper-firewall.service &>/dev/null; then
                firewall_status="${GREEN}Active${NC}"
            else
                firewall_status="${RED}Enabled but not active${NC}"
            fi
        else
            firewall_status="${RED}Disabled${NC}"
        fi
    fi
    
    # Return status info
    echo "DNSniper Timer: $timer_status"
    echo "DNSniper Service: $service_status"
    echo "Firewall Service: $firewall_status"
}

# Improved run with process locking in foreground
run_with_lock() {
    # Start with lower priority using nice
    if nice -n 10 acquire_lock; then
        # Execute command with lock
        resolve_block
        
        # Release lock when done
        release_lock
        return 0
    else
        log "WARNING" "Cannot acquire lock, another DNSniper process is running"
        echo -e "${YELLOW}Warning:${NC} Another DNSniper process is running. Please wait for it to complete."
        return 1
    fi
}

# Improved background execution function with better resource constraints
run_background() {
    # Update status to indicate we're starting
    update_status "starting" "Initializing background operation" "0" "0"
    
    # Background processes shouldn't ask for user input - always use non-interactive mode
    export DNSniper_NONINTERACTIVE=1
    
    if acquire_lock; then
        # We got the lock, execute in the background with redirected output
        # Use nice to lower priority and ionice to reduce i/o impact
        if command -v ionice >/dev/null 2>&1; then
            # Use ionice if available (class 3 = idle)
            (
                ionice -c3 nice -n 10 resolve_block > /dev/null 2>&1
                result=$?
                
                # Update status and release lock when done
                if [[ $result -eq 0 ]]; then
                    update_status "completed" "Background operation completed successfully" "100" "0"
                else
                    update_status "error" "Background operation failed with error code $result" "0" "0"
                fi
                
                release_lock
                exit $result
            ) &
        else
            # Fallback to just nice if ionice isn't available
            (
                nice -n 10 resolve_block > /dev/null 2>&1
                result=$?
                
                # Update status and release lock when done
                if [[ $result -eq 0 ]]; then
                    update_status "completed" "Background operation completed successfully" "100" "0"
                else
                    update_status "error" "Background operation failed with error code $result" "0" "0"
                fi
                
                release_lock
                exit $result
            ) &
        fi
        
        # Return success - the background process is now running
        echo -e "${GREEN}Started background process.${NC}"
        return 0
    else
        log "WARNING" "Cannot acquire lock, another DNSniper process is running"
        update_status "error" "Cannot start background operation - another process is running" "0" "0"
        echo -e "${YELLOW}Warning:${NC} Another DNSniper process is running. Please wait for it to complete."
        return 1
    fi
}

# Clean up any cron jobs from previous versions
cleanup_cron_jobs() {
    log "INFO" "Checking for old cron jobs" "verbose"
    
    if command -v crontab &>/dev/null; then
        # Check if dnsniper is in crontab
        if crontab -l 2>/dev/null | grep -q "$BIN_CMD"; then
            log "INFO" "Found old cron jobs, removing them" "verbose"
            
            # Remove dnsniper entries from crontab safely
            (crontab -l 2>/dev/null | grep -v "$BIN_CMD") | crontab - 2>/dev/null || {
                log "WARNING" "Failed to update crontab"
                echo -e "${YELLOW}Warning: Failed to remove old cron jobs.${NC}" >&2
            }
            
            echo -e "${YELLOW}Removed old cron jobs from previous DNSniper version${NC}"
        else
            log "INFO" "No old cron jobs found" "verbose"
        fi
    fi
}

# Initialize ipsets for better performance
initialize_ipsets() {
    log "INFO" "Initializing ipsets for DNSniper" "verbose"
    
    if command -v ipset &>/dev/null; then
        # Create IPv4 ipset if it doesn't exist
        if ! ipset list "$IPSET4" &>/dev/null; then
            ipset create "$IPSET4" hash:ip family inet -exist || {
                log "WARNING" "Failed to create IPv4 ipset"
                echo -e "${YELLOW}Warning: Failed to create IPv4 ipset.${NC}" >&2
            }
        fi
        
        # Create IPv6 ipset if it doesn't exist
        if ! ipset list "$IPSET6" &>/dev/null; then
            ipset create "$IPSET6" hash:ip family inet6 -exist || {
                log "WARNING" "Failed to create IPv6 ipset"
                echo -e "${YELLOW}Warning: Failed to create IPv6 ipset.${NC}" >&2
            }
        fi
        
        # If saved ipsets exist, try to restore them
        if [[ -f "$BASE_DIR/ipset4.conf" ]]; then
            ipset restore < "$BASE_DIR/ipset4.conf" 2>/dev/null || log "WARNING" "Failed to restore IPv4 ipset"
        fi
        
        if [[ -f "$BASE_DIR/ipset6.conf" ]]; then
            ipset restore < "$BASE_DIR/ipset6.conf" 2>/dev/null || log "WARNING" "Failed to restore IPv6 ipset"
        fi
        
        log "INFO" "Ipsets initialized successfully" "verbose"
        return 0
    else
        log "WARNING" "ipset command not available, will use traditional iptables rules"
        echo -e "${YELLOW}Warning: ipset command not available. Performance may be reduced for large rule sets.${NC}" >&2
        return 1
    fi
}