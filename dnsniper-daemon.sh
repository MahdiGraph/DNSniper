#!/usr/bin/env bash
# DNSniper Service Functions - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.3

# Fallback logger for early errors before core.sh is sourced
_daemon_early_log() {
    local level="$1" message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DAEMON-EARLY-$level] $message" >&2
}

# Source the core functionality; exit if it fails.
if [[ -f /etc/dnsniper/dnsniper-core.sh && -x /etc/dnsniper/dnsniper-core.sh ]]; then
    source /etc/dnsniper/dnsniper-core.sh
else
    _daemon_early_log "CRITICAL" "Core DNSniper functionality (/etc/dnsniper/dnsniper-core.sh) not found or not executable."
    exit 1
fi
# Now the 'log' function from core.sh is available.

# Atomic process locking mechanism
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local existing_pid
        existing_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
            log "WARNING" "DNSniper lock held by running process PID: $existing_pid. New process cannot start." "verbose"
            return 1 # Lock busy
        else
            log "INFO" "Found stale lock file for PID $existing_pid (or unreadable PID), removing it." "verbose"
            rm -f "$LOCK_FILE" 2>/dev/null || true
        fi
    fi

    # Attempt to acquire lock using noclobber
    if (set -o noclobber; echo "$$" > "$LOCK_FILE") 2>/dev/null; then
        log "INFO" "Lock acquired by PID $$ for $LOCK_FILE." "verbose"
        trap 'release_lock' EXIT HUP INT QUIT TERM # Ensure lock is released on script exit
        return 0 # Lock acquired
    else
        # This case should be rare if the stale lock check worked.
        # Could be a race condition or filesystem issue.
        local current_holder_pid
        current_holder_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")
        log "ERROR" "Failed to acquire lock $LOCK_FILE. It might be held by PID $current_holder_pid or there's a filesystem issue."
        return 1 # Lock busy or error
    fi
}

# Check if a background process (identified by the lock file) is running
is_background_process_running() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid_in_lock
        pid_in_lock=$(cat "$LOCK_FILE" 2>/dev/null)
        if [[ -n "$pid_in_lock" ]] && kill -0 "$pid_in_lock" 2>/dev/null; then
            local proc_start proc_cmd
            proc_start=$(ps -p "$pid_in_lock" -o lstart= 2>/dev/null || echo "Unknown Start Time")
            proc_cmd=$(ps -p "$pid_in_lock" -o cmd= 2>/dev/null || echo "Unknown Command")
            # Remove extra spaces from proc_start
            proc_start=$(echo "$proc_start" | awk '{$1=$1;print}')
            echo "1|$pid_in_lock|$proc_start|$proc_cmd" # Running|PID|StartTime|Command
            return 0 # Process is running
        fi
    fi
    echo "0|0|None|None" # Not Running
    return 1 # Process not running or lock file issue
}

# Release the lock file, ensuring it's the current process's lock
release_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid_in_lock
        pid_in_lock=$(cat "$LOCK_FILE" 2>/dev/null)
        if [[ "$pid_in_lock" == "$$" ]]; then # Only remove if this process owns the lock
            rm -f "$LOCK_FILE" 2>/dev/null || true
            log "INFO" "Lock $LOCK_FILE released by PID $$." "verbose"
        elif [[ -n "$pid_in_lock" ]]; then
            log "WARNING" "PID $$ attempted to release lock $LOCK_FILE, but it's owned by PID $pid_in_lock. Not removing." "verbose"
        fi
    fi
    trap - EXIT HUP INT QUIT TERM # Remove the trap
    return 0
}

# Create/Update systemd service and timer files
create_systemd_service() {
    log "INFO" "Configuring systemd services for DNSniper..." "verbose"

    # Ensure config values are loaded for timer interval
    local current_schedule_minutes
    current_schedule_minutes=$(get_config_value "schedule_minutes" "$DEFAULT_SCHEDULE_MINUTES")
    
    # dnsniper-firewall.service: Loads iptables rules at boot and on demand
    cat > /etc/systemd/system/dnsniper-firewall.service << EOF
[Unit]
Description=DNSniper Firewall Rules Persistence Service
Documentation=https://github.com/MahdiGraph/DNSniper
# Should run before network is fully up to establish base firewall rules early.
# And before shutdown to ensure rules are saved (though DNSniper mainly saves on change).
Before=network-pre.target shutdown.target
DefaultDependencies=no # This service is critical for firewall state

[Service]
Type=oneshot
# Use full paths for iptables-restore for robustness
ExecStart=/sbin/iptables-restore $RULES_V4_FILE
ExecStart=/sbin/ip6tables-restore $RULES_V6_FILE
# If using ipset directly and saving its state:
# ExecStart=/sbin/ipset restore -f /etc/dnsniper/ipset.rules
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

    # dnsniper.service: The main worker service, run by the timer or manually
    cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation Worker Service
Documentation=https://github.com/MahdiGraph/DNSniper
After=network-online.target dnsniper-firewall.service # Ensure network is up and base firewall rules loaded
Wants=network-online.target
Requires=dnsniper-firewall.service # Must have firewall service available

[Service]
Type=oneshot
# BIN_CMD is defined in core.sh
ExecStart=${BIN_CMD} --run-background
RemainAfterExit=no # Service is oneshot, doesn't remain active
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=30m  # Max time for the service to start and complete (generous)
TimeoutStopSec=1m30s # Time to allow for graceful stop if needed
KillMode=process     # Kill only the main process on stop
# Resource limiting (adjust based on system capacity)
CPUQuota=50%         # Limit to 50% of one CPU core on average
MemoryAccounting=true
MemoryHigh=768M      # Soft limit for memory usage
MemoryMax=1.5G       # Hard limit
IOWeight=200         # Lower I/O priority (10-1000, default 100 for non-system)
Nice=10              # Lower CPU priority

[Install]
WantedBy=multi-user.target # Not directly WantedBy, timer will start it
EOF

    # dnsniper.timer: Schedules the execution of dnsniper.service
    cat > /etc/systemd/system/dnsniper.timer << EOF
[Unit]
Description=DNSniper Periodic Execution Timer
Documentation=https://github.com/MahdiGraph/DNSniper
Requires=dnsniper.service # The timer is for this service

[Timer]
Unit=dnsniper.service
OnBootSec=5min            # Run 5 minutes after boot
OnUnitActiveSec=${current_schedule_minutes}m # Run periodically after the service was last active
AccuracySec=2min          # Allow system to shift timer by up to 2 mins for coalescing
RandomizedDelaySec=1min   # Add random delay to splay jobs if many timers fire at once
Persistent=true           # Run job if missed due to system down time (on next boot/activation)

[Install]
WantedBy=timers.target # Correct target for timers
EOF

    log "INFO" "Systemd unit files created/updated." "verbose"
    if ! systemctl daemon-reload; then
        log "ERROR" "Failed to reload systemd daemon. Manual 'systemctl daemon-reload' may be needed."
        return 1
    fi
    log "INFO" "Systemd daemon reloaded." "verbose"

    # Ensure minimal rules files exist before starting firewall service
    # This is crucial for the first start of dnsniper-firewall.service
    for rules_file in "$RULES_V4_FILE" "$RULES_V6_FILE"; do
        local chain_name="$IPT_CHAIN"
        [[ "$rules_file" == "$RULES_V6_FILE" ]] && chain_name="$IPT6_CHAIN"
        if [[ ! -s "$rules_file" ]]; then # If file doesn't exist or is empty
            log "INFO" "Creating minimal rules file: $rules_file" "verbose"
            echo "*filter" > "$rules_file"
            echo ":INPUT ACCEPT [0:0]" >> "$rules_file"
            echo ":FORWARD ACCEPT [0:0]" >> "$rules_file"
            echo ":OUTPUT ACCEPT [0:0]" >> "$rules_file"
            echo ":${chain_name} - [0:0]" >> "$rules_file" # Ensure our chain is defined
            echo "COMMIT" >> "$rules_file"
        fi
    done

    # Enable and start the firewall service unconditionally
    if systemctl enable dnsniper-firewall.service && systemctl restart dnsniper-firewall.service; then
        log "INFO" "dnsniper-firewall.service enabled and (re)started." "verbose"
    else
        log "WARNING" "Failed to enable or (re)start dnsniper-firewall.service. Check 'journalctl -u dnsniper-firewall.service'."
    fi

    # Enable/disable worker service and timer based on config
    local current_scheduler_enabled
    current_scheduler_enabled=$(get_config_value "scheduler_enabled" "$DEFAULT_SCHEDULER_ENABLED")

    if [[ "$current_scheduler_enabled" == "1" ]]; then
        if systemctl enable dnsniper.service && systemctl enable dnsniper.timer; then
            log "INFO" "dnsniper.service and dnsniper.timer enabled." "verbose"
        else
            log "WARNING" "Failed to enable dnsniper.service or dnsniper.timer."
        fi
        if systemctl start dnsniper.timer; then
            log "INFO" "dnsniper.timer started. DNSniper will run every $current_schedule_minutes minutes."
        else
            log "WARNING" "Failed to start dnsniper.timer."
        fi
    else # Scheduler disabled
        if systemctl disable dnsniper.timer && systemctl stop dnsniper.timer; then
            log "INFO" "dnsniper.timer disabled and stopped as per configuration." "verbose"
        else
            log "WARNING" "Attempted to disable/stop dnsniper.timer but failed or already in that state."
        fi
        # dnsniper.service can remain enabled if users want to trigger it manually via 'systemctl start dnsniper.service'
        # systemctl disable dnsniper.service # Optional: disable the service too if timer is off
    fi
    log "INFO" "Systemd service configuration process finished." "verbose"
    return 0
}

# Update systemd timer settings if schedule changes in config
update_systemd_timer() {
    log "INFO" "Updating systemd timer settings based on configuration." "verbose"
    if ! command -v systemctl &>/dev/null; then
        log "WARNING" "systemctl not found. Cannot update systemd timer."
        return 1
    fi

    # This function essentially re-runs part of create_systemd_service logic
    # related to the timer enable/disable and interval.
    # A simpler way is just to call create_systemd_service again, as it's idempotent.
    if create_systemd_service; then
        log "INFO" "Systemd timer settings successfully updated."
    else
        log "ERROR" "Failed to update systemd timer settings."
        return 1
    fi
    return 0
}

# Get status of DNSniper systemd services
get_service_status() {
    if ! command -v systemctl &>/dev/null; then
        echo "systemctl not found. Cannot retrieve service status."
        return
    fi
    local firewall_active firewall_enabled timer_active timer_enabled service_enabled next_run
    
    firewall_enabled=$(systemctl is-enabled dnsniper-firewall.service 2>/dev/null && echo "Enabled" || echo "Disabled")
    firewall_active=$(systemctl is-active dnsniper-firewall.service 2>/dev/null && echo "${GREEN}Active${NC}" || echo "${RED}Inactive${NC}")
    
    service_enabled=$(systemctl is-enabled dnsniper.service 2>/dev/null && echo "Enabled" || echo "Disabled")
    # dnsniper.service is oneshot, so is-active is usually 'inactive' unless running right now.
    # Check last run time from journal or status file perhaps.

    timer_enabled=$(systemctl is-enabled dnsniper.timer 2>/dev/null && echo "Enabled" || echo "Disabled")
    timer_active=$(systemctl is-active dnsniper.timer 2>/dev/null && echo "${GREEN}Active${NC}" || echo "${RED}Inactive${NC}")
    
    echo -e "Firewall Service (dnsniper-firewall.service): $firewall_enabled, Status: $firewall_active"
    echo -e "Worker Service (dnsniper.service):         $service_enabled"
    echo -e "Timer Service (dnsniper.timer):            $timer_enabled, Status: $timer_active"

    if [[ "$timer_enabled" == "Enabled" && "$timer_active" == "${GREEN}Active${NC}" ]]; then
        next_run=$(systemctl list-timers dnsniper.timer --no-legend | awk '{print $2" "$3" "$4" "$5}')
        # On systemd versions that don't show NEXT directly, this might be harder.
        # systemctl show -p NextElapseUSec --value dnsniper.timer might be better if available.
        local next_elapse_usec next_elapse_realtime
        next_elapse_usec=$(systemctl show -p NextElapseUSec --value dnsniper.timer 2>/dev/null)
        if [[ "$next_elapse_usec" != "0" && -n "$next_elapse_usec" ]]; then
             next_elapse_realtime=$(date -d "@$(($(date +%s) + $(($(systemctl show -p NextElapseUSecMonotonic --value dnsniper.timer)/1000000)) ))" '+%a %Y-%m-%d %H:%M:%S %Z')
             echo -e "Next scheduled run: ${BLUE}${next_elapse_realtime}${NC}"
        else
             echo -e "Next scheduled run: ${YELLOW}Unknown or timer not active/properly set.${NC}"
        fi
    fi
}

# Run DNSniper main logic with process locking (typically for foreground/CLI triggered runs)
run_with_lock() {
    log "INFO" "Attempting to run DNSniper with lock (PID $$)."
    # Set DNSniper_NONINTERACTIVE to 0 if not already set, for interactive-like feedback
    export DNSniper_NONINTERACTIVE=${DNSniper_NONINTERACTIVE:-0}

    if nice -n 5 acquire_lock; then # Slightly higher priority than pure background runs
        log "INFO" "Lock acquired. Executing resolve_block for PID $$."
        # resolve_block is the main workhorse from core.sh
        if resolve_block; then
            log "INFO" "resolve_block completed successfully for PID $$."
        else
            log "ERROR" "resolve_block reported an error for PID $$."
        fi
        release_lock # Ensure lock is always released
        # Return status of resolve_block
        return $? # This will be 0 if resolve_block was successful, non-zero otherwise
    else
        log "WARNING" "Could not acquire lock for PID $$. Another DNSniper process may be running."
        if [[ "${DNSniper_NONINTERACTIVE:-0}" -eq 0 ]]; then # Only echo if interactive context
            echo -e "${YELLOW}Warning:${NC} Another DNSniper process is running or lock file is stuck."
            echo -e "${YELLOW}Please wait for it to complete or check 'dnsniper --status'.${NC}"
        fi
        return 1 # Failed to acquire lock
    fi
}

# Run DNSniper main logic in the background (typically for scheduled/systemd runs)
run_background() {
    # This function is usually called by systemd or cron, so it must be non-interactive.
    export DNSniper_NONINTERACTIVE=1
    log "INFO" "Attempting to run DNSniper in background (PID $$)."
    update_status "starting" "Background operation initializing" "0" "0"

    if acquire_lock; then
        log "INFO" "Lock acquired for background run (PID $$). Executing resolve_block."
        # Use nice to lower priority, ionice for I/O if available
        local cmd_prefix="nice -n 10"
        if command -v ionice &>/dev/null; then
            cmd_prefix="ionice -c3 $cmd_prefix" # Idle I/O priority
        fi
        
        # Execute resolve_block with the chosen prefix. Output goes to systemd journal or /dev/null.
        # Errors from resolve_block will be logged by itself.
        if $cmd_prefix resolve_block; then
            log "INFO" "Background resolve_block completed successfully for PID $$."
            update_status "completed" "Background operation finished successfully." "100" "0"
        else
            local exit_code=$?
            log "ERROR" "Background resolve_block failed for PID $$ with exit code $exit_code."
            update_status "error" "Background operation failed (exit code $exit_code)." "0" "0"
        fi
        release_lock
        return $? # Return the exit code of resolve_block
    else
        log "WARNING" "Could not acquire lock for background run (PID $$). Another instance likely running."
        update_status "error" "Failed to start background task: Lock busy." "0" "0"
        # No echo here, as it's a background task. Logging is sufficient.
        return 1 # Failed to acquire lock
    fi
}

# Clean up old cron jobs if systemd timer is now used
cleanup_cron_jobs() {
    if command -v crontab &>/dev/null; then
        if crontab -l 2>/dev/null | grep -q "$BIN_CMD"; then # BIN_CMD from core.sh
            log "INFO" "Old DNSniper cron job(s) found. Removing them in favor of systemd timer." "verbose"
            (crontab -l 2>/dev/null | grep -v "$BIN_CMD") | crontab - 2>/dev/null || true
            if [[ -t 1 ]]; then # Only echo if in an interactive terminal
                echo -e "${YELLOW}Removed old cron job entries for DNSniper.${NC}"
            fi
        else
            log "INFO" "No old DNSniper cron jobs found." "verbose"
        fi
    fi
}