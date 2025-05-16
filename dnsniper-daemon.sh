#!/usr/bin/env bash
# DNSniper Service Functions - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.1
# Source the core functionality
if [[ -f /etc/dnsniper/dnsniper-core.sh ]]; then
    source /etc/dnsniper/dnsniper-core.sh
else
    echo "Error: Core DNSniper functionality not found" >&2
    exit 1
fi
# مکانیزم قفل‌گذاری پروسس با عملیات اتمیک
acquire_lock() {
    # استفاده از ایجاد فایل اتمیک برای کسب قفل
    if ( set -o noclobber; echo "$$" > "$LOCK_FILE") 2> /dev/null; then
        # قفل با موفقیت گرفته شد
        log "INFO" "Lock acquired for process $$" "verbose"
        # تنظیم trap برای حذف فایل قفل هنگام خروج
        trap 'release_lock' EXIT HUP INT QUIT TERM
        return 0
    else
        # ناموفق در کسب قفل
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        # بررسی فعال بودن پروسس
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            # پروسس هنوز در حال اجراست
            log "WARNING" "Another DNSniper process is already running (PID: $pid)" "verbose"
            return 1
        else
            # فایل قفل قدیمی، حذف و تلاش مجدد
            rm -f "$LOCK_FILE" 2>/dev/null || true
            if ( set -o noclobber; echo "$$" > "$LOCK_FILE") 2> /dev/null; then
                # قفل در تلاش دوم با موفقیت گرفته شد
                log "INFO" "Lock acquired for process $$ (after removing stale lock)" "verbose"
                # تنظیم trap برای حذف فایل قفل هنگام خروج
                trap 'release_lock' EXIT HUP INT QUIT TERM
                return 0
            else
                # همچنان ناموفق در کسب قفل
                log "WARNING" "Failed to acquire lock after removing stale lock file" "verbose"
                return 1
            fi
        fi
    fi
}
release_lock() {
    # حذف قفل فقط اگر متعلق به پروسس فعلی باشد
    local pid
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [[ "$pid" == "$$" ]]; then
        rm -f "$LOCK_FILE" 2>/dev/null || true
        log "INFO" "Lock released for process $$" "verbose"
        # حذف trap
        trap - EXIT HUP INT QUIT TERM
    fi
    return 0
}
# Create systemd service and timer
create_systemd_service() {
    log "INFO" "Creating systemd services for DNSniper" "verbose"
    # Create the main service
    cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/dnsniper --run
RemainAfterExit=no
[Install]
WantedBy=multi-user.target
EOF
    # Create the timer
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
OnBootSec=60s
OnUnitActiveSec=${schedule_minutes}m
AccuracySec=60s
[Install]
WantedBy=timers.target
EOF
    # Create firewall persistence service
    cat > /etc/systemd/system/dnsniper-firewall.service << EOF
[Unit]
Description=DNSniper Firewall Rules
After=network.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore $RULES_V4_FILE
ExecStart=/sbin/ip6tables-restore $RULES_V6_FILE
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    # Reload systemd
    systemctl daemon-reload &>/dev/null || true
    # Enable firewall persistence service
    systemctl enable dnsniper-firewall.service &>/dev/null || true
    # Enable timer if scheduler is enabled
    local scheduler_enabled=$(grep '^scheduler_enabled=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ "$scheduler_enabled" == "1" ]]; then
        systemctl enable dnsniper.service &>/dev/null || true
        systemctl enable dnsniper.timer &>/dev/null || true
        systemctl start dnsniper.timer &>/dev/null || true
        log "INFO" "DNSniper scheduler enabled to run every $schedule_minutes minutes" "verbose"
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
    systemctl restart dnsniper-firewall.service &>/dev/null
    log "INFO" "Created initial rules files and started firewall service" "verbose"
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
    systemctl daemon-reload &>/dev/null || true
    # Enable or disable timer based on settings
    if [[ "$scheduler_enabled" == "1" ]]; then
        systemctl enable dnsniper.service &>/dev/null || true
        systemctl enable dnsniper.timer &>/dev/null || true
        systemctl restart dnsniper.timer &>/dev/null || true
        log "INFO" "DNSniper scheduler updated to run every $schedule_minutes minutes" "verbose"
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
                timer_status="${GREEN}Active ($(systemctl show -p NextElopement --value dnsniper.timer))${NC}"
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
        local last_run=$(systemctl show dnsniper.service -p ActiveEnterTimestamp --value)
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
# Run with process locking
run_with_lock() {
    if acquire_lock; then
        # Execute command with lock
        resolve_block
        # Release lock when done
        release_lock
    else
        log "WARNING" "Cannot acquire lock, another DNSniper process is running"
        echo -e "${YELLOW}Warning:${NC} Another DNSniper process is running. Please wait for it to complete."
        return 1
    fi
    return 0
}
# Clean up any cron jobs from previous versions
cleanup_cron_jobs() {
    log "INFO" "Checking for old cron jobs" "verbose"
    if command -v crontab &>/dev/null; then
        # Check if dnsniper is in crontab
        if crontab -l 2>/dev/null | grep -q "$BIN_CMD"; then
            log "INFO" "Found old cron jobs, removing them" "verbose"
            # Remove dnsniper entries from crontab
            (crontab -l 2>/dev/null | grep -v "$BIN_CMD") | crontab - 2>/dev/null || true
            echo -e "${YELLOW}Removed old cron jobs from previous DNSniper version${NC}"
        else
            log "INFO" "No old cron jobs found" "verbose"
        fi
    fi
}