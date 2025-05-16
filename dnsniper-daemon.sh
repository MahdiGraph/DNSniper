#!/usr/bin/env bash
# DNSniper Daemon - Background service
# Version: 2.0.0

# Base paths 
BASE_DIR="/etc/dnsniper"
CORE_SCRIPT="$BASE_DIR/dnsniper-core.sh"
LOG_FILE="$BASE_DIR/dnsniper.log"
STATUS_FILE="$BASE_DIR/status.txt"
LOCK_FILE="/var/lock/dnsniper-daemon.lock"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)." >&2
    exit 1
fi

# Check if another instance is already running
if [[ -f "$LOCK_FILE" ]]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [[ -n "$pid" ]] && ps -p "$pid" > /dev/null 2>&1; then
        echo "DNSniper daemon is already running with PID: $pid"
        exit 0
    else
        # Stale lock file, remove it
        rm -f "$LOCK_FILE"
    fi
fi

# Create lock file
echo $$ > "$LOCK_FILE"

# Create cleanup function to remove lock file on exit
cleanup() {
    rm -f "$LOCK_FILE"
    exit "${1:-0}"
}

# Set up traps for various signals
trap 'cleanup 1' INT TERM
trap 'cleanup 0' EXIT

# Check if core script exists
if [[ ! -f "$CORE_SCRIPT" ]]; then
    echo "Error: Core script not found at $CORE_SCRIPT" >&2
    echo "DNSniper may not be properly installed. Please reinstall." >&2
    cleanup 1
fi

# Source core functions
source "$CORE_SCRIPT"

# Main daemon function
run_daemon() {
    # Update status
    echo "RUNNING" > "$STATUS_FILE"
    
    # Initialize logging
    init_logging
    
    # Log start
    log "INFO" "DNSniper daemon started"
    
    # Update domains list if auto-update is enabled
    if is_auto_update_enabled; then
        log "INFO" "Auto-update enabled, updating domains list"
        update_domains
    fi
    
    # Check for expired domains
    log "INFO" "Checking for expired domains"
    check_expired_domains
    
    # Process domains
    log "INFO" "Processing domains"
    process_domains
    
    # Update status
    echo "READY" > "$STATUS_FILE"
    
    # Log completion
    log "INFO" "DNSniper daemon completed successfully"
    
    return 0
}

# Run the daemon
run_daemon

# Exit is handled by the trap
