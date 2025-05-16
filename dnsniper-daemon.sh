#!/usr/bin/env bash
# DNSniper Daemon - Background service for domain blocking
# Version: 2.0.0

# Daemon lock file
LOCK_FILE="/var/lock/dnsniper-daemon.lock"

# Check if daemon is already running
if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
        echo "DNSniper daemon is already running with PID $pid."
        exit 0
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
STATUS_FILE="$BASE_DIR/status.txt"

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

# Main function
main() {
    # Make sure we're running as root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Must run as root (sudo)."
        exit 1
    fi
    
    # Ensure environment is setup
    ensure_environment
    
    # Initialize logging
    init_logging
    
    # Set initial status
    update_status "RUNNING"
    log "INFO" "DNSniper daemon starting" "verbose"
    
    # Main blocking operation
    if ! resolve_and_block; then
        update_status "ERROR"
        log "ERROR" "Domain resolution failed"
        exit 1
    fi
    
    log "INFO" "DNSniper daemon finished successfully" "verbose"
    update_status "READY"
    exit 0
}

# Call main function
main "$@"