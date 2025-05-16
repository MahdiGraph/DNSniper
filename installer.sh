#!/usr/bin/env bash
# DNSniper Installer
# Version: 1.4.0

set -e

# ANSI color codes
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
BOLD='\e[1m'
NC='\e[0m'

# Paths
BASE_DIR="/etc/dnsniper"
BIN_PATH="/usr/local/bin/dnsniper"
DAEMON_PATH="/usr/local/bin/dnsniper-daemon"
TMP_SCRIPT="/tmp/dnsniper.sh"
TMP_DAEMON="/tmp/dnsniper-daemon.sh"
BACKUP_DIR="/tmp/dnsniper-backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/tmp/dnsniper-install.log"
GITHUB_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main"

# Display banner
echo -e "${BLUE}${BOLD}"
echo -e "    ____  _   _ ____       _                 "
echo -e "   |   _\\| \\ | /_ __|_ __ (_)_ __   ___ _ __ "
echo -e "   | | | |  \\| \\___ \\ '_ \\| | '_ \\ / _\\ '__|"
echo -e "   | |_| | |\\  |___) | | | | | |_) |  __/ |  "
echo -e "   |____/|_| \\_|____/|_| |_|_| .__/ \\___|_|  "
echo -e "                             |_|              "
echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v1.4.0 ${NC}"
echo -e ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error:${NC} This installer must be run as root (sudo)." >&2
    exit 1
fi

# Setup logging
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${CYAN}${BOLD}CHECKING PREVIOUS INSTALLATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Check for previous installation
if [[ -f "$BIN_PATH" || -d "$BASE_DIR" ]]; then
    echo -e "${YELLOW}${BOLD}Previous installation detected!${NC}"
    echo -e "1) Upgrade (keeps your configurations)"
    echo -e "2) Clean install (removes all configurations)"
    echo -e "3) Cancel installation"
    
    read -rp "Choose an option [1-3]: " choice
    
    case "$choice" in
        1)
            echo -e "${YELLOW}Upgrading DNSniper...${NC}"
            
            # Create backup directory
            mkdir -p "$BACKUP_DIR"
            
            # Stop any running processes and services
            echo -e "${BLUE}Stopping DNSniper services...${NC}"
            
            # Kill any running DNSniper processes
            pkill -f "dnsniper" 2>/dev/null || true
            
            # Disable and stop systemd services if they exist
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.service 2>/dev/null || true
                systemctl disable dnsniper.service 2>/dev/null || true
                
                # Remove old style services if they exist
                systemctl stop dnsniper.timer 2>/dev/null || true
                systemctl disable dnsniper.timer 2>/dev/null || true
                systemctl stop dnsniper-firewall.service 2>/dev/null || true
                systemctl disable dnsniper-firewall.service 2>/dev/null || true
                
                rm -f /etc/systemd/system/dnsniper.timer 2>/dev/null || true
                rm -f /etc/systemd/system/dnsniper-firewall.service 2>/dev/null || true
                
                systemctl daemon-reload 2>/dev/null || true
            fi
            
            # Remove cron jobs
            echo -e "${BLUE}Removing cron jobs...${NC}"
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Backup configuration
            if [[ -d "$BASE_DIR" ]]; then
                echo -e "${YELLOW}Backing up configuration files...${NC}"
                cp -r "$BASE_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
                echo -e "${GREEN}Configuration backed up to: $BACKUP_DIR${NC}"
            fi
            
            # Remove binaries
            rm -f "$BIN_PATH" 2>/dev/null || true
            rm -f "$DAEMON_PATH" 2>/dev/null || true
            ;;
        2)
            echo -e "${YELLOW}Performing clean install...${NC}"
            
            # Kill any running DNSniper processes
            pkill -f "dnsniper" 2>/dev/null || true
            
            # Clean up systemd services
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.service 2>/dev/null || true
                systemctl disable dnsniper.service 2>/dev/null || true
                
                # Remove old style services if they exist
                systemctl stop dnsniper.timer 2>/dev/null || true
                systemctl disable dnsniper.timer 2>/dev/null || true
                systemctl stop dnsniper-firewall.service 2>/dev/null || true
                systemctl disable dnsniper-firewall.service 2>/dev/null || true
                
                rm -f /etc/systemd/system/dnsniper.service 2>/dev/null || true
                rm -f /etc/systemd/system/dnsniper.timer 2>/dev/null || true
                rm -f /etc/systemd/system/dnsniper-firewall.service 2>/dev/null || true
                
                systemctl daemon-reload 2>/dev/null || true
            fi
            
            # Remove cron jobs
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Clean up firewall rules if DNSniper binary exists
            if [[ -f "$BIN_PATH" ]]; then
                echo -e "${YELLOW}Cleaning firewall rules...${NC}"
                "$BIN_PATH" --clean-rules 2>/dev/null || true
            fi
            
            # Remove files
            rm -f "$BIN_PATH" "$DAEMON_PATH" 2>/dev/null || true
            rm -rf "$BASE_DIR" 2>/dev/null || true
            
            echo -e "${GREEN}Previous installation completely removed.${NC}"
            ;;
        3|*)
            echo -e "${RED}Installation cancelled.${NC}"
            exit 0
            ;;
    esac
fi

echo -e "${CYAN}${BOLD}SYSTEM DETECTION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Detect package manager and set command variables
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    PKG_UPDATE="apt update"
    PKG_INSTALL="apt install -y"
    DEPS="iptables iptables-persistent curl dnsutils sqlite3 cron procps"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite crontabs procps-ng"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite crontabs procps-ng"
else
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- sqlite3\n- cron/crontabs\n- procps"
    read -rp "Continue anyway? [y/N]: " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        exit 1
    fi
    PKG_MANAGER="manual"
fi

echo -e "${GREEN}Detected system: ${PKG_MANAGER}${NC}"

# Check system compatibility
if ! command -v iptables &>/dev/null; then
    echo -e "${RED}${BOLD}Error:${NC} iptables not found. DNSniper requires iptables."
    exit 1
fi

# Install dependencies
if [[ "$PKG_MANAGER" != "manual" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}DEPENDENCIES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}Updating package lists...${NC}"
    
    # Use a timeout to prevent hanging on package updates
    timeout 120 bash -c "$PKG_UPDATE" || {
        echo -e "${YELLOW}Package update timed out, continuing anyway...${NC}"
    }
    
    echo -e "${YELLOW}Installing required packages:${NC} ${DEPS}"
    
    # Install packages with error handling
    if ! $PKG_INSTALL $DEPS; then
        echo -e "${YELLOW}Some packages failed to install. Continuing anyway...${NC}"
        echo -e "${YELLOW}You may need to manually install missing dependencies.${NC}"
    else
        echo -e "${GREEN}Dependencies successfully installed.${NC}"
    fi
else
    echo -e ""
    echo -e "${CYAN}${BOLD}DEPENDENCIES CHECK${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    missing=()
    for cmd in iptables ip6tables curl dig sqlite3 crontab ps; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}Missing dependencies:${NC} ${missing[*]}"
        echo -e "${YELLOW}Please install these dependencies and run the installer again.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}All dependencies present.${NC}"
fi

# Create directories
echo -e ""
echo -e "${CYAN}${BOLD}DIRECTORY SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

mkdir -p "$BASE_DIR/logs"
echo -e "${GREEN}Directory created: $BASE_DIR${NC}"

# Setup firewall persistence according to system type
echo -e ""
echo -e "${CYAN}${BOLD}FIREWALL PERSISTENCE${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Detect OS type
if [[ -f /etc/debian_version ]]; then
    OS_TYPE="debian"
    echo -e "${GREEN}Debian/Ubuntu detected, using iptables-persistent${NC}"
    
    # Make sure iptables-persistent is installed
    if ! dpkg -l | grep -q iptables-persistent; then
        echo -e "${YELLOW}Installing iptables-persistent...${NC}"
        # Preseeding debconf to avoid interactive prompts
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        apt install -y iptables-persistent
    fi
    
    mkdir -p /etc/iptables
elif [[ -f /etc/redhat-release ]]; then
    OS_TYPE="redhat"
    echo -e "${GREEN}RHEL/CentOS detected, using iptables-services${NC}"
    
    # Make sure iptables-services is enabled
    if command -v systemctl &>/dev/null; then
        systemctl enable iptables ip6tables &>/dev/null || true
    fi
elif [[ -f /etc/fedora-release ]]; then
    OS_TYPE="fedora"
    echo -e "${GREEN}Fedora detected, using iptables-services${NC}"
    
    # Make sure iptables-services is enabled
    if command -v systemctl &>/dev/null; then
        systemctl enable iptables ip6tables &>/dev/null || true
    fi
else
    OS_TYPE="unknown"
    echo -e "${YELLOW}Unknown OS, will create systemd service for persistence${NC}"
fi

# Download scripts
echo -e ""
echo -e "${CYAN}${BOLD}SCRIPT DOWNLOAD${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Download with retry logic
MAX_RETRIES=3
retry_count=0
download_success=false

# Download the main UI script
while [[ $retry_count -lt $MAX_RETRIES && $download_success == false ]]; do
    echo -e "${YELLOW}Downloading DNSniper UI script (attempt $((retry_count+1))/$MAX_RETRIES)...${NC}"
    
    if curl -sfL --connect-timeout 30 --max-time 60 "$GITHUB_URL/dnsniper.sh" -o "$TMP_SCRIPT"; then
        download_success=true
    else
        retry_count=$((retry_count+1))
        
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            echo -e "${YELLOW}Download failed, retrying in 3 seconds...${NC}"
            sleep 3
        else
            echo -e "${RED}${BOLD}Error:${NC} Failed to download DNSniper script after $MAX_RETRIES attempts."
            exit 1
        fi
    fi
done

# Verify script health
if [[ ! -s "$TMP_SCRIPT" ]]; then
    echo -e "${RED}${BOLD}Error:${NC} Downloaded script is empty."
    exit 1
fi

# Create the daemon service script
cat > "$TMP_DAEMON" << 'EOF'
#!/usr/bin/env bash
# DNSniper Daemon - Runs in background for domain blocking
# This is a separate process from the UI script

# Default paths and settings
BASE_DIR="/etc/dnsniper"
CONFIG_FILE="$BASE_DIR/config.conf"
LOG_FILE="$BASE_DIR/dnsniper.log"
STATUS_FILE="$BASE_DIR/status.txt"
LOCK_FILE="/var/lock/dnsniper-daemon.lock"

# Exit if another instance is running
if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && ps -p "$pid" > /dev/null; then
        echo "DNSniper daemon is already running with PID $pid."
        exit 0
    else
        # Stale lock file
        rm -f "$LOCK_FILE"
    fi
fi

# Create lock file
echo $$ > "$LOCK_FILE"

# Cleanup function
cleanup() {
    rm -f "$LOCK_FILE"
    exit "${1:-0}"
}

# Set traps
trap 'cleanup 1' INT TERM
trap 'cleanup 0' EXIT

# Update status
echo "RUNNING" > "$STATUS_FILE"

# Run the actual blocking operation
if [ -x /usr/local/bin/dnsniper ]; then
    /usr/local/bin/dnsniper --run-silent >> "$LOG_FILE" 2>&1
    result=$?
    
    # Update status based on result
    if [ $result -eq 0 ]; then
        echo "READY" > "$STATUS_FILE"
    else
        echo "ERROR" > "$STATUS_FILE"
    fi
else
    echo "ERROR: DNSniper executable not found" > "$STATUS_FILE"
    exit 1
fi

exit 0
EOF

# Make daemon script executable
chmod +x "$TMP_DAEMON"

# Check for backup to restore
if [[ -d "$BACKUP_DIR" && $(ls -A "$BACKUP_DIR" 2>/dev/null) ]]; then
    echo -e "${YELLOW}Found backup from previous installation.${NC}"
    read -rp "Restore configuration from backup? [Y/n]: " restore_backup
    
    if [[ ! "$restore_backup" =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}Restoring configuration from backup...${NC}"
        mkdir -p "$BASE_DIR"
        cp -r "$BACKUP_DIR"/* "$BASE_DIR/" 2>/dev/null || true
        echo -e "${GREEN}Configuration restored.${NC}"
    else
        echo -e "${YELLOW}Skipping backup restoration.${NC}"
    fi
fi

# Move scripts to final location
echo -e "${BLUE}Installing DNSniper...${NC}"
cp "$TMP_SCRIPT" "$BASE_DIR/dnsniper.sh"
cp "$TMP_DAEMON" "$BASE_DIR/dnsniper-daemon.sh"
ln -sf "$BASE_DIR/dnsniper.sh" "$BIN_PATH"
ln -sf "$BASE_DIR/dnsniper-daemon.sh" "$DAEMON_PATH"
chmod +x "$BASE_DIR/dnsniper.sh" "$BASE_DIR/dnsniper-daemon.sh" "$BIN_PATH" "$DAEMON_PATH"

# Clean up
rm -f "$TMP_SCRIPT" "$TMP_DAEMON"

echo -e "${GREEN}DNSniper scripts installed to:${NC}"
echo -e "  - UI Script: $BIN_PATH"
echo -e "  - Daemon: $DAEMON_PATH"

# Set up scheduling
echo -e ""
echo -e "${CYAN}${BOLD}SCHEDULING${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Ask user about schedule preference
echo -e "${YELLOW}Do you want DNSniper to run automatically?${NC}"
echo -e "1) Yes - Run hourly (recommended)"
echo -e "2) No - I'll run it manually"
read -rp "Choose an option [1-2]: " sched_choice

if [[ "$sched_choice" == "2" ]]; then
    echo -e "${YELLOW}Automatic scheduling disabled.${NC}"
    # Ensure config reflects disabled status
    mkdir -p "$BASE_DIR"
    touch "$BASE_DIR/config.conf"
    sed -i '/^cron=/d' "$BASE_DIR/config.conf" 2>/dev/null || true
    echo "cron='# DNSniper disabled'" >> "$BASE_DIR/config.conf"
else
    # Default: Enable automatic scheduling
    echo -e "${YELLOW}Setting up automatic scheduling...${NC}"
    
    # Create systemd service file (preferred method)
    if command -v systemctl &>/dev/null; then
        cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation
After=network.target

[Service]
Type=oneshot
ExecStart=$DAEMON_PATH
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
    else
        # Fallback to cron if systemd not available
        echo -e "${YELLOW}Systemd not available, using cron instead...${NC}"
        
        # Create cron job for hourly execution
        (crontab -l 2>/dev/null | grep -v "dnsniper"; echo "0 * * * * $DAEMON_PATH >/dev/null 2>&1") | crontab - 2>/dev/null || true
        
        echo -e "${GREEN}DNSniper scheduled with cron (runs hourly)${NC}"
    fi
    
    # Update config file to reflect the schedule
    mkdir -p "$BASE_DIR"
    touch "$BASE_DIR/config.conf"
    sed -i '/^cron=/d' "$BASE_DIR/config.conf" 2>/dev/null || true
    echo "cron='0 * * * * $DAEMON_PATH >/dev/null 2>&1'" >> "$BASE_DIR/config.conf"
fi

# Initialize database and config
echo -e ""
echo -e "${CYAN}${BOLD}INITIALIZING DATABASE${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Create default config if it doesn't exist
if [[ ! -f "$BASE_DIR/config.conf" ]]; then
    cat > "$BASE_DIR/config.conf" << EOF
# DNSniper Configuration
max_ips=10
timeout=30
update_url='https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt'
auto_update=1
expire_enabled=1
expire_multiplier=5
block_source=1
block_destination=1
logging_enabled=1
log_max_size=10
log_rotate_count=5
EOF
fi

# Create empty domain files if they don't exist
touch "$BASE_DIR/domains-default.txt" "$BASE_DIR/domains-add.txt" "$BASE_DIR/domains-remove.txt" "$BASE_DIR/ips-add.txt" "$BASE_DIR/ips-remove.txt"

# Initialize database
if command -v sqlite3 &>/dev/null; then
    sqlite3 "$BASE_DIR/history.db" <<EOF
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS history(
    domain TEXT,
    ips    TEXT,
    ts     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_history_domain ON history(domain);
CREATE TABLE IF NOT EXISTS expired_domains(
    domain TEXT PRIMARY KEY,
    last_seen TEXT,
    source TEXT
);
EOF
    echo -e "${GREEN}Database initialized successfully${NC}"
else
    echo -e "${YELLOW}Warning: sqlite3 not found, database functionality will be limited${NC}"
fi

# Set initial status
echo "READY" > "$BASE_DIR/status.txt"

# Run initial update and blocking in background
echo -e ""
echo -e "${CYAN}${BOLD}INITIAL SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}Starting initial domain update and blocking (runs in background)...${NC}"

# Run the daemon in background
nohup "$DAEMON_PATH" > /dev/null 2>&1 &
bg_pid=$!
echo -e "${GREEN}Initial setup started in background (PID: $bg_pid)${NC}"

# Final instructions
echo -e ""
echo -e "${CYAN}${BOLD}INSTALLATION COMPLETE!${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}DNSniper is now installed and running in the background.${NC}"
echo -e ""
echo -e "${YELLOW}Commands:${NC}"
echo -e "  ${GREEN}sudo dnsniper${NC}           - Open the interactive menu"
echo -e "  ${GREEN}sudo dnsniper --status${NC}  - Check current status"
echo -e "  ${GREEN}sudo dnsniper --help${NC}    - Show all available commands"
echo -e ""
echo -e "${YELLOW}The service will automatically update and run in the background.${NC}"
echo -e "${YELLOW}You don't need to manually run it unless you want to make changes.${NC}"
echo -e ""
echo -e "${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}"
echo -e ""
echo -e "${YELLOW}Installation log saved to: $LOG_FILE${NC}"