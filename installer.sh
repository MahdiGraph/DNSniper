#!/usr/bin/env bash
# DNSniper Installer
# Version: 2.0.0

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
BIN_DIR="/usr/local/bin"
BIN_PATH="$BIN_DIR/dnsniper"
DAEMON_PATH="$BIN_DIR/dnsniper-daemon"
CORE_PATH="$BASE_DIR/dnsniper-core.sh"
SYSTEMD_SERVICE="/etc/systemd/system/dnsniper.service"
SYSTEMD_TIMER="/etc/systemd/system/dnsniper.timer"
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
echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v2.0.0 ${NC}"
echo -e ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error:${NC} This installer must be run as root (sudo)." >&2
    exit 1
fi

# Check for systemd
if ! command -v systemctl &>/dev/null; then
    echo -e "${RED}${BOLD}Error:${NC} This version of DNSniper requires systemd."
    echo -e "       Your system does not have systemd installed."
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
    while [[ ! "$choice" =~ ^[1-3]$ ]]; do
        echo -e "${RED}Invalid selection. Please enter 1, 2, or 3${NC}"
        read -rp "Choose an option [1-3]: " choice
    done
    
    case "$choice" in
        1)
            echo -e "${YELLOW}Upgrading DNSniper...${NC}"
            
            # Create backup directory
            BACKUP_DIR="/tmp/dnsniper-backup-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$BACKUP_DIR"
            
            # Stop any running processes and services
            echo -e "${BLUE}Stopping DNSniper services...${NC}"
            
            # Stop systemd services if they exist
            systemctl stop dnsniper.timer 2>/dev/null || true
            systemctl stop dnsniper.service 2>/dev/null || true
            
            # Kill any running processes
            pkill -f "dnsniper" 2>/dev/null || true
            
            # Remove cron jobs (from old installations)
            echo -e "${BLUE}Removing old cron jobs...${NC}"
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Backup configuration
            if [[ -d "$BASE_DIR" ]]; then
                echo -e "${YELLOW}Backing up configuration files...${NC}"
                cp -r "$BASE_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
                echo -e "${GREEN}Configuration backed up to: $BACKUP_DIR${NC}"
            fi
            
            # Remove binaries but keep configuration
            rm -f "$BIN_PATH" "$DAEMON_PATH" 2>/dev/null || true
            ;;
        2)
            echo -e "${YELLOW}Performing clean install...${NC}"
            
            # Stop systemd services
            systemctl stop dnsniper.timer 2>/dev/null || true
            systemctl stop dnsniper.service 2>/dev/null || true
            
            # Kill any running DNSniper processes
            pkill -f "dnsniper" 2>/dev/null || true
            
            # Remove cron jobs (from old installations)
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Clean up firewall rules if DNSniper binary exists
            if [[ -f "$BIN_PATH" ]]; then
                echo -e "${YELLOW}Cleaning firewall rules...${NC}"
                "$BIN_PATH" --clean-rules 2>/dev/null || true
            fi
            
            # Remove files completely
            rm -f "$BIN_PATH" "$DAEMON_PATH" 2>/dev/null || true
            rm -rf "$BASE_DIR" 2>/dev/null || true
            rm -f "$SYSTEMD_SERVICE" "$SYSTEMD_TIMER" 2>/dev/null || true
            
            # Reload systemd
            systemctl daemon-reload 2>/dev/null || true
            
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
    DEPS="iptables iptables-persistent curl dnsutils sqlite3 procps"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite procps-ng"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite procps-ng"
else
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- sqlite3\n- procps"
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
    for cmd in iptables ip6tables curl dig sqlite3 ps; do
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
    systemctl enable iptables ip6tables &>/dev/null || true
elif [[ -f /etc/fedora-release ]]; then
    OS_TYPE="fedora"
    echo -e "${GREEN}Fedora detected, using iptables-services${NC}"
    
    # Make sure iptables-services is enabled
    systemctl enable iptables ip6tables &>/dev/null || true
else
    OS_TYPE="unknown"
    echo -e "${YELLOW}Unknown OS, will create systemd service for persistence${NC}"
fi

# Download scripts
echo -e ""
echo -e "${CYAN}${BOLD}DOWNLOADING COMPONENTS${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Function to download file with retry
download_file() {
    local url="$1"
    local destination="$2"
    local max_retries=3
    local retry_count=0
    local success=false
    
    while [[ $retry_count -lt $max_retries && $success == false ]]; do
        echo -e "${YELLOW}Downloading $(basename "$destination") (attempt $((retry_count+1))/$max_retries)...${NC}"
        
        if curl -sfL --connect-timeout 30 --max-time 60 "$url" -o "$destination"; then
            success=true
        else
            retry_count=$((retry_count+1))
            
            if [[ $retry_count -lt $max_retries ]]; then
                echo -e "${YELLOW}Download failed, retrying in 3 seconds...${NC}"
                sleep 3
            else
                echo -e "${RED}${BOLD}Error:${NC} Failed to download $(basename "$destination") after $max_retries attempts."
                return 1
            fi
        fi
    done
    
    # Verify file is not empty
    if [[ ! -s "$destination" ]]; then
        echo -e "${RED}${BOLD}Error:${NC} Downloaded $(basename "$destination") is empty."
        return 1
    fi
    
    return 0
}

# Download main components
TMP_DIR=$(mktemp -d)
download_file "$GITHUB_URL/dnsniper.sh" "$TMP_DIR/dnsniper.sh" || exit 1
download_file "$GITHUB_URL/dnsniper-daemon.sh" "$TMP_DIR/dnsniper-daemon.sh" || exit 1
download_file "$GITHUB_URL/dnsniper-core.sh" "$TMP_DIR/dnsniper-core.sh" || exit 1

# Download default domain list
download_file "$GITHUB_URL/domains-default.txt" "$TMP_DIR/domains-default.txt" || {
    echo -e "${YELLOW}Warning: Could not download default domain list, creating empty file.${NC}"
    echo "# Default domains to block" > "$TMP_DIR/domains-default.txt"
    echo "# One domain per line" >> "$TMP_DIR/domains-default.txt"
}

# Make scripts executable
chmod +x "$TMP_DIR/dnsniper.sh" "$TMP_DIR/dnsniper-daemon.sh" "$TMP_DIR/dnsniper-core.sh"

# Check for backup to restore
if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" && $(ls -A "$BACKUP_DIR" 2>/dev/null) ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}CONFIGURATION RESTORATION${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    echo -e "${YELLOW}Found backup from previous installation.${NC}"
    read -rp "Restore configuration from backup? [Y/n]: " restore_backup
    
    if [[ ! "$restore_backup" =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}Restoring configuration from backup...${NC}"
        
        # Restore configuration files but not scripts
        if [[ -f "$BACKUP_DIR/config.conf" ]]; then
            cp "$BACKUP_DIR/config.conf" "$BASE_DIR/" 2>/dev/null || true
        fi
        
        # Restore domain lists
        for list in domains-default.txt domains-add.txt domains-remove.txt ips-add.txt ips-remove.txt; do
            if [[ -f "$BACKUP_DIR/$list" ]]; then
                cp "$BACKUP_DIR/$list" "$BASE_DIR/" 2>/dev/null || true
            fi
        done
        
        # Restore database
        if [[ -f "$BACKUP_DIR/history.db" ]]; then
            cp "$BACKUP_DIR/history.db" "$BASE_DIR/" 2>/dev/null || true
        fi
        
        echo -e "${GREEN}Configuration restored.${NC}"
    else
        echo -e "${YELLOW}Skipping backup restoration.${NC}"
    fi
fi

# Install files
echo -e ""
echo -e "${CYAN}${BOLD}INSTALLING FILES${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Copy files to their destinations
cp "$TMP_DIR/dnsniper.sh" "$BIN_PATH"
cp "$TMP_DIR/dnsniper-daemon.sh" "$DAEMON_PATH"
cp "$TMP_DIR/dnsniper-core.sh" "$CORE_PATH"

# Copy domain list only if it doesn't exist or if doing a clean install
if [[ ! -f "$BASE_DIR/domains-default.txt" ]]; then
    cp "$TMP_DIR/domains-default.txt" "$BASE_DIR/"
fi

# Create empty files if they don't exist
touch "$BASE_DIR/domains-add.txt" "$BASE_DIR/domains-remove.txt" 
touch "$BASE_DIR/ips-add.txt" "$BASE_DIR/ips-remove.txt"

# Set permissions
chmod +x "$BIN_PATH" "$DAEMON_PATH" "$CORE_PATH"

# Clean up temp files
rm -rf "$TMP_DIR"

echo -e "${GREEN}DNSniper files installed successfully.${NC}"

# Set up systemd service
echo -e ""
echo -e "${CYAN}${BOLD}SETTING UP SYSTEMD SERVICE${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Ask user about schedule preference
echo -e "${YELLOW}Do you want DNSniper to run automatically?${NC}"
echo -e "1) Yes - Run hourly (recommended)"
echo -e "2) No - I'll run it manually"
read -rp "Choose an option [1-2]: " sched_choice

# Wait for valid input
while [[ ! "$sched_choice" =~ ^[1-2]$ ]]; do
    echo -e "${RED}Invalid selection. Please enter 1 or 2${NC}"
    read -rp "Choose an option [1-2]: " sched_choice
done

# Create service file
cat > "$SYSTEMD_SERVICE" << EOF
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

# Create timer file
cat > "$SYSTEMD_TIMER" << EOF
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

# Reload systemd configuration
systemctl daemon-reload

if [[ "$sched_choice" == "2" ]]; then
    echo -e "${YELLOW}Automatic scheduling disabled.${NC}"
    # Make sure timer is disabled
    systemctl disable dnsniper.timer &>/dev/null || true
    systemctl stop dnsniper.timer &>/dev/null || true
    
    # Update config to reflect disabled status
    if [[ -f "$BASE_DIR/config.conf" ]]; then
        sed -i '/^automatic_execution=/d' "$BASE_DIR/config.conf" 2>/dev/null || true
    else
        touch "$BASE_DIR/config.conf"
    fi
    echo "automatic_execution=0" >> "$BASE_DIR/config.conf"
else
    # Enable automatic execution
    systemctl enable dnsniper.timer
    systemctl start dnsniper.timer
    echo -e "${GREEN}DNSniper scheduled with systemd timer (runs hourly)${NC}"
    
    # Update config to reflect enabled status
    if [[ -f "$BASE_DIR/config.conf" ]]; then
        sed -i '/^automatic_execution=/d' "$BASE_DIR/config.conf" 2>/dev/null || true
    else
        touch "$BASE_DIR/config.conf"
    fi
    echo "automatic_execution=1" >> "$BASE_DIR/config.conf"
fi

# Initialize database
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
automatic_execution=$([[ "$sched_choice" == "1" ]] && echo "1" || echo "0")
EOF
fi

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

# Ask about running initial update
echo -e ""
echo -e "${CYAN}${BOLD}INITIAL SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}Do you want to run an initial update and domain blocking now?${NC}"
echo -e "1) Yes - Run in background now"
echo -e "2) No - I'll do it later"
read -rp "Choose an option [1-2]: " run_choice

# Wait for valid input
while [[ ! "$run_choice" =~ ^[1-2]$ ]]; do
    echo -e "${RED}Invalid selection. Please enter 1 or 2${NC}"
    read -rp "Choose an option [1-2]: " run_choice
done

if [[ "$run_choice" == "1" ]]; then
    echo -e "${YELLOW}Starting initial domain update and blocking (runs in background)...${NC}"
    
    # Run the service once manually
    systemctl start dnsniper.service
    
    echo -e "${GREEN}Initial setup triggered. It will run in the background.${NC}"
    echo -e "${YELLOW}You can check status with:${NC} sudo dnsniper --status"
else
    echo -e "${YELLOW}Skipping initial setup. You can run it later with:${NC}"
    echo -e "  ${GREEN}sudo systemctl start dnsniper.service${NC}"
    echo -e "  or"
    echo -e "  ${GREEN}sudo dnsniper --run${NC}"
fi

# Final instructions
echo -e ""
echo -e "${CYAN}${BOLD}INSTALLATION COMPLETE!${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}DNSniper is now installed.${NC}"
echo -e ""
echo -e "${YELLOW}Commands:${NC}"
echo -e "  ${GREEN}sudo dnsniper${NC}           - Open the interactive menu"
echo -e "  ${GREEN}sudo dnsniper --status${NC}  - Check current status"
echo -e "  ${GREEN}sudo dnsniper --help${NC}    - Show all available commands"
echo -e ""

if [[ "$sched_choice" == "1" ]]; then
    echo -e "${YELLOW}The service will automatically update and run in the background.${NC}"
    echo -e "${YELLOW}You don't need to manually run it unless you want to make changes.${NC}"
else
    echo -e "${YELLOW}Automatic scheduling is disabled. Use these commands to run manually:${NC}"
    echo -e "  ${GREEN}sudo systemctl start dnsniper.service${NC}"
    echo -e "  or"
    echo -e "  ${GREEN}sudo dnsniper --run${NC}"
fi

echo -e ""
echo -e "${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}"
echo -e ""
echo -e "${YELLOW}Installation log saved to: $LOG_FILE${NC}"