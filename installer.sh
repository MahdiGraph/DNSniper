#!/usr/bin/env bash
# DNSniper Complete Installer 
# Version: 2.0.0

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
LOG_FILE="/tmp/dnsniper-install.log"
GITHUB_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main"
DOMAINS_DEFAULT="$BASE_DIR/domains-default.txt"

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

# Setup log file
exec > >(tee -i "$LOG_FILE") 2>&1

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error:${NC} This installer must be run as root (sudo)." >&2
    exit 1
fi

# Function to handle errors
handle_error() {
    echo -e "${RED}${BOLD}Error:${NC} $1" >&2
    echo "Check log file for details: $LOG_FILE"
    echo -e "${YELLOW}Installation failed.${NC}"
    exit 1
}

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
            BACKUP_DIR="/tmp/dnsniper-backup-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$BACKUP_DIR" || handle_error "Failed to create backup directory"
            
            # Stop any running processes and services
            echo -e "${BLUE}Stopping DNSniper services...${NC}"
            
            # Stop systemd services if they exist
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.timer 2>/dev/null || true
                systemctl stop dnsniper.service 2>/dev/null || true
            fi
            
            # Kill any running processes
            pkill -f "dnsniper" 2>/dev/null || true
            
            # Remove cron jobs (from old installations)
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Backup configuration
            if [[ -d "$BASE_DIR" ]]; then
                echo -e "${YELLOW}Backing up configuration files...${NC}"
                cp -r "$BASE_DIR"/* "$BACKUP_DIR/" 2>/dev/null || echo "Warning: Some files could not be backed up"
                echo -e "${GREEN}Configuration backed up to: $BACKUP_DIR${NC}"
            fi
            
            # Remove binaries but keep configuration directory
            rm -f "$BIN_PATH" "$DAEMON_PATH" 2>/dev/null || echo "Warning: Could not remove binaries"
            ;;
        2)
            echo -e "${YELLOW}Performing clean install...${NC}"
            
            # Stop systemd services
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.timer 2>/dev/null || true
                systemctl stop dnsniper.service 2>/dev/null || true
                systemctl disable dnsniper.timer 2>/dev/null || true
                systemctl disable dnsniper.service 2>/dev/null || true
                rm -f /etc/systemd/system/dnsniper.service 2>/dev/null || true
                rm -f /etc/systemd/system/dnsniper.timer 2>/dev/null || true
                systemctl daemon-reload 2>/dev/null || true
            fi
            
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
            rm -f "$BIN_PATH" "$DAEMON_PATH" 2>/dev/null || echo "Warning: Could not remove binaries"
            rm -rf "$BASE_DIR" 2>/dev/null || echo "Warning: Could not remove $BASE_DIR"
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
    PKG_MANAGER="unknown"
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- sqlite3\n- procps"
    read -rp "Continue anyway? [y/N]: " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}Detected system: ${PKG_MANAGER}${NC}"

# Check system compatibility
if ! command -v iptables &>/dev/null; then
    handle_error "iptables not found. DNSniper requires iptables."
fi

# Install dependencies
if [[ "$PKG_MANAGER" != "unknown" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}INSTALLING DEPENDENCIES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}Updating package lists...${NC}"
    
    # Update package lists
    if ! $PKG_UPDATE; then
        echo -e "${YELLOW}Warning: Package update failed, continuing anyway...${NC}"
    fi
    
    echo -e "${YELLOW}Installing required packages:${NC} ${DEPS}"
    
    # Install packages
    if ! $PKG_INSTALL $DEPS; then
        echo -e "${YELLOW}Warning: Some packages failed to install. Continuing anyway...${NC}"
    else
        echo -e "${GREEN}Dependencies successfully installed.${NC}"
    fi
fi

# Create directories
echo -e ""
echo -e "${CYAN}${BOLD}CREATING DIRECTORIES${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

mkdir -p "$BASE_DIR/logs" || handle_error "Failed to create directories"
echo -e "${GREEN}Directory created: $BASE_DIR${NC}"

# Download all scripts
echo -e ""
echo -e "${CYAN}${BOLD}DOWNLOADING COMPONENTS${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Function to download a file with error handling
download_file() {
    local src="$1"
    local dest="$2"
    local description="$3"
    
    echo -e "${YELLOW}Downloading $description...${NC}"
    if ! curl -sSL "$src" -o "$dest"; then
        handle_error "Failed to download $description."
    fi
    
    # Make executable if it's a script
    if [[ "$dest" == *.sh ]]; then
        chmod +x "$dest" || handle_error "Failed to make $description executable"
    fi
    
    echo -e "${GREEN}$description downloaded successfully.${NC}"
}

# Download all components
download_file "$GITHUB_URL/dnsniper.sh" "$BIN_PATH" "DNSniper main script"
download_file "$GITHUB_URL/dnsniper-daemon.sh" "$DAEMON_PATH" "DNSniper daemon script"
download_file "$GITHUB_URL/dnsniper-core.sh" "$CORE_PATH" "DNSniper core library"
download_file "$GITHUB_URL/domains-default.txt" "$DOMAINS_DEFAULT" "Default domains list"

# Create config file if it doesn't exist
echo -e ""
echo -e "${CYAN}${BOLD}CREATING CONFIGURATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

if [[ ! -f "$BASE_DIR/config.conf" ]]; then
    cat > "$BASE_DIR/config.conf" << EOF
# DNSniper Configuration
max_ips=10
timeout=30
update_url='$GITHUB_URL/domains-default.txt'
auto_update=1
expire_enabled=1
expire_multiplier=5
block_source=1
block_destination=1
logging_enabled=1
log_max_size=10
log_rotate_count=5
EOF
    echo -e "${GREEN}Created configuration file.${NC}"
fi

# Create empty domain files if they don't exist
for file in "domains-add.txt" "domains-remove.txt" "ips-add.txt" "ips-remove.txt"; do
    if [[ ! -f "$BASE_DIR/$file" ]]; then
        touch "$BASE_DIR/$file" || handle_error "Failed to create $file"
    fi
done
echo -e "${GREEN}Created list files.${NC}"

# Set up scheduling
echo -e ""
echo -e "${CYAN}${BOLD}SETTING UP SCHEDULING${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Ask user about schedule preference
echo -e "${YELLOW}Do you want DNSniper to run automatically?${NC}"
echo -e "1) Yes - Run hourly (recommended)"
echo -e "2) No - I'll run it manually"
read -rp "Choose an option [1-2]: " sched_choice

if [[ "$sched_choice" == "2" ]]; then
    echo -e "${YELLOW}Automatic scheduling disabled.${NC}"
else
    # Default: Enable automatic scheduling
    echo -e "${YELLOW}Setting up automatic scheduling...${NC}"
    
    if command -v systemctl &>/dev/null; then
        # Set up systemd service
        cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation
After=network.target

[Service]
Type=oneshot
ExecStart=$DAEMON_PATH
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

        # Set up systemd timer
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
        # Fallback to cron
        echo -e "${YELLOW}Systemd not available, using cron instead...${NC}"
        (crontab -l 2>/dev/null | grep -v "$BIN_PATH"; echo "0 * * * * $DAEMON_PATH > /dev/null 2>&1") | crontab -
        echo -e "${GREEN}DNSniper scheduled with cron (runs hourly)${NC}"
    fi
fi

# Initialize the database
echo -e ""
echo -e "${CYAN}${BOLD}INITIALIZING DATABASE${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

if command -v sqlite3 &>/dev/null; then
    sqlite3 "$BASE_DIR/history.db" <<EOF || handle_error "Failed to initialize database"
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

# Create status file
echo "READY" > "$BASE_DIR/status.txt"

# Ask about running initial update
echo -e ""
echo -e "${CYAN}${BOLD}INITIAL SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}Do you want to run an initial update and domain blocking now?${NC}"
echo -e "1) Yes - Run in background"
echo -e "2) No - I'll do it later"
read -rp "Choose an option [1-2]: " run_choice

if [[ "$run_choice" == "1" ]]; then
    echo -e "${YELLOW}Starting initial domain update and blocking...${NC}"
    
    # Run daemon in background
    nohup "$DAEMON_PATH" > /dev/null 2>&1 &
    bg_pid=$!
    echo -e "${GREEN}Initial setup started in background (PID: $bg_pid)${NC}"
    echo -e "${YELLOW}You can check status with:${NC} sudo dnsniper --status"
else
    echo -e "${YELLOW}Skipping initial setup. You can run it later with:${NC}"
    echo -e "  ${GREEN}sudo $DAEMON_PATH${NC}"
    echo -e "  or"
    echo -e "  ${GREEN}sudo dnsniper --run${NC}"
fi

# Final instructions
echo -e ""
echo -e "${CYAN}${BOLD}INSTALLATION COMPLETE!${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${GREEN}DNSniper has been successfully installed!${NC}"
echo -e ""
echo -e "${YELLOW}Commands:${NC}"
echo -e "  ${GREEN}sudo dnsniper${NC}           - Open interactive menu"
echo -e "  ${GREEN}sudo dnsniper --status${NC}  - Check current status"
echo -e "  ${GREEN}sudo dnsniper --help${NC}    - Show all available commands"
echo -e "  ${GREEN}sudo dnsniper --run${NC}     - Run manually"
echo -e ""
echo -e "${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}"
echo -e ""
echo -e "${YELLOW}Installation log saved to: $LOG_FILE${NC}"