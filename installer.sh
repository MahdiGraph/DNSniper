#!/usr/bin/env bash
# DNSniper Installer
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.2
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash
set -e
# ANSI color codes
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
MAGENTA='\e[35m'
WHITE='\e[97m'
BOLD='\e[1m'
NC='\e[0m'
# Paths
BASE_DIR="/etc/dnsniper"
BIN_PATH="/usr/local/bin/dnsniper"
CORE_SCRIPT="$BASE_DIR/dnsniper-core.sh"
DAEMON_SCRIPT="$BASE_DIR/dnsniper-daemon.sh"
MAIN_SCRIPT="$BASE_DIR/dnsniper.sh"
CONFIG_FILE="$BASE_DIR/config.conf"
# Function to get latest commit with fallback support
get_latest_commit() {
    if ! command -v git &>/dev/null; then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Git is not installed. Using main branch instead."
        echo "main"
        return 1
    fi
    local commit
    commit=$(git ls-remote https://github.com/MahdiGraph/DNSniper.git HEAD | cut -f1)
    if [[ -z "$commit" ]]; then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Failed to retrieve latest commit hash. Using main branch."
        echo "main"
        return 1
    fi
    echo "$commit"
}
# Get latest commit
latest_commit=$(get_latest_commit)
github_url="https://raw.githubusercontent.com/MahdiGraph/DNSniper/${latest_commit}"
# Display banner
echo -e "${BLUE}${BOLD}"
echo -e "    ____  _   _ ____       _                 "
echo -e "   |   _\\| \\ | /_ __|_ __ (_)_ __   ___ _ __ "
echo -e "   | | | |  \\| \\___ \\ '_ \\| | '_ \\ / _\\ '__|"
echo -e "   | |_| | |\\  |___) | | | | | |_) |  __/ |  "
echo -e "   |____/|_| \\_|____/|_| |_|_| .__/ \\___|_|  "
echo -e "                             |_|              "
echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v2.1.2 ${NC}"
echo -e ""
# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error:${NC} This installer must be run as root (sudo)." >&2
    exit 1
fi
echo -e "${CYAN}${BOLD}SYSTEM DETECTION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
# Detect package manager and set command variables
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    PKG_UPDATE="apt update"
    PKG_INSTALL="apt install -y"
    DEPS="iptables iptables-persistent curl dnsutils git"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables iptables-services curl bind-utils git"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables iptables-services curl bind-utils git"
else
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- git"
    read -rp "Continue anyway? [y/N]: " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        exit 1
    fi
    PKG_MANAGER="manual"
fi
echo -e "${GREEN}Detected system: ${PKG_MANAGER}${NC}"
# Check for existing installation
installation_type="install"
if [[ -d "$BASE_DIR" || -f "$BIN_PATH" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}EXISTING INSTALLATION${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}DNSniper appears to be already installed.${NC}"
    echo -e "${YELLOW}What would you like to do?${NC}"
    echo -e "1. ${BOLD}Clean install${NC} - Remove existing installation and start fresh"
    echo -e "2. ${BOLD}Upgrade${NC} - Keep settings and data, upgrade to new version"
    echo -e "3. ${BOLD}Cancel${NC} - Exit without making changes"
    read -rp "Choice (1-3): " choice
    case "$choice" in
        1)
            echo -e "${YELLOW}Proceeding with clean installation...${NC}"
            installation_type="clean"
            ;;
        2)
            echo -e "${GREEN}Proceeding with upgrade...${NC}"
            installation_type="upgrade"
            ;;
        *)
            echo -e "${RED}Installation cancelled.${NC}"
            exit 0
            ;;
    esac
fi
# Install dependencies
if [[ "$PKG_MANAGER" != "manual" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}DEPENDENCIES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}Updating package lists...${NC}"
    $PKG_UPDATE
    echo -e "${YELLOW}Installing required packages:${NC} ${DEPS}"
    if ! $PKG_INSTALL $DEPS; then
        echo -e "${RED}${BOLD}Error:${NC} Failed to install dependencies."
        echo -e "Please install these packages manually and try again:"
        echo -e "${DEPS}"
        exit 1
    fi
    echo -e "${GREEN}Dependencies successfully installed.${NC}"
else
    echo -e ""
    echo -e "${CYAN}${BOLD}DEPENDENCIES CHECK${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    missing=()
    for cmd in iptables ip6tables curl dig git; do
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
# Clean up existing installation if needed
if [[ "$installation_type" == "clean" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}REMOVING EXISTING INSTALLATION${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    # Stop and disable systemd services
    if systemctl list-unit-files dnsniper.service &>/dev/null; then
        echo -e "${YELLOW}Stopping and disabling services...${NC}"
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
    # Check for and remove cron jobs
    if command -v crontab &>/dev/null; then
        echo -e "${YELLOW}Checking for old cron jobs...${NC}"
        if crontab -l 2>/dev/null | grep -q "dnsniper"; then
            (crontab -l 2>/dev/null | grep -v "dnsniper") | crontab - 2>/dev/null || true
            echo -e "${GREEN}Removed old cron jobs.${NC}"
        fi
    fi
    # Remove binary and directories
    echo -e "${YELLOW}Removing files...${NC}"
    rm -f "$BIN_PATH" 2>/dev/null || true
    rm -rf "$BASE_DIR" 2>/dev/null || true
    echo -e "${GREEN}Existing installation removed.${NC}"
fi
# Create directories
echo -e ""
echo -e "${CYAN}${BOLD}DIRECTORY SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
mkdir -p "$BASE_DIR"
mkdir -p "$BASE_DIR/history"
mkdir -p "$BASE_DIR/data"
mkdir -p "$BASE_DIR/status"
echo -e "${GREEN}Directories created: $BASE_DIR, $BASE_DIR/history, $BASE_DIR/data, $BASE_DIR/status${NC}"
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
# Function to download a script
download_script() {
    local script_name="$1"
    local output_file="$2"
    echo -e "${YELLOW}Downloading ${script_name}...${NC}"
    if curl -sfL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 "${github_url}/${script_name}" -o "${output_file}.tmp"; then
        if [[ ! -s "${output_file}.tmp" ]]; then
            echo -e "${RED}${BOLD}Error:${NC} Downloaded ${script_name} is empty."
            rm -f "${output_file}.tmp"
            return 1
        fi
        chmod +x "${output_file}.tmp"
        mv "${output_file}.tmp" "${output_file}"
        echo -e "${GREEN}${script_name} successfully downloaded.${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}Error:${NC} Failed to download ${script_name}."
        rm -f "${output_file}.tmp" 2>/dev/null || true
        return 1
    fi
}
# Download the scripts
if ! download_script "dnsniper-core.sh" "$CORE_SCRIPT"; then
    echo -e "${RED}${BOLD}Failed to download core script. Installation aborted.${NC}"
    exit 1
fi
if ! download_script "dnsniper-daemon.sh" "$DAEMON_SCRIPT"; then
    echo -e "${RED}${BOLD}Failed to download daemon script. Installation aborted.${NC}"
    exit 1
fi
if ! download_script "dnsniper.sh" "$MAIN_SCRIPT"; then
    echo -e "${RED}${BOLD}Failed to download main script. Installation aborted.${NC}"
    exit 1
fi
# Create symlink
ln -sf "$MAIN_SCRIPT" "$BIN_PATH"
chmod +x "$BIN_PATH"
echo -e "${GREEN}Created symlink: $BIN_PATH${NC}"
# Clean up any old cron jobs (migration)
echo -e ""
echo -e "${CYAN}${BOLD}CRON JOB CLEANUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
if command -v crontab &>/dev/null; then
    if crontab -l 2>/dev/null | grep -q "dnsniper"; then
        (crontab -l 2>/dev/null | grep -v "dnsniper") | crontab - 2>/dev/null || true
        echo -e "${GREEN}Removed old cron jobs from previous versions.${NC}"
    else
        echo -e "${GREEN}No old cron jobs found.${NC}"
    fi
fi
# Ask about scheduling
echo -e ""
echo -e "${CYAN}${BOLD}SCHEDULING${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}Do you want DNSniper to run automatically on a schedule?${NC}"
echo -e "1. ${BOLD}Yes${NC} - Run every hour (recommended)"
echo -e "2. ${BOLD}Yes${NC} - Run every 30 minutes (more frequent)"
echo -e "3. ${BOLD}No${NC} - I'll manually run it when needed"
read -rp "Choice (1-3): " schedule_choice
scheduler_enabled=1
schedule_minutes=60
case "$schedule_choice" in
    1)
        scheduler_enabled=1
        schedule_minutes=60
        echo -e "${GREEN}Scheduled to run hourly.${NC}"
        ;;
    2)
        scheduler_enabled=1
        schedule_minutes=30
        echo -e "${GREEN}Scheduled to run every 30 minutes.${NC}"
        ;;
    3)
        scheduler_enabled=0
        echo -e "${YELLOW}Automatic scheduling disabled.${NC}"
        ;;
    *)
        echo -e "${YELLOW}Invalid choice. Using default: hourly schedule.${NC}"
        ;;
esac
# Create or update config file
if [[ "$installation_type" == "upgrade" && -f "$CONFIG_FILE" ]]; then
    # Keep existing config, just update the scheduler settings
    if grep -q "^scheduler_enabled=" "$CONFIG_FILE"; then
        # Config file already has new format
        sed -i "s/^scheduler_enabled=.*/scheduler_enabled=$scheduler_enabled/" "$CONFIG_FILE"
        sed -i "s/^schedule_minutes=.*/schedule_minutes=$schedule_minutes/" "$CONFIG_FILE"
    else
        # Convert old cron setting to new scheduler format
        echo "scheduler_enabled=$scheduler_enabled" >> "$CONFIG_FILE"
        echo "schedule_minutes=$schedule_minutes" >> "$CONFIG_FILE"
    fi
    echo -e "${GREEN}Updated configuration with scheduler settings.${NC}"
else
    # Create default configuration file for clean install
    source "$CORE_SCRIPT" 2>/dev/null || true
    # If source fails, set defaults directly
    [[ -z "$DEFAULT_MAX_IPS" ]] && DEFAULT_MAX_IPS=10
    [[ -z "$DEFAULT_TIMEOUT" ]] && DEFAULT_TIMEOUT=30
    [[ -z "$DEFAULT_URL" ]] && DEFAULT_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/${latest_commit}/domains-default.txt"
    [[ -z "$DEFAULT_AUTO_UPDATE" ]] && DEFAULT_AUTO_UPDATE=1
    [[ -z "$DEFAULT_EXPIRE_ENABLED" ]] && DEFAULT_EXPIRE_ENABLED=1
    [[ -z "$DEFAULT_EXPIRE_MULTIPLIER" ]] && DEFAULT_EXPIRE_MULTIPLIER=5
    [[ -z "$DEFAULT_BLOCK_SOURCE" ]] && DEFAULT_BLOCK_SOURCE=1
    [[ -z "$DEFAULT_BLOCK_DESTINATION" ]] && DEFAULT_BLOCK_DESTINATION=1
    [[ -z "$DEFAULT_LOGGING_ENABLED" ]] && DEFAULT_LOGGING_ENABLED=0
    [[ -z "$DEFAULT_STATUS_ENABLED" ]] && DEFAULT_STATUS_ENABLED=1
    cat > "$CONFIG_FILE" << EOF
# DNSniper Configuration
scheduler_enabled=$scheduler_enabled
schedule_minutes=$schedule_minutes
max_ips=$DEFAULT_MAX_IPS
timeout=$DEFAULT_TIMEOUT
update_url='$DEFAULT_URL'
auto_update=$DEFAULT_AUTO_UPDATE
expire_enabled=$DEFAULT_EXPIRE_ENABLED
expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER
block_source=$DEFAULT_BLOCK_SOURCE
block_destination=$DEFAULT_BLOCK_DESTINATION
logging_enabled=$DEFAULT_LOGGING_ENABLED
status_enabled=$DEFAULT_STATUS_ENABLED
EOF
    echo -e "${GREEN}Created default configuration file.${NC}"
fi
# Create empty files if not upgrading
if [[ "$installation_type" != "upgrade" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}CREATING FILES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    touch "$BASE_DIR/domains-default.txt" "$BASE_DIR/domains-add.txt" "$BASE_DIR/domains-remove.txt" \
          "$BASE_DIR/ips-add.txt" "$BASE_DIR/ips-remove.txt" 2>/dev/null
    # Create required data files
    touch "$BASE_DIR/data/cdn_domains.txt" "$BASE_DIR/data/expired_domains.txt" 2>/dev/null
    # Add explanatory comment to default domains file
    cat > "$BASE_DIR/domains-default.txt" << EOF
# DNSniper Default Domains
# One domain per line
# Lines starting with # are comments and will be ignored
# Empty lines will also be ignored
# Example:
# malicious-domain.com
EOF
    echo -e "${GREEN}Created required files.${NC}"
fi
# Initialize DNSniper
echo -e ""
echo -e "${CYAN}${BOLD}INITIALIZATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
# Source daemon script to create systemd services
bash -c "source '$DAEMON_SCRIPT' && create_systemd_service" || true
# IMPROVED SECTION: Enable and start services - without hanging
if [[ "$scheduler_enabled" -eq 1 ]]; then
    echo -e "${GREEN}Enabling and starting DNSniper services...${NC}"
    # Enable services first (this is quick and shouldn't hang)
    systemctl enable dnsniper-firewall.service &>/dev/null || true
    systemctl enable dnsniper.service &>/dev/null || true
    systemctl enable dnsniper.timer &>/dev/null || true
    # Start services in background with nohup to ensure they don't hang
    echo -e "${YELLOW}Starting services in background...${NC}"
    nohup systemctl start dnsniper-firewall.service >/dev/null 2>&1 &
    nohup systemctl start dnsniper.timer >/dev/null 2>&1 &
    # Brief pause to allow services to begin startup
    sleep 1
    echo -e "${GREEN}Services enabled and started in background.${NC}"
    echo -e "${BLUE}Tip: Check service status with: sudo dnsniper --status${NC}"
fi
# IMPROVED SECTION: Make sure initialization check doesn't hang
# Check version instead of doing a full run to avoid hanging
"$BIN_PATH" --version >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}DNSniper successfully initialized.${NC}"
    if [[ "$installation_type" != "upgrade" ]]; then
        echo -e "${YELLOW}Running initial domains update in background...${NC}"
        # Run update in background to avoid hanging the installer
        nohup "$BIN_PATH" --update >/dev/null 2>&1 &
    fi
else
    echo -e "${RED}${BOLD}Warning:${NC} There might be issues with initialization."
    echo -e "${YELLOW}Please check by running: sudo dnsniper --status${NC}"
fi
# Final instructions
echo -e ""
echo -e "${CYAN}${BOLD}INSTALLATION COMPLETE!${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}To start using DNSniper:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper"
echo -e ""
echo -e "${YELLOW}To view help:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --help"
echo -e ""
echo -e "${YELLOW}To run DNSniper once:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --run"
echo -e ""
echo -e "${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}"
echo -e ""