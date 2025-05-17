#!/usr/bin/env bash
# DNSniper Installer
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.3
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

# Default configuration values (used if creating a new config file)
DEFAULT_SCHEDULER_ENABLED=1
DEFAULT_SCHEDULE_MINUTES=60
DEFAULT_MAX_IPS=10
DEFAULT_TIMEOUT=30
# DEFAULT_URL will be set after latest_commit is determined
DEFAULT_AUTO_UPDATE=1
DEFAULT_EXPIRE_ENABLED=1
DEFAULT_EXPIRE_MULTIPLIER=5
DEFAULT_BLOCK_SOURCE=1
DEFAULT_BLOCK_DESTINATION=1
DEFAULT_LOGGING_ENABLED=0 # Default to off initially
DEFAULT_STATUS_ENABLED=1

# Function to get latest commit with fallback support
get_latest_commit() {
    if ! command -v git &>/dev/null; then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Git is not installed. Using 'main' branch for downloads."
        echo "main"
        return
    fi
    local commit
    commit=$(git ls-remote https://github.com/MahdiGraph/DNSniper.git HEAD 2>/dev/null | cut -f1)
    if [[ -z "$commit" ]]; then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Failed to retrieve latest commit hash. Using 'main' branch for downloads."
        echo "main"
        return
    fi
    echo "$commit"
}

# Get latest commit and set up URLs
latest_commit=$(get_latest_commit)
github_url="https://raw.githubusercontent.com/MahdiGraph/DNSniper/${latest_commit}"
DEFAULT_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/${latest_commit}/domains-default.txt"

# Display banner
echo -e "${BLUE}${BOLD}"
echo -e "    ____  _   _ ____       _                 "
echo -e "   |   _\\| \\ | /_ __|_ __ (_)_ __   ___ _ __ "
echo -e "   | | | |  \\| \\___ \\ '_ \\| | '_ \\ / _\\ '__|"
echo -e "   | |_| | |\\  |___) | | | | | |_) |  __/ |  "
echo -e "   |____/|_| \\_|____/|_| |_|_| .__/ \\___|_|  "
echo -e "                             |_|              "
echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v2.1.3 ${NC}"
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
    DEPS="iptables iptables-persistent curl dnsutils git ipset sort coreutils" # Added sort, coreutils (for comm)
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables iptables-services curl bind-utils git ipset sort coreutils"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables iptables-services curl bind-utils git ipset sort coreutils"
else
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- git\n- ipset\n- sort\n- coreutils (for comm)"
    read -rp "Continue anyway? [y/N]: " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        exit 1
    fi
    PKG_MANAGER="manual"
fi
echo -e "${GREEN}Detected package manager: ${PKG_MANAGER}${NC}"

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
    read -rp "Choice (1-3) [Default: 2 if installed, 1 otherwise]: " choice
    choice=${choice:-2}

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
    if ! $PKG_UPDATE; then
        echo -e "${YELLOW}Warning: Failed to update package lists. Proceeding with dependency installation...${NC}"
    fi
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
    missing_deps=()
    for cmd in iptables ip6tables curl dig git ipset sort comm; do # Added sort, comm
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}Missing dependencies:${NC} ${missing_deps[*]}"
        echo -e "${YELLOW}Please install these dependencies and run the installer again.${NC}"
        exit 1
    fi
    echo -e "${GREEN}All essential dependencies appear to be present.${NC}"
fi

# Clean up existing installation if needed
if [[ "$installation_type" == "clean" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}REMOVING EXISTING INSTALLATION${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    if [[ -f "$BASE_DIR/dnsniper.lock" ]]; then
        echo -e "${YELLOW}Stopping any running DNSniper processes...${NC}"
        pid=$(cat "$BASE_DIR/dnsniper.lock" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -15 "$pid" 2>/dev/null || true; sleep 1
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$BASE_DIR/dnsniper.lock" 2>/dev/null || true
    fi

    if command -v ipset &>/dev/null; then
        echo -e "${YELLOW}Removing ipsets...${NC}"
        ipset destroy dnsniper-ipv4 2>/dev/null || true
        ipset destroy dnsniper-ipv6 2>/dev/null || true
    fi

    systemd_services_removed=0
    if systemctl list-unit-files --type=service | grep -q "dnsniper.service"; then
        echo -e "${YELLOW}Stopping and disabling DNSniper services...${NC}"
        systemctl stop dnsniper.timer &>/dev/null || true
        systemctl disable dnsniper.timer &>/dev/null || true
        systemctl stop dnsniper.service &>/dev/null || true
        systemctl disable dnsniper.service &>/dev/null || true
        rm -f /etc/systemd/system/dnsniper.service /lib/systemd/system/dnsniper.service &>/dev/null || true
        rm -f /etc/systemd/system/dnsniper.timer /lib/systemd/system/dnsniper.timer &>/dev/null || true
        systemd_services_removed=1
    fi
    if systemctl list-unit-files --type=service | grep -q "dnsniper-firewall.service"; then
        systemctl stop dnsniper-firewall.service &>/dev/null || true
        systemctl disable dnsniper-firewall.service &>/dev/null || true
        rm -f /etc/systemd/system/dnsniper-firewall.service /lib/systemd/system/dnsniper-firewall.service &>/dev/null || true
        systemd_services_removed=1
    fi

    if [[ $systemd_services_removed -eq 1 ]] && command -v systemctl &>/dev/null; then
        systemctl daemon-reload &>/dev/null || true
    fi

    if command -v crontab &>/dev/null; then
        echo -e "${YELLOW}Checking for old cron jobs...${NC}"
        if crontab -l 2>/dev/null | grep -q "dnsniper"; then
            (crontab -l 2>/dev/null | grep -v "dnsniper") | crontab - 2>/dev/null || true
            echo -e "${GREEN}Removed old cron jobs.${NC}"
        fi
    fi

    echo -e "${YELLOW}Removing files...${NC}"
    rm -f "$BIN_PATH" 2>/dev/null || true
    rm -rf "$BASE_DIR" 2>/dev/null || true # This removes config, data, history, etc.
    echo -e "${GREEN}Existing installation completely removed.${NC}"
fi

# Create directories
echo -e ""
echo -e "${CYAN}${BOLD}DIRECTORY SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
mkdir -p "$BASE_DIR" "$BASE_DIR/history" "$BASE_DIR/data" "$BASE_DIR/status"
echo -e "${GREEN}Directories created: $BASE_DIR and subdirectories.${NC}"


echo -e ""
echo -e "${CYAN}${BOLD}FIREWALL PERSISTENCE SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
OS_TYPE="unknown"
if [[ -f /etc/debian_version ]]; then
    OS_TYPE="debian"
    echo -e "${GREEN}Debian/Ubuntu detected. Ensuring iptables-persistent is set up.${NC}"
    if ! dpkg -s iptables-persistent &>/dev/null; then
        echo -e "${YELLOW}iptables-persistent not found. Installing...${NC}"
        DEBIAN_FRONTEND=noninteractive $PKG_INSTALL iptables-persistent
    fi
    mkdir -p /etc/iptables
elif [[ -f /etc/redhat-release || -f /etc/centos-release ]]; then
    OS_TYPE="redhat"
    echo -e "${GREEN}RHEL/CentOS detected. Ensuring iptables-services is set up.${NC}"
    if ! rpm -q iptables-services &>/dev/null; then
        echo -e "${YELLOW}iptables-services not found. Installing...${NC}"
        $PKG_INSTALL iptables-services
    fi
    if command -v systemctl &>/dev/null; then
        systemctl enable iptables &>/dev/null || true
        systemctl enable ip6tables &>/dev/null || true
    fi
elif [[ -f /etc/fedora-release ]]; then
    OS_TYPE="fedora" # Fedora uses firewalld by default, iptables-services might not be the primary
    echo -e "${GREEN}Fedora detected. DNSniper will use its own systemd service for rule persistence.${NC}"
    echo -e "${YELLOW}If you use firewalld, ensure it doesn't conflict. DNSniper manages iptables directly.${NC}"
else
    echo -e "${YELLOW}OS detection unclear. DNSniper will use its own systemd service for rule persistence if available.${NC}"
fi


echo -e ""
echo -e "${CYAN}${BOLD}DOWNLOADING SCRIPTS${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
_download_script() {
    local script_name="$1"
    local output_file="$2"
    echo -e "${YELLOW}Downloading ${script_name}...${NC}"
    if curl -sfL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 45 "${github_url}/${script_name}" -o "${output_file}.tmp"; then
        if [[ ! -s "${output_file}.tmp" ]]; then
            echo -e "${RED}${BOLD}Error:${NC} Downloaded ${script_name} is empty."
            rm -f "${output_file}.tmp"
            return 1
        fi
        chmod +x "${output_file}.tmp"
        mv "${output_file}.tmp" "${output_file}"
        echo -e "${GREEN}${script_name} successfully downloaded to ${output_file}.${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}Error:${NC} Failed to download ${script_name} from ${github_url}/${script_name}."
        rm -f "${output_file}.tmp" 2>/dev/null || true
        return 1
    fi
}
scripts_to_download=(
    "dnsniper-core.sh $CORE_SCRIPT"
    "dnsniper-daemon.sh $DAEMON_SCRIPT"
    "dnsniper.sh $MAIN_SCRIPT"
)
for item in "${scripts_to_download[@]}"; do
    script_name=$(echo "$item" | cut -d' ' -f1)
    output_file=$(echo "$item" | cut -d' ' -f2)
    if ! _download_script "$script_name" "$output_file"; then
        echo -e "${RED}${BOLD}Failed to download critical script ${script_name}. Installation aborted.${NC}"
        # Attempt cleanup if this was a fresh/clean install
        if [[ "$installation_type" == "clean" || "$installation_type" == "install" ]]; then
             rm -rf "$BASE_DIR" 2>/dev/null
        fi
        exit 1
    fi
done

ln -sf "$MAIN_SCRIPT" "$BIN_PATH"
chmod +x "$BIN_PATH" # Symlink target already executable, but good practice for the link itself.
echo -e "${GREEN}Symlink created: $BIN_PATH -> $MAIN_SCRIPT ${NC}"


echo -e ""
echo -e "${CYAN}${BOLD}CRON JOB MIGRATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
if command -v crontab &>/dev/null; then
    if crontab -l 2>/dev/null | grep -q "dnsniper"; then
        (crontab -l 2>/dev/null | grep -v "dnsniper") | crontab - 2>/dev/null || true
        echo -e "${GREEN}Removed old DNSniper cron jobs (migrating to systemd timer).${NC}"
    else
        echo -e "${GREEN}No old cron jobs found.${NC}"
    fi
fi


echo -e ""
echo -e "${CYAN}${BOLD}SCHEDULING SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}Do you want DNSniper to run automatically using a systemd timer?${NC}"
echo -e "1. ${BOLD}Yes${NC} - Run every hour (recommended)"
echo -e "2. ${BOLD}Yes${NC} - Run every 30 minutes"
echo -e "3. ${BOLD}No${NC} - I'll run it manually or set up my own scheduler"
read -rp "Choice (1-3) [Default: 1]: " schedule_choice
schedule_choice=${schedule_choice:-1}

new_scheduler_enabled=1
new_schedule_minutes=60
case "$schedule_choice" in
    1) new_scheduler_enabled=1; new_schedule_minutes=60; echo -e "${GREEN}Scheduled to run hourly.${NC}" ;;
    2) new_scheduler_enabled=1; new_schedule_minutes=30; echo -e "${GREEN}Scheduled to run every 30 minutes.${NC}" ;;
    3) new_scheduler_enabled=0; echo -e "${YELLOW}Automatic scheduling via systemd timer disabled.${NC}" ;;
    *) echo -e "${YELLOW}Invalid choice. Defaulting to hourly schedule.${NC}"; new_scheduler_enabled=1; new_schedule_minutes=60 ;;
esac


echo -e ""
echo -e "${CYAN}${BOLD}CONFIGURING DNSNIPER${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
if [[ "$installation_type" == "upgrade" && -f "$CONFIG_FILE" ]]; then
    echo -e "${YELLOW}Upgrading existing configuration file: $CONFIG_FILE ${NC}"
    # Update scheduler settings, or add them if missing
    grep -q "^scheduler_enabled=" "$CONFIG_FILE" && sed -i "s/^scheduler_enabled=.*/scheduler_enabled=$new_scheduler_enabled/" "$CONFIG_FILE" || echo "scheduler_enabled=$new_scheduler_enabled" >> "$CONFIG_FILE"
    grep -q "^schedule_minutes=" "$CONFIG_FILE" && sed -i "s/^schedule_minutes=.*/schedule_minutes=$new_schedule_minutes/" "$CONFIG_FILE" || echo "schedule_minutes=$new_schedule_minutes" >> "$CONFIG_FILE"
    
    # Add any missing default settings during upgrade
    [[ ! $(grep '^max_ips=' "$CONFIG_FILE") ]] && echo "max_ips=$DEFAULT_MAX_IPS" >> "$CONFIG_FILE"
    [[ ! $(grep '^timeout=' "$CONFIG_FILE") ]] && echo "timeout=$DEFAULT_TIMEOUT" >> "$CONFIG_FILE"
    [[ ! $(grep '^update_url=' "$CONFIG_FILE") ]] && echo "update_url='$DEFAULT_URL'" >> "$CONFIG_FILE"
    [[ ! $(grep '^auto_update=' "$CONFIG_FILE") ]] && echo "auto_update=$DEFAULT_AUTO_UPDATE" >> "$CONFIG_FILE"
    [[ ! $(grep '^expire_enabled=' "$CONFIG_FILE") ]] && echo "expire_enabled=$DEFAULT_EXPIRE_ENABLED" >> "$CONFIG_FILE"
    [[ ! $(grep '^expire_multiplier=' "$CONFIG_FILE") ]] && echo "expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER" >> "$CONFIG_FILE"
    [[ ! $(grep '^block_source=' "$CONFIG_FILE") ]] && echo "block_source=$DEFAULT_BLOCK_SOURCE" >> "$CONFIG_FILE"
    [[ ! $(grep '^block_destination=' "$CONFIG_FILE") ]] && echo "block_destination=$DEFAULT_BLOCK_DESTINATION" >> "$CONFIG_FILE"
    [[ ! $(grep '^logging_enabled=' "$CONFIG_FILE") ]] && echo "logging_enabled=$DEFAULT_LOGGING_ENABLED" >> "$CONFIG_FILE"
    [[ ! $(grep '^status_enabled=' "$CONFIG_FILE") ]] && echo "status_enabled=$DEFAULT_STATUS_ENABLED" >> "$CONFIG_FILE"
    echo -e "${GREEN}Configuration updated.${NC}"
else
    echo -e "${GREEN}Creating new default configuration file: $CONFIG_FILE ${NC}"
    cat > "$CONFIG_FILE" << EOF
# DNSniper Configuration File
# Version: $latest_commit (used for default URL if not overridden)

# Scheduler settings (used by systemd timer)
scheduler_enabled=$new_scheduler_enabled
schedule_minutes=$new_schedule_minutes

# Core behavior settings
max_ips=$DEFAULT_MAX_IPS                  # Max IPs to resolve per domain (5-50 recommended)
timeout=$DEFAULT_TIMEOUT                  # Timeout for DNS lookups and downloads (in seconds, 5-60 recommended)
update_url='$DEFAULT_URL'     # URL for the default domain blocklist
auto_update=$DEFAULT_AUTO_UPDATE            # 1 to auto-update default list on run, 0 to disable

# Rule expiration settings
expire_enabled=$DEFAULT_EXPIRE_ENABLED        # 1 to enable auto-removal of rules for domains no longer in default list
expire_multiplier=$DEFAULT_EXPIRE_MULTIPLIER  # How many 'schedule_minutes' cycles before a removed domain's rules expire (e.g., 5 * 60min = 5 hours)

# Firewall rule type settings
block_source=$DEFAULT_BLOCK_SOURCE          # 1 to block traffic FROM malicious IPs (INPUT/FORWARD chains if applicable)
block_destination=$DEFAULT_BLOCK_DESTINATION  # 1 to block traffic TO malicious IPs (OUTPUT chain)

# Logging and Status
logging_enabled=$DEFAULT_LOGGING_ENABLED    # 1 to enable uitgebreide logging to $LOG_FILE, 0 to disable
status_enabled=$DEFAULT_STATUS_ENABLED      # 1 to enable detailed status tracking in $STATUS_FILE, 0 to disable
EOF
    echo -e "${GREEN}Default configuration file created.${NC}"
fi


if [[ "$installation_type" != "upgrade" || ! -f "$BASE_DIR/domains-default.txt" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}CREATING INITIAL DATA FILES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    touch "$BASE_DIR/domains-default.txt" "$BASE_DIR/domains-add.txt" "$BASE_DIR/domains-remove.txt" \
          "$BASE_DIR/ips-add.txt" "$BASE_DIR/ips-remove.txt" \
          "$BASE_DIR/data/cdn_domains.txt" "$BASE_DIR/data/expired_domains.txt"
    cat > "$BASE_DIR/domains-default.txt" << EOF
# DNSniper Default Domains Blocklist
# This file is typically auto-updated from the 'update_url' in your config.
# Manual additions here might be overwritten on update unless 'auto_update' is disabled.
#
# One domain per line.
# Lines starting with # are comments. Empty lines are ignored.
# Example:
# bad-domain.example.com
EOF
    echo -e "${GREEN}Initial data and list files created.${NC}"
fi


echo -e ""
echo -e "${CYAN}${BOLD}SYSTEMD SERVICE INITIALIZATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
if command -v systemctl &>/dev/null; then
    echo -e "${BLUE}Configuring systemd services...${NC}"
    # Ensure daemon script is executable before sourcing
    chmod +x "$DAEMON_SCRIPT"
    if source "$DAEMON_SCRIPT" && create_systemd_service; then # create_systemd_service will call daemon-reload and enable/start
        echo -e "${GREEN}Systemd services (dnsniper.service, dnsniper.timer, dnsniper-firewall.service) configured.${NC}"
    else
        echo -e "${RED}${BOLD}Warning:${NC} Error creating or configuring systemd services."
        echo -e "${YELLOW}Check logs in $BASE_DIR/dnsniper.log (if enabled) or system journal (journalctl).${NC}"
    fi
else
    echo -e "${YELLOW}Systemctl not found. DNSniper will not be managed by systemd.${NC}"
    echo -e "${YELLOW}If you need automatic runs, please configure a cron job manually to execute 'sudo dnsniper --run-background'.${NC}"
fi


echo -e ""
echo -e "${CYAN}${BOLD}VERIFYING INSTALLATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
if "$BIN_PATH" --version >/dev/null 2>&1; then
    VERSION_OUTPUT=$("$BIN_PATH" --version)
    echo -e "${GREEN}DNSniper installation verified: ${VERSION_OUTPUT}${NC}"

    if [[ "$installation_type" != "upgrade" ]]; then
        echo -e "${YELLOW}Running initial default domains update in background...${NC}"
        nohup bash -c "source \"$DAEMON_SCRIPT\" &>/dev/null; USER=\$(whoami) LOGNAME=\$(whoami) HOME=\$HOME nice -n 10 \"$BIN_PATH\" --update" > "$BASE_DIR/initial_update.log" 2>&1 &
        echo -e "${BLUE}Initial update process started in background. Log: $BASE_DIR/initial_update.log${NC}"
        echo -e "${BLUE}You can check its progress via 'sudo dnsniper --status' once it starts.${NC}"
    fi
else
    echo -e "${RED}${BOLD}Warning:${NC} DNSniper command verification failed."
    echo -e "${YELLOW}Please try running 'sudo dnsniper --help' or 'sudo dnsniper --status'.${NC}"
    echo -e "${YELLOW}Check logs in $BASE_DIR (if logging enabled) or system journal for service errors.${NC}"
fi


echo -e ""
echo -e "${CYAN}${BOLD}INSTALLATION COMPLETE!${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}Usage:${NC}"
echo -e "  ${BOLD}Interactive Menu:${NC}   sudo dnsniper"
echo -e "  ${BOLD}View Help:${NC}          sudo dnsniper --help"
echo -e "  ${BOLD}Run Once (FG):${NC}      sudo dnsniper --run"
echo -e "  ${BOLD}Run Once (BG):${NC}      sudo dnsniper --run-background"
echo -e "  ${BOLD}Check Status:${NC}       sudo dnsniper --status"
echo -e "  ${BOLD}Update Default List:${NC} sudo dnsniper --update"
echo -e ""
echo -e "${BLUE}${BOLD}Thank you for installing DNSniper!${NC}"
echo -e ""