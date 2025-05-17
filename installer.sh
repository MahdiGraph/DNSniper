#!/usr/bin/env bash
# DNSniper Installer
# Repository: https://github.com/MahdiGraph/DNSniper
# Version: 2.1.3
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash

set -eo pipefail

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
RULES_V4_FILE="$BASE_DIR/iptables.rules"
RULES_V6_FILE="$BASE_DIR/ip6tables.rules"

# Function to get latest commit with better error handling
get_latest_commit() {
    if ! command -v git &>/dev/null; then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Git is not installed. Using main branch instead." >&2
        echo "main"
        return 1
    fi
    
    local commit
    # Add timeout to prevent hanging
    if ! commit=$(timeout 10 git ls-remote https://github.com/MahdiGraph/DNSniper.git HEAD 2>/dev/null | cut -f1); then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Failed to retrieve latest commit hash. Using main branch." >&2
        echo "main"
        return 1
    fi
    
    if [[ -z "$commit" ]]; then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Empty commit hash received. Using main branch." >&2
        echo "main"
        return 1
    fi
    
    echo "$commit"
}

# Get latest commit with better error handling
latest_commit=$(get_latest_commit)
github_url="https://raw.githubusercontent.com/MahdiGraph/DNSniper/${latest_commit}"

# Display banner
echo -e "${BLUE}${BOLD}"
echo -e "    ____  _   _ ____       _                 "
echo -e "   |  _ \| \ | / ___| _ __ (_)_ __   ___ _ __ "
echo -e "   | | | |  \| \___ \| '_ \| | '_ \ / _ \ '__|"
echo -e "   | |_| | |\  |___) | | | | | |_) |  __/ |  "
echo -e "   |____/|_| \_|____/|_| |_|_| .__/ \___|_|  "
echo -e "                             |_|              "
echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v2.1.3 ${NC}"
echo -e ""

# Check root with clearer message
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error:${NC} This installer must be run as root (sudo)." >&2
    echo -e "Please run this command again with sudo privileges." >&2
    exit 1
fi

echo -e "${CYAN}${BOLD}SYSTEM DETECTION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Improved package manager detection with fallbacks
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    PKG_UPDATE="apt update"
    PKG_INSTALL="apt install -y"
    DEPS="iptables iptables-persistent curl dnsutils git ipset"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables iptables-services curl bind-utils git ipset"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables iptables-services curl bind-utils git ipset"
else
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- git\n- ipset"
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
    for cmd in iptables ip6tables curl dig git ipset; do
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
    
    # Stop running processes more gracefully
    if [[ -f "$BASE_DIR/dnsniper.lock" ]]; then
        echo -e "${YELLOW}Stopping any running DNSniper processes...${NC}"
        pid=$(cat "$BASE_DIR/dnsniper.lock" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo -e "${YELLOW}Sending graceful termination signal...${NC}"
            kill -15 "$pid" 2>/dev/null || true
            
            # Wait up to 10 seconds for process to terminate
            for i in {1..10}; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    echo -e "${GREEN}Process terminated successfully.${NC}"
                    break
                fi
                sleep 1
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "${YELLOW}Process still running, sending SIGKILL...${NC}"
                kill -9 "$pid" 2>/dev/null || true
                sleep 1
            fi
        fi
        rm -f "$BASE_DIR/dnsniper.lock" 2>/dev/null || true
    fi
    
    # Clean up ipsets with better error handling
    if command -v ipset &>/dev/null; then
        echo -e "${YELLOW}Removing ipsets...${NC}"
        if ipset list dnsniper-ipv4 &>/dev/null; then
            ipset destroy dnsniper-ipv4 2>/dev/null || echo -e "${YELLOW}Warning: Failed to destroy dnsniper-ipv4 ipset${NC}"
        fi
        if ipset list dnsniper-ipv6 &>/dev/null; then
            ipset destroy dnsniper-ipv6 2>/dev/null || echo -e "${YELLOW}Warning: Failed to destroy dnsniper-ipv6 ipset${NC}"
        fi
    fi
    
    # Improved service cleanup
    echo -e "${YELLOW}Stopping and disabling services...${NC}"
    for service in dnsniper.timer dnsniper.service dnsniper-firewall.service; do
        if systemctl list-unit-files "${service}" &>/dev/null; then
            systemctl stop "${service}" &>/dev/null || true
            systemctl disable "${service}" &>/dev/null || true
            rm -f "/etc/systemd/system/${service}" &>/dev/null || true
            echo -e "${GREEN}Removed service: ${service}${NC}"
        fi
    done
    
    # Reload systemd
    systemctl daemon-reload &>/dev/null || true
    
    # Clean up any old cron jobs
    if command -v crontab &>/dev/null; then
        echo -e "${YELLOW}Checking for old cron jobs...${NC}"
        if crontab -l 2>/dev/null | grep -q "dnsniper"; then
            (crontab -l 2>/dev/null | grep -v "dnsniper") | crontab - 2>/dev/null || true
            echo -e "${GREEN}Removed old cron jobs.${NC}"
        fi
    fi
    
    # Remove binary and directories with better error handling
    echo -e "${YELLOW}Removing files...${NC}"
    rm -f "$BIN_PATH" 2>/dev/null || echo -e "${YELLOW}Warning: Could not remove ${BIN_PATH}${NC}"
    if [[ -d "$BASE_DIR" ]]; then
        rm -rf "$BASE_DIR" 2>/dev/null || {
            echo -e "${YELLOW}Warning: Could not completely remove ${BASE_DIR}${NC}"
            echo -e "${YELLOW}Some files may need manual removal.${NC}"
        }
    fi
    
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

# Improved function to download scripts with better security
download_script() {
    local script_name="$1"
    local output_file="$2"
    
    echo -e "${YELLOW}Downloading ${script_name}...${NC}"
    
    # Enhanced security for downloads with proper certificate validation
    if curl -sfL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
            --retry 3 --retry-delay 2 --retry-max-time 60 \
            "${github_url}/${script_name}" -o "${output_file}.tmp"; then
        
        # Verify download size
        if [[ ! -s "${output_file}.tmp" ]]; then
            echo -e "${RED}${BOLD}Error:${NC} Downloaded ${script_name} is empty."
            rm -f "${output_file}.tmp"
            return 1
        fi
        
        # Make executable and move to final destination (atomic operation)
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

# Download scripts
echo -e ""
echo -e "${CYAN}${BOLD}SCRIPT DOWNLOAD${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Download the scripts with retry mechanism
max_retries=3
for script_name in "dnsniper-core.sh" "dnsniper-daemon.sh" "dnsniper.sh"; do
    output_file=""
    case "$script_name" in
        "dnsniper-core.sh") output_file="$CORE_SCRIPT" ;;
        "dnsniper-daemon.sh") output_file="$DAEMON_SCRIPT" ;;
        "dnsniper.sh") output_file="$MAIN_SCRIPT" ;;
    esac
    
    retries=0
    success=false
    
    while [[ $retries -lt $max_retries && $success == false ]]; do
        if download_script "$script_name" "$output_file"; then
            success=true
        else
            retries=$((retries + 1))
            if [[ $retries -lt $max_retries ]]; then
                echo -e "${YELLOW}Retrying download ($retries of $max_retries)...${NC}"
                sleep 2
            else
                echo -e "${RED}${BOLD}Failed to download $script_name after $max_retries attempts. Installation aborted.${NC}"
                exit 1
            fi
        fi
    done
done

# Create symlink
ln -sf "$MAIN_SCRIPT" "$BIN_PATH"
chmod +x "$BIN_PATH"
echo -e "${GREEN}Created symlink: $BIN_PATH${NC}"

# Create or update systemd services with optimized settings
echo -e ""
echo -e "${CYAN}${BOLD}SYSTEMD SERVICES${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

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

# Timer with randomized delay to prevent system load spikes
local_schedule_minutes=60
if [[ -f "$CONFIG_FILE" ]]; then
    config_minutes=$(grep '^schedule_minutes=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -n "$config_minutes" && "$config_minutes" =~ ^[0-9]+$ ]]; then
        local_schedule_minutes=$config_minutes
    fi
fi

cat > /etc/systemd/system/dnsniper.timer << EOF
[Unit]
Description=Run DNSniper periodically
Requires=dnsniper.service

[Timer]
Unit=dnsniper.service
OnBootSec=120s
OnUnitActiveSec=${local_schedule_minutes}m
AccuracySec=60s
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOF

# Firewall service with proper failure handling
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

# Create initial firewall rules files if needed
if [[ ! -f "$RULES_V4_FILE" ]]; then
    echo "*filter" > "$RULES_V4_FILE"
    echo ":INPUT ACCEPT [0:0]" >> "$RULES_V4_FILE"
    echo ":FORWARD ACCEPT [0:0]" >> "$RULES_V4_FILE"
    echo ":OUTPUT ACCEPT [0:0]" >> "$RULES_V4_FILE"
    echo ":DNSniper - [0:0]" >> "$RULES_V4_FILE"
    echo "COMMIT" >> "$RULES_V4_FILE"
fi

if [[ ! -f "$RULES_V6_FILE" ]]; then
    echo "*filter" > "$RULES_V6_FILE"
    echo ":INPUT ACCEPT [0:0]" >> "$RULES_V6_FILE"
    echo ":FORWARD ACCEPT [0:0]" >> "$RULES_V6_FILE"
    echo ":OUTPUT ACCEPT [0:0]" >> "$RULES_V6_FILE"
    echo ":DNSniper6 - [0:0]" >> "$RULES_V6_FILE"
    echo "COMMIT" >> "$RULES_V6_FILE"
fi

# Initialize DNSniper
echo -e ""
echo -e "${CYAN}${BOLD}INITIALIZATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Reload systemd to apply changes
systemctl daemon-reload || {
    echo -e "${YELLOW}Warning: Failed to reload systemd. Services may not be properly registered.${NC}"
}

# Enable and start services based on configuration
if [[ "$scheduler_enabled" -eq 1 ]]; then
    echo -e "${GREEN}Enabling DNSniper services...${NC}"
    
    # Enable services with better error handling
    systemctl enable dnsniper-firewall.service &>/dev/null || echo -e "${YELLOW}Warning: Failed to enable dnsniper-firewall.service${NC}"
    systemctl enable dnsniper.service &>/dev/null || echo -e "${YELLOW}Warning: Failed to enable dnsniper.service${NC}"
    systemctl enable dnsniper.timer &>/dev/null || echo -e "${YELLOW}Warning: Failed to enable dnsniper.timer${NC}"
    
    # Start firewall service first
    echo -e "${YELLOW}Starting firewall service...${NC}"
    if ! systemctl start dnsniper-firewall.service &>/dev/null; then
        echo -e "${YELLOW}Warning: Failed to start dnsniper-firewall.service. Will retry after creating chains.${NC}"
        # Try to initialize firewall chains manually
        if [[ -x "$BIN_PATH" ]]; then
            "$BIN_PATH" --initialize-firewall &>/dev/null || true
            # Retry starting the service
            systemctl start dnsniper-firewall.service &>/dev/null || echo -e "${YELLOW}Warning: Still failed to start firewall service. Please check logs.${NC}"
        fi
    fi
    
    # Start timer service in background
    echo -e "${YELLOW}Starting timer service...${NC}"
    systemctl start dnsniper.timer &>/dev/null &
    
    echo -e "${GREEN}Services enabled and started in background.${NC}"
    echo -e "${BLUE}Tip: Check service status with: sudo dnsniper --status${NC}"
else
    echo -e "${YELLOW}Scheduler disabled. Only enabling firewall service.${NC}"
    systemctl enable dnsniper-firewall.service &>/dev/null || true
    systemctl start dnsniper-firewall.service &>/dev/null || true
fi

# IMPROVED SECTION: Make sure initialization doesn't hang
# Only check version instead of running a full operation
echo -e "${BLUE}Verifying installation...${NC}"
if "$BIN_PATH" --version >/dev/null 2>&1; then
    echo -e "${GREEN}DNSniper successfully initialized.${NC}"
    if [[ "$installation_type" != "upgrade" ]]; then
        echo -e "${YELLOW}Running initial domains update in background...${NC}"
        # Run update in background to avoid blocking the installer
        nohup bash -c "nice -n 10 $BIN_PATH --update" >/dev/null 2>&1 &
        echo -e "${BLUE}Initial update will continue in background.${NC}"
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