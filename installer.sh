#!/usr/bin/env bash
# DNSniper Installer
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

# Paths
BASE_DIR="/etc/dnsniper"
BIN_PATH="/usr/local/bin/dnsniper"
TMP_SCRIPT="/tmp/dnsniper.sh"
CHECKSUM_FILE="/tmp/dnsniper.sha256"
GITHUB_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main"

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
    
    # Create systemd unit for loading rules at boot
    cat > /etc/systemd/system/dnsniper-firewall.service << EOF
[Unit]
Description=DNSniper Firewall Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore $BASE_DIR/iptables.rules
ExecStart=/sbin/ip6tables-restore $BASE_DIR/ip6tables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload &>/dev/null || true
    systemctl enable dnsniper-firewall.service &>/dev/null || true
fi

# Download script
echo -e ""
echo -e "${CYAN}${BOLD}SCRIPT DOWNLOAD${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Download with retry logic
MAX_RETRIES=3
retry_count=0
download_success=false

while [[ $retry_count -lt $MAX_RETRIES && $download_success == false ]]; do
    echo -e "${YELLOW}Downloading DNSniper script (attempt $((retry_count+1))/$MAX_RETRIES)...${NC}"
    
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

# Make sure script is executable
chmod +x "$TMP_SCRIPT"

# Test the script with a simple command
if ! "$TMP_SCRIPT" --version &>/dev/null; then
    echo -e "${RED}${BOLD}Warning:${NC} Script test failed. Installing anyway, but there might be issues."
fi

# Move script to final location
cp "$TMP_SCRIPT" "$BASE_DIR/dnsniper.sh"
ln -sf "$BASE_DIR/dnsniper.sh" "$BIN_PATH"
chmod +x "$BASE_DIR/dnsniper.sh" "$BIN_PATH"

# Clean up
rm -f "$TMP_SCRIPT"

echo -e "${GREEN}DNSniper script installed to: $BIN_PATH${NC}"

# Initialize DNSniper
echo -e ""
echo -e "${CYAN}${BOLD}INITIALIZATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

if "$BIN_PATH" --version &>/dev/null; then
    echo -e "${GREEN}DNSniper successfully initialized.${NC}"
    
    # Add default empty block list file if not exists
    if [[ ! -s "$BASE_DIR/domains-default.txt" ]]; then
        echo "# Default domains to block" > "$BASE_DIR/domains-default.txt"
        echo "# One domain per line" >> "$BASE_DIR/domains-default.txt"
        echo "" >> "$BASE_DIR/domains-default.txt"
        echo -e "${YELLOW}Created empty default domains file. Use 'Update Lists' to populate it.${NC}"
    fi
    
    # Set up automatic updates
    echo -e ""
    echo -e "${CYAN}${BOLD}SCHEDULING${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Ask user about schedule preference
    echo -e "${YELLOW}How would you like to schedule DNSniper?${NC}"
    echo -e "1) Using cron (default)"
    echo -e "2) Using systemd timer"
    echo -e "3) No automatic scheduling"
    read -rp "Choose an option [1-3]: " sched_choice
    
    case "$sched_choice" in
        2)
            # Use systemd timer
            if command -v systemctl &>/dev/null; then
                echo -e "${YELLOW}Setting up systemd timer...${NC}"
                
                # Create systemd service
                cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation
After=network.target

[Service]
Type=oneshot
ExecStart=$BIN_PATH --run
User=root
Group=root
IOSchedulingClass=best-effort
CPUSchedulingPolicy=batch
Nice=19

[Install]
WantedBy=multi-user.target
EOF

                # Create systemd timer
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

                # Enable and start the timer
                systemctl daemon-reload
                systemctl enable dnsniper.timer
                systemctl start dnsniper.timer
                
                # Configure DNSniper to use systemd
                sed -i "s|^use_systemd=.*|use_systemd=1|" "$BASE_DIR/config.conf" 2>/dev/null || true
                
                echo -e "${GREEN}DNSniper scheduled with systemd timer (runs hourly)${NC}"
            else
                echo -e "${RED}Systemd not available. Falling back to cron.${NC}"
                
                # Create cron job for hourly execution
                (crontab -l 2>/dev/null | grep -v "$BIN_PATH"; echo "0 * * * * $BIN_PATH --run >/dev/null 2>&1") | crontab - 2>/dev/null || true
                
                echo -e "${GREEN}DNSniper scheduled with cron (runs hourly)${NC}"
            fi
            ;;
        3)
            # No scheduling
            echo -e "${YELLOW}Not setting up automatic scheduling.${NC}"
            echo -e "${YELLOW}You can manually run DNSniper with: ${NC}sudo dnsniper --run"
            ;;
        *)
            # Default: Use cron
            echo -e "${YELLOW}Setting up cron job...${NC}"
            
            # Create cron job for hourly execution
            (crontab -l 2>/dev/null | grep -v "$BIN_PATH"; echo "0 * * * * $BIN_PATH --run >/dev/null 2>&1") | crontab - 2>/dev/null || true
            
            echo -e "${GREEN}DNSniper scheduled with cron (runs hourly)${NC}"
            ;;
    esac
    
    # Ask about initial run
    echo -e ""
    echo -e "${CYAN}${BOLD}INITIAL RUN${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Would you like to run DNSniper now to update domain lists? [Y/n]: " run_now
    
    if [[ ! "$run_now" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}Running DNSniper for initial setup...${NC}"
        $BIN_PATH --update && $BIN_PATH --run
        echo -e "${GREEN}Initial setup complete!${NC}"
    else
        echo -e "${YELLOW}Skipping initial run. You can run DNSniper manually with 'sudo dnsniper'${NC}"
    fi
else
    echo -e "${RED}${BOLD}Error:${NC} Failed to initialize DNSniper. Please run 'sudo dnsniper' to check for errors."
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
echo -e "${YELLOW}To run manually:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --run"
echo -e ""
echo -e "${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}"
echo -e ""