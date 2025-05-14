#!/usr/bin/env bash
# DNSniper Installer
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash
set -e

# ANSI color codes
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
WHITE='\e[97m'
BOLD='\e[1m'
NC='\e[0m'

# Display banner
echo -e "${BLUE}${BOLD}
$WHITE╔$BLUE═══════════════════════════════════════════$WHITE╗
$WHITE║$BLUE  ____  _   _ ____       _                 $WHITE║
$WHITE║$BLUE |  _ \\| \\ | / ___|_ __ (_)_ __   ___ _ __ $WHITE║
$WHITE║$BLUE | | | |  \\| \\___ \\ '_ \\| | '_ \\ / _ \\ '__|$WHITE║
$WHITE║$BLUE | |_| | |\\  |___) | | | | | |_) |  __/ |  $WHITE║
$WHITE║$BLUE |____/|_| \\_|____/|_| |_|_| .__/ \\___|_|  $WHITE║
$WHITE║$BLUE                           |_|              $WHITE║
$WHITE║$GREEN${BOLD} Domain-based Network Threat Mitigation    $WHITE║
$WHITE╚$BLUE═══════════════════════════════════════════$WHITE╝${NC}
"

# Paths
BASE_DIR="/etc/dnsniper"
BIN_PATH="/usr/local/bin/dnsniper"
TMP_SCRIPT="/tmp/dnsniper.sh"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error:${NC} This installer must be run as root (sudo)." >&2
    exit 1
fi

echo -e "${BLUE}${BOLD}[1/6]${NC} Detecting system..."

# Detect package manager and set command variables
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    PKG_UPDATE="apt update"
    PKG_INSTALL="apt install -y"
    DEPS="iptables iptables-persistent curl dnsutils sqlite3 cron"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite crontabs"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite crontabs"
else
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- sqlite3\n- cron/crontabs"
    
    read -rp "Continue anyway? [y/N]: " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        exit 1
    fi
    
    PKG_MANAGER="manual"
fi

echo -e "${GREEN}Detected system: ${PKG_MANAGER}${NC}"

# Install dependencies
if [[ "$PKG_MANAGER" != "manual" ]]; then
    echo -e "\n${BLUE}${BOLD}[2/6]${NC} Installing dependencies..."
    echo -e "${YELLOW}Updating package lists...${NC}"
    $PKG_UPDATE
    
    echo -e "${YELLOW}Installing required packages:${NC}"
    echo -e "${DEPS}"
    if ! $PKG_INSTALL $DEPS; then
        echo -e "${RED}${BOLD}Error:${NC} Failed to install dependencies."
        echo -e "Please install these packages manually and try again:"
        echo -e "${DEPS}"
        exit 1
    fi
    echo -e "${GREEN}Dependencies successfully installed.${NC}"
else
    echo -e "\n${BLUE}${BOLD}[2/6]${NC} Checking dependencies..."
    missing=()
    for cmd in iptables ip6tables curl dig sqlite3 crontab; do
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
echo -e "\n${BLUE}${BOLD}[3/6]${NC} Setting up directories..."
mkdir -p "$BASE_DIR"
echo -e "${GREEN}Directory created: $BASE_DIR${NC}"

# Setup firewall persistence according to system type
echo -e "\n${BLUE}${BOLD}[4/6]${NC} Configuring firewall persistence..."

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
echo -e "\n${BLUE}${BOLD}[5/6]${NC} Downloading DNSniper script..."
if curl -sfL --connect-timeout 10 --max-time 30 "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/dnsniper.sh" -o "$TMP_SCRIPT"; then
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
else
    echo -e "${RED}${BOLD}Error:${NC} Failed to download DNSniper script."
    exit 1
fi

# Initialize DNSniper
echo -e "\n${BLUE}${BOLD}[6/6]${NC} Initializing DNSniper..."
if "$BIN_PATH" --version &>/dev/null; then
    echo -e "${GREEN}DNSniper successfully initialized.${NC}"
    
    # Add default empty block list file if not exists
    if [[ ! -s "$BASE_DIR/domains-default.txt" ]]; then
        echo "# Default domains to block" > "$BASE_DIR/domains-default.txt"
        echo "# One domain per line" >> "$BASE_DIR/domains-default.txt"
        echo "" >> "$BASE_DIR/domains-default.txt"
        echo -e "${YELLOW}Created empty default domains file. Use 'Update Lists' to populate it.${NC}"
    fi
else
    echo -e "${RED}${BOLD}Error:${NC} Failed to initialize DNSniper. Please run 'sudo dnsniper' to check for errors."
fi

# Final instructions
echo -e "\n${GREEN}${BOLD}=== Installation Completed Successfully! ===${NC}"
echo -e "\n${YELLOW}To start using DNSniper:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper"
echo -e "\n${YELLOW}To view help:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --help" 
echo -e "\n${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}\n"