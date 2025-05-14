#!/usr/bin/env bash
# DNSniper Installer
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash

set -e

# ANSI color codes
RED='\e[31m' GREEN='\e[32m' YELLOW='\e[33m' BLUE='\e[34m' BOLD='\e[1m' NC='\e[0m'

# Display banner
echo -e "${BLUE}${BOLD}
 ____  _   _ ____       _                 
|  _ \| \ | / ___|_ __ (_)_ __   ___ _ __ 
| | | |  \| \___ \ '_ \| | '_ \ / _ \ '__|
| |_| | |\  |___) | | | | | |_) |  __/ |   
|____/|_| \_|____/|_| |_|_| .__/ \___|_|   
                          |_|             
${NC}
${BOLD}Domain-based Threat Mitigation${NC}
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

echo -e "${BLUE}${BOLD}[1/5]${NC} Detecting system..."

# Detect package manager and set command variables
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    PKG_UPDATE="apt update"
    PKG_INSTALL="apt install -y"
    DEPS="iptables curl dnsutils sqlite3 cron"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables curl bind-utils sqlite crontabs"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables curl bind-utils sqlite crontabs"
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
    echo -e "\n${BLUE}${BOLD}[2/5]${NC} Installing dependencies..."
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
    echo -e "\n${BLUE}${BOLD}[2/5]${NC} Checking dependencies..."
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
echo -e "\n${BLUE}${BOLD}[3/5]${NC} Setting up directories..."
mkdir -p "$BASE_DIR"
echo -e "${GREEN}Directory created: $BASE_DIR${NC}"

# Download script
echo -e "\n${BLUE}${BOLD}[4/5]${NC} Downloading DNSniper script..."
if curl -sfL --connect-timeout 10 --max-time 30 "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/dnsniper.sh" -o "$TMP_SCRIPT"; then
    # Verify script health
    if [[ ! -s "$TMP_SCRIPT" ]]; then
        echo -e "${RED}${BOLD}Error:${NC} Downloaded script is empty."
        exit 1
    fi
    
    # Make sure script is executable
    chmod +x "$TMP_SCRIPT"
    
    # Move script to final location
    cp "$TMP_SCRIPT" "$BASE_DIR/dnsniper.sh"
    ln -sf "$BASE_DIR/dnsniper.sh" "$BIN_PATH"
    chmod +x "$BIN_PATH"
    
    # Clean up
    rm -f "$TMP_SCRIPT"
    
    echo -e "${GREEN}DNSniper script installed to: $BIN_PATH${NC}"
else
    echo -e "${RED}${BOLD}Error:${NC} Failed to download DNSniper script."
    exit 1
fi

# Initialize DNSniper
echo -e "\n${BLUE}${BOLD}[5/5]${NC} Initializing DNSniper..."
if "$BIN_PATH" --version; then
    echo -e "${GREEN}DNSniper successfully initialized.${NC}"
else
    echo -e "${RED}${BOLD}Error:${NC} Failed to initialize DNSniper."
    exit 1
fi

# Final instructions
echo -e "\n${GREEN}${BOLD}=== Installation Completed Successfully! ===${NC}"
echo -e "\n${YELLOW}To start using DNSniper:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper"
echo -e "\n${YELLOW}To view help:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --help"
echo -e "\n${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}\n"