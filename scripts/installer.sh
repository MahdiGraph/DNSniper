#!/bin/bash
# DNSniper v2.0 Installer

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions for colored output
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Paths
INSTALL_DIR="/etc/dnsniper"
LOG_DIR="/var/log/dnsniper"
BIN_DIR="/usr/bin"
SYSTEMD_DIR="/etc/systemd/system"
IPTABLES_DIR="/etc/iptables"
CONFIG_FILE="${INSTALL_DIR}/config.yaml"

# GitHub repository information
GITHUB_REPO="MahdiGraph/DNSniper"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}"

# Check for root access
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS and package manager
detect_os() {
    if command_exists apt-get; then
        OS="debian"
        PKG_MANAGER="apt-get"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update -q"
    elif command_exists yum; then
        OS="redhat"
        PKG_MANAGER="yum"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum check-update -q"
    elif command_exists dnf; then
        OS="redhat"
        PKG_MANAGER="dnf"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf check-update -q"
    elif command_exists zypper; then
        OS="suse"
        PKG_MANAGER="zypper"
        PKG_INSTALL="zypper install -y"
        PKG_UPDATE="zypper refresh"
    elif command_exists pacman; then
        OS="arch"
        PKG_MANAGER="pacman"
        PKG_INSTALL="pacman -S --noconfirm"
        PKG_UPDATE="pacman -Sy"
    else
        OS="unknown"
        print_error "Unsupported Linux distribution. Package manager not found."
        exit 1
    fi
    
    print_info "Detected OS: $OS with package manager: $PKG_MANAGER"
}

# Function to check and install dependencies
install_dependencies() {
    print_info "Checking and installing dependencies..."
    
    # Update package lists
    $PKG_UPDATE
    
    # List of packages to check and install
    local packages=()
    
    # Check curl
    if ! command_exists curl; then
        print_info "Installing curl..."
        packages+=("curl")
    fi
    
    # Check sqlite3
    if ! command_exists sqlite3; then
        print_info "Installing sqlite3..."
        if [ "$OS" = "debian" ]; then
            packages+=("sqlite3")
        elif [ "$OS" = "redhat" ]; then
            packages+=("sqlite")
        elif [ "$OS" = "suse" ]; then
            packages+=("sqlite3")
        elif [ "$OS" = "arch" ]; then
            packages+=("sqlite")
        fi
    fi
    
    # Check iptables
    if ! command_exists iptables; then
        print_info "Installing iptables..."
        packages+=("iptables")
    fi
    
    # Check ipset
    if ! command_exists ipset; then
        print_info "Installing ipset..."
        packages+=("ipset")
    fi
    
    # Check for iptables persistence packages based on OS
    if [ "$OS" = "debian" ]; then
        if ! dpkg -l | grep -q iptables-persistent; then
            print_info "Installing iptables-persistent..."
            # Pre-configure iptables-persistent to not ask questions
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
            packages+=("iptables-persistent")
        fi
    elif [ "$OS" = "redhat" ]; then
        if ! rpm -q iptables-services >/dev/null 2>&1; then
            print_info "Installing iptables-services..."
            packages+=("iptables-services")
        fi
    elif [ "$OS" = "suse" ]; then
        # SUSE uses a different mechanism for persistence
        touch /etc/sysconfig/iptables
        touch /etc/sysconfig/ip6tables
    elif [ "$OS" = "arch" ]; then
        # Arch has iptables-persistance package
        if ! pacman -Q iptables-persistent >/dev/null 2>&1; then
            print_info "Installing iptables-persistent..."
            packages+=("iptables-persistent")
        fi
    fi
    
    # Install all required packages if any
    if [ ${#packages[@]} -gt 0 ]; then
        print_info "Installing packages: ${packages[*]}"
        $PKG_INSTALL "${packages[@]}"
        if [ $? -ne 0 ]; then
            print_error "Failed to install required packages"
            exit 1
        fi
    else
        print_info "All required packages are already installed."
    fi
}

# Function to enable persistence services
enable_persistence_services() {
    print_info "Enabling persistence services..."
    
    if [ "$OS" = "debian" ]; then
        # Enable and restart netfilter-persistent service
        systemctl enable netfilter-persistent 2>/dev/null || true
        systemctl restart netfilter-persistent 2>/dev/null || true
    elif [ "$OS" = "redhat" ]; then
        # Enable and start iptables and ipset services
        systemctl enable iptables 2>/dev/null || true
        systemctl enable ip6tables 2>/dev/null || true
        systemctl enable ipset 2>/dev/null || true
        systemctl start iptables 2>/dev/null || true
        systemctl start ip6tables 2>/dev/null || true
        systemctl start ipset 2>/dev/null || true
    elif [ "$OS" = "suse" ]; then
        # Enable SuSEfirewall2
        systemctl enable SuSEfirewall2 2>/dev/null || true
        systemctl restart SuSEfirewall2 2>/dev/null || true
    elif [ "$OS" = "arch" ]; then
        # Arch uses iptables.service and ip6tables.service
        systemctl enable iptables 2>/dev/null || true
        systemctl enable ip6tables 2>/dev/null || true
        systemctl start iptables 2>/dev/null || true
        systemctl start ip6tables 2>/dev/null || true
    fi
}

# Function to save ipset and iptables rules for persistence
save_rules_for_persistence() {
    print_info "Saving rules for persistence..."
    
    # Create iptables rules directory if it doesn't exist
    mkdir -p "$IPTABLES_DIR"
    
    # Save ipset configuration
    ipset save > /etc/ipset.conf
    
    # Save iptables rules
    iptables-save > "${IPTABLES_DIR}/rules.v4"
    ip6tables-save > "${IPTABLES_DIR}/rules.v6"
    
    # Apply persistence based on OS
    if [ "$OS" = "debian" ]; then
        systemctl restart netfilter-persistent 2>/dev/null || true
    elif [ "$OS" = "redhat" ]; then
        systemctl restart iptables 2>/dev/null || true
        systemctl restart ip6tables 2>/dev/null || true
        systemctl restart ipset 2>/dev/null || true
    elif [ "$OS" = "suse" ]; then
        systemctl restart SuSEfirewall2 2>/dev/null || true
    elif [ "$OS" = "arch" ]; then
        systemctl restart iptables 2>/dev/null || true
        systemctl restart ip6tables 2>/dev/null || true
    fi
}

# Function to build the binaries directly to installation directory
build_binaries() {
    print_info "Building DNSniper binaries..."
    
    # Determine script location
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    
    # Go one level up from scripts directory
    cd "$(dirname "$SCRIPT_DIR")"
    
    # Ensure install directory exists
    mkdir -p "$INSTALL_DIR"
    
    # Build dnsniper directly to installation directory
    print_info "Building dnsniper..."
    go build -o "$INSTALL_DIR/dnsniper" "./cmd/dnsniper"
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper"
        exit 1
    fi
    
    # Build dnsniper-agent directly to installation directory
    print_info "Building dnsniper-agent..."
    go build -o "$INSTALL_DIR/dnsniper-agent" "./cmd/dnsniper-agent"
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper-agent"
        exit 1
    fi
    
    # Create symlinks
    ln -sf "$INSTALL_DIR/dnsniper" "$BIN_DIR/dnsniper"
    ln -sf "$INSTALL_DIR/dnsniper-agent" "$BIN_DIR/dnsniper-agent"
    
    print_success "Binaries built and installed successfully"
    exit 0
}

# Function to download binaries from GitHub
download_binaries() {
    print_info "Downloading DNSniper binaries..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        armv7*)
            ARCH="arm"
            ;;
        i386|i686)
            ARCH="386"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    print_info "Detected architecture: $ARCH"
    
    # Find latest release
    print_info "Fetching latest release information..."
    LATEST_VERSION=""
    
    if command_exists curl && command_exists jq; then
        # Try with GitHub API first
        API_RESPONSE=$(curl -s "${GITHUB_API}/releases/latest")
        if [ $? -eq 0 ] && [ -n "$API_RESPONSE" ]; then
            LATEST_VERSION=$(echo "$API_RESPONSE" | jq -r .tag_name 2>/dev/null)
        fi
    fi
    
    # Fallback if API call failed or jq is not available
    if [ -z "$LATEST_VERSION" ] || [ "$LATEST_VERSION" = "null" ]; then
        print_warning "Could not determine latest version from GitHub API. Using fallback method."
        # Parse HTML page as a fallback (less reliable)
        RELEASES_PAGE=$(curl -s "https://github.com/${GITHUB_REPO}/releases")
        if [ $? -eq 0 ] && [ -n "$RELEASES_PAGE" ]; then
            # Extract the first release tag with grep and sed
            LATEST_VERSION=$(echo "$RELEASES_PAGE" | grep -o "/${GITHUB_REPO}/releases/tag/[^ \"]*" | head -1 | sed "s/.*\/tag\///")
        fi
        # If still no version found, use a hardcoded fallback
        if [ -z "$LATEST_VERSION" ]; then
            LATEST_VERSION="v2.0.0"  # Fallback version
            print_warning "Could not determine latest version. Using fallback version ${LATEST_VERSION}."
        else
            print_info "Found latest version: ${LATEST_VERSION}"
        fi
    else
        print_info "Found latest version: ${LATEST_VERSION}"
    fi
    
    # Construct download URLs
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_VERSION}/dnsniper-linux-${ARCH}.zip"
    CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_VERSION}/dnsniper-linux-${ARCH}.zip.sha256"
    
    # Download package
    print_info "Downloading DNSniper binary package for ${ARCH}..."
    print_info "Download URL: ${DOWNLOAD_URL}"
    curl -L --fail "${DOWNLOAD_URL}" -o "${TEMP_DIR}/dnsniper.zip"
    if [ $? -ne 0 ]; then
        print_error "Failed to download DNSniper. Please check your internet connection and try again."
        print_error "If the problem persists, visit https://github.com/${GITHUB_REPO}/releases for manual download."
        exit 1
    fi
    
    # Verify checksum if available
    if command_exists sha256sum; then
        print_info "Downloading checksum file..."
        if curl -L --fail -s "${CHECKSUM_URL}" -o "${TEMP_DIR}/checksum.sha256"; then
            print_info "Verifying package integrity..."
            # Extract just the hash from the checksum file
            EXPECTED_HASH=$(cut -d ' ' -f 1 "${TEMP_DIR}/checksum.sha256")
            # Calculate hash of the downloaded file
            ACTUAL_HASH=$(sha256sum "${TEMP_DIR}/dnsniper.zip" | cut -d ' ' -f 1)
            # Compare hashes
            if [ "$EXPECTED_HASH" = "$ACTUAL_HASH" ]; then
                print_success "Checksum verification passed!"
            else
                print_error "Checksum verification failed! The downloaded package may be corrupted."
                print_error "Expected: $EXPECTED_HASH"
                print_error "Actual:   $ACTUAL_HASH"
                print_error "Please try again or download manually from https://github.com/${GITHUB_REPO}/releases"
                exit 1
            fi
        else
            print_warning "Could not download checksum file. Skipping integrity check."
        fi
    else
        print_warning "sha256sum not found. Skipping integrity check."
    fi
    
    # Extract the package
    print_info "Extracting DNSniper binaries..."
    unzip -q "${TEMP_DIR}/dnsniper.zip" -d "${TEMP_DIR}"
    if [ $? -ne 0 ]; then
        print_error "Failed to extract DNSniper binaries."
        exit 1
    fi
    
    # Find the binaries
    MAIN_BINARY="${TEMP_DIR}/dnsniper-linux-${ARCH}"
    AGENT_BINARY="${TEMP_DIR}/dnsniper-agent-linux-${ARCH}"
    
    # Check if binaries were found
    if [ ! -f "$MAIN_BINARY" ] || [ ! -f "$AGENT_BINARY" ]; then
        print_error "Could not find expected DNSniper executables in the downloaded package."
        print_error "Files in package:"
        ls -la "${TEMP_DIR}"
        print_error "Installation failed."
        exit 1
    fi
    
    # Install binaries to installation directory
    cp "$MAIN_BINARY" "$INSTALL_DIR/dnsniper"
    cp "$AGENT_BINARY" "$INSTALL_DIR/dnsniper-agent"
    
    # Create symlinks
    ln -sf "$INSTALL_DIR/dnsniper" "$BIN_DIR/dnsniper"
    ln -sf "$INSTALL_DIR/dnsniper-agent" "$BIN_DIR/dnsniper-agent"
    
    # Set executable permissions
    chmod +x "$INSTALL_DIR/dnsniper"
    chmod +x "$INSTALL_DIR/dnsniper-agent"
    
    print_success "Binaries installed successfully"
    return 0
}

# Function to uninstall DNSniper
uninstall_dnsniper() {
    print_info "Uninstalling DNSniper..."
    
    # Stop and disable services
    print_info "Stopping and disabling services..."
    systemctl stop dnsniper-agent.service 2>/dev/null
    systemctl disable dnsniper-agent.service 2>/dev/null
    systemctl stop dnsniper-agent.timer 2>/dev/null
    systemctl disable dnsniper-agent.timer 2>/dev/null
    
    # Destroy ipset sets
    print_info "Destroying ipset sets..."
    ipset destroy whitelistIP-v4 2>/dev/null
    ipset destroy whitelistRange-v4 2>/dev/null
    ipset destroy blocklistIP-v4 2>/dev/null
    ipset destroy blocklistRange-v4 2>/dev/null
    ipset destroy whitelistIP-v6 2>/dev/null
    ipset destroy whitelistRange-v6 2>/dev/null
    ipset destroy blocklistIP-v6 2>/dev/null
    ipset destroy blocklistRange-v6 2>/dev/null
    
    # Remove iptables rules
    print_info "Removing iptables rules..."
    for chain in INPUT OUTPUT FORWARD; do
        iptables -D $chain -m set --match-set whitelistIP-v4 src -j ACCEPT 2>/dev/null
        iptables -D $chain -m set --match-set whitelistRange-v4 src -j ACCEPT 2>/dev/null
        iptables -D $chain -m set --match-set blocklistIP-v4 src -j DROP 2>/dev/null
        iptables -D $chain -m set --match-set blocklistRange-v4 src -j DROP 2>/dev/null
        iptables -D $chain -m set --match-set whitelistIP-v4 dst -j ACCEPT 2>/dev/null
        iptables -D $chain -m set --match-set whitelistRange-v4 dst -j ACCEPT 2>/dev/null
        iptables -D $chain -m set --match-set blocklistIP-v4 dst -j DROP 2>/dev/null
        iptables -D $chain -m set --match-set blocklistRange-v4 dst -j DROP 2>/dev/null
        
        ip6tables -D $chain -m set --match-set whitelistIP-v6 src -j ACCEPT 2>/dev/null
        ip6tables -D $chain -m set --match-set whitelistRange-v6 src -j ACCEPT 2>/dev/null
        ip6tables -D $chain -m set --match-set blocklistIP-v6 src -j DROP 2>/dev/null
        ip6tables -D $chain -m set --match-set blocklistRange-v6 src -j DROP 2>/dev/null
        ip6tables -D $chain -m set --match-set whitelistIP-v6 dst -j ACCEPT 2>/dev/null
        ip6tables -D $chain -m set --match-set whitelistRange-v6 dst -j ACCEPT 2>/dev/null
        ip6tables -D $chain -m set --match-set blocklistIP-v6 dst -j DROP 2>/dev/null
        ip6tables -D $chain -m set --match-set blocklistRange-v6 dst -j DROP 2>/dev/null
    done
    
    # Save iptables rules
    mkdir -p $IPTABLES_DIR
    iptables-save > "${IPTABLES_DIR}/rules.v4" 2>/dev/null
    ip6tables-save > "${IPTABLES_DIR}/rules.v6" 2>/dev/null
    
    # Apply persistence based on OS
    detect_os
    save_rules_for_persistence
    
    # Delete systemd files
    print_info "Removing systemd files..."
    rm -f "${SYSTEMD_DIR}/dnsniper-agent.service"
    rm -f "${SYSTEMD_DIR}/dnsniper-agent.timer"
    systemctl daemon-reload
    
    # Remove binaries and directories
    print_info "Removing binaries and directories..."
    rm -f "${BIN_DIR}/dnsniper"
    rm -f "${BIN_DIR}/dnsniper-agent"
    rm -f "${BIN_DIR}/dnsniper-installer"
    rm -rf "$INSTALL_DIR"
    rm -rf "$LOG_DIR"
    
    print_success "DNSniper has been uninstalled"
    exit 0
}

# Check command line arguments
if [ "$1" = "--build" ]; then
    build_binaries
    # build_binaries will exit after completion
elif [ "$1" = "uninstall" ]; then
    uninstall_dnsniper
fi

# Detect OS
detect_os

# Install dependencies
install_dependencies

# Clean install or reinstall
print_info "Installing DNSniper v2.0..."

# Stop and disable any existing service
systemctl stop dnsniper-agent.service 2>/dev/null
systemctl disable dnsniper-agent.service 2>/dev/null
systemctl stop dnsniper-agent.timer 2>/dev/null
systemctl disable dnsniper-agent.timer 2>/dev/null

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$IPTABLES_DIR"

# Check for existing installation and configuration
CONFIG_EXISTS="false"
if [ -f "$CONFIG_FILE" ]; then
    CONFIG_EXISTS="true"
fi

# Determine installation type
INSTALL_TYPE="clean"
if [ -d "$INSTALL_DIR" ] || [ -f "$BIN_DIR/dnsniper" ] || [ -f "$SYSTEMD_DIR/dnsniper-agent.service" ]; then
    print_warning "DNSniper installation found. What would you like to do?"
    echo "1) Reinstall with existing settings"
    echo "2) Clean install (remove existing installation and reinstall)"
    echo "3) Cancel"
    read -p "Enter choice [1-3]: " choice
    case $choice in
        1)
            print_info "Reinstalling with existing settings..."
            INSTALL_TYPE="reinstall"
            
            # If reinstalling, get the current configuration
            if [ "$CONFIG_EXISTS" = "true" ]; then
                print_info "Using existing configuration"
                
                # Try to extract existing configuration
                if command_exists grep && command_exists awk; then
                    # Extract block_chains
                    BLOCK_CHAINS_LINE=$(grep "block_chains:" "$CONFIG_FILE" | awk '{print $2}')
                    if [ -n "$BLOCK_CHAINS_LINE" ]; then
                        BLOCK_CHAINS="$BLOCK_CHAINS_LINE"
                    fi
                    
                    # Extract update_interval
                    UPDATE_INTERVAL_LINE=$(grep "update_interval:" "$CONFIG_FILE" | awk '{print $2}')
                    if [ -n "$UPDATE_INTERVAL_LINE" ]; then
                        UPDATE_INTERVAL="$UPDATE_INTERVAL_LINE"
                    fi
                fi
            fi
            ;;
        2)
            print_info "Performing clean install..."
            INSTALL_TYPE="clean"
            
            # Remove old files to ensure clean installation
            rm -f "$BIN_DIR/dnsniper" "$BIN_DIR/dnsniper-agent"
            rm -f "${SYSTEMD_DIR}/dnsniper-agent.service"
            rm -f "${SYSTEMD_DIR}/dnsniper-agent.timer"
            rm -rf "$INSTALL_DIR"
            rm -rf "$LOG_DIR"
            mkdir -p "$INSTALL_DIR"
            mkdir -p "$LOG_DIR"
            
            CONFIG_EXISTS="false"
            ;;
        3)
            print_info "Installation cancelled."
            exit 0
            ;;
        *)
            print_error "Invalid choice. Exiting."
            exit 1
            ;;
    esac
else
    print_info "No existing installation found. Performing clean install."
    INSTALL_TYPE="clean"
    CONFIG_EXISTS="false"
fi

# Set default values
BLOCK_CHAINS="ALL"
UPDATE_INTERVAL="3h"

# Get configuration settings from user if needed
if [ "$INSTALL_TYPE" = "clean" ] || [ "$CONFIG_EXISTS" = "false" ]; then
    # Prompt for block chains
    print_info "Select chains to apply blocking rules:"
    echo "1) ALL chains (INPUT + OUTPUT + FORWARD) [Default]"
    echo "2) INPUT only"
    echo "3) OUTPUT only"
    echo "4) FORWARD only"
    echo "5) INPUT + OUTPUT"
    echo "6) INPUT + FORWARD"
    echo "7) OUTPUT + FORWARD"
    read -p "Enter choice [1-7]: " chain_choice
    
    case $chain_choice in
        2)
            BLOCK_CHAINS="INPUT"
            ;;
        3)
            BLOCK_CHAINS="OUTPUT"
            ;;
        4)
            BLOCK_CHAINS="FORWARD"
            ;;
        5)
            BLOCK_CHAINS="INPUT,OUTPUT"
            ;;
        6)
            BLOCK_CHAINS="INPUT,FORWARD"
            ;;
        7)
            BLOCK_CHAINS="OUTPUT,FORWARD"
            ;;
        *)
            BLOCK_CHAINS="ALL"
            ;;
    esac
    
    print_info "Using block chains: $BLOCK_CHAINS"
    
    # Prompt for update interval
    print_info "How often should DNSniper update its rules?"
    echo "1) Every hour"
    echo "2) Every 3 hours [Default]"
    echo "3) Every 6 hours"
    echo "4) Every 12 hours"
    echo "5) Every day"
    echo "6) Custom interval"
    read -p "Enter choice [1-6]: " interval_choice
    
    case $interval_choice in
        1)
            UPDATE_INTERVAL="1h"
            ;;
        3)
            UPDATE_INTERVAL="6h"
            ;;
        4)
            UPDATE_INTERVAL="12h"
            ;;
        5)
            UPDATE_INTERVAL="24h"
            ;;
        6)
            print_info "Enter custom interval (format: 1h, 30m, 12h, etc):"
            read -p "> " custom_interval
            if [[ "$custom_interval" =~ ^[0-9]+[mhdw]$ ]]; then
                UPDATE_INTERVAL="$custom_interval"
            else
                print_warning "Invalid format. Using default (3h)."
                UPDATE_INTERVAL="3h"
            fi
            ;;
        *)
            UPDATE_INTERVAL="3h"
            ;;
    esac
    
    print_info "Using update interval: $UPDATE_INTERVAL"
fi

# Check for already built binaries in install directory
if [ -f "$INSTALL_DIR/dnsniper" ] && [ -f "$INSTALL_DIR/dnsniper-agent" ]; then
    print_info "Using existing binaries in $INSTALL_DIR..."
else
    # No local binaries, download from GitHub
    download_binaries
fi

# Create symlinks (in case they were deleted)
ln -sf "$INSTALL_DIR/dnsniper" "$BIN_DIR/dnsniper"
ln -sf "$INSTALL_DIR/dnsniper-agent" "$BIN_DIR/dnsniper-agent"

# Set executable permissions
chmod +x "$INSTALL_DIR/dnsniper"
chmod +x "$INSTALL_DIR/dnsniper-agent"

# Create config.yaml if it doesn't exist
if [ "$CONFIG_EXISTS" = "false" ]; then
    cat > "$CONFIG_FILE" << EOF
# DNSniper v2.0 Configuration
dns_resolvers:
  - "8.8.8.8"
  - "1.1.1.1"

# Firewall configuration
block_chains: $BLOCK_CHAINS
enable_ipv6: true

# Update configuration
update_urls:
  - "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
update_interval: $UPDATE_INTERVAL

# Domain handling
rule_expiration: 30d
max_ips_per_domain: 5

# Logging
logging_enabled: false
log_level: info

# Paths
database_path: "/etc/dnsniper/dnsniper.db"
log_path: "/var/log/dnsniper"
iptables_path: "/sbin/iptables"
ip6tables_path: "/sbin/ip6tables"
ipset_path: "/sbin/ipset"
EOF
fi

# Create systemd service
cat > "${SYSTEMD_DIR}/dnsniper-agent.service" << EOF
[Unit]
Description=DNSniper Agent Service
After=network.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/dnsniper-agent
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer
cat > "${SYSTEMD_DIR}/dnsniper-agent.timer" << EOF
[Unit]
Description=Run DNSniper Agent regularly
Requires=dnsniper-agent.service

[Timer]
Unit=dnsniper-agent.service
OnBootSec=1min
OnUnitActiveSec=$UPDATE_INTERVAL

[Install]
WantedBy=timers.target
EOF

# Reload systemd
systemctl daemon-reload

# Create ipset sets
print_info "Creating ipset sets..."
ipset create whitelistIP-v4 hash:ip hashsize 4096 maxelem 65536 -exist
ipset create whitelistRange-v4 hash:net hashsize 4096 maxelem 65536 -exist
ipset create blocklistIP-v4 hash:ip hashsize 4096 maxelem 65536 -exist
ipset create blocklistRange-v4 hash:net hashsize 4096 maxelem 65536 -exist

ipset create whitelistIP-v6 hash:ip family inet6 hashsize 4096 maxelem 65536 -exist
ipset create whitelistRange-v6 hash:net family inet6 hashsize 4096 maxelem 65536 -exist
ipset create blocklistIP-v6 hash:ip family inet6 hashsize 4096 maxelem 65536 -exist
ipset create blocklistRange-v6 hash:net family inet6 hashsize 4096 maxelem 65536 -exist

# Generate iptables rules files
print_info "Generating iptables rules files..."

# Function to generate rules file
generate_rules_file() {
    local file="$1"
    local ipv6="$2"
    local ip_suffix=""
    local cmd="iptables-save"
    
    if [ "$ipv6" = "true" ]; then
        ip_suffix="-v6"
        cmd="ip6tables-save"
    else
        ip_suffix="-v4"
    fi
    
    # Get current rules
    $cmd > "$file"
    
    # Parse chains to use
    local chains=""
    if [ "$BLOCK_CHAINS" = "ALL" ]; then
        chains="INPUT OUTPUT FORWARD"
    else
        chains=$(echo "$BLOCK_CHAINS" | tr ',' ' ')
    fi
    
    # Add our rules to each chain
    for chain in $chains; do
        # First whitelist rules
        echo "-A $chain -m set --match-set whitelistIP$ip_suffix src -j ACCEPT" >> "$file"
        echo "-A $chain -m set --match-set whitelistRange$ip_suffix src -j ACCEPT" >> "$file"
        
        # Then blocklist rules
        echo "-A $chain -m set --match-set blocklistIP$ip_suffix src -j DROP" >> "$file"
        echo "-A $chain -m set --match-set blocklistRange$ip_suffix src -j DROP" >> "$file"
        
        # For OUTPUT and FORWARD, also check destination
        if [ "$chain" = "OUTPUT" ] || [ "$chain" = "FORWARD" ]; then
            echo "-A $chain -m set --match-set whitelistIP$ip_suffix dst -j ACCEPT" >> "$file"
            echo "-A $chain -m set --match-set whitelistRange$ip_suffix dst -j ACCEPT" >> "$file"
            echo "-A $chain -m set --match-set blocklistIP$ip_suffix dst -j DROP" >> "$file"
            echo "-A $chain -m set --match-set blocklistRange$ip_suffix dst -j DROP" >> "$file"
        fi
    done
    
    # Ensure COMMIT is at the end
    echo "COMMIT" >> "$file"
}

# Generate rules files
generate_rules_file "$IPTABLES_DIR/rules.v4" "false"
generate_rules_file "$IPTABLES_DIR/rules.v6" "true"

# Apply rules
print_info "Applying iptables rules..."
iptables-restore < "$IPTABLES_DIR/rules.v4"
ip6tables-restore < "$IPTABLES_DIR/rules.v6"

# Save rules for persistence
save_rules_for_persistence

# Enable persistence services
enable_persistence_services

# Enable and start the timer
print_info "Enabling and starting DNSniper agent timer..."
systemctl enable dnsniper-agent.timer
systemctl start dnsniper-agent.timer

# Create a symlink for the installer
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ln -sf "$SCRIPT_DIR/installer.sh" "$BIN_DIR/dnsniper-installer"

print_success "DNSniper v2.0 has been installed successfully!"
print_info "You can now run 'dnsniper' to start the interactive menu."
print_info "The agent will run automatically every $UPDATE_INTERVAL."
print_info "First run will start in approximately 1 minute."