#!/bin/bash
# DNSniper Installation Script with IPSet Support (Updated for IPSet-only mode)
# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub repository information
GITHUB_REPO="MahdiGraph/DNSniper"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if ipset is working correctly
check_ipset_functionality() {
    print_info "Verifying ipset functionality..."
    
    # Check if ipset command works
    if ! ipset -v &>/dev/null; then
        return 1
    fi
    
    # Try to create a test set
    if ! ipset create dnsniper-test hash:ip -exist &>/dev/null; then
        return 2
    fi
    
    # Try to add an IP to test set
    if ! ipset add dnsniper-test 198.51.100.1 -exist &>/dev/null; then
        ipset destroy dnsniper-test &>/dev/null
        return 3
    fi
    
    # Try to test if IP was added
    if ! ipset test dnsniper-test 198.51.100.1 &>/dev/null; then
        ipset destroy dnsniper-test &>/dev/null
        return 4
    fi
    
    # Clean up test set
    ipset destroy dnsniper-test &>/dev/null
    return 0
}

# Parse command line arguments
USE_LOCAL_BUILD=false
for arg in "$@"; do
    case $arg in
        --build)
            USE_LOCAL_BUILD=true
            print_info "Using local build mode - will build from source"
            ;;
    esac
done

# 1. Check for root access
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# 2. Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    print_info "Detected Debian/Ubuntu system"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    print_info "Detected RHEL/CentOS system"
else
    print_error "Unsupported OS. DNSniper currently supports Debian/Ubuntu and RHEL/CentOS"
    exit 1
fi

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

# Define paths
INSTALL_DIR="/etc/dnsniper"
LOG_DIR="/var/log/dnsniper"
SERVICE_FILE="/etc/systemd/system/dnsniper-agent.service"
TIMER_FILE="/etc/systemd/system/dnsniper-agent.timer"
TEMP_DIR=$(mktemp -d)

# Determine correct bin directory for symlinks based on OS
if [ "$OS" = "debian" ] || [ "$OS" = "redhat" ]; then
    BIN_DIR="/usr/bin"
else
    BIN_DIR="/usr/local/bin"  # Fallback
fi

# 3. Check for existing installation
if [ -d "$INSTALL_DIR" ] || [ -f "$BIN_DIR/dnsniper" ] || [ -f "$SERVICE_FILE" ]; then
    print_warning "DNSniper installation found. What would you like to do?"
    echo "1) Reinstall with existing settings"
    echo "2) Clean install (remove existing installation and reinstall)"
    echo "3) Uninstall DNSniper"
    echo "4) Cancel"
    read -p "Enter choice [1-4]: " choice
    case $choice in
        1)
            print_info "Reinstalling with existing settings..."
            REINSTALL=true
            # If reinstalling, get the current block rule type
            if [ -f "$INSTALL_DIR/settings.db" ]; then
                print_info "Trying to determine existing block rule type..."
                # We need sqlite3 to read the database
                if command_exists sqlite3; then
                    BLOCK_RULE_TYPE=$(sqlite3 "$INSTALL_DIR/settings.db" "SELECT value FROM settings WHERE key='block_rule_type' LIMIT 1;" 2>/dev/null)
                    if [ -n "$BLOCK_RULE_TYPE" ]; then
                        print_info "Found existing block rule type: $BLOCK_RULE_TYPE"
                    else
                        BLOCK_RULE_TYPE="both"
                        print_info "No existing block rule type found, using default: both"
                    fi
                else
                    print_warning "sqlite3 is not available, cannot read existing settings"
                    BLOCK_RULE_TYPE="both"
                fi
            else
                BLOCK_RULE_TYPE="both"
                print_info "No existing settings database found, using default block rule type: both"
            fi
            ;;
        2)
            print_info "Performing clean install..."
            systemctl stop dnsniper-agent.service 2>/dev/null
            systemctl disable dnsniper-agent.service 2>/dev/null
            systemctl stop dnsniper-agent.timer 2>/dev/null
            systemctl disable dnsniper-agent.timer 2>/dev/null
            rm -f "$SERVICE_FILE" "$TIMER_FILE"
            rm -f "$BIN_DIR/dnsniper" "$BIN_DIR/dnsniper-agent"
            rm -rf "$INSTALL_DIR"
            rm -rf "$LOG_DIR"
            CLEAN_INSTALL=true
            # Default block rule type for clean install
            BLOCK_RULE_TYPE="both"
            ;;
        3)
            print_info "Uninstalling DNSniper..."
            systemctl stop dnsniper-agent.service 2>/dev/null
            systemctl disable dnsniper-agent.service 2>/dev/null
            systemctl stop dnsniper-agent.timer 2>/dev/null
            systemctl disable dnsniper-agent.timer 2>/dev/null
            rm -f "$SERVICE_FILE" "$TIMER_FILE"
            rm -f "$BIN_DIR/dnsniper" "$BIN_DIR/dnsniper-agent"
            rm -rf "$INSTALL_DIR"
            # Optionally, ask if logs should be kept
            read -p "Would you like to keep log files? (y/n): " keep_logs
            if [[ "$keep_logs" =~ ^[Nn]$ ]]; then
                rm -rf "$LOG_DIR"
                print_info "Log files removed"
            else
                print_info "Log files kept at $LOG_DIR"
            fi
            # Clean up iptables rules
            print_info "Cleaning up iptables rules..."
            # First remove any traditional direct DROP rules that might exist (legacy cleanup)
            print_info "Removing legacy direct DROP rules..."
            iptables-save | grep -v -- "-A DNSniper .* -j DROP" | iptables-restore
            ip6tables-save | grep -v -- "-A DNSniper6 .* -j DROP" | ip6tables-restore
            # Remove ipset rules from iptables
            print_info "Removing ipset rules from iptables..."
            iptables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null
            iptables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null
            iptables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null
            iptables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null
            iptables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null
            iptables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null
            iptables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null
            iptables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null
            # Same for IPv6
            ip6tables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null
            ip6tables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null
            ip6tables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null
            ip6tables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null
            ip6tables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null
            ip6tables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null
            ip6tables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null
            ip6tables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null
            # Remove chain references
            if iptables -L DNSniper >/dev/null 2>&1; then
                iptables -D INPUT -j DNSniper 2>/dev/null
                iptables -D OUTPUT -j DNSniper 2>/dev/null
                iptables -D FORWARD -j DNSniper 2>/dev/null
                iptables -F DNSniper 2>/dev/null
                iptables -X DNSniper 2>/dev/null
            fi
            if ip6tables -L DNSniper6 >/dev/null 2>&1; then
                ip6tables -D INPUT -j DNSniper6 2>/dev/null
                ip6tables -D OUTPUT -j DNSniper6 2>/dev/null
                ip6tables -D FORWARD -j DNSniper6 2>/dev/null
                ip6tables -F DNSniper6 2>/dev/null
                ip6tables -X DNSniper6 2>/dev/null
            fi
            # Clean up ipset rules
            print_info "Destroying ipset sets..."
            ipset destroy dnsniper-whitelist 2>/dev/null
            ipset destroy dnsniper-blocklist 2>/dev/null
            ipset destroy dnsniper-range-whitelist 2>/dev/null
            ipset destroy dnsniper-range-blocklist 2>/dev/null
            # Delete ipset configuration file
            rm -f /etc/ipset.conf
            # Save iptables rules
            if [ "$OS" = "debian" ]; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
                systemctl restart netfilter-persistent 2>/dev/null
            else
                service iptables save 2>/dev/null
                service ip6tables save 2>/dev/null
            fi
            print_success "DNSniper has been uninstalled."
            exit 0
            ;;
        4)
            print_info "Operation cancelled."
            exit 0
            ;;
        *)
            print_error "Invalid choice. Exiting."
            exit 1
            ;;
    esac
else
    # 4. Confirm installation for fresh installs
    print_info "No existing installation found."
    read -p "Are you sure you want to install DNSniper? (y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled."
        exit 0
    fi
    # Set default block rule type for new installs
    BLOCK_RULE_TYPE="both"
fi

# 5. Check for required dependencies
print_info "Checking required dependencies..."
# Function to install package(s)
install_package() {
    local pkg_list="$1"
    if [ "$OS" = "debian" ]; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg_list
    elif [ "$OS" = "redhat" ]; then
        if command_exists dnf; then
            dnf install -y $pkg_list
        else
            yum install -y $pkg_list
        fi
    fi
}

# Check for curl
if ! command_exists curl; then
    print_info "Installing curl..."
    install_package "curl"
fi

# Check for jq (needed for parsing JSON)
if ! command_exists jq; then
    print_info "Installing jq..."
    install_package "jq"
fi

# Check for unzip
if ! command_exists unzip; then
    print_info "Installing unzip..."
    install_package "unzip"
fi

# Check for iptables
if ! command_exists iptables; then
    print_info "Installing iptables..."
    install_package "iptables"
fi

# Check for ipset - REQUIRED now that we only use ipset
if ! command_exists ipset; then
    print_warning "ipset is required for DNSniper. Installing ipset..."
    install_package "ipset"
    # Verify installation was successful
    if ! command_exists ipset; then
        print_error "Failed to install ipset. DNSniper requires ipset to function."
        exit 1
    else
        print_success "ipset installed successfully."
    fi
fi

# Check that ipset is working correctly
ipset_check=$(check_ipset_functionality)
ipset_result=$?
if [ $ipset_result -ne 0 ]; then
    print_error "ipset is installed but not functioning properly (error code: $ipset_result)."
    print_error "Trying additional ipset dependencies..."
    
    # Install additional dependencies based on OS
    if [ "$OS" = "debian" ]; then
        install_package "ipset iptables-persistent kmod"
    elif [ "$OS" = "redhat" ]; then
        install_package "ipset iptables-services kernel-modules"
    fi
    
    # Try loading required modules
    modprobe ip_set &>/dev/null
    modprobe ip_set_hash_ip &>/dev/null
    modprobe ip_set_hash_net &>/dev/null
    
    # Check again after installing dependencies
    ipset_check=$(check_ipset_functionality)
    ipset_result=$?
    if [ $ipset_result -ne 0 ]; then
        print_error "ipset is still not functioning properly. DNSniper requires a working ipset."
        print_error "Please check your system configuration or contact support."
        exit 1
    else
        print_success "ipset is now functioning properly."
    fi
else
    print_success "ipset is functioning properly."
fi

# If not in reinstall mode, ask for block rule type
if [ "$REINSTALL" != "true" ]; then
    print_info "Select block rule type:"
    echo "1) both - Block IPs as both source and destination (default)"
    echo "2) source - Block IPs only as source"
    echo "3) destination - Block IPs only as destination"
    read -p "Enter your choice [1-3]: " block_rule_choice
    case $block_rule_choice in
        2)
            BLOCK_RULE_TYPE="source"
            print_info "Block rule type set to: source"
            ;;
        3)
            BLOCK_RULE_TYPE="destination"
            print_info "Block rule type set to: destination"
            ;;
        *)
            BLOCK_RULE_TYPE="both"
            print_info "Block rule type set to: both (default)"
            ;;
    esac
fi

# If building locally, check for Go
if [ "$USE_LOCAL_BUILD" = true ]; then
    if ! command_exists go; then
        print_info "Installing Go (required for building from source)..."
        if [ "$OS" = "debian" ]; then
            install_package "golang-go"
        elif [ "$OS" = "redhat" ]; then
            install_package "golang"
        fi
    fi
fi

# Install iptables and ipset persistence
if [ "$OS" = "debian" ]; then
    if ! dpkg -l | grep -q iptables-persistent; then
        print_info "Installing iptables-persistent and ipset-persistent..."
        # Pre-configure iptables-persistent to not ask questions
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        install_package "iptables-persistent ipset-persistent"
    fi
elif [ "$OS" = "redhat" ]; then
    if ! systemctl list-unit-files | grep -q iptables.service; then
        print_info "Installing iptables-services and ipset-service..."
        install_package "iptables-services ipset-service"
    fi
fi

# 6. Get binaries - either by building locally or downloading
if [ "$USE_LOCAL_BUILD" = true ]; then
    print_info "Building DNSniper from source..."
    # Check if we're in the correct directory
    if [ ! -d "cmd" ] || [ ! -f "go.mod" ]; then
        # Try parent directory
        cd ..
        if [ ! -d "cmd" ] || [ ! -f "go.mod" ]; then
            print_error "Could not find source code. Make sure you're running this script from the repository directory or its scripts subdirectory."
            exit 1
        fi
    fi
    print_info "Found source code, building..."
    # Clean any existing binaries
    rm -f dnsniper dnsniper-agent 2>/dev/null
    # Build dnsniper
    print_info "Building dnsniper..."
    go build -o dnsniper ./cmd/dnsniper/
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper. Please check for errors."
        exit 1
    fi
    # Build dnsniper-agent
    print_info "Building dnsniper-agent..."
    go build -o dnsniper-agent ./cmd/dnsniper-agent/
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper-agent. Please check for errors."
        exit 1
    fi
    print_success "Successfully built DNSniper binaries"
    # Use the newly built binaries
    MAIN_BINARY="./dnsniper"
    AGENT_BINARY="./dnsniper-agent"
    LATEST_VERSION="local-build"
else
    # Download from GitHub
    print_info "Fetching latest release information..."
    # First attempt with GitHub API
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
            LATEST_VERSION="v1.0.0"  # Fallback version
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
    # 7. Download DNSniper package
    print_info "Downloading DNSniper binary package for ${ARCH}..."
    print_info "Download URL: ${DOWNLOAD_URL}"
    curl -L --fail "${DOWNLOAD_URL}" -o "${TEMP_DIR}/dnsniper.zip"
    if [ $? -ne 0 ]; then
        print_error "Failed to download DNSniper. Please check your internet connection and try again."
        print_error "If the problem persists, visit https://github.com/${GITHUB_REPO}/releases for manual download."
        rm -rf "${TEMP_DIR}"
        exit 1
    fi
    # 8. Download and verify checksum if available
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
                rm -rf "${TEMP_DIR}"
                exit 1
            fi
        else
            print_warning "Could not download checksum file. Skipping integrity check."
        fi
    else
        print_warning "sha256sum not found. Skipping integrity check."
    fi
    # 9. Extract and install executables
    print_info "Installing DNSniper executables..."
    print_info "Extracting DNSniper binaries..."
    unzip -q "${TEMP_DIR}/dnsniper.zip" -d "${TEMP_DIR}"
    if [ $? -ne 0 ]; then
        print_error "Failed to extract DNSniper binaries."
        rm -rf "${TEMP_DIR}"
        exit 1
    fi
    # Look for architecture-specific binary names
    MAIN_BINARY="${TEMP_DIR}/dnsniper-linux-${ARCH}"
    AGENT_BINARY="${TEMP_DIR}/dnsniper-agent-linux-${ARCH}"
    # Check if binaries were found
    if [ ! -f "$MAIN_BINARY" ] || [ ! -f "$AGENT_BINARY" ]; then
        print_error "Could not find expected DNSniper executables in the downloaded package."
        print_error "Files in package:"
        ls -la "${TEMP_DIR}"
        print_error "Installation failed."
        rm -rf "${TEMP_DIR}"
        exit 1
    fi
    print_info "Found executables for ${ARCH} architecture"
fi

# Create required directories
print_info "Creating required directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$INSTALL_DIR/scripts"

# Copy binaries to installation directory
cp "$MAIN_BINARY" "$INSTALL_DIR/dnsniper"
cp "$AGENT_BINARY" "$INSTALL_DIR/dnsniper-agent"

# Set executable permissions
chmod +x "$INSTALL_DIR/dnsniper"
chmod +x "$INSTALL_DIR/dnsniper-agent"

# Create symlinks in bin directory
ln -sf "$INSTALL_DIR/dnsniper" "$BIN_DIR/dnsniper"
ln -sf "$INSTALL_DIR/dnsniper-agent" "$BIN_DIR/dnsniper-agent"

print_success "Executable files installed and symlinks created"

# 10. Ask for agent execution interval
print_info "Setting up agent execution interval..."
echo "How often would you like the DNSniper agent to run?"
echo "1) Every 3 hours (default)"
echo "2) Hourly"
echo "3) Every 6 hours"
echo "4) Daily"
echo "5) Custom interval"
read -p "Select an option [1-5]: " interval_choice
case $interval_choice in
    1)
        INTERVAL="3h"
        FRIENDLY_INTERVAL="3 hours"
        ;;
    2)
        INTERVAL="1h"
        FRIENDLY_INTERVAL="1 hour"
        ;;
    3)
        INTERVAL="6h"
        FRIENDLY_INTERVAL="6 hours"
        ;;
    4)
        INTERVAL="1d"
        FRIENDLY_INTERVAL="1 day"
        ;;
    5)
        read -p "Enter custom interval (format: 1h, 30m, 12h, etc): " INTERVAL
        FRIENDLY_INTERVAL="$INTERVAL"
        ;;
    *)
        print_warning "Invalid choice. Using default (3 hours)"
        INTERVAL="3h"
        FRIENDLY_INTERVAL="3 hours"
        ;;
esac

# 11. Create systemd service and timer
print_info "Creating systemd service for DNSniper agent..."
# Create systemd service
cat > "$SERVICE_FILE" << EOSERVICE
[Unit]
Description=DNSniper Agent Service
After=network.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/dnsniper-agent
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOSERVICE

# Create systemd timer
cat > "$TIMER_FILE" << EOTIMER
[Unit]
Description=Run DNSniper Agent regularly
Requires=dnsniper-agent.service

[Timer]
Unit=dnsniper-agent.service
OnBootSec=1min
OnUnitActiveSec=$INTERVAL

[Install]
WantedBy=timers.target
EOTIMER

print_success "Systemd service and timer created"

# Clean up any existing legacy direct DROP rules from previous versions
print_info "Cleaning up any legacy direct DROP rules from previous versions..."
iptables-save | grep -v -- "-A DNSniper .* -j DROP" | iptables-restore
ip6tables-save | grep -v -- "-A DNSniper6 .* -j DROP" | ip6tables-restore

# First ensure DNSniper chains are properly setup but empty
print_info "Setting up DNSniper chains (empty)..."
if ! iptables -L DNSniper >/dev/null 2>&1; then
    iptables -N DNSniper
fi
iptables -F DNSniper

if ! ip6tables -L DNSniper6 >/dev/null 2>&1; then
    ip6tables -N DNSniper6
fi
ip6tables -F DNSniper6

# Ensure chain references exist
for CHAIN in INPUT OUTPUT FORWARD; do
    # Check for IPv4
    if ! iptables -C $CHAIN -j DNSniper 2>/dev/null; then
        iptables -I $CHAIN -j DNSniper
    fi
    # Check for IPv6
    if ! ip6tables -C $CHAIN -j DNSniper6 2>/dev/null; then
        ip6tables -I $CHAIN -j DNSniper6
    fi
done

# 12. Setup ipset - PRIMARY METHOD FOR BLOCKING
print_info "Setting up ipset sets and rules..."

# Create ipset sets
print_info "Creating ipset sets..."
ipset create dnsniper-whitelist hash:ip hashsize 4096 -exist
ipset create dnsniper-blocklist hash:ip hashsize 4096 -exist
ipset create dnsniper-range-whitelist hash:net hashsize 1024 -exist
ipset create dnsniper-range-blocklist hash:net hashsize 1024 -exist

# Add ipset rules to iptables
print_info "Setting up ipset rules in iptables with block rule type: $BLOCK_RULE_TYPE"

# First remove any existing rules to avoid duplicates
print_info "Removing any existing ipset rules..."
iptables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null
iptables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null
iptables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null
iptables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null

# Same for IPv6
if command_exists ip6tables; then
    ip6tables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null
    ip6tables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null
    ip6tables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null
    ip6tables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null
    ip6tables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null
    ip6tables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null
    ip6tables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null
    ip6tables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null
fi

# Whitelist rules (higher priority) - always apply to both directions
iptables -I INPUT 1 -m set --match-set dnsniper-whitelist src -j ACCEPT
iptables -I OUTPUT 1 -m set --match-set dnsniper-whitelist dst -j ACCEPT
iptables -I INPUT 2 -m set --match-set dnsniper-range-whitelist src -j ACCEPT
iptables -I OUTPUT 2 -m set --match-set dnsniper-range-whitelist dst -j ACCEPT

# Add blocklist rules based on block rule type
if [ "$BLOCK_RULE_TYPE" = "source" ]; then
    print_info "Adding blocklist rules for source-only blocking..."
    iptables -I INPUT 3 -m set --match-set dnsniper-blocklist src -j DROP
    iptables -I INPUT 4 -m set --match-set dnsniper-range-blocklist src -j DROP
elif [ "$BLOCK_RULE_TYPE" = "destination" ]; then
    print_info "Adding blocklist rules for destination-only blocking..."
    iptables -I OUTPUT 3 -m set --match-set dnsniper-blocklist dst -j DROP
    iptables -I OUTPUT 4 -m set --match-set dnsniper-range-blocklist dst -j DROP
else
    print_info "Adding blocklist rules for blocking both source and destination..."
    iptables -I INPUT 3 -m set --match-set dnsniper-blocklist src -j DROP
    iptables -I OUTPUT 3 -m set --match-set dnsniper-blocklist dst -j DROP
    iptables -I INPUT 4 -m set --match-set dnsniper-range-blocklist src -j DROP
    iptables -I OUTPUT 4 -m set --match-set dnsniper-range-blocklist dst -j DROP
fi

# Setup IPv6 rules similarly
if command_exists ip6tables; then
    # Whitelist rules for IPv6
    ip6tables -I INPUT 1 -m set --match-set dnsniper-whitelist src -j ACCEPT
    ip6tables -I OUTPUT 1 -m set --match-set dnsniper-whitelist dst -j ACCEPT
    ip6tables -I INPUT 2 -m set --match-set dnsniper-range-whitelist src -j ACCEPT
    ip6tables -I OUTPUT 2 -m set --match-set dnsniper-range-whitelist dst -j ACCEPT

    # Add IPv6 blocklist rules based on block rule type
    if [ "$BLOCK_RULE_TYPE" = "source" ]; then
        ip6tables -I INPUT 3 -m set --match-set dnsniper-blocklist src -j DROP
        ip6tables -I INPUT 4 -m set --match-set dnsniper-range-blocklist src -j DROP
    elif [ "$BLOCK_RULE_TYPE" = "destination" ]; then
        ip6tables -I OUTPUT 3 -m set --match-set dnsniper-blocklist dst -j DROP
        ip6tables -I OUTPUT 4 -m set --match-set dnsniper-range-blocklist dst -j DROP
    else
        ip6tables -I INPUT 3 -m set --match-set dnsniper-blocklist src -j DROP
        ip6tables -I OUTPUT 3 -m set --match-set dnsniper-blocklist dst -j DROP
        ip6tables -I INPUT 4 -m set --match-set dnsniper-range-blocklist src -j DROP
        ip6tables -I OUTPUT 4 -m set --match-set dnsniper-range-blocklist dst -j DROP
    fi
fi

# 13. Initialize SQLite database for fresh installs and save the block rule type
if [ "$CLEAN_INSTALL" = "true" ] || [ ! -f "$INSTALL_DIR/settings.db" ]; then
    print_info "Initializing settings database..."
    # Check if sqlite3 is available
    if command_exists sqlite3; then
        # Create a temporary SQL file
        SQL_TEMP=$(mktemp)
        cat > "$SQL_TEMP" << EOSQL
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT NULL
);
INSERT OR REPLACE INTO settings (key, value, description) VALUES
('dns_resolver', '8.8.8.8', 'DNS resolver to use for domain resolution'),
('block_rule_type', '$BLOCK_RULE_TYPE', 'Type of blocking rule (source, destination, both)'),
('logging_enabled', 'false', 'Whether to enable logging'),
('rule_expiration', '30d', 'Expiration time for rules (e.g., 30d for 30 days)'),
('max_ips_per_domain', '5', 'Maximum number of IPs to track per domain');
EOSQL
        # Apply the SQL to create the database
        sqlite3 "$INSTALL_DIR/settings.db" < "$SQL_TEMP"
        rm -f "$SQL_TEMP"
        print_success "Settings database initialized with block rule type: $BLOCK_RULE_TYPE"
    else
        print_warning "sqlite3 not available, settings will be initialized when first running dnsniper"
    fi
elif [ "$REINSTALL" = "true" ]; then
    # If reinstalling, update the block rule type in the existing database
    if command_exists sqlite3; then
        print_info "Updating block rule type in existing database to: $BLOCK_RULE_TYPE"
        sqlite3 "$INSTALL_DIR/settings.db" "UPDATE settings SET value = '$BLOCK_RULE_TYPE' WHERE key = 'block_rule_type';"
        print_success "Block rule type updated in database"
    fi
fi

# Save ipset configuration
print_info "Saving ipset configuration..."
ipset save > /etc/ipset.conf

# Save iptables rules and enable persistence services
if [ "$OS" = "debian" ]; then
    print_info "Saving iptables rules..."
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    # Enable and start ipset and netfilter persistence services
    print_info "Enabling and starting persistence services..."
    # Enable and restart netfilter-persistent service
    systemctl enable netfilter-persistent
    systemctl restart netfilter-persistent
    # Enable and start ipset.service if available
    if systemctl list-unit-files | grep -q ipset.service; then
        systemctl enable ipset.service
        systemctl start ipset.service
    fi
else
    print_info "Saving iptables rules..."
    ipset save > /etc/ipset.conf
    service iptables save
    service ip6tables save
    # Enable ipset.service if available
    if systemctl list-unit-files | grep -q ipset.service; then
        systemctl enable ipset.service
        systemctl start ipset.service
    fi
fi

# 14. Start and enable systemd services
print_info "Starting and enabling DNSniper agent service..."
systemctl daemon-reload
systemctl enable dnsniper-agent.timer
systemctl start dnsniper-agent.timer

# Start the agent service in the background
print_info "Starting DNSniper agent in background..."
systemctl start dnsniper-agent.service &

# 15. Clean up temporary files
if [ -d "${TEMP_DIR}" ]; then
    rm -rf "${TEMP_DIR}"
fi

# Clean up local build files if we built them
if [ "$USE_LOCAL_BUILD" = true ]; then
    # Only clean up if we're sure these are the files we built
    if [ -f "./dnsniper" ] && [ -f "./dnsniper-agent" ]; then
        print_info "Cleaning up local build files..."
        rm -f ./dnsniper ./dnsniper-agent
    fi
fi

# Final message
print_success "╔════════════════════════════════════════╗"
print_success "║     DNSniper Installation Complete     ║"
print_success "╚════════════════════════════════════════╝"
print_success "Version ${LATEST_VERSION} has been installed"
print_success "Block rule type: $BLOCK_RULE_TYPE"
print_success "The agent will run every $FRIENDLY_INTERVAL"
print_info "Run 'dnsniper' to start the interactive menu"
print_info "You can check service status with 'systemctl status dnsniper-agent.service'"
print_info "You can check timer status with 'systemctl status dnsniper-agent.timer'"
print_info "IPSet is now the exclusive method used for IP blocking for improved performance"