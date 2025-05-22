#!/bin/bash
# DNSniper Installation Script

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
            if iptables -L DNSniper >/dev/null 2>&1; then
                iptables -D INPUT -j DNSniper 2>/dev/null
                iptables -D OUTPUT -j DNSniper 2>/dev/null
                iptables -F DNSniper 2>/dev/null
                iptables -X DNSniper 2>/dev/null
            fi
            if ip6tables -L DNSniper6 >/dev/null 2>&1; then
                ip6tables -D INPUT -j DNSniper6 2>/dev/null
                ip6tables -D OUTPUT -j DNSniper6 2>/dev/null
                ip6tables -F DNSniper6 2>/dev/null
                ip6tables -X DNSniper6 2>/dev/null
            fi
            # Save iptables rules
            if [ "$OS" = "debian" ]; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
                systemctl disable netfilter-persistent 2>/dev/null
                systemctl stop netfilter-persistent 2>/dev/null
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

# Install iptables persistence
if [ "$OS" = "debian" ]; then
    if ! dpkg -l | grep -q iptables-persistent; then
        print_info "Installing iptables-persistent..."
        # Pre-configure iptables-persistent to not ask questions
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        install_package "iptables-persistent"
    fi
elif [ "$OS" = "redhat" ]; then
    if ! systemctl list-unit-files | grep -q iptables.service; then
        print_info "Installing iptables-services..."
        install_package "iptables-services"
    fi
fi

# 6. Get the latest release version
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

# 12. Setup iptables
print_info "Setting up iptables rules..."
# Ensure DNSniper chains exist
iptables -N DNSniper 2>/dev/null || iptables -F DNSniper
iptables -I INPUT -j DNSniper
iptables -I OUTPUT -j DNSniper
iptables -I FORWARD -j DNSniper

# Do the same for IPv6
ip6tables -N DNSniper6 2>/dev/null || ip6tables -F DNSniper6
ip6tables -I INPUT -j DNSniper6
ip6tables -I OUTPUT -j DNSniper6
ip6tables -I FORWARD -j DNSniper6

# Save iptables rules
if [ "$OS" = "debian" ]; then
    print_info "Saving iptables rules..."
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    # Enable and start netfilter-persistent
    print_info "Enabling netfilter-persistent service..."
    systemctl enable netfilter-persistent
    systemctl start netfilter-persistent
else
    print_info "Saving iptables rules..."
    service iptables save
    service ip6tables save
fi

# 13. Start and enable systemd services
print_info "Starting and enabling DNSniper agent service..."
systemctl daemon-reload
systemctl enable dnsniper-agent.timer
systemctl start dnsniper-agent.timer

# Start the agent service in the background
print_info "Starting DNSniper agent in background..."
systemctl start dnsniper-agent.service &

# 14. Clean up temporary files
rm -rf "${TEMP_DIR}"

# Final message
print_success "╔════════════════════════════════════════╗"
print_success "║     DNSniper Installation Complete     ║"
print_success "╚════════════════════════════════════════╝"
print_success "Version ${LATEST_VERSION} has been installed"
print_success "The agent will run every $FRIENDLY_INTERVAL"
print_info "Run 'dnsniper' to start the interactive menu"
print_info "You can check service status with 'systemctl status dnsniper-agent.service'"
print_info "You can check timer status with 'systemctl status dnsniper-agent.timer'"