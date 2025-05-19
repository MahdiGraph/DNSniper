#!/bin/bash

# DNSniper Installation Script

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Define paths
INSTALL_DIR="/etc/dnsniper"
LOG_DIR="/var/log/dnsniper"
SERVICE_FILE="/etc/systemd/system/dnsniper-agent.service"
TIMER_FILE="/etc/systemd/system/dnsniper-agent.timer"

# Determine correct bin directory for symlinks based on OS
if [ "$OS" = "debian" ]; then
    BIN_DIR="/usr/bin"
elif [ "$OS" = "redhat" ]; then
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
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
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

# Install required packages based on OS
if [ "$OS" = "debian" ]; then
    print_info "Updating package lists..."
    apt-get update -qq
    
    # Check for required tools
    PACKAGES_TO_INSTALL=""
    
    if ! command_exists iptables; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL iptables"
    fi
    
    if ! dpkg -l | grep -q iptables-persistent; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL iptables-persistent"
    fi
    
    if [ -n "$PACKAGES_TO_INSTALL" ]; then
        print_info "Installing required packages: $PACKAGES_TO_INSTALL"
        # Pre-configure iptables-persistent to not ask questions
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        apt-get install -y $PACKAGES_TO_INSTALL
    fi
    
elif [ "$OS" = "redhat" ]; then
    # Check for package manager
    if command_exists dnf; then
        PKG_MANAGER="dnf"
    else
        PKG_MANAGER="yum"
    fi
    
    PACKAGES_TO_INSTALL=""
    
    if ! command_exists iptables; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL iptables"
    fi
    
    if ! systemctl list-unit-files | grep -q iptables.service; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL iptables-services"
    fi
    
    if [ -n "$PACKAGES_TO_INSTALL" ]; then
        print_info "Installing required packages: $PACKAGES_TO_INSTALL"
        $PKG_MANAGER install -y $PACKAGES_TO_INSTALL
    fi
fi

# Create required directories
print_info "Creating required directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"

# 6. Copy executables to install directory and create symlinks
print_info "Installing DNSniper executables..."

if [ -f "../dnsniper" ] && [ -f "../dnsniper-agent" ]; then
    # Copy executables to install directory
    cp ../dnsniper "$INSTALL_DIR/dnsniper"
    cp ../dnsniper-agent "$INSTALL_DIR/dnsniper-agent"
    
    # Set executable permissions
    chmod +x "$INSTALL_DIR/dnsniper"
    chmod +x "$INSTALL_DIR/dnsniper-agent"
    
    # Create symlinks in bin directory
    ln -sf "$INSTALL_DIR/dnsniper" "$BIN_DIR/dnsniper"
    ln -sf "$INSTALL_DIR/dnsniper-agent" "$BIN_DIR/dnsniper-agent"
    
    print_success "Executable files installed and symlinks created"
else
    print_error "Could not find DNSniper executable files (../dnsniper and ../dnsniper-agent)"
    exit 1
fi

# 7. Ask for agent execution interval
print_info "Setting up agent execution interval..."
echo "How often would you like the DNSniper agent to run?"
echo "1) Every 3 hours (default)"
echo "2) Hourly"
echo "3) Every 6 hours"
echo "4) Daily"
echo "5) Every 1 minute (for testing)"
echo "6) Custom interval"

read -p "Select an option [1-6]: " interval_choice

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
        INTERVAL="1m"
        FRIENDLY_INTERVAL="1 minute"
        ;;
    6)
        read -p "Enter custom interval (format: 1h, 30m, 12h, etc): " INTERVAL
        FRIENDLY_INTERVAL="$INTERVAL"
        ;;
    *)
        print_warning "Invalid choice. Using default (3 hours)"
        INTERVAL="3h"
        FRIENDLY_INTERVAL="3 hours"
        ;;
esac

# 8. Create systemd service and timer
print_info "Creating systemd service for DNSniper agent..."

# Create systemd service
cat > "$SERVICE_FILE" << EOF
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
cat > "$TIMER_FILE" << EOF
[Unit]
Description=Run DNSniper Agent regularly
Requires=dnsniper-agent.service

[Timer]
Unit=dnsniper-agent.service
OnBootSec=1min
OnUnitActiveSec=$INTERVAL

[Install]
WantedBy=timers.target
EOF

print_success "Systemd service and timer created"

# Setup iptables
print_info "Setting up iptables rules..."

# Ensure DNSniper chains exist
iptables -N DNSniper 2>/dev/null || iptables -F DNSniper
iptables -I INPUT -j DNSniper
iptables -I OUTPUT -j DNSniper

# Do the same for IPv6
ip6tables -N DNSniper6 2>/dev/null || ip6tables -F DNSniper6
ip6tables -I INPUT -j DNSniper6
ip6tables -I OUTPUT -j DNSniper6

# Save iptables rules
if [ "$OS" = "debian" ]; then
    print_info "Saving iptables rules..."
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
else
    print_info "Saving iptables rules..."
    service iptables save
    service ip6tables save
fi

# Start and enable systemd services
print_info "Starting and enabling DNSniper agent service..."
systemctl daemon-reload
systemctl enable dnsniper-agent.timer
systemctl start dnsniper-agent.timer

# Run DNSniper agent once immediately
print_info "Running DNSniper agent for the first time..."
systemctl start dnsniper-agent.service

# Final message
print_success "DNSniper installation completed successfully!"
print_success "The agent will run every $FRIENDLY_INTERVAL"
print_info "Run 'dnsniper' to start the interactive menu"
print_info "You can check service status with 'systemctl status dnsniper-agent.service'"
print_info "You can check timer status with 'systemctl status dnsniper-agent.timer'"