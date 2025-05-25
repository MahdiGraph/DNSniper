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

# Function to build the binaries
build_binaries() {
    print_info "Building DNSniper binaries..."
    
    # Determine script location
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    
    # Go one level up as required
    cd ..
    
    # Create bin directory if it doesn't exist
    mkdir -p "bin"
    
    # Build dnsniper
    print_info "Building dnsniper..."
    go build -o "bin/dnsniper" "./cmd/dnsniper"
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper"
        exit 1
    fi
    
    # Build dnsniper-agent
    print_info "Building dnsniper-agent..."
    go build -o "bin/dnsniper-agent" "./cmd/dnsniper-agent"
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper-agent"
        exit 1
    fi
    
    print_success "Binaries built successfully in bin/"
    exit 0
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
elif [ "$1" = "uninstall" ]; then
    uninstall_dnsniper
fi

# Detect OS
detect_os

# Check for existing installation and configuration
CONFIG_EXISTS="false"
if [ -f "$CONFIG_FILE" ]; then
    CONFIG_EXISTS="true"
fi

# Set default values
BLOCK_CHAINS="ALL"
UPDATE_INTERVAL="3h"

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
            
            # Stop and disable any existing service
            systemctl stop dnsniper-agent.service 2>/dev/null
            systemctl disable dnsniper-agent.service 2>/dev/null
            systemctl stop dnsniper-agent.timer 2>/dev/null
            systemctl disable dnsniper-agent.timer 2>/dev/null
            
            # Remove old files
            rm -f "$BIN_DIR/dnsniper" "$BIN_DIR/dnsniper-agent"
            rm -f "${SYSTEMD_DIR}/dnsniper-agent.service"
            rm -f "${SYSTEMD_DIR}/dnsniper-agent.timer"
            rm -rf "$INSTALL_DIR"
            rm -rf "$LOG_DIR"
            
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

# Install dependencies
install_dependencies

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$IPTABLES_DIR"

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

# Get binaries - either from local build or download
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN_PATH="${PROJECT_DIR}/bin"

if [ -f "${BIN_PATH}/dnsniper" ] && [ -f "${BIN_PATH}/dnsniper-agent" ]; then
    print_info "Using locally built binaries..."
    cp "${BIN_PATH}/dnsniper" "$BIN_DIR/"
    cp "${BIN_PATH}/dnsniper-agent" "$BIN_DIR/"
else
    print_error "Binaries not found in ${BIN_PATH}"
    print_info "Please build the binaries first with: ./installer.sh --build"
    exit 1
fi

# Set executable permissions
chmod +x "$BIN_DIR/dnsniper"
chmod +x "$BIN_DIR/dnsniper-agent"

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
ExecStart=$BIN_DIR/dnsniper-agent
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
ln -sf "$SCRIPT_DIR/installer.sh" "$BIN_DIR/dnsniper-installer"

print_success "DNSniper v2.0 has been installed successfully!"
print_info "You can now run 'dnsniper' to start the interactive menu."
print_info "The agent will run automatically every $UPDATE_INTERVAL."
print_info "First run will start in approximately 1 minute."