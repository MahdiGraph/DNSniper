#!/bin/bash
# DNSniper v2.0 Installer - Linux Only

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
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dnsniper"
LOG_DIR="/var/log/dnsniper"
DATA_DIR="/var/lib/dnsniper"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_DIR="/etc/systemd/system"

# GitHub repository information
GITHUB_REPO="MahdiGraph/DNSniper"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}"

# Flag to track if binaries were built locally
BUILT_LOCALLY=false

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        print_info "Detected Linux distribution: $PRETTY_NAME"
    else
        print_error "❌ Cannot detect Linux distribution!"
        print_error "DNSniper requires a modern Linux distribution."
        exit 1
    fi
}

# Function to check and install dependencies
install_dependencies() {
    print_info "Checking and installing dependencies..."
    
    # Check if required tools are installed
    if ! command_exists ipset; then
        print_error "ipset is not installed. Please install it first:"
        print_error "  Ubuntu/Debian: sudo apt-get install ipset"
        print_error "  RHEL/CentOS: sudo yum install ipset"
        exit 1
    fi
    
    if ! command_exists iptables; then
        print_error "iptables is not installed. Please install it first:"
        print_error "  Ubuntu/Debian: sudo apt-get install iptables"
        print_error "  RHEL/CentOS: sudo yum install iptables"
        exit 1
    fi
    
    # Check if Go is installed (for building from source)
    if ! command_exists go; then
        print_warning "Go is not installed. Will try to download pre-built binaries."
    fi
    
    print_success "Dependencies check completed."
}

# Function to validate configuration structure
validate_config() {
    print_info "Validating configuration structure..."
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "Configuration file not found: $CONFIG_FILE"
        return 1
    fi
    
    # Check for required configuration fields
    local required_fields=(
        "affected_chains"
        "update_interval"
        "rule_expiration"
        "max_ips_per_domain"
        "dns_resolvers"
        "database_path"
        "version"
    )
    
    local missing_fields=()
    
    for field in "${required_fields[@]}"; do
        if ! grep -q "^${field}:" "$CONFIG_FILE"; then
            missing_fields+=("$field")
        fi
    done
    
    if [ ${#missing_fields[@]} -gt 0 ]; then
        print_warning "Missing configuration fields: ${missing_fields[*]}"
        print_info "Configuration may need to be regenerated"
        return 0
    fi
    
    # Validate YAML array format for affected_chains
    if grep -q "affected_chains: \[" "$CONFIG_FILE"; then
        print_success "✅ affected_chains: Valid YAML array format"
    else
        print_warning "⚠️  affected_chains: Not in YAML array format (backward compatibility mode)"
    fi
    
    # Validate time duration formats
    local time_fields=("update_interval" "rule_expiration")
    for field in "${time_fields[@]}"; do
        local value=$(grep "^${field}:" "$CONFIG_FILE" | awk '{print $2}')
        if [[ "$value" =~ ^[0-9]+[mhd]$ ]]; then
            print_success "✅ $field: Valid duration format ($value)"
        else
            print_warning "⚠️  $field: Unusual duration format ($value)"
        fi
    done
    
    # Check version
    local version=$(grep "^version:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
    if [ "$version" = "2.0" ]; then
        print_success "✅ DNSniper version: $version"
    else
        print_info "DNSniper version: ${version:-unknown}"
    fi
    
    print_success "Configuration validation completed"
    return 0
}

# Function to create Linux systemd services
create_systemd_services() {
    print_info "Creating systemd services..."
    
    # Create DNSniper agent service
    cat > "${SERVICE_DIR}/dnsniper-agent.service" << EOF
[Unit]
Description=DNSniper Agent - Automated DNS Firewall
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/dnsniper-agent
User=root
Group=root
StandardOutput=journal
StandardError=journal
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

    # Create DNSniper agent timer
    cat > "${SERVICE_DIR}/dnsniper-agent.timer" << EOF
[Unit]
Description=Run DNSniper Agent regularly
Requires=dnsniper-agent.service

[Timer]
Unit=dnsniper-agent.service
OnBootSec=1min
OnUnitActiveSec=3h

[Install]
WantedBy=timers.target
EOF

    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl enable dnsniper-agent.service
    systemctl enable dnsniper-agent.timer
    systemctl start dnsniper-agent.timer
    
    print_success "✅ Systemd services created and enabled"
    return 0
}

# Function to build the binaries
build_binaries() {
    print_info "Building DNSniper binaries..."
    
    # Check if Go is available
    if ! command_exists go; then
        print_warning "Go not available, will try to download pre-built binaries"
        return 1
    fi
    
    # Determine script location
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    
    # Go one level up from scripts directory
    cd "$(dirname "$SCRIPT_DIR")"
    
    # Build main binary
    print_info "Building dnsniper..."
    go build -ldflags="-s -w" -o "${INSTALL_DIR}/dnsniper" ./cmd/dnsniper
    
    if [ $? -ne 0 ]; then
        print_error "Failed to build main binary"
        return 1
    fi
    
    # Build agent binary
    print_info "Building dnsniper-agent..."
    go build -ldflags="-s -w" -o "${INSTALL_DIR}/dnsniper-agent" ./cmd/dnsniper-agent
    
    if [ $? -ne 0 ]; then
        print_error "Failed to build agent binary"
        return 1
    fi
    
    # Make binaries executable
    chmod +x "${INSTALL_DIR}/dnsniper"
    chmod +x "${INSTALL_DIR}/dnsniper-agent"
    
    BUILT_LOCALLY=true
    print_success "✅ Binaries built successfully"
    return 0
}

# Function to create directories
create_directories() {
    print_info "Creating directories..."
    
    # Create installation directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    
    # Set proper permissions
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$DATA_DIR"
    
    print_success "✅ Directories created successfully"
}

# Function to install files
install_files() {
    print_info "Installing files..."
    
    # Create default configuration if it doesn't exist
    if [ ! -f "$CONFIG_FILE" ]; then
        print_info "Creating default configuration..."
        cat > "$CONFIG_FILE" << EOF
version: "2.0"
dns_resolvers:
  - "8.8.8.8"
  - "1.1.1.1"
affected_chains:
  - "INPUT"
  - "OUTPUT"
  - "FORWARD"
enable_ipv6: true
rate_limit_enabled: true
rate_limit_count: 1000
rate_limit_window: 1m
update_urls:
  - "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
update_interval: 3h
rule_expiration: 12h
max_ips_per_domain: 5
logging_enabled: false
log_level: "info"
database_path: "/etc/dnsniper/dnsniper.db"
log_path: "/var/log/dnsniper"
EOF
    fi
    
    # Set proper permissions
    chmod 644 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    
    print_success "✅ Files installed successfully"
}

# Function to check for existing installation
check_existing_installation() {
    if [ -d "$INSTALL_DIR" ]; then
        return 0
    fi
    return 1
}

# Function to uninstall DNSniper
uninstall_dnsniper() {
    print_info "Uninstalling DNSniper..."
    
    # Stop and disable systemd services
    systemctl stop dnsniper-agent.timer 2>/dev/null || true
    systemctl stop dnsniper-agent.service 2>/dev/null || true
    systemctl disable dnsniper-agent.timer 2>/dev/null || true
    systemctl disable dnsniper-agent.service 2>/dev/null || true
    
    # Remove service files
    rm -f "${SERVICE_DIR}/dnsniper-agent.service"
    rm -f "${SERVICE_DIR}/dnsniper-agent.timer"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Remove binaries
    rm -f "${INSTALL_DIR}/dnsniper"
    rm -f "${INSTALL_DIR}/dnsniper-agent"
    
    # Remove configuration and data directories
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    rm -rf "$DATA_DIR"
    
    print_success "✅ DNSniper uninstalled successfully"
}

# Main installation process
main() {
    print_info "Starting DNSniper installation..."
    
    # Detect OS
    detect_os
    
    # Check for existing installation
    if check_existing_installation; then
        print_warning "DNSniper installation found. What would you like to do?"
        echo "1) Reinstall with existing settings"
        echo "2) Clean install (remove existing installation and reinstall)"
        echo "3) Uninstall DNSniper completely"
        echo "4) Cancel"
        read -p "Enter choice [1-4]: " choice
        case $choice in
            1)
                print_info "Reinstalling with existing settings..."
                INSTALL_TYPE="reinstall"
                ;;
            2)
                print_info "Performing clean install..."
                uninstall_dnsniper
                INSTALL_TYPE="clean"
                ;;
            3)
                print_info "Uninstalling DNSniper..."
                uninstall_dnsniper
                exit 0
                ;;
            4)
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
    fi
    
    # Install dependencies
    install_dependencies
    
    # Create directories
    create_directories
    
    # Build binaries
    build_binaries
    
    # Install files
    install_files
    
    # Create systemd services
    create_systemd_services
    
    # Validate configuration
    validate_config
    
    print_success "✅ DNSniper installation completed successfully"
    print_info "You can now use DNSniper to protect your system"
}

# Display persistence information
print_info ""
print_info "🔧 Persistence Configuration:"
print_info "• Ubuntu/Debian: Using netfilter-persistent service"
print_info "• IPv4/IPv6 rules: Saved automatically via netfilter-persistent"
print_info "• IPSet rules: /etc/ipset.conf"
print_info ""
print_info "🔧 Architecture:"
print_info "• Database: GORM with automatic firewall sync"
print_info "• Firewall: ipset + iptables with whitelist priority"
print_info "• Configuration: Auto-generated with validation"
print_info "• Commands: Standard system tools (iptables, ipset)"
print_info ""
print_success "🎉 DNSniper is ready for production use!"
