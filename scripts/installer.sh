#!/bin/bash
# DNSniper v2.0 Enhanced Installer - Linux Only
# Supports automatic download from GitHub releases or local build

set -e  # Exit on any error

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Functions for colored output
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_header() { echo -e "${CYAN}${BOLD}$1${NC}"; }

# Installation paths
INSTALL_DIR="/etc/dnsniper"
CONFIG_DIR="/etc/dnsniper"
LOG_DIR="/var/log/dnsniper"
DATA_DIR="/var/lib/dnsniper"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
SERVICE_DIR="/etc/systemd/system"

# GitHub repository information
GITHUB_REPO="MahdiGraph/DNSniper"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
GITHUB_RELEASES="https://github.com/${GITHUB_REPO}/releases"

# Installation flags and variables
BUILD_FROM_SOURCE=false
INSTALL_TYPE=""
ARCHITECTURE=""
TEMP_DIR="/tmp/dnsniper-install"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD_FROM_SOURCE=true
            shift
            ;;
        --help|-h)
            echo "DNSniper v2.0 Installer"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --build    Build from source instead of downloading release"
            echo "  --help     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                # Install from latest GitHub release"
            echo "  $0 --build       # Build and install from source"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS and check compatibility
detect_os() {
    print_header "🔍 Detecting Operating System"
    
    if [ ! -f /etc/os-release ]; then
        print_error "Cannot detect Linux distribution!"
        print_error "DNSniper requires a modern Linux distribution with systemd."
        exit 1
    fi
    
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
    
    print_success "Detected: $PRETTY_NAME"
    
    # Check if systemd is available
    if ! command_exists systemctl; then
        print_error "systemd is required but not found!"
        print_error "DNSniper requires a systemd-based Linux distribution."
        exit 1
    fi
    
    print_success "systemd detected and available"
    
    # Check kernel version for iptables/netfilter support
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    print_info "Kernel version: $(uname -r)"
    
    if [[ $(echo "$KERNEL_VERSION >= 3.10" | bc -l 2>/dev/null || echo "1") == "1" ]]; then
        print_success "Kernel version is compatible"
    else
        print_warning "Kernel version might be too old for optimal performance"
    fi
}

# Function to detect system architecture
detect_architecture() {
    print_header "🏗️  Detecting System Architecture"
    
    local arch=$(uname -m)
    case $arch in
        x86_64)
            ARCHITECTURE="amd64"
            ;;
        aarch64|arm64)
            ARCHITECTURE="arm64"
            ;;
        armv7l|armv6l)
            ARCHITECTURE="arm"
            ;;
        i386|i686)
            ARCHITECTURE="386"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
            print_error "Supported architectures: x86_64, aarch64, armv7l, i386"
            exit 1
            ;;
    esac
    
    print_success "Architecture: $arch -> $ARCHITECTURE"
}

# Function to install system dependencies
install_dependencies() {
    print_header "📦 Installing System Dependencies"
    
    # Detect package manager and install dependencies
    if command_exists apt-get; then
        print_info "Using apt package manager (Debian/Ubuntu)"
        
        # Update package list
        print_info "Updating package list..."
        apt-get update -qq
        
        # Install required packages
        local packages=(
            "iptables"
            "ipset" 
            "iptables-persistent"
            "netfilter-persistent"
            "curl"
            "wget"
            "unzip"
            "systemd"
        )
        
        for package in "${packages[@]}"; do
            if ! dpkg -l | grep -q "^ii  $package "; then
                print_info "Installing $package..."
                apt-get install -y "$package" || {
                    print_error "Failed to install $package"
                    exit 1
                }
            else
                print_success "$package is already installed"
            fi
        done
        
    elif command_exists yum; then
        print_info "Using yum package manager (RHEL/CentOS)"
        
        local packages=(
            "iptables"
            "ipset"
            "iptables-services"
            "curl"
            "wget"
            "unzip"
            "systemd"
        )
        
        for package in "${packages[@]}"; do
            if ! rpm -q "$package" >/dev/null 2>&1; then
                print_info "Installing $package..."
                yum install -y "$package" || {
                    print_error "Failed to install $package"
                    exit 1
                }
            else
                print_success "$package is already installed"
            fi
        done
        
    elif command_exists dnf; then
        print_info "Using dnf package manager (Fedora)"
        
        local packages=(
            "iptables"
            "ipset"
            "iptables-services"
            "curl"
            "wget"
            "unzip"
            "systemd"
        )
        
        for package in "${packages[@]}"; do
            if ! rpm -q "$package" >/dev/null 2>&1; then
                print_info "Installing $package..."
                dnf install -y "$package" || {
                    print_error "Failed to install $package"
                    exit 1
                }
            else
                print_success "$package is already installed"
            fi
        done
        
    else
        print_error "Unsupported package manager!"
        print_error "Please install the following packages manually:"
        print_error "  - iptables, ipset, curl, wget, unzip, systemd"
        print_error "  - iptables-persistent (Debian/Ubuntu) or iptables-services (RHEL/CentOS)"
        exit 1
    fi
    
    # Verify critical commands are available
    local critical_commands=("iptables" "ipset" "systemctl" "curl")
    for cmd in "${critical_commands[@]}"; do
        if ! command_exists "$cmd"; then
            print_error "Critical command '$cmd' not found after installation!"
            exit 1
        fi
    done
    
    print_success "All dependencies installed successfully"
}

# Function to check for existing installation
check_existing_installation() {
    print_header "🔍 Checking for Existing Installation"
    
    local has_binaries=false
    local has_config=false
    local has_services=false
    
    # Check for binaries
    if [ -f "${INSTALL_DIR}/dnsniper" ] || [ -f "${INSTALL_DIR}/dnsniper-agent" ]; then
        has_binaries=true
        print_info "Found existing binaries"
    fi
    
    # Check for configuration
    if [ -f "$CONFIG_FILE" ]; then
        has_config=true
        print_info "Found existing configuration"
    fi
    
    # Check for services
    if [ -f "${SERVICE_DIR}/dnsniper-agent.service" ]; then
        has_services=true
        print_info "Found existing systemd services"
    fi
    
    if [ "$has_binaries" = true ] || [ "$has_config" = true ] || [ "$has_services" = true ]; then
        print_warning "Existing DNSniper installation detected!"
        echo ""
        echo "What would you like to do?"
        echo "1) Update installation (keep existing database and configuration)"
        echo "2) Clean install (remove everything and start fresh)"
        echo "3) Uninstall DNSniper completely"
        echo "4) Cancel installation"
        echo ""
        
        while true; do
            read -p "Enter your choice [1-4]: " choice
            case $choice in
                1)
                    INSTALL_TYPE="update"
                    print_info "Selected: Update installation"
                    break
                    ;;
                2)
                    INSTALL_TYPE="clean"
                    print_info "Selected: Clean installation"
                    break
                    ;;
                3)
                    uninstall_dnsniper
                    exit 0
                    ;;
                4)
                    print_info "Installation cancelled by user"
                    exit 0
                    ;;
                *)
                    print_error "Invalid choice. Please enter 1, 2, 3, or 4."
                    ;;
            esac
        done
    else
        INSTALL_TYPE="clean"
        print_success "No existing installation found"
    fi
}

# Function to uninstall DNSniper
uninstall_dnsniper() {
    print_header "🗑️  Uninstalling DNSniper"
    
    # Check if dnsniper binary exists and has uninstall function
    if [ -f "${INSTALL_DIR}/dnsniper" ]; then
        print_info "Using built-in uninstaller..."
        "${INSTALL_DIR}/dnsniper" --uninstall || {
            print_warning "Built-in uninstaller failed, proceeding with manual cleanup"
        }
    fi
    
    # Manual cleanup
    print_info "Performing manual cleanup..."
    
    # Stop and disable services
    systemctl stop dnsniper-agent.timer 2>/dev/null || true
    systemctl stop dnsniper-agent.service 2>/dev/null || true
    systemctl disable dnsniper-agent.timer 2>/dev/null || true
    systemctl disable dnsniper-agent.service 2>/dev/null || true
    
    # Remove service files
    rm -f "${SERVICE_DIR}/dnsniper-agent.service"
    rm -f "${SERVICE_DIR}/dnsniper-agent.timer"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Remove binaries and symlinks
    rm -f "${INSTALL_DIR}/dnsniper"
    rm -f "${INSTALL_DIR}/dnsniper-agent"
    rm -f "/usr/bin/dnsniper"                         # symlink
    rm -f "/usr/local/bin/dnsniper"                   # legacy path (backward compatibility)
    rm -f "/usr/local/bin/dnsniper-agent"             # legacy path (backward compatibility)
    
    # Remove directories (only if clean install)
    if [ "$INSTALL_TYPE" = "clean" ]; then
        print_info "Removing configuration and data directories..."
        rm -rf "$CONFIG_DIR"
        rm -rf "$LOG_DIR"
        rm -rf "$DATA_DIR"
        
        # Note: We intentionally do NOT remove the ipset service or /etc/ipset.conf
        # as these may be used by other applications or the system itself
        print_info "Note: ipset service and /etc/ipset.conf are preserved for system compatibility"
    fi
    
    print_success "DNSniper uninstalled successfully"
}

# Function to get latest release version from GitHub
get_latest_release() {
    print_info "Fetching latest release information from GitHub..."
    
    local latest_url="${GITHUB_API}/releases/latest"
    local release_info
    
    if command_exists curl; then
        release_info=$(curl -s "$latest_url") || {
            print_error "Failed to fetch release information"
            return 1
        }
    elif command_exists wget; then
        release_info=$(wget -qO- "$latest_url") || {
            print_error "Failed to fetch release information"
            return 1
        }
    else
        print_error "Neither curl nor wget is available"
        return 1
    fi
    
    # Extract tag name (version)
    local version=$(echo "$release_info" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
    
    if [ -z "$version" ]; then
        print_error "Could not determine latest version"
        return 1
    fi
    
    echo "$version"
}

# Function to download and verify release
download_release() {
    local version="$1"
    print_header "📥 Downloading DNSniper Release"
    
    print_info "Version: $version"
    print_info "Architecture: $ARCHITECTURE"
    
    # Create temporary directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Construct download URLs
    local zip_file="dnsniper-linux-${ARCHITECTURE}.zip"
    local sha_file="${zip_file}.sha256"
    local base_url="${GITHUB_RELEASES}/download/${version}"
    local zip_url="${base_url}/${zip_file}"
    local sha_url="${base_url}/${sha_file}"
    
    print_info "Downloading $zip_file..."
    
    # Download files
    if command_exists curl; then
        curl -L -o "$zip_file" "$zip_url" || {
            print_error "Failed to download release archive"
            return 1
        }
        curl -L -o "$sha_file" "$sha_url" || {
            print_error "Failed to download SHA256 checksum"
            return 1
        }
    elif command_exists wget; then
        wget -O "$zip_file" "$zip_url" || {
            print_error "Failed to download release archive"
            return 1
        }
        wget -O "$sha_file" "$sha_url" || {
            print_error "Failed to download SHA256 checksum"
            return 1
        }
    else
        print_error "Neither curl nor wget is available"
        return 1
    fi
    
    print_success "Download completed"
    
    # Verify SHA256 checksum
    print_info "Verifying SHA256 checksum..."
    
    if command_exists sha256sum; then
        if sha256sum -c "$sha_file"; then
            print_success "SHA256 verification passed"
        else
            print_error "SHA256 verification failed!"
            print_error "The downloaded file may be corrupted or tampered with."
            return 1
        fi
    else
        print_warning "sha256sum not available, skipping verification"
    fi
    
    # Extract archive
    print_info "Extracting archive..."
    unzip -q "$zip_file" || {
        print_error "Failed to extract archive"
        return 1
    }
    
    # Verify extracted files exist
    local main_binary="dnsniper-linux-${ARCHITECTURE}"
    local agent_binary="dnsniper-agent-linux-${ARCHITECTURE}"
    
    if [ ! -f "$main_binary" ] || [ ! -f "$agent_binary" ]; then
        print_error "Expected binaries not found in archive"
        return 1
    fi
    
    # Rename binaries to standard names
    mv "$main_binary" "dnsniper"
    mv "$agent_binary" "dnsniper-agent"
    
    print_success "Release extracted and prepared"
}

# Function to build from source
build_from_source() {
    print_header "🔨 Building DNSniper from Source"
    
    # Check if Go is available
    if ! command_exists go; then
        print_error "Go is not installed!"
        print_error "Please install Go 1.21+ or use release download (remove --build flag)"
        exit 1
    fi
    
    # Check Go version
    local go_version=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
    print_info "Go version: $go_version"
    
    # Determine source directory (should be one level up from scripts)
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local source_dir="$(dirname "$script_dir")"
    
    if [ ! -f "$source_dir/go.mod" ]; then
        print_error "Source code not found!"
        print_error "Make sure you're running this script from the DNSniper project directory"
        exit 1
    fi
    
    print_info "Building from source directory: $source_dir"
    cd "$source_dir"
    
    # Create temporary directory for binaries
    mkdir -p "$TEMP_DIR"
    
    # Build main binary
    print_info "Building dnsniper..."
    go build -ldflags="-s -w" -o "${TEMP_DIR}/dnsniper" ./cmd/dnsniper || {
        print_error "Failed to build main binary"
        exit 1
    }
    
    # Build agent binary
    print_info "Building dnsniper-agent..."
    go build -ldflags="-s -w" -o "${TEMP_DIR}/dnsniper-agent" ./cmd/dnsniper-agent || {
        print_error "Failed to build agent binary"
        exit 1
    }
    
    print_success "Build completed successfully"
    cd "$TEMP_DIR"
}

# Function to create directories
create_directories() {
    print_header "📁 Creating Directories"
    
    local directories=("$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR")
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            print_info "Creating $dir"
            mkdir -p "$dir"
        else
            print_info "Directory $dir already exists"
        fi
    done
    
    # Set proper permissions
    chmod 755 "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    
    print_success "Directories created successfully"
}

# Function to install binaries
install_binaries() {
    print_header "📦 Installing Binaries"
    
    # Stop services if they're running
    systemctl stop dnsniper-agent.timer 2>/dev/null || true
    systemctl stop dnsniper-agent.service 2>/dev/null || true
    
    # Install binaries
    print_info "Installing dnsniper to ${INSTALL_DIR}/dnsniper"
    cp "dnsniper" "${INSTALL_DIR}/dnsniper"
    chmod +x "${INSTALL_DIR}/dnsniper"
    
    print_info "Installing dnsniper-agent to ${INSTALL_DIR}/dnsniper-agent"
    cp "dnsniper-agent" "${INSTALL_DIR}/dnsniper-agent"
    chmod +x "${INSTALL_DIR}/dnsniper-agent"
    
    # Create symlink for easy access
    if [ ! -L "/usr/bin/dnsniper" ]; then
        print_info "Creating symlink /usr/bin/dnsniper"
        ln -sf "${INSTALL_DIR}/dnsniper" "/usr/bin/dnsniper"
    fi
    
    print_success "Binaries installed successfully"
}

# Function to create or update configuration
setup_configuration() {
    print_header "⚙️  Setting up Configuration"
    
    if [ "$INSTALL_TYPE" = "update" ] && [ -f "$CONFIG_FILE" ]; then
        print_info "Keeping existing configuration file"
        print_info "Configuration location: $CONFIG_FILE"
    else
        print_info "Creating default configuration..."
        
        cat > "$CONFIG_FILE" << 'EOF'
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
rate_limit_window: "1m"
update_urls:
  - "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
update_interval: "3h"
rule_expiration: "12h"
max_ips_per_domain: 5
logging_enabled: false
log_level: "info"
database_path: "/etc/dnsniper/dnsniper.db"
log_path: "/var/log/dnsniper"
config_path: "/etc/dnsniper/config.yaml"
EOF
        
        print_success "Default configuration created"
    fi
    
    # Set proper permissions
    chmod 644 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
}

# Function to read update interval from config
get_update_interval() {
    local interval="3h"  # Default value
    
    if [ -f "$CONFIG_FILE" ]; then
        # Try to extract update_interval from config
        local config_interval=$(grep "^update_interval:" "$CONFIG_FILE" | sed 's/update_interval: *//; s/"//g; s/'\''//g' | tr -d ' ')
        
        if [ -n "$config_interval" ]; then
            interval="$config_interval"
            print_info "Using update interval from config: $interval"
        else
            print_info "Using default update interval: $interval"
        fi
    else
        print_info "Config file not found, using default update interval: $interval"
    fi
    
    echo "$interval"
}

# Function to create systemd services
create_systemd_services() {
    print_header "🔧 Creating Systemd Services"
    
    local update_interval=$(get_update_interval)
    
    # Create DNSniper agent service
    print_info "Creating dnsniper-agent.service"
    cat > "${SERVICE_DIR}/dnsniper-agent.service" << EOF
[Unit]
Description=DNSniper Agent - Automated DNS Firewall
Documentation=https://github.com/MahdiGraph/DNSniper
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
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${CONFIG_DIR} ${LOG_DIR} ${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

    # Create DNSniper agent timer
    print_info "Creating dnsniper-agent.timer with interval: $update_interval"
    cat > "${SERVICE_DIR}/dnsniper-agent.timer" << EOF
[Unit]
Description=Run DNSniper Agent regularly
Documentation=https://github.com/MahdiGraph/DNSniper
Requires=dnsniper-agent.service

[Timer]
Unit=dnsniper-agent.service
OnBootSec=1min
OnUnitActiveSec=${update_interval}
Persistent=true

[Install]
WantedBy=timers.target
EOF

    print_success "Systemd services created"
}

# Function to enable persistence services
enable_persistence_services() {
    print_header "🛡️  Enabling Firewall Persistence"
    
    # Enable iptables persistence based on distribution
    if command_exists netfilter-persistent; then
        print_info "Enabling netfilter-persistent service"
        systemctl enable netfilter-persistent
        systemctl start netfilter-persistent
        print_success "netfilter-persistent enabled"
    elif command_exists iptables-save && [ -f /etc/systemd/system/iptables.service ]; then
        print_info "Enabling iptables service"
        systemctl enable iptables
        systemctl start iptables
        print_success "iptables service enabled"
    else
        print_warning "No iptables persistence service found"
        print_info "Rules may not persist across reboots"
    fi
    
    # Check for ipset persistence
    if [ -f /etc/systemd/system/ipset.service ]; then
        print_info "Found existing ipset service"
        
        # Check if the service is already enabled and working
        if systemctl is-enabled ipset >/dev/null 2>&1; then
            print_info "ipset service is already enabled"
            
            # Try to start it if not running
            if ! systemctl is-active ipset >/dev/null 2>&1; then
                print_info "Starting existing ipset service"
                systemctl start ipset 2>/dev/null || {
                    print_warning "Failed to start existing ipset service, will recreate"
                    # Remove the problematic service and recreate
                    systemctl stop ipset 2>/dev/null || true
                    systemctl disable ipset 2>/dev/null || true
                    rm -f /etc/systemd/system/ipset.service
                    systemctl daemon-reload
                    # Fall through to create new service
                }
            fi
            
            # If service is working, we're done
            if systemctl is-active ipset >/dev/null 2>&1; then
                print_success "ipset service is running"
            else
                # Service exists but not working, recreate it
                print_info "Recreating ipset service configuration"
                systemctl stop ipset 2>/dev/null || true
                systemctl disable ipset 2>/dev/null || true
                rm -f /etc/systemd/system/ipset.service
                systemctl daemon-reload
                # Fall through to create new service
            fi
        else
            print_info "Enabling existing ipset service"
            systemctl enable ipset
            systemctl start ipset 2>/dev/null || {
                print_warning "Existing ipset service failed to start, recreating"
                systemctl disable ipset 2>/dev/null || true
                rm -f /etc/systemd/system/ipset.service
                systemctl daemon-reload
                # Fall through to create new service
            }
        fi
    fi
    
    # Create ipset service if it doesn't exist or was removed due to issues
    if [ ! -f /etc/systemd/system/ipset.service ]; then
        print_info "Creating ipset persistence configuration"
        
        # Create empty ipset configuration file if it doesn't exist
        if [ ! -f /etc/ipset.conf ]; then
            print_info "Creating empty ipset configuration file"
            touch /etc/ipset.conf
        fi
        
        # Create basic ipset persistence service
        cat > /etc/systemd/system/ipset.service << 'EOF'
[Unit]
Description=IP Sets
Before=netfilter-persistent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ipset -exist -file /etc/ipset.conf restore
ExecStop=/sbin/ipset -file /etc/ipset.conf save
TimeoutSec=0

[Install]
WantedBy=multi-user.target
EOF
        
        # Reload systemd and enable the service
        systemctl daemon-reload
        systemctl enable ipset
        systemctl start ipset 2>/dev/null || {
            print_warning "ipset service created but failed to start (this is normal on first run)"
        }
        print_success "ipset persistence configured"
    fi
}

# Function to start DNSniper services
start_services() {
    print_header "🚀 Starting DNSniper Services"
    
    # Reload systemd daemon
    print_info "Reloading systemd daemon"
    systemctl daemon-reload
    
    # Enable and start services
    print_info "Enabling dnsniper-agent.service"
    systemctl enable dnsniper-agent.service
    
    print_info "Enabling dnsniper-agent.timer"
    systemctl enable dnsniper-agent.timer
    
    print_info "Starting dnsniper-agent.timer"
    systemctl start dnsniper-agent.timer
    
    # Run agent once in background to initialize
    print_info "Running initial agent execution in background..."
    systemctl start dnsniper-agent.service &
    
    print_success "DNSniper services started successfully"
}

# Function to cleanup temporary files
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        print_info "Cleaning up temporary files"
        rm -rf "$TEMP_DIR"
    fi
}

# Function to display final status
show_final_status() {
    print_header "🎉 Installation Complete!"
    
    echo ""
    print_success "DNSniper v2.0 has been installed successfully!"
    echo ""
    
    print_info "📍 Installation Details:"
    echo "   • Binaries: ${INSTALL_DIR}/dnsniper, ${INSTALL_DIR}/dnsniper-agent"
    echo "   • Configuration: ${CONFIG_FILE}"
    echo "   • Database: ${CONFIG_DIR}/dnsniper.db"
    echo "   • Logs: ${LOG_DIR}/"
    echo "   • Command: dnsniper (available system-wide)"
    echo ""
    
    print_info "🔧 Service Status:"
    echo "   • Agent Service: $(systemctl is-enabled dnsniper-agent.service 2>/dev/null || echo 'unknown')"
    echo "   • Agent Timer: $(systemctl is-active dnsniper-agent.timer 2>/dev/null || echo 'unknown')"
    echo "   • Update Interval: $(get_update_interval)"
    echo ""
    
    print_info "🚀 Quick Start:"
    echo "   • Open menu: dnsniper"
    echo "   • Check status: systemctl status dnsniper-agent.timer"
    echo "   • View logs: journalctl -u dnsniper-agent.service"
    echo "   • Manual run: dnsniper-agent"
    echo ""
    
    print_info "📚 Next Steps:"
    echo "   1. Run 'dnsniper' to open the management interface"
    echo "   2. Configure your whitelist/blocklist as needed"
    echo "   3. The agent will run automatically every $(get_update_interval)"
    echo "   4. Check firewall rules with 'iptables -L' and 'ipset list'"
    echo ""
    
    print_warning "⚠️  Important Notes:"
    echo "   • The agent is running in the background to initialize the system"
    echo "   • You can modify settings later through the dnsniper menu"
    echo "   • Firewall rules will persist across reboots"
    echo "   • Check the documentation for advanced configuration"
    echo ""
    
    print_success "🛡️  Your system is now protected by DNSniper!"
}

# Main installation function
main() {
    # Set trap for cleanup
    trap cleanup EXIT
    
    print_header "🚀 DNSniper v2.0 Enhanced Installer"
    echo ""
    
    # Step 1: System detection and compatibility check
    detect_os
    detect_architecture
    
    # Step 2: Install system dependencies
    install_dependencies
    
    # Step 3: Check for existing installation
    check_existing_installation
    
    # Step 4: Clean install if needed
    if [ "$INSTALL_TYPE" = "clean" ]; then
        uninstall_dnsniper
    fi
    
    # Step 5: Get binaries (download or build)
    if [ "$BUILD_FROM_SOURCE" = true ]; then
        build_from_source
    else
        local version=$(get_latest_release)
        if [ $? -eq 0 ] && [ -n "$version" ]; then
            download_release "$version"
        else
            print_error "Failed to get release information"
            print_info "You can try building from source with --build flag"
            exit 1
        fi
    fi
    
    # Step 6: Install components
    create_directories
    install_binaries
    setup_configuration
    create_systemd_services
    
    # Step 7: Enable system services
    enable_persistence_services
    start_services
    
    # Step 8: Show final status
    show_final_status
}

# Run main function
main "$@"
