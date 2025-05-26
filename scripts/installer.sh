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

# Flag to track if binaries were built locally
BUILT_LOCALLY=false



# Check for root access
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS - Ubuntu/Debian only
detect_os() {
    if command_exists apt-get; then
        OS="debian"
        PKG_MANAGER="apt-get"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update -q"
        print_info "Detected Ubuntu/Debian system"
    else
        print_error "❌ Unsupported Linux distribution!"
        print_error "DNSniper currently supports Ubuntu/Debian systems only."
        print_error "Required: apt-get package manager"
        exit 1
    fi
}

# Function to check and install dependencies for Ubuntu/Debian
install_dependencies() {
    print_info "Checking and installing dependencies for Ubuntu/Debian..."
    
    # Update package lists
    $PKG_UPDATE
    
    # List of packages to check and install
    local packages=()
    
    # Check basic tools
    if ! command_exists curl; then
        print_info "Installing curl..."
        packages+=("curl")
    fi
    
    if ! command_exists sqlite3; then
        print_info "Installing sqlite3..."
        packages+=("sqlite3")
    fi
    
    # Check firewall tools
    if ! command_exists iptables; then
        print_info "Installing iptables..."
        packages+=("iptables")
    fi
    
    if ! command_exists ipset; then
        print_info "Installing ipset..."
        packages+=("ipset")
    fi
    
    # Install persistence packages for Ubuntu/Debian
    print_info "Setting up firewall persistence packages..."
    
    # Install netfilter-persistent (main package)
    if ! dpkg -l | grep -q netfilter-persistent; then
        print_info "Installing netfilter-persistent..."
        packages+=("netfilter-persistent")
    fi
    
    # Install iptables-persistent 
    if ! dpkg -l | grep -q iptables-persistent; then
        print_info "Installing iptables-persistent..."
        # Pre-configure to avoid interactive prompts
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        packages+=("iptables-persistent")
    fi
    
    # Install ipset-persistent
    if ! dpkg -l | grep -q ipset-persistent; then
        print_info "Installing ipset-persistent..."
        packages+=("ipset-persistent")
    fi
    
    # Install all required packages
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
    
    print_success "Dependencies installed successfully."
}



# Function to enable persistence services for Ubuntu/Debian
enable_persistence_services() {
    print_info "Enabling persistence services for Ubuntu/Debian..."
    
    # Enable netfilter-persistent service (main service)
    print_info "Enabling netfilter-persistent service..."
    systemctl enable netfilter-persistent 2>/dev/null || true
    
    # Enable ipset-persistent service if available
    if systemctl list-unit-files | grep -q ipset-persistent; then
        print_info "Enabling ipset-persistent service..."
        systemctl enable ipset-persistent 2>/dev/null || true
    fi
    
    print_success "✅ Persistence services enabled successfully"
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

# Function to save rules for persistence using netfilter-persistent
save_rules_for_persistence() {
    print_info "Saving firewall rules for persistence..."
    
    # Ubuntu/Debian: Use netfilter-persistent
    if command_exists netfilter-persistent; then
        print_info "Saving iptables rules using netfilter-persistent..."
        netfilter-persistent save
        print_success "✅ Iptables rules saved using netfilter-persistent"
    else
        print_warning "netfilter-persistent not found, using manual method..."
        mkdir -p "/etc/iptables"
        iptables-save > "/etc/iptables/rules.v4"
        ip6tables-save > "/etc/iptables/rules.v6"
        print_success "✅ Iptables rules saved manually to /etc/iptables/"
    fi
    
    # Save ipset configuration
    print_info "Saving ipset configuration..."
    ipset save > "/etc/ipset.conf"
    print_success "✅ IPset rules saved to /etc/ipset.conf"
    
    print_success "🔥 Firewall persistence configuration completed"
}

# Function to build the binaries
build_binaries() {
    print_info "Building DNSniper binaries with enhanced features..."
    
    # Determine script location
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    
    # Go one level up from scripts directory
    cd "$(dirname "$SCRIPT_DIR")"
    
    # Verify Go is available
    if ! command_exists go; then
        print_error "Go is not installed or not in PATH"
        print_info "Please install Go 1.21+ to build DNSniper locally"
        return 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_info "Using Go version: $GO_VERSION"
    
    # Verify go.mod exists
    if [ ! -f "go.mod" ]; then
        print_error "go.mod not found. Please run from the DNSniper project directory"
        return 1
    fi
    
    # Download and verify all dependencies including GORM
    print_info "Downloading and verifying dependencies (including GORM)..."
    go mod download
    if [ $? -ne 0 ]; then
        print_error "Failed to download Go modules"
        return 1
    fi
    
    # Verify GORM dependencies are available
    print_info "Verifying GORM integration dependencies..."
    go mod verify
    if [ $? -ne 0 ]; then
        print_error "Failed to verify Go modules"
        return 1
    fi
    
    # Ensure all modules are up to date
    go mod tidy
    
    # Create installation directory if it doesn't exist
    mkdir -p "$INSTALL_DIR/bin"
    
    # Build dnsniper with all enhanced features
    print_info "Building dnsniper with complete feature set..."
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/dnsniper" "./cmd/dnsniper"
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper"
        return 1
    fi
    
    # Build dnsniper-agent with GORM compatibility
    print_info "Building dnsniper-agent with GORM integration..."
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/dnsniper-agent" "./cmd/dnsniper-agent"
    if [ $? -ne 0 ]; then
        print_error "Failed to build dnsniper-agent"
        return 1
    fi
    
    print_success "Enhanced DNSniper v2.0 binaries built successfully!"
    print_info "Built with: GORM database, enhanced UI, advanced settings, OS-specific paths"
    BUILT_LOCALLY=true
    return 0
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
    
    # Create the bin directory in installation path
    mkdir -p "$INSTALL_DIR/bin"
    
    # Install binaries to installation directory
    cp "$MAIN_BINARY" "$INSTALL_DIR/bin/dnsniper"
    cp "$AGENT_BINARY" "$INSTALL_DIR/bin/dnsniper-agent"
    
    # Set executable permissions
    chmod +x "$INSTALL_DIR/bin/dnsniper"
    chmod +x "$INSTALL_DIR/bin/dnsniper-agent"
    
    print_success "Binaries installed successfully to $INSTALL_DIR/bin/"
    return 0
}

# Function to uninstall DNSniper (fallback method - matches main binary uninstaller)
uninstall_dnsniper() {
    print_info "🗑️  DNSniper Complete Uninstaller (Fallback Method)"
    print_info "=================================================="
    
    print_warning ""
    print_warning "⚠️  WARNING: This will completely remove DNSniper from your system including:"
    print_warning "   • All services and timers"
    print_warning "   • All firewall rules and ipset sets"
    print_warning "   • All configuration files"
    print_warning "   • All database files"
    print_warning "   • All log files"
    print_warning "   • All binaries and directories"
    print_warning ""
    print_warning "This action cannot be undone!"
    
    echo -n "Are you absolutely sure you want to continue? (yes/no): "
    read response
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    
    if [ "$response" != "yes" ] && [ "$response" != "y" ]; then
        print_error "❌ Uninstall cancelled."
        return
    fi

    # Ask about firewall rules specifically
    echo -n "🔥 Do you want to remove all DNSniper firewall rules? (yes/no): "
    read response2
    response2=$(echo "$response2" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    remove_rules=""
    if [ "$response2" = "yes" ] || [ "$response2" = "y" ]; then
        remove_rules="true"
    else
        remove_rules="false"
    fi

    print_info ""
    print_info "🔄 Starting uninstall process..."

    # Step 1: Stop and disable services
    print_info "1️⃣  Stopping and disabling services..."
    systemctl stop dnsniper-agent.service 2>/dev/null || true
    systemctl stop dnsniper-agent.timer 2>/dev/null || true
    systemctl disable dnsniper-agent.service 2>/dev/null || true
    systemctl disable dnsniper-agent.timer 2>/dev/null || true

    # Step 2: Remove firewall rules if requested
    if [ "$remove_rules" = "true" ]; then
        print_info "2️⃣  Removing firewall rules and ipset sets..."
        
        # List of DNSniper ipset names
        ipset_names="whitelistIP-v4 whitelistRange-v4 blocklistIP-v4 blocklistRange-v4 whitelistIP-v6 whitelistRange-v6 blocklistIP-v6 blocklistRange-v6"
        
        # Remove iptables rules first
        for chain in INPUT OUTPUT FORWARD; do
            for setName in $ipset_names; do
                # IPv4 and IPv6 rules
                iptables -D $chain -m set --match-set $setName src -j ACCEPT 2>/dev/null || true
                iptables -D $chain -m set --match-set $setName src -j DROP 2>/dev/null || true
                iptables -D $chain -m set --match-set $setName dst -j ACCEPT 2>/dev/null || true
                iptables -D $chain -m set --match-set $setName dst -j DROP 2>/dev/null || true
                
                ip6tables -D $chain -m set --match-set $setName src -j ACCEPT 2>/dev/null || true
                ip6tables -D $chain -m set --match-set $setName src -j DROP 2>/dev/null || true
                ip6tables -D $chain -m set --match-set $setName dst -j ACCEPT 2>/dev/null || true
                ip6tables -D $chain -m set --match-set $setName dst -j DROP 2>/dev/null || true
            done
        done
        
        # Remove ipset sets
        for setName in $ipset_names; do
            ipset flush $setName 2>/dev/null || true
            ipset destroy $setName 2>/dev/null || true
            print_success "   ✅ Removed ipset: $setName"
        done
    else
        print_info "2️⃣  Skipping firewall rules removal (as requested)..."
    fi

    # Step 3: Remove systemd files
    print_info "3️⃣  Removing systemd service files..."
    if [ -f "${SYSTEMD_DIR}/dnsniper-agent.service" ]; then
        rm -f "${SYSTEMD_DIR}/dnsniper-agent.service"
        print_success "   ✅ Removed: ${SYSTEMD_DIR}/dnsniper-agent.service"
    fi
    if [ -f "${SYSTEMD_DIR}/dnsniper-agent.timer" ]; then
        rm -f "${SYSTEMD_DIR}/dnsniper-agent.timer"
        print_success "   ✅ Removed: ${SYSTEMD_DIR}/dnsniper-agent.timer"
    fi
    systemctl daemon-reload 2>/dev/null || true

    # Step 4: Remove binaries
    print_info "4️⃣  Removing binaries..."
    for binary in "${BIN_DIR}/dnsniper" "${BIN_DIR}/dnsniper-agent" "${BIN_DIR}/dnsniper-installer"; do
        if [ -f "$binary" ]; then
            rm -f "$binary"
            print_success "   ✅ Removed: $binary"
        fi
    done

    # Step 5: Remove directories
    print_info "5️⃣  Removing directories..."
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        print_success "   ✅ Removed directory: $INSTALL_DIR"
    fi
    if [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"
        print_success "   ✅ Removed directory: $LOG_DIR"
    fi

    # Step 6: Clean up persistence files
    print_info "6️⃣  Cleaning up persistence files..."
    persistence_files="/etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/sysconfig/iptables /etc/sysconfig/ip6tables /etc/ipset.conf"
    for file in $persistence_files; do
        if [ -f "$file" ]; then
            rm -f "$file"
            print_success "   ✅ Removed: $file"
        fi
    done
    
    # Restart persistence services to apply changes
    systemctl restart netfilter-persistent 2>/dev/null || true
    systemctl restart iptables 2>/dev/null || true
    systemctl restart ip6tables 2>/dev/null || true

    print_success ""
    print_success "✅ DNSniper has been completely uninstalled!"
    print_success "🎯 All components removed successfully."
    
    if [ "$remove_rules" != "true" ]; then
        print_warning ""
        print_warning "⚠️  Note: Firewall rules were kept as requested."
        print_warning "   You can manually remove them if needed."
    fi
    
    print_success "DNSniper has been uninstalled"
    exit 0
}

# Detect OS
detect_os

# Process command line arguments
if [ "$1" = "uninstall" ]; then
    # Use enhanced uninstaller if available
    if command_exists dnsniper && [ -x "$BIN_DIR/dnsniper" ]; then
        print_info "Using enhanced uninstaller..."
        exec "$BIN_DIR/dnsniper" --uninstall
    else
        print_warning "Enhanced uninstaller not found, using fallback method..."
        uninstall_dnsniper
    fi
fi

# Install dependencies
install_dependencies

# Create necessary directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$IPTABLES_DIR"

# Check for existing installation and configuration
CONFIG_EXISTS="false"
if [ -f "$CONFIG_FILE" ]; then
    CONFIG_EXISTS="true"
fi

# Function to check for existing installation
check_existing_installation() {
    # Check all locations that uninstaller removes
    local installation_found=false
    
    # Check directories
    if [ -d "$INSTALL_DIR" ] || [ -d "$LOG_DIR" ]; then
        installation_found=true
    fi
    
    # Check binaries
    if [ -f "$BIN_DIR/dnsniper" ] || [ -f "$BIN_DIR/dnsniper-agent" ] || [ -f "$BIN_DIR/dnsniper-installer" ]; then
        installation_found=true
    fi
    
    # Check systemd services
    if [ -f "$SYSTEMD_DIR/dnsniper-agent.service" ] || [ -f "$SYSTEMD_DIR/dnsniper-agent.timer" ]; then
        installation_found=true
    fi
    
    # Check if services are registered (even if files don't exist)
    if systemctl list-unit-files | grep -q "dnsniper-agent"; then
        installation_found=true
    fi
    
    # Return result
    if [ "$installation_found" = true ]; then
        return 0  # Installation found
    else
        return 1  # No installation found
    fi
}

# Determine installation type
INSTALL_TYPE="clean"
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
            
            # If reinstalling, get the current configuration
            if [ "$CONFIG_EXISTS" = "true" ]; then
                print_info "Using existing configuration"
                
                # Try to extract existing configuration
                if command_exists grep && command_exists awk; then
                    # Extract affected_chains - handle both old (block_chains) and new formats
                    AFFECTED_CHAINS_LINE=$(grep "affected_chains:" "$CONFIG_FILE" | cut -d':' -f2- | tr -d ' ')
                    if [ -z "$AFFECTED_CHAINS_LINE" ]; then
                        # Fallback to old block_chains format for backward compatibility
                        AFFECTED_CHAINS_LINE=$(grep "block_chains:" "$CONFIG_FILE" | cut -d':' -f2- | tr -d ' ')
                        if [ -n "$AFFECTED_CHAINS_LINE" ]; then
                            print_info "🔄 Upgrading configuration: block_chains → affected_chains"
                        fi
                    fi
                    
                    if [ -n "$AFFECTED_CHAINS_LINE" ]; then
                        # Convert YAML array format back to simple format for internal processing
                        if [[ "$AFFECTED_CHAINS_LINE" == *"["* ]]; then
                            # It's already in array format, extract the values
                            if [[ "$AFFECTED_CHAINS_LINE" == *"INPUT"* ]] && [[ "$AFFECTED_CHAINS_LINE" == *"OUTPUT"* ]] && [[ "$AFFECTED_CHAINS_LINE" == *"FORWARD"* ]]; then
                                AFFECTED_CHAINS="ALL"
                            else
                                # Extract individual chains and convert to comma-separated
                                EXTRACTED_CHAINS=$(echo "$AFFECTED_CHAINS_LINE" | sed 's/\[//g' | sed 's/\]//g' | sed 's/"//g' | tr ',' '\n' | tr -d ' ' | paste -sd ',' -)
                                AFFECTED_CHAINS="$EXTRACTED_CHAINS"
                            fi
                        else
                            AFFECTED_CHAINS="$AFFECTED_CHAINS_LINE"
                        fi
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
            
            # Use enhanced uninstaller for clean removal
            if command_exists dnsniper && [ -x "$BIN_DIR/dnsniper" ]; then
                print_info "Using enhanced uninstaller for clean removal..."
                "$BIN_DIR/dnsniper" --uninstall >/dev/null 2>&1 || true
            else
                # Fallback to manual removal (matches uninstaller exactly)
                print_info "Using fallback removal method..."
                
                # Stop and disable services
                print_info "Stopping and disabling services..."
                systemctl stop dnsniper-agent.service 2>/dev/null
                systemctl disable dnsniper-agent.service 2>/dev/null
                systemctl stop dnsniper-agent.timer 2>/dev/null
                systemctl disable dnsniper-agent.timer 2>/dev/null
                
                # Remove systemd files
                print_info "Removing systemd files..."
                rm -f "${SYSTEMD_DIR}/dnsniper-agent.service"
                rm -f "${SYSTEMD_DIR}/dnsniper-agent.timer"
                systemctl daemon-reload 2>/dev/null || true
                
                # Remove binaries (matches uninstaller exactly)
                print_info "Removing binaries..."
                rm -f "$BIN_DIR/dnsniper"
                rm -f "$BIN_DIR/dnsniper-agent"
                rm -f "$BIN_DIR/dnsniper-installer"
                
                # Remove directories (matches uninstaller exactly)
                print_info "Removing directories..."
                rm -rf "$INSTALL_DIR"
                rm -rf "$LOG_DIR"
                
                print_info "Clean removal completed using fallback method"
            fi
            
            # Recreate directories
            mkdir -p "$INSTALL_DIR"
            mkdir -p "$LOG_DIR"
            
            CONFIG_EXISTS="false"
            ;;
        3)
            print_info "Starting uninstall process..."
            if command_exists dnsniper && [ -x "$BIN_DIR/dnsniper" ]; then
                print_info "Using enhanced uninstaller..."
                exec "$BIN_DIR/dnsniper" --uninstall
            else
                print_warning "Enhanced uninstaller not found, using fallback method..."
                uninstall_dnsniper
            fi
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
    CONFIG_EXISTS="false"
fi

# Set default values
AFFECTED_CHAINS="ALL"
UPDATE_INTERVAL="3h"

# Get configuration settings from user if needed
if [ "$INSTALL_TYPE" = "clean" ] || [ "$CONFIG_EXISTS" = "false" ]; then
    # Prompt for affected chains
    print_info "Select chains to apply firewall rules (affects both whitelist and blacklist):"
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
            AFFECTED_CHAINS="INPUT"
            ;;
        3)
            AFFECTED_CHAINS="OUTPUT"
            ;;
        4)
            AFFECTED_CHAINS="FORWARD"
            ;;
        5)
            AFFECTED_CHAINS="INPUT,OUTPUT"
            ;;
        6)
            AFFECTED_CHAINS="INPUT,FORWARD"
            ;;
        7)
            AFFECTED_CHAINS="OUTPUT,FORWARD"
            ;;
        *)
            AFFECTED_CHAINS="ALL"
            ;;
    esac
    
    print_info "Using affected chains: $AFFECTED_CHAINS"
    
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

# Process --build flag and get binaries
if [ "$1" = "--build" ]; then
    print_info "Build flag detected, building binaries locally..."
    if build_binaries; then
        print_success "Successfully built binaries"
    else
        print_error "Failed to build binaries"
        exit 1
    fi
else
    # No build flag, check for local binaries or download
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    BIN_PATH="${PROJECT_DIR}/bin"
    
    if [ -f "${BIN_PATH}/dnsniper" ] && [ -f "${BIN_PATH}/dnsniper-agent" ]; then
        print_info "Using locally available binaries..."
        mkdir -p "$INSTALL_DIR/bin"
        cp "${BIN_PATH}/dnsniper" "$INSTALL_DIR/bin/dnsniper"
        cp "${BIN_PATH}/dnsniper-agent" "$INSTALL_DIR/bin/dnsniper-agent"
        chmod +x "$INSTALL_DIR/bin/dnsniper"
        chmod +x "$INSTALL_DIR/bin/dnsniper-agent"
        BUILT_LOCALLY=true
    else
        # No local binaries, download from GitHub
        if ! download_binaries; then
            print_error "Failed to download binaries"
            exit 1
        fi
    fi
fi

# Create symlinks to binaries
print_info "Creating symlinks to binaries..."
ln -sf "$INSTALL_DIR/bin/dnsniper" "$BIN_DIR/dnsniper"
ln -sf "$INSTALL_DIR/bin/dnsniper-agent" "$BIN_DIR/dnsniper-agent"

# Verify enhanced binaries functionality
print_info "Verifying enhanced binaries functionality..."
if [ -x "$INSTALL_DIR/bin/dnsniper" ]; then
    # Test if the binary can access enhanced configuration
    if "$INSTALL_DIR/bin/dnsniper" --help >/dev/null 2>&1; then
        print_success "✅ dnsniper binary: Enhanced features accessible"
    else
        print_warning "⚠️  dnsniper binary: May have compatibility issues"
    fi
else
    print_error "❌ dnsniper binary: Not executable"
fi

if [ -x "$INSTALL_DIR/bin/dnsniper-agent" ]; then
    # Test if the agent binary is functional
    if "$INSTALL_DIR/bin/dnsniper-agent" --help >/dev/null 2>&1; then
        print_success "✅ dnsniper-agent binary: GORM integration ready"
    else
        print_warning "⚠️  dnsniper-agent binary: May have compatibility issues"
    fi
else
    print_error "❌ dnsniper-agent binary: Not executable"
fi

# Verify netfilter tools are available
print_info "Verifying netfilter tools availability..."

if command_exists iptables; then
    print_success "✅ iptables: Available"
else
    print_error "❌ iptables: Not found"
fi

if command_exists ip6tables; then
    print_success "✅ ip6tables: Available"
else
    print_error "❌ ip6tables: Not found"
fi

if command_exists ipset; then
    print_success "✅ ipset: Available"
else
    print_error "❌ ipset: Not found"
fi

print_info "📝 Configuration will be auto-generated on first run with your chosen settings"

# Create systemd service
print_info "Creating systemd service files..."
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

ipset create whitelistIP-v4 hash:ip family inet hashsize 4096 maxelem 65536 -exist
ipset create whitelistRange-v4 hash:net family inet hashsize 4096 maxelem 65536 -exist
ipset create blacklistIP-v4 hash:ip family inet hashsize 4096 maxelem 65536 -exist
ipset create blacklistRange-v4 hash:net family inet hashsize 4096 maxelem 65536 -exist

ipset create whitelistIP-v6 hash:ip family inet6 hashsize 4096 maxelem 65536 -exist
ipset create whitelistRange-v6 hash:net family inet6 hashsize 4096 maxelem 65536 -exist
ipset create blacklistIP-v6 hash:ip family inet6 hashsize 4096 maxelem 65536 -exist
ipset create blacklistRange-v6 hash:net family inet6 hashsize 4096 maxelem 65536 -exist

# Initial ipset configuration  
print_info "Setting up initial firewall rules..."
print_info "Rules will be generated automatically when DNSniper runs"

# Save rules for persistence
save_rules_for_persistence

# Enable persistence services
enable_persistence_services

# Validate configuration
validate_config

# Enable and start the timer
print_info "Enabling and starting DNSniper agent timer..."
systemctl enable dnsniper-agent.timer
systemctl start dnsniper-agent.timer

# Create a symlink for the installer
ln -sf "$SCRIPT_DIR/installer.sh" "$BIN_DIR/dnsniper-installer"

print_success "🎉 DNSniper v2.0 installed successfully!"
print_info ""
print_info "🚀 Key Features:"
print_info "✅ Advanced DNS firewall with GORM database integration"
print_info "✅ Automatic rule persistence using system tools"
print_info "✅ Interactive management with pagination"
print_info "✅ Whitelist priority system (overrides blocklist)"
print_info "✅ Progress indicators for operations"
print_info "✅ Comprehensive settings management"
print_info "✅ Multi-threaded agent with DNS load balancing"
print_info ""
print_info "🎯 Quick Start:"
print_info "• Run 'dnsniper' to start the interactive menu"
print_info "• The agent will run automatically every $UPDATE_INTERVAL"
print_info "• Configuration will be created on first run"
print_info ""
print_info "📊 System Integration:"

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
