#!/bin/bash

# DNSniper Newman Installation Script
# This script installs Newman and its dependencies for running API tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Node.js installation
check_nodejs() {
    print_info "Checking Node.js installation..."
    
    if command_exists node; then
        local node_version=$(node --version)
        print_success "Node.js is installed: $node_version"
        
        # Check if version is recent enough (v14+)
        local major_version=$(echo $node_version | sed 's/v\([0-9]*\).*/\1/')
        if [ "$major_version" -ge 14 ]; then
            print_success "Node.js version is compatible"
            return 0
        else
            print_warning "Node.js version $node_version might be too old. Recommended: v14+"
            return 0
        fi
    else
        print_error "Node.js is not installed"
        return 1
    fi
}

# Function to check npm installation
check_npm() {
    print_info "Checking npm installation..."
    
    if command_exists npm; then
        local npm_version=$(npm --version)
        print_success "npm is installed: v$npm_version"
        return 0
    else
        print_error "npm is not installed"
        return 1
    fi
}

# Function to install Node.js (Ubuntu/Debian)
install_nodejs_ubuntu() {
    print_info "Installing Node.js on Ubuntu/Debian..."
    
    # Update package list
    sudo apt update
    
    # Install Node.js and npm
    sudo apt install -y nodejs npm
    
    # Verify installation
    if check_nodejs && check_npm; then
        print_success "Node.js and npm installed successfully"
        return 0
    else
        print_error "Failed to install Node.js and npm"
        return 1
    fi
}

# Function to install Node.js (CentOS/RHEL/Fedora)
install_nodejs_redhat() {
    print_info "Installing Node.js on CentOS/RHEL/Fedora..."
    
    # Try dnf first (Fedora), then yum (CentOS/RHEL)
    if command_exists dnf; then
        sudo dnf install -y nodejs npm
    elif command_exists yum; then
        sudo yum install -y nodejs npm
    else
        print_error "No supported package manager found"
        return 1
    fi
    
    # Verify installation
    if check_nodejs && check_npm; then
        print_success "Node.js and npm installed successfully"
        return 0
    else
        print_error "Failed to install Node.js and npm"
        return 1
    fi
}

# Function to install Node.js (macOS)
install_nodejs_macos() {
    print_info "Installing Node.js on macOS..."
    
    if command_exists brew; then
        brew install node
    else
        print_error "Homebrew not found. Please install Homebrew first or install Node.js manually"
        print_info "Visit: https://nodejs.org/en/download/"
        return 1
    fi
    
    # Verify installation
    if check_nodejs && check_npm; then
        print_success "Node.js and npm installed successfully"
        return 0
    else
        print_error "Failed to install Node.js and npm"
        return 1
    fi
}

# Function to install Newman
install_newman() {
    print_info "Installing Newman..."
    
    # Install Newman globally
    if npm install -g newman; then
        print_success "Newman installed successfully"
    else
        print_error "Failed to install Newman"
        print_info "You might need to run with sudo: sudo npm install -g newman"
        return 1
    fi
    
    # Install HTML reporter
    print_info "Installing Newman HTML reporter..."
    if npm install -g newman-reporter-html; then
        print_success "Newman HTML reporter installed successfully"
    else
        print_warning "Failed to install Newman HTML reporter (optional)"
    fi
    
    # Verify Newman installation
    if command_exists newman; then
        local newman_version=$(newman --version)
        print_success "Newman is ready: $newman_version"
        return 0
    else
        print_error "Newman installation verification failed"
        return 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if [ -f /etc/debian_version ]; then
            echo "ubuntu"
        elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ] || [ -f /etc/fedora-release ]; then
            echo "redhat"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to show manual installation instructions
show_manual_instructions() {
    print_info "Manual Installation Instructions:"
    echo
    echo "1. Install Node.js (v14 or higher):"
    echo "   - Visit: https://nodejs.org/en/download/"
    echo "   - Download and install the LTS version"
    echo
    echo "2. Install Newman:"
    echo "   npm install -g newman"
    echo
    echo "3. Install Newman HTML reporter (optional):"
    echo "   npm install -g newman-reporter-html"
    echo
    echo "4. Verify installation:"
    echo "   newman --version"
}

# Main installation function
main() {
    print_info "DNSniper Newman Installation Script"
    print_info "=================================="
    
    # Check if already installed
    if command_exists newman; then
        local newman_version=$(newman --version)
        print_success "Newman is already installed: $newman_version"
        print_info "Installation complete!"
        exit 0
    fi
    
    # Check prerequisites
    local needs_nodejs=false
    
    if ! check_nodejs || ! check_npm; then
        needs_nodejs=true
    fi
    
    # Install Node.js if needed
    if [ "$needs_nodejs" = true ]; then
        print_info "Node.js or npm is missing. Installing..."
        
        local os=$(detect_os)
        case $os in
            ubuntu)
                if ! install_nodejs_ubuntu; then
                    print_error "Failed to install Node.js automatically"
                    show_manual_instructions
                    exit 1
                fi
                ;;
            redhat)
                if ! install_nodejs_redhat; then
                    print_error "Failed to install Node.js automatically"
                    show_manual_instructions
                    exit 1
                fi
                ;;
            macos)
                if ! install_nodejs_macos; then
                    print_error "Failed to install Node.js automatically"
                    show_manual_instructions
                    exit 1
                fi
                ;;
            *)
                print_warning "Unsupported OS detected: $OSTYPE"
                show_manual_instructions
                exit 1
                ;;
        esac
    fi
    
    # Install Newman
    if ! install_newman; then
        print_error "Failed to install Newman"
        show_manual_instructions
        exit 1
    fi
    
    print_success "Installation completed successfully!"
    print_info "You can now run DNSniper API tests with: ./run-tests.sh"
}

# Run main function
main "$@" 