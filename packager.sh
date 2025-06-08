#!/bin/bash

# DNSniper Release Packager Script
# This script creates a complete, ready-to-deploy package of DNSniper

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
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

print_arch() {
    echo -e "${CYAN}[ARCH: $1]${NC} $2"
}

# Usage function
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --multi-arch    Build for multiple architectures using Docker (requires buildx)"
    echo "  --local         Build for current architecture only (default)"
    echo "  --arch ARCH     Specify architectures to build (multi-arch mode only)"
    echo "                  ARCH can be: x64, arm64, or comma-separated list"
    echo "  --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Local build for current architecture"
    echo "  $0 --local                  # Same as above"
    echo "  $0 --multi-arch             # Build for all architectures (x64, arm64)"
    echo "  $0 --multi-arch --arch x64   # Build for x64 only"
    echo "  $0 --multi-arch --arch arm64 # Build for arm64 only"
    echo "  $0 --multi-arch --arch x64,arm64  # Build for both architectures"
    echo ""
    echo "Available architectures:"
    echo "  x64     - Intel/AMD 64-bit (linux/amd64) - Most servers and desktops"
    echo "  arm64   - ARM 64-bit (linux/arm64) - Modern ARM devices, Apple Silicon"
    echo ""
    echo "Requirements:"
    echo "  Local mode:      Root privileges, Python 3.x, PyInstaller"
    echo "  Multi-arch mode: Docker with buildx support (Docker 20.10+)"
    echo ""
    echo "Note: If buildx is not available, install with:"
    echo "  sudo apt install docker-buildx-plugin"
}

# Parse command line arguments
BUILD_MODE="local"
ARCH_LIST=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --multi-arch)
            BUILD_MODE="multi-arch"
            shift
            ;;
        --local)
            BUILD_MODE="local"
            shift
            ;;
        --arch)
            ARCH_LIST="$2"
            shift
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate --arch flag can only be used with --multi-arch
if [ -n "$ARCH_LIST" ] && [ "$BUILD_MODE" != "multi-arch" ]; then
    print_error "--arch flag can only be used with --multi-arch mode"
    print_status "Use: ./packager.sh --multi-arch --arch x64,arm64"
    exit 1
fi

# Check if running as root
if [ "$BUILD_MODE" = "local" ]; then
    if [[ $EUID -ne 0 ]]; then
       print_error "Local build mode requires root privileges (use sudo)"
       exit 1
    fi
    
    # Detect the original user (who ran sudo)
    ORIGINAL_USER=${SUDO_USER:-$USER}
    if [ -z "$ORIGINAL_USER" ] || [ "$ORIGINAL_USER" = "root" ]; then
        print_warning "Could not detect original user, files will remain owned by root"
        ORIGINAL_USER=""
    fi
else
    # Multi-arch mode can run as root or regular user
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running multi-arch mode as root - consider using regular user for better security"
        print_status "Docker commands will be executed with appropriate permissions"
    fi
fi

if [ "$BUILD_MODE" = "local" ]; then
    print_status "Starting DNSniper LOCAL packaging process..."
else
    print_status "🐳 Starting DNSniper MULTI-ARCHITECTURE packaging process..."
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$BUILD_MODE" = "local" ]; then
    PACKAGER_DIR="$SCRIPT_DIR/packager"
else
    PACKAGER_DIR="$SCRIPT_DIR/multi-packager"
    DOCKER_BUILD_DIR="$PACKAGER_DIR/docker-build"
    
    # Architecture definitions for multi-arch mode
    declare -A ALL_ARCHITECTURES=(
        ["x64"]="linux/amd64"
        ["arm64"]="linux/arm64"
    )
    
    # Filter architectures based on --arch flag
    declare -A ARCHITECTURES=()
    if [ -n "$ARCH_LIST" ]; then
        # Parse comma-separated architecture list
        IFS=',' read -ra ARCH_ARRAY <<< "$ARCH_LIST"
        for arch in "${ARCH_ARRAY[@]}"; do
            # Trim whitespace
            arch=$(echo "$arch" | xargs)
            
            if [[ -n "${ALL_ARCHITECTURES[$arch]}" ]]; then
                ARCHITECTURES["${ALL_ARCHITECTURES[$arch]}"]="$arch"
                print_status "Selected architecture: $arch (${ALL_ARCHITECTURES[$arch]})"
            else
                print_error "Invalid architecture: $arch"
                print_status "Available architectures: x64, arm64"
                exit 1
            fi
        done
        
        if [ ${#ARCHITECTURES[@]} -eq 0 ]; then
            print_error "No valid architectures specified"
            exit 1
        fi
    else
        # Default: build all architectures
        ARCHITECTURES=(
            ["linux/amd64"]="x64"
            ["linux/arm64"]="arm64"
        )
        print_status "Building for all architectures: x64, arm64"
    fi
fi

# Docker setup for multi-arch mode
if [ "$BUILD_MODE" = "multi-arch" ]; then
    # Check Docker availability
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        print_status "Please install Docker: https://docs.docker.com/install/"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        print_status "Please start Docker daemon first"
        exit 1
    fi

    # Check if user can run Docker commands
    if [[ $EUID -eq 0 ]]; then
        # Running as root - no sudo needed
        DOCKER_CMD="docker"
        print_status "Running as root - using direct Docker commands"
    elif ! docker ps &> /dev/null; then
        print_warning "Cannot run Docker commands without sudo"
        print_status "Adding current user to docker group might be needed:"
        print_status "sudo usermod -aG docker \$USER && newgrp docker"
        DOCKER_CMD="sudo docker"
    else
        DOCKER_CMD="docker"
    fi

    print_success "Docker is available and running"

    # Check if buildx is available
    if ! $DOCKER_CMD buildx version &> /dev/null; then
        print_error "Docker buildx is not available or not enabled"
        print_status "Multi-architecture builds require Docker buildx support."
        print_status ""
        print_status "To enable buildx, try one of these options:"
        print_status "1. Update Docker to a newer version (20.10+):"
        print_status "   curl -fsSL https://get.docker.com | sh"
        print_status ""
        print_status "2. Install docker-buildx plugin:"
        print_status "   sudo apt update && sudo apt install docker-buildx-plugin"
        print_status ""
        print_status "3. Enable experimental features in Docker:"
        print_status "   echo '{\"experimental\": true}' | sudo tee /etc/docker/daemon.json"
        print_status "   sudo systemctl restart docker"
        print_status ""
        print_status "4. Alternative: Use local mode for single architecture:"
        print_status "   sudo ./packager.sh --local"
        exit 1
    fi

    # Setup Docker buildx for multi-platform builds
    print_status "Setting up Docker buildx for multi-platform builds..."
    if ! $DOCKER_CMD buildx ls | grep -q "multi-arch-builder"; then
        print_status "Creating multi-architecture builder..."
        if ! $DOCKER_CMD buildx create --name multi-arch-builder --use --platform linux/amd64,linux/arm64; then
            print_error "Failed to create multi-architecture builder"
            print_status "Your Docker installation may not support all target platforms."
            print_status "Try using local mode instead: sudo ./packager.sh --local"
            exit 1
        fi
    else
        print_status "Using existing multi-architecture builder..."
        if ! $DOCKER_CMD buildx use multi-arch-builder; then
            print_error "Failed to use existing multi-architecture builder"
            print_status "Try removing and recreating: docker buildx rm multi-arch-builder"
            exit 1
        fi
    fi

    print_success "Docker buildx setup completed successfully"
fi

# Clean and create packager directory
print_status "Setting up packager directory..."
if [ -d "$PACKAGER_DIR" ]; then
    print_warning "Removing existing packager directory..."
    rm -rf "$PACKAGER_DIR"
fi
mkdir -p "$PACKAGER_DIR"

# Create Docker build directory for multi-arch mode
if [ "$BUILD_MODE" = "multi-arch" ]; then
    mkdir -p "$DOCKER_BUILD_DIR"
fi

# Check if required directories exist
if [ ! -d "$SCRIPT_DIR/backend" ]; then
    print_error "Backend directory not found!"
    exit 1
fi

if [ ! -d "$SCRIPT_DIR/frontend" ]; then
    print_error "Frontend directory not found!"
    exit 1
fi

# Step 1: Get version from frontend/version.json
print_status "Reading version information..."
VERSION_FILE="$SCRIPT_DIR/frontend/version.json"
if [ ! -f "$VERSION_FILE" ]; then
    print_error "Version file not found at $VERSION_FILE"
    exit 1
fi

# Extract version using python
VERSION=$(python3 -c "
import json
with open('$VERSION_FILE', 'r') as f:
    data = json.load(f)
    print(data.get('version', 'unknown'))
")

if [ "$VERSION" = "unknown" ]; then
    print_error "Could not extract version from $VERSION_FILE"
    exit 1
fi

print_success "Version detected: $VERSION"

# Step 2: Build frontend
print_status "Building frontend..."
cd "$SCRIPT_DIR/frontend"

# Check if node_modules exists, if not install dependencies
if [ ! -d "node_modules" ]; then
    print_status "Installing frontend dependencies..."
    npm install
fi

# Build frontend
print_status "Running frontend build..."
npm run build

# Check if build was successful
if [ ! -d "build" ]; then
    print_error "Frontend build failed - build directory not found"
    exit 1
fi

print_success "Frontend build completed"

# Step 3: Copy frontend build to packager/static/
print_status "Copying frontend build to packager/static/..."
if [ "$BUILD_MODE" = "local" ]; then
    mkdir -p "$PACKAGER_DIR/static"
    cp -r "$SCRIPT_DIR/frontend/build/"* "$PACKAGER_DIR/static/"
else
    # For multi-arch, copy to Docker build directory
    mkdir -p "$DOCKER_BUILD_DIR/static"
    cp -r "$SCRIPT_DIR/frontend/build/"* "$DOCKER_BUILD_DIR/static/"
    # Also copy backend source to Docker build directory
    print_status "Preparing backend files for Docker builds..."
    cp -r "$SCRIPT_DIR/backend" "$DOCKER_BUILD_DIR/"
fi
print_success "Frontend files copied to static/"

# Step 4: Create config.json
print_status "Creating config.json..."
if [ "$BUILD_MODE" = "local" ]; then
    cat > "$PACKAGER_DIR/config.json" << 'EOF'
{
  "web_server": {
    "host": "0.0.0.0",
    "port": 8000
  },
  "frontend": {
    "static_path": "static/"
  },
  "_packaged": true,
  "_comments": {
    "static_path": "Frontend files location relative to binary - DO NOT change this in packaged version",
    "_packaged": "Internal flag indicating this is a packaged distribution"
  }
}
EOF
else
    # For multi-arch mode, create Dockerfile instead
    print_status "Creating Dockerfile for multi-architecture builds..."
    cat > "$DOCKER_BUILD_DIR/Dockerfile" << 'EOF'
# Multi-stage Dockerfile for DNSniper multi-architecture builds
ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim-bullseye AS builder

# Install essential build dependencies for x64 and arm64
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libffi-dev \
    libssl-dev \
    cargo \
    rustc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy backend source
COPY backend/ ./backend/

# Copy frontend static files
COPY static/ ./static/

# Install Python dependencies
WORKDIR /app/backend
RUN pip install --upgrade pip setuptools wheel

# Install requirements with proper build environment
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir pyinstaller

# Create config.json for packaged environment
RUN echo '{\
  "web_server": {\
    "host": "0.0.0.0",\
    "port": 8000\
  },\
  "frontend": {\
    "static_path": "static/"\
  },\
  "_packaged": true,\
  "_comments": {\
    "static_path": "Frontend files location relative to binary - DO NOT change this in packaged version",\
    "_packaged": "Internal flag indicating this is a packaged distribution"\
  }\
}' > /app/config.json

# Build main binary
RUN pyinstaller --onefile \
    --name="dnsniper" \
    --distpath="/app/dist" \
    --workpath="/app/build" \
    --specpath="/app/specs" \
    main.py

# Build CLI binary if it exists
RUN if [ -f "cli.py" ]; then \
    pyinstaller --onefile \
        --name="dnsniper-cli" \
        --distpath="/app/dist" \
        --workpath="/app/build" \
        --specpath="/app/specs" \
        cli.py; \
    fi

# Final stage - create minimal output
FROM scratch AS output
COPY --from=builder /app/dist/ /dist/
COPY --from=builder /app/static/ /static/
COPY --from=builder /app/config.json /config.json
EOF
fi
print_success "Configuration created"

# Backend Compilation
if [ "$BUILD_MODE" = "local" ]; then
    # Step 5: Local PyInstaller compilation
    print_status "Setting up Python environment for compilation..."
    cd "$SCRIPT_DIR/backend"

    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_status "Creating Python virtual environment..."
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Install/upgrade required packages
    print_status "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install pyinstaller

    # Step 6: Compile main.py to dnsniper
    print_status "Compiling main.py to dnsniper binary..."
    pyinstaller --onefile \
        --name="dnsniper" \
        --distpath="$PACKAGER_DIR" \
        --workpath="$PACKAGER_DIR/build_temp" \
        --specpath="$PACKAGER_DIR/specs" \
        main.py

    if [ ! -f "$PACKAGER_DIR/dnsniper" ]; then
        print_error "Failed to compile main.py"
        exit 1
    fi
    print_success "dnsniper binary created"

    # Step 7: Check if cli.py exists and compile it
    if [ -f "cli.py" ]; then
        print_status "Compiling cli.py to dnsniper-cli binary..."
        pyinstaller --onefile \
            --name="dnsniper-cli" \
            --distpath="$PACKAGER_DIR" \
            --workpath="$PACKAGER_DIR/build_temp" \
            --specpath="$PACKAGER_DIR/specs" \
            cli.py
        
        if [ ! -f "$PACKAGER_DIR/dnsniper-cli" ]; then
            print_error "Failed to compile cli.py"
            exit 1
        fi
        print_success "dnsniper-cli binary created"
    else
        print_warning "cli.py not found, skipping CLI compilation"
    fi

    # Deactivate virtual environment
    deactivate

    # Step 8: Clean up temporary build files
    print_status "Cleaning up temporary files..."
    rm -rf "$PACKAGER_DIR/build_temp"
    rm -rf "$PACKAGER_DIR/specs"
    
else
    # Step 5-7: Multi-architecture Docker compilation
    print_status "🚀 Starting multi-architecture builds..."
    echo "============================================="

    for platform in "${!ARCHITECTURES[@]}"; do
        arch_name="${ARCHITECTURES[$platform]}"
        print_arch "$arch_name" "Building DNSniper for $platform..."
        
        # Create architecture-specific output directory
        ARCH_OUTPUT_DIR="$PACKAGER_DIR/packages/dnsniper-v${VERSION}-linux-${arch_name}"
        mkdir -p "$ARCH_OUTPUT_DIR"
        
        # Build Docker image for this architecture
        BUILD_START_TIME=$(date +%s)
        
        $DOCKER_CMD buildx build \
            --platform "$platform" \
            --target output \
            --output type=local,dest="$ARCH_OUTPUT_DIR" \
            "$DOCKER_BUILD_DIR"
        
        BUILD_END_TIME=$(date +%s)
        BUILD_DURATION=$((BUILD_END_TIME - BUILD_START_TIME))
        
        # Verify build was successful
        if [ ! -f "$ARCH_OUTPUT_DIR/dist/dnsniper" ]; then
            print_error "Build failed for $arch_name - binary not found"
            continue
        fi
        
        # Reorganize files for packaging (Docker output structure -> final structure)
        # Move binaries from dist/ to root
        mv "$ARCH_OUTPUT_DIR/dist/"* "$ARCH_OUTPUT_DIR/"
        rmdir "$ARCH_OUTPUT_DIR/dist"
        
        # static/ and config.json are already in the right place from Docker output
        # No need to move them as they're already at the correct paths
        
        # Make binaries executable
        chmod +x "$ARCH_OUTPUT_DIR/dnsniper"
        if [ -f "$ARCH_OUTPUT_DIR/dnsniper-cli" ]; then
            chmod +x "$ARCH_OUTPUT_DIR/dnsniper-cli"
        fi
        
        # Get file sizes for progress reporting
        BINARY_SIZE=$(du -h "$ARCH_OUTPUT_DIR/dnsniper" | cut -f1)
        STATIC_COUNT=$(find "$ARCH_OUTPUT_DIR/static" -type f | wc -l)
        
        print_arch "$arch_name" "✅ Build completed in ${BUILD_DURATION}s"
        print_arch "$arch_name" "   Binary size: $BINARY_SIZE"
        print_arch "$arch_name" "   Frontend files: $STATIC_COUNT"
        if [ -f "$ARCH_OUTPUT_DIR/dnsniper-cli" ]; then
            CLI_SIZE=$(du -h "$ARCH_OUTPUT_DIR/dnsniper-cli" | cut -f1)
            print_arch "$arch_name" "   CLI size: $CLI_SIZE"
        fi
        echo ""
    done
fi

# Create release zip file(s)
cd "$SCRIPT_DIR"

if [ "$BUILD_MODE" = "local" ]; then
    # Step 9: Create single zip file for local build
    print_status "Creating release package..."

    # Detect system architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_NAME="x64" ;;
        aarch64) ARCH_NAME="arm64" ;;
        armv7l) ARCH_NAME="arm32" ;;
        *) ARCH_NAME="$ARCH" ;;
    esac

    # Create zip filename with version and architecture
    ZIP_FILENAME="dnsniper-v${VERSION}-linux-${ARCH_NAME}.zip"
    ZIP_PATH="$SCRIPT_DIR/$ZIP_FILENAME"

    # Remove existing zip if it exists
    if [ -f "$ZIP_PATH" ]; then
        rm "$ZIP_PATH"
    fi

    # Create zip file
    cd "$PACKAGER_DIR"
    zip -r "$ZIP_PATH" . -x "*.log" "*.tmp"

    # Verify zip was created
    if [ ! -f "$ZIP_PATH" ]; then
        print_error "Failed to create zip file"
        exit 1
    fi

    # Get zip file size
    ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)

    print_success "Package created successfully!"
    print_success "File: $ZIP_FILENAME"
    print_success "Size: $ZIP_SIZE"
    print_success "Location: $ZIP_PATH"
    
else
    # Step 8: Create zip files for multi-arch builds
    print_status "Creating release packages for all architectures..."
    cd "$PACKAGER_DIR/packages"
    
    for platform in "${!ARCHITECTURES[@]}"; do
        arch_name="${ARCHITECTURES[$platform]}"
        ZIP_FILENAME="dnsniper-v${VERSION}-linux-${arch_name}.zip"
        
        if [ -d "dnsniper-v${VERSION}-linux-${arch_name}" ]; then
            zip -r "$ZIP_FILENAME" "dnsniper-v${VERSION}-linux-${arch_name}/" -x "*.log" "*.tmp"
            
            if [ -f "$ZIP_FILENAME" ]; then
                ZIP_SIZE=$(du -h "$ZIP_FILENAME" | cut -f1)
                print_arch "$arch_name" "📦 Package: $ZIP_SIZE"
            fi
        fi
    done
    
    cd "$SCRIPT_DIR"
fi

# Display package contents and summary
if [ "$BUILD_MODE" = "local" ]; then
    # Step 10: Display package contents
    print_status "Package contents:"
    echo "==================="
    ls -la "$PACKAGER_DIR"
    echo "==================="

    # Step 11: Verify binaries
    print_status "Verifying compiled binaries..."
    if [ -f "$PACKAGER_DIR/dnsniper" ]; then
        DNSNIPER_SIZE=$(du -h "$PACKAGER_DIR/dnsniper" | cut -f1)
        print_success "dnsniper binary: $DNSNIPER_SIZE"
    fi

    if [ -f "$PACKAGER_DIR/dnsniper-cli" ]; then
        CLI_SIZE=$(du -h "$PACKAGER_DIR/dnsniper-cli" | cut -f1)
        print_success "dnsniper-cli binary: $CLI_SIZE"
    fi

    STATIC_COUNT=$(find "$PACKAGER_DIR/static" -type f | wc -l)
    print_success "Frontend files: $STATIC_COUNT files in static/"

    # Step 12: File Size Summary
    print_status "=== FILE SIZE SUMMARY ==="
    echo ""
    printf "%-25s %10s\n" "FILE/DIRECTORY" "SIZE"
    echo "==========================================="

    # Main binaries
    if [ -f "$PACKAGER_DIR/dnsniper" ]; then
        DNSNIPER_SIZE=$(du -h "$PACKAGER_DIR/dnsniper" | cut -f1)
        printf "%-25s %10s\n" "dnsniper binary" "$DNSNIPER_SIZE"
    fi

    if [ -f "$PACKAGER_DIR/dnsniper-cli" ]; then
        CLI_SIZE=$(du -h "$PACKAGER_DIR/dnsniper-cli" | cut -f1)
        printf "%-25s %10s\n" "dnsniper-cli binary" "$CLI_SIZE"
    fi

    # Configuration and docs
    if [ -f "$PACKAGER_DIR/config.json" ]; then
        CONFIG_SIZE=$(du -h "$PACKAGER_DIR/config.json" | cut -f1)
        printf "%-25s %10s\n" "config.json" "$CONFIG_SIZE"
    fi

    # Frontend static files
    if [ -d "$PACKAGER_DIR/static" ]; then
        STATIC_SIZE=$(du -sh "$PACKAGER_DIR/static" | cut -f1)
        printf "%-25s %10s\n" "static/ (frontend)" "$STATIC_SIZE"
    fi

    # Total package size
    TOTAL_PACKAGE_SIZE=$(du -sh "$PACKAGER_DIR" | cut -f1)
    echo "==========================================="
    printf "%-25s %10s\n" "TOTAL PACKAGE SIZE" "$TOTAL_PACKAGE_SIZE"

    # Final zip size
    printf "%-25s %10s\n" "COMPRESSED ZIP" "$ZIP_SIZE"
    echo "==========================================="
    echo ""

    print_success "======================================="
    print_success "DNSniper v$VERSION packaged successfully!"
    print_success "Ready for GitHub release upload:"
    print_success "$ZIP_FILENAME"
    print_success "======================================="

    # Optional: Show hash for verification
    if command -v sha256sum &> /dev/null; then
        HASH=$(sha256sum "$ZIP_PATH" | cut -d' ' -f1)
        print_status "SHA256: $HASH"
    fi
    
else
    # Multi-arch build summary
    print_status "📦 Multi-Architecture Build Summary"
    echo "============================================="
    printf "%-15s %-15s %-15s %-15s\n" "ARCHITECTURE" "BINARY SIZE" "PACKAGE SIZE" "STATUS"
    echo "-------------------------------------------------------------"

    for platform in "${!ARCHITECTURES[@]}"; do
        arch_name="${ARCHITECTURES[$platform]}"
        ARCH_OUTPUT_DIR="$PACKAGER_DIR/packages/dnsniper-v${VERSION}-linux-${arch_name}"
        ZIP_FILE="$PACKAGER_DIR/packages/dnsniper-v${VERSION}-linux-${arch_name}.zip"
        
        if [ -f "$ARCH_OUTPUT_DIR/dnsniper" ] && [ -f "$ZIP_FILE" ]; then
            BINARY_SIZE=$(du -h "$ARCH_OUTPUT_DIR/dnsniper" | cut -f1)
            ZIP_SIZE=$(du -h "$ZIP_FILE" | cut -f1)
            STATUS="✅ SUCCESS"
        else
            BINARY_SIZE="N/A"
            ZIP_SIZE="N/A" 
            STATUS="❌ FAILED"
        fi
        
        printf "%-15s %-15s %-15s %-15s\n" "$arch_name" "$BINARY_SIZE" "$ZIP_SIZE" "$STATUS"
    done

    echo ""
    print_success "🎉 Multi-architecture packaging completed!"
    print_status "📁 Packages are available in: $PACKAGER_DIR/packages/"
    print_status "🐳 To clean up Docker builder: docker buildx rm multi-arch-builder"

    # Optional: Calculate SHA256 hashes
    if command -v sha256sum &> /dev/null; then
        print_status "📋 Generating SHA256 hashes..."
        cd "$PACKAGER_DIR/packages"
        sha256sum *.zip > dnsniper-v${VERSION}-SHA256SUMS.txt 2>/dev/null
        if [ -f "dnsniper-v${VERSION}-SHA256SUMS.txt" ]; then
            print_success "SHA256 hashes saved to dnsniper-v${VERSION}-SHA256SUMS.txt"
        fi
        cd "$SCRIPT_DIR"
    fi

    # Show final file listing
    print_status "📦 Final package listing:"
    ls -la "$PACKAGER_DIR/packages/"*.zip 2>/dev/null || print_warning "No packages found"
fi

# Permission fixes (only for local builds)
if [ "$BUILD_MODE" = "local" ]; then
    # Step 13: Fix ownership and permissions for packager directory
    if [ -n "$ORIGINAL_USER" ] && [ "$ORIGINAL_USER" != "root" ]; then
        print_status "Fixing ownership and permissions for user access..."
        
        # Change ownership of packager directory and all contents to original user
        chown -R "$ORIGINAL_USER:$ORIGINAL_USER" "$PACKAGER_DIR"
        
        # Set read/write permissions for user, read for group/others
        chmod -R 755 "$PACKAGER_DIR"
        
        # Make config.json specifically writable by user
        chmod 644 "$PACKAGER_DIR/config.json"
        
        # Make binaries executable
        if [ -f "$PACKAGER_DIR/dnsniper" ]; then
            chmod 755 "$PACKAGER_DIR/dnsniper"
        fi
        
        if [ -f "$PACKAGER_DIR/dnsniper-cli" ]; then
            chmod 755 "$PACKAGER_DIR/dnsniper-cli"
        fi
        
        # Change ownership of the zip file as well
        chown "$ORIGINAL_USER:$ORIGINAL_USER" "$ZIP_PATH"
        
        print_success "Ownership changed to: $ORIGINAL_USER"
        print_success "You can now edit files in the packager/ directory"
    else
        print_warning "Running as root user - packager directory will remain owned by root"
    fi
fi

# Final completion message
print_status "✨ Packaging complete!"
if [ "$BUILD_MODE" = "local" ]; then
    print_status "📦 Single architecture package ready for GitHub release!"
else
    print_status "📦 Multi-architecture packages ready for GitHub release!" 