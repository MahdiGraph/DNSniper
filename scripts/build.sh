#!/bin/bash
# build-release.sh - DNSniper Release Builder
# Creates architecture-specific builds for release packages

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colorful messages
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Determine version
VERSION=""
# Check if version is provided as argument
if [ -n "$1" ]; then
    VERSION="$1"
    print_info "Using provided version: ${VERSION}"
else
    # Try to get from git tag
    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        GIT_VERSION=$(git describe --tags --exact-match 2>/dev/null)
        if [ -n "$GIT_VERSION" ]; then
            VERSION="$GIT_VERSION"
            print_info "Using Git tag version: ${VERSION}"
        else
            VERSION="v1.0.0"
            print_warning "No Git tag found. Using default version: ${VERSION}"
            print_warning "You can specify a version as an argument: ./build-release.sh v1.2.3"
        fi
    else
        VERSION="v1.0.0"
        print_warning "Git not available. Using default version: ${VERSION}"
        print_warning "You can specify a version as an argument: ./build-release.sh v1.2.3"
    fi
fi

# Output directory
OUTPUT_DIR="./release-builds"
print_info "Build output directory: ${OUTPUT_DIR}"

# Make sure output directory exists and is clean
mkdir -p "${OUTPUT_DIR}"
rm -rf "${OUTPUT_DIR:?}"/* 2>/dev/null

# Verify Go is installed
if ! command -v go >/dev/null 2>&1; then
    print_error "Go is not installed or not in your PATH"
    exit 1
fi

# Check that we're in the right directory (repository root)
if [ ! -d "./cmd/dnsniper" ] || [ ! -d "./cmd/dnsniper-agent" ]; then
    print_error "Could not find cmd/dnsniper or cmd/dnsniper-agent directories"
    print_error "Please run this script from the root of the repository"
    exit 1
fi

# Print build information
print_info "Building DNSniper ${VERSION}"
go version

# Build for each architecture
ARCHITECTURES=("amd64" "arm64" "arm" "386")
for ARCH in "${ARCHITECTURES[@]}"; do
    print_info "Building for linux/${ARCH}..."
    
    # Create directory for this architecture
    ARCH_DIR="${OUTPUT_DIR}/linux-${ARCH}"
    mkdir -p "${ARCH_DIR}"
    
    # Build DNSniper with architecture-specific name
    print_info "Building dnsniper-linux-${ARCH}..."
    GOOS=linux GOARCH=${ARCH} go build -ldflags="-s -w" -o "${ARCH_DIR}/dnsniper-linux-${ARCH}" ./cmd/dnsniper/ || {
        print_error "Failed to build dnsniper for ${ARCH}"
        continue
    }
    
    # Build DNSniper-agent with architecture-specific name
    print_info "Building dnsniper-agent-linux-${ARCH}..."
    GOOS=linux GOARCH=${ARCH} go build -ldflags="-s -w" -o "${ARCH_DIR}/dnsniper-agent-linux-${ARCH}" ./cmd/dnsniper-agent/ || {
        print_error "Failed to build dnsniper-agent for ${ARCH}"
        continue
    }
    
    # Create zip file
    print_info "Creating zip package for linux/${ARCH}..."
    (cd "${ARCH_DIR}" && zip -j "../dnsniper-linux-${ARCH}.zip" "dnsniper-linux-${ARCH}" "dnsniper-agent-linux-${ARCH}") || {
        print_error "Failed to create zip package for ${ARCH}"
        continue
    }
    
    # Generate SHA256 checksum
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "${OUTPUT_DIR}" && sha256sum "dnsniper-linux-${ARCH}.zip" > "dnsniper-linux-${ARCH}.zip.sha256")
        print_info "Generated SHA256 checksum for linux/${ARCH}"
    fi
    
    print_success "Created ${OUTPUT_DIR}/dnsniper-linux-${ARCH}.zip"
done

# Create installer script in the output directory
print_info "Copying installer script..."
if [ -f "./installer.sh" ]; then
    cp "./installer.sh" "${OUTPUT_DIR}/installer.sh"
    chmod +x "${OUTPUT_DIR}/installer.sh"
    print_success "Installer script copied to ${OUTPUT_DIR}/installer.sh"
elif [ -f "./scripts/installer.sh" ]; then
    cp "./scripts/installer.sh" "${OUTPUT_DIR}/installer.sh"
    chmod +x "${OUTPUT_DIR}/installer.sh"
    print_success "Installer script copied to ${OUTPUT_DIR}/installer.sh"
else
    print_warning "Could not find installer.sh in repository root or scripts directory"
fi

# Summary
SUCCESSFUL_BUILDS=$(find "${OUTPUT_DIR}" -name "dnsniper-linux-*.zip" | wc -l)
print_success "Build completed: ${SUCCESSFUL_BUILDS}/${#ARCHITECTURES[@]} architectures built successfully"
print_info "Release files are available in ${OUTPUT_DIR}/"
ls -lh "${OUTPUT_DIR}"

if [ "${SUCCESSFUL_BUILDS}" -gt 0 ]; then
    print_info "Next steps:"
    print_info "1. Create a new release on GitHub with tag ${VERSION}"
    print_info "2. Upload the zip files from ${OUTPUT_DIR}/ to the release"
    print_info "3. Make the installer.sh script available for users to download"
    exit 0
else
    print_error "No successful builds were created."
    exit 1
fi