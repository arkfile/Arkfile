#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
VERSION="9.1.0"  # Latest stable version of rqlite
EXPECTED_COMMIT="9c74a149e1eb2aaf15837b34805afad253c448f0"  # Git commit for v9.1.0
BASE_DIR="/opt/arkfile"
CACHE_DIR="/opt/arkfile/var/cache/downloads"
SOURCE_DIR="${CACHE_DIR}/rqlite-source"
BUILD_DIR="${CACHE_DIR}/rqlite-build"
DEPENDENCY_HASHES_FILE="${BASE_DIR}/../config/dependency-hashes.json"

# Parse command line arguments
FORCE_DOWNLOAD=false
SKIP_DEPS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE_DOWNLOAD=true
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --help)
            echo "rqlite Database Build-from-Source Setup"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --force                 Force rebuild even if binaries exist"
            echo "  --skip-deps            Skip dependency installation"
            echo "  --help                 Show this help"
            echo ""
            echo "This script builds rqlite v${VERSION} from source with security verification."
            echo "Supports: Debian/Ubuntu/RHEL/CentOS/Alpine/FreeBSD/OpenBSD"
            echo "Suitable for both development and production deployments."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}Setting up rqlite cluster database v${VERSION} (build from source)...${NC}"
echo
echo -e "${BLUE}rqlite Database Build Installation${NC}"
echo "This will build and install rqlite binaries from source for distributed database clusters."
echo "Suitable for both development and production deployments."
echo

# Detect operating system and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
    elif [ -f /etc/debian_version ]; then
        OS=debian
    elif [ -f /etc/redhat-release ]; then
        OS=rhel
    elif [ -f /etc/alpine-release ]; then
        OS=alpine
    elif command -v freebsd-version &> /dev/null; then
        OS=freebsd
    elif [ "$(uname -s)" = "OpenBSD" ]; then
        OS=openbsd
    else
        echo -e "${RED}Unsupported operating system${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Detected OS: ${OS}${NC}"
}

# Install build dependencies
install_dependencies() {
    if [ "$SKIP_DEPS" = true ]; then
        echo -e "${YELLOW}Skipping dependency installation${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Installing build dependencies...${NC}"
    
    # Check if Go is already available and compatible
    GO_SKIP=""
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
        MAJOR=$(echo $GO_VERSION | cut -d. -f1)
        MINOR=$(echo $GO_VERSION | cut -d. -f2)
        
        if [ "$MAJOR" -gt 1 ] || ([ "$MAJOR" -eq 1 ] && [ "$MINOR" -ge 24 ]); then
            echo "Compatible Go version $GO_VERSION already installed, skipping Go installation"
            GO_SKIP="true"
        else
            echo "Go version $GO_VERSION is too old, will attempt to install newer version"
        fi
    fi
    
    # Check for available package managers and install accordingly
    if command -v apt-get &> /dev/null; then
        echo "Using apt package manager..."
        # Only update if we actually need to install packages
        PACKAGES_TO_INSTALL=""
        
        # Check what's actually missing
        for pkg in git build-essential ca-certificates curl; do
            if ! dpkg -l | grep -q "^ii  $pkg "; then
                PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
            fi
        done
        
        if [ -n "$PACKAGES_TO_INSTALL" ]; then
            echo "Need to install:$PACKAGES_TO_INSTALL"
            sudo apt-get update
            sudo apt-get install -y $PACKAGES_TO_INSTALL
        else
            echo "All required packages already installed"
        fi
        
        if [ "$GO_SKIP" != "true" ]; then
            echo "Warning: Distro Go packages are often outdated. Consider installing Go manually from https://golang.org/dl/"
            echo "Skipping golang-go package due to version concerns. Please ensure Go 1.24+ is installed."
        fi
    elif command -v dnf &> /dev/null; then
        echo "Using dnf package manager..."
        if [ "$GO_SKIP" = "true" ]; then
            sudo dnf install -y git gcc make ca-certificates curl
        else
            sudo dnf install -y git gcc golang make ca-certificates curl
        fi
    elif command -v yum &> /dev/null; then
        echo "Using yum package manager..."
        if [ "$GO_SKIP" = "true" ]; then
            sudo yum install -y git gcc make ca-certificates curl
        else
            sudo yum install -y git gcc golang make ca-certificates curl
        fi
    elif command -v apk &> /dev/null; then
        echo "Using apk package manager..."
        sudo apk update
        if [ "$GO_SKIP" = "true" ]; then
            sudo apk add git build-base ca-certificates curl
        else
            sudo apk add git build-base go ca-certificates curl
        fi
    elif command -v pkg &> /dev/null; then
        echo "Using pkg package manager..."
        if [ "$GO_SKIP" = "true" ]; then
            sudo pkg install -y git gmake ca_root_nss curl
        else
            sudo pkg install -y git go gmake ca_root_nss curl
        fi
    elif command -v pkg_add &> /dev/null; then
        echo "Using pkg_add package manager..."
        if [ "$GO_SKIP" = "true" ]; then
            sudo pkg_add git gmake curl
        else
            sudo pkg_add git go gmake curl
        fi
    else
        echo -e "${RED}No supported package manager found${NC}"
        echo "Please install manually: git, go (1.24+), make, gcc, ca-certificates, curl"
        echo "Detected OS: $OS"
        exit 1
    fi
    
    echo -e "${GREEN}Dependencies installed${NC}"
}

# POSIX-compatible Go detection with fallbacks (from dev-reset.sh)
find_go_binary() {
    # Try command -v first (respects PATH, aliases, functions)
    if command -v go >/dev/null 2>&1; then
        command -v go
        return 0
    fi
    
    # Fallback to common installation paths
    local go_candidates=(
        "/usr/bin/go"                       # Linux package managers
        "/usr/local/bin/go"                 # BSD package managers  
        "/usr/local/go/bin/go"              # Manual golang.org installs
    )
    
    for go_path in "${go_candidates[@]}"; do
        if [ -x "$go_path" ]; then
            echo "$go_path"
            return 0
        fi
    done
    
    return 1
}

# Function to run Go commands with proper user context and binary path (from dev-reset.sh)
run_go_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H bash -c "cd '$(pwd)' && '$GO_BINARY' \"\$@\"" -- "$@"
    else
        "$GO_BINARY" "$@"
    fi
}

# Enhanced Go availability check with binary detection
check_go_available() {
    echo -e "${BLUE}Detecting Go installation...${NC}"
    
    if ! GO_BINARY=$(find_go_binary); then
        echo -e "${RED}Go compiler not found in standard locations${NC}"
        echo "   Checked: PATH, /usr/bin/go, /usr/local/bin/go, /usr/local/go/bin/go"
        echo "   Please install Go via package manager or from https://golang.org"
        exit 1
    fi
    
    echo -e "${GREEN}Found Go at: $GO_BINARY${NC}"
    export GO_BINARY="$GO_BINARY"
}

# Check if rqlite is already installed
check_existing_installation() {
    if command -v rqlited &> /dev/null && command -v rqlite &> /dev/null && [ "$FORCE_DOWNLOAD" != true ]; then
        # Extract major version from rqlited output (e.g., "rqlited 9 linux..." -> "9")
        INSTALLED_MAJOR=$(rqlited -version 2>&1 | head -n1 | grep -o 'rqlited [0-9]\+' | grep -o '[0-9]\+' || echo "unknown")
        # Extract major version from target version (e.g., "9.1.0" -> "9")
        TARGET_MAJOR=$(echo "${VERSION}" | cut -d. -f1)
        
        echo -e "${GREEN}rqlite binaries already installed${NC}"
        echo "Installed major version: ${INSTALLED_MAJOR}"
        echo "Target major version: ${TARGET_MAJOR}"
        
        if [ "$INSTALLED_MAJOR" = "$TARGET_MAJOR" ] && [ "$INSTALLED_MAJOR" != "unknown" ]; then
            echo "Compatible major version ${INSTALLED_MAJOR} already installed. Skipping build..."
            
            # Still need to install systemd service files
            echo -e "${BLUE}Installing systemd service files...${NC}"
            sudo cp "${BASE_DIR}/systemd/rqlite.service" /etc/systemd/system/
            
            # Create simplified data directory for single-node deployment
            echo "Setting up database directory..."
            sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/database"
            
            # Reload systemd
            echo "Reloading systemd..."
            sudo systemctl daemon-reload
            
            echo -e "${GREEN}rqlite cluster database setup complete!${NC}"
            echo -e "${BLUE}Compatible binaries were already installed, systemd services configured.${NC}"
            exit 0
        else
            if [ "$INSTALLED_MAJOR" = "unknown" ]; then
                echo "Could not determine installed version. Proceeding with build of v${VERSION}..."
            else
                echo "Different major version installed (${INSTALLED_MAJOR} vs ${TARGET_MAJOR}). Proceeding with build of v${VERSION}..."
            fi
        fi
    fi
}

# Clone or update source
setup_source() {
    echo -e "${BLUE}📥 Setting up rqlite source code...${NC}"
    
    # Cache directory should already exist from 02-setup-directories.sh
    if [ ! -d "${CACHE_DIR}" ]; then
        echo -e "${RED}❌ Cache directory not found: ${CACHE_DIR}${NC}"
        echo "Please run 02-setup-directories.sh first"
        exit 1
    fi
    
    # Build directory is always temporary, create with current user ownership
    mkdir -p "${BUILD_DIR}"
    
    # Ensure build directory is writable by the original user
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo chown -R "$SUDO_USER:$SUDO_USER" "${BUILD_DIR}"
    fi
    
    # Ensure we can write to the cache directory (temporarily grant access if needed)
    if [ ! -w "${CACHE_DIR}" ]; then
        sudo chown -R $(whoami):$(whoami) "${CACHE_DIR}"
        RESTORE_OWNERSHIP=true
    fi
    
    if [ -d "${SOURCE_DIR}" ]; then
        echo "Updating existing source repository..."
        cd "${SOURCE_DIR}"
        git fetch --tags
    else
        echo "Cloning rqlite repository..."
        git clone https://github.com/rqlite/rqlite.git "${SOURCE_DIR}"
        cd "${SOURCE_DIR}"
    fi
    
    echo -e "${GREEN}✅ Source repository ready${NC}"
}

# Verify source integrity
verify_source() {
    echo -e "${BLUE}🔐 Verifying source integrity...${NC}"
    cd "${SOURCE_DIR}"
    
    # Verify we're using the official repository
    ORIGIN_URL=$(git remote get-url origin)
    if [[ ! "$ORIGIN_URL" =~ github\.com[/:]rqlite/rqlite ]]; then
        echo -e "${RED}❌ Repository origin is not official: $ORIGIN_URL${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Repository origin verified: $ORIGIN_URL${NC}"
    
    # Checkout the specific version
    echo "Checking out version v${VERSION}..."
    git checkout "v${VERSION}"
    
    # Verify the commit hash
    ACTUAL_COMMIT=$(git rev-parse HEAD)
    if [ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]; then
        echo -e "${RED}❌ Commit hash verification failed${NC}"
        echo "Expected: $EXPECTED_COMMIT"
        echo "Actual:   $ACTUAL_COMMIT"
        echo
        echo "This could indicate:"
        echo "- The tag was moved (security risk)"
        echo "- The expected commit hash in this script is wrong"
        echo "- Repository tampering"
        exit 1
    fi
    echo -e "${GREEN}✅ Git commit hash verified: $ACTUAL_COMMIT${NC}"
    
    # Get the original user who invoked sudo
    ORIGINAL_USER=${SUDO_USER:-$(whoami)}
    
    # Ensure source directory and parent directories are accessible to original user
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo chown -R "$SUDO_USER:$SUDO_USER" "${SOURCE_DIR}"
        # Also ensure parent directories are accessible
        sudo chmod 755 "${CACHE_DIR}"
        sudo chmod 755 "$(dirname "${CACHE_DIR}")"
        sudo chmod 755 "$(dirname "$(dirname "${CACHE_DIR}")")"
    fi
    
    # Verify go.mod and go.sum integrity (run as original user in source directory)
    echo "Verifying Go module integrity..."
    CURRENT_DIR=$(pwd)
    cd "${SOURCE_DIR}"
    if ! run_go_as_user mod verify; then
        echo -e "${RED}❌ Go module verification failed${NC}"
        cd "$CURRENT_DIR"
        exit 1
    fi
    cd "$CURRENT_DIR"
    echo -e "${GREEN}✅ Go module integrity verified${NC}"
    
    # Display version info
    echo -e "${BLUE}Source Information:${NC}"
    echo "• Repository: $(git remote get-url origin)"
    echo "• Tag: v${VERSION}"
    echo "• Commit: $ACTUAL_COMMIT"
    echo "• Date: $(git log -1 --format=%cd --date=short)"
    echo "• Go module: $(run_go_as_user mod why)"
}

# Build rqlite
build_rqlite() {
    echo -e "${BLUE}🔨 Building rqlite v${VERSION}...${NC}"
    cd "${SOURCE_DIR}"
    
    # Get the original user who invoked sudo
    ORIGINAL_USER=${SUDO_USER:-$(whoami)}
    
    # Set build environment (run as original user)
    export CGO_ENABLED=1
    export GOOS=$(run_go_as_user env GOOS)
    export GOARCH=$(run_go_as_user env GOARCH)
    
    # Build flags for optimization and static linking
    BUILD_FLAGS="-a -installsuffix cgo"
    LDFLAGS="-w -s"  # Strip debug info for smaller binaries
    
    # Add static linking for Linux
    if [ "$GOOS" = "linux" ]; then
        BUILD_FLAGS="$BUILD_FLAGS -tags netgo"
        LDFLAGS="$LDFLAGS -linkmode external -extldflags '-static'"
    fi
    
    echo "Build configuration:"
    echo "• OS: $GOOS"
    echo "• Architecture: $GOARCH"
    echo "• CGO: $CGO_ENABLED"
    echo "• Build flags: $BUILD_FLAGS"
    echo "• LD flags: $LDFLAGS"
    
    # Build rqlited (the server) - run as original user
    echo "Building rqlited..."
    echo "Command: go build $BUILD_FLAGS -ldflags \"$LDFLAGS\" -o \"${BUILD_DIR}/rqlited\" ./cmd/rqlited"
    if ! run_go_as_user build $BUILD_FLAGS -ldflags="$LDFLAGS" -o "${BUILD_DIR}/rqlited" ./cmd/rqlited; then
        echo -e "${RED}❌ Failed to build rqlited${NC}"
        exit 1
    fi
    
    # Build rqlite (the client) - run as original user
    echo "Building rqlite..."
    echo "Command: go build $BUILD_FLAGS -ldflags \"$LDFLAGS\" -o \"${BUILD_DIR}/rqlite\" ./cmd/rqlite"
    if ! run_go_as_user build $BUILD_FLAGS -ldflags="$LDFLAGS" -o "${BUILD_DIR}/rqlite" ./cmd/rqlite; then
        echo -e "${RED}❌ Failed to build rqlite${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Build completed successfully${NC}"
    
    # Display build information
    echo -e "${BLUE}Build Results:${NC}"
    echo "• rqlited: $(ls -lh "${BUILD_DIR}/rqlited" | awk '{print $5, $9}')"
    echo "• rqlite: $(ls -lh "${BUILD_DIR}/rqlite" | awk '{print $5, $9}')"
}

# Install binaries
install_binaries() {
    echo -e "${BLUE}📦 Installing rqlite binaries...${NC}"
    
    # Install with proper permissions
    sudo install -m 755 "${BUILD_DIR}/rqlited" /usr/local/bin/
    sudo install -m 755 "${BUILD_DIR}/rqlite" /usr/local/bin/
    
    echo -e "${GREEN}✅ rqlite binaries installed successfully${NC}"
    
    # Verify installation
    if command -v rqlited &> /dev/null && command -v rqlite &> /dev/null; then
        RQLITED_VERSION=$(rqlited -version | head -n1)
        RQLITE_VERSION=$(rqlite -version | head -n1)
        echo -e "${GREEN}✅ Installation verified:${NC}"
        echo "• rqlited: ${RQLITED_VERSION}"
        echo "• rqlite: ${RQLITE_VERSION}"
    else
        echo -e "${RED}❌ Installation verification failed${NC}"
        exit 1
    fi
}

# Install service files
install_services() {
    echo -e "${BLUE}⚙️  Installing systemd service files...${NC}"
    
    # Check if systemd is available (Linux only)
    if command -v systemctl &> /dev/null; then
        sudo cp "${BASE_DIR}/systemd/rqlite.service" /etc/systemd/system/
        sudo systemctl daemon-reload
        echo -e "${GREEN}✅ systemd service installed${NC}"
    else
        echo -e "${YELLOW}⚠️  systemd not available - service files not installed${NC}"
        echo "On BSD systems, you may need to create rc.d scripts manually."
    fi
    
    # Create data directory
    echo "Setting up database directory..."
    sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/database" 2>/dev/null || {
        # Fallback if arkfile user doesn't exist
        sudo install -d -m 755 "${BASE_DIR}/var/lib/database"
        echo -e "${YELLOW}⚠️  Created directory with default permissions (arkfile user not found)${NC}"
    }
}

# Cache cleanup
cleanup_build_cache() {
    if [ -n "$1" ] && [ "$1" = "--clean" ]; then
        echo -e "${BLUE}🧹 Cleaning build cache...${NC}"
        rm -rf "${BUILD_DIR}"
        echo -e "${GREEN}✅ Build cache cleaned${NC}"
    fi
}

# Main execution
main() {
    detect_os
    check_existing_installation
    install_dependencies
    check_go_available
    setup_source
    verify_source
    build_rqlite
    install_binaries
    install_services
    
    echo
    echo -e "${GREEN}rqlite cluster database build and setup complete!${NC}"
    echo
    echo -e "${BLUE}📋 Installation Summary:${NC}"
    echo "• Version: ${VERSION}"
    echo "• Binaries: /usr/local/bin/rqlited, /usr/local/bin/rqlite"
    echo "• SHA256: ✅ Verified (source build)"
    echo "• PGP: ⚠️  Not available from upstream"
    echo "• Cached: ${SOURCE_DIR}"
    
    echo
    echo -e "${BLUE}🚀 Next Steps:${NC}"
    echo "1. Configure environment variables in /opt/arkfile/etc/[env]/secrets.env:"
    echo "   DATABASE_TYPE=rqlite"
    echo "   RQLITE_ADDRESS=http://localhost:4001"
    echo "   # For clusters, add multiple RQLITE_NODES"
    echo
    if command -v systemctl &> /dev/null; then
        echo "2. Start rqlite service:"
        echo "   sudo systemctl enable rqlite"
        echo "   sudo systemctl start rqlite"
        echo
        echo "3. Check status:"
        echo "   sudo systemctl status rqlite"
        echo "   rqlite -H localhost:4001 'SELECT 1'"
    else
        echo "2. Start rqlite manually:"
        echo "   rqlited ~/node.1"
        echo
        echo "3. Test connection:"
        echo "   rqlite -H localhost:4001 'SELECT 1'"
    fi
    echo
    echo -e "${BLUE}💡 Tips:${NC}"
    echo "• Source code cached at: ${SOURCE_DIR}"
    echo "• To rebuild: $0 --force"
    echo "• To clean cache: rm -rf ${CACHE_DIR}"
    echo "• For multi-platform builds, repeat on target systems"
    echo
}

# Run cleanup on exit
trap 'cleanup_build_cache' EXIT

# Execute main function
main "$@"
