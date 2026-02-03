#!/bin/bash

# Build libopaque.js WASM library for browser-based OPAQUE authentication
# This script builds the JavaScript/WASM bindings for the libopaque library
# with automated Emscripten installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building libopaque.js WASM library${NC}"
echo "===================================="

# Function to print status messages
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "INFO")
            echo -e "  ${BLUE}INFO:${NC} ${message}"
            ;;
        "SUCCESS")
            echo -e "  ${GREEN}SUCCESS:${NC} ${message}"
            ;;
        "WARNING")
            echo -e "  ${YELLOW}WARNING:${NC} ${message}"
            ;;
        "ERROR")
            echo -e "  ${RED}ERROR:${NC} ${message}"
            ;;
    esac
}

# Enhanced cross-platform system detection (matching build-libopaque.sh)
detect_system_and_packages() {
    OS=""
    PACKAGE_MANAGER=""
    INSTALL_CMD=""
    EMSCRIPTEN_PKG=""
    
    # Enhanced OS detection with multiple methods
    if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "linux-musl"* ]] || [ -f /etc/os-release ]; then
        # Alpine Linux detection
        if [ -f /etc/alpine-release ] || grep -q "Alpine" /etc/os-release 2>/dev/null; then
            OS="alpine"
            PACKAGE_MANAGER="apk"
            INSTALL_CMD="apk add --no-cache"
            EMSCRIPTEN_PKG="emscripten"
        # Debian/Ubuntu detection
        elif command -v apt-get >/dev/null || [ -f /etc/debian_version ] || grep -qE "(Ubuntu|Debian)" /etc/os-release 2>/dev/null; then
            OS="debian"
            PACKAGE_MANAGER="apt"
            INSTALL_CMD="apt-get update && apt-get install -y"
            EMSCRIPTEN_PKG="emscripten"
        # RHEL family detection
        elif command -v dnf >/dev/null || command -v yum >/dev/null || [ -f /etc/redhat-release ] || grep -qE "(Red Hat|CentOS|AlmaLinux|Rocky)" /etc/os-release 2>/dev/null; then
            OS="rhel"
            if command -v dnf >/dev/null; then
                PACKAGE_MANAGER="dnf"
                INSTALL_CMD="dnf install -y"
            else
                PACKAGE_MANAGER="yum"
                INSTALL_CMD="yum install -y"
            fi
            EMSCRIPTEN_PKG="emscripten"
        # Arch Linux detection
        elif command -v pacman >/dev/null || [ -f /etc/arch-release ] || grep -q "Arch" /etc/os-release 2>/dev/null; then
            OS="arch"
            PACKAGE_MANAGER="pacman"
            INSTALL_CMD="pacman -S --noconfirm"
            EMSCRIPTEN_PKG="emscripten"
        else
            OS="unknown-linux"
        fi
    elif [[ "$OSTYPE" == "freebsd"* ]] || uname | grep -q FreeBSD; then
        OS="freebsd"
        PACKAGE_MANAGER="pkg"
        INSTALL_CMD="pkg install -y"
        EMSCRIPTEN_PKG="emscripten"
    elif [[ "$OSTYPE" == "openbsd"* ]] || uname | grep -q OpenBSD; then
        OS="openbsd"
        PACKAGE_MANAGER="pkg_add"
        INSTALL_CMD="pkg_add"
        EMSCRIPTEN_PKG="emscripten"
    elif [[ "$OSTYPE" == "netbsd"* ]] || uname | grep -q NetBSD; then
        OS="netbsd"
        PACKAGE_MANAGER="pkgin"
        INSTALL_CMD="pkgin -y install"
        EMSCRIPTEN_PKG="emscripten"
    else
        OS="unknown"
    fi
    
    print_status "INFO" "Detected OS: $OS"
}

# Install Emscripten via package manager
install_emscripten_package() {
    print_status "INFO" "Attempting to install Emscripten via $PACKAGE_MANAGER..."
    
    case $PACKAGE_MANAGER in
        apk)
            if sudo $INSTALL_CMD $EMSCRIPTEN_PKG; then
                return 0
            fi
            ;;
        apt)
            if sudo $INSTALL_CMD $EMSCRIPTEN_PKG; then
                return 0
            fi
            ;;
        dnf|yum)
            # RHEL family may need EPEL repository
            print_status "INFO" "Enabling EPEL repository for Emscripten..."
            sudo $INSTALL_CMD epel-release 2>/dev/null || true
            if sudo $INSTALL_CMD $EMSCRIPTEN_PKG; then
                return 0
            fi
            ;;
        pacman)
            if sudo $INSTALL_CMD $EMSCRIPTEN_PKG; then
                return 0
            fi
            ;;
        pkg)
            if sudo $INSTALL_CMD $EMSCRIPTEN_PKG; then
                return 0
            fi
            ;;
        pkg_add)
            if sudo $INSTALL_CMD $EMSCRIPTEN_PKG; then
                return 0
            fi
            ;;
        pkgin)
            if sudo $INSTALL_CMD $EMSCRIPTEN_PKG; then
                return 0
            fi
            ;;
    esac
    
    return 1
}

# Install Emscripten via emsdk (fallback method)
install_emscripten_emsdk() {
    print_status "INFO" "Installing Emscripten via emsdk (fallback method)..."
    
    local EMSDK_DIR="vendor/emsdk"
    # Use Emscripten 3.1.45 for compatibility with libsodium.js
    # (Emscripten 5.0+ has breaking API changes)
    local EMSCRIPTEN_VERSION="3.1.45"
    
    # Clone emsdk if not already present
    if [ ! -d "$EMSDK_DIR" ]; then
        print_status "INFO" "Cloning emsdk repository..."
        if ! git clone https://github.com/emscripten-core/emsdk.git "$EMSDK_DIR"; then
            print_status "ERROR" "Failed to clone emsdk repository"
            return 1
        fi
    else
        print_status "INFO" "emsdk directory already exists, updating..."
        cd "$EMSDK_DIR"
        git pull || true
        cd ../..
    fi
    
    # Install and activate Emscripten 3.1.45
    cd "$EMSDK_DIR"
    
    print_status "INFO" "Installing Emscripten $EMSCRIPTEN_VERSION (compatible with libsodium.js)..."
    if ! ./emsdk install "$EMSCRIPTEN_VERSION"; then
        print_status "ERROR" "Failed to install Emscripten via emsdk"
        cd ../..
        return 1
    fi
    
    print_status "INFO" "Activating Emscripten $EMSCRIPTEN_VERSION..."
    if ! ./emsdk activate "$EMSCRIPTEN_VERSION"; then
        print_status "ERROR" "Failed to activate Emscripten"
        cd ../..
        return 1
    fi
    
    # Source the environment
    print_status "INFO" "Loading Emscripten environment..."
    if [ -f "./emsdk_env.sh" ]; then
        source ./emsdk_env.sh
    else
        print_status "ERROR" "emsdk_env.sh not found"
        cd ../..
        return 1
    fi
    
    cd ../..
    
    # Verify emcc is now available
    if command -v emcc >/dev/null 2>&1; then
        print_status "SUCCESS" "Emscripten installed successfully via emsdk"
        return 0
    else
        print_status "ERROR" "Emscripten installation via emsdk failed"
        return 1
    fi
}

# Ensure Emscripten is available
ensure_emscripten() {
    print_status "INFO" "Checking for Emscripten..."
    
    # Check if already installed
    if command -v emcc >/dev/null 2>&1; then
        EMCC_VERSION=$(emcc --version | head -n1)
        print_status "SUCCESS" "Found Emscripten: $EMCC_VERSION"
        return 0
    fi
    
    # Check if emsdk is already installed locally
    if [ -f "vendor/emsdk/emsdk_env.sh" ]; then
        print_status "INFO" "Found local emsdk installation, loading environment..."
        cd vendor/emsdk
        source ./emsdk_env.sh
        cd ../..
        
        if command -v emcc >/dev/null 2>&1; then
            EMCC_VERSION=$(emcc --version | head -n1)
            print_status "SUCCESS" "Loaded Emscripten from local emsdk: $EMCC_VERSION"
            return 0
        fi
    fi
    
    # Emscripten not found, attempt installation
    print_status "WARNING" "Emscripten not found, attempting automatic installation..."
    
    # Detect system
    detect_system_and_packages
    
    # Try package manager first (faster and cleaner)
    if [ "$OS" != "unknown" ] && [ "$OS" != "unknown-linux" ]; then
        if install_emscripten_package; then
            # Verify installation
            if command -v emcc >/dev/null 2>&1; then
                EMCC_VERSION=$(emcc --version | head -n1)
                print_status "SUCCESS" "Emscripten installed via package manager: $EMCC_VERSION"
                return 0
            fi
        fi
        
        print_status "WARNING" "Package manager installation failed, trying emsdk..."
    fi
    
    # Fallback to emsdk
    if install_emscripten_emsdk; then
        return 0
    fi
    
    # All installation methods failed
    print_status "ERROR" "Failed to install Emscripten automatically"
    echo ""
    echo "Please install Emscripten manually:"
    echo "  https://emscripten.org/docs/getting_started/downloads.html"
    echo ""
    return 1
}

# Validate Makefile configuration
validate_makefile() {
    print_status "INFO" "Validating Makefile configuration..."
    local MAKEFILE_PATH="vendor/stef/libopaque/js/Makefile"
    
    if [ ! -f "$MAKEFILE_PATH" ]; then
        print_status "ERROR" "Makefile not found at $MAKEFILE_PATH"
        exit 1
    fi
    
    # Check for dangerous -DNORANDOM flag
    if grep -q "DEFINES=.*-DNORANDOM" "$MAKEFILE_PATH"; then
        print_status "ERROR" "Invalid libopaque.js configuration detected!"
        echo ""
        echo -e "${RED}The Makefile contains the -DNORANDOM flag which:${NC}"
        echo -e "${RED}  1. Makes OPAQUE deterministic (insecure for production)${NC}"
        echo -e "${RED}  2. Changes protocol data structures (breaks backend compatibility)${NC}"
        echo ""
        echo -e "${YELLOW}The backend Go code uses standard libopaque without -DNORANDOM.${NC}"
        echo -e "${YELLOW}Frontend and backend MUST use matching configurations.${NC}"
        echo ""
        echo -e "${BLUE}To fix:${NC}"
        echo "  Edit: $MAKEFILE_PATH"
        echo "  Change: DEFINES=-DTRACE -DNORANDOM"
        echo "  To:     DEFINES=-DTRACE"
        echo ""
        echo -e "${BLUE}Or for production (no trace logging):${NC}"
        echo "  To:     DEFINES="
        echo ""
        exit 1
    fi
    
    print_status "SUCCESS" "Makefile configuration is valid"
}

# Build the WASM library
build_wasm_library() {
    # Change to the libopaque.js directory
    cd vendor/stef/libopaque/js
    
    # Clean previous builds
    print_status "INFO" "Cleaning previous WASM builds..."
    make clean-libopaquejs >/dev/null 2>&1 || true
    
    # Build libsodium.js dependency if needed
    if [ ! -f "libsodium.js/libsodium/src/libsodium/.libs/libsodium.a" ]; then
        print_status "INFO" "Building libsodium.js dependency (this may take a few minutes)..."
        if ! make libsodium; then
            print_status "ERROR" "Failed to build libsodium.js"
            exit 1
        fi
        print_status "SUCCESS" "libsodium.js built successfully"
    else
        print_status "INFO" "libsodium.js already built, skipping"
    fi
    
    # Build libopaque.js WASM library
    print_status "INFO" "Building libopaque.js WASM library..."
    if ! make libopaquejs; then
        print_status "ERROR" "Failed to build libopaque.js"
        exit 1
    fi
    
    # Verify output files exist
    if [ ! -f "dist/libopaque.js" ]; then
        print_status "ERROR" "Build succeeded but dist/libopaque.js not found"
        exit 1
    fi
    
    if [ ! -f "dist/libopaque.debug.js" ]; then
        print_status "ERROR" "Build succeeded but dist/libopaque.debug.js not found"
        exit 1
    fi
    
    print_status "SUCCESS" "libopaque.js WASM library built successfully"
    
    # Return to project root
    cd ../../../..
}

# Copy built files to client directory
deploy_wasm_files() {
    print_status "INFO" "Copying WASM library to client directory..."
    mkdir -p client/static/js
    cp vendor/stef/libopaque/js/dist/libopaque.js client/static/js/
    cp vendor/stef/libopaque/js/dist/libopaque.debug.js client/static/js/
    
    # Verify files were copied
    if [ ! -f "client/static/js/libopaque.js" ]; then
        print_status "ERROR" "Failed to copy libopaque.js to client directory"
        exit 1
    fi
    
    if [ ! -f "client/static/js/libopaque.debug.js" ]; then
        print_status "ERROR" "Failed to copy libopaque.debug.js to client directory"
        exit 1
    fi
    
    print_status "SUCCESS" "WASM library copied to client/static/js/"
    
    # Show file sizes
    MINIFIED_SIZE=$(du -h client/static/js/libopaque.js | cut -f1)
    DEBUG_SIZE=$(du -h client/static/js/libopaque.debug.js | cut -f1)
    
    echo ""
    echo -e "${GREEN}Build complete!${NC}"
    echo "  libopaque.js (minified): $MINIFIED_SIZE"
    echo "  libopaque.debug.js (unminified): $DEBUG_SIZE"
    echo ""
}

# Main execution
main() {
    # Ensure Emscripten is available (install if needed)
    if ! ensure_emscripten; then
        exit 1
    fi
    
    # Validate Makefile configuration
    validate_makefile
    
    # Build the WASM library
    build_wasm_library
    
    # Deploy to client directory
    deploy_wasm_files
}

# Run main function
main "$@"

exit 0
