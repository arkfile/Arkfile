#!/bin/bash
# Cross-platform static library build system

set -e

echo "Arkfile Static Library Build System"

# Robust cross-platform tool detection
find_pkg_config() {
    # Try multiple common names for pkg-config
    local pkg_config_candidates=(
        "pkg-config"
        "pkgconf" 
        "pkgconfig"
    )
    
    for cmd in "${pkg_config_candidates[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "$cmd"
            return 0
        fi
    done
    
    return 1
}

find_make_command() {
    # Try different make commands based on platform
    if command -v gmake >/dev/null 2>&1; then
        echo "gmake"
    elif command -v make >/dev/null 2>&1; then
        echo "make"
    else
        return 1
    fi
}

# Enhanced cross-platform system detection with fallbacks
detect_system_and_packages() {
    # Initialize variables
    OS=""
    PACKAGE_MANAGER=""
    INSTALL_CMD=""
    SODIUM_PKG=""
    LIBC=""
    PKG_CONFIG_PKG=""
    BUILD_TOOLS_PKG=""
    MAKE_CMD=""
    
    # Detect make command early
    if ! MAKE_CMD=$(find_make_command); then
        echo "[X] No make command found (tried: make, gmake)"
        exit 1
    fi
    
    # Enhanced OS detection with multiple methods
    if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "linux-musl"* ]] || [ -f /etc/os-release ]; then
        # Alpine Linux detection (multiple methods)
        if [ -f /etc/alpine-release ] || grep -q "Alpine" /etc/os-release 2>/dev/null; then
            OS="alpine"
            PACKAGE_MANAGER="apk"
            INSTALL_CMD="apk add --no-cache"
            SODIUM_PKG="libsodium-dev libsodium-static"
            PKG_CONFIG_PKG="pkgconf-dev"
            BUILD_TOOLS_PKG="gcc musl-dev make cmake"
            LIBC="musl"
        # Debian/Ubuntu detection (multiple methods)
        elif command -v apt-get >/dev/null || [ -f /etc/debian_version ] || grep -qE "(Ubuntu|Debian)" /etc/os-release 2>/dev/null; then
            OS="debian"
            PACKAGE_MANAGER="apt"
            INSTALL_CMD="apt-get update && apt-get install -y"
            SODIUM_PKG="libsodium-dev"
            PKG_CONFIG_PKG="pkg-config"
            BUILD_TOOLS_PKG="build-essential cmake"
            LIBC="glibc"
        # RHEL family detection (multiple methods)
        elif command -v dnf >/dev/null || command -v yum >/dev/null || [ -f /etc/redhat-release ] || grep -qE "(Red Hat|CentOS|AlmaLinux|Rocky)" /etc/os-release 2>/dev/null; then
            OS="rhel"
            # Prefer dnf over yum if available
            if command -v dnf >/dev/null; then
                PACKAGE_MANAGER="dnf"
                INSTALL_CMD="dnf install -y"
            else
                PACKAGE_MANAGER="yum"
                INSTALL_CMD="yum install -y"
            fi
            SODIUM_PKG="libsodium-devel"
            # Try pkgconf-devel first, fallback to pkg-config
            PKG_CONFIG_PKG="pkgconf-devel"
            BUILD_TOOLS_PKG="gcc make cmake"
            LIBC="glibc"
        # Arch Linux detection
        elif command -v pacman >/dev/null || [ -f /etc/arch-release ] || grep -q "Arch" /etc/os-release 2>/dev/null; then
            OS="arch"
            PACKAGE_MANAGER="pacman"
            INSTALL_CMD="pacman -S --noconfirm"
            SODIUM_PKG="libsodium"
            PKG_CONFIG_PKG="pkgconf"
            BUILD_TOOLS_PKG="gcc make cmake"
            LIBC="glibc"
        else
            echo "[X] Unknown Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "freebsd"* ]] || uname | grep -q FreeBSD; then
        OS="freebsd"
        PACKAGE_MANAGER="pkg"
        INSTALL_CMD="pkg install -y"
        SODIUM_PKG="libsodium"
        PKG_CONFIG_PKG="pkgconf"
        BUILD_TOOLS_PKG="gcc cmake"
        LIBC="freebsd-libc"
    elif [[ "$OSTYPE" == "openbsd"* ]] || uname | grep -q OpenBSD; then
        OS="openbsd"
        PACKAGE_MANAGER="pkg_add"
        INSTALL_CMD="pkg_add"
        SODIUM_PKG="libsodium"
        PKG_CONFIG_PKG="pkgconf"
        BUILD_TOOLS_PKG="gcc cmake"
        LIBC="openbsd-libc"
    elif [[ "$OSTYPE" == "netbsd"* ]] || uname | grep -q NetBSD; then
        OS="netbsd"
        PACKAGE_MANAGER="pkgin"
        INSTALL_CMD="pkgin -y install"
        SODIUM_PKG="libsodium"
        PKG_CONFIG_PKG="pkg-config"
        BUILD_TOOLS_PKG="gcc cmake"
        LIBC="netbsd-libc"
    else
        echo "[X] Unsupported platform: $OSTYPE ($(uname -s))"
        echo "Supported: Linux (Debian, RHEL, Alpine, Arch), FreeBSD, OpenBSD, NetBSD"
        exit 1
    fi
    
    echo "[INFO] Detected: $OS ($LIBC) with $PACKAGE_MANAGER using $MAKE_CMD"
}

# POSIX-compatible Go detection with fallbacks
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

# Go version verification
check_go_version() {
    local required_major=1
    local required_minor=24
    
    local go_binary
    if ! go_binary=$(find_go_binary); then
        echo "[X] Go compiler not found in standard locations:"
        echo "   Checked: PATH, /usr/bin/go, /usr/local/bin/go, /usr/local/go/bin/go"
        echo "   Please install Go 1.24+ via package manager or from https://golang.org"
        echo ""
        echo "   Package manager installs:"
        echo "   • Debian/Ubuntu: apt install golang-go"
        echo "   • Alpine: apk add go"
        echo "   • Alma/RHEL: dnf install golang"
        echo "   • FreeBSD: pkg install go"
        echo "   • OpenBSD: pkg_add go"
        exit 1
    fi
    
    echo "[OK] Found Go at: $go_binary"
    
    local current_version=$("$go_binary" version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    local current_major=$(echo $current_version | cut -d. -f1)
    local current_minor=$(echo $current_version | cut -d. -f2)
    
    if [ "$current_major" -lt "$required_major" ] || 
       ([ "$current_major" -eq "$required_major" ] && [ "$current_minor" -lt "$required_minor" ]); then
        echo "[X] Go version $current_version is too old"
        echo "Required: Go ${required_major}.${required_minor}+ (from go.mod)"
        echo "Please update Go to version 1.24 or later"
        exit 1
    fi
    
    echo "[OK] Go version $current_version meets requirements (>= ${required_major}.${required_minor})"
}

# Enhanced dependency installation with fallbacks
install_dependencies_universal() {
    echo "Installing dependencies on $OS..."
    
    # Build the full package list
    local packages="$SODIUM_PKG $PKG_CONFIG_PKG $BUILD_TOOLS_PKG"
    
    echo "Installing packages: $packages"
    
    case $PACKAGE_MANAGER in
        apk)
            if ! sudo $INSTALL_CMD $packages; then
                echo "[WARNING]  Primary package installation failed, trying alternatives..."
                # Try alternative package names for Alpine
                sudo $INSTALL_CMD libsodium-dev libsodium-static pkgconf-dev gcc musl-dev make cmake || {
                    echo "[X] Failed to install required packages on Alpine"
                    exit 1
                }
            fi
            ;;
        apt)
            if ! sudo $INSTALL_CMD $packages; then
                echo "[WARNING]  Primary package installation failed, trying alternatives..."
                # Try alternative package names for Debian/Ubuntu
                sudo $INSTALL_CMD libsodium-dev pkg-config build-essential cmake || {
                    echo "[X] Failed to install required packages on Debian/Ubuntu"
                    exit 1
                }
            fi
            ;;
        dnf|yum)
            if ! sudo $INSTALL_CMD $packages; then
                echo "[WARNING]  Primary package installation failed, trying alternatives..."
                # Try alternative package names for RHEL family
                if ! sudo $INSTALL_CMD libsodium-devel pkg-config gcc make cmake; then
                    # Final fallback - try pkgconfig instead of pkg-config
                    sudo $INSTALL_CMD libsodium-devel pkgconfig gcc make cmake || {
                        echo "[X] Failed to install required packages on RHEL family"
                        exit 1
                    }
                fi
            fi
            ;;
        pacman)
            if ! sudo $INSTALL_CMD $packages; then
                echo "[X] Failed to install required packages on Arch Linux"
                exit 1
            fi
            ;;
        pkg)
            if ! sudo $INSTALL_CMD $packages; then
                echo "[WARNING]  Primary package installation failed, trying alternatives..."
                # Try alternative package names for FreeBSD
                sudo $INSTALL_CMD libsodium pkgconf gcc cmake || {
                    echo "[X] Failed to install required packages on FreeBSD"
                    exit 1
                }
            fi
            ;;
        pkg_add)
            # OpenBSD pkg_add doesn't have good error handling, so try one by one
            echo "Installing packages individually on OpenBSD..."
            for pkg in $packages; do
                sudo $INSTALL_CMD "$pkg" || echo "[WARNING]  Failed to install $pkg, continuing..."
            done
            ;;
        pkgin)
            if ! sudo $INSTALL_CMD $packages; then
                echo "[X] Failed to install required packages on NetBSD"
                exit 1
            fi
            ;;
    esac
    
    echo "[OK] Dependencies installed for $OS"
}

# Build static libraries in vendor directories
build_static_libraries() {
    echo "[BUILD] Building static libraries in vendor/ directories..."
    
    # Detect pkg-config command
    local PKG_CONFIG_CMD
    if ! PKG_CONFIG_CMD=$(find_pkg_config); then
        echo "[X] No pkg-config command found (tried: pkg-config, pkgconf, pkgconfig)"
        exit 1
    fi
    echo "[OK] Using pkg-config command: $PKG_CONFIG_CMD"
    
    # Create temporary workaround for vendor makefile pkgconf dependency
    local TEMP_PKGCONF_LINK=""
    local NEED_PKGCONF_LINK=false
    
    # Check if vendor makefile needs pkgconf but we only have pkg-config
    if [ "$PKG_CONFIG_CMD" = "pkg-config" ] && ! command -v pkgconf >/dev/null 2>&1; then
        echo "[CONFIG]  Creating temporary pkgconf symlink for vendor makefile compatibility..."
        # Create symlink in /usr/local/bin which is typically in PATH
        TEMP_PKGCONF_LINK="/usr/local/bin/pkgconf"
        if sudo ln -sf "$(which pkg-config)" "$TEMP_PKGCONF_LINK"; then
            NEED_PKGCONF_LINK=true
            echo "[OK] Temporary pkgconf link created at $TEMP_PKGCONF_LINK"
            # Verify it's working
            if command -v pkgconf >/dev/null 2>&1; then
                echo "[OK] pkgconf symlink is accessible"
            else
                echo "[WARNING]  pkgconf symlink may not be in PATH, but should work for make"
            fi
        else
            echo "[WARNING]  Failed to create pkgconf symlink, trying alternative approach..."
            # Fallback: try creating in /tmp and modify PATH more aggressively
            TEMP_PKGCONF_LINK="/tmp/arkfile-bin-$$"
            mkdir -p "$TEMP_PKGCONF_LINK"
            ln -sf "$(which pkg-config)" "$TEMP_PKGCONF_LINK/pkgconf"
            export PATH="$TEMP_PKGCONF_LINK:$PATH"
            NEED_PKGCONF_LINK=true
            echo "[OK] Created temporary bin directory with pkgconf at $TEMP_PKGCONF_LINK"
        fi
    fi
    
    # Set universal optimization flags
    export CFLAGS="-O2 -fPIC"
    export LDFLAGS="-static"
    
    # Platform-specific optimizations (not preferences)
    case $LIBC in
        musl)
            # musl allows additional size optimizations
            CFLAGS="$CFLAGS -Os -fomit-frame-pointer"
            ;;
        glibc|freebsd-libc|openbsd-libc|netbsd-libc)
            # Standard flags work well
            ;;
    esac
    
    # Vendor directories
    OPRF_DIR="vendor/stef/liboprf/src"
    OPAQUE_DIR="vendor/stef/libopaque/src"
    
    # Build noise_xk library first (dependency for liboprf)
    echo "Building noise_xk static library..."
    if [ ! -d "$OPRF_DIR" ]; then
        echo "[X] liboprf source directory not found: $OPRF_DIR"
        echo "Attempting to initialize git submodules..."
        
        if ! git submodule update --init --recursive; then
            echo "[X] Failed to initialize git submodules"
            exit 1
        fi
        
        # Note: Ownership will be handled by calling script (build.sh)
        
        if [ ! -d "$OPRF_DIR" ]; then
            echo "[X] liboprf source directory still not found after submodule initialization"
            exit 1
        fi
        
        echo "[OK] Git submodules initialized successfully"
    fi
    
    cd "$OPRF_DIR/noise_xk"
    $MAKE_CMD clean || true
    # Store our CFLAGS and let noise_xk use its own optimized CFLAGS
    SAVED_CFLAGS="$CFLAGS"
    unset CFLAGS
    $MAKE_CMD AR=ar ARFLAGS=rcs liboprf-noiseXK.a
    
    # Build liboprf static library
    echo "Building liboprf static library..."
    cd ..
    $MAKE_CMD clean || true
    
    # Restore our CFLAGS and add noise_xk include paths
    export CFLAGS="$SAVED_CFLAGS"
    NOISE_INCLUDES="-Inoise_xk/include -Inoise_xk/include/karmel -Inoise_xk/include/karmel/minimal"
    
    # Get libsodium flags using detected pkg-config command
    SODIUM_CFLAGS=$($PKG_CONFIG_CMD --cflags libsodium)
    
    $MAKE_CMD CFLAGS="$CFLAGS $SODIUM_CFLAGS $NOISE_INCLUDES" \
              LDFLAGS="$LDFLAGS -Lnoise_xk" \
              AR=ar ARFLAGS=rcs liboprf.a
    
    # Build libopaque static library
    echo "Building libopaque static library..."
    cd "../../libopaque/src"
    $MAKE_CMD clean || true
    
    # Create oprf subdirectory and symlink headers for libopaque build
    mkdir -p oprf
    ln -sf ../../../liboprf/src/toprf.h oprf/toprf.h 2>/dev/null || true
    ln -sf ../../../liboprf/src/oprf.h oprf/oprf.h 2>/dev/null || true
    
    # Get libsodium flags using detected pkg-config command
    SODIUM_CFLAGS=$($PKG_CONFIG_CMD --cflags libsodium)
    
    $MAKE_CMD CFLAGS="$CFLAGS -I../../liboprf/src -I. $SODIUM_CFLAGS" \
              AR=ar ARFLAGS=rcs libopaque.a
    
    # Clean up temporary pkgconf symlink if we created one
    if [ "$NEED_PKGCONF_LINK" = true ] && [ -n "$TEMP_PKGCONF_LINK" ]; then
        echo "[CLEANUP] Cleaning up temporary pkgconf symlink..."
        if [ "$TEMP_PKGCONF_LINK" = "/usr/local/bin/pkgconf" ]; then
            sudo rm -f "$TEMP_PKGCONF_LINK"
        else
            # Remove temporary directory and its contents
            rm -rf "$TEMP_PKGCONF_LINK"
        fi
        echo "[OK] Temporary symlink cleaned up"
    fi
    
    echo "[OK] Static libraries built successfully on $OS"
}

# Verify libraries from project root
verify_static_libraries() {
    # The libraries should be exactly where we built them
    local OPRF_LIB="vendor/stef/liboprf/src/liboprf.a"
    local OPAQUE_LIB="vendor/stef/libopaque/src/libopaque.a"
    
    if [ -f "$OPRF_LIB" ] && [ -f "$OPAQUE_LIB" ]; then
        echo "[FILES] Static libraries verified:"
        ls -la "$OPRF_LIB" "$OPAQUE_LIB"
        return 0
    else
        echo "[X] Static library verification failed"
        [ ! -f "$OPRF_LIB" ] && echo "Missing: $OPRF_LIB"
        [ ! -f "$OPAQUE_LIB" ] && echo "Missing: $OPAQUE_LIB"
        return 1
    fi
}

# Main execution
main() {
    # Store the initial working directory
    local SCRIPT_START_DIR
    SCRIPT_START_DIR="$(pwd)"
    
    check_go_version
    detect_system_and_packages
    
    # Check for libsodium availability using detected pkg-config command
    local PKG_CONFIG_CMD
    if ! PKG_CONFIG_CMD=$(find_pkg_config); then
        echo "[WARNING]  No pkg-config command found, installing dependencies..."
        install_dependencies_universal
    else
        if ! $PKG_CONFIG_CMD --exists libsodium; then
            echo "[WARNING]  libsodium not found, attempting to install..."
            install_dependencies_universal
        else
            echo "[OK] libsodium found: $($PKG_CONFIG_CMD --modversion libsodium)"
        fi
    fi
    
    build_static_libraries
    
    # Return to the starting directory for verification
    cd "$SCRIPT_START_DIR"
    
    # Verify the libraries were built correctly
    if verify_static_libraries; then
        echo "[OK] Static library build completed successfully!"
    else
        echo "[X] Static library verification failed"
        exit 1
    fi
}

# Run main function
main "$@"
