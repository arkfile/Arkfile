#!/bin/bash
# Cross-platform static library build system

set -e

echo "=== Arkfile Static Library Build System ==="

# Cross-platform system detection
detect_system_and_packages() {
    if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "linux-musl"* ]]; then
        if [ -f /etc/alpine-release ]; then
            OS="alpine"
            PACKAGE_MANAGER="apk"
            INSTALL_CMD="apk add --no-cache"
            SODIUM_PKG="libsodium-dev libsodium-static"
            LIBC="musl"
        elif command -v apt-get >/dev/null; then
            OS="debian"
            PACKAGE_MANAGER="apt"
            INSTALL_CMD="apt-get update && apt-get install -y"
            SODIUM_PKG="libsodium-dev"
            LIBC="glibc"
        elif command -v dnf >/dev/null; then
            OS="alma"
            PACKAGE_MANAGER="dnf"
            INSTALL_CMD="dnf install -y"
            SODIUM_PKG="libsodium-devel"
            LIBC="glibc"
        fi
    elif [[ "$OSTYPE" == "freebsd"* ]]; then
        OS="freebsd"
        PACKAGE_MANAGER="pkg"
        INSTALL_CMD="pkg install -y"
        SODIUM_PKG="libsodium"
        LIBC="freebsd-libc"
    elif [[ "$OSTYPE" == "openbsd"* ]]; then
        OS="openbsd"
        PACKAGE_MANAGER="pkg_add"
        INSTALL_CMD="pkg_add"
        SODIUM_PKG="libsodium"
        LIBC="openbsd-libc"
    else
        echo "❌ Unsupported platform: $OSTYPE"
        exit 1
    fi
    
    echo "📋 Detected: $OS ($LIBC) with $PACKAGE_MANAGER"
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
        echo "❌ Go compiler not found in standard locations:"
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
    
    echo "✅ Found Go at: $go_binary"
    
    local current_version=$("$go_binary" version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    local current_major=$(echo $current_version | cut -d. -f1)
    local current_minor=$(echo $current_version | cut -d. -f2)
    
    if [ "$current_major" -lt "$required_major" ] || 
       ([ "$current_major" -eq "$required_major" ] && [ "$current_minor" -lt "$required_minor" ]); then
        echo "❌ Go version $current_version is too old"
        echo "Required: Go ${required_major}.${required_minor}+ (from go.mod)"
        echo "Please update Go to version 1.24 or later"
        exit 1
    fi
    
    echo "✅ Go version $current_version meets requirements (>= ${required_major}.${required_minor})"
}

# Universal dependency installation
install_dependencies_universal() {
    echo "📦 Installing dependencies on $OS..."
    
    case $PACKAGE_MANAGER in
        apk)
            sudo $INSTALL_CMD libsodium-dev libsodium-static gcc musl-dev make pkgconfig cmake
            ;;
        apt)
            sudo $INSTALL_CMD libsodium-dev build-essential pkg-config cmake
            ;;
        dnf)
            sudo $INSTALL_CMD libsodium-devel gcc make pkgconfig cmake
            ;;
        pkg)
            sudo $INSTALL_CMD libsodium gcc gmake pkgconf cmake
            ;;
        pkg_add)
            sudo $INSTALL_CMD libsodium gcc gmake pkgconf cmake
            ;;
    esac
    
    echo "✅ Dependencies installed for $OS"
}

# Build static libraries in vendor directories
build_static_libraries() {
    echo "🔨 Building static libraries in vendor/ directories..."
    
    # Set universal optimization flags
    export CFLAGS="-O2 -fPIC"
    export LDFLAGS="-static"
    
    # Platform-specific optimizations (not preferences)
    case $LIBC in
        musl)
            # musl allows additional size optimizations
            CFLAGS="$CFLAGS -Os -fomit-frame-pointer"
            ;;
        glibc|freebsd-libc|openbsd-libc)
            # Standard flags work well
            ;;
    esac
    
    # Vendor directories
    OPRF_DIR="vendor/stef/liboprf/src"
    OPAQUE_DIR="vendor/stef/libopaque/src"
    
    # Build noise_xk library first (dependency for liboprf)
    echo "Building noise_xk static library..."
    if [ ! -d "$OPRF_DIR" ]; then
        echo "❌ liboprf source directory not found: $OPRF_DIR"
        echo "Attempting to initialize git submodules..."
        
        if ! git submodule update --init --recursive; then
            echo "❌ Failed to initialize git submodules"
            exit 1
        fi
        
        # Fix ownership if running as root (preserve original user ownership)
        if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
            echo "Fixing git submodule ownership after root initialization..."
            chown -R "$SUDO_USER:$SUDO_USER" vendor/ 2>/dev/null || true
            echo "✅ Vendor directory ownership restored to $SUDO_USER"
        fi
        
        if [ ! -d "$OPRF_DIR" ]; then
            echo "❌ liboprf source directory still not found after submodule initialization"
            exit 1
        fi
        
        echo "✅ Git submodules initialized successfully"
    fi
    
    cd "$OPRF_DIR/noise_xk"
    make clean || true
    # Store our CFLAGS and let noise_xk use its own optimized CFLAGS
    SAVED_CFLAGS="$CFLAGS"
    unset CFLAGS
    make AR=ar ARFLAGS=rcs liboprf-noiseXK.a
    
    # Build liboprf static library
    echo "Building liboprf static library..."
    cd ..
    make clean || true
    
    # Restore our CFLAGS and add noise_xk include paths
    export CFLAGS="$SAVED_CFLAGS"
    NOISE_INCLUDES="-Inoise_xk/include -Inoise_xk/include/karmel -Inoise_xk/include/karmel/minimal"
    make CFLAGS="$CFLAGS $(pkg-config --cflags libsodium) $NOISE_INCLUDES" \
         LDFLAGS="$LDFLAGS -Lnoise_xk" \
         AR=ar ARFLAGS=rcs liboprf.a
    
    # Build libopaque static library
    echo "Building libopaque static library..."
    cd "../../libopaque/src"
    make clean || true
    make CFLAGS="$CFLAGS -I../../liboprf/src $(pkg-config --cflags libsodium)" \
         AR=ar ARFLAGS=rcs libopaque.a
    
    echo "✅ Static libraries built successfully on $OS"
}

# Verify libraries from project root
verify_static_libraries() {
    # The libraries should be exactly where we built them
    local OPRF_LIB="vendor/stef/liboprf/src/liboprf.a"
    local OPAQUE_LIB="vendor/stef/libopaque/src/libopaque.a"
    
    if [ -f "$OPRF_LIB" ] && [ -f "$OPAQUE_LIB" ]; then
        echo "📁 Static libraries verified:"
        ls -la "$OPRF_LIB" "$OPAQUE_LIB"
        return 0
    else
        echo "❌ Static library verification failed"
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
    
    # Check for libsodium availability
    if ! pkg-config --exists libsodium; then
        echo "⚠️  libsodium not found, attempting to install..."
        install_dependencies_universal
    else
        echo "✅ libsodium found: $(pkg-config --modversion libsodium)"
    fi
    
    build_static_libraries
    
    # Return to the starting directory for verification
    cd "$SCRIPT_START_DIR"
    
    # Verify the libraries were built correctly
    if verify_static_libraries; then
        echo "🎉 Static library build completed successfully!"
    else
        echo "❌ Static library verification failed"
        exit 1
    fi
}

# Run main function
main "$@"
