#!/bin/bash
# Shared build configuration for Arkfile
# Source this file in all build/setup/deploy scripts
#
# Usage: source "$(dirname "$0")/build-config.sh" 2>/dev/null || source scripts/setup/build-config.sh

# =============================================================================
# BUILD ROOT CONFIGURATION
# =============================================================================
# Default to /var/tmp/arkfile-build for POSIX compliance across all target OSs
# Override with ARKFILE_BUILD_DIR environment variable if needed
export BUILD_ROOT="${ARKFILE_BUILD_DIR:-/var/tmp/arkfile-build}"

# =============================================================================
# BUILD SUBDIRECTORIES
# =============================================================================
export BUILD_BIN="$BUILD_ROOT/bin"                    # Go binaries
export BUILD_CLIENT="$BUILD_ROOT/client"              # Client static files
export BUILD_CLIENT_JS="$BUILD_ROOT/client/static/js" # JavaScript/TypeScript
export BUILD_CLIENT_JS_DIST="$BUILD_ROOT/client/static/js/dist"  # TS compiled output
export BUILD_CLIBS="$BUILD_ROOT/c-libs"               # C static libraries (.a files)
export BUILD_WASM="$BUILD_ROOT/wasm"                  # WASM build output
export BUILD_EMSDK="$BUILD_ROOT/emsdk"                # Emscripten SDK
export BUILD_DATABASE="$BUILD_ROOT/database"          # Database schema copies
export BUILD_SYSTEMD="$BUILD_ROOT/systemd"            # Systemd service copies
export BUILD_WEBROOT="$BUILD_ROOT/webroot"            # Web root (error pages, etc.)

# =============================================================================
# SOURCE DIRECTORIES (in repo)
# =============================================================================
export SRC_CLIENT="client/static"
export SRC_CLIENT_JS="client/static/js"
export SRC_CLIENT_JS_SRC="client/static/js/src"
export SRC_DATABASE="database"
export SRC_SYSTEMD="systemd"
export SRC_VENDOR_STEF="vendor/stef"

# =============================================================================
# C LIBRARY PATHS
# =============================================================================
export LIBOPAQUE_A="$BUILD_CLIBS/libopaque.a"
export LIBOPRF_A="$BUILD_CLIBS/liboprf.a"
export NOISE_XK_A="$BUILD_CLIBS/liboprf-noiseXK.a"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Ensure build directory exists with correct ownership
ensure_build_dir() {
    mkdir -p "$BUILD_ROOT" "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_CLIBS" \
             "$BUILD_WASM" "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT" \
             "$BUILD_CLIENT_JS_DIST"
    
    # If running as root via sudo, set ownership to the original user
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$BUILD_ROOT" 2>/dev/null || true
    fi
    
    echo "[OK] Build directory ready: $BUILD_ROOT"
}

# Clean build directory (preserves C libs by default for faster rebuilds)
clean_build_dir() {
    local clean_all="${1:-false}"
    
    if [ "$clean_all" = "true" ] || [ "$clean_all" = "--all" ]; then
        echo "[CLEAN] Removing entire build directory: $BUILD_ROOT"
        rm -rf "$BUILD_ROOT"
    else
        echo "[CLEAN] Cleaning build artifacts (preserving C libs for faster rebuilds)"
        rm -rf "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_WASM" \
               "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT"
        rm -f "$BUILD_ROOT/version.json"
    fi
}

# Check if C libraries exist and are valid
c_libs_exist() {
    if [ -f "$LIBOPAQUE_A" ] && [ -f "$LIBOPRF_A" ]; then
        # Verify they're actual archive files
        if file "$LIBOPAQUE_A" | grep -q "archive" && \
           file "$LIBOPRF_A" | grep -q "archive"; then
            return 0
        fi
    fi
    return 1
}

# Check if WASM files exist
wasm_exists() {
    if [ -f "$BUILD_WASM/libopaque.js" ]; then
        return 0
    fi
    return 1
}

# Print build configuration (for debugging)
print_build_config() {
    echo "=== Arkfile Build Configuration ==="
    echo "BUILD_ROOT:      $BUILD_ROOT"
    echo "BUILD_BIN:       $BUILD_BIN"
    echo "BUILD_CLIENT:    $BUILD_CLIENT"
    echo "BUILD_CLIBS:     $BUILD_CLIBS"
    echo "BUILD_WASM:      $BUILD_WASM"
    echo "BUILD_EMSDK:     $BUILD_EMSDK"
    echo "==================================="
}

# Export the script directory for relative path resolution
if [ -n "$BASH_SOURCE" ]; then
    export BUILD_CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # POSIX fallback
    export BUILD_CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
