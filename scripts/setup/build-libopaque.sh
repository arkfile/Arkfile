#!/bin/bash

# Build script for libopaque and liboprf dependencies
# This script builds the Stef libopaque library for Arkfile

set -e

echo "=== Building libopaque and liboprf for Arkfile ==="
echo

# Check for libsodium dependency
if ! pkg-config --exists libsodium; then
    echo -e "\033[1;33m⚠️  libsodium development library not found.\033[0m"
    echo "This is required to compile the OPAQUE cryptography module."

    PACKAGE_MANAGER=""
    INSTALL_COMMAND=""
    PACKAGE_NAME=""

    if command -v apt-get &> /dev/null; then
        PACKAGE_MANAGER="apt-get"
        INSTALL_COMMAND="sudo apt-get update && sudo apt-get install -y"
        PACKAGE_NAME="libsodium-dev"
    elif command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
        INSTALL_COMMAND="sudo dnf install -y"
        PACKAGE_NAME="libsodium-devel"
    elif command -v yum &> /dev/null; then
        PACKAGE_MANAGER="yum"
        INSTALL_COMMAND="sudo yum install -y"
        PACKAGE_NAME="libsodium-devel"
    elif command -v zypper &> /dev/null; then
        PACKAGE_MANAGER="zypper"
        INSTALL_COMMAND="sudo zypper install -y"
        PACKAGE_NAME="libsodium-devel"
    else
        echo -e "\033[0;31m❌ Could not detect a supported package manager (apt, dnf, yum, zypper).\033[0m"
        echo "Please install the libsodium development package for your distribution manually."
        exit 1
    fi

    echo "Detected package manager: $PACKAGE_MANAGER"
    read -p "Attempt to install '$PACKAGE_NAME' now? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Running: $INSTALL_COMMAND $PACKAGE_NAME"
        eval "$INSTALL_COMMAND $PACKAGE_NAME" || (echo -e "\033[0;31m❌ Installation failed. Please install '$PACKAGE_NAME' manually.\033[0m"; exit 1)
    else
        echo -e "\033[0;31m❌ Build cannot continue without libsodium.\033[0m"; exit 1
    fi
fi

# Paths
OPRF_DIR="vendor/stef/liboprf/src"
OPAQUE_DIR="vendor/stef/libopaque/src"

# Build liboprf first
echo "Building liboprf..."
(
    cd "$OPRF_DIR"

    # Create oprf subdirectory with symlinks for header compatibility
    mkdir -p oprf
    ln -sf ../toprf.h oprf/toprf.h 2>/dev/null || true
    ln -sf ../oprf.h oprf/oprf.h 2>/dev/null || true

    # Build liboprf
    make -f makefile
    ln -sf liboprf.so liboprf.so.0 2>/dev/null || true

    # Build noise library
    cd noise_xk
    ln -sf liboprf-noiseXK.so liboprf-noiseXK.so.0 2>/dev/null || true
)
echo "✓ liboprf built successfully"

# Build libopaque
echo "Building libopaque..."
(
    cd "$OPAQUE_DIR"

    # Build common objects
    gcc -c -I../../liboprf/src -fPIC -O2 -g common.c -o common.o

    # Build main opaque implementation
    gcc -c -I../../liboprf/src -fPIC -O2 -g opaque.c -o opaque.o

    # Build aux HKDF implementation (for older libsodium compatibility)
    gcc -c -I../../liboprf/src -I. -fPIC -O2 -g aux_/kdf_hkdf_sha512.c -o aux_kdf.o

    # Create shared library with all components
    gcc -shared -fPIC -o libopaque.so common.o opaque.o aux_kdf.o -L../../liboprf/src -loprf -lsodium

    # Create versioned symlink
    ln -sf libopaque.so libopaque.so.0 2>/dev/null || true
)
echo "✓ libopaque built successfully"

echo
echo "=== Build Complete ==="
echo "Libraries built:"
echo "  - $(pwd)/$OPRF_DIR/liboprf.so ($(stat -c%s "$OPRF_DIR/liboprf.so" 2>/dev/null | numfmt --to=iec-i || echo "unknown") bytes)"
echo "  - $(pwd)/$OPAQUE_DIR/libopaque.so ($(stat -c%s "$OPAQUE_DIR/libopaque.so" 2>/dev/null | numfmt --to=iec-i || echo "unknown") bytes)"
echo
echo "To run tests:"
echo "  export LD_LIBRARY_PATH=\$(pwd)/$OPAQUE_DIR:\$(pwd)/$OPRF_DIR:\$(pwd)/$OPRF_DIR/noise_xk"
echo "  go test -v ./auth -run TestOpaque"
echo
echo "Or use the wrapper script:"
echo "  ./scripts/test-opaque.sh"
