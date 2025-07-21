#!/bin/bash

# Build script for libopaque and liboprf dependencies
# This script builds the Stef libopaque library for Arkfile

set -e

echo "=== Building libopaque and liboprf for Arkfile ==="
echo

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
