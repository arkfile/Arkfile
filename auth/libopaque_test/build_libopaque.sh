#!/bin/bash

# Build script for libopaque with proper include paths

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENDOR_DIR="$SCRIPT_DIR/../../vendor/stef"
LIBOPRF_DIR="$VENDOR_DIR/liboprf"
LIBOPAQUE_DIR="$VENDOR_DIR/libopaque"

echo "Building libopaque with custom include paths..."

cd "$LIBOPAQUE_DIR/src"

# Build libopaque with the correct include paths
make CFLAGS="-march=native -Wall -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables \
  -Werror=format-security -Werror=implicit-function-declaration \
  -Warray-bounds -fsanitize=bounds -fsanitize-undefined-trap-on-error -ftrapv \
  -std=c99 -fpic -Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now \
  -fsanitize=signed-integer-overflow -fsanitize-undefined-trap-on-error \
  -fcf-protection=full -fstack-clash-protection -Iaux_ \
  -I$LIBOPRF_DIR/src -I$LIBOPRF_DIR/src/oprf" \
  OPRFHOME="$LIBOPRF_DIR/src"

echo "Build complete!"
