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

# Configuration - Latest stable versions
EMSCRIPTEN_VERSION="3.1.74"
LIBSODIUM_JS_VERSION="0.7.16"

# Build configuration - passed to make (not modifying submodule Makefile)
# LIBOPRFHOME: Path to liboprf source (relative to js/ directory)
# DEFINES: Compiler defines (-DTRACE for debug logging, empty for production)
#          IMPORTANT: Do NOT include -DNORANDOM - it makes OPAQUE deterministic (insecure)
LIBOPRFHOME_PATH="../../liboprf/src"
BUILD_DEFINES="-DTRACE"

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

# Check if we're running under sudo (to avoid nested sudo calls)
is_running_as_root() {
    [ "$EUID" -eq 0 ]
}

# Install Emscripten via emsdk (local installation - no sudo needed)
install_emscripten_emsdk() {
    print_status "INFO" "Installing Emscripten $EMSCRIPTEN_VERSION via emsdk..."
    
    local EMSDK_DIR="vendor/emsdk"
    
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
        git fetch --all || true
        cd ../..
    fi
    
    cd "$EMSDK_DIR"
    
    # Check if the desired version is already installed and active
    if [ -f ".emscripten" ]; then
        CURRENT_VERSION=$(./emsdk list 2>/dev/null | grep -E "^\s*\*" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1 || echo "")
        if [ "$CURRENT_VERSION" = "$EMSCRIPTEN_VERSION" ]; then
            print_status "INFO" "Emscripten $EMSCRIPTEN_VERSION already installed and active"
            source ./emsdk_env.sh 2>/dev/null || true
            cd ../..
            return 0
        else
            print_status "INFO" "Current version ($CURRENT_VERSION) differs from target ($EMSCRIPTEN_VERSION), updating..."
        fi
    fi
    
    # Install and activate the target version
    print_status "INFO" "Installing Emscripten $EMSCRIPTEN_VERSION..."
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
        # Restore bun to PATH (emsdk clobbers user paths)
        [ -d "$HOME/.bun/bin" ] && export PATH="$HOME/.bun/bin:$PATH"
    else
        print_status "ERROR" "emsdk_env.sh not found"
        cd ../..
        return 1
    fi
    
    cd ../..
    
    # Verify emcc is now available
    if command -v emcc >/dev/null 2>&1; then
        print_status "SUCCESS" "Emscripten $EMSCRIPTEN_VERSION installed successfully via emsdk"
        return 0
    else
        print_status "ERROR" "Emscripten installation via emsdk failed"
        return 1
    fi
}

# Ensure Emscripten is available
ensure_emscripten() {
    print_status "INFO" "Checking for Emscripten..."
    
    # Priority 1: Check if local emsdk is already installed
    if [ -f "vendor/emsdk/emsdk_env.sh" ]; then
        print_status "INFO" "Found local emsdk installation, loading environment..."
        cd vendor/emsdk
        source ./emsdk_env.sh
        # Restore bun to PATH (emsdk clobbers user paths)
        [ -d "$HOME/.bun/bin" ] && export PATH="$HOME/.bun/bin:$PATH"
        cd ../..
        
        if command -v emcc >/dev/null 2>&1; then
            EMCC_VERSION=$(emcc --version | head -n1)
            print_status "SUCCESS" "Loaded Emscripten from local emsdk: $EMCC_VERSION"
            
            # Check if version matches target
            CURRENT_VER=$(echo "$EMCC_VERSION" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
            if [ "$CURRENT_VER" != "$EMSCRIPTEN_VERSION" ]; then
                print_status "WARNING" "Installed version ($CURRENT_VER) differs from target ($EMSCRIPTEN_VERSION)"
                print_status "INFO" "Updating to target version..."
                if ! install_emscripten_emsdk; then
                    print_status "WARNING" "Failed to update, continuing with current version"
                fi
            fi
            return 0
        fi
    fi
    
    # Priority 2: Check if system emcc is available
    if command -v emcc >/dev/null 2>&1; then
        EMCC_VERSION=$(emcc --version | head -n1)
        print_status "SUCCESS" "Found system Emscripten: $EMCC_VERSION"
        return 0
    fi
    
    # Priority 3: Install via emsdk (no sudo needed)
    print_status "WARNING" "Emscripten not found, installing via emsdk..."
    if install_emscripten_emsdk; then
        return 0
    fi
    
    # All installation methods failed
    print_status "ERROR" "Failed to install Emscripten"
    echo ""
    echo "Please install Emscripten manually:"
    echo "  https://emscripten.org/docs/getting_started/downloads.html"
    echo ""
    return 1
}

# Update libsodium.js to target version
update_libsodium_js() {
    local LIBSODIUM_DIR="vendor/stef/libopaque/js/libsodium.js"
    
    if [ ! -d "$LIBSODIUM_DIR" ]; then
        print_status "INFO" "libsodium.js not found, will be initialized during build"
        return 0
    fi
    
    print_status "INFO" "Checking libsodium.js version..."
    
    cd "$LIBSODIUM_DIR"
    
    # Fetch latest tags
    git fetch --tags 2>/dev/null || true
    
    # Check current version
    CURRENT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "unknown")
    
    if [ "$CURRENT_TAG" = "$LIBSODIUM_JS_VERSION" ]; then
        print_status "SUCCESS" "libsodium.js already at version $LIBSODIUM_JS_VERSION"
        cd ../../../../..
        return 0
    fi
    
    print_status "INFO" "Updating libsodium.js from $CURRENT_TAG to $LIBSODIUM_JS_VERSION..."
    
    # Checkout the target version
    if git checkout "$LIBSODIUM_JS_VERSION" 2>/dev/null; then
        print_status "SUCCESS" "libsodium.js updated to $LIBSODIUM_JS_VERSION"
    else
        print_status "WARNING" "Could not checkout $LIBSODIUM_JS_VERSION, using current version"
    fi
    
    cd ../../../../..
    return 0
}

# Validate that we're not using -DNORANDOM (security check)
validate_build_config() {
    print_status "INFO" "Validating build configuration..."
    
    if echo "$BUILD_DEFINES" | grep -q "NORANDOM"; then
        print_status "ERROR" "CRITICAL: BUILD_DEFINES contains -DNORANDOM!"
        echo ""
        echo -e "${RED}The -DNORANDOM flag:${NC}"
        echo -e "${RED}  1. Makes OPAQUE deterministic (insecure for production)${NC}"
        echo -e "${RED}  2. Changes protocol data structures (breaks backend compatibility)${NC}"
        echo ""
        exit 1
    fi
    
    print_status "SUCCESS" "Build configuration is secure (no -DNORANDOM)"
}

# Patch emscripten.sh for compatibility with Emscripten 3.1.74+
# The upstream libsodium (1.0.18) emscripten.sh uses flags that are incompatible
# with modern Emscripten's upstream LLVM backend. Rather than modifying the
# submodule directly, we apply a sed patch at build time.
# Flags removed:
#   -sRUNNING_JS_OPTS=1              - removed from Emscripten, causes "not a valid option" error
#   --llvm-lto 1                     - no-op with upstream LLVM backend (Emscripten 2.x+)
#   -sAGGRESSIVE_VARIABLE_ELIMINATION=1 - removed from Emscripten
#   -sALIASING_FUNCTION_POINTERS=1   - removed from Emscripten
#   -sDISABLE_EXCEPTION_CATCHING=1   - now default behavior, flag removed
patch_emscripten_for_modern_emcc() {
    local EMSCRIPTEN_SH="vendor/stef/libopaque/js/libsodium.js/libsodium/dist-build/emscripten.sh"

    if [ ! -f "$EMSCRIPTEN_SH" ]; then
        print_status "WARNING" "emscripten.sh not found, skipping patch"
        return 0
    fi

    # Check if already patched (idempotent)
    if grep -q "# ARKFILE-PATCHED" "$EMSCRIPTEN_SH"; then
        print_status "INFO" "emscripten.sh already patched for modern Emscripten"
        return 0
    fi

    print_status "INFO" "Patching emscripten.sh for Emscripten $EMSCRIPTEN_VERSION compatibility..."

    # Remove flags incompatible with upstream LLVM backend (Emscripten 3.x)
    sed -i \
        -e 's/-sRUNNING_JS_OPTS=1//g' \
        -e 's/--llvm-lto 1//g' \
        -e 's/-sAGGRESSIVE_VARIABLE_ELIMINATION=1//g' \
        -e 's/-sALIASING_FUNCTION_POINTERS=1//g' \
        -e 's/-sDISABLE_EXCEPTION_CATCHING=1//g' \
        -e '1s/^/# ARKFILE-PATCHED for Emscripten 3.x compatibility\n/' \
        "$EMSCRIPTEN_SH"

    print_status "SUCCESS" "emscripten.sh patched for modern Emscripten"
}

# Build the WASM library
build_wasm_library() {
    # Change to the libopaque.js directory
    cd vendor/stef/libopaque/js
    
    # Clean previous builds
    print_status "INFO" "Cleaning previous WASM builds..."
    make clean-libopaquejs >/dev/null 2>&1 || true
    rm -f libopaque.so  # Also clean the WASM shared library
    
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
    
    # WASM-compatible CFLAGS - same as upstream but without -march=native
    # The $(SODIUMDIR), $(LIBOPRFHOME), and $(DEFINES) are expanded by make
    WASM_LIBOPAQUE_CFLAGS='-I$(SODIUMDIR)/include -I$(LIBOPRFHOME) -Wall -O2 -g -fno-stack-protector -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fpic -Werror=format-security -Werror=implicit-function-declaration -ftrapv $(DEFINES)'
    
    # Step 1: Build libopaque.so with emcc (WASM shared library)
    # This is CRITICAL - we must build libopaque with emcc, not use the native libopaque.a from ../src/
    print_status "INFO" "Building libopaque.so with emcc (WASM shared library)..."
    print_status "INFO" "  LIBOPRFHOME=$LIBOPRFHOME_PATH"
    print_status "INFO" "  DEFINES=$BUILD_DEFINES"
    
    if ! make LIBOPRFHOME="$LIBOPRFHOME_PATH" DEFINES="$BUILD_DEFINES" LIBOPAQUE_CFLAGS="$WASM_LIBOPAQUE_CFLAGS" libopaque; then
        print_status "ERROR" "Failed to build libopaque.so (WASM shared library)"
        exit 1
    fi
    
    # Verify libopaque.so was built
    if [ ! -f "libopaque.so" ]; then
        print_status "ERROR" "libopaque.so not found after build"
        exit 1
    fi
    print_status "SUCCESS" "libopaque.so built with emcc"
    
    # Step 2: Build libopaque.js WASM library
    # Override LDFLAGS to link against local libopaque.so (not ../src/libopaque.a which is native x86)
    print_status "INFO" "Building libopaque.js WASM library..."
    print_status "INFO" "  LDFLAGS=-L. -lopaque (using local WASM libopaque.so)"
    
    # LDFLAGS must use -L. to link against the local libopaque.so we just built with emcc
    # The upstream Makefile has -L../src which would link against native x86 libopaque.a
    WASM_LDFLAGS='-L. -lopaque -Wl,-z,defs -Wl,-z,relro -Wl,-z,noexecstack'
    
    if ! make LIBOPRFHOME="$LIBOPRFHOME_PATH" DEFINES="$BUILD_DEFINES" LIBOPAQUE_CFLAGS="$WASM_LIBOPAQUE_CFLAGS" LDFLAGS="$WASM_LDFLAGS" libopaquejs; then
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
    echo "  Emscripten version: $EMSCRIPTEN_VERSION"
    echo "  libsodium.js version: $LIBSODIUM_JS_VERSION"
    echo "  libopaque.js (minified): $MINIFIED_SIZE"
    echo "  libopaque.debug.js (unminified): $DEBUG_SIZE"
    echo ""
}

# Main execution
main() {
    # Validate build configuration (security check)
    validate_build_config
    
    # Ensure Emscripten is available (install if needed - no sudo)
    if ! ensure_emscripten; then
        exit 1
    fi
    
    # Update libsodium.js to target version
    update_libsodium_js
    
    # Patch emscripten.sh for modern Emscripten compatibility (idempotent)
    patch_emscripten_for_modern_emcc
    
    # Build the WASM library
    build_wasm_library
    
    # Deploy to client directory
    deploy_wasm_files
}

# Run main function
main "$@"

exit 0
