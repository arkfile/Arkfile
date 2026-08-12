#!/bin/bash

# Build libopaque.js WASM library for browser-based OPAQUE authentication
# This script builds the JavaScript/WASM bindings for the libopaque library
# with automated Emscripten installation

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=build-config.sh
source "$SCRIPT_DIR/build-config.sh"

# Build from clean copies under BUILD_WASM so generated files and nested
# dependency checkouts never modify the pinned source submodules.
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LIBOPAQUE_WASM_SOURCE="$BUILD_WASM/source/libopaque"
LIBOPAQUE_JS_DIR="$LIBOPAQUE_WASM_SOURCE/js"
LIBSODIUM_JS_DIR="$LIBOPAQUE_JS_DIR/libsodium.js"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building libopaque.js WASM library${NC}"
echo "===================================="

# Build configuration - passed to make (not modifying submodule Makefile)
# LIBOPRFHOME: Path to liboprf source (relative to js/ directory)
# DEFINES: Compiler defines (-DTRACE for debug logging, empty for production)
#          IMPORTANT: Do NOT include -DNORANDOM - it makes OPAQUE deterministic (insecure)
#
# LIBOPAQUE_DEFINES env var controls trace logging:
#   - dev-reset.sh sets LIBOPAQUE_DEFINES="-DTRACE" for verbose debug output
#   - local-deploy.sh / test-deploy.sh leave it empty (no trace logging)
#   - Default: empty (production-safe, no cryptographic debug dumps in browser console)
LIBOPRFHOME_PATH="$REPO_ROOT/$LIBOPRF_SRC"
BUILD_DEFINES="${LIBOPAQUE_DEFINES:-}"
if [[ "$BUILD_DEFINES" == *"-DNORANDOM"* ]]; then
    echo "ERROR: Insecure -DNORANDOM build flag is forbidden" >&2
    exit 1
fi
if [[ "$BUILD_DEFINES" == *"-DTRACE"* ]] && [ "${ARKFILE_ALLOW_WASM_TRACE:-false}" != "true" ]; then
    echo "ERROR: OPAQUE trace logging requires the explicit development trace profile" >&2
    exit 1
fi

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

# Function to run git commands with proper user context (avoids "dubious ownership" errors)
run_git_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" git "$@"
    else
        git "$@"
    fi
}

# Resolve and export EMSDK_PYTHON before any ./emsdk invocation.
require_emsdk_python() {
    if ensure_emsdk_python; then
        print_status "INFO" "Using EMSDK_PYTHON=$EMSDK_PYTHON ($("$EMSDK_PYTHON" --version 2>&1))"
        return 0
    fi

    print_status "ERROR" "Python ${EMSDK_MIN_PYTHON_MAJOR}.${EMSDK_MIN_PYTHON_MINOR}+ is required for emsdk"
    print_emsdk_python_install_hint
    return 1
}

# Install Emscripten via emsdk (local installation - no sudo needed)
install_emscripten_emsdk() {
    print_status "INFO" "Installing Emscripten $EMSCRIPTEN_VERSION via emsdk..."

    if ! require_emsdk_python; then
        return 1
    fi

    local EMSDK_DIR="vendor/emsdk"
    
    # Clone emsdk if not already present
    if [ ! -d "$EMSDK_DIR" ]; then
        print_status "INFO" "Cloning emsdk repository..."
        if ! run_git_as_user clone https://github.com/emscripten-core/emsdk.git "$EMSDK_DIR"; then
            print_status "ERROR" "Failed to clone emsdk repository"
            return 1
        fi
    else
        print_status "INFO" "emsdk directory already exists, updating..."
        cd "$EMSDK_DIR"
        run_git_as_user fetch --all || true
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

    if ! require_emsdk_python; then
        return 1
    fi

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
                    print_status "ERROR" "Failed to activate pinned Emscripten $EMSCRIPTEN_VERSION"
                    return 1
                fi
            fi
            CURRENT_VER=$(emcc --version | head -n1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
            if [ "$CURRENT_VER" != "$EMSCRIPTEN_VERSION" ]; then
                print_status "ERROR" "Active Emscripten ($CURRENT_VER) does not match pin $EMSCRIPTEN_VERSION"
                return 1
            fi
            return 0
        fi
    fi
    
    # Priority 2: system emcc only when it matches the pinned emsdk version
    if command -v emcc >/dev/null 2>&1; then
        EMCC_VERSION=$(emcc --version | head -n1)
        CURRENT_VER=$(echo "$EMCC_VERSION" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
        if [ "$CURRENT_VER" = "$EMSCRIPTEN_VERSION" ]; then
            print_status "SUCCESS" "Found system Emscripten $EMCC_VERSION"
            return 0
        fi
        print_status "WARNING" "System Emscripten ($CURRENT_VER) differs from target ($EMSCRIPTEN_VERSION); preferring emsdk"
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

# Prepare exact, clean WASM sources without changing vendor_c.
prepare_wasm_source() {
    local opaque_commit
    opaque_commit=$(git -C "$REPO_ROOT/$VENDOR_C_LIBOPAQUE_DIR" rev-parse HEAD 2>/dev/null || true)
    if [ "$opaque_commit" != "$VENDOR_C_LIBOPAQUE_COMMIT" ]; then
        print_status "ERROR" "libopaque source does not match pinned commit $VENDOR_C_LIBOPAQUE_COMMIT"
        return 1
    fi

    print_status "INFO" "Preparing clean libopaque WASM source at $LIBOPAQUE_WASM_SOURCE..."
    rm -rf "$LIBOPAQUE_WASM_SOURCE"
    mkdir -p "$(dirname "$LIBOPAQUE_WASM_SOURCE")"
    # A local clone is required instead of git archive because upstream marks
    # /js as export-ignore, which would omit the WASM Makefile and wrappers.
    if ! run_git_as_user clone --no-checkout --no-hardlinks \
        "$REPO_ROOT/$VENDOR_C_LIBOPAQUE_DIR" "$LIBOPAQUE_WASM_SOURCE"; then
        print_status "ERROR" "Failed to clone pinned libopaque source"
        return 1
    fi
    if ! run_git_as_user -C "$LIBOPAQUE_WASM_SOURCE" checkout --detach "$VENDOR_C_LIBOPAQUE_COMMIT"; then
        print_status "ERROR" "Failed to check out pinned libopaque commit"
        return 1
    fi
    if [ "$(git -C "$LIBOPAQUE_WASM_SOURCE" rev-parse HEAD 2>/dev/null || true)" != "$VENDOR_C_LIBOPAQUE_COMMIT" ] ||
       [ ! -f "$LIBOPAQUE_JS_DIR/Makefile" ] ||
       [ ! -f "$LIBOPAQUE_JS_DIR/wrapper/libopaque-pre.js" ]; then
        print_status "ERROR" "Prepared libopaque source is incomplete or not pinned"
        return 1
    fi

    # libopaque includes these as <oprf/...>. The native build creates the same
    # staging directory in its source tree; reproduce it inside the clean WASM
    # clone without modifying either pinned vendor checkout.
    mkdir -p "$LIBOPAQUE_WASM_SOURCE/src/oprf"
    cp "$REPO_ROOT/$LIBOPRF_SRC/toprf.h" "$LIBOPAQUE_WASM_SOURCE/src/oprf/toprf.h"
    cp "$REPO_ROOT/$LIBOPRF_SRC/oprf.h" "$LIBOPAQUE_WASM_SOURCE/src/oprf/oprf.h"

    rm -rf "$LIBSODIUM_JS_DIR"
    print_status "INFO" "Cloning libsodium.js $LIBSODIUM_JS_VERSION..."
    if ! run_git_as_user clone --depth 1 --branch "$LIBSODIUM_JS_VERSION" \
        https://github.com/jedisct1/libsodium.js.git "$LIBSODIUM_JS_DIR"; then
        print_status "ERROR" "Failed to clone pinned libsodium.js"
        return 1
    fi
    if [ "$(git -C "$LIBSODIUM_JS_DIR" describe --tags --exact-match 2>/dev/null || true)" != "$LIBSODIUM_JS_VERSION" ] ||
       [ "$(git -C "$LIBSODIUM_JS_DIR" rev-parse HEAD 2>/dev/null || true)" != "$LIBSODIUM_JS_COMMIT" ]; then
        print_status "ERROR" "libsodium.js checkout does not match $LIBSODIUM_JS_VERSION @ $LIBSODIUM_JS_COMMIT"
        return 1
    fi
    if ! ensure_libsodium_js_submodules; then
        return 1
    fi
    print_status "SUCCESS" "Pinned WASM source prepared"
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

# Ensure nested libsodium submodule exists before patching or building.
ensure_libsodium_js_submodules() {
    local libsodium_js_dir="$LIBSODIUM_JS_DIR"

    if [ ! -d "$libsodium_js_dir" ]; then
        print_status "WARNING" "libsodium.js directory missing at $libsodium_js_dir"
        return 1
    fi

    print_status "INFO" "Ensuring libsodium.js git submodules are initialized..."
    if ! run_git_as_user -C "$libsodium_js_dir" submodule update --init --recursive; then
        print_status "ERROR" "Failed to initialize libsodium.js submodules"
        return 1
    fi
    return 0
}

# Patch legacy emscripten.sh flags only if the pinned source still contains them.
# Flags removed:
#   -sRUNNING_JS_OPTS=1              - removed from Emscripten, causes "not a valid option" error
#   --llvm-lto 1                     - no-op with upstream LLVM backend (Emscripten 2.x+)
#   -sAGGRESSIVE_VARIABLE_ELIMINATION=1 - removed from Emscripten
#   -sALIASING_FUNCTION_POINTERS=1   - removed from Emscripten
#   -sDISABLE_EXCEPTION_CATCHING=1   - now default behavior, flag removed
patch_emscripten_for_modern_emcc() {
    local EMSCRIPTEN_SH="$LIBSODIUM_JS_DIR/libsodium/dist-build/emscripten.sh"

    if [ ! -f "$EMSCRIPTEN_SH" ]; then
        print_status "WARNING" "emscripten.sh not found at $EMSCRIPTEN_SH (submodules may be missing)"
        return 1
    fi

    if ! grep -qE 'RUNNING_JS_OPTS|--llvm-lto 1|AGGRESSIVE_VARIABLE_ELIMINATION|ALIASING_FUNCTION_POINTERS|DISABLE_EXCEPTION_CATCHING' "$EMSCRIPTEN_SH"; then
        if grep -q "# ARKFILE-PATCHED" "$EMSCRIPTEN_SH"; then
            print_status "INFO" "emscripten.sh already patched for modern Emscripten"
        else
            print_status "INFO" "emscripten.sh already compatible with modern Emscripten"
        fi
        return 0
    fi

    print_status "INFO" "Patching emscripten.sh for Emscripten $EMSCRIPTEN_VERSION compatibility..."

    # Remove flags incompatible with the upstream LLVM backend.
    # Handle both "-sFLAG=1" and "-s FLAG=1" forms (libsodium uses the space form)
    sed -i \
        -e 's/-sRUNNING_JS_OPTS=1//g' \
        -e 's/-s RUNNING_JS_OPTS=1//g' \
        -e 's/--llvm-lto 1//g' \
        -e 's/-sAGGRESSIVE_VARIABLE_ELIMINATION=1//g' \
        -e 's/-s AGGRESSIVE_VARIABLE_ELIMINATION=1//g' \
        -e 's/-sALIASING_FUNCTION_POINTERS=1//g' \
        -e 's/-s ALIASING_FUNCTION_POINTERS=1//g' \
        -e 's/-sDISABLE_EXCEPTION_CATCHING=1//g' \
        -e 's/-s DISABLE_EXCEPTION_CATCHING=1//g' \
        "$EMSCRIPTEN_SH"

    if ! grep -q "# ARKFILE-PATCHED" "$EMSCRIPTEN_SH"; then
        sed -i '1s/^/# ARKFILE-PATCHED for modern Emscripten compatibility\n/' "$EMSCRIPTEN_SH"
    fi

    print_status "SUCCESS" "emscripten.sh patched for modern Emscripten"
    return 0
}

prepare_libsodium_js_for_build() {
    if ! patch_emscripten_for_modern_emcc; then
        exit 1
    fi
}

validate_wasm_runtime() {
    local artifact="$LIBOPAQUE_JS_DIR/dist/libopaque.debug.js"
    local harness="$REPO_ROOT/scripts/testing/opaque-wasm-interop-harness.js"

    if ! command -v bun >/dev/null 2>&1; then
        print_status "ERROR" "Bun is required to validate the libopaque WASM runtime"
        return 1
    fi
    if [ ! -f "$harness" ]; then
        print_status "ERROR" "OPAQUE WASM runtime harness is missing: $harness"
        return 1
    fi

    print_status "INFO" "Validating libopaque WASM memory access..."
    if ! printf '%s' '{"operation":"registration_request","password":"wasm runtime validation password"}' |
        bun "$harness" "$artifact" >/dev/null; then
        print_status "ERROR" "libopaque WASM runtime validation failed"
        return 1
    fi
    print_status "SUCCESS" "libopaque WASM runtime validation passed"
}

# Build the WASM library
build_wasm_library() {
    # Change to the libopaque.js directory
    cd "$LIBOPAQUE_JS_DIR"
    
    # Clean previous builds
    print_status "INFO" "Cleaning previous WASM builds..."
    make clean-libopaquejs >/dev/null 2>&1 || true
    rm -f libopaque.so  # Also clean the WASM shared library
    
    # Build libsodium.js sumo output (required by libopaque WASM link).
    # Check the final .js artifact, not libsodium.a alone -- emscripten.sh can leave
    # a static archive behind while the emcc JS link step still fails.
    local sumo_js="libsodium.js/libsodium/libsodium-js-sumo/lib/libsodium.js"
    if [ ! -f "$sumo_js" ]; then
        print_status "INFO" "Building libsodium.js dependency (this may take a few minutes)..."
        prepare_libsodium_js_for_build
        if ! make libsodium; then
            print_status "ERROR" "Failed to build libsodium.js"
            exit 1
        fi
        if [ ! -f "$sumo_js" ]; then
            print_status "ERROR" "libsodium.js build finished but $sumo_js is missing"
            exit 1
        fi
        print_status "SUCCESS" "libsodium.js built successfully"
    else
        print_status "INFO" "libsodium.js sumo build present, skipping"
        prepare_libsodium_js_for_build
    fi
    
    # WASM-compatible CFLAGS - same as upstream but without -march=native
    # The $(SODIUMDIR), $(LIBOPRFHOME), and $(DEFINES) are expanded by make
    WASM_LIBOPAQUE_CFLAGS='-I$(SODIUMDIR)/include -I$(LIBOPRFHOME) -Wall -O2 -g -fno-stack-protector -D_FORTIFY_SOURCE=2 -DHAVE_SODIUM_HKDF=1 -fasynchronous-unwind-tables -fpic -Werror=format-security -Werror=implicit-function-declaration -ftrapv $(DEFINES)'
    WASM_LIBOPAQUE_LDFLAGS='-g -L$(SODIUMDIR)/.libs -lsodium'
    
    # Step 1: Build libopaque.so with emcc (WASM shared library)
    # This is CRITICAL - we must build libopaque with emcc, not use the native libopaque.a from ../src/
    print_status "INFO" "Building libopaque.so with emcc (WASM shared library)..."
    print_status "INFO" "  LIBOPRFHOME=$LIBOPRFHOME_PATH"
    print_status "INFO" "  DEFINES=$BUILD_DEFINES"
    
    if ! make LIBOPRFHOME="$LIBOPRFHOME_PATH" DEFINES="$BUILD_DEFINES" \
        LIBOPAQUE_CFLAGS="$WASM_LIBOPAQUE_CFLAGS" LIBOPAQUE_LDFLAGS="$WASM_LIBOPAQUE_LDFLAGS" \
        SODIUM_NEWER_THAN_1_0_18=0 libopaque; then
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
    WASM_LDFLAGS='-L. -lopaque'
    # Emscripten 4.0.7+ no longer exposes memory views on Module by default.
    # libopaque's wrapper reads and writes WASM memory through Module.HEAPU8.
    WASM_EXPORTED_RUNTIME_METHODS='"cwrap", "getValue", "setValue", "stringToUTF8", "UTF8ToString", "HEAPU8"'
    
    if ! make LIBOPRFHOME="$LIBOPRFHOME_PATH" DEFINES="$BUILD_DEFINES" \
        LIBOPAQUE_CFLAGS="$WASM_LIBOPAQUE_CFLAGS" SODIUM_NEWER_THAN_1_0_18=0 \
        LDFLAGS="$WASM_LDFLAGS" EXPORTED_RUNTIME_METHODS="$WASM_EXPORTED_RUNTIME_METHODS" \
        libopaquejs; then
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

    if ! validate_wasm_runtime; then
        exit 1
    fi
    
    print_status "SUCCESS" "libopaque.js WASM library built successfully"
    
    # Return to project root
    cd "$REPO_ROOT"
}

# Copy built files to client directory
deploy_wasm_files() {
    cd "$REPO_ROOT"
    print_status "INFO" "Copying WASM library to client directory..."
    mkdir -p client/static/js
    cp "$LIBOPAQUE_JS_DIR/dist/libopaque.js" client/static/js/
    cp "$LIBOPAQUE_JS_DIR/dist/libopaque.debug.js" client/static/js/
    
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
    
    if ! prepare_wasm_source; then
        exit 1
    fi

    # Build the WASM library (patches emscripten.sh after submodule init, inside build)
    build_wasm_library
    
    # Deploy to client directory
    deploy_wasm_files
}

# Run main function
main "$@"

exit 0
