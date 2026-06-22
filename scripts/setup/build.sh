#!/bin/bash
set -e

# Source shared build configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/build-config.sh"

# Parse arguments
BUILD_ONLY=false
PRODUCTION_BUILD=false
for arg in "$@"; do
    case $arg in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --production)
            PRODUCTION_BUILD=true
            shift
            ;;
    esac
done

# Configuration
APP_NAME="arkfile"
BUILD_DIR="$BUILD_ROOT"  # Use BUILD_ROOT from build-config.sh
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BASE_DIR="/opt/arkfile"

# Colors for output 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# find_go_binary, fix_go_ownership, run_go_as_user are provided by build-config.sh

# Extended ownership fix for standalone build.sh usage (adds non-root recovery)
fix_vendor_ownership() {
    # Use shared function for the root-via-sudo case
    fix_go_ownership

    # Additional fix: when running as non-root, check if vendor is root-owned
    if [ "$EUID" -ne 0 ] && [ -d "vendor" ]; then
        VENDOR_OWNER=$(stat -c '%U' vendor 2>/dev/null || echo "unknown")
        CURRENT_USER=$(whoami)
        if [ "$VENDOR_OWNER" = "root" ] && [ "$CURRENT_USER" != "root" ] && [ -z "$SUDO_USER" ]; then
            echo -e "${YELLOW}Vendor directory owned by root, fixing with sudo...${NC}"
            sudo chown -R "$CURRENT_USER:$CURRENT_USER" vendor/ vendor_c/ go.mod go.sum 2>/dev/null || true
            [ -f ".vendor_cache" ] && sudo chown "$CURRENT_USER:$CURRENT_USER" .vendor_cache 2>/dev/null || true
        fi
    fi
    if [ "$EUID" -ne 0 ] && [ -d "vendor_c" ]; then
        VENDOR_C_OWNER=$(stat -c '%U' vendor_c 2>/dev/null || echo "unknown")
        CURRENT_USER=$(whoami)
        if [ "$VENDOR_C_OWNER" = "root" ] && [ "$CURRENT_USER" != "root" ] && [ -z "$SUDO_USER" ]; then
            echo -e "${YELLOW}vendor_c/ owned by root, fixing with sudo...${NC}"
            sudo chown -R "$CURRENT_USER:$CURRENT_USER" vendor_c/ 2>/dev/null || true
        fi
    fi
}

# Function to check Go version requirements from go.mod
check_go_version() {
    local required_version=$(grep '^go [0-9]' go.mod | awk '{print $2}')
    
    if [ -z "$required_version" ]; then
        echo -e "${YELLOW}[WARNING]  Cannot determine Go version requirement from go.mod${NC}"
        return 0
    fi
    
    local go_binary
    if ! go_binary=$(find_go_binary); then
        echo -e "${RED}[X] Go compiler not found in standard locations:${NC}"
        echo "   Checked: PATH, /usr/bin/go, /usr/local/bin/go, /usr/local/go/bin/go"
        echo "   Please install Go $required_version+ via package manager or from https://golang.org"
        echo ""
        echo "   Package manager installs:"
        echo "   - Debian/Ubuntu: apt install golang-go"
        echo "   - Alpine: apk add go"
        echo "   - Alma/RHEL: dnf install golang"
        echo "   - FreeBSD: pkg install go"
        echo "   - OpenBSD: pkg_add go"
        exit 1
    fi
    
    echo -e "${GREEN}[OK] Found Go at: $go_binary${NC}"
    
    local current_version=$("$go_binary" version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
    
    if [ -z "$current_version" ]; then
        echo -e "${RED}[X] Cannot determine Go version${NC}"
        exit 1
    fi
    
    # Convert versions to comparable format (remove dots and compare as integers)
    local current_num=$(echo $current_version | awk -F. '{printf "%d%02d%02d", $1, $2, $3}')
    local required_num=$(echo $required_version | awk -F. '{printf "%d%02d%02d", $1, $2, $3}')
    
    if [ "$current_num" -lt "$required_num" ]; then
        echo -e "${RED}[X] Go version $current_version is too old${NC}"
        echo -e "${YELLOW}Required: Go $required_version or later (from go.mod)${NC}"
        echo -e "${YELLOW}Current:  Go $current_version${NC}"
        echo
        echo -e "${BLUE}To update Go:${NC}"
        echo "1. Visit https://golang.org/dl/"
        echo "2. Download and install Go $required_version or later"
        echo "3. Or use your system's package manager"
        exit 1
    fi
    
    echo -e "${GREEN}[OK] Go version $current_version meets requirements (>= $required_version)${NC}"
    
    # Store the Go binary path for later use
    export GO_BINARY="$go_binary"

    # Pin the module toolchain so go install/run (e.g. govulncheck) matches go.mod.
    export GOTOOLCHAIN="go${required_version}+auto"
}

# Ensure required tools are installed and get Go binary path
check_go_version

# Ensure Go dependencies are properly resolved
if [ "$PRODUCTION_BUILD" = "true" ]; then
    echo -e "${YELLOW}Production mode: Verifying checked-in vendor directory and lockfile state...${NC}"
    # Verify vendor directory exists and hash matches
    VENDOR_CACHE=".vendor_cache"
    CURRENT_HASH=""
    CACHED_HASH=""
    if [ -f "go.sum" ]; then
        CURRENT_HASH=$(sha256sum go.sum | cut -d' ' -f1)
        CACHED_HASH=$(cat "$VENDOR_CACHE" 2>/dev/null || echo "")
    fi
    if [ ! -d "vendor" ] || [ "$CURRENT_HASH" != "$CACHED_HASH" ]; then
        echo -e "${RED}[X] Production build fail: Checked-in vendor/ dependencies are missing or out of sync with go.sum!${NC}" >&2
        echo -e "${RED}[X] Please run a development/test deploy or updates first to securely sync vendor/ directory under version control.${NC}" >&2
        exit 1
    fi
    echo -e "${GREEN}[OK] Checked-in vendor directory matches dependencies (no mutation allowed)${NC}"
else
    echo -e "${YELLOW}Checking Go module dependencies...${NC}"
    fix_vendor_ownership
    if ! run_go_as_user mod download; then
        echo -e "${YELLOW}Dependencies need updating, running go mod tidy...${NC}"
        run_go_as_user mod tidy
        fix_vendor_ownership
        if ! run_go_as_user mod download; then
            echo -e "${RED}Failed to resolve Go dependencies${NC}" >&2
            exit 1
        fi
    fi
    fix_vendor_ownership

    # Smart vendor directory sync - only when dependencies actually change
    echo -e "${YELLOW}Checking vendor directory consistency...${NC}"
    VENDOR_CACHE=".vendor_cache"
    CURRENT_HASH=""
    CACHED_HASH=""

    if [ -f "go.sum" ]; then
        CURRENT_HASH=$(sha256sum go.sum | cut -d' ' -f1)
        CACHED_HASH=$(cat "$VENDOR_CACHE" 2>/dev/null || echo "")
    fi

    if [ "$CURRENT_HASH" = "$CACHED_HASH" ] && [ -d "vendor" ]; then
        echo -e "${GREEN}[OK] Vendor directory matches go.sum, skipping sync (preserves compiled libraries)${NC}"
    else
        echo -e "${YELLOW}Dependencies changed or vendor missing, syncing vendor directory...${NC}"

        if ! run_go_as_user mod vendor; then
            echo -e "${YELLOW}Vendor sync failed, attempting to fix with go mod tidy...${NC}"
            run_go_as_user mod tidy
            fix_vendor_ownership
            if ! run_go_as_user mod vendor; then
                echo -e "${RED}Failed to sync vendor directory${NC}" >&2
                exit 1
            fi
        fi
        fix_vendor_ownership

        # Cache the successful sync (recompute hash since go mod tidy may have changed go.sum)
        CURRENT_HASH=$(sha256sum go.sum | cut -d' ' -f1)
        echo "$CURRENT_HASH" > "$VENDOR_CACHE"
        echo -e "${GREEN}[OK] Vendor directory synced with dependencies${NC}"
    fi
fi

# C sources live in vendor_c/ and are independent of go mod vendor.
echo -e "${YELLOW}Ensuring C vendor sources (vendor_c/)...${NC}"
if ! ./scripts/setup/ensure-vendor-c.sh; then
    echo -e "${RED}[X] Failed to provision C vendor sources${NC}"
    exit 1
fi

# Build static dependencies first
build_static_dependencies() {
    echo -e "${YELLOW}Building static dependencies...${NC}"
    
    # Fix permissions before building
    fix_vendor_ownership
    
    if ! ./scripts/setup/build-libopaque.sh; then
        echo -e "${RED}[X] Failed to build static dependencies${NC}"
        exit 1
    fi

    if ! ./scripts/setup/build-libfido2.sh; then
        echo -e "${RED}[X] Failed to build FIDO2 libraries for CLI${NC}"
        exit 1
    fi
    
    # Fix permissions after building
    fix_vendor_ownership
    
    echo -e "${GREEN}[OK] Static dependencies built successfully${NC}"
}

# Initialize and build C dependencies
echo -e "${YELLOW}Initializing and building C dependencies...${NC}"

# Check if we should skip C library building
if [ "${SKIP_C_LIBS}" = "true" ]; then
    echo -e "${GREEN}[OK] Skipping C library rebuild (libraries already exist)${NC}"
    
    # Verify static libraries still exist
    if [ ! -f "$LIBOPRF_A" ] || [ ! -f "$LIBOPAQUE_A" ]; then
        echo -e "${YELLOW}[WARNING]  Expected static libraries missing, forcing rebuild...${NC}"
        SKIP_C_LIBS="false"
    fi
fi

if [ "${SKIP_C_LIBS}" != "true" ]; then
    if [ -f "$OPAQUE_C_SOURCE" ] && [ -f "$OPRF_C_SOURCE" ]; then
        echo -e "${GREEN}[OK] Source code available, building static libraries...${NC}"
        build_static_dependencies
        echo -e "${GREEN}[OK] Static C dependencies built successfully${NC}"
    else
        echo -e "${RED}[X] C vendor sources missing after ensure-vendor-c.sh${NC}"
        echo "    Missing: $OPAQUE_C_SOURCE or $OPRF_C_SOURCE"
        exit 1
    fi
else
    echo -e "${GREEN}[OK] Using existing static C dependencies${NC}"
fi

# Run user and directory setup if needed (skip in --build-only mode, caller handles setup)
if [ "$BUILD_ONLY" = "false" ] && [ ! -d "${BASE_DIR}" ]; then
    echo -e "${YELLOW}Setting up initial directory structure...${NC}"
    ./scripts/setup/01-setup-users.sh
    ./scripts/setup/02-setup-directories.sh
fi

echo -e "${GREEN}Building ${APP_NAME} version ${VERSION}${NC}"

# Stop arkfile service if it's running to avoid "text file busy" errors
# Skip this step if --build-only is set (assumes caller handles service management)
if [ "$BUILD_ONLY" = "false" ] && systemctl is-active --quiet arkfile 2>/dev/null; then
    echo -e "${YELLOW}Stopping arkfile service for rebuild...${NC}"
    sudo systemctl stop arkfile
    # Wait a moment for the service to fully stop
    sleep 2
    
    # Kill any remaining arkfile processes
    if pgrep -f "arkfile" > /dev/null; then
        echo "Terminating remaining arkfile processes..."
        sudo pkill -f "arkfile" 2>/dev/null || true
        sleep 1
        
        # Force kill if still running
        if pgrep -f "arkfile" > /dev/null; then
            echo "Force killing remaining arkfile processes..."
            sudo pkill -9 -f "arkfile" 2>/dev/null || true
            sleep 1
        fi
    fi
    
    echo -e "${GREEN}Service stopped successfully${NC}"
fi

# Create build directory using shared helper
ensure_build_dir
echo -e "${GREEN}Building in directory: ${BUILD_DIR}${NC}"
echo -e "${GREEN}Source directory: $(pwd)${NC}"

# Build libopaque WASM/JS library
echo -e "${YELLOW}Building libopaque WASM/JS library...${NC}"

# Check if we should skip WASM library building (respects SKIP_C_LIBS flag)
if [ "${SKIP_C_LIBS}" = "true" ]; then
    # Verify WASM files exist in client directory
    if [ -f "client/static/js/libopaque.js" ] && [ -f "client/static/js/libopaque.debug.js" ]; then
        echo -e "${GREEN}[OK] Skipping WASM library rebuild (libraries already exist)${NC}"
    else
        echo -e "${YELLOW}[WARNING] Expected WASM libraries missing, forcing rebuild...${NC}"
        SKIP_C_LIBS="false"
    fi
fi

if [ "${SKIP_C_LIBS}" != "true" ]; then
    # Use the dedicated WASM build script (includes validation and proper error handling)
    if ! ./scripts/setup/build-libopaque-wasm.sh; then
        echo -e "${RED}[X] Failed to build libopaque WASM library${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] libopaque WASM library built successfully${NC}"
else
    echo -e "${GREEN}[OK] Using existing libopaque WASM library${NC}"
fi

# Build TypeScript Frontend (Mandatory)
echo "Building TypeScript frontend..."

# Find bun in various locations
BUN_CMD=""
# First check if bun is in PATH
if command -v bun >/dev/null 2>&1; then
    BUN_CMD="bun"
# Check current user's home directory
elif [ -f "$HOME/.bun/bin/bun" ]; then
    BUN_CMD="$HOME/.bun/bin/bun"
# Check root's home directory (when running under sudo)
elif [ -f "/root/.bun/bin/bun" ]; then
    BUN_CMD="/root/.bun/bin/bun"
# Check if SUDO_USER is set and try their home directory
elif [ -n "$SUDO_USER" ] && [ -f "/home/$SUDO_USER/.bun/bin/bun" ]; then
    BUN_CMD="/home/$SUDO_USER/.bun/bin/bun"
fi

if [ -z "$BUN_CMD" ]; then
    echo -e "${RED}[X] Bun is required for TypeScript compilation${NC}"
    echo -e "${YELLOW}Install Bun using: curl -fsSL https://bun.sh/install | bash${NC}"
    exit 1
fi

echo -e "${GREEN}Using Bun $(${BUN_CMD} --version) for TypeScript compilation${NC}"

# Set up PATH to include bun directory for package.json scripts
BUN_DIR=$(dirname "${BUN_CMD}")
export PATH="${BUN_DIR}:${PATH}"

pushd client/static/js > /dev/null

# Always ensure dependencies are up to date.
# --frozen-lockfile refuses to install if package.json
# and bun.lock disagree. This prevents supply-chain drift on every deploy and
# enforces that any dependency-version change must be a deliberate, reviewed
# update to both files.
echo "Ensuring Bun dependencies are installed (frozen lockfile)..."
${BUN_CMD} install --frozen-lockfile || {
    echo -e "${RED}[X] Failed to install dependencies (frozen lockfile)${NC}"
    echo -e "${YELLOW}If package.json was changed, regenerate bun.lock with:${NC}"
    echo -e "${YELLOW}  cd client/static/js && bun install${NC}"
    exit 1
}

# Verify source files exist
if [ ! -f "src/app.ts" ]; then
    echo -e "${RED}[X] Missing TypeScript source files${NC}"
    exit 1
fi

# Run TypeScript type checking
echo "Running TypeScript type checking..."
if ! ${BUN_CMD} run type-check; then
    echo -e "${RED}[X] TypeScript type checking failed - aborting build${NC}"
    exit 1
fi

# Check build cache
CACHE_FILE=".buildcache"
TS_HASH=$(find src -name "*.ts" -type f -exec sha256sum {} \; | sha256sum)
BUILD_HASH=$(cat ${CACHE_FILE} 2>/dev/null || true)

if [ "${TS_HASH}" = "${BUILD_HASH}" ] && [ -f "dist/app.js" ]; then
    echo -e "${GREEN}[OK] No TypeScript changes - skipping build${NC}"
else
    echo "Building TypeScript production bundle..."
    ${BUN_CMD} run build:prod || {
        echo -e "${RED}[X] TypeScript build failed${NC}"
        exit 1
    }
    
    # Verify build output
    if [ ! -f "dist/app.js" ] || [ ! -s "dist/app.js" ]; then
        echo -e "${RED}[X] Build output missing or empty${NC}"
        exit 1
    fi
    
    # Update build cache
    echo "${TS_HASH}" > ${CACHE_FILE}
fi

popd > /dev/null

# Validate final JS path
JS_PATH="client/static/js/dist/app.js"
if [ ! -f "${JS_PATH}" ]; then
    echo -e "${RED}[X] Missing built JavaScript file at ${JS_PATH}${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] TypeScript frontend built successfully${NC}"

# Build Go binaries (server static; CLI mixed linking for FIDO)
build_go_binaries_static() {
    echo -e "${YELLOW}Building Go binaries...${NC}"
    
    if [ ! -f "$LIBSODIUM_A" ]; then
        echo -e "${RED}[X] Vendored libsodium archive not found: $LIBSODIUM_A${NC}"
        echo -e "${YELLOW}    The build-libopaque.sh step should have produced this.${NC}"
        exit 1
    fi

    local REPO_ROOT
    REPO_ROOT="$(pwd)"
    local SERVER_LDFLAGS CLI_LDFLAGS
    SERVER_LDFLAGS="$(server_go_ldflags)"
    CLI_LDFLAGS="$(cli_go_ldflags)"
    local REPRO_FLAGS='-trimpath -buildvcs=false'
    
    local PROD_BUILD_FLAGS=""
    if [ "$PRODUCTION_BUILD" = "true" ]; then
        PROD_BUILD_FLAGS="-mod=vendor"
    fi

    # Server: OPAQUE only (no libfido2), fully static.
    export CGO_ENABLED=1
    export CGO_CFLAGS="$(opaque_cgo_cflags)"
    export CGO_LDFLAGS="$(opaque_cgo_ldflags "$REPO_ROOT")"

    echo "Building arkfile server..."
    # shellcheck disable=SC2086
    "$GO_BINARY" build -a $PROD_BUILD_FLAGS $REPRO_FLAGS -ldflags "$SERVER_LDFLAGS" -o ${BUILD_DIR}/${APP_NAME} .
    echo -e "${GREEN}[OK] arkfile server built${NC}"

    # CLI binaries: OPAQUE + vendored libfido2 for security-key MFA.
    if ! fido_cache_valid; then
        echo -e "${YELLOW}FIDO2 libraries missing or stale for this platform; building via build-libfido2.sh...${NC}"
        if ! ./scripts/setup/build-libfido2.sh; then
            echo -e "${RED}[X] Failed to build FIDO2 libraries for CLI${NC}"
            exit 1
        fi
    fi
    export CGO_CFLAGS="$(cli_fido_cgo_cflags)"
    # shellcheck disable=SC2086
    export CGO_LDFLAGS="$(cli_fido_cgo_ldflags "$REPO_ROOT")"
    
    echo "Building arkfile-client..."
    # shellcheck disable=SC2086
    "$GO_BINARY" build -a $PROD_BUILD_FLAGS $REPRO_FLAGS -ldflags "$CLI_LDFLAGS" -o ${BUILD_DIR}/arkfile-client ./cmd/arkfile-client
    echo -e "${GREEN}[OK] arkfile-client built${NC}"
    
    echo "Building arkfile-admin..."
    # shellcheck disable=SC2086
    "$GO_BINARY" build -a $PROD_BUILD_FLAGS $REPRO_FLAGS -ldflags "$CLI_LDFLAGS" -o ${BUILD_DIR}/arkfile-admin ./cmd/arkfile-admin
    echo -e "${GREEN}[OK] arkfile-admin built${NC}"
    
    export CGO_ENABLED=0
    unset CGO_CFLAGS CGO_LDFLAGS
    
    echo -e "${GREEN}[OK] Go binaries built (server static; CLI vendored C static + OS libs dynamic)${NC}"
}

# Verify server static linking and CLI mixed linking policy.
verify_built_binaries() {
    echo -e "${YELLOW}Verifying built binaries...${NC}"

    if ! verify_server_binary_static "${BUILD_DIR}/${APP_NAME}"; then
        exit 1
    fi

    if ! verify_cli_binary_linking "${BUILD_DIR}/arkfile-client"; then
        ldd "${BUILD_DIR}/arkfile-client" 2>&1 || true
        exit 1
    fi

    if ! verify_cli_binary_linking "${BUILD_DIR}/arkfile-admin"; then
        ldd "${BUILD_DIR}/arkfile-admin" 2>&1 || true
        exit 1
    fi
    
    echo -e "${GREEN}[OK] All binaries verified${NC}"
}

# Build main application binaries
echo "Building Go binaries..."
build_go_binaries_static

# Verify binary linking policy
verify_built_binaries

# Run Go vulnerability check and generate SBOM
run_security_audits_and_sbom() {
    echo -e "${YELLOW}Running security audits and generating SBOM...${NC}"
    
    # 1. Check and run govulncheck
    local govulncheck_bin=""
    local gopath
    gopath=$(run_go_as_user env GOPATH 2>/dev/null | tr -d '\r')

    if command -v govulncheck >/dev/null 2>&1; then
        govulncheck_bin="$(command -v govulncheck)"
    elif [ -n "$gopath" ] && [ -x "$gopath/bin/govulncheck" ]; then
        govulncheck_bin="$gopath/bin/govulncheck"
    else
        echo -e "${YELLOW}govulncheck not found. Attempting to install golang.org/x/vuln/cmd/govulncheck...${NC}"
        run_go_as_user install golang.org/x/vuln/cmd/govulncheck@latest || true
        gopath=$(run_go_as_user env GOPATH 2>/dev/null | tr -d '\r')
        if [ -n "$gopath" ] && [ -x "$gopath/bin/govulncheck" ]; then
            govulncheck_bin="$gopath/bin/govulncheck"
        fi
    fi

    if [ -z "$govulncheck_bin" ] || [ ! -x "$govulncheck_bin" ]; then
        echo -e "${YELLOW}[WARNING] govulncheck binary not available. Skipping Go vulnerability check.${NC}"
    else
        local govulncheck_failed=false
        local binary
        for binary in "${BUILD_DIR}/${APP_NAME}" "${BUILD_DIR}/arkfile-client" "${BUILD_DIR}/arkfile-admin"; do
            if [ ! -x "$binary" ]; then
                echo -e "${YELLOW}[WARNING] Skipping govulncheck; binary not found: $binary${NC}"
                continue
            fi
            echo "Running govulncheck ($govulncheck_bin) on $(basename "$binary")..."
            if ! GOTOOLCHAIN="${GOTOOLCHAIN:-local}" "$govulncheck_bin" -mode=binary "$binary"; then
                govulncheck_failed=true
            fi
        done

        if [ "$govulncheck_failed" = "true" ]; then
            echo -e "${RED}[X] govulncheck found known vulnerabilities in Go dependencies!${NC}"
            if [ "$PRODUCTION_BUILD" = "true" ]; then
                echo -e "${RED}[X] Failing production build due to Go dependency vulnerabilities.${NC}" >&2
                exit 1
            fi
        else
            echo -e "${GREEN}[OK] govulncheck passed successfully${NC}"
        fi
    fi

    # 2. Generate and save Software Bill of Materials (SBOM)
    echo "Generating SBOM..."
    local sbom_file="${BUILD_DIR}/sbom-dependencies.json"
    
    # Generate list of Go dependencies
    local go_deps
    go_deps=$("$GO_BINARY" list -m -json all 2>/dev/null | jq -s '.' 2>/dev/null || echo "[]")
    
    # Generate list of Bun dependencies
    local bun_deps="{}"
    if [ -f "client/static/js/package.json" ]; then
        bun_deps=$(cat client/static/js/package.json | jq '.dependencies + .devDependencies' 2>/dev/null || echo "{}")
    fi

    # Write unified SBOM json
    cat > "$sbom_file" <<EOF
{
  "sbom_version": "1.0",
  "build_time": "${BUILD_TIME}",
  "arkfile_version": "${VERSION}",
  "go_version": "$("$GO_BINARY" version)",
  "go_dependencies": ${go_deps},
  "bun_dependencies": ${bun_deps}
}
EOF
    echo -e "${GREEN}[OK] SBOM generated at: ${sbom_file}${NC}"
}

run_security_audits_and_sbom

# Copy static files directly to final client location (using BUILD_CLIENT from build-config.sh)
echo "Copying static files..."
mkdir -p "${BUILD_CLIENT}/static"
cp -r client/static/css "${BUILD_CLIENT}/static/" 2>/dev/null || true
cp -r client/static/errors "${BUILD_CLIENT}/static/" 2>/dev/null || true
cp client/static/*.html "${BUILD_CLIENT}/static/" 2>/dev/null || true
cp client/static/*.ico "${BUILD_CLIENT}/static/" 2>/dev/null || true

# Copy JS files (libopaque.js, etc.) but handle dist separately
mkdir -p "${BUILD_CLIENT_JS}"
cp client/static/js/*.js "${BUILD_CLIENT_JS}/" 2>/dev/null || true

# Explicitly copy TypeScript dist files (critical - these are the compiled app)
echo "Copying TypeScript build artifacts..."
if [ -d "client/static/js/dist" ] && [ -f "client/static/js/dist/app.js" ]; then
    mkdir -p "${BUILD_CLIENT_JS_DIST}"
    cp -v client/static/js/dist/app.js "${BUILD_CLIENT_JS_DIST}/"
    cp -v client/static/js/dist/app.js.map "${BUILD_CLIENT_JS_DIST}/" 2>/dev/null || true
    
    # Verify the copy succeeded
    if [ -f "${BUILD_CLIENT_JS_DIST}/app.js" ]; then
        echo -e "${GREEN}[OK] TypeScript dist files copied to build directory${NC}"
        ls -la "${BUILD_CLIENT_JS_DIST}/"
    else
        echo -e "${RED}[X] Failed to copy TypeScript dist files${NC}"
        exit 1
    fi
else
    echo -e "${RED}[X] TypeScript dist directory or app.js not found - build may have failed${NC}"
    echo "Expected: client/static/js/dist/app.js"
    ls -la client/static/js/dist/ 2>/dev/null || echo "dist directory does not exist"
    exit 1
fi

# Inject Subresource Integrity (SRI) attributes
#
# We compute sha384 of every shipped client-side script in the build tree and
# rewrite the deployed HTML copies under ${BUILD_CLIENT}/static/ to add
# `integrity="sha384-..." crossorigin="anonymous"` attributes on the matching
# <script> tags. Source HTML files in client/static/ are NOT modified; only the
# deployed copies under ${BUILD_CLIENT}/static/ carry the SRI attributes.
#
# Three shipped scripts cover both HTML files:
#   /js/libopaque.js     -- WASM OPAQUE library (index.html)
#   /js/dist/app.js      -- Compiled TypeScript bundle (index.html and shared.html)
#   /js/shared-init.js   -- Inline init for the share page (shared.html)
inject_sri_attributes() {
    echo -e "${YELLOW}Injecting SRI attributes into shipped HTML...${NC}"

    local libopaque_js="${BUILD_CLIENT_JS}/libopaque.js"
    local app_js="${BUILD_CLIENT_JS_DIST}/app.js"
    local shared_init_js="${BUILD_CLIENT_JS}/shared-init.js"

    for f in "$libopaque_js" "$app_js" "$shared_init_js"; do
        if [ ! -f "$f" ]; then
            echo -e "${RED}[X] SRI source missing: $f${NC}"
            exit 1
        fi
    done

    # `openssl dgst -sha384 -binary | openssl base64 -A` is the canonical SRI
    # hash format (sha384, base64-encoded, single-line). Fall back to printing
    # an error if openssl is absent.
    if ! command -v openssl >/dev/null 2>&1; then
        echo -e "${RED}[X] openssl is required for SRI injection${NC}"
        exit 1
    fi

    local libopaque_sri
    local app_sri
    local shared_init_sri
    libopaque_sri="sha384-$(openssl dgst -sha384 -binary "$libopaque_js" | openssl base64 -A)"
    app_sri="sha384-$(openssl dgst -sha384 -binary "$app_js" | openssl base64 -A)"
    shared_init_sri="sha384-$(openssl dgst -sha384 -binary "$shared_init_js" | openssl base64 -A)"

    echo "  libopaque.js     -> $libopaque_sri"
    echo "  dist/app.js      -> $app_sri"
    echo "  shared-init.js   -> $shared_init_sri"

    local index_html="${BUILD_CLIENT}/static/index.html"
    local shared_html="${BUILD_CLIENT}/static/shared.html"

    if [ ! -f "$index_html" ] || [ ! -f "$shared_html" ]; then
        echo -e "${RED}[X] Expected HTML files missing in build directory${NC}"
        exit 1
    fi

    # index.html: /js/libopaque.js, /js/dist/app.js
    sed -i \
        -e "s|<script src=\"/js/libopaque.js\"></script>|<script src=\"/js/libopaque.js\" integrity=\"${libopaque_sri}\" crossorigin=\"anonymous\"></script>|" \
        -e "s|<script src=\"/js/dist/app.js\"></script>|<script src=\"/js/dist/app.js\" integrity=\"${app_sri}\" crossorigin=\"anonymous\"></script>|" \
        "$index_html"

    # shared.html: /js/dist/app.js, /js/shared-init.js
    sed -i \
        -e "s|<script src=\"/js/dist/app.js\"></script>|<script src=\"/js/dist/app.js\" integrity=\"${app_sri}\" crossorigin=\"anonymous\"></script>|" \
        -e "s|<script src=\"/js/shared-init.js\"></script>|<script src=\"/js/shared-init.js\" integrity=\"${shared_init_sri}\" crossorigin=\"anonymous\"></script>|" \
        "$shared_html"

    # Verify each injection actually landed -- if any pattern failed to match,
    # the HTML still references the script without SRI and we want a hard fail
    # rather than a silently-unprotected deploy.
    if ! grep -q "integrity=\"${libopaque_sri}\"" "$index_html"; then
        echo -e "${RED}[X] SRI injection FAILED for libopaque.js in index.html${NC}"
        exit 1
    fi
    if ! grep -q "integrity=\"${app_sri}\"" "$index_html"; then
        echo -e "${RED}[X] SRI injection FAILED for dist/app.js in index.html${NC}"
        exit 1
    fi
    if ! grep -q "integrity=\"${app_sri}\"" "$shared_html"; then
        echo -e "${RED}[X] SRI injection FAILED for dist/app.js in shared.html${NC}"
        exit 1
    fi
    if ! grep -q "integrity=\"${shared_init_sri}\"" "$shared_html"; then
        echo -e "${RED}[X] SRI injection FAILED for shared-init.js in shared.html${NC}"
        exit 1
    fi

    echo -e "${GREEN}[OK] SRI attributes injected into index.html and shared.html${NC}"
}

inject_sri_attributes

# Setup error pages in webroot
echo "Setting up error pages..."
mkdir -p ${BUILD_DIR}/webroot/errors
cp client/static/errors/* ${BUILD_DIR}/webroot/errors/

# Copy systemd service files
echo "Copying systemd service files..."
mkdir -p ${BUILD_DIR}/systemd
cp systemd/* ${BUILD_DIR}/systemd/

# Create version file
echo "Creating version file..."
cat > ${BUILD_DIR}/version.json <<EOF
{
   "version": "${VERSION}",
   "buildTime": "${BUILD_TIME}",
   "staticLinking": true
}
EOF

# Arrange final artifacts in build directory
echo "Arranging final artifacts in build directory..."

# Binaries
mkdir -p "${BUILD_DIR}/bin"
mv "${BUILD_DIR}/${APP_NAME}" "${BUILD_DIR}/bin/"
mv "${BUILD_DIR}/arkfile-client" "${BUILD_DIR}/bin/"
mv "${BUILD_DIR}/arkfile-admin" "${BUILD_DIR}/bin/"

# Client files are already in the correct location (BUILD_CLIENT = BUILD_ROOT/client)
# No need to move - we copied directly to BUILD_CLIENT/static earlier

# Database files
mkdir -p "${BUILD_DIR}/database"
cp -r database/* "${BUILD_DIR}/database/"

# Systemd files are already in build/systemd

# version.json is already in build/

if [ "$BUILD_ONLY" = "true" ]; then
    echo -e "${GREEN}Build-only mode: Skipping deployment steps${NC}"
else
    # Deploy systemd service files to production location
    echo "Deploying systemd service files to ${BASE_DIR}/systemd/..."
    sudo install -d -m 755 -o arkfile -g arkfile "${BASE_DIR}/systemd"
    for file in "${BUILD_DIR}/systemd/"*; do
        sudo install -m 644 -o arkfile -g arkfile "$file" "${BASE_DIR}/systemd/"
    done

    # Deploy database schema to production location
    echo "Deploying database schema to ${BASE_DIR}/database/..."
    sudo install -d -m 755 -o arkfile -g arkfile "${BASE_DIR}/database"
    for file in "${BUILD_DIR}/database/"*; do
        sudo install -m 644 -o arkfile -g arkfile "$file" "${BASE_DIR}/database/"
    done

    # Deploy binaries to production location for key setup scripts
    echo "Deploying binaries to ${BASE_DIR}/bin/..."
    sudo install -d -m 755 -o root -g root "${BASE_DIR}/bin"
    for file in "${BUILD_DIR}/bin/"*; do
        sudo install -m 755 -o root -g root "$file" "${BASE_DIR}/bin/"
    done
fi

# Fix any root-owned files in the source tree (final cleanup)
if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
    echo -e "${YELLOW}Performing final ownership verification and cleanup...${NC}"
    
    # Fix ownership of key directories that may have been touched during build
    chown -R "$SUDO_USER:$SUDO_USER" client/static/js/ 2>/dev/null || true
    chown -R "$SUDO_USER:$SUDO_USER" vendor/ 2>/dev/null || true
    chown "$SUDO_USER:$SUDO_USER" go.mod go.sum 2>/dev/null || true
    [ -f ".vendor_cache" ] && chown "$SUDO_USER:$SUDO_USER" .vendor_cache 2>/dev/null || true
    [ -f "client/static/js/.buildcache" ] && chown "$SUDO_USER:$SUDO_USER" client/static/js/.buildcache 2>/dev/null || true
    
    echo -e "${GREEN}[OK] Source tree ownership restored to $SUDO_USER${NC}"
fi

echo -e "${GREEN}Build complete!${NC}"
echo "Build artifacts are ready in the '${BUILD_DIR}' directory."
