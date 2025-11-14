#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
BUILD_DIR="build"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BASE_DIR="/opt/arkfile"

# Colors for output 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
        echo "   • Debian/Ubuntu: apt install golang-go"
        echo "   • Alpine: apk add go"
        echo "   • Alma/RHEL: dnf install golang"
        echo "   • FreeBSD: pkg install go"
        echo "   • OpenBSD: pkg_add go"
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
}

# Function to fix vendor directory ownership
fix_vendor_ownership() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        echo -e "${YELLOW}Fixing vendor directory ownership (running as root)...${NC}"
        chown -R "$SUDO_USER:$SUDO_USER" vendor/ 2>/dev/null || true
        chown -R "$SUDO_USER:$SUDO_USER" go.mod go.sum 2>/dev/null || true
        [ -f ".vendor_cache" ] && chown "$SUDO_USER:$SUDO_USER" .vendor_cache 2>/dev/null || true
        echo -e "${GREEN}[OK] Vendor directory ownership restored to $SUDO_USER${NC}"
    elif [ "$EUID" -ne 0 ] && [ -d "vendor" ]; then
        # Check if vendor directory has wrong ownership
        VENDOR_OWNER=$(stat -c '%U' vendor 2>/dev/null || echo "unknown")
        CURRENT_USER=$(whoami)
        if [ "$VENDOR_OWNER" = "root" ] && [ "$CURRENT_USER" != "root" ]; then
            echo -e "${YELLOW}Vendor directory owned by root, fixing with sudo...${NC}"
            sudo chown -R "$CURRENT_USER:$CURRENT_USER" vendor/ 2>/dev/null || true
            sudo chown -R "$CURRENT_USER:$CURRENT_USER" go.mod go.sum 2>/dev/null || true
            [ -f ".vendor_cache" ] && sudo chown "$CURRENT_USER:$CURRENT_USER" .vendor_cache 2>/dev/null || true
            echo -e "${GREEN}[OK] Vendor directory ownership restored to $CURRENT_USER${NC}"
        fi
    fi
}

# Function to run Go commands with proper user context
run_go_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H "$GO_BINARY" "$@"
    else
        "$GO_BINARY" "$@"
    fi
}

# Ensure required tools are installed and get Go binary path
check_go_version

# Ensure Go dependencies are properly resolved
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
    
    # CRITICAL: Backup C library submodules before Go vendor sync
    C_LIBS_BACKUP=""
    if [ -d "vendor/stef" ]; then
        C_LIBS_BACKUP=$(mktemp -d)
        echo -e "${YELLOW}Backing up C libraries to: $C_LIBS_BACKUP${NC}"
        cp -r vendor/stef "$C_LIBS_BACKUP/" 2>/dev/null || true
    fi
    
    if ! run_go_as_user mod vendor; then
        echo -e "${YELLOW}Vendor sync failed, attempting to fix missing dependencies...${NC}"
        # Try to get missing dependencies that might not be in go.sum
        run_go_as_user get -d ./...
        fix_vendor_ownership
        if ! run_go_as_user mod vendor; then
            echo -e "${RED}Failed to sync vendor directory${NC}" >&2
            exit 1
        fi
    fi
    fix_vendor_ownership
    
    # CRITICAL: Restore C library submodules after Go vendor sync
    if [ -n "$C_LIBS_BACKUP" ] && [ -d "$C_LIBS_BACKUP/stef" ]; then
        echo -e "${YELLOW}Restoring C libraries from backup...${NC}"
        mkdir -p vendor/stef
        cp -r "$C_LIBS_BACKUP/stef/"* vendor/stef/ 2>/dev/null || true
        rm -rf "$C_LIBS_BACKUP"
        echo -e "${GREEN}[OK] C libraries restored after vendor sync${NC}"
    else
        echo -e "${YELLOW}No C libraries to restore - will initialize via submodules${NC}"
    fi
    
    # Cache the successful sync
    if [ -n "$CURRENT_HASH" ]; then
        echo "$CURRENT_HASH" > "$VENDOR_CACHE"
    fi
    echo -e "${GREEN}[OK] Vendor directory synced with dependencies${NC}"
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
    if [ ! -f "vendor/stef/liboprf/src/liboprf.a" ] || [ ! -f "vendor/stef/libopaque/src/libopaque.a" ]; then
        echo -e "${YELLOW}[WARNING]  Expected static libraries missing, forcing rebuild...${NC}"
        SKIP_C_LIBS="false"
    fi
fi

if [ "${SKIP_C_LIBS}" != "true" ]; then
    # Smart source code detection - check for key source files instead of .git directories
    OPAQUE_SOURCE="vendor/stef/libopaque/src/opaque.c"
    OPRF_SOURCE="vendor/stef/liboprf/src/oprf.c"
    
    if [ -f "$OPAQUE_SOURCE" ] && [ -f "$OPRF_SOURCE" ]; then
        echo -e "${GREEN}[OK] Source code available, building static libraries...${NC}"
        
        # Use specialized build script with static linking
        build_static_dependencies
        
        echo -e "${GREEN}[OK] Static C dependencies built successfully${NC}"
    else
        echo -e "${YELLOW}[WARNING] Source code missing, checking for source directory availability...${NC}"
        echo "Missing files: $OPAQUE_SOURCE or $OPRF_SOURCE"
        
        # Initialize git submodules with proper ownership preservation
        if ! git submodule update --init --recursive; then
            echo -e "${RED}[X] Failed to initialize git submodules${NC}"
            exit 1
        fi
        
    # Fix ownership immediately after any root operations
    fix_vendor_ownership
        echo -e "${GREEN}[OK] Git submodules initialized${NC}"
        
        # Verify source files are now available
        if [ -f "$OPAQUE_SOURCE" ] && [ -f "$OPRF_SOURCE" ]; then
            echo "Building static libopaque and liboprf after source setup..."
            build_static_dependencies
            echo -e "${GREEN}[OK] Static C dependencies built successfully${NC}"
        else
            echo -e "${RED}[X] Source files still missing after source setup${NC}"
            exit 1
        fi
    fi
else
    echo -e "${GREEN}[OK] Using existing static C dependencies${NC}"
fi

# Run user and directory setup if needed
if [ ! -d "${BASE_DIR}" ]; then
    echo -e "${YELLOW}Setting up initial directory structure...${NC}"
    ./scripts/setup/01-setup-users.sh
    ./scripts/setup/02-setup-directories.sh
fi

echo -e "${GREEN}Building ${APP_NAME} version ${VERSION}${NC}"

# Stop arkfile service if it's running to avoid "text file busy" errors
if systemctl is-active --quiet arkfile 2>/dev/null; then
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

# Create build directory
mkdir -p ${BUILD_DIR}
echo -e "${GREEN}Building in directory: $(pwd)${NC}"

# Build libopaque WASM/JS from vendor submodule
echo -e "${YELLOW}Building libopaque WASM/JS from vendor submodule...${NC}"

# Check if emscripten is available
if ! command -v emcc >/dev/null 2>&1; then
    echo -e "${RED}[X] Emscripten (emcc) is required to build libopaque.js${NC}"
    echo -e "${YELLOW}Install Emscripten: https://emscripten.org/docs/getting_started/downloads.html${NC}"
    exit 1
fi

# Build libopaque.js in the vendor submodule
cd vendor/stef/libopaque/js

# Check if node_modules exists, install if needed
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies for libopaque.js build..."
    npm install || {
        echo -e "${RED}[X] Failed to install npm dependencies for libopaque.js${NC}"
        exit 1
    }
fi

# Build libopaque.js
echo "Building libopaque.js and libopaque.debug.js..."
if ! make libopaquejs; then
    echo -e "${RED}[X] Failed to build libopaque.js${NC}"
    exit 1
fi

# Verify build output
if [ ! -f "dist/libopaque.js" ] || [ ! -f "dist/libopaque.debug.js" ]; then
    echo -e "${RED}[X] libopaque.js build output missing${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] libopaque.js built successfully${NC}"

# Copy to client static directory
echo "Copying libopaque.js files to client/static/js/..."
cd ../../../../
cp vendor/stef/libopaque/js/dist/libopaque.js client/static/js/
cp vendor/stef/libopaque/js/dist/libopaque.debug.js client/static/js/

echo -e "${GREEN}[OK] libopaque.js files copied to client/static/js/${NC}"

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

cd client/static/js

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing Bun dependencies..."
    ${BUN_CMD} install || {
        echo -e "${RED}[X] Failed to install dependencies${NC}"
        exit 1
    }
fi

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

cd ../../..

# Validate final JS path
JS_PATH="client/static/js/dist/app.js"
if [ ! -f "${JS_PATH}" ]; then
    echo -e "${RED}[X] Missing built JavaScript file at ${JS_PATH}${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] TypeScript frontend built successfully${NC}"

# Build Go binaries with static linking
build_go_binaries_static() {
    echo -e "${YELLOW}Building Go binaries with static linking...${NC}"
    
    # Build main arkfile server with CGO (needs libopaque)
    echo "Building arkfile server with CGO static linking..."
    export CGO_ENABLED=1
    export CGO_CFLAGS="-I./vendor/stef/libopaque/src -I./vendor/stef/liboprf/src"
    export CGO_LDFLAGS="-L./vendor/stef/libopaque/src -L./vendor/stef/liboprf/src -lopaque -loprf"
    export CGO_LDFLAGS="$CGO_LDFLAGS $(pkg-config --libs --static libsodium)"
    
    "$GO_BINARY" build -a -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -extldflags '-static'" -o ${BUILD_DIR}/${APP_NAME} .
    echo -e "${GREEN}[OK] arkfile server built with CGO static linking${NC}"
    
    # Build Go utility tools without CGO (pure static)
    echo "Building Go utility tools with pure static linking..."
    export CGO_ENABLED=0
    unset CGO_CFLAGS CGO_LDFLAGS
    
    echo "Building cryptocli..."
    "$GO_BINARY" build -a -ldflags '-extldflags "-static"' -o ${BUILD_DIR}/cryptocli ./cmd/cryptocli
    
    echo "Building arkfile-client..."
    "$GO_BINARY" build -a -ldflags '-extldflags "-static"' -o ${BUILD_DIR}/arkfile-client ./cmd/arkfile-client
    
    echo "Building arkfile-admin..."
    "$GO_BINARY" build -a -ldflags '-extldflags "-static"' -o ${BUILD_DIR}/arkfile-admin ./cmd/arkfile-admin
    
    echo -e "${GREEN}[OK] Go utility tools built with pure static linking${NC}"
    echo -e "${GREEN}[OK] All Go binaries built with static linking${NC}"
}

# Verify static binaries
verify_static_binaries() {
    echo -e "${YELLOW}Verifying static binaries...${NC}"
    
    for binary in ${BUILD_DIR}/${APP_NAME} ${BUILD_DIR}/cryptocli ${BUILD_DIR}/arkfile-client ${BUILD_DIR}/arkfile-admin; do
        if [ -f "$binary" ]; then
            # Use appropriate verification for platform
            if [[ "$OSTYPE" == "freebsd"* ]] || [[ "$OSTYPE" == "openbsd"* ]]; then
                # BSD systems use different tools
                if file "$binary" | grep -q "statically linked"; then
                    echo -e "${GREEN}[OK] $(basename $binary): Static binary verified${NC}"
                else
                    echo -e "${RED}[X] $(basename $binary): Dynamic linking detected${NC}"
                    exit 1
                fi
            else
                # Linux systems (includes Alpine, Debian, Alma, etc.)
                if ldd "$binary" 2>&1 | grep -q "not a dynamic executable"; then
                    echo -e "${GREEN}[OK] $(basename $binary): Static binary verified${NC}"
                else
                    echo -e "${RED}[X] $(basename $binary): Dynamic linking detected${NC}"
                    ldd "$binary" 2>&1 || true
                    exit 1
                fi
            fi
        else
            echo -e "${RED}[X] Binary not found: $binary${NC}"
            exit 1
        fi
    done
    
    echo -e "${GREEN}[OK] All binaries verified as static${NC}"
}

# Build main application with static linking
echo "Building Go binaries with static linking..."
build_go_binaries_static

# Verify static linking
verify_static_binaries

# Copy static files
echo "Copying static files..."
cp -r client/static ${BUILD_DIR}/static

# Ensure TypeScript dist files are copied (they're built in source, not build dir)
if [ -d "client/static/js/dist" ]; then
    echo "Copying TypeScript build artifacts..."
    mkdir -p ${BUILD_DIR}/static/js/dist
    cp -r client/static/js/dist/* ${BUILD_DIR}/static/js/dist/
    echo -e "${GREEN}[OK] TypeScript dist files copied to build directory${NC}"
else
    echo -e "${RED}[X] TypeScript dist directory not found - build may have failed${NC}"
    exit 1
fi

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
mv "${BUILD_DIR}/cryptocli" "${BUILD_DIR}/bin/"
mv "${BUILD_DIR}/arkfile-client" "${BUILD_DIR}/bin/"
mv "${BUILD_DIR}/arkfile-admin" "${BUILD_DIR}/bin/"

# Client files and WASM deployment
mkdir -p "${BUILD_DIR}/client"
mv "${BUILD_DIR}/static" "${BUILD_DIR}/client/static"

# Move the js directory with compiled TypeScript to the correct location
if [ -d "${BUILD_DIR}/client/js" ]; then
    mv "${BUILD_DIR}/client/js" "${BUILD_DIR}/client/static/"
    echo -e "${GREEN}[OK] Moved compiled TypeScript to client/static/js/${NC}"
fi

# Database files
mkdir -p "${BUILD_DIR}/database"
cp -r database/* "${BUILD_DIR}/database/"

# Systemd files are already in build/systemd

# version.json is already in build/

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
sudo install -d -m 755 -o arkfile -g arkfile "${BASE_DIR}/bin"
for file in "${BUILD_DIR}/bin/"*; do
    sudo install -m 755 -o arkfile -g arkfile "$file" "${BASE_DIR}/bin/"
done

echo -e "${GREEN}Build complete!${NC}"
echo "Build artifacts are ready in the '${BUILD_DIR}' directory."
