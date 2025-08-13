#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
WASM_DIR="client"
BUILD_DIR="build"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BASE_DIR="/opt/arkfile"

# Colors for output 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to check Go version requirements from go.mod
check_go_version() {
    local required_version=$(grep '^go [0-9]' go.mod | awk '{print $2}')
    
    if [ -z "$required_version" ]; then
        echo -e "${YELLOW}⚠️  Cannot determine Go version requirement from go.mod${NC}"
        return 0
    fi
    
    local current_version=$(/usr/local/go/bin/go version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
    
    if [ -z "$current_version" ]; then
        echo -e "${RED}❌ Cannot determine Go version${NC}"
        exit 1
    fi
    
    # Convert versions to comparable format (remove dots and compare as integers)
    local current_num=$(echo $current_version | awk -F. '{printf "%d%02d%02d", $1, $2, $3}')
    local required_num=$(echo $required_version | awk -F. '{printf "%d%02d%02d", $1, $2, $3}')
    
    if [ "$current_num" -lt "$required_num" ]; then
        echo -e "${RED}❌ Go version $current_version is too old${NC}"
        echo -e "${YELLOW}Required: Go $required_version or later (from go.mod)${NC}"
        echo -e "${YELLOW}Current:  Go $current_version${NC}"
        echo
        echo -e "${BLUE}To update Go:${NC}"
        echo "1. Visit https://golang.org/dl/"
        echo "2. Download and install Go $required_version or later"
        echo "3. Or use your system's package manager"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Go version $current_version meets requirements (>= $required_version)${NC}"
}

# Ensure required tools are installed
command -v /usr/local/go/bin/go >/dev/null 2>&1 || { echo -e "${RED}Go is required but not installed.${NC}" >&2; exit 1; }
check_go_version

# Ensure Go dependencies are properly resolved
echo -e "${YELLOW}Checking Go module dependencies...${NC}"
if ! /usr/local/go/bin/go mod download; then
    echo -e "${YELLOW}Dependencies need updating, running go mod tidy...${NC}"
    /usr/local/go/bin/go mod tidy
    if ! /usr/local/go/bin/go mod download; then
        echo -e "${RED}Failed to resolve Go dependencies${NC}" >&2
        exit 1
    fi
fi

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
    echo -e "${GREEN}✅ Vendor directory matches go.sum, skipping sync (preserves compiled libraries)${NC}"
else
    echo -e "${YELLOW}Dependencies changed or vendor missing, syncing vendor directory...${NC}"
    if ! /usr/local/go/bin/go mod vendor; then
        echo -e "${YELLOW}Vendor sync failed, attempting to fix missing dependencies...${NC}"
        # Try to get missing dependencies that might not be in go.sum
        /usr/local/go/bin/go get -d ./...
        if ! /usr/local/go/bin/go mod vendor; then
            echo -e "${RED}Failed to sync vendor directory${NC}" >&2
            exit 1
        fi
    fi
    # Cache the successful sync
    if [ -n "$CURRENT_HASH" ]; then
        echo "$CURRENT_HASH" > "$VENDOR_CACHE"
    fi
    echo -e "${GREEN}✅ Vendor directory synced with dependencies${NC}"
fi

# Build static dependencies first
build_static_dependencies() {
    echo -e "${YELLOW}Building static dependencies...${NC}"
    
    if ! ./scripts/setup/build-libopaque.sh; then
        echo -e "${RED}❌ Failed to build static dependencies${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Static dependencies built successfully${NC}"
}

# Initialize and build C dependencies
echo -e "${YELLOW}Initializing and building C dependencies...${NC}"

# Check if we should skip C library building
if [ "${SKIP_C_LIBS}" = "true" ]; then
    echo -e "${GREEN}✅ Skipping C library rebuild (libraries already exist)${NC}"
    
    # Verify static libraries still exist
    if [ ! -f "vendor/stef/liboprf/src/liboprf.a" ] || [ ! -f "vendor/stef/libopaque/src/libopaque.a" ]; then
        echo -e "${YELLOW}⚠️  Expected static libraries missing, forcing rebuild...${NC}"
        SKIP_C_LIBS="false"
    fi
fi

if [ "${SKIP_C_LIBS}" != "true" ]; then
    # Smart source code detection - check for key source files instead of .git directories
    OPAQUE_SOURCE="vendor/stef/libopaque/src/opaque.c"
    OPRF_SOURCE="vendor/stef/liboprf/src/oprf.c"
    
    if [ -f "$OPAQUE_SOURCE" ] && [ -f "$OPRF_SOURCE" ]; then
        echo -e "${GREEN}✅ Source code available, building static libraries...${NC}"
        
        # Use specialized build script with static linking
        build_static_dependencies
        
        echo -e "${GREEN}✅ Static C dependencies built successfully${NC}"
    else
        echo -e "${YELLOW}⚠️ Source code missing, checking for source directory availability...${NC}"
        echo "Missing files: $OPAQUE_SOURCE or $OPRF_SOURCE"
        
        # Initialize git submodules
        if ! git submodule update --init --recursive; then
            echo -e "${RED}❌ Failed to initialize git submodules${NC}"
            exit 1
        fi
        echo -e "${GREEN}✅ Git submodules initialized${NC}"
        
        # Verify source files are now available
        if [ -f "$OPAQUE_SOURCE" ] && [ -f "$OPRF_SOURCE" ]; then
            echo "Building static libopaque and liboprf after source setup..."
            build_static_dependencies
            echo -e "${GREEN}✅ Static C dependencies built successfully${NC}"
        else
            echo -e "${RED}❌ Source files still missing after source setup${NC}"
            exit 1
        fi
    fi
else
    echo -e "${GREEN}✅ Using existing static C dependencies${NC}"
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
    echo -e "${RED}❌ Bun is required for TypeScript compilation${NC}"
    echo -e "${YELLOW}Install Bun using: source <(curl -fsSL https://bun.sh/install)${NC}"
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
        echo -e "${RED}❌ Failed to install dependencies${NC}"
        exit 1
    }
fi

# Verify source files exist
if [ ! -f "src/app.ts" ]; then
    echo -e "${RED}❌ Missing TypeScript source files${NC}"
    exit 1
fi

# Run TypeScript type checking
echo "Running TypeScript type checking..."
if ! ${BUN_CMD} run type-check; then
    echo -e "${RED}❌ TypeScript type checking failed - aborting build${NC}"
    exit 1
fi

# Check build cache
CACHE_FILE=".buildcache"
TS_HASH=$(find src -name "*.ts" -type f -exec sha256sum {} \; | sha256sum)
BUILD_HASH=$(cat ${CACHE_FILE} 2>/dev/null || true)

if [ "${TS_HASH}" = "${BUILD_HASH}" ] && [ -f "dist/app.js" ]; then
    echo -e "${GREEN}✅ No TypeScript changes - skipping build${NC}"
else
    echo "Building TypeScript production bundle..."
    ${BUN_CMD} run build:prod || {
        echo -e "${RED}❌ TypeScript build failed${NC}"
        exit 1
    }
    
    # Verify build output
    if [ ! -f "dist/app.js" ] || [ ! -s "dist/app.js" ]; then
        echo -e "${RED}❌ Build output missing or empty${NC}"
        exit 1
    fi
    
    # Update build cache
    echo "${TS_HASH}" > ${CACHE_FILE}
fi

cd ../../..

# Validate final JS path
JS_PATH="client/static/js/dist/app.js"
if [ ! -f "${JS_PATH}" ]; then
    echo -e "${RED}❌ Missing built JavaScript file at ${JS_PATH}${NC}"
    exit 1
fi

echo -e "${GREEN}✅ TypeScript frontend built successfully${NC}"

# Build WebAssembly
echo "Building WebAssembly..."
GOOS=js GOARCH=wasm /usr/local/go/bin/go build -o ${BUILD_DIR}/${WASM_DIR}/main.wasm ./${WASM_DIR}/main.go

# Find wasm_exec.js using Go's environment
GOROOT=$(/usr/local/go/bin/go env GOROOT)
WASM_EXEC_JS=""
if [ -f "${GOROOT}/lib/wasm/wasm_exec.js" ]; then
    WASM_EXEC_JS="${GOROOT}/lib/wasm/wasm_exec.js"
elif [ -f "${GOROOT}/misc/wasm/wasm_exec.js" ]; then
    WASM_EXEC_JS="${GOROOT}/misc/wasm/wasm_exec.js"
else
    echo -e "${RED}❌ Cannot find wasm_exec.js in Go installation at ${GOROOT}${NC}"
    exit 1
fi

echo "Using wasm_exec.js from: ${WASM_EXEC_JS}"
cp "${WASM_EXEC_JS}" ${BUILD_DIR}/${WASM_DIR}/

# Build Go binaries with static linking
build_go_binaries_static() {
    echo -e "${YELLOW}Building Go binaries with static linking...${NC}"
    
    # Set up static linking environment
    export CGO_ENABLED=1
    export CGO_CFLAGS="-I./vendor/stef/libopaque/src -I./vendor/stef/liboprf/src"
    export CGO_LDFLAGS="-L./vendor/stef/libopaque/src -L./vendor/stef/liboprf/src -lopaque -loprf"
    export CGO_LDFLAGS="$CGO_LDFLAGS $(pkg-config --libs --static libsodium)"
    
    echo "Building arkfile server..."
    /usr/local/go/bin/go build -a -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -extldflags '-static'" -o ${BUILD_DIR}/${APP_NAME} .
    
    echo "Building cryptocli..."
    /usr/local/go/bin/go build -a -ldflags '-extldflags "-static"' -o ${BUILD_DIR}/cryptocli ./cmd/cryptocli
    
    echo -e "${GREEN}✅ Go binaries built with static linking${NC}"
}

# Verify static binaries
verify_static_binaries() {
    echo -e "${YELLOW}Verifying static binaries...${NC}"
    
    for binary in ${BUILD_DIR}/${APP_NAME} ${BUILD_DIR}/cryptocli; do
        if [ -f "$binary" ]; then
            # Use appropriate verification for platform
            if [[ "$OSTYPE" == "freebsd"* ]] || [[ "$OSTYPE" == "openbsd"* ]]; then
                # BSD systems use different tools
                if file "$binary" | grep -q "statically linked"; then
                    echo -e "${GREEN}✅ $(basename $binary): Static binary verified${NC}"
                else
                    echo -e "${RED}❌ $(basename $binary): Dynamic linking detected${NC}"
                    exit 1
                fi
            else
                # Linux systems (includes Alpine, Debian, Alma, etc.)
                if ldd "$binary" 2>&1 | grep -q "not a dynamic executable"; then
                    echo -e "${GREEN}✅ $(basename $binary): Static binary verified${NC}"
                else
                    echo -e "${RED}❌ $(basename $binary): Dynamic linking detected${NC}"
                    ldd "$binary" 2>&1 || true
                    exit 1
                fi
            fi
        else
            echo -e "${RED}❌ Binary not found: $binary${NC}"
            exit 1
        fi
    done
    
    echo -e "${GREEN}✅ All binaries verified as static${NC}"
}

# Build main application with static linking
echo "Building Go binaries with static linking..."
build_go_binaries_static

# Verify static linking
verify_static_binaries

# Copy static files
echo "Copying static files..."
cp -r client/static ${BUILD_DIR}/static

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

# Create release directory with timestamp
RELEASE_DIR="${BASE_DIR}/releases/$(date +%Y%m%d_%H%M%S)"
echo "Creating release directory: ${RELEASE_DIR}"

# Copy build artifacts to release directory
sudo mkdir -p "${RELEASE_DIR}"
sudo cp -r ${BUILD_DIR}/* "${RELEASE_DIR}/"

# Update ownership and permissions
echo "Setting ownership and permissions..."
sudo chown -R arkadmin:arkfile "${RELEASE_DIR}"
sudo chmod 755 "${RELEASE_DIR}/${APP_NAME}"

if command -v semanage >/dev/null 2>&1; then
    sudo semanage fcontext -a -t bin_t "${RELEASE_DIR}/${APP_NAME}"
    sudo restorecon -v "${RELEASE_DIR}/${APP_NAME}"
else
    echo -e "${YELLOW}semanage not found - skipping SELinux context${NC}"
fi

# Update the 'current' symlink
sudo ln -snf "${RELEASE_DIR}" "${BASE_DIR}/releases/current"

# Copy binary to bin directory
sudo mkdir -p "${BASE_DIR}/bin/"
sudo cp "${RELEASE_DIR}/${APP_NAME}" "${BASE_DIR}/bin/"
sudo chown arkadmin:arkfile "${BASE_DIR}/bin/${APP_NAME}"
sudo chmod 755 "${BASE_DIR}/bin/${APP_NAME}"

# Copy database files to working directory for runtime access
echo "Copying database files to working directory..."
sudo mkdir -p "${BASE_DIR}/database"
sudo cp -r database/* "${BASE_DIR}/database/"
sudo chown -R arkfile:arkfile "${BASE_DIR}/database"

# Copy client files to working directory for runtime access
echo "Copying client files to working directory..."
sudo mkdir -p "${BASE_DIR}/client"
sudo cp -r client/* "${BASE_DIR}/client/"

# Ensure WASM binary is copied from build directory to working directory
if [ -f "${BUILD_DIR}/${WASM_DIR}/main.wasm" ]; then
    echo "Copying WASM binary to working directory..."
    sudo cp "${BUILD_DIR}/${WASM_DIR}/main.wasm" "${BASE_DIR}/client/main.wasm"
else
    echo -e "${YELLOW}⚠️ WASM binary not found in build directory - may cause runtime issues${NC}"
fi

# Ensure wasm_exec.js is also available in working directory
if [ -f "${BUILD_DIR}/${WASM_DIR}/wasm_exec.js" ]; then
    echo "Copying wasm_exec.js to working directory..."
    sudo cp "${BUILD_DIR}/${WASM_DIR}/wasm_exec.js" "${BASE_DIR}/client/wasm_exec.js"
fi

sudo chown -R arkfile:arkfile "${BASE_DIR}/client"

# Clean up temporary build directory
rm -rf ${BUILD_DIR}

echo -e "${GREEN}Build complete!${NC}"
echo "Release directory: ${RELEASE_DIR}"
echo "Binary location: ${BASE_DIR}/bin/${APP_NAME}"
echo "Current symlink updated: ${BASE_DIR}/releases/current"
