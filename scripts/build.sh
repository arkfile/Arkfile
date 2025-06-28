#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
WASM_DIR="client"
BUILD_DIR="build"
VERSION=$(git describe --tags --always --dirty)
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BASE_DIR="/opt/arkfile"

# Colors for output 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Ensure required tools are installed
command -v go >/dev/null 2>&1 || { echo -e "${RED}Go is required but not installed.${NC}" >&2; exit 1; }

# Run user and directory setup if needed
if [ ! -d "${BASE_DIR}" ]; then
    echo -e "${YELLOW}Setting up initial directory structure...${NC}"
    ./scripts/setup-users.sh
    ./scripts/setup-directories.sh
fi

echo -e "${GREEN}Building ${APP_NAME} version ${VERSION}${NC}"

# Create temporary build directory
mkdir -p ${BUILD_DIR}

# Build WebAssembly
echo "Building WebAssembly..."
GOOS=js GOARCH=wasm go build -o ${BUILD_DIR}/${WASM_DIR}/main.wasm ./${WASM_DIR}/main.go
cp "/usr/local/go/misc/wasm/wasm_exec.js" ${BUILD_DIR}/${WASM_DIR}/

# Build main application with version information
echo "Building main application..."
go build -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" -o ${BUILD_DIR}/${APP_NAME}

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
   "buildTime": "${BUILD_TIME}"
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
sudo cp "${RELEASE_DIR}/${APP_NAME}" "${BASE_DIR}/bin/"
sudo chown arkadmin:arkfile "${BASE_DIR}/bin/${APP_NAME}"
sudo chmod 755 "${BASE_DIR}/bin/${APP_NAME}"

# Clean up temporary build directory
rm -rf ${BUILD_DIR}

echo -e "${GREEN}Build complete!${NC}"
echo "Release directory: ${RELEASE_DIR}"
echo "Binary location: ${BASE_DIR}/bin/${APP_NAME}"
echo "Current symlink updated: ${BASE_DIR}/releases/current"
