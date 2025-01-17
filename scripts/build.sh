#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
WASM_DIR="client"
BUILD_DIR="build"
VERSION=$(git describe --tags --always --dirty)
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Colors for output 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Ensure required tools are installed
command -v go >/dev/null 2>&1 || { echo -e "${RED}Go is required but not installed.${NC}" >&2; exit 1; }

# Check/create app user and group
echo "Checking for app user and group..."
if ! getent group app >/dev/null; then
   echo -e "${YELLOW}Creating app group...${NC}"
   sudo groupadd -r app
fi

if ! getent passwd app >/dev/null; then
   echo -e "${YELLOW}Creating app user...${NC}"
   sudo useradd -r -g app -s /sbin/nologin
fi

echo -e "${GREEN}Building ${APP_NAME} version ${VERSION}${NC}"

# Create build directory
mkdir -p ${BUILD_DIR}

# Build WebAssembly
echo "Building WebAssembly..."
GOOS=js GOARCH=wasm go build -o ${BUILD_DIR}/${WASM_DIR}/main.wasm ./${WASM_DIR}
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ${BUILD_DIR}/${WASM_DIR}/

# Build main application with version information
echo "Building main application..."
go build -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" -o ${BUILD_DIR}/${APP_NAME}

# Copy static files
echo "Copying static files..."
cp -r client/static ${BUILD_DIR}/static
cp .env.example ${BUILD_DIR}/.env.example

# Create version file
echo "Creating version file..."
cat > ${BUILD_DIR}/version.json <<EOF
{
   "version": "${VERSION}",
   "buildTime": "${BUILD_TIME}"
}
EOF

# Fix ownership and permissions
echo "Setting ownership and permissions..."
if command -v semanage >/dev/null 2>&1; then
   # Only run SELinux commands if semanage is available
   sudo semanage fcontext -a -t bin_t "${BUILD_DIR}/${APP_NAME}"
   sudo restorecon -v "${BUILD_DIR}/${APP_NAME}"
else
   echo -e "${RED}semanage not found - skipping SELinux context${NC}"
fi

sudo chown app:app "${BUILD_DIR}/${APP_NAME}"
sudo chmod 755 "${BUILD_DIR}/${APP_NAME}"

# Verify changes
echo "Verifying binary..."
ls -lZ "${BUILD_DIR}/${APP_NAME}"

echo -e "${GREEN}Build complete!${NC}"
echo "Build artifacts are in the '${BUILD_DIR}' directory"

