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
NC='\033[0m'

# Ensure required tools are installed
command -v go >/dev/null 2>&1 || { echo -e "${RED}Go is required but not installed.${NC}" >&2; exit 1; }

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
cp -r client/static ${BUILD_DIR}/
cp .env.example ${BUILD_DIR}/.env.example
cp Caddyfile ${BUILD_DIR}/
cp -r systemd ${BUILD_DIR}/

# Create version file
echo "Creating version file..."
cat > ${BUILD_DIR}/version.json <<EOF
{
    "version": "${VERSION}",
    "buildTime": "${BUILD_TIME}"
}
EOF

echo -e "${GREEN}Build complete!${NC}"
echo "Build artifacts are in the '${BUILD_DIR}' directory"
