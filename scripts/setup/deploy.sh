#!/bin/bash
set -e

# Source shared build configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/build-config.sh"

# Configuration
APP_NAME="arkfile"
BASE_DIR="/opt/arkfile"
BUILD_DIR="$BUILD_ROOT"  # Use BUILD_ROOT from build-config.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[X] deploy.sh must run as root (it is called by dev-reset.sh, local-deploy.sh, and the VPS deploy scripts).${NC}"
    exit 1
fi

# Shared helpers: print_status, verify_ownership, apply_arkfile_bin_ownership,
# remove_stale_build_output_from_install_root.
ARKFILE_DIR="$BASE_DIR"
ARKFILE_USER="arkfile"
ARKFILE_GROUP="arkfile"
source "$SCRIPT_DIR/deploy-common.sh"

# Runtime artifacts copied from the build root. Other build-root content
# (c-libs/, wasm/) is build output and must not land in the install root.
REQUIRED_ARTIFACT_DIRS="bin client database systemd webroot"
OPTIONAL_ARTIFACT_FILES="version.json sbom.cdx.json build-dependencies.json"

echo -e "${GREEN}Deploying ${APP_NAME} locally...${NC}"

# Pre-flight: verify deployment target exists
if [ ! -d "$BASE_DIR" ]; then
    echo -e "${RED}[X] Deployment target ${BASE_DIR} does not exist.${NC}"
    echo -e "${YELLOW}    Run scripts/setup/01-setup-users.sh and scripts/setup/02-setup-directories.sh first.${NC}"
    exit 1
fi

# Verify we have build artifacts
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${RED}[X] Build directory ${BUILD_DIR} not found. Run build first.${NC}"
    exit 1
fi

# Verify build directory has content
if [ ! "$(ls -A $BUILD_DIR)" ]; then
    echo -e "${RED}[X] Build directory ${BUILD_DIR} is empty. Run build first.${NC}"
    exit 1
fi

# Verify critical files exist in build directory
echo -e "${YELLOW}Verifying critical build artifacts...${NC}"
if [ ! -f "$BUILD_DIR/client/static/js/dist/app.js" ]; then
    echo -e "${RED}[X] TypeScript bundle missing from build directory${NC}"
    echo "Expected: $BUILD_DIR/client/static/js/dist/app.js"
    echo "Build directory contents:"
    find "$BUILD_DIR" -name "*.js" -type f 2>/dev/null | head -20
    exit 1
fi
echo -e "${GREEN}[OK] TypeScript bundle found in build directory${NC}"

if [ ! -f "$BUILD_DIR/client/static/js/libopaque.js" ]; then
    echo -e "${RED}[X] libopaque.js missing from build directory${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] libopaque.js found in build directory${NC}"

# Copy build artifacts to installation directory with proper ownership
echo -e "${YELLOW}Copying build artifacts to ${BASE_DIR}...${NC}"
for artifact in $REQUIRED_ARTIFACT_DIRS; do
    if [ ! -d "${BUILD_DIR}/${artifact}" ]; then
        echo -e "${RED}[X] Required build artifact directory missing: ${BUILD_DIR}/${artifact}${NC}"
        exit 1
    fi
    cp -r "${BUILD_DIR}/${artifact}" "${BASE_DIR}/"
done
for artifact in $OPTIONAL_ARTIFACT_FILES; do
    if [ -f "${BUILD_DIR}/${artifact}" ]; then
        cp "${BUILD_DIR}/${artifact}" "${BASE_DIR}/"
    fi
done
remove_stale_build_output_from_install_root "$BASE_DIR"

# Set proper ownership after copy
echo -e "${YELLOW}[KEY] Setting permissions (least-privilege secured: bin directory remains root-owned)...${NC}"
chown -R arkfile:arkfile "${BASE_DIR}"
apply_arkfile_bin_ownership "$BASE_DIR"

# Ensure executable permissions on binaries
sudo find ${BASE_DIR} -type f -executable -exec chmod 755 {} \;

# Copy systemd service files
echo -e "${YELLOW}[CONFIG]  Installing systemd services...${NC}"
sudo cp ${BASE_DIR}/systemd/${APP_NAME}.service /etc/systemd/system/
sudo cp ${BASE_DIR}/systemd/rqlite.service /etc/systemd/system/ 2>/dev/null || true
sudo cp ${BASE_DIR}/systemd/seaweedfs.service /etc/systemd/system/ 2>/dev/null || true
sudo cp ${BASE_DIR}/systemd/caddy.service /etc/systemd/system/ 2>/dev/null || true

# Reload systemd daemon
echo -e "${YELLOW}Reloading systemd...${NC}"
sudo systemctl daemon-reload

# Enable services (but don't auto-start)
echo -e "${YELLOW}[INFO] Enabling services (without auto-start)...${NC}"
sudo systemctl enable ${APP_NAME} 2>/dev/null || true

# Verify ownership after deployment
if ! verify_ownership "$BASE_DIR"; then
    echo -e "${RED}[X] Ownership verification failed after deployment${NC}"
    echo -e "${YELLOW}[FIX] Attempting to fix ownership...${NC}"
    chown -R arkfile:arkfile "$BASE_DIR"
    apply_arkfile_bin_ownership "$BASE_DIR"

    if ! verify_ownership "$BASE_DIR"; then
        echo -e "${RED}[X] Failed to fix ownership issues${NC}"
        exit 1
    fi
fi

# Services can be started manually by the user when ready
echo -e "${GREEN}[OK] Deployment complete!${NC}"
echo
echo -e "${YELLOW}[STATS] Deployment Summary:${NC}"
echo "- Build artifacts copied to: ${BASE_DIR}"
echo "- Permissions set for arkfile:arkfile user (bin/ owned by root)"
echo "- Systemd services installed and enabled"
echo
echo -e "${BLUE}[START] To start the services:${NC}"
echo "  sudo systemctl start ${APP_NAME}"
echo "  sudo systemctl start rqlite 2>/dev/null || true"
echo "  sudo systemctl start seaweedfs 2>/dev/null || true"
echo "  sudo systemctl start caddy 2>/dev/null || true"
echo
echo -e "${BLUE}[INFO] Check service status:${NC}"
echo "  sudo systemctl status ${APP_NAME}"
echo
echo -e "${GREEN}[TARGET] Ready for deployment validation!${NC}"
