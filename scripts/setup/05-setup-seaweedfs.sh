#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BASE_DIR="/opt/arkfile"
SEAWEEDFS_VERSION="4.18"
SEAWEEDFS_DOWNLOAD_URL="https://github.com/seaweedfs/seaweedfs/releases/download/${SEAWEEDFS_VERSION}/linux_amd64.tar.gz"
SEAWEEDFS_MD5_URL="https://github.com/seaweedfs/seaweedfs/releases/download/${SEAWEEDFS_VERSION}/linux_amd64.tar.gz.md5"
INSTALL_DIR="/usr/local/bin"
CACHE_DIR="/var/cache/arkfile/seaweedfs"

echo -e "${GREEN}Setting up SeaweedFS ${SEAWEEDFS_VERSION}...${NC}"

# Ensure cache directory exists
sudo mkdir -p "${CACHE_DIR}"

# Check if SeaweedFS is already installed at the expected version
NEEDS_INSTALL=true
if [ -x "${INSTALL_DIR}/weed" ]; then
    INSTALLED_VERSION=$("${INSTALL_DIR}/weed" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "unknown")
    echo -e "${GREEN}[OK] SeaweedFS is already installed${NC}"
    echo "Installed version: ${INSTALLED_VERSION}"
    echo "Location: ${INSTALL_DIR}/weed"

    if [ "${INSTALLED_VERSION}" = "${SEAWEEDFS_VERSION}" ]; then
        echo -e "${GREEN}[OK] Version matches expected version ${SEAWEEDFS_VERSION}${NC}"
        echo "Skipping download and installation"
        NEEDS_INSTALL=false
    else
        echo -e "${YELLOW}[WARNING] Installed version (${INSTALLED_VERSION}) doesn't match expected (${SEAWEEDFS_VERSION})${NC}"
        echo "Proceeding with download to update..."
    fi
else
    echo "SeaweedFS not found, downloading and installing..."
fi

if [ "${NEEDS_INSTALL}" = "true" ]; then
    TARBALL="${CACHE_DIR}/linux_amd64-${SEAWEEDFS_VERSION}.tar.gz"

    # Download tarball if not cached
    if [ ! -f "${TARBALL}" ]; then
        echo "Downloading SeaweedFS ${SEAWEEDFS_VERSION}..."
        curl -fSL "${SEAWEEDFS_DOWNLOAD_URL}" -o "${TARBALL}"
    else
        echo "Using cached tarball: ${TARBALL}"
    fi

    # Verify repo-pinned SHA-256 checksum
    echo "Verifying SHA-256 checksum against repo-pinned digest..."
    EXPECTED_SHA256="abe924a3b5a16af889675005b7ee3ffcc424bc78c7f0be1126a8c8681667c22c"
    ACTUAL_SHA256=$(sha256sum "${TARBALL}" | awk '{print $1}')

    if [ "${EXPECTED_SHA256}" != "${ACTUAL_SHA256}" ]; then
        echo -e "${RED}[X] SHA-256 checksum verification FAILED${NC}"
        echo "  Expected: ${EXPECTED_SHA256}"
        echo "  Got:      ${ACTUAL_SHA256}"
        echo "Removing corrupt download..."
        rm -f "${TARBALL}"
        exit 1
    fi
    echo -e "${GREEN}[OK] SHA-256 checksum verified securely${NC}"

    # Extract and install
    echo "Extracting SeaweedFS binary..."
    TMPDIR=$(mktemp -d)
    tar -xzf "${TARBALL}" -C "${TMPDIR}"

    if [ ! -f "${TMPDIR}/weed" ]; then
        echo -e "${RED}[X] 'weed' binary not found in archive${NC}"
        rm -rf "${TMPDIR}"
        exit 1
    fi

    echo "Installing SeaweedFS binary to ${INSTALL_DIR}/weed..."
    sudo install -m 755 "${TMPDIR}/weed" "${INSTALL_DIR}/weed"
    rm -rf "${TMPDIR}"

    # Verify installation
    if [ -x "${INSTALL_DIR}/weed" ]; then
        echo -e "${GREEN}[OK] SeaweedFS installed successfully${NC}"
        echo "Version: $("${INSTALL_DIR}/weed" version 2>/dev/null | head -1)"
    else
        echo -e "${RED}[X] SeaweedFS installation failed${NC}"
        exit 1
    fi
fi

# Install systemd service file
echo "Installing systemd service file..."
sudo cp "${BASE_DIR}/systemd/seaweedfs.service" /etc/systemd/system/

# Create data directories
echo "Setting up SeaweedFS directories..."
sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/seaweedfs"
sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/seaweedfs/data"

# Reload systemd
echo "Reloading systemd..."
sudo systemctl daemon-reload

echo -e "${GREEN}SeaweedFS setup complete!${NC}"
echo "SeaweedFS binary installed:"
echo "- weed: ${INSTALL_DIR}/weed"
echo "- version: $("${INSTALL_DIR}/weed" version 2>/dev/null | head -1)"
echo "Systemd service installed:"
echo "- seaweedfs.service"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Ensure S3 credentials are configured in /opt/arkfile/etc/seaweedfs-s3.json"
echo "2. Start SeaweedFS service: sudo systemctl start seaweedfs"
echo "3. Enable SeaweedFS service: sudo systemctl enable seaweedfs"
echo "4. Check status: sudo systemctl status seaweedfs"
echo ""
echo "S3 API access (localhost only):"
echo "- S3 Gateway: http://localhost:9332"
