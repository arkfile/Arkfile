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
    MD5FILE="${CACHE_DIR}/linux_amd64-${SEAWEEDFS_VERSION}.tar.gz.md5"

    # Download tarball if not cached
    if [ ! -f "${TARBALL}" ]; then
        echo "Downloading SeaweedFS ${SEAWEEDFS_VERSION}..."
        curl -fSL "${SEAWEEDFS_DOWNLOAD_URL}" -o "${TARBALL}"
    else
        echo "Using cached tarball: ${TARBALL}"
    fi

    # Always download fresh checksum for verification
    echo "Downloading MD5 checksum..."
    curl -fSL "${SEAWEEDFS_MD5_URL}" -o "${MD5FILE}"

    # Verify MD5 checksum
    echo "Verifying MD5 checksum..."
    EXPECTED_MD5=$(awk '{print $1}' "${MD5FILE}")
    ACTUAL_MD5=$(md5sum "${TARBALL}" | awk '{print $1}')

    if [ "${EXPECTED_MD5}" != "${ACTUAL_MD5}" ]; then
        echo -e "${RED}[X] MD5 checksum verification FAILED${NC}"
        echo "  Expected: ${EXPECTED_MD5}"
        echo "  Got:      ${ACTUAL_MD5}"
        echo "Removing corrupt download..."
        rm -f "${TARBALL}"
        exit 1
    fi
    echo -e "${GREEN}[OK] MD5 checksum verified${NC}"

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
