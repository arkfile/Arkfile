#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BASE_DIR="/opt/arkfile"
MINIO_VERSION="RELEASE.2025-06-13T11-33-47Z"  # Latest stable version
MINIO_DOWNLOAD_URL="https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${MINIO_VERSION}"

echo -e "${GREEN}Setting up MinIO Server ${MINIO_VERSION}...${NC}"

# Check if MinIO is already installed
if command -v minio >/dev/null 2>&1; then
    INSTALLED_VERSION=$(minio --version 2>/dev/null | head -1 || echo "unknown")
    echo -e "${GREEN}✅ MinIO is already installed${NC}"
    echo "Installed version: ${INSTALLED_VERSION}"
    echo "Location: $(which minio)"
    
    # Check if the version matches what we expect
    if echo "${INSTALLED_VERSION}" | grep -q "${MINIO_VERSION}"; then
        echo -e "${GREEN}✅ Version matches expected version ${MINIO_VERSION}${NC}"
        echo "Skipping download and installation"
    else
        echo -e "${YELLOW}⚠️  Installed version doesn't match expected version ${MINIO_VERSION}${NC}"
        echo "Proceeding with download to update..."
        
        # Download and install MinIO using secure download script
        echo "Downloading and installing MinIO securely..."
        if [ -x "./scripts/maintenance/download-minio.sh" ]; then
            # Use our secure download script
            ./scripts/maintenance/download-minio.sh --version "${MINIO_VERSION}"
        else
            echo -e "${YELLOW}⚠️  Secure download script not found, falling back to direct download${NC}"
            echo "Downloading MinIO..."
            curl -L ${MINIO_DOWNLOAD_URL} -o /tmp/minio
            
            echo "Installing MinIO..."
            sudo install -m 755 /tmp/minio /usr/local/bin/minio
            
            # Clean up temporary files
            rm -f /tmp/minio
        fi
    fi
else
    echo "MinIO not found, downloading and installing..."
    
    # Download and install MinIO using secure download script
    echo "Downloading and installing MinIO securely..."
    if [ -x "./scripts/maintenance/download-minio.sh" ]; then
        # Use our secure download script
        ./scripts/maintenance/download-minio.sh --version "${MINIO_VERSION}"
    else
        echo -e "${YELLOW}⚠️  Secure download script not found, falling back to direct download${NC}"
        echo "Downloading MinIO..."
        curl -L ${MINIO_DOWNLOAD_URL} -o /tmp/minio
        
        echo "Installing MinIO..."
        sudo install -m 755 /tmp/minio /usr/local/bin/minio
        
        # Clean up temporary files
        rm -f /tmp/minio
    fi
fi

# Copy systemd service files
echo "Installing systemd service files..."
sudo cp ${BASE_DIR}/releases/current/systemd/minio.service /etc/systemd/system/

# Create simplified directory structure for single-node deployment
echo "Setting up MinIO directories..."
sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/minio"
sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/minio/data"

# Reload systemd
echo "Reloading systemd..."
sudo systemctl daemon-reload

echo -e "${GREEN}MinIO setup complete!${NC}"
echo "MinIO binary installed:"
echo "- minio: $(which minio)"
echo "- version: $(minio --version)"
echo "Systemd services installed:"
echo "- minio.service"

echo -e "${YELLOW}Next steps:${NC}"
echo "1. Configure the MINIO_* environment variables in /opt/arkfile/etc/secrets.env:"
echo "   - MINIO_ROOT_USER: MinIO root user (default: minioadmin)"
echo "   - MINIO_ROOT_PASSWORD: MinIO root password (default: minioadmin)"
echo "   - LOCAL_STORAGE_PATH: Path to store data (e.g., /opt/arkfile/var/lib/minio/data)"
echo "2. Start MinIO service: sudo systemctl start minio"
echo "3. Enable MinIO service: sudo systemctl enable minio"
echo "4. Check status: sudo systemctl status minio"
echo
echo "Console access:"
echo "- Local mode: http://localhost:9001"
echo "- Cluster mode: http://[first-node]:9001"
