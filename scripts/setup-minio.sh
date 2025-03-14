#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BASE_DIR="/opt/arkfile"
MINIO_VERSION="RELEASE.2024-03-10T02-53-48Z"  # Latest stable version
MINIO_DOWNLOAD_URL="https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${MINIO_VERSION}"

echo -e "${GREEN}Setting up MinIO Server ${MINIO_VERSION}...${NC}"

# Download and install MinIO
echo "Downloading MinIO..."
curl -L ${MINIO_DOWNLOAD_URL} -o /tmp/minio

echo "Installing MinIO..."
sudo install -m 755 /tmp/minio /usr/local/bin/minio

# Clean up temporary files
rm -f /tmp/minio

# Copy systemd service files
echo "Installing systemd service files..."
sudo cp ${BASE_DIR}/releases/current/systemd/minio@.service /etc/systemd/system/
sudo cp ${BASE_DIR}/releases/current/systemd/minio.target /etc/systemd/system/

# Create directory structure for both environments
for env in prod test; do
    echo "Setting up ${env} environment directories..."
    
    # Create MinIO data directory
    sudo install -d -m 750 -o "ark${env}" -g arkfile "${BASE_DIR}/var/lib/${env}/minio"
    sudo install -d -m 750 -o "ark${env}" -g arkfile "${BASE_DIR}/var/lib/${env}/minio/data"
done

# Reload systemd
echo "Reloading systemd..."
sudo systemctl daemon-reload

echo -e "${GREEN}MinIO setup complete!${NC}"
echo "MinIO binary installed:"
echo "- minio: $(which minio)"
echo "- version: $(minio --version)"
echo "Systemd services installed:"
echo "- minio@.service"
echo "- minio.target"

echo -e "${YELLOW}Next steps:${NC}"
echo "1. Configure the MINIO_* environment variables in /opt/arkfile/etc/[env]/secrets.env:"
echo "   - MINIO_ROOT_USER: MinIO root user (default: minioadmin)"
echo "   - MINIO_ROOT_PASSWORD: MinIO root password (default: minioadmin)"
echo "   - LOCAL_STORAGE_PATH: Path to store data (e.g., /opt/arkfile/var/lib/prod/minio/data)"
echo "   For cluster mode also set:"
echo "   - MINIO_CLUSTER_NODES: Comma-separated list of node addresses"
echo "   - MINIO_CLUSTER_ACCESS_KEY: Cluster access key"
echo "   - MINIO_CLUSTER_SECRET_KEY: Cluster secret key"
echo "2. Start MinIO service: sudo systemctl start minio@prod"
echo "3. Enable MinIO service: sudo systemctl enable minio@prod"
echo "4. Check status: sudo systemctl status minio@prod"
echo
echo "Console access:"
echo "- Local mode: http://localhost:9001"
echo "- Cluster mode: http://[first-node]:9001"
