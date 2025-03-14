#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
VERSION="7.21.1"  # Latest stable version of rqlite
BASE_DIR="/opt/arkfile"
RQLITE_DOWNLOAD_URL="https://github.com/rqlite/rqlite/releases/download/v${VERSION}/rqlite-v${VERSION}-linux-amd64.tar.gz"

echo -e "${GREEN}Setting up rqlite v${VERSION}...${NC}"

# Download and install rqlite
echo "Downloading rqlite..."
curl -L ${RQLITE_DOWNLOAD_URL} -o /tmp/rqlite.tar.gz

echo "Installing rqlite..."
sudo tar xzf /tmp/rqlite.tar.gz -C /tmp
sudo install -m 755 /tmp/rqlite-v${VERSION}-linux-amd64/rqlited /usr/local/bin/
sudo install -m 755 /tmp/rqlite-v${VERSION}-linux-amd64/rqlite /usr/local/bin/

# Clean up temporary files
rm -rf /tmp/rqlite.tar.gz /tmp/rqlite-v${VERSION}-linux-amd64

# Copy systemd service files
echo "Installing systemd service files..."
sudo cp ${BASE_DIR}/releases/current/systemd/rqlite@.service /etc/systemd/system/
sudo cp ${BASE_DIR}/releases/current/systemd/rqlite.target /etc/systemd/system/

# Reload systemd
echo "Reloading systemd..."
sudo systemctl daemon-reload

echo -e "${GREEN}rqlite setup complete!${NC}"
echo "rqlite binaries installed:"
echo "- rqlited (server): $(which rqlited)"
echo "- rqlite (client): $(which rqlite)"
echo "Systemd services installed:"
echo "- rqlite@.service"
echo "- rqlite.target"

echo -e "${YELLOW}Next steps:${NC}"
echo "1. Configure the RQLITE_* environment variables in /opt/arkfile/etc/[env]/secrets.env"
echo "2. Start rqlite service: sudo systemctl start rqlite@prod"
echo "3. Enable rqlite service: sudo systemctl enable rqlite@prod"
echo "4. Check status: sudo systemctl status rqlite@prod"
