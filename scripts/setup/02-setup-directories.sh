#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BASE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"

echo -e "${GREEN}Setting up Arkfile directory structure...${NC}"

# Create main directory structure
echo "Creating main directories..."
sudo install -d -m 755 -o ${USER} -g ${GROUP} ${BASE_DIR}
sudo install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/bin"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys"

# Generate Tier-3 user-secret-master.bin if missing (F-01 / F-02)
MASTER_KEY_FILE="${BASE_DIR}/etc/keys/user-secret-master.bin"
if [ ! -f "$MASTER_KEY_FILE" ]; then
    echo "Generating Tier-3 user-secret-master.bin..."
    sudo dd if=/dev/urandom of="$MASTER_KEY_FILE" bs=32 count=1 status=none
    sudo chmod 400 "$MASTER_KEY_FILE"
    sudo chown ${USER}:${GROUP} "$MASTER_KEY_FILE"
fi

sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/log"
sudo install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/run"
sudo install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/webroot"

# Create key management subdirectories
echo "Creating key management directories..."
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/opaque"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/ca"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/arkfile"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/rqlite"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/seaweedfs"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/backups"

# Create application data directories
echo "Creating application data directories..."
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib/database"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib/storage"

# Create cache directory for downloads
echo "Creating cache directories..."
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/cache"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/cache/downloads"

# Create state tracking directory
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/setup-state"

# Create a releases directory for deployment
sudo install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/releases"

echo -e "${GREEN}Directory setup complete!${NC}"
echo "Base directory: ${BASE_DIR}"
echo "User: ${USER} (group: ${GROUP})"

# Display clean directory summary
echo -e "${YELLOW}Directory structure created:${NC}"
echo "  ${BASE_DIR}/"
echo "  ├── bin/              # Application binaries"
echo "  ├── etc/keys/         # Cryptographic keys"
echo "  ├── var/lib/          # Application data"
echo "  └── releases/         # Deployment releases"
