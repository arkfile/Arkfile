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
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/log"
sudo install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/run"
sudo install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/webroot"

# Create key management subdirectories
echo "Creating key management directories..."
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/opaque"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/jwt"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/jwt/current"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/jwt/backup"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/ca"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/rqlite"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/minio"
sudo install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/backups"

# Create application data directories
echo "Creating application data directories..."
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib/database"
sudo install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib/storage"

# Create a releases directory for deployment
sudo install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/releases"

echo -e "${GREEN}Directory setup complete!${NC}"
echo "Base directory: ${BASE_DIR}"
echo "User: ${USER} (group: ${GROUP})"

# Display directory structure
echo -e "${YELLOW}Directory structure created:${NC}"
if command -v tree >/dev/null 2>&1; then
    sudo tree -L 4 --dirsfirst ${BASE_DIR}
else
    echo "Install 'tree' command to see directory structure visualization"
    echo "Main structure:"
    echo "  ${BASE_DIR}/"
    echo "  ├── bin/              # Application binaries"
    echo "  ├── etc/              # Configuration files"
    echo "  │   └── keys/         # Cryptographic keys (700 permissions)"
    echo "  ├── var/              # Variable data"
    echo "  │   ├── lib/          # Application data"
    echo "  │   ├── log/          # Log files"
    echo "  │   └── run/          # Runtime files"
    echo "  ├── webroot/          # Static web assets"
    echo "  └── releases/         # Deployment releases"
fi
