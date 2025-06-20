#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
KEY_DIR="/opt/arkfile/etc/keys/opaque"
USER="arkfile"
GROUP="arkfile"
ARKFILE_BIN="/opt/arkfile/bin/arkfile"

echo -e "${GREEN}Setting up OPAQUE server keys...${NC}"

# Check if arkfile binary exists
if [ ! -f "${ARKFILE_BIN}" ]; then
    echo -e "${RED}Error: Arkfile binary not found at ${ARKFILE_BIN}${NC}"
    echo "Please build and install the application first"
    exit 1
fi

# Check if key directory exists
if [ ! -d "${KEY_DIR}" ]; then
    echo -e "${RED}Error: Key directory ${KEY_DIR} does not exist${NC}"
    echo "Please run setup-directories.sh first"
    exit 1
fi

# Check if keys already exist
if [ -f "${KEY_DIR}/server_private.key" ]; then
    echo -e "${YELLOW}OPAQUE keys already exist. Skipping generation.${NC}"
    echo "To regenerate keys, remove existing files first:"
    echo "  sudo rm ${KEY_DIR}/*"
    exit 0
fi

echo "Generating OPAQUE server keys..."

# Generate OPAQUE server keys using Go application
# Note: This would require implementing a CLI command in main.go
# For now, we'll create placeholder keys and document the proper implementation

echo "Creating OPAQUE key placeholders..."
sudo -u ${USER} bash -c "
    echo 'OPAQUE_SERVER_PRIVATE_KEY_PLACEHOLDER' > '${KEY_DIR}/server_private.key'
    echo 'OPAQUE_SERVER_PUBLIC_KEY_PLACEHOLDER' > '${KEY_DIR}/server_public.key'
    echo 'OPAQUE_OPRF_SEED_PLACEHOLDER' > '${KEY_DIR}/oprf_seed.key'
"

# Set proper permissions
sudo chown -R ${USER}:${GROUP} ${KEY_DIR}
sudo chmod 600 ${KEY_DIR}/*.key
sudo chmod 644 ${KEY_DIR}/server_public.key  # Public key can be readable

echo -e "${GREEN}✓ OPAQUE keys generated and secured${NC}"
echo "Location: ${KEY_DIR}"
echo "Permissions: Private keys (600), Public key (644)"
echo "Owner: ${USER}:${GROUP}"

echo -e "${YELLOW}Note: Generated placeholder keys for development.${NC}"
echo "Production deployment requires implementing OPAQUE key generation in main.go:"
echo "  - Add CLI command: arkfile generate-opaque-keys"
echo "  - Use bytemare/opaque library to generate real keys"
echo "  - Replace placeholders with actual cryptographic material"

# Validate key files exist and have correct permissions
echo "Validating key setup..."
for key_file in server_private.key server_public.key oprf_seed.key; do
    key_path="${KEY_DIR}/${key_file}"
    if [ -f "${key_path}" ]; then
        perms=$(stat -c "%a" "${key_path}")
        owner=$(stat -c "%U:%G" "${key_path}")
        echo "  ✓ ${key_file}: ${perms} ${owner}"
    else
        echo -e "  ${RED}✗ ${key_file}: Missing${NC}"
    fi
done

echo -e "${GREEN}OPAQUE key setup complete!${NC}"
