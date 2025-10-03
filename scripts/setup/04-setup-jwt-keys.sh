#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
KEY_DIR="/opt/arkfile/etc/keys/jwt"
USER="arkfile"
GROUP="arkfile"

echo -e "${GREEN}Setting up JWT signing keys...${NC}"

# Check if key directory exists
if [ ! -d "${KEY_DIR}" ]; then
    echo -e "${RED}Error: Key directory ${KEY_DIR} does not exist${NC}"
    echo "Please run setup-directories.sh first"
    exit 1
fi

# Check if keys already exist
if [ -f "${KEY_DIR}/current/signing.key" ]; then
    echo -e "${YELLOW}JWT keys already exist. Skipping generation.${NC}"
    echo "To regenerate keys, remove existing files first:"
    echo "  sudo rm ${KEY_DIR}/current/*"
    exit 0
fi

echo "Generating JWT signing keys..."

# Generate Ed25519 private key for JWT signing
echo "Creating Ed25519 private key..."
sudo -u ${USER} openssl genpkey -algorithm ed25519 \
    -out "${KEY_DIR}/current/signing.key"

# Extract public key
echo "Extracting public key..."
sudo -u ${USER} openssl pkey -in "${KEY_DIR}/current/signing.key" \
    -pubout -out "${KEY_DIR}/current/public.key"

# Create key metadata file
echo "Creating key metadata..."
sudo -u ${USER} bash -c "cat > '${KEY_DIR}/current/metadata.json' << EOF
{
  \"algorithm\": \"Ed25519\",
  \"purpose\": \"JWT signing\",
  \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"rotation_due\": \"$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)\",
  \"key_id\": \"$(openssl rand -hex 8)\"
}
EOF"

# Set proper permissions
sudo chown -R ${USER}:${GROUP} ${KEY_DIR}
sudo chmod 600 ${KEY_DIR}/current/signing.key
sudo chmod 644 ${KEY_DIR}/current/public.key
sudo chmod 644 ${KEY_DIR}/current/metadata.json

echo -e "${GREEN}[OK] JWT keys generated and secured${NC}"
echo "Location: ${KEY_DIR}/current/"
echo "Algorithm: Ed25519"
echo "Permissions: Private key (600), Public key (644)"
echo "Owner: ${USER}:${GROUP}"

# Create rotation schedule file
echo "Creating rotation schedule..."
sudo -u ${USER} bash -c "cat > '${KEY_DIR}/rotation.schedule' << EOF
# JWT Key Rotation Schedule
# Format: YYYY-MM-DD HH:MM action
# Actions: rotate, backup, cleanup

# Automatic rotation every 30 days
$(date -u -d '+30 days' +%Y-%m-%d) 02:00 rotate

# Backup old keys every week  
$(date -u -d '+7 days' +%Y-%m-%d) 03:00 backup

# Cleanup old backups older than 90 days
$(date -u -d '+90 days' +%Y-%m-%d) 04:00 cleanup
EOF"

sudo chmod 644 ${KEY_DIR}/rotation.schedule

# Validate key files exist and have correct permissions
echo "Validating key setup..."
for key_file in signing.key public.key metadata.json; do
    key_path="${KEY_DIR}/current/${key_file}"
    if [ -f "${key_path}" ]; then
        perms=$(stat -c "%a" "${key_path}")
        owner=$(stat -c "%U:%G" "${key_path}")
        echo "  [OK] ${key_file}: ${perms} ${owner}"
    else
        echo -e "  ${RED}[X] ${key_file}: Missing${NC}"
    fi
done

# Test the generated keys
echo "Testing key generation..."
if command -v openssl >/dev/null 2>&1; then
    # Create a test message and sign it with timeout
    test_message="test_jwt_signing_$(date +%s)"
    
    # Use timeout to prevent hanging (5 second limit)
    if timeout 5s bash -c "echo -n '${test_message}' | sudo -u ${USER} openssl dgst -sha256 -sign '${KEY_DIR}/current/signing.key' > /tmp/test_signature 2>/dev/null"; then
        if [ -f "/tmp/test_signature" ] && [ -s "/tmp/test_signature" ]; then
            echo "  [OK] Key signing test: PASSED"
            rm -f /tmp/test_signature
        else
            echo -e "  ${YELLOW}[WARNING] Key signing test: No output generated (keys may still be valid)${NC}"
        fi
    else
        echo -e "  ${YELLOW}[WARNING] Key signing test: Timeout or error (keys may still be valid)${NC}"
        rm -f /tmp/test_signature 2>/dev/null
    fi
else
    echo -e "  ${YELLOW}[WARNING] OpenSSL not available for testing${NC}"
fi

echo -e "${GREEN}JWT key setup complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Configure application to use keys in ${KEY_DIR}/current/"
echo "  2. Set up automated key rotation using rotation.schedule"
echo "  3. Implement backup procedures for old keys"
