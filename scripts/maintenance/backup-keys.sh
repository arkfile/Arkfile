#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
KEY_DIR="/opt/arkfile/etc/keys"
BACKUP_DIR="/opt/arkfile/etc/keys/backups"
USER="arkfile"
GROUP="arkfile"
BACKUP_PREFIX="arkfile-keys"
RETENTION_DAYS=90

echo -e "${GREEN}Backing up Arkfile cryptographic keys...${NC}"

# Check if key directory exists
if [ ! -d "${KEY_DIR}" ]; then
    echo -e "${RED}Error: Key directory ${KEY_DIR} does not exist${NC}"
    exit 1
fi

# Check if backup directory exists
if [ ! -d "${BACKUP_DIR}" ]; then
    echo -e "${RED}Error: Backup directory ${BACKUP_DIR} does not exist${NC}"
    echo "Please run setup-directories.sh first"
    exit 1
fi

# Generate backup filename with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_PREFIX}_${TIMESTAMP}.tar.gz.enc"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILE}"

echo "Creating encrypted key backup..."
echo "Backup file: ${BACKUP_FILE}"

# Generate a backup encryption key
BACKUP_KEY=$(openssl rand -hex 32)
BACKUP_KEY_FILE="${BACKUP_DIR}/backup_key_${TIMESTAMP}.key"

# Create the backup archive (excluding the backups directory itself)
echo "Creating archive..."
sudo -u ${USER} tar -czf "/tmp/keys_backup_${TIMESTAMP}.tar.gz" \
    -C "${KEY_DIR}" \
    --exclude="backups" \
    opaque jwt tls

# Encrypt the backup archive
echo "Encrypting backup..."
sudo -u ${USER} bash -c "
    echo '${BACKUP_KEY}' | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in '/tmp/keys_backup_${TIMESTAMP}.tar.gz' \
        -out '${BACKUP_PATH}' \
        -pass stdin
"

# Save the backup key securely
sudo -u ${USER} bash -c "echo '${BACKUP_KEY}' > '${BACKUP_KEY_FILE}'"
sudo chmod 600 "${BACKUP_KEY_FILE}"

# Clean up temporary file
sudo rm -f "/tmp/keys_backup_${TIMESTAMP}.tar.gz"

# Create backup metadata
echo "Creating backup metadata..."
sudo -u ${USER} bash -c "cat > '${BACKUP_DIR}/backup_${TIMESTAMP}.json' << EOF
{
  \"backup_file\": \"${BACKUP_FILE}\",
  \"key_file\": \"backup_key_${TIMESTAMP}.key\",
  \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"retention_until\": \"$(date -u -d '+${RETENTION_DAYS} days' +%Y-%m-%dT%H:%M:%SZ)\",
  \"contents\": [
    \"opaque/server_private.key\",
    \"opaque/server_public.key\",
    \"opaque/oprf_seed.key\",
    \"jwt/current/signing.key\",
    \"jwt/current/public.key\",
    \"jwt/current/metadata.json\",
    \"tls/ca/ca.key\",
    \"tls/ca/ca.crt\",
    \"tls/rqlite/server.key\",
    \"tls/rqlite/server.crt\",
    \"tls/minio/server.key\",
    \"tls/minio/server.crt\"
  ],
  \"encryption\": \"AES-256-CBC with PBKDF2\",
  \"verification\": \"$(sha256sum '${BACKUP_PATH}' | cut -d' ' -f1)\"
}
EOF"

sudo chmod 644 "${BACKUP_DIR}/backup_${TIMESTAMP}.json"

echo -e "${GREEN}✓ Key backup created successfully${NC}"
echo "Backup file: ${BACKUP_PATH}"
echo "Key file: ${BACKUP_KEY_FILE}"
echo "Metadata: ${BACKUP_DIR}/backup_${TIMESTAMP}.json"

# Test backup integrity
echo "Testing backup integrity..."
if sudo -u ${USER} bash -c "
    echo '${BACKUP_KEY}' | openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
        -in '${BACKUP_PATH}' -pass stdin | tar -tz >/dev/null 2>&1
"; then
    echo "  ✓ Backup integrity test: PASSED"
else
    echo -e "  ${RED}✗ Backup integrity test: FAILED${NC}"
    exit 1
fi

# Clean up old backups
echo "Cleaning up old backups (older than ${RETENTION_DAYS} days)..."
OLD_BACKUPS=$(find "${BACKUP_DIR}" -name "${BACKUP_PREFIX}_*.tar.gz.enc" -mtime +${RETENTION_DAYS} 2>/dev/null || true)

if [ -n "${OLD_BACKUPS}" ]; then
    echo "Removing old backup files:"
    echo "${OLD_BACKUPS}" | while read -r old_backup; do
        if [ -f "${old_backup}" ]; then
            backup_basename=$(basename "${old_backup}" .tar.gz.enc)
            timestamp_part=$(echo "${backup_basename}" | sed "s/${BACKUP_PREFIX}_//")
            
            # Remove backup file
            sudo rm -f "${old_backup}"
            echo "  - Removed: $(basename "${old_backup}")"
            
            # Remove associated key and metadata files
            sudo rm -f "${BACKUP_DIR}/backup_key_${timestamp_part}.key"
            sudo rm -f "${BACKUP_DIR}/backup_${timestamp_part}.json"
        fi
    done
else
    echo "  No old backups to remove"
fi

# Display backup summary
echo ""
echo -e "${GREEN}Backup Summary${NC}"
echo "===================="
BACKUP_COUNT=$(find "${BACKUP_DIR}" -name "${BACKUP_PREFIX}_*.tar.gz.enc" | wc -l)
BACKUP_SIZE=$(du -sh "${BACKUP_PATH}" | cut -f1)
echo "Total backups: ${BACKUP_COUNT}"
echo "Latest backup size: ${BACKUP_SIZE}"
echo "Retention period: ${RETENTION_DAYS} days"
echo ""
echo "Backup restoration:"
echo "  1. Decrypt: echo '<backup_key>' | openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 -in '${BACKUP_FILE}' -pass stdin > keys.tar.gz"
echo "  2. Extract: tar -xzf keys.tar.gz -C /opt/arkfile/etc/keys/"
echo ""
echo -e "${YELLOW}Important: Store backup key securely and separately from backup file!${NC}"

# Clear sensitive variables
unset BACKUP_KEY
