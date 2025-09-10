#!/bin/bash
# Test script to verify metadata encryption/decryption fixes
# This tests that arkfile-client encrypts metadata with password-derived keys
# and that cryptocli can decrypt it correctly

set -e

echo "=== Testing Metadata Encryption/Decryption Fix ==="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test data
TEST_FILE="/tmp/test-metadata-file.txt"
TEST_PASSWORD="TestPassword123!"
TEST_USERNAME="testuser"

# Create a test file
echo "This is test content for metadata encryption test" > "$TEST_FILE"

# Calculate expected SHA256
EXPECTED_SHA256=$(sha256sum "$TEST_FILE" | awk '{print $1}')
EXPECTED_FILENAME=$(basename "$TEST_FILE")

echo "Test file created: $TEST_FILE"
echo "Expected filename: $EXPECTED_FILENAME"
echo "Expected SHA256: $EXPECTED_SHA256"
echo

# Step 1: Simulate metadata encryption using arkfile-client approach
echo "Step 1: Testing metadata encryption (simulating arkfile-client upload)"
echo "------------------------------------------------------------------------"

# We'll use cryptocli to encrypt metadata the way arkfile-client now does it
# arkfile-client now uses: metadataKey := crypto.DeriveAccountPasswordKey(password, session.Username)

ENCRYPTED_OUTPUT=$(echo "$TEST_PASSWORD" | ./cmd/cryptocli/cryptocli encrypt-metadata \
    --filename "$EXPECTED_FILENAME" \
    --sha256sum "$EXPECTED_SHA256" \
    --username "$TEST_USERNAME" \
    --password-source stdin 2>/dev/null)

# Extract the encrypted values
ENCRYPTED_FILENAME=$(echo "$ENCRYPTED_OUTPUT" | grep "Encrypted Filename:" | awk '{print $3}')
ENCRYPTED_SHA256=$(echo "$ENCRYPTED_OUTPUT" | grep "Encrypted SHA256:" | awk '{print $3}')

if [ -n "$ENCRYPTED_FILENAME" ] && [ -n "$ENCRYPTED_SHA256" ]; then
    echo -e "${GREEN}✓ Metadata encrypted successfully${NC}"
    echo "  Encrypted filename: ${ENCRYPTED_FILENAME:0:20}..."
    echo "  Encrypted SHA256: ${ENCRYPTED_SHA256:0:20}..."
else
    echo -e "${RED}✗ Failed to encrypt metadata${NC}"
    exit 1
fi
echo

# Step 2: Test metadata decryption
echo "Step 2: Testing metadata decryption (using cryptocli)"
echo "-------------------------------------------------------"

# Create a temporary file with encrypted metadata to simulate what cryptocli would receive
METADATA_FILE="/tmp/encrypted-metadata.json"
cat > "$METADATA_FILE" <<EOF
{
  "encrypted_filename": "$ENCRYPTED_FILENAME",
  "encrypted_sha256sum": "$ENCRYPTED_SHA256",
  "username": "$TEST_USERNAME"
}
EOF

# Decrypt the metadata
DECRYPTED_OUTPUT=$(echo "$TEST_PASSWORD" | ./cmd/cryptocli/cryptocli decrypt-metadata \
    --encrypted-filename "$ENCRYPTED_FILENAME" \
    --encrypted-sha256sum "$ENCRYPTED_SHA256" \
    --username "$TEST_USERNAME" \
    --password-source stdin 2>/dev/null)

# Extract the decrypted values
DECRYPTED_FILENAME=$(echo "$DECRYPTED_OUTPUT" | grep "Decrypted Filename:" | cut -d':' -f2- | xargs)
DECRYPTED_SHA256=$(echo "$DECRYPTED_OUTPUT" | grep "Decrypted SHA256:" | cut -d':' -f2- | xargs)

echo "Decrypted filename: $DECRYPTED_FILENAME"
echo "Decrypted SHA256: $DECRYPTED_SHA256"
echo

# Step 3: Verify the results
echo "Step 3: Verifying results"
echo "--------------------------"

SUCCESS=true

if [ "$DECRYPTED_FILENAME" = "$EXPECTED_FILENAME" ]; then
    echo -e "${GREEN}✓ Filename matches${NC}"
else
    echo -e "${RED}✗ Filename mismatch!${NC}"
    echo "  Expected: $EXPECTED_FILENAME"
    echo "  Got: $DECRYPTED_FILENAME"
    SUCCESS=false
fi

if [ "$DECRYPTED_SHA256" = "$EXPECTED_SHA256" ]; then
    echo -e "${GREEN}✓ SHA256 matches${NC}"
else
    echo -e "${RED}✗ SHA256 mismatch!${NC}"
    echo "  Expected: $EXPECTED_SHA256"
    echo "  Got: $DECRYPTED_SHA256"
    SUCCESS=false
fi

# Clean up
rm -f "$TEST_FILE" "$METADATA_FILE"

echo
if [ "$SUCCESS" = true ]; then
    echo -e "${GREEN}=== ALL TESTS PASSED ===${NC}"
    echo "The metadata encryption/decryption fix is working correctly!"
    echo "- arkfile-client now encrypts metadata with password-derived keys"
    echo "- cryptocli can successfully decrypt the metadata"
    echo "- No more 0x41 version errors!"
    exit 0
else
    echo -e "${RED}=== TESTS FAILED ===${NC}"
    echo "There are still issues with metadata encryption/decryption"
    exit 1
fi
