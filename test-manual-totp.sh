#!/bin/bash

# Manual TOTP test script to test the fix
set -e

echo "=== Manual TOTP Testing ==="
echo "Testing TOTP setup and completion flow"

USER_EMAIL="manual-totp-test@example.com"
BASE_URL="https://localhost:4443"

# Test 1: Complete OPAQUE registration first
echo
echo "Step 1: Testing OPAQUE registration..."

# Registration request
REG_REQUEST=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
    -d "{\"userEmail\":\"$USER_EMAIL\",\"password\":\"TestPassword123!\"}" \
    "$BASE_URL/api/auth/register/init")

echo "Registration init response: $REG_REQUEST"

# Extract values from registration response
REQUEST_STATE=$(echo "$REG_REQUEST" | jq -r '.requestState // empty')
OPAQUE_KEY=$(echo "$REG_REQUEST" | jq -r '.opaqueKey // empty')

if [[ -z "$REQUEST_STATE" || -z "$OPAQUE_KEY" ]]; then
    echo "❌ Failed to get registration data"
    exit 1
fi

echo "✅ Got registration data"

# Complete registration
REG_COMPLETE=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
    -d "{\"userEmail\":\"$USER_EMAIL\",\"requestState\":\"$REQUEST_STATE\",\"responseState\":\"dummy_response_state\",\"exportKey\":\"$(echo -n 'REGISTRATION_TEMP_KEY_32_BYTES!' | base64)\"}" \
    "$BASE_URL/api/auth/register/complete")

echo "Registration complete response: $REG_COMPLETE"

# Test 2: Login to get session key
echo
echo "Step 2: Testing OPAQUE login..."

LOGIN_INIT=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
    -d "{\"userEmail\":\"$USER_EMAIL\",\"password\":\"TestPassword123!\"}" \
    "$BASE_URL/api/auth/login/init")

echo "Login init response: $LOGIN_INIT"

# For testing, we'll create a mock session key
SESSION_KEY="UkVHSVNUUkFUSU9OX1RFTVBfS0VZXzMyX0JZVEVTISE="

# Test 3: Generate TOTP setup
echo
echo "Step 3: Testing TOTP setup generation..."

TOTP_SETUP=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
    -d "{\"userEmail\":\"$USER_EMAIL\",\"sessionKey\":\"$SESSION_KEY\"}" \
    "$BASE_URL/api/totp/generate-setup")

echo "TOTP setup response: $TOTP_SETUP"

# Extract secret
SECRET=$(echo "$TOTP_SETUP" | jq -r '.secret // empty')

if [[ -z "$SECRET" ]]; then
    echo "❌ Failed to generate TOTP setup"
    exit 1
fi

echo "✅ Generated TOTP setup with secret: $SECRET"

# Test 4: Generate current TOTP code
echo
echo "Step 4: Generating current TOTP code..."

CURRENT_CODE=$(./scripts/totp-generator "$SECRET")
echo "Current TOTP code: $CURRENT_CODE"

# Test 5: Complete TOTP setup
echo
echo "Step 5: Testing TOTP setup completion..."

TOTP_COMPLETE=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
    -d "{\"userEmail\":\"$USER_EMAIL\",\"testCode\":\"$CURRENT_CODE\",\"sessionKey\":\"$SESSION_KEY\"}" \
    "$BASE_URL/api/totp/complete-setup")

echo "TOTP complete response: $TOTP_COMPLETE"

# Check if successful
if echo "$TOTP_COMPLETE" | jq -e '.message | contains("success")' > /dev/null 2>&1; then
    echo "✅ TOTP setup completed successfully!"
else
    echo "❌ TOTP setup completion failed"
    echo "Response: $TOTP_COMPLETE"
    exit 1
fi

echo
echo "=== All tests passed! ==="
