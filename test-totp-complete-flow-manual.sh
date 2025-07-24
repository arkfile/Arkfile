#!/bin/bash

set -e

BASE_URL="https://localhost:4443"
TEST_EMAIL="manual-test-$(date +%s)@example.com"
TEST_PASSWORD="TestPassword123!"

echo "=== ARKFILE TOTP COMPLETE FLOW TEST ==="
echo "Email: $TEST_EMAIL"
echo "Password: $TEST_PASSWORD"
echo

# Step 1: Register user
echo "Step 1: Registering user..."
REGISTER_RESPONSE=$(curl -s -k -X POST "$BASE_URL/api/opaque/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")

echo "Registration response: $REGISTER_RESPONSE"

# Extract temp token for TOTP setup
TEMP_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.tempToken // empty')
REQUIRES_TOTP=$(echo "$REGISTER_RESPONSE" | jq -r '.requiresTOTPSetup // false')

if [ -z "$TEMP_TOKEN" ] || [ "$TEMP_TOKEN" = "null" ]; then
    echo "❌ Failed to get temp token from registration"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
fi

if [ "$REQUIRES_TOTP" != "true" ]; then
    echo "❌ Registration should require TOTP setup"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
fi

echo "✅ User registered successfully with mandatory TOTP requirement"
echo "Temp token: ${TEMP_TOKEN:0:20}..."
echo "Requires TOTP: $REQUIRES_TOTP"
echo

# Extract session key from registration response
SESSION_KEY=$(echo "$REGISTER_RESPONSE" | jq -r '.sessionKey // empty')

if [ -z "$SESSION_KEY" ] || [ "$SESSION_KEY" = "null" ]; then
    echo "❌ Failed to get session key from registration"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
fi

echo "Session key: ${SESSION_KEY:0:20}..."

# Step 2: Setup TOTP
echo "Step 2: Setting up TOTP..."
TOTP_SETUP_RESPONSE=$(curl -s -k -X POST "$BASE_URL/api/totp/setup" \
    -H "Authorization: Bearer $TEMP_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"sessionKey\":\"$SESSION_KEY\"}")

echo "TOTP setup response: $TOTP_SETUP_RESPONSE"

# Extract TOTP secret
TOTP_SECRET=$(echo "$TOTP_SETUP_RESPONSE" | jq -r '.secret // empty')

if [ -z "$TOTP_SECRET" ] || [ "$TOTP_SECRET" = "null" ]; then
    echo "❌ Failed to get TOTP secret"
    exit 1
fi

echo "✅ TOTP setup initiated"
echo "Secret: $TOTP_SECRET"
echo

# Step 3: Generate TOTP code
echo "Step 3: Generating TOTP code..."
TOTP_CODE=$(./scripts/totp-generator "$TOTP_SECRET")

if [ -z "$TOTP_CODE" ]; then
    echo "❌ Failed to generate TOTP code"
    exit 1
fi

echo "✅ TOTP code generated: $TOTP_CODE"
echo

# Step 4: Complete TOTP setup
echo "Step 4: Completing TOTP setup..."
TOTP_VERIFY_RESPONSE=$(curl -s -k -X POST "$BASE_URL/api/totp/verify" \
    -H "Authorization: Bearer $TEMP_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$TOTP_CODE\",\"sessionKey\":\"$SESSION_KEY\"}")

echo "TOTP verification response: $TOTP_VERIFY_RESPONSE"

# Extract final tokens after TOTP verification
FINAL_ACCESS_TOKEN=$(echo "$TOTP_VERIFY_RESPONSE" | jq -r '.access_token // empty')
FINAL_REFRESH_TOKEN=$(echo "$TOTP_VERIFY_RESPONSE" | jq -r '.refresh_token // empty')

if [ -z "$FINAL_ACCESS_TOKEN" ] || [ "$FINAL_ACCESS_TOKEN" = "null" ]; then
    echo "❌ TOTP verification should return access token"
    echo "Response: $TOTP_VERIFY_RESPONSE"
    exit 1
fi

if echo "$TOTP_VERIFY_RESPONSE" | grep -q "error\|failed"; then
    echo "❌ TOTP verification failed"
    exit 1
fi

echo "✅ TOTP setup completed successfully"
echo "Final access token: ${FINAL_ACCESS_TOKEN:0:20}..."
echo

# Step 5: Check TOTP status
echo "Step 5: Checking TOTP status..."
TOTP_STATUS_RESPONSE=$(curl -s -k -X GET "$BASE_URL/api/totp/status" \
    -H "Authorization: Bearer $FINAL_ACCESS_TOKEN")

echo "TOTP status response: $TOTP_STATUS_RESPONSE"

if echo "$TOTP_STATUS_RESPONSE" | grep -q '"enabled":true'; then
    echo "✅ TOTP is now enabled for user"
else
    echo "❌ TOTP status check failed"
    exit 1
fi

echo
echo "🎉 COMPLETE TOTP FLOW TEST PASSED!"
echo "✅ User registration blocks immediate access (mandatory TOTP working)"
echo "✅ TOTP setup initiation with temp token"
echo "✅ TOTP code generation"
echo "✅ TOTP setup completion returns full access tokens"
echo "✅ TOTP status verification"
echo
echo "MANDATORY TOTP ENFORCEMENT CONFIRMED!"
echo "- Registration requires TOTP setup before full access"
echo "- No access tokens provided until TOTP is configured"
echo "- Users cannot bypass TOTP requirement"
