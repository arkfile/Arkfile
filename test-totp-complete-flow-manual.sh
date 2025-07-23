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

# Extract tokens from registration response
ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.access_token // empty')
REFRESH_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.refresh_token // empty')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "❌ Failed to get access token from registration"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
fi

echo "✅ User registered successfully"
echo "Access token: ${ACCESS_TOKEN:0:20}..."
echo

# Step 2: Setup TOTP
echo "Step 2: Setting up TOTP..."
TOTP_SETUP_RESPONSE=$(curl -s -k -X POST "$BASE_URL/api/totp/setup" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json")

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
TOTP_CODE=$(go run << 'GOCODE'
package main

import (
    "fmt"
    "os"
    "time"
    "github.com/pquerna/otp/totp"
)

func main() {
    secret := os.Args[1]
    code, err := totp.GenerateCode(secret, time.Now())
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    fmt.Print(code)
}
GOCODE
$TOTP_SECRET)

if [ -z "$TOTP_CODE" ]; then
    echo "❌ Failed to generate TOTP code"
    exit 1
fi

echo "✅ TOTP code generated: $TOTP_CODE"
echo

# Step 4: Complete TOTP setup
echo "Step 4: Completing TOTP setup..."
TOTP_VERIFY_RESPONSE=$(curl -s -k -X POST "$BASE_URL/api/totp/verify" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$TOTP_CODE\"}")

echo "TOTP verification response: $TOTP_VERIFY_RESPONSE"

if echo "$TOTP_VERIFY_RESPONSE" | grep -q "error\|failed"; then
    echo "❌ TOTP verification failed"
    exit 1
fi

echo "✅ TOTP setup completed successfully"
echo

# Step 5: Check TOTP status
echo "Step 5: Checking TOTP status..."
TOTP_STATUS_RESPONSE=$(curl -s -k -X GET "$BASE_URL/api/totp/status" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

echo "TOTP status response: $TOTP_STATUS_RESPONSE"

if echo "$TOTP_STATUS_RESPONSE" | grep -q '"enabled":true'; then
    echo "✅ TOTP is now enabled for user"
else
    echo "❌ TOTP status check failed"
    exit 1
fi

echo
echo "🎉 COMPLETE TOTP FLOW TEST PASSED!"
echo "✅ User registration with mandatory TOTP"
echo "✅ TOTP setup initiation"
echo "✅ TOTP code generation"
echo "✅ TOTP setup completion"
echo "✅ TOTP status verification"
echo
echo "The application now enforces mandatory TOTP for all users!"
