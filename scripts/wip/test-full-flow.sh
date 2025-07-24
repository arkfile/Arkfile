#!/bin/bash

# Test script for the complete Arkfile registration, approval, and TOTP flow.
set -xeuo pipefail

# Configuration
ARKFILE_BASE_URL="https://localhost:4443"
INSECURE_FLAG="--insecure"
TEST_EMAIL="full-flow-test@example.com"
TEST_PASSWORD="SecurePassword123!"
TEMP_DIR=$(mktemp -d)

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

cleanup() {
    log "Cleaning up temporary directory..."
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# 1. Clean up existing test user
log "Cleaning up existing user: $TEST_EMAIL..."
curl -s -v -u "demo-user:TestPassword123_Secure" \
    -X POST "http://localhost:4001/db/execute" \
    -H "Content-Type: application/json" \
    -d "[\"DELETE FROM users WHERE email = '$TEST_EMAIL'\"]" >/dev/null
success "User cleanup complete."

# 2. Register user
log "Registering new user: $TEST_EMAIL..."
REG_RESPONSE=$(curl -s $INSECURE_FLAG -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$TEST_EMAIL\", \"password\": \"$TEST_PASSWORD\"}" \
    "$ARKFILE_BASE_URL/api/opaque/register")

TEMP_TOKEN=$(echo "$REG_RESPONSE" | jq -r '.tempToken')
SESSION_KEY=$(echo "$REG_RESPONSE" | jq -r '.sessionKey')

if [ -z "$TEMP_TOKEN" ] || [ "$TEMP_TOKEN" == "null" ]; then
    error "Registration failed. Response: $REG_RESPONSE"
fi
success "User registered. Temp token and session key obtained."

# 3. Approve user
log "Approving user: $TEST_EMAIL..."
curl -s -u "demo-user:TestPassword123_Secure" \
    -X POST "http://localhost:4001/db/execute" \
    -H "Content-Type: application/json" \
    -d "[\"UPDATE users SET is_approved = 1 WHERE email = '$TEST_EMAIL'\"]" >/dev/null
success "User approved."

# 4. Set up TOTP
log "Setting up TOTP..."
SETUP_RESPONSE=$(curl -s $INSECURE_FLAG -X POST \
    -H "Authorization: Bearer $TEMP_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"sessionKey\": \"$SESSION_KEY\"}" \
    "$ARKFILE_BASE_URL/api/totp/setup")

TOTP_SECRET=$(echo "$SETUP_RESPONSE" | jq -r '.secret')
if [ -z "$TOTP_SECRET" ] || [ "$TOTP_SECRET" == "null" ]; then
    error "TOTP setup failed. Response: $SETUP_RESPONSE"
fi
success "TOTP setup initiated. Secret obtained."

# 5. Verify TOTP
log "Verifying TOTP..."
TOTP_CODE=$(go run scripts/totp-generator.go "$TOTP_SECRET")
VERIFY_RESPONSE=$(curl -s $INSECURE_FLAG -X POST \
    -H "Authorization: Bearer $TEMP_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\": \"$TOTP_CODE\", \"sessionKey\": \"$SESSION_KEY\"}" \
    "$ARKFILE_BASE_URL/api/totp/verify")

if [[ "$(echo "$VERIFY_RESPONSE" | jq -r '.status')" != "ok" ]]; then
    error "TOTP verification failed. Response: $VERIFY_RESPONSE"
fi
success "TOTP setup verified."

# 6. Log in
log "Logging in..."
LOGIN_RESPONSE=$(curl -s $INSECURE_FLAG -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$TEST_EMAIL\", \"password\": \"$TEST_PASSWORD\"}" \
    "$ARKFILE_BASE_URL/api/opaque/login")

LOGIN_TEMP_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.tempToken')
LOGIN_SESSION_KEY=$(echo "$LOGIN_RESPONSE" | jq -r '.sessionKey')

if [ -z "$LOGIN_TEMP_TOKEN" ] || [ "$LOGIN_TEMP_TOKEN" == "null" ]; then
    error "Login failed. Response: $LOGIN_RESPONSE"
fi
success "Login step 1 complete. TOTP required."

# 7. Final TOTP Authentication
log "Performing final TOTP authentication..."
LOGIN_TOTP_CODE=$(go run scripts/totp-generator.go "$TOTP_SECRET")
AUTH_RESPONSE=$(curl -s $INSECURE_FLAG -X POST \
    -H "Authorization: Bearer $LOGIN_TEMP_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\": \"$LOGIN_TOTP_CODE\", \"sessionKey\": \"$LOGIN_SESSION_KEY\"}" \
    "$ARKFILE_BASE_URL/api/totp/auth")

FINAL_TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.token')
if [ -z "$FINAL_TOKEN" ] || [ "$FINAL_TOKEN" == "null" ]; then
    error "Final authentication failed. Response: $AUTH_RESPONSE"
fi
success "Login successful! Final token obtained."

log "Full pipeline test completed successfully!"
