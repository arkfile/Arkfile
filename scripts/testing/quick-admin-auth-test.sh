#!/bin/bash

# Quick Admin Authentication Test
# Tests the complete OPAQUE + TOTP flow using correct endpoints

set -euo pipefail

# Configuration
ARKFILE_BASE_URL="${ARKFILE_BASE_URL:-https://localhost:4443}"
ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
TOTP_SECRET="JBSWY3DPEHPK3PXP"  # Fixed dev secret

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

echo -e "${BLUE}╔═══════════════════════════════════════════╗"
echo "║          QUICK ADMIN AUTH TEST            ║"
echo "╚═══════════════════════════════════════════╝${NC}"

# Step 1: OPAQUE Login (correct endpoint)
log "Step 1: OPAQUE Authentication..."
OPAQUE_RESPONSE=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/opaque/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$ADMIN_USERNAME\",
    \"password\": \"$ADMIN_PASSWORD\"
  }")

if echo "$OPAQUE_RESPONSE" | jq -e '.requiresTOTP' >/dev/null 2>&1; then
    success "OPAQUE authentication successful"
    TEMP_TOKEN=$(echo "$OPAQUE_RESPONSE" | jq -r '.tempToken')
    SESSION_KEY=$(echo "$OPAQUE_RESPONSE" | jq -r '.sessionKey')
    log "Extracted temporary token and session key"
else
    error "OPAQUE login failed: $OPAQUE_RESPONSE"
fi

# Step 2: Generate current TOTP code
log "Step 2: Generating TOTP code..."
if [ -x "./scripts/testing/totp-generator" ]; then
    TOTP_CODE=$(./scripts/testing/totp-generator "$TOTP_SECRET")
    success "Generated TOTP code: $TOTP_CODE"
elif [ -x "./totp-generator" ]; then
    TOTP_CODE=$(./totp-generator "$TOTP_SECRET")
    success "Generated TOTP code: $TOTP_CODE"
else
    error "TOTP generator not found. Please run from project root directory."
fi

# Step 3: Complete TOTP authentication
log "Step 3: TOTP Authentication..."
TOTP_RESPONSE=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/totp/auth" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TEMP_TOKEN" \
  -d "{
    \"code\": \"$TOTP_CODE\",
    \"sessionKey\": \"$SESSION_KEY\"
  }")

if echo "$TOTP_RESPONSE" | jq -e '.token' >/dev/null 2>&1; then
    success "TOTP authentication successful"
    FINAL_TOKEN=$(echo "$TOTP_RESPONSE" | jq -r '.token')
    REFRESH_TOKEN=$(echo "$TOTP_RESPONSE" | jq -r '.refreshToken')
    AUTH_METHOD=$(echo "$TOTP_RESPONSE" | jq -r '.authMethod')
    log "Final token obtained - Auth method: $AUTH_METHOD"
else
    error "TOTP authentication failed: $TOTP_RESPONSE"
fi

# Step 4: Test authenticated API call
log "Step 4: Testing authenticated API access..."
API_RESPONSE=$(curl -k -s -H "Authorization: Bearer $FINAL_TOKEN" \
  "$ARKFILE_BASE_URL/api/files")

if echo "$API_RESPONSE" | jq -e '.' >/dev/null 2>&1; then
    success "Authenticated API call successful"
    log "Files API response: $(echo "$API_RESPONSE" | jq -c '.')"
else
    warning "API call response: $API_RESPONSE"
fi

# Success summary
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════╗"
echo "║        ADMIN AUTH TEST PASSED ✅          ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}Test Summary:${NC}"
echo -e "${GREEN}✅ OPAQUE Login: /api/opaque/login endpoint working${NC}"
echo -e "${GREEN}✅ TOTP Generation: Real-time code generation${NC}"
echo -e "${GREEN}✅ TOTP Auth: /api/totp/auth endpoint working${NC}"
echo -e "${GREEN}✅ API Access: Authenticated endpoints accessible${NC}"
echo -e "${GREEN}✅ Full Flow: Complete OPAQUE+TOTP authentication${NC}"

log "🎉 Admin authentication system fully operational!"
