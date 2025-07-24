#!/bin/bash

# Detailed TOTP Validation Debug Script
# This script traces the complete TOTP validation flow to identify why codes are failing

echo "🔍 DETAILED TOTP VALIDATION DEBUG SESSION"
echo "========================================"

# Test user credentials from our manual testing
TEST_EMAIL="test-user@example.com"
TEST_PASSWORD="SecureTestPassword123!"

echo ""
echo "📋 Test Configuration:"
echo "  Email: $TEST_EMAIL"
echo "  Password: [REDACTED]"

echo ""
echo "🔄 Step 1: OPAQUE Login to get temp token and session key"
echo "-------------------------------------------------------"

LOGIN_RESPONSE=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}" \
  "https://localhost:4443/api/opaque/login")

echo "Login Response: $LOGIN_RESPONSE"

# Extract temp token and session key
TEMP_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.tempToken // empty')
SESSION_KEY=$(echo "$LOGIN_RESPONSE" | jq -r '.sessionKey // empty')

if [[ -z "$TEMP_TOKEN" || "$TEMP_TOKEN" == "null" ]]; then
    echo "❌ ERROR: Could not extract temp token from login response"
    exit 1
fi

if [[ -z "$SESSION_KEY" || "$SESSION_KEY" == "null" ]]; then
    echo "❌ ERROR: Could not extract session key from login response"
    exit 1
fi

echo ""
echo "✅ Extracted tokens:"
echo "  Temp Token: ${TEMP_TOKEN:0:50}..."
echo "  Session Key: $SESSION_KEY"

echo ""
echo "🔄 Step 2: Check TOTP status for user"
echo "------------------------------------"

TOTP_STATUS=$(curl -s --insecure -X GET -H "Authorization: Bearer $TEMP_TOKEN" \
  "https://localhost:4443/api/totp/status")

echo "TOTP Status Response: $TOTP_STATUS"

# Check if user has TOTP enabled
TOTP_ENABLED=$(echo "$TOTP_STATUS" | jq -r '.enabled // false')
echo "TOTP Enabled: $TOTP_ENABLED"

if [[ "$TOTP_ENABLED" != "true" ]]; then
    echo "❌ ERROR: User does not have TOTP enabled - need to set up first"
    exit 1
fi

echo ""
echo "🔄 Step 3: Retrieve TOTP secret from database"
echo "--------------------------------------------"

# We need to check the database directly to get the actual secret
echo "Checking database for TOTP secret..."

# Get the user's TOTP secret from database (we'll need to query this manually)
echo "NOTE: We need to check the database to see the actual stored secret"

echo ""
echo "🔄 Step 4: Generate multiple TOTP codes with current tool"
echo "--------------------------------------------------------"

# Get the TOTP secret that was stored during setup
# From our manual testing, we know it was: AFVSGGJAHMTTPOKGX3NYC4XGUQAYPD6RHN32N25WY3RJAUA44GAA
KNOWN_SECRET="AFVSGGJAHMTTPOKGX3NYC4XGUQAYPD6RHN32N25WY3RJAUA44GAA"

echo "Using known secret from manual testing: $KNOWN_SECRET"

echo ""
echo "Generating TOTP codes at different time windows:"

for i in {-2..2}; do
    # Calculate timestamp with offset
    TIMESTAMP=$(($(date +%s) + (i * 30)))
    echo "  Window $i (timestamp: $TIMESTAMP):"
    
    # Generate code for this timestamp
    CODE=$(./scripts/totp-generator "$KNOWN_SECRET" $TIMESTAMP 2>/dev/null || echo "ERROR")
    echo "    Generated code: $CODE"
    
    if [[ "$CODE" != "ERROR" && "$CODE" =~ ^[0-9]{6}$ ]]; then
        echo "    Testing this code..."
        
        TEST_RESPONSE=$(curl -s --insecure -X POST \
          -H "Authorization: Bearer $TEMP_TOKEN" \
          -H "Content-Type: application/json" \
          -d "{\"code\":\"$CODE\",\"sessionKey\":\"$SESSION_KEY\"}" \
          "https://localhost:4443/api/totp/auth")
        
        echo "    Response: $TEST_RESPONSE"
        
        # Check if successful
        if echo "$TEST_RESPONSE" | jq -e '.token' > /dev/null 2>&1; then
            echo "    ✅ SUCCESS: Code accepted!"
            break
        else
            echo "    ❌ FAILED: Code rejected"
        fi
    fi
    echo ""
done

echo ""
echo "🔄 Step 5: Test with current time code only"
echo "------------------------------------------"

CURRENT_CODE=$(./scripts/totp-generator "$KNOWN_SECRET")
echo "Current time code: $CURRENT_CODE"

echo ""
echo "Testing current code with /api/totp/auth endpoint:"
AUTH_RESPONSE=$(curl -s --insecure -X POST \
  -H "Authorization: Bearer $TEMP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"$CURRENT_CODE\",\"sessionKey\":\"$SESSION_KEY\"}" \
  "https://localhost:4443/api/totp/auth")

echo "Auth Response: $AUTH_RESPONSE"

echo ""
echo "Testing current code with /api/totp/verify endpoint:"
VERIFY_RESPONSE=$(curl -s --insecure -X POST \
  -H "Authorization: Bearer $TEMP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"$CURRENT_CODE\",\"sessionKey\":\"$SESSION_KEY\"}" \
  "https://localhost:4443/api/totp/verify")

echo "Verify Response: $VERIFY_RESPONSE"

echo ""
echo "🔄 Step 6: Check system time synchronization"
echo "-------------------------------------------"

echo "Current system time: $(date)"
echo "Unix timestamp: $(date +%s)"
echo "30-second window: $(($(date +%s) / 30))"

echo ""
echo "🔄 Step 7: Manual TOTP calculation verification"
echo "----------------------------------------------"

echo "Let's manually verify TOTP calculation..."
echo "Secret: $KNOWN_SECRET"
echo "Current timestamp: $(date +%s)"

# Use a simple Python calculation if available
if command -v python3 > /dev/null; then
    echo "Python3 TOTP calculation:"
    python3 -c "
import hmac
import hashlib
import base64
import struct
import time

secret = '$KNOWN_SECRET'
# Remove padding and decode
secret = secret.rstrip('=')
# Add back proper padding
while len(secret) % 8 != 0:
    secret += '='

try:
    key = base64.b32decode(secret)
    timestamp = int(time.time()) // 30
    
    # Pack timestamp
    packed_time = struct.pack('>Q', timestamp)
    
    # HMAC-SHA1
    hmac_digest = hmac.new(key, packed_time, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = hmac_digest[-1] & 0xf
    code = struct.unpack('>I', hmac_digest[offset:offset+4])[0]
    code = (code & 0x7fffffff) % 1000000
    
    print(f'Manual calculation: {code:06d}')
    print(f'Timestamp used: {timestamp}')
    print(f'Key length: {len(key)} bytes')
    
except Exception as e:
    print(f'Error in manual calculation: {e}')
"
else
    echo "Python3 not available for manual calculation"
fi

echo ""
echo "🔍 Debug session completed!"
echo "=========================="

echo ""
echo "📊 Summary of findings will be analyzed to identify the root cause."
