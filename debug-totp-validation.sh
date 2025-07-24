#!/bin/bash

set -e

# TOTP credentials from our last test
EMAIL="manual-test-1753365497@example.com"
SECRET="YWCB6LBIPBBVUA3Y73PJQ6DM3377YG3I7MMHIT3CC3ARQ63P2YXA"
TEMP_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im1hbnVhbC10ZXN0LTE3NTMzNjU0OTdAZXhhbXBsZS5jb20iLCJyZXF1aXJlc190b3RwIjp0cnVlLCJpc3MiOiJhcmtmaWxlLWF1dGgiLCJhdWQiOlsiYXJrZmlsZS10b3RwIl0sImV4cCI6MTc1MzM2NTc5NywibmJmIjoxNzUzMzY1NDk3LCJpYXQiOjE3NTMzNjU0OTcsImp0aSI6ImEzZTIyOWYyLWI5YWItNDEyZi1hNGIzLTgwMGIyNTI3MzRiMyJ9.j4rf3ZjfyRyFf9UcTC4XQS63VxQTDFCnweJJD0x_7KE"
SESSION_KEY="UkVHSVNUUkFUSU9OX1RFTVBfS0VZXzMyX0JZVEVTISE="

echo "=== TOTP VALIDATION DEBUG ==="
echo "Email: $EMAIL"
echo "Secret: $SECRET"
echo "Temp Token: ${TEMP_TOKEN:0:50}..."
echo "Session Key: $SESSION_KEY"
echo

# Test 1: Generate multiple TOTP codes
echo "Test 1: Generating TOTP codes for different time windows..."
CURRENT_TIME=$(date +%s)
echo "Current Unix timestamp: $CURRENT_TIME"

for i in -1 0 1; do
    OFFSET_TIME=$((CURRENT_TIME + i * 30))
    TOTP_CODE=$(./scripts/totp-generator "$SECRET" "$OFFSET_TIME")
    HUMAN_TIME=$(date -d "@$OFFSET_TIME" "+%Y-%m-%d %H:%M:%S")
    echo "Time window $i (${HUMAN_TIME}): $TOTP_CODE"
done
echo

# Test 2: Try current TOTP code
echo "Test 2: Testing current TOTP code..."
CURRENT_CODE=$(./scripts/totp-generator "$SECRET")
echo "Generated code: $CURRENT_CODE"

echo "Making verification request..."
VERIFY_RESPONSE=$(curl -s -k -X POST "https://localhost:4443/api/totp/verify" \
    -H "Authorization: Bearer $TEMP_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$CURRENT_CODE\",\"sessionKey\":\"$SESSION_KEY\"}")

echo "Response: $VERIFY_RESPONSE"
echo

# Test 3: Check if there's a token expiration issue
echo "Test 3: Checking token validity..."
JWT_PAYLOAD=$(echo "$TEMP_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.' 2>/dev/null || echo "Failed to decode JWT")
echo "JWT Payload: $JWT_PAYLOAD"
echo

# Test 4: Check database state
echo "Test 4: Checking TOTP setup status via API..."
STATUS_RESPONSE=$(curl -s -k -X GET "https://localhost:4443/api/totp/status" \
    -H "Authorization: Bearer $TEMP_TOKEN")
echo "TOTP Status: $STATUS_RESPONSE"
echo

echo "=== DEBUG COMPLETE ==="
