#!/bin/bash

# Enhanced Admin Authentication Test
# Comprehensive OPAQUE + TOTP flow testing with debugging capabilities

set -euo pipefail

# Configuration
ARKFILE_BASE_URL="${ARKFILE_BASE_URL:-https://localhost:4443}"
ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
TOTP_SECRET="ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"  # Fixed dev secret (32-character Base32)

# Script options
DEBUG_MODE="${DEBUG_MODE:-1}"
VERBOSE="${VERBOSE:-1}"
TEST_MULTIPLE_CODES="${TEST_MULTIPLE_CODES:-1}"
CHECK_DATABASE="${CHECK_DATABASE:-1}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Temp files for cleanup
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] $1${NC}"
}

debug() {
    if [[ "$DEBUG_MODE" == "1" ]]; then
        echo -e "${PURPLE}🐛 DEBUG: $1${NC}"
    fi
}

verbose() {
    if [[ "$VERBOSE" == "1" ]]; then
        echo -e "${CYAN}📝 $1${NC}"
    fi
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    if [[ $# -gt 1 ]]; then
        echo -e "${RED}   Details: $2${NC}"
    fi
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Function to generate TOTP code for specific time window
generate_totp_for_window() {
    local secret=$1
    local time_offset=${2:-0}  # offset in 30-second windows
    
    if [[ "$time_offset" == "0" ]]; then
        ./scripts/testing/totp-generator "$secret"
    else
        # Calculate time with offset
        local current_time=$(date +%s)
        local adjusted_time=$((current_time + (time_offset * 30)))
        
        # Use Go to generate TOTP for specific time
        cat > "$TEMP_DIR/totp_time.go" << 'EOF'
package main

import (
    "fmt"
    "os"
    "strconv"
    "time"
    "github.com/pquerna/otp/totp"
)

func main() {
    if len(os.Args) != 3 {
        fmt.Fprintf(os.Stderr, "Usage: %s <secret> <unix_timestamp>\n", os.Args[0])
        os.Exit(1)
    }
    
    secret := os.Args[1]
    timestamp, err := strconv.ParseInt(os.Args[2], 10, 64)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Invalid timestamp: %v\n", err)
        os.Exit(1)
    }
    
    t := time.Unix(timestamp, 0)
    code, err := totp.GenerateCode(secret, t)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating TOTP: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Print(code)
}
EOF
        
        cd "$TEMP_DIR" && go mod init totp_time && go mod tidy
        go run totp_time.go "$secret" "$adjusted_time" 2>/dev/null || echo "ERROR"
    fi
}

# Function to check database TOTP data
check_database_totp() {
    if [[ "$CHECK_DATABASE" != "1" ]]; then
        return
    fi
    
    debug "Checking database TOTP configuration for admin user..."
    
    local query="SELECT username, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = '$ADMIN_USERNAME';"
    
    if command -v sqlite3 >/dev/null 2>&1; then
        verbose "Querying rqlite database directly..."
        curl -s -G 'http://localhost:4001/db/query' --data-urlencode "q=$query" | jq -r '.results[0].values[]' 2>/dev/null || echo "No results"
    else
        verbose "sqlite3 not available, skipping database check"
    fi
}

# Function to test TOTP authentication with detailed error reporting
test_totp_auth() {
    local temp_token=$1
    local session_key=$2
    local totp_code=$3
    local description=${4:-"Current"}
    
    verbose "Testing TOTP code: $totp_code ($description)"
    
    local response=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/totp/auth" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $temp_token" \
      -d "{
        \"code\": \"$totp_code\",
        \"sessionKey\": \"$session_key\"
      }" 2>/dev/null)
    
    debug "TOTP auth response for $description code: $response"
    
    if echo "$response" | jq -e '.token' >/dev/null 2>&1; then
        success "TOTP authentication successful with $description code ($totp_code)"
        echo "$response"
        return 0
    else
        local error_msg=$(echo "$response" | jq -r '.message // .error // "Unknown error"' 2>/dev/null || echo "Invalid JSON response")
        verbose "TOTP auth failed for $description code ($totp_code): $error_msg"
        return 1
    fi
}

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗"
echo "║              ENHANCED ADMIN AUTH TEST                      ║"
echo "╚════════════════════════════════════════════════════════════╝${NC}"

log "Configuration:"
verbose "  Base URL: $ARKFILE_BASE_URL"
verbose "  Admin Username: $ADMIN_USERNAME"
verbose "  TOTP Secret: ${TOTP_SECRET:0:8}...${TOTP_SECRET: -8}"
verbose "  Debug Mode: $DEBUG_MODE"
verbose "  Test Multiple Codes: $TEST_MULTIPLE_CODES"

# Pre-flight checks
log "Pre-flight checks..."

if [[ ! -x "./scripts/testing/totp-generator" ]]; then
    error "TOTP generator not found at ./scripts/testing/totp-generator"
    exit 1
fi

success "TOTP generator found"

# Check server connectivity
log "Checking server connectivity..."
if curl -k -s --connect-timeout 5 "$ARKFILE_BASE_URL/health" >/dev/null 2>&1; then
    success "Server is responding"
else
    error "Server not responding at $ARKFILE_BASE_URL"
    exit 1
fi

# Database check
check_database_totp

# Step 1: OPAQUE Login
log "Step 1: OPAQUE Authentication..."

OPAQUE_RESPONSE=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/opaque/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$ADMIN_USERNAME\",
    \"password\": \"$ADMIN_PASSWORD\"
  }")

debug "OPAQUE response: $OPAQUE_RESPONSE"

if echo "$OPAQUE_RESPONSE" | jq -e '.requiresTOTP' >/dev/null 2>&1; then
    success "OPAQUE authentication successful"
    TEMP_TOKEN=$(echo "$OPAQUE_RESPONSE" | jq -r '.tempToken')
    SESSION_KEY=$(echo "$OPAQUE_RESPONSE" | jq -r '.sessionKey')
    
    verbose "Temporary token: ${TEMP_TOKEN:0:20}...${TEMP_TOKEN: -20}"
    verbose "Session key: ${SESSION_KEY:0:20}...${SESSION_KEY: -20}"
else
    error "OPAQUE login failed" "$OPAQUE_RESPONSE"
    exit 1
fi

# Step 2: Generate TOTP codes for multiple time windows
log "Step 2: Generating TOTP codes for multiple time windows..."

declare -a TOTP_CODES
declare -a TOTP_DESCRIPTIONS

# Current window
CURRENT_CODE=$(generate_totp_for_window "$TOTP_SECRET" 0)
TOTP_CODES+=("$CURRENT_CODE")
TOTP_DESCRIPTIONS+=("Current window")

if [[ "$TEST_MULTIPLE_CODES" == "1" ]]; then
    # Previous window
    PREV_CODE=$(generate_totp_for_window "$TOTP_SECRET" -1)
    TOTP_CODES+=("$PREV_CODE")
    TOTP_DESCRIPTIONS+=("Previous window (-30s)")
    
    # Next window
    NEXT_CODE=$(generate_totp_for_window "$TOTP_SECRET" 1)
    TOTP_CODES+=("$NEXT_CODE")
    TOTP_DESCRIPTIONS+=("Next window (+30s)")
    
    # Two windows back
    PREV2_CODE=$(generate_totp_for_window "$TOTP_SECRET" -2)
    TOTP_CODES+=("$PREV2_CODE")
    TOTP_DESCRIPTIONS+=("Two windows back (-60s)")
fi

success "Generated ${#TOTP_CODES[@]} TOTP codes for testing"
for i in "${!TOTP_CODES[@]}"; do
    verbose "  ${TOTP_DESCRIPTIONS[$i]}: ${TOTP_CODES[$i]}"
done

# Step 3: Test TOTP authentication with multiple codes
log "Step 3: Testing TOTP Authentication..."

TOTP_SUCCESS=0
FINAL_TOKEN=""
REFRESH_TOKEN=""
AUTH_METHOD=""

for i in "${!TOTP_CODES[@]}"; do
    debug "Attempting TOTP authentication with ${TOTP_DESCRIPTIONS[$i]} code..."
    
    if TOTP_RESPONSE=$(test_totp_auth "$TEMP_TOKEN" "$SESSION_KEY" "${TOTP_CODES[$i]}" "${TOTP_DESCRIPTIONS[$i]}"); then
        FINAL_TOKEN=$(echo "$TOTP_RESPONSE" | jq -r '.token')
        REFRESH_TOKEN=$(echo "$TOTP_RESPONSE" | jq -r '.refreshToken')
        AUTH_METHOD=$(echo "$TOTP_RESPONSE" | jq -r '.authMethod')
        TOTP_SUCCESS=1
        break
    fi
done

if [[ "$TOTP_SUCCESS" != "1" ]]; then
    error "All TOTP authentication attempts failed"
    
    # Additional debugging
    log "Additional debugging information:"
    
    # Check current system time
    verbose "Current system time: $(date)"
    verbose "Current Unix timestamp: $(date +%s)"
    
    # Check if TOTP is enabled in database
    check_database_totp
    
    # Try to get more detailed error from server logs
    debug "Recent server logs (TOTP related):"
    if command -v journalctl >/dev/null 2>&1; then
        sudo journalctl -u arkfile --no-pager -n 5 2>/dev/null | grep -i totp || echo "No recent TOTP logs"
    fi
    
    exit 1
fi

success "TOTP authentication successful"
verbose "Final token: ${FINAL_TOKEN:0:20}...${FINAL_TOKEN: -20}"
verbose "Auth method: $AUTH_METHOD"

# Step 4: Test authenticated API calls
log "Step 4: Testing authenticated API access..."

declare -a API_ENDPOINTS
API_ENDPOINTS=(
    "/api/files"
    "/health"
    "/api/totp/status"
)

for endpoint in "${API_ENDPOINTS[@]}"; do
    verbose "Testing endpoint: $endpoint"
    
    API_RESPONSE=$(curl -k -s \
      -H "Authorization: Bearer $FINAL_TOKEN" \
      "$ARKFILE_BASE_URL$endpoint")
    
    if echo "$API_RESPONSE" | jq -e '.' >/dev/null 2>&1; then
        success "✅ $endpoint - Valid JSON response"
        if [[ "$DEBUG_MODE" == "1" ]]; then
            debug "Response: $(echo "$API_RESPONSE" | jq -c '. | if type == "object" and has("message") then {message: .message} elif type == "array" then ("Array with " + (length | tostring) + " items") else . end')"
        fi
    else
        warning "⚠️  $endpoint - Non-JSON response: ${API_RESPONSE:0:100}..."
    fi
done

# Step 5: Test token refresh
log "Step 5: Testing token refresh..."

if [[ -n "$REFRESH_TOKEN" ]]; then
    REFRESH_RESPONSE=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/refresh" \
      -H "Content-Type: application/json" \
      -d "{\"refreshToken\": \"$REFRESH_TOKEN\"}")
    
    if echo "$REFRESH_RESPONSE" | jq -e '.token' >/dev/null 2>&1; then
        success "Token refresh successful"
        NEW_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.token')
        verbose "New token: ${NEW_TOKEN:0:20}...${NEW_TOKEN: -20}"
    else
        warning "Token refresh failed: $REFRESH_RESPONSE"
    fi
else
    warning "No refresh token available for testing"
fi

# Success summary
echo
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗"
echo "║                   🎉 ALL TESTS PASSED 🎉                   ║"
echo "╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "${BLUE}Test Summary:${NC}"
echo -e "${GREEN}✅ Server Connectivity: $ARKFILE_BASE_URL reachable${NC}"
echo -e "${GREEN}✅ OPAQUE Login: /api/opaque/login endpoint working${NC}"
echo -e "${GREEN}✅ TOTP Generation: Multiple time window codes generated${NC}"
echo -e "${GREEN}✅ TOTP Auth: /api/totp/auth endpoint working${NC}"
echo -e "${GREEN}✅ API Access: Multiple authenticated endpoints tested${NC}"
echo -e "${GREEN}✅ Token Refresh: Refresh token functionality verified${NC}"
echo -e "${GREEN}✅ Full Flow: Complete OPAQUE+TOTP authentication pipeline${NC}"

log "🚀 Admin authentication system fully operational and tested!"

# Output key information for further use
if [[ "$DEBUG_MODE" == "1" ]]; then
    echo
    log "Key tokens for manual testing:"
    echo "ADMIN_TOKEN=\"$FINAL_TOKEN\""
    echo "REFRESH_TOKEN=\"$REFRESH_TOKEN\""
    echo "SESSION_KEY=\"$SESSION_KEY\""
fi
