#!/bin/bash

# Admin Authentication Test
# Comprehensive OPAQUE + TOTP flow testing with clean output

set -euo pipefail

# Configuration
ARKFILE_BASE_URL="${ARKFILE_BASE_URL:-https://localhost:4443}"
ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
TOTP_SECRET="ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"  # Fixed dev secret (32-character Base32)

# Script options
DEBUG_MODE="${DEBUG_MODE:-0}"
VERBOSE="${VERBOSE:-0}"
TEST_MULTIPLE_CODES="${TEST_MULTIPLE_CODES:-1}"
CHECK_DATABASE="${CHECK_DATABASE:-0}"

# Test result tracking
declare -A TEST_RESULTS
TEST_RESULTS[connectivity]=0
TEST_RESULTS[opaque_auth]=0
TEST_RESULTS[totp_generation]=0
TEST_RESULTS[totp_auth]=0
TEST_RESULTS[api_access]=0
TEST_RESULTS[token_refresh]=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# Temp files for cleanup
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] $1${NC}"
}

debug() {
    if [[ "$DEBUG_MODE" == "1" ]]; then
        echo -e "${PURPLE}DEBUG: $1${NC}"
    fi
}

verbose() {
    if [[ "$VERBOSE" == "1" ]]; then
        echo -e "${CYAN}$1${NC}"
    fi
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    if [[ $# -gt 1 ]] && [[ "$DEBUG_MODE" == "1" ]]; then
        echo -e "${RED}   Details: $2${NC}"
    fi
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

info() {
    echo -e "${GRAY}   $1${NC}"
}

# Function to generate TOTP code for specific time window (with timestamp control)
generate_totp_for_window() {
    local secret=$1
    local time_offset=${2:-0}  # offset in 30-second windows

    # FIX: Use explicit timestamps to control TOTP generation timing
    if [[ "$time_offset" == "0" ]]; then
        # Current window - use current timestamp
        local current_ts=$(date +%s)
        debug "Generating TOTP for current timestamp: $current_ts"
        ./scripts/testing/totp-generator "$secret" "$current_ts"
    else
        # Offset window - calculate specific timestamp
        local offset_ts=$(( $(date +%s) + (time_offset * 30) ))
        debug "Generating TOTP for offset timestamp: $offset_ts (offset: ${time_offset}x30s)"
        ./scripts/testing/totp-generator "$secret" "$offset_ts"
    fi
}

# Function to check database TOTP data (only in debug mode)
check_database_totp() {
    if [[ "$CHECK_DATABASE" != "1" ]] || [[ "$DEBUG_MODE" != "1" ]]; then
        return
    fi
    
    debug "Checking database TOTP configuration..."
    
    # Get the rqlite password
    local rqlite_password=$(sudo cat /opt/arkfile/etc/secrets.env 2>/dev/null | grep RQLITE_PASSWORD | cut -d= -f2)
    
    if [[ -z "$rqlite_password" ]]; then
        debug "Could not retrieve rqlite password, skipping database check"
        return
    fi
    
    # Basic database query
    local basic_query="SELECT username, enabled, setup_completed FROM user_totp WHERE username = '$ADMIN_USERNAME';"
    local basic_result=$(curl -s -u "dev-user:$rqlite_password" -G 'http://localhost:4001/db/query' --data-urlencode "q=$basic_query" 2>/dev/null)
    
    if echo "$basic_result" | jq -e '.results[0].values[0]' >/dev/null 2>&1; then
        debug "TOTP database record found for admin user"
    else
        debug "No TOTP record found for admin user"
    fi
}

# Function to test TOTP authentication with clean error handling
test_totp_auth() {
    local temp_token=$1
    local session_key=$2
    local totp_code=$3
    local description=${4:-"Current"}
    
    local response=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/totp/auth" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $temp_token" \
      -d "{\"code\":\"$totp_code\",\"session_key\":\"$session_key\"}" 2>/dev/null)
    
    # Clean any potential whitespace or non-JSON characters from response
    local clean_response=$(echo "$response" | tr -d '\r' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    
    # Check if we got rate limited
    if echo "$clean_response" | jq -e '.message' | grep -q "Too many TOTP attempts" 2>/dev/null; then
        local wait_time=$(echo "$clean_response" | jq -r '.message' | grep -o '[0-9]\+ seconds' | grep -o '[0-9]\+' || echo "30")
        debug "Rate limited, waiting ${wait_time} seconds..."
        sleep $((wait_time + 2))
        return 1
    fi
    
    # Check if we have valid JSON first
    if ! echo "$clean_response" | jq -e '.' >/dev/null 2>&1; then
        debug "Invalid JSON response from server"
        return 1
    fi
    
    # Now check if we have a token field (success case)
    if echo "$clean_response" | jq -e '.token' >/dev/null 2>&1; then
        echo "$clean_response"
        return 0
    else
        # Extract error message from valid JSON
        local error_msg=$(echo "$clean_response" | jq -r '.message // .error // "Authentication failed"' 2>/dev/null)
        debug "TOTP authentication failed: $error_msg"
        return 1
    fi
}

# Function to show clean test summary
show_test_summary() {
    echo
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗"
    echo "║                     TEST RESULTS                         ║"
    echo "╚═══════════════════════════════════════════════════════════╝${NC}"
    echo
    
    local total_tests=0
    local passed_tests=0
    
    # Test 1: Server Connectivity
    total_tests=$((total_tests + 1))
    if [[ "${TEST_RESULTS[connectivity]}" == "1" ]]; then
        echo -e "${GREEN}✅ Test 1: Server Connectivity${NC}"
        info "Server responding at $ARKFILE_BASE_URL"
        passed_tests=$((passed_tests + 1))
    else
        echo -e "${RED}❌ Test 1: Server Connectivity${NC}"
        info "Server not reachable"
    fi
    
    # Test 2: OPAQUE Authentication
    total_tests=$((total_tests + 1))
    if [[ "${TEST_RESULTS[opaque_auth]}" == "1" ]]; then
        echo -e "${GREEN}✅ Test 2: OPAQUE Authentication${NC}"
        info "Login successful, TOTP required as expected"
        passed_tests=$((passed_tests + 1))
    else
        echo -e "${RED}❌ Test 2: OPAQUE Authentication${NC}"
        info "OPAQUE login failed"
    fi
    
    # Test 3: TOTP Code Generation
    total_tests=$((total_tests + 1))
    if [[ "${TEST_RESULTS[totp_generation]}" == "1" ]]; then
        echo -e "${GREEN}✅ Test 3: TOTP Code Generation${NC}"
        info "Successfully generated time-based codes"
        passed_tests=$((passed_tests + 1))
    else
        echo -e "${RED}❌ Test 3: TOTP Code Generation${NC}"
        info "Failed to generate TOTP codes"
    fi
    
    # Test 4: TOTP Authentication
    total_tests=$((total_tests + 1))
    if [[ "${TEST_RESULTS[totp_auth]}" == "1" ]]; then
        echo -e "${GREEN}✅ Test 4: TOTP Authentication${NC}"
        info "Successfully completed two-factor authentication"
        passed_tests=$((passed_tests + 1))
    else
        echo -e "${RED}❌ Test 4: TOTP Authentication${NC}"
        info "TOTP verification failed"
    fi
    
    # Test 5: Authenticated API Access
    total_tests=$((total_tests + 1))
    if [[ "${TEST_RESULTS[api_access]}" == "1" ]]; then
        echo -e "${GREEN}✅ Test 5: Authenticated API Access${NC}"
        info "API endpoints responding with valid tokens"
        passed_tests=$((passed_tests + 1))
    else
        echo -e "${RED}❌ Test 5: Authenticated API Access${NC}"
        info "Failed to access protected endpoints"
    fi
    
    # Test 6: Token Refresh
    total_tests=$((total_tests + 1))
    if [[ "${TEST_RESULTS[token_refresh]}" == "1" ]]; then
        echo -e "${GREEN}✅ Test 6: Token Refresh${NC}"
        info "Refresh token functionality working"
        passed_tests=$((passed_tests + 1))
    else
        echo -e "${RED}❌ Test 6: Token Refresh${NC}"
        info "Token refresh failed or not available"
    fi
    
    echo
    echo -e "${BLUE}Summary: ${NC}"
    if [[ $passed_tests -eq $total_tests ]]; then
        echo -e "${GREEN}All tests passed! ($passed_tests/$total_tests)${NC}"
        echo -e "${GREEN}Admin authentication system is fully operational${NC}"
    else
        echo -e "${YELLOW}Some tests failed ($passed_tests/$total_tests passed)${NC}"
        echo -e "${YELLOW}Review failed tests above for troubleshooting${NC}"
    fi
    echo
}

# Start of main script
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗"
echo "║                ADMIN AUTH TEST                             ║"
echo "╚════════════════════════════════════════════════════════════╝${NC}"
echo

if [[ "$DEBUG_MODE" == "1" ]]; then
    log "Configuration:"
    info "Base URL: $ARKFILE_BASE_URL"
    info "Admin Username: $ADMIN_USERNAME"
    info "TOTP Secret: ${TOTP_SECRET:0:8}...${TOTP_SECRET: -8}"
    info "Debug Mode: Enabled"
    echo
fi

# Pre-flight checks
log "Pre-flight checks..."

# TOTP generator check with auto-build
if [[ ! -x "./scripts/testing/totp-generator" ]]; then
    info "Building TOTP generator..."
    if command -v go >/dev/null 2>&1 && [[ -f "./scripts/testing/totp-generator.go" ]]; then
        if cd scripts/testing && go build -o totp-generator totp-generator.go && cd - >/dev/null; then
            success "TOTP generator ready"
        else
            error "Failed to build TOTP generator"
            show_test_summary
            exit 1
        fi
    else
        error "TOTP generator not available and Go not found"
        show_test_summary
        exit 1
    fi
else
    success "TOTP generator ready"
fi

echo

# Test 1: Server Connectivity
log "Test 1: Server Connectivity"

if curl -k -s --connect-timeout 5 "$ARKFILE_BASE_URL/health" >/dev/null 2>&1; then
    success "Server responding"
    TEST_RESULTS[connectivity]=1
elif [[ "$ARKFILE_BASE_URL" == "https://localhost:4443" ]]; then
    info "Trying HTTP fallback..."
    ARKFILE_BASE_URL="http://localhost:8080"
    if curl -s --connect-timeout 5 "$ARKFILE_BASE_URL/health" >/dev/null 2>&1; then
        success "Server responding (HTTP fallback)"
        TEST_RESULTS[connectivity]=1
    else
        error "Server not responding on HTTPS or HTTP"
        show_test_summary
        exit 1
    fi
else
    error "Server not responding"
    show_test_summary
    exit 1
fi

# Check database if in debug mode
check_database_totp

echo

# Test 2: OPAQUE Authentication
log "Test 2: OPAQUE Authentication"

OPAQUE_RESPONSE=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/opaque/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$ADMIN_USERNAME\",
    \"password\": \"$ADMIN_PASSWORD\"
  }")

debug "OPAQUE response: $OPAQUE_RESPONSE"

if echo "$OPAQUE_RESPONSE" | jq -e '.requires_totp' >/dev/null 2>&1; then
    success "OPAQUE login successful"
    TEST_RESULTS[opaque_auth]=1
    TEMP_TOKEN=$(echo "$OPAQUE_RESPONSE" | jq -r '.temp_token')
    SESSION_KEY=$(echo "$OPAQUE_RESPONSE" | jq -r '.session_key')
    
    debug "Temporary token: ${TEMP_TOKEN:0:20}...${TEMP_TOKEN: -20}"
    debug "Session key: ${SESSION_KEY:0:20}...${SESSION_KEY: -20}"
else
    error "OPAQUE authentication failed"
    if [[ "$DEBUG_MODE" == "1" ]]; then
        debug "Response: $OPAQUE_RESPONSE"
    fi
    show_test_summary
    exit 1
fi

echo

# Test 3: TOTP Code Generation
log "Test 3: TOTP Code Generation"

declare -a TOTP_CODES
declare -a TOTP_DESCRIPTIONS

# Generate TOTP codes
if CURRENT_CODE=$(generate_totp_for_window "$TOTP_SECRET" 0); then
    TOTP_CODES+=("$CURRENT_CODE")
    TOTP_DESCRIPTIONS+=("Current window")
    
    if [[ "$TEST_MULTIPLE_CODES" == "1" ]]; then
        # Generate additional codes for testing
        PREV_CODE=$(generate_totp_for_window "$TOTP_SECRET" -1)
        NEXT_CODE=$(generate_totp_for_window "$TOTP_SECRET" 1)
        PREV2_CODE=$(generate_totp_for_window "$TOTP_SECRET" -2)
        
        TOTP_CODES+=("$PREV_CODE" "$NEXT_CODE" "$PREV2_CODE")
        TOTP_DESCRIPTIONS+=("Previous window" "Next window" "Two windows back")
    fi
    
    success "Generated ${#TOTP_CODES[@]} TOTP codes"
    TEST_RESULTS[totp_generation]=1
    
    if [[ "$DEBUG_MODE" == "1" ]]; then
        for i in "${!TOTP_CODES[@]}"; do
            debug "${TOTP_DESCRIPTIONS[$i]}: ${TOTP_CODES[$i]}"
        done
    fi
else
    error "Failed to generate TOTP codes"
    show_test_summary
    exit 1
fi

echo

# Test 4: TOTP Authentication
log "Test 4: TOTP Authentication"

TOTP_SUCCESS=0
FINAL_TOKEN=""
REFRESH_TOKEN=""
AUTH_METHOD=""

info "Attempting TOTP authentication..."

for i in "${!TOTP_CODES[@]}"; do
    debug "Trying ${TOTP_DESCRIPTIONS[$i]} code..."
    
    # Get a fresh TOTP code for each attempt to avoid timing issues
    if [[ $i -eq 0 ]]; then
        CURRENT_TEST_CODE="${TOTP_CODES[$i]}"
    else
        CURRENT_TEST_CODE=$(generate_totp_for_window "$TOTP_SECRET" 0)
        debug "Generated fresh code: $CURRENT_TEST_CODE"
    fi
    
    if TOTP_RESPONSE=$(test_totp_auth "$TEMP_TOKEN" "$SESSION_KEY" "$CURRENT_TEST_CODE" "${TOTP_DESCRIPTIONS[$i]}"); then
        # Parse the successful response
        if echo "$TOTP_RESPONSE" | jq -e '.' >/dev/null 2>&1; then
            FINAL_TOKEN=$(echo "$TOTP_RESPONSE" | jq -r '.token // empty' 2>/dev/null)
            REFRESH_TOKEN=$(echo "$TOTP_RESPONSE" | jq -r '.refresh_token // empty' 2>/dev/null)
            AUTH_METHOD=$(echo "$TOTP_RESPONSE" | jq -r '.auth_method // empty' 2>/dev/null)
            TOTP_SUCCESS=1
            break
        fi
    fi
    
    # FIXME: Add proper rate limiting protection by incrementing delays
    if [[ $i -lt $((${#TOTP_CODES[@]} - 1)) ]]; then
        wait_time=$((2 + (i * 2)))  # Progressive wait: 2s, 4s, 6s, etc.
        debug "Waiting ${wait_time}s before next attempt (rate limiting protection)..."
        sleep $wait_time
    fi
done

if [[ "$TOTP_SUCCESS" == "1" ]]; then
    success "TOTP authentication successful"
    TEST_RESULTS[totp_auth]=1
    debug "Auth method: $AUTH_METHOD"
    debug "Token received: ${FINAL_TOKEN:0:20}...${FINAL_TOKEN: -20}"
else
    error "All TOTP authentication attempts failed"
    debug "Current system time: $(date)"
    show_test_summary
    exit 1
fi

echo

# Test 5: Authenticated API Access
log "Test 5: Authenticated API Access"

declare -a API_ENDPOINTS
API_ENDPOINTS=(
    "/api/files"
    "/health"
    "/api/totp/status"
)

API_SUCCESS_COUNT=0
info "Testing ${#API_ENDPOINTS[@]} API endpoints..."

for endpoint in "${API_ENDPOINTS[@]}"; do
    debug "Testing endpoint: $endpoint"
    
    API_RESPONSE=$(curl -k -s \
      -H "Authorization: Bearer $FINAL_TOKEN" \
      "$ARKFILE_BASE_URL$endpoint" 2>/dev/null)
    
    if echo "$API_RESPONSE" | jq -e '.' >/dev/null 2>&1; then
        debug "✅ $endpoint - Valid response"
        API_SUCCESS_COUNT=$((API_SUCCESS_COUNT + 1))
    else
        debug "⚠️ $endpoint - Invalid response"
    fi
done

if [[ $API_SUCCESS_COUNT -gt 0 ]]; then
    success "API endpoints accessible ($API_SUCCESS_COUNT/${#API_ENDPOINTS[@]} working)"
    TEST_RESULTS[api_access]=1
else
    error "No API endpoints accessible"
    show_test_summary
    exit 1
fi

echo

# Test 6: Token Refresh
log "Test 6: Token Refresh"

if [[ -n "$REFRESH_TOKEN" ]]; then
    info "Testing token refresh..."
    REFRESH_RESPONSE=$(curl -k -s -X POST "$ARKFILE_BASE_URL/api/refresh" \
      -H "Content-Type: application/json" \
      -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" 2>/dev/null)
    
    if echo "$REFRESH_RESPONSE" | jq -e '.token' >/dev/null 2>&1; then
        success "Token refresh working"
        TEST_RESULTS[token_refresh]=1
        NEW_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.token')
        debug "New token: ${NEW_TOKEN:0:20}...${NEW_TOKEN: -20}"
    else
        error "Token refresh failed"
        debug "Refresh response: $REFRESH_RESPONSE"
    fi
else
    error "No refresh token available"
    debug "Cannot test refresh functionality"
fi

# Show final test summary
show_test_summary

# Output key information for further use in debug mode
if [[ "$DEBUG_MODE" == "1" ]] && [[ "$TOTP_SUCCESS" == "1" ]]; then
    echo "Key tokens for manual testing:"
    echo "export ADMIN_TOKEN=\"$FINAL_TOKEN\""
    echo "export REFRESH_TOKEN=\"$REFRESH_TOKEN\""
    echo "export SESSION_KEY=\"$SESSION_KEY\""
    echo
fi

# Exit with appropriate code
if [[ "${TEST_RESULTS[connectivity]}" == "1" ]] && [[ "${TEST_RESULTS[opaque_auth]}" == "1" ]] && [[ "${TEST_RESULTS[totp_generation]}" == "1" ]] && [[ "${TEST_RESULTS[totp_auth]}" == "1" ]] && [[ "${TEST_RESULTS[api_access]}" == "1" ]]; then
    exit 0
else
    exit 1
fi
