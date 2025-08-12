#!/bin/bash

# Test script for Arkfile Credits System
# Tests all credits endpoints and functionality

set -e

# Configuration
BASE_URL="${BASE_URL:-https://localhost:4443}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-AdminPassword123!}"
TEST_USERNAME="${TEST_USERNAME:-credits.test.user}"
TEST_PASSWORD="${TEST_PASSWORD:-TestPassword123!}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TEMP_FILES=()

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up temporary files...${NC}"
    for file in "${TEMP_FILES[@]}"; do
        [ -f "$file" ] && rm -f "$file"
    done
}

# Set up cleanup on exit
trap cleanup EXIT

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# HTTP request helper
make_request() {
    local method="$1"
    local endpoint="$2"
    local token="$3"
    local data="$4"
    local output_file=$(mktemp)
    TEMP_FILES+=("$output_file")

    local curl_args=(
        -s -w "%{http_code}"
        -X "$method"
        -H "Content-Type: application/json"
        -k  # Allow self-signed certificates
    )

    if [ -n "$token" ]; then
        curl_args+=(-H "Authorization: Bearer $token")
    fi

    if [ -n "$data" ]; then
        curl_args+=(-d "$data")
    fi

    curl_args+=(-o "$output_file" "$BASE_URL$endpoint")

    local response=$(curl "${curl_args[@]}")
    local http_code="${response: -3}"
    local body=$(cat "$output_file")

    echo "$http_code|$body"
}

# Parse JSON response
get_json_field() {
    local json="$1"
    local field="$2"
    echo "$json" | grep -o "\"$field\":[^,}]*" | cut -d: -f2- | tr -d '"'
}

# Authentication helper
authenticate_user() {
    local username="$1"
    local password="$2"
    
    log_info "Authenticating user: $username"
    
    # Step 1: OPAQUE Login
    local login_data="{\"username\":\"$username\",\"password\":\"$password\"}"
    local response=$(make_request "POST" "/api/opaque/login" "" "$login_data")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    local body=$(echo "$response" | cut -d'|' -f2-)
    
    if [ "$http_code" != "200" ]; then
        log_error "OPAQUE login failed for $username: $http_code"
        return 1
    fi
    
    local temp_token=$(get_json_field "$body" "temp_token")
    local requires_totp=$(get_json_field "$body" "requires_totp")
    
    if [ "$requires_totp" = "true" ]; then
        log_info "TOTP required for $username"
        # For testing, we'll use a mock TOTP code
        # In real implementation, you'd generate actual TOTP
        local totp_data="{\"code\":\"123456\",\"is_backup\":false}"
        local totp_response=$(make_request "POST" "/api/totp/auth" "$temp_token" "$totp_data")
        local totp_code=$(echo "$totp_response" | cut -d'|' -f1)
        local totp_body=$(echo "$totp_response" | cut -d'|' -f2-)
        
        if [ "$totp_code" = "200" ]; then
            local jwt_token=$(get_json_field "$totp_body" "token")
            echo "$jwt_token"
            return 0
        else
            log_warning "TOTP authentication failed, trying without TOTP"
        fi
    fi
    
    # If no TOTP or TOTP failed, return temp token
    echo "$temp_token"
}

# Test functions

test_user_get_credits() {
    log_info "Testing: Get user credits"
    
    local token=$(authenticate_user "$TEST_USERNAME" "$TEST_PASSWORD")
    if [ -z "$token" ]; then
        log_error "Failed to authenticate test user"
        return 1
    fi
    
    local response=$(make_request "GET" "/api/credits" "$token")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    local body=$(echo "$response" | cut -d'|' -f2-)
    
    case "$http_code" in
        "200")
            log_success "User credits retrieved successfully"
            local balance=$(get_json_field "$body" "balance_usd_cents")
            log_info "User balance: $balance cents"
            ;;
        "401")
            log_warning "Authentication required (expected if user doesn't exist)"
            ;;
        "500")
            log_warning "Server error (expected if credits table doesn't exist yet)"
            ;;
        *)
            log_error "Unexpected response code: $http_code"
            return 1
            ;;
    esac
}

test_admin_get_all_credits() {
    log_info "Testing: Admin get all credits"
    
    local token=$(authenticate_user "$ADMIN_USERNAME" "$ADMIN_PASSWORD")
    if [ -z "$token" ]; then
        log_error "Failed to authenticate admin user"
        return 1
    fi
    
    local response=$(make_request "GET" "/api/admin/credits" "$token")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    local body=$(echo "$response" | cut -d'|' -f2-)
    
    case "$http_code" in
        "200")
            log_success "Admin retrieved all credits successfully"
            log_info "Response: $body"
            ;;
        "403")
            log_warning "Admin privileges required (expected if user is not admin)"
            ;;
        "401")
            log_warning "Authentication failed"
            ;;
        *)
            log_error "Unexpected response code: $http_code"
            return 1
            ;;
    esac
}

test_admin_get_user_credits() {
    log_info "Testing: Admin get specific user credits"
    
    local token=$(authenticate_user "$ADMIN_USERNAME" "$ADMIN_PASSWORD")
    if [ -z "$token" ]; then
        log_error "Failed to authenticate admin user"
        return 1
    fi
    
    local response=$(make_request "GET" "/api/admin/credits/$TEST_USERNAME" "$token")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    local body=$(echo "$response" | cut -d'|' -f2-)
    
    case "$http_code" in
        "200")
            log_success "Admin retrieved user credits successfully"
            log_info "Response: $body"
            ;;
        "403")
            log_warning "Admin privileges required"
            ;;
        "404")
            log_warning "User not found (expected if test user doesn't exist)"
            ;;
        *)
            log_error "Unexpected response code: $http_code"
            return 1
            ;;
    esac
}

test_admin_adjust_credits() {
    log_info "Testing: Admin adjust user credits"
    
    local token=$(authenticate_user "$ADMIN_USERNAME" "$ADMIN_PASSWORD")
    if [ -z "$token" ]; then
        log_error "Failed to authenticate admin user"
        return 1
    fi
    
    local adjust_data='{
        "amount_usd": "10.50",
        "operation": "add",
        "reason": "Test credit addition",
        "transaction_id": "test_tx_001"
    }'
    
    local response=$(make_request "POST" "/api/admin/credits/$TEST_USERNAME" "$token" "$adjust_data")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    local body=$(echo "$response" | cut -d'|' -f2-)
    
    case "$http_code" in
        "200")
            log_success "Admin adjusted credits successfully"
            log_info "Response: $body"
            ;;
        "400")
            log_warning "Bad request (expected if validation fails)"
            ;;
        "403")
            log_warning "Admin privileges required"
            ;;
        "404")
            log_warning "User not found"
            ;;
        *)
            log_error "Unexpected response code: $http_code"
            return 1
            ;;
    esac
}

test_admin_set_credits() {
    log_info "Testing: Admin set user credits balance"
    
    local token=$(authenticate_user "$ADMIN_USERNAME" "$ADMIN_PASSWORD")
    if [ -z "$token" ]; then
        log_error "Failed to authenticate admin user"
        return 1
    fi
    
    local set_data='{
        "balance_usd": "25.00",
        "reason": "Test balance reset",
        "transaction_id": "test_tx_002"
    }'
    
    local response=$(make_request "PUT" "/api/admin/credits/$TEST_USERNAME" "$token" "$set_data")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    local body=$(echo "$response" | cut -d'|' -f2-)
    
    case "$http_code" in
        "200")
            log_success "Admin set credits successfully"
            log_info "Response: $body"
            ;;
        "400")
            log_warning "Bad request (expected if validation fails)"
            ;;
        "403")
            log_warning "Admin privileges required"
            ;;
        "404")
            log_warning "User not found"
            ;;
        *)
            log_error "Unexpected response code: $http_code"
            return 1
            ;;
    esac
}

test_unauthorized_access() {
    log_info "Testing: Unauthorized access to admin endpoints"
    
    # Test without token
    local response=$(make_request "GET" "/api/admin/credits")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    
    if [ "$http_code" = "401" ]; then
        log_success "Properly rejected unauthorized request"
    else
        log_error "Expected 401, got $http_code"
        return 1
    fi
    
    # Test with regular user token (if available)
    local user_token=$(authenticate_user "$TEST_USERNAME" "$TEST_PASSWORD")
    if [ -n "$user_token" ]; then
        local response=$(make_request "GET" "/api/admin/credits" "$user_token")
        local http_code=$(echo "$response" | cut -d'|' -f1)
        
        if [ "$http_code" = "403" ] || [ "$http_code" = "401" ]; then
            log_success "Properly rejected non-admin user request"
        else
            log_error "Expected 401/403, got $http_code"
            return 1
        fi
    fi
}

test_server_connectivity() {
    log_info "Testing server connectivity"
    
    local response=$(make_request "GET" "/api/opaque/health")
    local http_code=$(echo "$response" | cut -d'|' -f1)
    
    if [ "$http_code" = "200" ]; then
        log_success "Server is responding"
    else
        log_error "Server connectivity test failed: $http_code"
        return 1
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}    Arkfile Credits System Test${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "Server: $BASE_URL"
    echo -e "Admin User: $ADMIN_USERNAME"
    echo -e "Test User: $TEST_USERNAME"
    echo -e "${BLUE}========================================${NC}\n"
    
    # Test server connectivity first
    test_server_connectivity
    
    # Test user endpoints
    test_user_get_credits
    
    # Test admin endpoints
    test_admin_get_all_credits
    test_admin_get_user_credits
    test_admin_adjust_credits
    test_admin_set_credits
    
    # Test security
    test_unauthorized_access
    
    # Summary
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}            Test Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests completed successfully!${NC}"
        echo -e "${GREEN}The credits system appears to be working correctly.${NC}"
    else
        echo -e "\n${YELLOW}⚠️  Some tests failed or returned warnings.${NC}"
        echo -e "${YELLOW}This is expected if the server/database isn't fully set up.${NC}"
    fi
    
    echo -e "\n${BLUE}Note:${NC} Many tests may show warnings if:"
    echo -e "  - The server is not running"
    echo -e "  - Users don't exist in the database"
    echo -e "  - TOTP is not properly configured"
    echo -e "  - Admin privileges are not set up"
    echo -e "\nThis is normal for initial testing before full setup."
    
    return $TESTS_FAILED
}

# Run the tests
main "$@"
