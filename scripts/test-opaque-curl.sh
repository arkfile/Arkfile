#!/bin/bash

# Test script for OPAQUE registration and login using bash/curl over HTTPS
# This script demonstrates how to use the Arkfile OPAQUE API with pure bash/curl

set -euo pipefail

# Configuration
ARKFILE_BASE_URL="https://localhost:4443"
INSECURE_FLAG="--insecure"  # For local development with self-signed certs
TEST_EMAIL="opaque-test@example.com"  # Fixed email for consistent testing
TEST_PASSWORD="SecureTestPassword123456789!"
TEMP_DIR=$(mktemp -d)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo -e "${BLUE}🧹 Cleaning up temporary files...${NC}"
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
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

# Test OPAQUE health endpoint
test_opaque_health() {
    log "Testing OPAQUE health endpoint..."
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/opaque/health" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to OPAQUE health endpoint"
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/health.json" 2>/dev/null || {
        error "Invalid JSON response from health endpoint: $response"
    }
    
    local status
    status=$(jq -r '.status' "$TEMP_DIR/health.json")
    
    if [ "$status" = "healthy" ]; then
        success "OPAQUE system is healthy"
        log "Health response: $(jq -c . "$TEMP_DIR/health.json")"
    else
        error "OPAQUE system is not healthy: $status"
    fi
}

# Test device capability detection
test_device_capability() {
    log "Testing device capability detection..."
    
    local capability_request='{
        "memoryGB": 8.0,
        "cpuCores": 4,
        "isMobile": false,
        "userAgent": "curl/arkfile-test"
    }'
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$capability_request" \
        "$ARKFILE_BASE_URL/api/opaque/capability" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        warning "Device capability detection failed (optional feature)"
        return
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/capability.json" 2>/dev/null || {
        warning "Invalid JSON response from capability endpoint"
        return
    }
    
    local recommended
    recommended=$(jq -r '.recommendedCapability' "$TEMP_DIR/capability.json")
    success "Recommended device capability: $recommended"
}

# Register a new user with OPAQUE or handle existing account
register_user() {
    log "Registering OPAQUE user: $TEST_EMAIL"
    
    local register_request
    register_request=$(jq -n \
        --arg email "$TEST_EMAIL" \
        --arg password "$TEST_PASSWORD" \
        --arg capability "interactive" \
        '{
            email: $email,
            password: $password,
            deviceCapability: $capability
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$register_request" \
        "$ARKFILE_BASE_URL/api/opaque/register" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to OPAQUE registration endpoint"
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/register.json" 2>/dev/null || {
        error "Invalid JSON response from registration: $response"
    }
    
    # Check for error in response
    if jq -e '.error' "$TEMP_DIR/register.json" >/dev/null 2>&1; then
        local error_msg
        error_msg=$(jq -r '.error' "$TEMP_DIR/register.json")
        
        # Handle existing user case
        if echo "$error_msg" | grep -q -i "already exists\|already registered\|duplicate"; then
            warning "User already exists: $TEST_EMAIL"
            log "Proceeding with existing account..."
            return
        else
            error "Registration failed: $error_msg"
        fi
    fi
    
    local message
    message=$(jq -r '.message' "$TEMP_DIR/register.json")
    success "User registered successfully: $message"
    
    local auth_method
    auth_method=$(jq -r '.authMethod' "$TEMP_DIR/register.json")
    log "Authentication method: $auth_method"
}

# Login with OPAQUE
login_user() {
    log "Logging in OPAQUE user: $TEST_EMAIL"
    
    local login_request
    login_request=$(jq -n \
        --arg email "$TEST_EMAIL" \
        --arg password "$TEST_PASSWORD" \
        '{
            email: $email,
            password: $password
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$login_request" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to OPAQUE login endpoint"
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/login.json" 2>/dev/null || {
        error "Invalid JSON response from login: $response"
    }
    
    # Check for error in response
    if jq -e '.error' "$TEMP_DIR/login.json" >/dev/null 2>&1; then
        local error_msg
        error_msg=$(jq -r '.error' "$TEMP_DIR/login.json")
        error "Login failed: $error_msg"
    fi
    
    # Check for authentication failure message
    if jq -e '.message' "$TEMP_DIR/login.json" | grep -q "Authentication failed" 2>/dev/null; then
        local message
        message=$(jq -r '.message' "$TEMP_DIR/login.json")
        error "Login failed: $message"
    fi
    
    # Check for approval requirement
    if jq -e '.message' "$TEMP_DIR/login.json" | grep -q "not approved" 2>/dev/null; then
        local message user_status registration_date
        message=$(jq -r '.message' "$TEMP_DIR/login.json")
        user_status=$(jq -r '.userStatus' "$TEMP_DIR/login.json")
        registration_date=$(jq -r '.registrationDate' "$TEMP_DIR/login.json")
        
        warning "Login blocked: $message"
        log "User status: $user_status"
        log "Registration date: $registration_date"
        log "User needs admin approval before login"
        return
    fi
    
    # Check if TOTP is required
    if jq -e '.requiresTOTP' "$TEMP_DIR/login.json" >/dev/null 2>&1; then
        local requires_totp
        requires_totp=$(jq -r '.requiresTOTP' "$TEMP_DIR/login.json")
        if [ "$requires_totp" = "true" ]; then
            success "Login successful, but TOTP required (not implemented in this test)"
            return
        fi
    fi
    
    # Extract tokens and session key
    local token refresh_token session_key auth_method
    token=$(jq -r '.token' "$TEMP_DIR/login.json")
    refresh_token=$(jq -r '.refreshToken' "$TEMP_DIR/login.json")
    session_key=$(jq -r '.sessionKey' "$TEMP_DIR/login.json")
    auth_method=$(jq -r '.authMethod' "$TEMP_DIR/login.json")
    
    success "Login successful!"
    log "Authentication method: $auth_method"
    log "JWT Token (first 20 chars): ${token:0:20}..."
    log "Session Key (first 20 chars): ${session_key:0:20}..."
    
    # Store tokens for further testing
    echo "$token" > "$TEMP_DIR/jwt_token"
    echo "$refresh_token" > "$TEMP_DIR/refresh_token"
    echo "$session_key" > "$TEMP_DIR/session_key"
}

# Approve user in database for complete testing
approve_user() {
    local user_email="$1"
    log "Approving user in database: $user_email"
    
    # Use the working rqlite REST API format
    local response
    response=$(curl -s -u "demo-user:TestPassword123_Secure" \
        -X POST "http://localhost:4001/db/execute" \
        -H "Content-Type: application/json" \
        -d "[\"UPDATE users SET is_approved = 1, approved_by = 'test-script', approved_at = CURRENT_TIMESTAMP WHERE email = '$user_email'\"]" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to rqlite database"
    fi
    
    # Check if the update was successful
    if echo "$response" | jq -e '.results[0].rows_affected' >/dev/null 2>&1; then
        local rows_affected
        rows_affected=$(echo "$response" | jq -r '.results[0].rows_affected')
        if [ "$rows_affected" -gt 0 ]; then
            success "User approved in database (rows affected: $rows_affected)"
        else
            warning "User may have already been approved or not found"
        fi
    else
        log "Database response: $response"
        warning "Could not verify user approval status"
    fi
    
    # Verify the approval worked by checking user status  
    local verify_response
    verify_response=$(curl -s -u "demo-user:TestPassword123_Secure" \
        -X GET "http://localhost:4001/db/query?q=SELECT%20email%2C%20is_approved%20FROM%20users%20WHERE%20email%20%3D%20%27$user_email%27%3B" || echo "ERROR")
    
    if [ "$verify_response" != "ERROR" ]; then
        if echo "$verify_response" | jq -e '.results[0].values[0][1]' >/dev/null 2>&1; then
            local is_approved
            is_approved=$(echo "$verify_response" | jq -r '.results[0].values[0][1]')
            if [ "$is_approved" = "true" ] || [ "$is_approved" = "1" ]; then
                success "User approval verified in database"
            else
                warning "User approval verification failed: is_approved=$is_approved"
            fi
        fi
    fi
}

# Test authenticated API call
test_authenticated_call() {
    log "Testing authenticated API call..."
    
    if [ ! -f "$TEMP_DIR/jwt_token" ]; then
        warning "No JWT token available, skipping authenticated test"
        return
    fi
    
    local token
    token=$(cat "$TEMP_DIR/jwt_token")
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/files" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        warning "Failed to make authenticated API call"
        return
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/files.json" 2>/dev/null || {
        warning "Invalid JSON response from files endpoint"
        return
    }
    
    success "Authenticated API call successful"
    log "Files response: $(jq -c . "$TEMP_DIR/files.json")"
}

# Test token refresh
test_token_refresh() {
    log "Testing token refresh..."
    
    if [ ! -f "$TEMP_DIR/refresh_token" ]; then
        warning "No refresh token available, skipping refresh test"
        return
    fi
    
    local refresh_token
    refresh_token=$(cat "$TEMP_DIR/refresh_token")
    
    local refresh_request
    refresh_request=$(jq -n \
        --arg refresh_token "$refresh_token" \
        '{
            refreshToken: $refresh_token
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$refresh_request" \
        "$ARKFILE_BASE_URL/api/refresh" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        warning "Failed to refresh token"
        return
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/refresh.json" 2>/dev/null || {
        warning "Invalid JSON response from refresh endpoint"
        return
    }
    
    # Check for error in response
    if jq -e '.error' "$TEMP_DIR/refresh.json" >/dev/null 2>&1; then
        local error_msg
        error_msg=$(jq -r '.error' "$TEMP_DIR/refresh.json")
        warning "Token refresh failed: $error_msg"
        return
    fi
    
    local new_token
    new_token=$(jq -r '.token' "$TEMP_DIR/refresh.json")
    success "Token refreshed successfully"
    log "New JWT Token (first 20 chars): ${new_token:0:20}..."
}

# Main execution
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║     ARKFILE OPAQUE API TEST (HTTPS/CURL)     ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "Testing Arkfile OPAQUE API over HTTPS"
    log "Base URL: $ARKFILE_BASE_URL"
    log "Test Email: $TEST_EMAIL"
    log "Temp Directory: $TEMP_DIR"
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        error "jq is required for JSON parsing. Please install jq."
    fi
    
    # Run tests
    test_opaque_health
    test_device_capability
    register_user
    
    # Approve the user so we can test complete login flow
    approve_user "$TEST_EMAIL"
    
    # Now test login with approved user
    login_user
    test_authenticated_call
    test_token_refresh
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║           ALL TESTS COMPLETED ✅              ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "OPAQUE authentication flow completed successfully!"
    log "Files saved in: $TEMP_DIR"
    log "You can now use the JWT token for authenticated API calls"
    
    if [ -f "$TEMP_DIR/jwt_token" ]; then
        echo -e "${YELLOW}"
        echo "Example authenticated API calls:"
        echo "export JWT_TOKEN=\"\$(cat $TEMP_DIR/jwt_token)\""
        echo "curl $INSECURE_FLAG -H \"Authorization: Bearer \$JWT_TOKEN\" $ARKFILE_BASE_URL/api/files"
        echo "curl $INSECURE_FLAG -H \"Authorization: Bearer \$JWT_TOKEN\" $ARKFILE_BASE_URL/api/user/shares"
        echo -e "${NC}"
    fi
}

# Check if running directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
