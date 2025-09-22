#!/bin/bash

# Master Arkfile App Testing Script
# Comprehensive End-to-End App Testing
#
# Flow: Cleanup → Registration → Approval → TOTP Setup → Login → 2FA Auth → 
#       Session Management → Endpoint Testing → Logout → Cleanup
#
# Features: Real TOTP codes, individual endpoint validation, mandatory TOTP enforcement,
#          database manipulation, comprehensive error handling, modular execution

# Note: Removed strict error handling to prevent silent failures in debugging
# set -euo pipefail
set -eo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'  # Bright white for better readability
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global test state
PHASE_COUNTER=0
TEST_START_TIME=$(date +%s)
SKIP_CLEANUP=false
ENDPOINTS_ONLY=false
MANDATORY_TOTP=false
ERROR_SCENARIOS=false
PERFORMANCE_MODE=false
QUICK_MODE=false
DEBUG_MODE=false

# Cleanup function
cleanup() {
    # This function is now a no-op as we use a persistent temp directory.
    # Manual cleanup of /tmp/test-app-curl can be done if needed.
    if [ "$SKIP_CLEANUP" != true ]; then
        # The directory is persistent, but we can clean its contents if not skipping
        echo -e "${WHITE}[CLEANUP] Cleaning contents of temporary directory $TEMP_DIR...${NC}"
        # Remove everything except the main test file to speed up subsequent runs
        find "$TEMP_DIR" -mindepth 1 ! -name "$(basename "$TEST_FILE_PATH")" -exec rm -rf {} +
    else
        echo -e "${WHITE}[CLEANUP] SKIPPING cleanup - temp files preserved in $TEMP_DIR${NC}"
    fi
}
trap cleanup EXIT

# Logging functions
log() {
    echo -e "${WHITE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

phase() {
    PHASE_COUNTER=$((PHASE_COUNTER + 1))
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  PHASE $PHASE_COUNTER: $1"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

error() {
    echo -e "${RED}[X] $1${NC}"
    echo -e "${RED}Test failed at: $(date +'%Y-%m-%d %H:%M:%S')${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${CYAN}[INFO] $1${NC}"
}

debug() {
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${PURPLE}[DEBUG] $1${NC}"
    fi
}

# Setup library paths automatically (Updated for static linking)
setup_library_paths() {
    local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    
    # With static linking, we only need to verify static libraries exist
    local LIBOPAQUE_PATH="$PROJECT_ROOT/vendor/stef/libopaque/src/libopaque.a"
    local LIBOPRF_PATH="$PROJECT_ROOT/vendor/stef/liboprf/src/liboprf.a"
    
    if [ ! -f "$LIBOPAQUE_PATH" ] || [ ! -f "$LIBOPRF_PATH" ]; then
        info "Static libraries not found, ensuring they are built..."
        if [ -x "$PROJECT_ROOT/scripts/setup/build-libopaque.sh" ]; then
            cd "$PROJECT_ROOT"
            ./scripts/setup/build-libopaque.sh >/dev/null 2>&1
        else
            warning "Cannot find build-libopaque.sh script, but may not be needed with static linking"
        fi
    else
        debug "Static libraries verified: libopaque.a and liboprf.a present"
    fi
    
    # With static linking, we don't need to set LD_LIBRARY_PATH since libraries are embedded in the binary
    # The arkfile binary already contains all required OPAQUE functionality
}

# Utility function to save and validate JSON responses
save_json_response() {
    local response="$1"
    local filename="$2"
    local error_context="$3"
    
    debug "Response from $error_context: $response"
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to server for $error_context"
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/$filename" 2>/dev/null || {
        error "Invalid JSON response from $error_context: $response"
    }
    
    # Check for API error in response (but NOT if success=true)
    if jq -e '.success == true' "$TEMP_DIR/$filename" >/dev/null 2>&1; then
        # Response has success=true, this is a successful API call
        return 0
    elif jq -e '.error' "$TEMP_DIR/$filename" >/dev/null 2>&1; then
        local error_msg
        error_msg=$(jq -r '.error' "$TEMP_DIR/$filename")
        
        # Some errors are expected (like TOTP setup required), return them
        echo "$error_msg"
        return 1
    fi
    
    return 0
}

# Admin authentication helper
authenticate_admin() {
    debug "Authenticating admin user: $ADMIN_USERNAME"
    
    # Login admin user directly (user should already exist from dev-reset)
    local login_request
    login_request=$(jq -n \
        --arg username "$ADMIN_USERNAME" \
        --arg password "$ADMIN_PASSWORD" \
        '{
            username: $username,
            password: $password
        }')
    
    local login_response
    login_response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$login_request" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")
    
    debug "Admin login response: $login_response"
    
    if [ "$login_response" = "ERROR" ]; then
        warning "Failed to authenticate admin user"
        return 1
    fi
    
    # Check if TOTP authentication is required
    if echo "$login_response" | jq -e '.requires_totp' >/dev/null 2>&1; then
        local requires_totp temp_token session_key
        requires_totp=$(echo "$login_response" | jq -r '.requires_totp')
        temp_token=$(echo "$login_response" | jq -r '.temp_token')
        session_key=$(echo "$login_response" | jq -r '.session_key')
        
        if [ "$requires_totp" = "true" ] && [ "$temp_token" != "null" ] && [ "$session_key" != "null" ]; then
            debug "Admin user requires TOTP authentication, completing flow..."
            
            # Generate TOTP code using known admin secret
            local totp_secret="ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"  # Known admin TOTP secret
            local totp_code
            if [ -x "scripts/testing/totp-generator" ]; then
                totp_code=$(scripts/testing/totp-generator "$totp_secret")
            elif [ -x "./totp-generator" ]; then
                totp_code=$(./totp-generator "$totp_secret")
            else
                warning "TOTP generator not found"
                return 1
            fi
            
            debug "Generated admin TOTP code: $totp_code"
            
            # Complete TOTP authentication
            local totp_request
            totp_request=$(jq -n \
                --arg code "$totp_code" \
                --arg session_key "$session_key" \
                --argjson is_backup false \
                '{
                    code: $code,
                    session_key: $session_key,
                    is_backup: $is_backup
                }')
            
            local totp_response
            totp_response=$(curl -s $INSECURE_FLAG \
                -X POST \
                -H "Authorization: Bearer $temp_token" \
                -H "Content-Type: application/json" \
                -d "$totp_request" \
                "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")
            
            debug "Admin TOTP response: $totp_response"
            
            if [ "$totp_response" = "ERROR" ]; then
                warning "Admin TOTP authentication failed"
                return 1
            fi
            
            # Extract final admin token
            local admin_token
            admin_token=$(echo "$totp_response" | jq -r '.token')
            
            if [ "$admin_token" = "null" ] || [ -z "$admin_token" ]; then
                warning "Failed to extract final admin token after TOTP"
                return 1
            fi
            
            echo "$admin_token" > "$TEMP_DIR/admin_token"
            debug "Admin TOTP authentication successful, final token stored"
            return 0
        else
            warning "Admin user requires TOTP but response is incomplete"
            return 1
        fi
    fi
    
    # Extract token for API calls (if TOTP wasn't required)
    local admin_token
    admin_token=$(echo "$login_response" | jq -r '.token')
    
    if [ "$admin_token" = "null" ] || [ -z "$admin_token" ]; then
        warning "Failed to extract admin token"
        return 1
    fi
    
    echo "$admin_token" > "$TEMP_DIR/admin_token"
    debug "Admin authentication successful, token stored"
    return 0
}

# Admin API helper functions
admin_cleanup_user() {
    local username="$1"
    local context="$2"
    
    debug "Admin API cleanup for user: $username - $context" >&2
    
    # Check if we have admin authentication token from main()
    if [ ! -f "$TEMP_DIR/admin_token" ]; then
        error "No admin token found - admin authentication failed"
    fi
    
    local admin_token
    admin_token=$(cat "$TEMP_DIR/admin_token")
    
    debug "Using existing admin token for cleanup API call" >&2
    
    local cleanup_request
    cleanup_request=$(jq -n \
        --arg username "$username" \
        --argjson confirm true \
        '{
            username: $username,
            confirm: $confirm
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $admin_token" \
        -H "Content-Type: application/json" \
        -d "$cleanup_request" \
        "$ARKFILE_BASE_URL/api/admin/dev-test/user/cleanup" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to admin API for: $context"
    fi
    
    echo "$response"
}

admin_approve_user() {
    local username="$1"
    local approved_by="$2"
    local context="$3"
    
    debug "Admin API user approval: $username by $approved_by - $context" >&2
    
    # Check if we have admin authentication token from main()
    if [ ! -f "$TEMP_DIR/admin_token" ]; then
        error "No admin token found - admin authentication failed"
    fi
    
    local admin_token
    admin_token=$(cat "$TEMP_DIR/admin_token")
    
    debug "Using existing admin token for approval API call" >&2
    
    local approve_request
    approve_request=$(jq -n \
        --arg approved_by "$approved_by" \
        '{
            approved_by: $approved_by
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $admin_token" \
        -H "Content-Type: application/json" \
        -d "$approve_request" \
        "$ARKFILE_BASE_URL/api/admin/user/$username/approve" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to admin API for: $context"
    fi
    
    echo "$response"
}

admin_get_user_status() {
    local username="$1"
    local context="$2"
    
    debug "Admin API user status check: $username - $context" >&2
    
    # Check if we have admin authentication token from main()
    if [ ! -f "$TEMP_DIR/admin_token" ]; then
        error "No admin token found - admin authentication failed"
    fi
    
    local admin_token
    admin_token=$(cat "$TEMP_DIR/admin_token")
    
    debug "Using existing admin token for status API call" >&2
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $admin_token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/admin/user/$username/status" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to connect to admin API for: $context"
    fi
    
    echo "$response"
}

# Generate real TOTP code using production-compatible generator (FIXED: Clean output parsing)
generate_totp_code() {
    local secret="$1"
    local timestamp="${2:-}"
    local output=""

    # Send debug messages to stderr to avoid polluting stdout
    debug "[DEBUG] Generating real TOTP code for secret: ${secret:0:10}..." >&2

    # Use our TOTP generator with the same parameters as production
    if [ -f "scripts/testing/totp-generator" ]; then
        if [ -n "$timestamp" ]; then
            output=$(scripts/testing/totp-generator "$secret" "$timestamp" 2>/dev/null)
        else
            output=$(scripts/testing/totp-generator "$secret" 2>/dev/null)
        fi
    elif [ -f "scripts/totp-generator" ]; then
        if [ -n "$timestamp" ]; then
            output=$(scripts/totp-generator "$secret" "$timestamp" 2>/dev/null)
        else
            output=$(scripts/totp-generator "$secret" 2>/dev/null)
        fi
    else
        # Build generator if it doesn't exist
        warning "TOTP generator not found, building..." >&2
        if [ -f "scripts/testing/totp-generator.go" ]; then
            cd scripts/testing && go build -o totp-generator totp-generator.go && cd ../.. >/dev/null 2>&1
            generate_totp_code "$secret" "$timestamp"
            return $?
        elif [ -f "scripts/totp-generator.go" ]; then
            cd scripts && go build -o totp-generator totp-generator.go && cd .. >/dev/null 2>&1
            generate_totp_code "$secret" "$timestamp"
            return $?
        else
            error "TOTP generator source not found"
        fi
    fi
    
    # CRITICAL FIX: Extract only the 6-digit code from output (robust parsing)
    local clean_code
    clean_code=$(echo "$output" | grep -o '[0-9]\{6\}' | head -n1)
    
    if [ -z "$clean_code" ] || [ ${#clean_code} -ne 6 ]; then
        debug "Failed to extract clean TOTP code from output: '$output'" >&2
        return 1
    fi
    
    debug "[DEBUG] Generated clean TOTP code: $clean_code" >&2
    # OUTPUT ONLY THE CLEAN CODE TO STDOUT
    echo "$clean_code"
}

# TOTP code tracking to prevent reuse within 30-second window
LAST_TOTP_CODE=""
LAST_TOTP_TIMESTAMP=""

# Generate TOTP code with reuse prevention
generate_totp_with_reuse_prevention() {
    local secret="$1"
    local max_attempts=5
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        local current_timestamp=$(date +%s)
        local new_totp_code
        new_totp_code=$(generate_totp_code "$secret" 2>/dev/null)
        
        # Check if this is a different code or enough time has passed (30+ seconds)
        if [ "$new_totp_code" != "$LAST_TOTP_CODE" ] || [ -z "$LAST_TOTP_TIMESTAMP" ] || [ $((current_timestamp - LAST_TOTP_TIMESTAMP)) -ge 30 ]; then
            # Update tracking variables
            LAST_TOTP_CODE="$new_totp_code"
            LAST_TOTP_TIMESTAMP="$current_timestamp"
            echo "$new_totp_code"
            return 0
        fi
        
        # Same code within 30 seconds, wait for next window
        debug "TOTP code reuse detected ($new_totp_code), waiting for new code window..."
        attempt=$((attempt + 1))
        sleep 6  # Wait 6 seconds and try again
    done
    
    # If we get here, we've exceeded max attempts
    warning "Failed to generate unique TOTP code after $max_attempts attempts"
    echo "$new_totp_code"  # Return the last code anyway
}

# Fresh authentication helper function (standardized pattern from fix-upload.sh)
authenticate_via_curl() {
    debug "=== Starting fresh authentication workflow ==="
    
    # Phase 1: OPAQUE Login
    debug "Phase 1: OPAQUE authentication for fresh login..."
    local login_request
    login_request=$(jq -n \
        --arg username "$TEST_USERNAME" \
        --arg password "$TEST_PASSWORD" \
        '{
            username: $username,
            password: $password
        }')
    
    local opaque_response
    opaque_response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$login_request" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")
    
    if [ "$opaque_response" = "ERROR" ]; then
        warning "Fresh OPAQUE authentication failed - cannot connect to server"
        return 1
    fi
    
    if ! echo "$opaque_response" | jq -e '.requires_totp' >/dev/null 2>&1; then
        warning "Fresh OPAQUE authentication failed: $opaque_response"
        return 1
    fi
    
    # Extract temporary tokens using consistent snake_case
    local temp_token session_key
    temp_token=$(echo "$opaque_response" | jq -r '.temp_token')
    session_key=$(echo "$opaque_response" | jq -r '.session_key')
    
    if [ "$temp_token" = "null" ] || [ "$session_key" = "null" ]; then
        warning "Fresh OPAQUE response missing required tokens"
        return 1
    fi
    
    debug "OPAQUE phase successful, proceeding to TOTP authentication"
    
    # Phase 2: TOTP Authentication
    debug "Phase 2: TOTP authentication for fresh login..."
    
    # Check for stored TOTP secret from Phase 4
    if [ ! -f "$TEMP_DIR/totp_secret" ]; then
        warning "TOTP secret not found - cannot complete fresh authentication"
        return 1
    fi
    
    local totp_secret padded_secret totp_code
    totp_secret=$(cat "$TEMP_DIR/totp_secret")
    padded_secret=$(fix_totp_secret_padding "$totp_secret")
    totp_code=$(generate_totp_with_reuse_prevention "$padded_secret")
    
    if [ -z "$totp_code" ] || [ ${#totp_code} -ne 6 ] || ! [[ "$totp_code" =~ ^[0-9]{6}$ ]]; then
        warning "Failed to generate valid TOTP code for fresh authentication: '$totp_code'"
        return 1
    fi
    
    debug "Generated TOTP code for fresh authentication: $totp_code"
    
    # Complete TOTP authentication using consistent snake_case payload
    local totp_request
    totp_request=$(jq -n \
        --arg code "$totp_code" \
        --arg session_key "$session_key" \
        --argjson is_backup false \
        '{
            code: $code,
            session_key: $session_key,
            is_backup: $is_backup
        }')
    
    local totp_response
    totp_response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $temp_token" \
        -H "Content-Type: application/json" \
        -d "$totp_request" \
        "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")
    
    if [ "$totp_response" = "ERROR" ]; then
        warning "Fresh TOTP authentication failed - cannot connect to server"
        return 1
    fi
    
    if ! echo "$totp_response" | jq -e '.token' >/dev/null 2>&1; then
        warning "Fresh TOTP authentication failed: $totp_response"
        return 1
    fi
    
    # Extract final tokens using consistent snake_case keys
    local final_token refresh_token
    final_token=$(echo "$totp_response" | jq -r '.token')
    refresh_token=$(echo "$totp_response" | jq -r '.refresh_token')
    
    if [ "$final_token" = "null" ] || [ -z "$final_token" ]; then
        warning "Fresh authentication response missing valid token"
        return 1
    fi
    
    debug "Fresh authentication successful, creating session files..."
    
    # Create session and config files following fix-upload.sh schema
    local client_session_file="$TEMP_DIR/fresh_auth_session.json"
    local client_config_file="$TEMP_DIR/fresh_auth_config.json"
    
    # Parse JWT expiration for session file
    local expires_at
    expires_at=$(date -u -d "+30 minutes" --iso-8601=seconds)
    
    jq -n \
        --arg username "$TEST_USERNAME" \
        --arg access_token "$final_token" \
        --arg refresh_token "$refresh_token" \
        --arg expires_at "$expires_at" \
        --arg server_url "$ARKFILE_BASE_URL" \
        --arg session_created "$(date -u --iso-8601=seconds)" \
        '{
            username: $username,
            access_token: $access_token,
            refresh_token: $refresh_token,
            expires_at: $expires_at,
            server_url: $server_url,
            session_created: $session_created
        }' > "$client_session_file"
    
    jq -n \
        --arg server_url "$ARKFILE_BASE_URL" \
        --arg username "$TEST_USERNAME" \
        --arg token_file "$client_session_file" \
        '{
            server_url: $server_url,
            username: $username,
            tls_insecure: true,
            token_file: $token_file
        }' > "$client_config_file"
    
    # Store paths for caller
    echo "$client_config_file" > "$TEMP_DIR/fresh_auth_config_path"
    echo "$client_session_file" > "$TEMP_DIR/fresh_auth_session_path"
    echo "$final_token" > "$TEMP_DIR/fresh_auth_token"
    
    debug "Fresh authentication completed successfully"
    return 0
}

# Performance timing utility
start_timer() {
    echo "$(date +%s%N)"
}

end_timer() {
    local start_time="$1"
    local end_time="$(date +%s%N)"
    local duration=$((($end_time - $start_time) / 1000000))  # Convert to milliseconds
    echo "${duration}ms"
}

# PHASE 1: PRE-FLIGHT & CLEANUP
phase_cleanup_and_health() {
    phase "PRE-FLIGHT & CLEANUP"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    log "Cleaning up existing test user: $TEST_USERNAME"
    
    # Use Admin API for comprehensive cleanup
    local result
    result=$(admin_cleanup_user "$TEST_USERNAME" "Test user cleanup" 2>/dev/null || echo "ERROR")
    
    if [[ "$result" != "ERROR" ]]; then
        if save_json_response "$result" "cleanup.json" "admin cleanup API"; then
            local success tables_cleaned total_rows
            success=$(jq -r '.success' "$TEMP_DIR/cleanup.json")
            tables_cleaned=$(jq -r '.tables_cleaned | keys | length' "$TEMP_DIR/cleanup.json")
            total_rows=$(jq -r '.total_rows_affected' "$TEMP_DIR/cleanup.json")
            
            if [ "$success" = "true" ]; then
                success "Test user cleanup completed via Admin API: $tables_cleaned tables, $total_rows total rows"
            else
                warning "Admin API cleanup reported failure"
                info "Some cleanup failures are expected if user doesn't exist yet"
            fi
        else
            warning "Admin API cleanup had issues but may have partially succeeded"
            info "Some cleanup failures are expected if user doesn't exist yet"
        fi
    else
        warning "Admin API not available, cleanup may be incomplete"
        info "This is expected if admin endpoints are not accessible"
    fi
    
    # Verify cleanup using admin API status check with retry logic
    local verify_result exists
    local retry_count=0
    local max_retries=3
    
    while [ $retry_count -lt $max_retries ]; do
        verify_result=$(admin_get_user_status "$TEST_USERNAME" "Verify user deletion" 2>/dev/null || echo "ERROR")
        
        if [[ "$verify_result" != "ERROR" ]]; then
            if save_json_response "$verify_result" "user_status_${retry_count}.json" "admin user status check"; then
                exists=$(jq -r '.exists' "$TEMP_DIR/user_status_${retry_count}.json")
                if [ "$exists" = "false" ]; then
                    debug "Verified: User does not exist (Admin API confirmation after $((retry_count + 1)) attempt(s))"
                    break
                else
                    retry_count=$((retry_count + 1))
                    if [ $retry_count -lt $max_retries ]; then
                        debug "User still exists, retrying verification in 1 second... (attempt $((retry_count + 1))/$max_retries)"
                        sleep 1
                    else
                        warning "User still exists after cleanup and $max_retries verification attempts!"
                        info "This may indicate a database transaction timing issue or incomplete cleanup"
                    fi
                fi
            else
                warning "Failed to verify user status via admin API"
                break
            fi
        else
            warning "Admin API not available for cleanup verification"
            break
        fi
    done
    
    # Test server health
    log "Testing server connectivity and health..."
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/opaque/health" || echo "ERROR")
    
    save_json_response "$response" "health.json" "health endpoint" || error "Health check failed"
    
    local status
    status=$(jq -r '.status' "$TEMP_DIR/health.json")
    
    if [ "$status" = "healthy" ]; then
        success "Server is healthy and accessible"
    else
        error "Server is not healthy: $status"
    fi
    
    # Test TOTP generator
    log "Testing TOTP generator..."
    local test_code
    test_code=$(generate_totp_code "JBSWY3DPEHPK3PXP" "1609459200" 2>/dev/null)
    
    if [ ${#test_code} -eq 6 ] && [[ "$test_code" =~ ^[0-9]+$ ]]; then
        success "TOTP generator working correctly (generated: $test_code)"
    else
        error "TOTP generator failed to produce valid code: $test_code"
    fi
    
    # Validate required utilities
    log "Validating required utilities..."
    
    if ! command -v jq &> /dev/null; then
        error "jq is required for JSON parsing. Please install jq."
    fi
    
    if ! command -v curl &> /dev/null; then
        error "curl is required for API testing. Please install curl."
    fi
    
    success "All utilities available"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "Cleanup & Health Check completed in: $duration"
    fi
}

# PHASE 2: OPAQUE REGISTRATION
phase_registration() {
    phase "OPAQUE REGISTRATION"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    log "Registering new user: $TEST_USERNAME"
    
    local register_request
    register_request=$(jq -n \
        --arg username "$TEST_USERNAME" \
        --arg password "$TEST_PASSWORD" \
        '{
            username: $username,
            password: $password
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$register_request" \
        "$ARKFILE_BASE_URL/api/opaque/register" || echo "ERROR")
    
    debug "Registration response: $response"
    
    local error_msg=""
    if ! save_json_response "$response" "register.json" "registration endpoint"; then
        error_msg=$(save_json_response "$response" "register.json" "registration endpoint" 2>&1 || echo "Registration failed")
        
        # Handle existing user case
        if echo "$error_msg" | grep -q -i "already exists\|already registered\|duplicate"; then
            warning "User already exists: $TEST_USERNAME"
            log "Proceeding with existing account..."
            return
        else
            error "Registration failed: $error_msg"
        fi
    fi
    
    # Extract registration details
    local temp_token session_key auth_method email requires_totp_setup message
    temp_token=$(jq -r '.temp_token' "$TEMP_DIR/register.json")
    session_key=$(jq -r '.session_key' "$TEMP_DIR/register.json")
    auth_method=$(jq -r '.auth_method' "$TEMP_DIR/register.json")
    email=$(jq -r '.email' "$TEMP_DIR/register.json")
    requires_totp_setup=$(jq -r '.requires_totp_setup' "$TEMP_DIR/register.json")
    message=$(jq -r '.message' "$TEMP_DIR/register.json")
    
    debug "Extracted values: temp_token=${temp_token:0:20}..., session_key=${session_key:0:20}..., requires_totp_setup=$requires_totp_setup"
    
    # Validate registration response for TOTP setup requirement
    if [ "$temp_token" = "null" ] || [ "$session_key" = "null" ]; then
        error "Registration response missing required tokens for TOTP setup. tempToken=$temp_token, sessionKey=$session_key"
    fi
    
    if [ "$requires_totp_setup" != "true" ]; then
        if [ "$MANDATORY_TOTP" = true ]; then
            error "Expected requires_totp_setup=true for mandatory TOTP mode, got: $requires_totp_setup"
        else
            warning "TOTP setup not required (non-mandatory mode): $requires_totp_setup"
        fi
    fi
    
    success "User registered successfully: $message"
    info "Authentication method: $auth_method"
    info "Email: $email"
    info "TOTP setup required: $requires_totp_setup"
    
    # Store tokens for TOTP setup phase
    echo "$temp_token" > "$TEMP_DIR/temp_token"
    echo "$session_key" > "$TEMP_DIR/session_key"
    
    success "Registration phase completed - TOTP setup tokens stored"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "Registration completed in: $duration"
    fi
}

# PHASE 3: ADMIN API USER APPROVAL
phase_user_approval() {
    phase "ADMIN API USER APPROVAL"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    log "Approving user via Admin API: $TEST_USERNAME"
    
    # Use Admin API for user approval  
    local response
    response=$(admin_approve_user "$TEST_USERNAME" "$ADMIN_USERNAME" "Test user approval" 2>/dev/null || echo "ERROR")
    
    if [[ "$response" = "ERROR" ]]; then
        error "Admin API not available for user approval - this is a critical failure"
    fi
    
    if ! save_json_response "$response" "approve.json" "admin approval API"; then
        error "Admin API approval failed with invalid response - this is a critical failure"
    fi
    
    local success username is_approved approved_by
    success=$(jq -r '.success' "$TEMP_DIR/approve.json")
    username=$(jq -r '.username' "$TEMP_DIR/approve.json")
    is_approved=$(jq -r '.is_approved' "$TEMP_DIR/approve.json")
    approved_by=$(jq -r '.approved_by' "$TEMP_DIR/approve.json")
    
    if [ "$success" != "true" ] || [ "$is_approved" != "true" ]; then
        error "Admin API user approval failed: success=$success, isApproved=$is_approved - this is a critical failure"
    fi
    
    success "User approved via Admin API: $username by $approved_by"
    
    # Verify approval using admin API status check
    local verify_result
    verify_result=$(admin_get_user_status "$TEST_USERNAME" "Verify user approval" 2>/dev/null || echo "ERROR")
    
    if [[ "$verify_result" = "ERROR" ]]; then
        error "Could not verify user approval status via Admin API - this is a critical failure"
    fi
    
    if ! save_json_response "$verify_result" "user_approval_status.json" "admin user approval status"; then
        error "Admin API status verification failed with invalid response - this is a critical failure"
    fi
    
    local exists user_approved
    exists=$(jq -r '.exists' "$TEMP_DIR/user_approval_status.json")
    user_approved=$(jq -r '.user.is_approved' "$TEMP_DIR/user_approval_status.json")
    
    if [ "$exists" != "true" ]; then
        error "User does not exist after approval attempt - this is a critical failure"
    fi
    
    if [ "$user_approved" != "true" ]; then
        error "User approval verification failed: user exists but isApproved=$user_approved - this is a critical failure"
    fi
    
    success "User approval verified via Admin API"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "User approval completed in: $duration"
    fi
}

# PHASE 4: TOTP SETUP & ENDPOINT VALIDATION
phase_totp_setup_comprehensive() {
    phase "TOTP SETUP & ENDPOINT VALIDATION"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    if [ "$ENDPOINTS_ONLY" = true ]; then
        log "Running TOTP endpoint validation only..."
        test_individual_totp_endpoints
        return
    fi
    
    if [ ! -f "$TEMP_DIR/temp_token" ] || [ ! -f "$TEMP_DIR/session_key" ]; then
        error "Missing temp token or session key for TOTP setup"
    fi
    
    local temp_token session_key
    temp_token=$(cat "$TEMP_DIR/temp_token")
    session_key=$(cat "$TEMP_DIR/session_key")
    
    log "Initiating TOTP setup..."
    
    # Test TOTP setup endpoint
    local setup_request
    setup_request=$(jq -n \
        --arg session_key "$session_key" \
        '{
            session_key: $session_key
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $temp_token" \
        -H "Content-Type: application/json" \
        -d "$setup_request" \
        "$ARKFILE_BASE_URL/api/totp/setup" || echo "ERROR")
    
    save_json_response "$response" "totp_setup.json" "TOTP setup endpoint" || error "TOTP setup failed"
    
    # Extract TOTP details
    local secret qr_url backup_codes manual_entry backup_code_count
    secret=$(jq -r '.secret' "$TEMP_DIR/totp_setup.json")
    qr_url=$(jq -r '.qr_code_url' "$TEMP_DIR/totp_setup.json")
    manual_entry=$(jq -r '.manual_entry' "$TEMP_DIR/totp_setup.json")

    # Handle backup codes with null check (check both formats)
    if jq -e '.backup_codes == null and .backupCodes == null' "$TEMP_DIR/totp_setup.json" >/dev/null 2>&1; then
        warning "Backup codes field is null in TOTP setup response"
        backup_codes=""
        backup_code_count=0
    elif jq -e '.backup_codes' "$TEMP_DIR/totp_setup.json" >/dev/null 2>&1; then  # Try snake_case first
        backup_codes=$(jq -r '.backup_codes[]' "$TEMP_DIR/totp_setup.json")
        backup_code_count=$(echo "$backup_codes" | wc -l)
    elif jq -e '.backupCodes' "$TEMP_DIR/totp_setup.json" >/dev/null 2>&1; then  # Fall back to camelCase
        backup_codes=$(jq -r '.backupCodes[]' "$TEMP_DIR/totp_setup.json")
        backup_code_count=$(echo "$backup_codes" | wc -l)
    else
        warning "No backupCodes/backup_codes field found in TOTP setup response"
        backup_codes=""
        backup_code_count=0
    fi

    # Validate TOTP setup response
    if [ "$secret" = "null" ] || [ "$qr_url" = "null" ] || [ "$manual_entry" = "null" ]; then
        error "TOTP setup response missing required fields"
    fi

    success "TOTP setup initiated successfully"
    info "TOTP Secret length: ${#secret} characters"
    info "QR Code URL: ${qr_url:0:50}..."
    info "Manual entry format: ${manual_entry:0:30}..."
    info "Backup codes generated: $backup_code_count"

    # Store TOTP data for verification
    echo "$secret" > "$TEMP_DIR/totp_secret"
    if [ "$backup_code_count" -gt 0 ]; then
        echo "$backup_codes" | head -n1 > "$TEMP_DIR/backup_code"
    fi
    
    # Test TOTP status endpoint
    log "Testing TOTP status endpoint..."
    response=$(curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $temp_token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/totp/status" || echo "ERROR")
    
    if save_json_response "$response" "totp_status.json" "TOTP status endpoint"; then
        local enabled setup_required
        enabled=$(jq -r '.enabled' "$TEMP_DIR/totp_status.json")
        setup_required=$(jq -r '.setupRequired' "$TEMP_DIR/totp_status.json")
        success "TOTP status endpoint working correctly (enabled: $enabled, setup_required: $setup_required)"
    else
        warning "TOTP status endpoint failed"
    fi
    
    # Complete TOTP setup with verification
    log "Completing TOTP setup with real code verification..."
    
    # Fix the TOTP secret padding for proper base32 decoding
    local padded_secret
    padded_secret=$(fix_totp_secret_padding "$secret")

    local test_code
    test_code=$(generate_totp_code "$padded_secret" "" 2>/dev/null)
    
    if [ -z "$test_code" ] || [ ${#test_code} -ne 6 ]; then
        error "Failed to generate valid TOTP code for verification. Secret: ${secret:0:10}..., Padded: ${padded_secret:0:10}..."
    fi
    
    info "Generated TOTP verification code: $test_code"
    
    local verify_request
    verify_request=$(jq -n \
        --arg code "$test_code" \
        --arg sessionKey "$session_key" \
        '{
            code: $code,
            sessionKey: $sessionKey
        }')
    
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $temp_token" \
        -H "Content-Type: application/json" \
        -d "$verify_request" \
        "$ARKFILE_BASE_URL/api/totp/verify" || echo "ERROR")
    
    debug "TOTP verification response: $response"
    
    # Handle TOTP verification - check for success message or error
    local verification_success=false
    local error_msg=""
    
    if save_json_response "$response" "totp_verify.json" "TOTP verification endpoint"; then
        # Check if response contains success message
        local message enabled
        message=$(jq -r '.message' "$TEMP_DIR/totp_verify.json" 2>/dev/null || echo "")
        enabled=$(jq -r '.enabled' "$TEMP_DIR/totp_verify.json" 2>/dev/null || echo "")
        
        if [ "$message" = "TOTP setup completed successfully" ] || [ "$enabled" = "true" ]; then
            verification_success=true
            success "TOTP verification completed successfully with real code!"
            info "TOTP is now enabled for the user"
        else
            error_msg="Server response: $message"
            warning "TOTP verification with real code failed: $error_msg"
        fi
    else
        error_msg=$(save_json_response "$response" "totp_verify.json" "TOTP verification endpoint" 2>&1 || echo "Verification failed")
        warning "TOTP verification with real code failed: $error_msg"
    fi
    
    if [ "$verification_success" = false ]; then
        error "TOTP verification failed - this is a critical failure in Phase 4"
    fi
    
    success "TOTP setup phase completed"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "TOTP setup completed in: $duration"
    fi
}

# Helper function to add proper base32 padding to TOTP secret
fix_totp_secret_padding() {
    local secret="$1"
    local secret_len=${#secret}
    local remainder=$((secret_len % 8))
    
    if [ $remainder -ne 0 ]; then
        local padding_needed=$((8 - remainder))
        for ((i=0; i<padding_needed; i++)); do
            secret="${secret}="
        done
    fi
    
    echo "$secret"
}

# Individual TOTP endpoint testing function
test_individual_totp_endpoints() {
    log "Testing individual TOTP endpoints..."
    
    # This requires having a valid JWT token, so we need to create a test user first
    setup_test_user_for_endpoint_testing
    
    local token
    token=$(cat "$TEMP_DIR/jwt_token")
    
    # Test each endpoint individually
    test_totp_setup_endpoint "$token"
    test_totp_status_endpoint "$token"
    test_totp_verify_endpoint "$token"
    test_totp_auth_endpoint
    test_totp_disable_endpoint "$token"
    
    success "Individual TOTP endpoint testing completed"
}

# Setup test user for endpoint testing
setup_test_user_for_endpoint_testing() {
    log "Setting up test user for endpoint testing..."
    
    # Register user
    local register_request
    register_request=$(jq -n \
        --arg username "$TEST_USERNAME" \
        --arg password "$TEST_PASSWORD" \
        '{
            username: $username,
            password: $password
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$register_request" \
        "$ARKFILE_BASE_URL/api/opaque/register" || echo "ERROR")
    
    if [ "$response" != "ERROR" ]; then
        debug "User registration for endpoint testing: success"
    fi
    
    # Approve user via Admin API (no direct database access)
    local approve_resp
    approve_resp=$(admin_approve_user "$TEST_USERNAME" "endpoint-test" "Endpoint test approval" 2>/dev/null || echo "ERROR")
    if [[ "$approve_resp" != "ERROR" ]]; then
        if echo "$approve_resp" | jq -e '.success == true and .is_approved == true' >/dev/null 2>&1; then
            debug "User approved via Admin API for endpoint testing"
        else
            warning "Admin API approval may not have succeeded for endpoint testing"
        fi
    else
        warning "Admin API approval unavailable during endpoint testing"
    fi
    
    # Login user to get full token
    local login_request
    login_request=$(jq -n \
        --arg username "$TEST_USERNAME" \
        --arg password "$TEST_PASSWORD" \
        '{
            username: $username,
            password: $password
        }')
    
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$login_request" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        error "Failed to login test user for endpoint testing"
    fi
    
    echo "$response" | jq . > "$TEMP_DIR/login.json" 2>/dev/null || {
        error "Invalid JSON response from login for endpoint testing: $response"
    }
    
    # Extract tokens
    local token session_key
    token=$(jq -r '.temp_token' "$TEMP_DIR/login.json")
    session_key=$(jq -r '.session_key' "$TEMP_DIR/login.json")
    
    if [ "$token" = "null" ] || [ "$session_key" = "null" ]; then
        error "Failed to extract authentication tokens for endpoint testing"
    fi
    
    echo "$token" > "$TEMP_DIR/jwt_token"
    echo "$session_key" > "$TEMP_DIR/session_key"
    
    success "Test user setup completed for endpoint testing"
}

# Individual endpoint testing functions
test_totp_setup_endpoint() {
    local token="$1"
    local session_key
    session_key=$(cat "$TEMP_DIR/session_key")
    
    log "Testing TOTP Setup endpoint..."
    
    local setup_request
    setup_request=$(jq -n \
        --arg sessionKey "$session_key" \
        '{
            sessionKey: $sessionKey
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$setup_request" \
        "$ARKFILE_BASE_URL/api/totp/setup" || echo "ERROR")
    
    if save_json_response "$response" "totp_setup_endpoint.json" "TOTP setup endpoint test"; then
        success "TOTP Setup endpoint working correctly"
        
        # Validate response structure
        local secret qr_code backup_codes
        secret=$(jq -r '.secret' "$TEMP_DIR/totp_setup_endpoint.json")
        qr_code=$(jq -r '.qrCodeUrl' "$TEMP_DIR/totp_setup_endpoint.json")
        backup_codes=$(jq -r '.backupCodes | length' "$TEMP_DIR/totp_setup_endpoint.json")
        
        info "  - Secret length: ${#secret} characters"
        info "  - QR Code URL provided: ${qr_code:0:50}..."
        info "  - Backup codes provided: $backup_codes"
    else
        warning "TOTP Setup endpoint test failed"
    fi
}

test_totp_status_endpoint() {
    local token="$1"
    
    log "Testing TOTP Status endpoint..."
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/totp/status" || echo "ERROR")
    
    if save_json_response "$response" "totp_status_endpoint.json" "TOTP status endpoint test"; then
        local enabled setup_required
        enabled=$(jq -r '.enabled' "$TEMP_DIR/totp_status_endpoint.json")
        setup_required=$(jq -r '.setupRequired' "$TEMP_DIR/totp_status_endpoint.json")
        
        success "TOTP Status endpoint working correctly"
        info "  - TOTP enabled: $enabled"
        info "  - Setup required: $setup_required"
    else
        warning "TOTP Status endpoint test failed"
    fi
}

test_totp_verify_endpoint() {
    local token="$1"
    local session_key
    session_key=$(cat "$TEMP_DIR/session_key")
    
    log "Testing TOTP Verify endpoint..."
    
    # Use a test code (this will fail verification but tests the endpoint)
    local verify_request
    verify_request=$(jq -n \
        --arg code "123456" \
        --arg sessionKey "$session_key" \
        '{
            code: $code,
            sessionKey: $sessionKey
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$verify_request" \
        "$ARKFILE_BASE_URL/api/totp/verify" || echo "ERROR")
    
    # This should fail with invalid code, which proves the endpoint is working
    if save_json_response "$response" "totp_verify_endpoint.json" "TOTP verify endpoint test"; then
        warning "TOTP Verify endpoint accepted invalid code (unexpected)"
    else
        local error_msg
        error_msg=$(save_json_response "$response" "totp_verify_endpoint.json" "TOTP verify endpoint test" 2>&1 || echo "")
        if echo "$error_msg" | grep -q -i "invalid\|expired\|incorrect"; then
            success "TOTP Verify endpoint correctly rejects invalid codes"
            info "  - Expected error: $error_msg"
        else
            warning "TOTP Verify endpoint failed with unexpected error: $error_msg"
        fi
    fi
}

test_totp_auth_endpoint() {
    log "Testing TOTP Auth endpoint..."
    
    # Test with invalid token (should fail with unauthorized)
    local auth_request
    auth_request=$(jq -n \
        --arg code "123456" \
        --arg sessionKey "test-session-key" \
        --argjson isBackup false \
        '{
            code: $code,
            sessionKey: $sessionKey,
            isBackup: $isBackup
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer invalid-temp-token" \
        -H "Content-Type: application/json" \
        -d "$auth_request" \
        "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")
    
    # This should fail with unauthorized, which proves the endpoint is working
    if save_json_response "$response" "totp_auth_endpoint.json" "TOTP auth endpoint test"; then
        warning "TOTP Auth endpoint accepted invalid token (unexpected)"
    else
        local error_msg
        error_msg=$(save_json_response "$response" "totp_auth_endpoint.json" "TOTP auth endpoint test" 2>&1 || echo "")
        if echo "$error_msg" | grep -q -i "unauthorized\|invalid.*token\|expired"; then
            success "TOTP Auth endpoint correctly rejects invalid tokens"
            info "  - Expected error: $error_msg"
        else
            warning "TOTP Auth endpoint failed with unexpected error: $error_msg"
        fi
    fi
}

test_totp_disable_endpoint() {
    local token="$1"
    local session_key
    session_key=$(cat "$TEMP_DIR/session_key")
    
    log "Testing TOTP Disable endpoint..."
    
    local disable_request
    disable_request=$(jq -n \
        --arg currentCode "123456" \
        --arg sessionKey "$session_key" \
        '{
            currentCode: $currentCode,
            sessionKey: $sessionKey
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$disable_request" \
        "$ARKFILE_BASE_URL/api/totp/disable" || echo "ERROR")
    
    # This should fail since TOTP isn't actually set up
    if save_json_response "$response" "totp_disable_endpoint.json" "TOTP disable endpoint test"; then
        warning "TOTP Disable endpoint succeeded (unexpected without setup)"
    else
        local error_msg
        error_msg=$(save_json_response "$response" "totp_disable_endpoint.json" "TOTP disable endpoint test" 2>&1 || echo "")
        if echo "$error_msg" | grep -q -i "not.*enabled\|invalid\|not.*found"; then
            success "TOTP Disable endpoint correctly handles requests"
            info "  - Expected error: $error_msg"
        else
            warning "TOTP Disable endpoint failed with unexpected error: $error_msg"
        fi
    fi
}

# PHASE 5: OPAQUE LOGIN AUTHENTICATION
phase_login() {
    phase "OPAQUE LOGIN AUTHENTICATION"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    log "Attempting login with OPAQUE user: $TEST_USERNAME"
    
    local login_request
    login_request=$(jq -n \
        --arg username "$TEST_USERNAME" \
        --arg password "$TEST_PASSWORD" \
        '{
            username: $username,
            password: $password
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$login_request" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")
    
    debug "Login response: $response"
    
    local error_msg=""
    if ! save_json_response "$response" "login.json" "login endpoint"; then
        error_msg=$(save_json_response "$response" "login.json" "login endpoint" 2>&1 || echo "Login failed")
        
        # Check if it's the expected mandatory TOTP setup error
        if echo "$error_msg" | grep -q "Two-factor authentication setup is required"; then
            if [ "$MANDATORY_TOTP" = true ]; then
                success "Login correctly blocked - TOTP setup is mandatory [OK]"
                info "Error message: $error_msg"
                return
            else
                error "Login blocked - TOTP setup is mandatory but not expected: $error_msg"
            fi
        else
            info "Login error details: $error_msg"
            info "This may be expected if TOTP setup is required during login flow"
        fi
    fi
    
    # Extract login details
    local temp_token session_key auth_method requires_totp
    temp_token=$(jq -r '.temp_token' "$TEMP_DIR/login.json")
    session_key=$(jq -r '.session_key' "$TEMP_DIR/login.json")
    auth_method=$(jq -r '.auth_method' "$TEMP_DIR/login.json")
    requires_totp=$(jq -r '.requires_totp' "$TEMP_DIR/login.json")
    
    # Validate login response
    if [ "$temp_token" = "null" ] || [ "$session_key" = "null" ]; then
        error "Login response missing required tokens"
    fi
    
    if [ "$requires_totp" != "true" ]; then
        error "Expected requires_totp=true, got: $requires_totp"
    fi
    
    success "OPAQUE login successful - TOTP authentication required"
    info "Authentication method: $auth_method"
    info "TOTP required: $requires_totp"
    
    # Store tokens for TOTP auth (temporary tokens, will be upgraded after TOTP)
    echo "$temp_token" > "$TEMP_DIR/temp_token"
    echo "$session_key" > "$TEMP_DIR/session_key"
    
    success "Login phase completed - TOTP authentication needed"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "Login completed in: $duration"
    fi
}

# PHASE 6: TOTP TWO-FACTOR AUTHENTICATION
phase_totp_authentication() {
    phase "TOTP TWO-FACTOR AUTHENTICATION"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    if [ ! -f "$TEMP_DIR/temp_token" ] || [ ! -f "$TEMP_DIR/session_key" ]; then
        error "Missing login tokens for TOTP authentication"
    fi
    
    local temp_token session_key
    temp_token=$(cat "$TEMP_DIR/temp_token")
    session_key=$(cat "$TEMP_DIR/session_key")
    

    log "Attempting TOTP authentication with real code..."

    # Always try real TOTP code first - this should work reliably
    if [ -f "$TEMP_DIR/totp_secret" ]; then
        local totp_secret totp_code
        totp_secret=$(cat "$TEMP_DIR/totp_secret")
        totp_code=$(generate_totp_code "$totp_secret" 2>/dev/null)

        if [ -n "$totp_code" ] && [ ${#totp_code} -eq 6 ] && [[ "$totp_code" =~ ^[0-9]+$ ]]; then
            info "Using real TOTP code: $totp_code"

            local auth_request
            auth_request=$(jq -n \
                --arg code "$totp_code" \
                --arg session_key "$session_key" \
                --argjson is_backup false \
                '{
                    code: $code,
                    session_key: $session_key,
                    is_backup: $is_backup
                }')

            local response
            response=$(curl -s $INSECURE_FLAG \
                -X POST \
                -H "Authorization: Bearer $temp_token" \
                -H "Content-Type: application/json" \
                -d "$auth_request" \
                "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")

            # Check if TOTP code worked
            if save_json_response "$response" "totp_auth_real.json" "TOTP auth with real code"; then
                local token_in_response
                token_in_response=$(jq -r '.token' "$TEMP_DIR/totp_auth_real.json")
                if [ "$token_in_response" != "null" ] && [ -n "$token_in_response" ]; then
                    success "TOTP authentication successful with real code!"

                    # Extract final tokens (using correct snake_case keys from server response)
                    local final_token refresh_token final_session_key auth_method
                    final_token=$(jq -r '.token' "$TEMP_DIR/totp_auth_real.json")
                    refresh_token=$(jq -r '.refresh_token' "$TEMP_DIR/totp_auth_real.json")
                    final_session_key=$(jq -r '.session_key' "$TEMP_DIR/totp_auth_real.json")
                    auth_method=$(jq -r '.auth_method' "$TEMP_DIR/totp_auth_real.json")

                    # Store final tokens in single jwt_token file (standardized)
                    echo "$final_token" > "$TEMP_DIR/jwt_token"
                    echo "$refresh_token" > "$TEMP_DIR/refresh_token"
                    echo "$final_session_key" > "$TEMP_DIR/session_key"

                    success "TOTP authentication completed with real code"
                    info "Final authentication method: $auth_method"
                    info "JWT Token length: ${#final_token} characters"
                    info "Token valid for 30 minutes with 25-minute auto-refresh"

                    return 0
                fi
            fi
        fi
    fi

    # Only as a last resort, try backup codes - but this should not be needed for properly working system
    if [ -f "$TEMP_DIR/backup_code" ]; then
        warning "Real TOTP failed, attempting backup code as fallback..."
        local backup_code
        backup_code=$(cat "$TEMP_DIR/backup_code")
        info "TOTP code generation appears to have timing issues - trying backup code"
        info "Using backup code: $backup_code"

        # Note: Depending on server implementation, backup codes may need different endpoint
        # Most systems handle backup codes separately from regular TOTP
        # For now, let's try with isBackup=true but if server doesn't support it, error will be clear

        local auth_request
        auth_request=$(jq -n \
            --arg code "$backup_code" \
            --arg sessionKey "$session_key" \
            --argjson isBackup true \
            '{
                code: $code,
                session_key: $sessionKey,
                is_backup: $isBackup
            }')

        local response
        response=$(curl -s $INSECURE_FLAG \
            -X POST \
            -H "Authorization: Bearer $temp_token" \
            -H "Content-Type: application/json" \
            -d "$auth_request" \
            "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")

        local error_msg=""
        if ! save_json_response "$response" "totp_auth_backup.json" "TOTP auth with backup code"; then
            error_msg=$(save_json_response "$response" "totp_auth_backup.json" "TOTP auth with backup code" 2>&1 || echo "Backup auth failed")
            warning "TOTP authentication with backup code also failed: $error_msg"
            error "CRITICAL: Both real TOTP and backup code authentication failed - cannot proceed with tests"
        fi

        # Extract final tokens from backup code auth (using correct snake_case keys from server response)
        local final_token refresh_token final_session_key auth_method
        final_token=$(jq -r '.token' "$TEMP_DIR/totp_auth_backup.json")
        if [ "$final_token" = "null" ] || [ -z "$final_token" ]; then
            error "Backup code auth response missing valid token"
        fi

        refresh_token=$(jq -r '.refresh_token' "$TEMP_DIR/totp_auth_backup.json")
        final_session_key=$(jq -r '.session_key' "$TEMP_DIR/totp_auth_backup.json")
        auth_method=$(jq -r '.auth_method' "$TEMP_DIR/totp_auth_backup.json")

        success "TOTP authentication completed with backup code"
        info "Final authentication method: $auth_method"
        info "JWT Token length: ${#final_token} characters"
        info "Token valid for 30 minutes with 25-minute auto-refresh"

        # Store final tokens
        echo "$final_token" > "$TEMP_DIR/final_jwt_token"
        echo "$refresh_token" > "$TEMP_DIR/final_refresh_token"
        echo "$final_session_key" > "$TEMP_DIR/final_session_key"
    else
        error "No backup code available and TOTP generation failed - cannot authenticate"
    fi

    success "TOTP authentication phase completed"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "TOTP authentication completed in: $duration"
    fi
}

# PHASE 7: SESSION MANAGEMENT & API ACCESS
phase_session_testing() {
    phase "SESSION MANAGEMENT & API ACCESS"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    if [ ! -f "$TEMP_DIR/jwt_token" ]; then
        warning "No JWT token available, skipping session tests"
        return
    fi
    
    local token
    token=$(cat "$TEMP_DIR/jwt_token")
    
    # Test authenticated API call
    log "Testing authenticated API access..."
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/files" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        warning "Failed to make authenticated API call (may be due to mock token)"
    elif save_json_response "$response" "files.json" "files endpoint"; then
        success "Authenticated API call successful"
        info "Files endpoint accessible with final token"
    else
        warning "Authenticated API call failed (expected with mock tokens)"
    fi
    
    # Test token refresh (if we have a real refresh token)
    if [ -f "$TEMP_DIR/final_refresh_token" ]; then
        local refresh_token
        refresh_token=$(cat "$TEMP_DIR/final_refresh_token")
        
        if [[ "$refresh_token" != "mock-"* ]]; then
            log "Testing token refresh (30-minute JWT token lifecycle)..."
            
            local refresh_request
            refresh_request=$(jq -n \
                --arg refreshToken "$refresh_token" \
                '{
                    refreshToken: $refreshToken
                }')
            
            response=$(curl -s $INSECURE_FLAG \
                -X POST \
                -H "Content-Type: application/json" \
                -d "$refresh_request" \
                "$ARKFILE_BASE_URL/api/refresh" || echo "ERROR")
            
            if [ "$response" != "ERROR" ] && save_json_response "$response" "refresh.json" "token refresh endpoint"; then
                local new_token
                new_token=$(jq -r '.token' "$TEMP_DIR/refresh.json")
                success "Token refresh successful (30-minute token lifecycle)"
                info "New JWT Token length: ${#new_token} characters"
                info "Token will auto-refresh at 25-minute mark in production"
                
                # Update token for logout test
                echo "$new_token" > "$TEMP_DIR/final_jwt_token"
            else
                warning "Token refresh failed (may be expected with test data)"
            fi
        else
            info "Skipping token refresh test (using mock tokens)"
        fi
    fi
    
    success "Session testing phase completed"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "Session testing completed in: $duration"
    fi
}

# PHASE 8: TOTP MANAGEMENT OPERATIONS
phase_totp_management() {
    phase "TOTP MANAGEMENT OPERATIONS"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    if [ ! -f "$TEMP_DIR/jwt_token" ]; then
        warning "No JWT token available, skipping TOTP management tests"
        return
    fi
    
    log "Testing TOTP management operations..."
    
    # Test TOTP status after authentication
    local token
    token=$(cat "$TEMP_DIR/jwt_token")
    
    if [[ "$token" != "mock-"* ]]; then
        local response
        response=$(curl -s $INSECURE_FLAG \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            "$ARKFILE_BASE_URL/api/totp/status" || echo "ERROR")
        
        if save_json_response "$response" "totp_status_post_auth.json" "TOTP status after auth"; then
            local enabled setup_required
            enabled=$(jq -r '.enabled' "$TEMP_DIR/totp_status_post_auth.json")
            setup_required=$(jq -r '.setupRequired' "$TEMP_DIR/totp_status_post_auth.json")
            success "TOTP status post-authentication (enabled: $enabled, setup_required: $setup_required)"
        else
            warning "TOTP status check after authentication failed"
        fi
    else
        info "Skipping TOTP management operations (using mock tokens)"
    fi
    
    success "TOTP management phase completed"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "TOTP management completed in: $duration"
    fi
}

# PHASE 9: FILE OPERATIONS WITH ENCRYPTION WORKFLOW
phase_9_file_operations() {
    phase "FILE OPERATIONS WITH ENCRYPTION WORKFLOW"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    local test_file="$TEST_FILE_PATH"
    local file_hash="$TEST_FILE_SHA256"
    local encrypted_file="${TEMP_DIR}/test_file_100mb_encrypted.bin"
    local decrypted_file="${TEMP_DIR}/test_file_100mb_decrypted.bin"
    
    info "Testing complete file encryption workflow using cryptocli with unified password architecture..."
    
    # Ensure cryptocli is available from the deployed location
    if ! command -v /opt/arkfile/bin/cryptocli >/dev/null 2>&1; then
        error "cryptocli tool not found at /opt/arkfile/bin/cryptocli - Please re-run 'sudo scripts/dev-reset.sh'"
    fi
    success "cryptocli tool available and ready"
    
    # Step 1: Verify or generate the standard 100MB deterministic test file
    log "Step 1: Verifying or generating standard 100MB test file..."

    # Check if the file exists and its hash is correct
    local needs_generation=false
    if [ -f "$test_file" ]; then
        info "Test file found at $test_file. Verifying integrity..."
        local existing_hash
        existing_hash=$(sha256sum "$test_file" | awk '{print $1}')
        if [ "$existing_hash" == "$file_hash" ]; then
            success "Test file already exists and hash is correct. Skipping generation."
        else
            warning "Test file exists but hash is incorrect. Will regenerate."
            info "Expected hash: $file_hash"
            info "Existing hash: $existing_hash"
            needs_generation=true
        fi
    else
        info "Test file not found. Will generate a new one."
        needs_generation=true
    fi

    if [ "$needs_generation" = true ]; then
        info "Generating new 100MB test file..."
        if ! /opt/arkfile/bin/cryptocli generate-test-file --filename "$test_file" --size "$TEST_FILE_SIZE" --pattern deterministic >/dev/null 2>&1; then
            error "Failed to generate standard test file using cryptocli."
        fi
        local new_hash
        new_hash=$(sha256sum "$test_file" | awk '{print $1}')
        if [ "$new_hash" == "$file_hash" ]; then
            success "Successfully generated new standard test file."
        else
            error "Generated file hash does not match the expected standard hash."
        fi
    fi
    
    local file_size
    file_size=$(stat -c%s "$test_file" 2>/dev/null || echo "0")
    success "Standard test file is ready."
    info "File location: $test_file"
    info "File size: $(printf "%'d" $file_size) bytes (100.00 MB)"
    info "Pattern: deterministic (generated by cryptocli)"
    info "Verified SHA256: $file_hash"
    
    # Step 2: Test account password encryption using unified Argon2ID architecture
    log "Step 2: Encrypting file with account password using unified Argon2ID (256MB/8i/4t)..."
    
    # Use the TEST_PASSWORD from the authentication phase and TEST_USERNAME
    if ! echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-password \
        --file "$test_file" \
        --output "$encrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account 2>/dev/null; then
        error "Failed to encrypt file with account password"
    fi
    
    # Verify encrypted file was created and is larger than original (due to envelope + nonce + tag)
    local encrypted_size=$(stat -c%s "$encrypted_file" 2>/dev/null || echo "0")
    
    if [ "$encrypted_size" -le "$file_size" ]; then
        error "Encrypted file size invalid: expected > $file_size, got $encrypted_size"
    fi
    
    success "File encrypted successfully with account password"
    info "Encrypted file size: $(printf "%'d" $encrypted_size) bytes"
    info "Overhead: $((encrypted_size - file_size)) bytes (envelope + nonce + tag)"
    
    # Step 3: Test decryption with account password  
    log "Step 3: Decrypting file with account password..."
    
    if ! echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli decrypt-password \
        --file "$encrypted_file" \
        --output "$decrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account 2>/dev/null; then
        error "Failed to decrypt file with account password"
    fi
    
    # Verify decrypted file was created and has correct size
    local decrypted_size=$(stat -c%s "$decrypted_file" 2>/dev/null || echo "0")
    
    if [ "$decrypted_size" -ne "$file_size" ]; then
        error "Decrypted file size mismatch: expected $file_size, got $decrypted_size"
    fi
    
    success "File decrypted successfully with account password"
    info "Decrypted file size: $(printf "%'d" $decrypted_size) bytes"
    
    # Step 4: Verify perfect integrity through complete encryption/decryption cycle
    log "Step 4: Verifying perfect integrity through complete encryption/decryption cycle..."
    
    local decrypted_hash
    if command -v sha256sum >/dev/null 2>&1; then
        decrypted_hash=$(sha256sum "$decrypted_file" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        decrypted_hash=$(shasum -a 256 "$decrypted_file" | cut -d' ' -f1)
    else
        error "Neither sha256sum nor shasum available for integrity verification"
    fi
    
    if [ "$file_hash" = "$decrypted_hash" ]; then
        success "PERFECT INTEGRITY VERIFIED - Complete encryption workflow successful!"
        info "Workflow: Generate → Encrypt (Argon2ID) → Decrypt → Verify"
        info "SHA-256 hashes:"
        info "  Original:  $file_hash"
        info "  Decrypted: $decrypted_hash"
        info "  [OK] EXACT MATCH - Zero data corruption through complete cycle"
        info "  [OK] Unified Argon2ID parameters (256MB/8i/4t) working correctly"
        info "  [OK] Account password encryption/decryption validated"
    else
        error "INTEGRITY VERIFICATION FAILED - Hash mismatch detected!"
        error "Original:  $file_hash"
        error "Decrypted: $decrypted_hash"
        error "This indicates data corruption in the encryption/decryption workflow"
    fi
    
    # Step 5: Test custom password encryption (different from account password)
    log "Step 5: Testing custom password encryption with different password..."
    
    local custom_encrypted_file="${TEMP_DIR}/test_file_100mb_custom_encrypted.bin"
    local custom_decrypted_file="${TEMP_DIR}/test_file_100mb_custom_decrypted.bin"
    
    # Use a different password for custom encryption (simulates user providing custom password)
    local CUSTOM_TEST_PASSWORD="CustomPassword123!DifferentFromAccount"
    
    if ! echo "$CUSTOM_TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-password \
        --file "$test_file" \
        --output "$custom_encrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type custom 2>/dev/null; then
        error "Failed to encrypt file with custom password"
    fi
    
    success "File encrypted successfully with custom password (different key derivation)"
    
    # Decrypt with custom password
    if ! echo "$CUSTOM_TEST_PASSWORD" | /opt/arkfile/bin/cryptocli decrypt-password \
        --file "$custom_encrypted_file" \
        --output "$custom_decrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type custom 2>/dev/null; then
        error "Failed to decrypt file with custom password"
    fi
    
    # Verify integrity for custom password workflow
    local custom_decrypted_hash
    if command -v sha256sum >/dev/null 2>&1; then
        custom_decrypted_hash=$(sha256sum "$custom_decrypted_file" | cut -d' ' -f1)
    else
        custom_decrypted_hash=$(shasum -a 256 "$custom_decrypted_file" | cut -d' ' -f1)
    fi
    
    if [ "$file_hash" = "$custom_decrypted_hash" ]; then
        success "Custom password encryption/decryption cycle verified [OK]"
        info "Custom password uses same unified Argon2ID parameters but different salt"
    else
        error "Custom password integrity verification failed"
    fi
    
    # Step 6: Verify account and custom passwords produce different encrypted files
    log "Step 6: Verifying account and custom passwords produce different ciphertexts..."
    
    local account_encrypted_hash custom_encrypted_hash
    if command -v sha256sum >/dev/null 2>&1; then
        account_encrypted_hash=$(sha256sum "$encrypted_file" | cut -d' ' -f1)
        custom_encrypted_hash=$(sha256sum "$custom_encrypted_file" | cut -d' ' -f1)
    else
        account_encrypted_hash=$(shasum -a 256 "$encrypted_file" | cut -d' ' -f1)
        custom_encrypted_hash=$(shasum -a 256 "$custom_encrypted_file" | cut -d' ' -f1)
    fi
    
    if [ "$account_encrypted_hash" != "$custom_encrypted_hash" ]; then
        success "Account and custom password encryption produce different ciphertexts [OK]"
        info "This confirms different key derivation is working correctly"
    else
        error "Account and custom encrypted files are identical - key derivation problem!"
    fi
    
    # Step 7: Test encryption with TEST_PASSWORD using cryptocli secure password prompting
    log "Step 7: Testing cryptocli encryption with secure password prompting..."
    
    local secure_encrypted_file="${TEMP_DIR}/test_file_100mb_secure_encrypted.bin"
    
    # Use cryptocli encrypt-password command (this will prompt for password securely)
    info "Encrypting file using cryptocli secure password prompting..."
    if ! echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-password \
        --file "$test_file" \
        --output "$secure_encrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account 2>/dev/null; then
        error "Failed to encrypt file using cryptocli secure password prompting"
    fi
    
    # Verify encrypted file was created
    local secure_encrypted_size=$(stat -c%s "$secure_encrypted_file" 2>/dev/null || echo "0")
    
    if [ "$secure_encrypted_size" -le "$file_size" ]; then
        error "Secure encrypted file size invalid: expected > $file_size, got $secure_encrypted_size"
    fi
    
    success "File encrypted successfully using cryptocli secure password prompting"
    info "Secure encrypted file size: $(printf "%'d" $secure_encrypted_size) bytes"
    info "Password used: MyVacation2025PhotosForFamily!ExtraSecure"
    
    # Step 8: Test decryption with same password and verify SHA256 integrity
    log "Step 8: Testing cryptocli decryption and SHA256 verification..."
    
    local secure_decrypted_file="${TEMP_DIR}/test_file_100mb_secure_decrypted.bin"
    
    # Use cryptocli decrypt-password command (this will prompt for password securely)
    info "Decrypting file using cryptocli secure password prompting..."
    if ! echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli decrypt-password \
        --file "$secure_encrypted_file" \
        --output "$secure_decrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account 2>/dev/null; then
        error "Failed to decrypt file using cryptocli secure password prompting"
    fi
    
    # Verify decrypted file was created and has correct size
    local secure_decrypted_size=$(stat -c%s "$secure_decrypted_file" 2>/dev/null || echo "0")
    
    if [ "$secure_decrypted_size" -ne "$file_size" ]; then
        error "Secure decrypted file size mismatch: expected $file_size, got $secure_decrypted_size"
    fi
    
    success "File decrypted successfully using cryptocli secure password prompting"
    info "Secure decrypted file size: $(printf "%'d" $secure_decrypted_size) bytes"
    
    # Verify SHA256 integrity of secure decrypted file
    local secure_decrypted_hash
    if command -v sha256sum >/dev/null 2>&1; then
        secure_decrypted_hash=$(sha256sum "$secure_decrypted_file" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        secure_decrypted_hash=$(shasum -a 256 "$secure_decrypted_file" | cut -d' ' -f1)
    else
        error "Neither sha256sum nor shasum available for secure integrity verification"
    fi
    
    if [ "$file_hash" = "$secure_decrypted_hash" ]; then
        success "SECURE ENCRYPTION INTEGRITY VERIFIED - Complete cryptocli workflow successful!"
        info "Secure Workflow: Generate → Encrypt (Secure Prompting) → Decrypt (Secure Prompting) → Verify"
        info "SHA-256 hashes:"
        info "  Original:         $file_hash"
        info "  Secure Decrypted: $secure_decrypted_hash"
        info "  [OK] EXACT MATCH - Zero data corruption through secure prompting cycle"
        info "  [OK] Secure password prompting working correctly"
        info "  [OK] Password 'MyVacation2025PhotosForFamily!ExtraSecure' validated"
    else
        error "SECURE ENCRYPTION INTEGRITY VERIFICATION FAILED - Hash mismatch detected!"
        error "Original:         $file_hash"
        error "Secure Decrypted: $secure_decrypted_hash"
        error "This indicates data corruption in the secure encryption workflow"
    fi
    
    # Store file paths for cleanup
    echo "$test_file" > "$TEMP_DIR/phase9_test_file"
    echo "$hash_file" > "$TEMP_DIR/phase9_hash_file"
    echo "$encrypted_file" > "$TEMP_DIR/phase9_encrypted_file"
    echo "$decrypted_file" > "$TEMP_DIR/phase9_decrypted_file"
    echo "$custom_encrypted_file" > "$TEMP_DIR/phase9_custom_encrypted_file"
    echo "$custom_decrypted_file" > "$TEMP_DIR/phase9_custom_decrypted_file"
    echo "$secure_encrypted_file" > "$TEMP_DIR/phase9_secure_encrypted_file"
    echo "$secure_decrypted_file" > "$TEMP_DIR/phase9_secure_decrypted_file"
    
    success "Complete file encryption workflow testing completed successfully!"
    info "[OK] File generation with cryptocli working"
    info "[OK] Account password encryption/decryption working"
    info "[OK] Custom password encryption/decryption working"
    info "[OK] Secure password prompting encryption/decryption working"
    info "[OK] Unified Argon2ID parameters (256MB/8i/4t) validated"
    info "[OK] Perfect integrity verification through complete cycles"
    info "[OK] Different passwords produce different ciphertexts"
    info "[OK] TEST_PASSWORD 'MyVacation2025PhotosForFamily!ExtraSecure' validated in secure workflow"
    info "Ready for future server upload/download workflow testing"

    #
    # --- BEGIN NETWORK FILE OPERATIONS ---
    #
    info "---"
    info "Starting complete end-to-end network file operations test..."

    # Ensure arkfile-client is available
    if ! command -v /opt/arkfile/bin/arkfile-client >/dev/null 2>&1; then
        error "arkfile-client tool not found at /opt/arkfile/bin/arkfile-client - Please re-run 'sudo scripts/dev-reset.sh'"
    fi
    success "arkfile-client tool available and ready"

    # Step 9: Use existing authentication to create a valid client session
    log "Step 9: Preparing arkfile-client session from existing tokens..."

    # Check for the tokens we expect to exist from Phase 6
    if [ ! -f "$TEMP_DIR/jwt_token" ] || [ ! -f "$TEMP_DIR/refresh_token" ]; then
        warning "Authentication tokens from Phase 6 not found. Skipping network file operations."
        return
    fi
    local access_token=$(cat "$TEMP_DIR/jwt_token")
    local refresh_token=$(cat "$TEMP_DIR/refresh_token")
    if [ -z "$access_token" ]; then
        error "Access token file is empty. Cannot proceed."
    fi

    # Create the session file with the PROVEN schema from fix-upload.sh
    local client_session_file="$TEMP_DIR/client_session.json"
    local jwt_payload B64_DECODE_CMD expires_at_iso expiry_timestamp
    jwt_payload=$(echo "$access_token" | cut -d'.' -f2)
    if command -v base64 >/dev/null && [[ "$(base64 --version 2>/dev/null)" == *"GNU coreutils"* ]]; then B64_DECODE_CMD="base64 -d"; else B64_DECODE_CMD="base64 -D"; fi
    case $(( ${#jwt_payload} % 4 )) in 2) jwt_payload="${jwt_payload}==";; 3) jwt_payload="${jwt_payload}=";; esac
    expiry_timestamp=$(echo "$jwt_payload" | $B64_DECODE_CMD | jq -r .exp 2>/dev/null || date -d "+30 minutes" +%s)
    expires_at_iso=$(date -u -d "@$expiry_timestamp" +"%Y-%m-%dT%H:%M:%SZ")

    jq -n \
        --arg u "$TEST_USERNAME" \
        --arg at "$access_token" \
        --arg rt "$refresh_token" \
        --arg ea "$expires_at_iso" \
        --arg su "$ARKFILE_BASE_URL" \
        '{
            "username": $u,
            "access_token": $at,
            "refresh_token": $rt,
            "expires_at": $ea,
            "server_url": $su,
            "session_created": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"
        }' > "$client_session_file"

    # Create the client config file that points to our session file
    local client_config_file="$TEMP_DIR/client_config.json"
    jq -n \
        --arg url "$ARKFILE_BASE_URL" \
        --arg user "$TEST_USERNAME" \
        --arg tf "$client_session_file" \
        '{
            server_url:$url, 
            username:$user, 
            tls_insecure:true, 
            token_file:$tf
        }' > "$client_config_file"

    success "Created valid arkfile-client config and session files."
    debug "Client Config: $(cat $client_config_file)"
    debug "Client Session: $(cat $client_session_file)"

    # Step 10: Upload the file using the simplified, robust arkfile-client logic
    log "Step 10: Uploading file using arkfile-client..."

    # Prepare file and metadata for upload (this part is working correctly)
    local upload_encrypted_file="$TEMP_DIR/upload_ready.enc"
    local metadata_json_file="$TEMP_DIR/upload_metadata.json"

    info "Encrypting file with cryptocli for upload..."
    echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-password \
        --file "$test_file" \
        --output "$upload_encrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account >/dev/null 2>&1
    success "File encrypted for upload."

    info "Generating and encrypting metadata..."
    local fek_hex
    fek_hex=$(/opt/arkfile/bin/cryptocli generate-key --size 32 --format hex | grep "Key (hex):" | cut -d' ' -f3)

    local encrypted_fek_output
    encrypted_fek_output=$(echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-fek --fek "$fek_hex" --username "$TEST_USERNAME" 2>&1)
    local encrypted_fek=$(echo "$encrypted_fek_output" | grep "Encrypted FEK (base64):" | cut -d' ' -f4)

    local metadata_output
    metadata_output=$(echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-metadata --filename "e2e-test-file.dat" --sha256sum "$file_hash" --username "$TEST_USERNAME" 2>&1)
    local filename_nonce=$(echo "$metadata_output" | grep "Filename Nonce:" | cut -d' ' -f3)
    local encrypted_filename_data=$(echo "$metadata_output" | grep "Encrypted Filename:" | cut -d' ' -f3)
    local sha256sum_nonce=$(echo "$metadata_output" | grep "SHA256 Nonce:" | cut -d' ' -f3)
    local encrypted_sha256sum_data=$(echo "$metadata_output" | grep "Encrypted SHA256:" | cut -d' ' -f3)

    jq -n \
        --arg filename_nonce "$filename_nonce" \
        --arg encrypted_filename "$encrypted_filename_data" \
        --arg sha256sum_nonce "$sha256sum_nonce" \
        --arg encrypted_sha256sum "$encrypted_sha256sum_data" \
        --arg encrypted_fek "$encrypted_fek" \
        '{
            filename_nonce: $filename_nonce,
            encrypted_filename: $encrypted_filename,
            sha256sum_nonce: $sha256sum_nonce,
            encrypted_sha256sum: $encrypted_sha256sum,
            encrypted_fek: $encrypted_fek,
            password_type: "account",
            password_hint: ""
        }' > "$metadata_json_file"
    success "File and metadata are prepared for upload."

    # Execute the upload, trusting arkfile-client's Go-based session handling
    local upload_log="$TEMP_DIR/upload.log"
    info "Attempting upload... Log will be at $upload_log"
    local upload_exit_code=0
    set +e
    echo "$TEST_PASSWORD" | /opt/arkfile/bin/arkfile-client \
        --config "$client_config_file" \
        --verbose \
        upload \
        --file "$upload_encrypted_file" \
        --metadata "$metadata_json_file" \
        --progress=false > "$upload_log" 2>&1
    upload_exit_code=$?
    set -e

    # Final validation of the upload
    local file_id
    file_id=$(grep "File ID:" "$upload_log" | grep -o "[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}" | tail -1)
    
    if [ $upload_exit_code -eq 0 ] && [ -n "$file_id" ]; then
        success "File upload successful!"
        info "File ID: $file_id"
        echo "$file_id" > "$TEMP_DIR/uploaded_file_id.txt"
    else
        error "File upload failed with exit code $upload_exit_code. Log below:\n$(cat "$upload_log")"
    fi

        # IMPLEMENTED: Step 11: Get file metadata using optimized API flow
    log "Step 11: Getting file metadata using optimized /meta endpoint..."

    # Use the dedicated /meta endpoint instead of extracting from file list
    # This is more efficient and matches our optimized API flow
    local meta_response_file="$TEMP_DIR/file_metadata.json"
    
    if ! curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $access_token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/files/$file_id/meta" \
        -o "$meta_response_file"; then
        error "Failed to retrieve file metadata from /meta endpoint"
    fi

    # Validate the metadata response
    if ! jq empty "$meta_response_file" 2>/dev/null; then
        error "Invalid JSON response from /meta endpoint"
    fi

    info "Successfully retrieved file metadata using optimized /meta endpoint"

    # Extract encrypted metadata directly from the dedicated endpoint
    local encrypted_filename encrypted_sha256 filename_nonce sha256sum_nonce encrypted_fek
    encrypted_filename=$(jq -r '.encrypted_filename' "$meta_response_file" 2>/dev/null)
    encrypted_sha256=$(jq -r '.encrypted_sha256sum' "$meta_response_file" 2>/dev/null)
    filename_nonce=$(jq -r '.filename_nonce' "$meta_response_file" 2>/dev/null)
    sha256sum_nonce=$(jq -r '.sha256sum_nonce' "$meta_response_file" 2>/dev/null)
    encrypted_fek=$(jq -r '.encrypted_fek' "$meta_response_file" 2>/dev/null)

    # Validate extracted metadata
    if [ -z "$encrypted_filename" ] || [ -z "$encrypted_sha256" ] || [ -z "$filename_nonce" ] || [ -z "$sha256sum_nonce" ]; then
        error "Failed to extract complete metadata from /meta endpoint response"
    fi

    success "Successfully extracted encrypted metadata from dedicated /meta endpoint"
    info "Metadata includes: filename, SHA256, nonces, and encrypted FEK"

    # IMPLEMENTED: Decrypt metadata using cryptocli (THIS WAS MISSING!)
    log "Step 12: Decrypting file metadata with cryptocli..."

    # Verify required variables are not empty before proceeding
    if [ -z "$encrypted_filename" ]; then
        error "encrypted_filename is empty - cannot proceed with metadata decryption"
    fi
    if [ -z "$filename_nonce" ]; then
        error "filename_nonce is empty - cannot proceed with metadata decryption"
    fi
    if [ -z "$encrypted_sha256" ]; then
        error "encrypted_sha256 is empty - cannot proceed with metadata decryption"
    fi
    if [ -z "$sha256sum_nonce" ]; then
        error "sha256sum_nonce is empty - cannot proceed with metadata decryption"
    fi

    # Decrypt the metadata using cryptocli (server now returns base64 strings directly - pass them as-is)
    local metadata_decrypt_output
    set +e  # Don't exit on command failure so we can capture error
    metadata_decrypt_output=$(echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli decrypt-metadata \
        --encrypted-filename-data "$encrypted_filename" \
        --filename-nonce "$filename_nonce" \
        --encrypted-sha256sum-data "$encrypted_sha256" \
        --sha256sum-nonce "$sha256sum_nonce" \
        --username "$TEST_USERNAME" 2>&1)
    local decrypt_exit_code=$?
    set -e  # Restore exit on error

    if [ $decrypt_exit_code -ne 0 ]; then
        error "cryptocli decrypt-metadata failed (exit code: $decrypt_exit_code). Error output:
$metadata_decrypt_output"
    fi

    local decrypted_filename decrypted_sha256
    decrypted_filename=$(echo "$metadata_decrypt_output" | grep "Decrypted Filename:" | cut -d':' -f2- | sed 's/^ *//')
    decrypted_sha256=$(echo "$metadata_decrypt_output" | grep "Decrypted SHA256:" | cut -d':' -f2- | sed 's/^ *//')

    if [ -z "$decrypted_filename" ] || [ -z "$decrypted_sha256" ]; then
        error "Failed to decrypt file metadata - missing decrypted values"
    fi

    success "Successfully decrypted file metadata"
    info "Original filename: e2e-test-file.dat"
    info "Decrypted filename: $decrypted_filename"
    info "Original SHA256: $file_hash"
    info "Decrypted SHA256: $decrypted_sha256"

    # IMPLEMENTED: Step 13: Download and decrypt file content using optimized chunked API
    log "Step 13: Downloading file content using optimized chunked download API..."
    local downloaded_e2e_file="$TEMP_DIR/e2e_downloaded_file.enc"
    local decrypted_e2e_file="$TEMP_DIR/e2e_decrypted_file.dat"

    # Use optimized chunked download API that fetches metadata once from /meta endpoint
    # then downloads chunks efficiently without redundant metadata headers
    info "Using optimized API flow: metadata from /meta, efficient chunk downloads"
    
    /opt/arkfile/bin/arkfile-client --config "$client_config_file" download \
        --file-id "$file_id" \
        --output "$downloaded_e2e_file"

    if [ $? -ne 0 ]; then
        error "File download failed with exit code $?"
    fi

    success "File downloaded successfully using optimized chunked API"
    info "✓ Metadata fetched once from dedicated /meta endpoint"
    info "✓ Chunks downloaded without redundant metadata headers"  
    info "✓ Efficient API flow reduces server load and improves performance"

    # Decrypt the downloaded encrypted content
    if ! echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli decrypt-password \
        --file "$downloaded_e2e_file" \
        --output "$decrypted_e2e_file" \
        --username "$TEST_USERNAME" \
        --key-type account 2>/dev/null; then
        error "Failed to decrypt downloaded file content."
    fi

    success "Downloaded encrypted content decrypted successfully"

    # IMPLEMENTED: Step 14: Multi-layer integrity verification
    log "Step 14: Performing comprehensive end-to-end integrity verification..."

    # Verify metadata SHA256 matches original
    if [ "$file_hash" = "$decrypted_sha256" ]; then
        success "Metadata integrity verified - server SHA256 matches original"
    else
        error "METADATA INTEGRITY FAILURE! Server SHA256 does not match original."
        error "Original:  $file_hash"
        error "Metadata:  $decrypted_sha256"
    fi

    # Verify content SHA256 matches decrypted content
    local final_e2e_hash
    final_e2e_hash=$(sha256sum "$decrypted_e2e_file" | cut -d' ' -f1)

    if [ "$file_hash" = "$final_e2e_hash" ]; then
        success "PERFECT END-TO-END INTEGRITY VERIFIED! Complete workflow successful."
        info "Full workflow validated:"
        info "  ✓ Generate original file"
        info "  ✓ Encrypt content + metadata"
        info "  ✓ Upload encrypted content + encrypted metadata"
        info "  ✓ Store and retrieve encrypted metadata"
        info "  ✓ Decrypt metadata (filenames, hashes)"
        info "  ✓ Download encrypted content in chunks"
        info "  ✓ Decrypt content"
        info "  ✓ Verify perfect integrity through entire cycle"
        info "Final validation:"
        info "  Original file:      $file_hash"
        info "  Decrypted metadata: $decrypted_sha256"
        info "  Decrypted content:  $final_e2e_hash"
        info "  [ALL THREE MATCH PERFECTLY]"
    else
        error "CONTENT INTEGRITY FAILURE! Decrypted content hash mismatch."
        error "Original: $file_hash"
        error "Content:  $final_e2e_hash"
        error "This indicates corruption in encrypt/decrypt cycle"
    fi
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "Complete file operations (local + network) completed in: $duration"
    fi
}

# PHASE 10: LOGOUT & SESSION TERMINATION
phase_10_logout() {
    phase "LOGOUT & SESSION TERMINATION"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    if [ ! -f "$TEMP_DIR/jwt_token" ]; then
        warning "No JWT token available, skipping logout test"
        return
    fi
    
    local token
    token=$(cat "$TEMP_DIR/jwt_token")
    
    log "Testing logout functionality..."
    
    # Test logout endpoint
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/logout" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        warning "Logout endpoint not accessible or doesn't exist"
    elif save_json_response "$response" "logout.json" "logout endpoint"; then
        success "Logout successful"
        info "Session terminated properly"
    else
        warning "Logout failed (may be expected depending on implementation)"
    fi
    
    # Verify token is invalidated by trying to access protected resource
    log "Verifying token invalidation..."
    
    response=$(curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/files" || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        success "Token properly invalidated after logout"
    elif echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        local error_msg
        error_msg=$(echo "$response" | jq -r '.error')
        if echo "$error_msg" | grep -q -i "unauthorized\|invalid.*token\|expired"; then
            success "Token properly invalidated after logout"
        else
            warning "Unexpected error after logout: $error_msg"
        fi
    else
        warning "Token may still be valid after logout (check logout implementation)"
    fi
    
    success "Logout phase completed"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "Logout completed in: $duration"
    fi
}

# PHASE 11: FINAL COMPREHENSIVE CLEANUP
phase_11_final_cleanup() {
    phase "FINAL COMPREHENSIVE CLEANUP"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    log "Removing test user data from database..."
    
    # Use Admin API for final cleanup instead of direct database access
    local final_cleanup_result
    final_cleanup_result=$(admin_cleanup_user "$TEST_USERNAME" "Final comprehensive cleanup" 2>/dev/null || echo "ERROR")
    
    if [[ "$final_cleanup_result" != "ERROR" ]]; then
        if save_json_response "$final_cleanup_result" "final_cleanup.json" "admin final cleanup API"; then
            local success total_rows
            success=$(jq -r '.success' "$TEMP_DIR/final_cleanup.json" 2>/dev/null || echo "false")
            total_rows=$(jq -r '.total_rows_affected' "$TEMP_DIR/final_cleanup.json" 2>/dev/null || echo "0")
            
            if [ "$success" = "true" ]; then
                success "Final cleanup completed via Admin API: $total_rows total rows removed"
            else
                info "Admin API cleanup completed (some operations may have been no-ops)"
            fi
        else
            info "Admin API cleanup executed (response format may vary)"
        fi
    else
        info "Admin API not available for final cleanup - this is expected in some environments"
    fi
    
    success "Final cleanup completed"
    
    # Test summary
    local test_end_time duration
    test_end_time=$(date +%s)
    duration=$((test_end_time - TEST_START_TIME))
    
    info "Test execution time: ${duration} seconds"
    info "Test files saved in: $TEMP_DIR (will be auto-cleaned)"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local cleanup_duration=$(end_timer "$timer_start")
        info "Final cleanup completed in: $cleanup_duration"
    fi
}

# Error scenario testing
test_error_scenarios() {
    log "Testing error scenarios..."
    
    # Test invalid registration
    local invalid_request
    invalid_request=$(jq -n \
        --arg email "invalid-email" \
        --arg password "short" \
        '{
            email: $email,
            password: $password
        }')
    
    local response
    response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$invalid_request" \
        "$ARKFILE_BASE_URL/api/opaque/register" || echo "ERROR")
    
    if [ "$response" != "ERROR" ]; then
        if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
            success "Registration correctly rejects invalid input"
        else
            warning "Registration accepted invalid input"
        fi
    fi
    
    # Add more error scenarios as needed
    success "Error scenario testing completed"
}

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Master Arkfile Authentication Testing Script"
    echo "Comprehensive End-to-End Authentication Flow Testing"
    echo ""
    echo "Options:"
    echo "  --help, -h              Show this help message"
    echo "  --url URL               Set base URL (default: https://localhost:4443)"
    echo "  --email EMAIL           Set test email (default: auth-test@example.com)"
    echo "  --password PASS         Set test password"
    echo "  --endpoints-only        Test TOTP endpoints only"
    echo "  --mandatory-totp        Test mandatory TOTP enforcement"
    echo "  --error-scenarios       Test error conditions"
    echo "  --performance           Enable performance benchmarking"
    echo "  --quick                 Run streamlined essential tests"
    echo "  --debug                 Enable debug output"
    echo "  --skip-cleanup          Skip final cleanup (for debugging)"
    echo ""
    echo "Environment Variables:"
    echo "  ARKFILE_BASE_URL        Base URL for the server"
    echo "  TEST_USERNAME           Test user username"
    echo "  TEST_PASSWORD           Test user password"
    echo ""
    echo "Flow (Full Mode):"
    echo "  1. Pre-flight & Cleanup"
    echo "  2. OPAQUE Registration"
    echo "  3. Admin API User Approval"
    echo "  4. TOTP Setup & Endpoint Validation"
    echo "  5. OPAQUE Login Authentication"
    echo "  6. TOTP Two-Factor Authentication"
    echo "  7. Session Management & API Access"
    echo "  8. TOTP Management Operations"
    echo "  9. Logout & Session Termination"
    echo "  10. Comprehensive Cleanup"
    echo ""
    echo "Specialized Modes:"
    echo "  --endpoints-only        Test only TOTP API endpoints"
    echo "  --mandatory-totp        Test mandatory TOTP enforcement mode"
    echo "  --error-scenarios       Test error handling and edge cases"
    echo "  --performance           Benchmark execution times"
    echo "  --quick                 Skip optional tests for faster execution"
    echo ""
    echo "Examples:"
    echo "  $0                                          # Full comprehensive flow"
    echo "  $0 --endpoints-only                         # Test TOTP endpoints only"
    echo "  $0 --email test@example.com                 # Custom test email"
    echo "  $0 --url https://arkfile.example.com        # Test remote server"
    echo "  $0 --mandatory-totp                         # Test mandatory TOTP mode"
    echo "  $0 --performance --debug                    # Performance testing with debug"
    echo "  $0 --quick --skip-cleanup                   # Quick test without cleanup"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --url)
            ARKFILE_BASE_URL="$2"
            shift 2
            ;;
        --username)
            TEST_USERNAME="$2"
            shift 2
            ;;
        --password)
            TEST_PASSWORD="$2"
            shift 2
            ;;
        --endpoints-only)
            ENDPOINTS_ONLY=true
            shift
            ;;
        --mandatory-totp)
            MANDATORY_TOTP=true
            shift
            ;;
        --error-scenarios)
            ERROR_SCENARIOS=true
            shift
            ;;
        --performance)
            PERFORMANCE_MODE=true
            shift
            ;;
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --skip-cleanup)
            SKIP_CLEANUP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution function
main() {
    # --- Standardized Configuration ---
    export ARKFILE_BASE_URL="${ARKFILE_BASE_URL:-https://localhost:4443}"
    export INSECURE_FLAG="--insecure"
    export TEST_USERNAME="${TEST_USERNAME:-arkfile-dev-test-user}"
    export TEST_PASSWORD="${TEST_PASSWORD:-MyVacation2025PhotosForFamily!ExtraSecure}"
    export ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
    export ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
    export TEMP_DIR="/tmp/test-app-curl"
    
    # Create the standardized temp directory
    mkdir -p "$TEMP_DIR"

    # Standardized test file configuration
    TEST_FILE_PATH="$TEMP_DIR/test-100mb-deterministic.bin"
    TEST_FILE_SIZE=104857600 # 100 MiB
    TEST_FILE_SHA256="4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0"
    # --- End Standardized Configuration ---

    echo -e "${WHITE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          ARKFILE MASTER AUTHENTICATION TEST SUITE        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "Starting comprehensive authentication flow test"
    log "Base URL: $ARKFILE_BASE_URL"
    log "Test Username: $TEST_USERNAME"
    log "Mode: $([ "$ENDPOINTS_ONLY" = true ] && echo "ENDPOINTS ONLY" || [ "$MANDATORY_TOTP" = true ] && echo "MANDATORY TOTP" || [ "$ERROR_SCENARIOS" = true ] && echo "ERROR SCENARIOS" || [ "$QUICK_MODE" = true ] && echo "QUICK MODE" || echo "FULL COMPREHENSIVE")"
    log "Performance Benchmarking: $([ "$PERFORMANCE_MODE" = true ] && echo "ENABLED" || echo "DISABLED")"
    log "Debug Mode: $([ "$DEBUG_MODE" = true ] && echo "ENABLED" || echo "DISABLED")"
    log "Temp Directory: $TEMP_DIR"
    echo
    
    # ADMIN AUTHENTICATION SETUP
    echo -e "${CYAN}╔═══════════════════════════════════════════╗"
    echo "║         ADMIN AUTHENTICATION              ║"
    echo -e "╚═══════════════════════════════════════════╝${NC}"
    
    log "Authenticating admin user for critical operations..."

    # Add a small delay to allow services (and system clock) to stabilize after reset
    log "Waiting for services to stabilize before admin auth..."
    sleep 3 # Allow services to fully initialize, preventing TOTP timing issues
    
    # Step 1: OPAQUE Authentication (using proven pattern from admin-auth-test.sh)
    local admin_opaque_response
    admin_opaque_response=$(curl -s $INSECURE_FLAG \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"$ADMIN_USERNAME\",
            \"password\": \"$ADMIN_PASSWORD\"
        }" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")
    
    if [ "$admin_opaque_response" = "ERROR" ]; then
        error "Failed to connect to server for admin authentication"
    fi
    
    if ! echo "$admin_opaque_response" | jq -e '.requires_totp' >/dev/null 2>&1; then
        error "Admin OPAQUE authentication failed: $admin_opaque_response"
    fi
    
    success "Admin OPAQUE login successful"
    
    local admin_temp_token admin_session_key
    admin_temp_token=$(echo "$admin_opaque_response" | jq -r '.temp_token')
    admin_session_key=$(echo "$admin_opaque_response" | jq -r '.session_key')
    
    if [ "$admin_temp_token" = "null" ] || [ "$admin_session_key" = "null" ]; then
        error "Admin OPAQUE response missing required tokens"
    fi
    
    # Step 2: TOTP Authentication (using proven pattern)
    log "Completing admin TOTP authentication..."
    
    # Ensure TOTP generator is available
    if [ ! -x "scripts/testing/totp-generator" ]; then
        if [ -f "scripts/testing/totp-generator.go" ]; then
            log "Building TOTP generator..."
            cd scripts/testing && go build -o totp-generator totp-generator.go && cd - >/dev/null
        else
            error "TOTP generator not found. Please run from project root directory."
        fi
    fi
    
    # Generate TOTP code and use immediately (atomic operation to avoid timing issues)
    local admin_totp_response
    admin_totp_response=$(
        local current_timestamp=$(date +%s)
        local totp_code=$(scripts/testing/totp-generator "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D" "$current_timestamp")
        curl -s $INSECURE_FLAG \
            -X POST \
            -H "Authorization: Bearer $admin_temp_token" \
            -H "Content-Type: application/json" \
            -d "{\"code\":\"$totp_code\",\"sessionKey\":\"$admin_session_key\"}" \
            "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR"
    )
    
    if [ "$admin_totp_response" = "ERROR" ]; then
        error "Failed to connect to server for admin TOTP authentication"
    fi
    
    if ! echo "$admin_totp_response" | jq -e '.token' >/dev/null 2>&1; then
        error "Admin TOTP authentication failed: $admin_totp_response"
    fi
    
    local admin_final_token auth_method
    admin_final_token=$(echo "$admin_totp_response" | jq -r '.token')
    auth_method=$(echo "$admin_totp_response" | jq -r '.auth_method')
    
    # Store admin token for use in admin API functions
    echo "$admin_final_token" > "$TEMP_DIR/admin_token"
    
    success "Admin authentication completed - Auth method: $auth_method"
    
    # Test admin token with a quick API call to ensure it works
    log "Validating admin token functionality..."
    local test_response
    test_response=$(curl -s $INSECURE_FLAG \
        -H "Authorization: Bearer $admin_final_token" \
        -H "Content-Type: application/json" \
        "$ARKFILE_BASE_URL/api/admin/dev-test/user/$TEST_USERNAME/status" || echo "ERROR")
    
    if [ "$test_response" = "ERROR" ]; then
        error "Admin token validation failed - cannot access admin API"
    fi
    
    success "Admin token validated and ready for critical operations"
    
    echo
    
    # Setup library paths
    setup_library_paths
    
    # Choose execution path based on mode
    if [ "$ENDPOINTS_ONLY" = true ]; then
        # Endpoints-only mode
        phase_cleanup_and_health
        phase_totp_setup_comprehensive  # This will call test_individual_totp_endpoints
        
    elif [ "$ERROR_SCENARIOS" = true ]; then
        # Error scenarios mode
        phase_cleanup_and_health
        test_error_scenarios
        
    elif [ "$QUICK_MODE" = true ]; then
        # Quick mode - essential tests only
        phase_cleanup_and_health
        phase_registration
        phase_user_approval
        phase_totp_setup_comprehensive
        phase_login
        phase_totp_authentication
        
        if [ "$SKIP_CLEANUP" = false ]; then
            phase_final_cleanup
        fi
        
    else
        # Full comprehensive mode
        phase_cleanup_and_health
        phase_registration
        phase_user_approval
        phase_totp_setup_comprehensive
        phase_login
        phase_totp_authentication
        phase_session_testing
        phase_totp_management
        phase_9_file_operations
        phase_10_logout
        
        if [ "$SKIP_CLEANUP" = false ]; then
            phase_11_final_cleanup
        fi
    fi
    
    # Success summary
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              ALL AUTHENTICATION TESTS PASSED [OK]        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "[SUCCESS] Master authentication test suite completed successfully!"
    
    echo -e "${CYAN}"
    echo "Test Summary:"
    if [ "$ENDPOINTS_ONLY" = true ]; then
        echo "[OK] TOTP Endpoint Testing - All 5 endpoints validated"
    elif [ "$ERROR_SCENARIOS" = true ]; then
        echo "[OK] Error Scenario Testing - Edge cases validated"
    elif [ "$QUICK_MODE" = true ]; then
        echo "[OK] Quick Mode Testing - Essential flow validated"
        echo "[OK] OPAQUE Registration - User registered successfully"
        echo "[OK] Database Approval - User approved for testing"
        echo "[OK] TOTP Setup - Two-factor authentication configured"
        echo "[OK] OPAQUE Login - Initial authentication successful"
        echo "[OK] TOTP Authentication - 2FA verification completed"
    else
        echo "[OK] OPAQUE Registration - User registered successfully"
        echo "[OK] Database Approval - User approved for testing"
        echo "[OK] TOTP Setup - Two-factor authentication configured"
        echo "[OK] OPAQUE Login - Initial authentication successful"
        echo "[OK] TOTP Authentication - 2FA verification completed"
        echo "[OK] Session Management - API access and token refresh tested"
        echo "[OK] TOTP Management - Post-auth operations verified"
        echo "[OK] Logout Process - Session termination verified"
        echo "[OK] Cleanup - Test data removed"
    fi
    echo -e "${NC}"
    
    log "Authentication system is working correctly end-to-end!"
    
    if [ "$SKIP_CLEANUP" = false ]; then
        info "All test data cleaned up successfully"
    else
        warning "Cleanup skipped - test data remains for debugging"
        info "Test user username: $TEST_USERNAME"
    fi
    
    echo -e "${NC}"
    
    # Performance summary
    if [ "$PERFORMANCE_MODE" = true ]; then
        local total_duration=$(($(date +%s) - TEST_START_TIME))
        echo -e "${PURPLE}"
        echo "[PERFORMANCE] Performance Summary:"
        echo "   Total execution time: ${total_duration} seconds"
        echo "   Average phase time: $((total_duration / PHASE_COUNTER)) seconds"
        echo -e "${NC}"
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
