#!/bin/bash

# Focused File Upload Debugging Script
#
# This script is a stripped-down version of test-app-curl.sh to isolate and
# debug file upload issues, specifically the 'complete' step.
#
# Flow:
# 1. Authenticate Admin
# 2. Clean up and register a test user
# 3. Authenticate the test user to get a valid JWT
# 4. Attempt to upload a file

set -euo pipefail

# --- Configuration ---
ARKFILE_BASE_URL="${ARKFILE_BASE_URL:-https://localhost:4443}"
INSECURE_FLAG="--insecure"
TEST_USERNAME="${TEST_USERNAME:-arkfile-dev-test-user}"
TEST_PASSWORD="${TEST_PASSWORD:-MyVacation2025PhotosForFamily!ExtraSecure}"
ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
TEMP_DIR=$(mktemp -d)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# --- Logging ---
log() { echo -e "[$(date +'%T')] ${CYAN}$1${NC}"; }
info() { echo -e "[$(date +'%T')] ${PURPLE}$1${NC}"; }
success() { echo -e "[$(date +'%T')] ${GREEN}$1${NC}"; }
error() { echo -e "[$(date +'%T')] ${RED}$1${NC}"; exit 1; }
debug_log() { if [[ "${DEBUG:-}" == "true" ]]; then echo -e "[$(date +'%T')] [DEBUG] $1"; fi }

# --- Cleanup ---
cleanup() {
    log "Cleaning up temporary directory: $TEMP_DIR"
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# --- Helper Functions (Copied from test-app-curl.sh) ---

# Helper to fix base32 padding for TOTP secrets
fix_totp_secret_padding() {
    local secret="$1"
    local secret_len=${#secret}
    local remainder=$((secret_len % 8))
    if [ $remainder -ne 0 ]; then
        local padding_needed=$((8 - remainder));
        for ((i=0; i<padding_needed; i++)); do secret="${secret}="; done;
    fi
    echo "$secret"
}

# Generate real TOTP code using production-compatible generator
generate_totp_code() {
    local secret="$1"; local timestamp="${2:-}";
    # Redirecting info logs to stderr to avoid polluting stdout for command substitution
    info "[TOTP Gen] Received secret: ${secret:0:4}...${secret: -4}, Timestamp: ${timestamp:-'current'}" >&2
    local padded_secret=$(fix_totp_secret_padding "$secret")
    info "[TOTP Gen] Padded secret: ${padded_secret:0:4}...${padded_secret: -4}" >&2
    if [ ! -x "scripts/testing/totp-generator" ]; then
        info "[TOTP Gen] Building totp-generator..." >&2
        (cd scripts/testing && go build -o totp-generator totp-generator.go) >/dev/null 2>&1
    fi
    local generated_code
    generated_code=$(scripts/testing/totp-generator "$padded_secret" "$timestamp")
    info "[TOTP Gen] Generated code (sent to stdout): $generated_code" >&2
    echo "$generated_code"
}

# --- Main Test Logic ---

# Step 1: Authenticate Admin User (copied from test-app-curl.sh)
authenticate_admin() {
    info "STEP 1: Authenticating admin user"
    sleep 3 # Allow services to stabilize
    local admin_opaque_response
    info "[Admin Auth] Sending OPAQUE login request..."
    admin_opaque_response=$(curl -s $INSECURE_FLAG -X POST -H "Content-Type: application/json" \
        -d "{\"username\": \"$ADMIN_USERNAME\", \"password\": \"$ADMIN_PASSWORD\"}" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")
    
    info "[Admin Auth] OPAQUE Response: $admin_opaque_response"
    if [[ "$admin_opaque_response" == "ERROR" ]] || ! echo "$admin_opaque_response" | jq -e '.requiresTOTP' >/dev/null; then error "Admin OPAQUE login failed"; fi
    
    local admin_temp_token=$(echo "$admin_opaque_response" | jq -r '.tempToken')
    local admin_session_key=$(echo "$admin_opaque_response" | jq -r '.sessionKey')
    info "[Admin Auth] Temp Token: $admin_temp_token"
    info "[Admin Auth] Session Key: $admin_session_key"

    local admin_totp_response
    local ts=$(date +%s)
    local code=$(generate_totp_code "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D")

    local totp_request_payload
    totp_request_payload=$(jq -n --arg code "$code" --arg sessionKey "$admin_session_key" '{"code":$code,"sessionKey":$sessionKey,"isBackup":false}')
    info "[Admin Auth] Sending TOTP auth request with payload: $totp_request_payload"

    admin_totp_response=$(
        curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $admin_temp_token" -H "Content-Type: application/json" \
            -d "$totp_request_payload" "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR"
    )
    
    info "[Admin Auth] TOTP Response: $admin_totp_response"
    if [[ "$admin_totp_response" == "ERROR" ]] || ! echo "$admin_totp_response" | jq -e '.token' >/dev/null; then error "Admin TOTP auth failed"; fi
    
    echo "$admin_totp_response" | jq -r '.token' > "$TEMP_DIR/admin_token.txt"
    success "Admin authenticated."
}

# Step 2: Full user setup and authentication chain (copied from test-app-curl.sh)
setup_and_authenticate_user() {
    info "STEP 2: Setting up and authenticating test user"
    local admin_token=$(cat "$TEMP_DIR/admin_token.txt")

    # Cleanup
    info "[Sub-step] Cleaning up user..."
    curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" -d "{\"username\":\"$TEST_USERNAME\",\"confirm\":true}" "$ARKFILE_BASE_URL/api/admin/dev-test/user/cleanup" > /dev/null

    # Registration
    info "[Sub-step] Registering user..."
    local reg_req=$(jq -n --arg u "$TEST_USERNAME" --arg p "$TEST_PASSWORD" '{username:$u, password:$p}')
    local reg_resp=$(curl -s $INSECURE_FLAG -X POST -H "Content-Type: application/json" -d "$reg_req" "$ARKFILE_BASE_URL/api/opaque/register")
    if ! echo "$reg_resp" | jq -e '.requiresTOTPSetup' >/dev/null; then error "Registration failed: $reg_resp"; fi
    local reg_temp_token=$(echo "$reg_resp" | jq -r '.tempToken')
    local reg_session_key=$(echo "$reg_resp" | jq -r '.sessionKey')

    # Approval
    info "[Sub-step] Approving user..."
    local approve_req=$(jq -n --arg approved_by "$ADMIN_USERNAME" '{approved_by:$approved_by}')
    curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" -d "$approve_req" "$ARKFILE_BASE_URL/api/admin/user/$TEST_USERNAME/approve" > /dev/null

    # TOTP Setup & Verify
    info "[Sub-step] Setting up and verifying TOTP..."
    local setup_req=$(jq -n --arg sessionKey "$reg_session_key" '{sessionKey:$sessionKey}')
    local setup_resp=$(curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$setup_req" "$ARKFILE_BASE_URL/api/totp/setup")
    local secret=$(echo "$setup_resp" | jq -r '.secret')
    if [[ "$secret" == "null" ]]; then error "TOTP setup failed: $setup_resp"; fi

    local verify_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg sessionKey "$reg_session_key" '{code:$code, sessionKey:$sessionKey}')
    local verify_resp=$(curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$verify_req" "$ARKFILE_BASE_URL/api/totp/verify")
    if ! echo "$verify_resp" | jq -e '.enabled' >/dev/null; then error "TOTP verification failed: $verify_resp"; fi

    # Login for 2FA
    info "[Sub-step] Logging in for 2FA..."
    local login_req=$(jq -n --arg u "$TEST_USERNAME" --arg p "$TEST_PASSWORD" '{username:$u, password:$p}')
    local login_resp=$(curl -s $INSECURE_FLAG -X POST -H "Content-Type: application/json" -d "$login_req" "$ARKFILE_BASE_URL/api/opaque/login")
    local login_temp_token=$(echo "$login_resp" | jq -r '.tempToken')
    local login_session_key=$(echo "$login_resp" | jq -r '.sessionKey')

    # Final TOTP Auth
    info "[Sub-step] Finalizing 2FA..."
    local auth_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg sessionKey "$login_session_key" '{code:$code, sessionKey:$sessionKey, isBackup:false}')
    local auth_resp=$(curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $login_temp_token" -H "Content-Type: application/json" -d "$auth_req" "$ARKFILE_BASE_URL/api/totp/auth")
    local final_token=$(echo "$auth_resp" | jq -r '.token')
    if [[ "$final_token" == "null" ]]; then error "Final user auth failed: $auth_resp"; fi

    # Create client config
    info "[Sub-step] Creating client config..."
    local client_session_file="$TEMP_DIR/client_auth_session.json"
    local jwt_payload=$(echo "$final_token" | cut -d'.' -f2 | sed 's/-/+/g; s/_/\//g'); case $(( ${#jwt_payload} % 4 )) in 2) jwt_payload="${jwt_payload}==";; 3) jwt_payload="${jwt_payload}=";; esac
    local expiry_timestamp=$(echo "$jwt_payload" | base64 -d | jq .exp)
    local expires_at_iso=$(date -u -d "@$expiry_timestamp" +"%Y-%m-%dT%H:%M:%SZ")

    jq -n --arg u "$TEST_USERNAME" --arg at "$final_token" --arg rt "$(echo $auth_resp | jq -r .refreshToken)" --arg ea "$expires_at_iso" --arg su "$ARKFILE_BASE_URL" \
        '{username:$u, access_token:$at, refresh_token:$rt, expires_at:$ea, server_url:$su, session_created:"'$(date -u -d@$(date +%s) --iso-8601=seconds)'"}' > "$client_session_file"
    
    local client_config_file="$TEMP_DIR/client_config.json"
    jq -n --arg url "$ARKFILE_BASE_URL" --arg user "$TEST_USERNAME" --arg tf "$client_session_file" '{server_url:$url, username:$user, tls_insecure:true, token_file:$tf}' > "$client_config_file"
    echo "$client_config_file" > "$TEMP_DIR/client_config_path.txt"
    success "Full user authentication complete."
}

# Run the Upload Test
run_upload_test() {
    log "Starting file upload test..."
    local client_config_file=$(cat "$TEMP_DIR/client_config_path.txt")

    # Generate a large test file
    local test_file="${TEMP_DIR}/upload_test.dat"
    # 100MB = 100 * 1024 * 1024 = 104857600 bytes
    /opt/arkfile/bin/cryptocli generate-test-file --filename "$test_file" --size 104857600 >/dev/null
    info "Generated 100MB test file: $test_file"

    # Run upload command
    local upload_log="$TEMP_DIR/upload.log"
    info "Attempting upload... Log will be at $upload_log"
    
    echo "$TEST_PASSWORD" | /opt/arkfile/bin/arkfile-client \
        --config "$client_config_file" \
        --verbose \
        upload \
        --file "$test_file" \
        --name "debug-upload.dat" \
        --progress=false 2>&1 | tee "$upload_log"
    
    # Check the exit code of the arkfile-client command
    local exit_code=$?
    if [ $exit_code -eq 0 ] && grep -q "File uploaded successfully" "$upload_log"; then
        success "🎉 File upload appears to be successful!"
        cat "$upload_log"
    else
        error "File upload failed with exit code $exit_code. See log below:\n$(cat "$upload_log")"
    fi
}


# --- Main Execution ---
main() {
    log "Starting focused upload debug script..."
    authenticate_admin
    setup_and_authenticate_user
    run_upload_test
    log "Debug script finished."
}

main
