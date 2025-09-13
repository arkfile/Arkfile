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

# Step 1: Authenticate Admin User (Fixed version)
authenticate_admin() {
    info "STEP 1: Authenticating admin user"
    sleep 3 # Allow services to stabilize

    # OPAQUE Authentication
    info "[Admin Auth] Sending OPAQUE login request..."
    local admin_opaque_response
    admin_opaque_response=$(curl -s $INSECURE_FLAG -X POST -H "Content-Type: application/json" \
        -d "{\"username\": \"$ADMIN_USERNAME\", \"password\": \"$ADMIN_PASSWORD\"}" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")

    info "[Admin Auth] OPAQUE Response: $admin_opaque_response"
    if [[ "$admin_opaque_response" == "ERROR" ]] || ! echo "$admin_opaque_response" | jq -e '.requires_totp' >/dev/null; then error "Admin OPAQUE login failed: $admin_opaque_response"; fi

    local admin_temp_token=$(echo "$admin_opaque_response" | jq -r '.temp_token')
    local admin_session_key=$(echo "$admin_opaque_response" | jq -r '.session_key')
    info "[Admin Auth] Temp Token: $admin_temp_token"
    info "[Admin Auth] Session Key: $admin_session_key"

    # TOTP Authentication (FIX: No subshell variable scoping issues)
    info "[Admin Auth] Performing TOTP authentication..."
    # Get current timestamp and generate fresh TOTP code
    local ts=$(date +%s)
    local code=$(generate_totp_code "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D" "$ts")

    local totp_request_payload
    totp_request_payload=$(jq -n --arg code "$code" --arg sessionKey "$admin_session_key" '{"code":$code,"session_key":$sessionKey,"is_backup":false}')
    info "[Admin Auth] Sending TOTP auth request with code: $code (timestamp: $ts)"

    local admin_totp_response
    admin_totp_response=$(curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $admin_temp_token" -H "Content-Type: application/json" \
        -d "$totp_request_payload" "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")

    info "[Admin Auth] TOTP Response: $admin_totp_response"
    if [[ "$admin_totp_response" == "ERROR" ]] || ! echo "$admin_totp_response" | jq -e '.token' >/dev/null; then error "Admin TOTP auth failed: $admin_totp_response"; fi

    # Extract and save token (FIX: This now works because admin_totp_response is in function scope)
    local admin_token=$(echo "$admin_totp_response" | jq -r '.token')
    echo "$admin_token" > "$TEMP_DIR/admin_token.txt"
    success "Admin authenticated successfully."
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
    if ! echo "$reg_resp" | jq -e '.requires_totp_setup' >/dev/null; then error "Registration failed: $reg_resp"; fi
    local reg_temp_token=$(echo "$reg_resp" | jq -r '.temp_token')
    local reg_session_key=$(echo "$reg_resp" | jq -r '.session_key')

    # Approval
    info "[Sub-step] Approving user..."
    local approve_req=$(jq -n --arg approved_by "$ADMIN_USERNAME" '{approved_by:$approved_by}')
    curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" -d "$approve_req" "$ARKFILE_BASE_URL/api/admin/user/$TEST_USERNAME/approve" > /dev/null

    # TOTP Setup & Verify
    info "[Sub-step] Setting up and verifying TOTP..."
    local setup_req=$(jq -n --arg sessionKey "$reg_session_key" '{session_key:$sessionKey}')
    local setup_resp=$(curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$setup_req" "$ARKFILE_BASE_URL/api/totp/setup")
    local secret=$(echo "$setup_resp" | jq -r '.secret')
    if [[ "$secret" == "null" ]]; then error "TOTP setup failed: $setup_resp"; fi

    local verify_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg sessionKey "$reg_session_key" '{code:$code, session_key:$sessionKey}')
    local verify_resp=$(curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$verify_req" "$ARKFILE_BASE_URL/api/totp/verify")
    if ! echo "$verify_resp" | jq -e '.enabled' >/dev/null; then error "TOTP verification failed: $verify_resp"; fi

    # Login for 2FA
    info "[Sub-step] Logging in for 2FA..."
    local login_req=$(jq -n --arg u "$TEST_USERNAME" --arg p "$TEST_PASSWORD" '{username:$u, password:$p}')
    local login_resp=$(curl -s $INSECURE_FLAG -X POST -H "Content-Type: application/json" -d "$login_req" "$ARKFILE_BASE_URL/api/opaque/login")
    local login_temp_token=$(echo "$login_resp" | jq -r '.temp_token')
    local login_session_key=$(echo "$login_resp" | jq -r '.session_key')

    # Final TOTP Auth
    info "[Sub-step] Finalizing 2FA..."
    local auth_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg session_key "$login_session_key" '{code:$code, session_key:$session_key, is_backup:false}')
    local auth_resp=$(curl -s $INSECURE_FLAG -X POST -H "Authorization: Bearer $login_temp_token" -H "Content-Type: application/json" -d "$auth_req" "$ARKFILE_BASE_URL/api/totp/auth")
    local final_token=$(echo "$auth_resp" | jq -r '.token')
    if [[ "$final_token" == "null" ]]; then error "Final user auth failed: $auth_resp"; fi

    # Create client config
    info "[Sub-step] Creating client config..."
    local client_session_file="$TEMP_DIR/client_auth_session.json"
    local jwt_payload=$(echo "$final_token" | cut -d'.' -f2 | sed 's/-/+/g; s/_/\//g'); case $(( ${#jwt_payload} % 4 )) in 2) jwt_payload="${jwt_payload}==";; 3) jwt_payload="${jwt_payload}=";; esac
    local expiry_timestamp=$(echo "$jwt_payload" | base64 -d | jq .exp)
    local expires_at_iso=$(date -u -d "@$expiry_timestamp" +"%Y-%m-%dT%H:%M:%SZ")

    jq -n --arg u "$TEST_USERNAME" --arg at "$final_token" --arg rt "$(echo $auth_resp | jq -r .refresh_token)" --arg ea "$expires_at_iso" --arg su "$ARKFILE_BASE_URL" \
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

    # Generate a test file (smaller size to account for encryption overhead)
    local test_file="${TEMP_DIR}/upload_test.dat"
    # Generate smaller file (95MB) to account for ~30 bytes envelope overhead
    # 95MB = 95 * 1024 * 1024 = 99614720 bytes
    local target_size=$((95 * 1024 * 1024))  # 95MB in bytes

    info "Generating test file with size: $(printf "%'d" $target_size) bytes (95MB)"
    /opt/arkfile/bin/cryptocli generate-test-file --filename "$test_file" --size "$target_size" >/dev/null

    # Verify file was created
    local actual_size=$(stat -c%s "$test_file" 2>/dev/null || echo "0")
    if [ "$actual_size" -ne "$target_size" ]; then
        error "File size mismatch: expected $target_size, got $actual_size bytes"
    fi

    info "Generated test file: $test_file ($(printf "%'d" $actual_size) bytes)"

    # Encrypt the file for upload (this creates the pre-encrypted file arkfile-client expects)
    info "Encrypting test file for arkfile-client upload..."
    local encrypted_file="$TEMP_DIR/upload_test.enc"
    echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-password \
        --file "$test_file" \
        --output "$encrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account >/dev/null 2>&1

    if [ ! -f "$encrypted_file" ]; then
        error "File encryption failed - could not create $encrypted_file"
    fi

    info "File encrypted for upload: $encrypted_file"

    # Calculate SHA256 hash of the original file for metadata
    info "Calculating SHA256 hash..."
    local file_hash
    file_hash=$(sha256sum "$test_file" | cut -d' ' -f1)
    info "File hash: $file_hash"

    # Generate and encrypt FEK (File Encryption Key)
    info "Generating and encrypting File Encryption Key (FEK)..."
    local fek_hex encrypted_fek_output encrypted_fek
    fek_hex=$(/opt/arkfile/bin/cryptocli generate-key --size 32 --format hex | grep "Key (hex):" | cut -d' ' -f3)
    info "Generated FEK: ${fek_hex:0:20}..."

    encrypted_fek_output=$(echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-fek \
        --fek "$fek_hex" \
        --username "$TEST_USERNAME" 2>&1)

    encrypted_fek=$(echo "$encrypted_fek_output" | grep "Encrypted FEK (base64):" | cut -d' ' -f4)
    info "Encrypted FEK: ${encrypted_fek:0:20}..."

    # Generate encrypted metadata for the upload
    info "Generating encrypted metadata..."
    local metadata_output
    metadata_output=$(echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli encrypt-metadata \
        --filename "debug-upload.dat" \
        --sha256sum "$file_hash" \
        --username "$TEST_USERNAME")

    # Parse metadata from cryptocli output
    local filename_nonce encrypted_filename sha256sum_nonce encrypted_sha256sum

    filename_nonce=$(echo "$metadata_output" | grep "Filename Nonce:" | cut -d' ' -f3)
    encrypted_filename=$(echo "$metadata_output" | grep "Encrypted Filename:" | cut -d' ' -f3)
    sha256sum_nonce=$(echo "$metadata_output" | grep "SHA256 Nonce:" | cut -d' ' -f3)
    encrypted_sha256sum=$(echo "$metadata_output" | grep "Encrypted SHA256:" | cut -d' ' -f3)

    # Validate parsing succeeded
    if [[ -z "$encrypted_filename" ]]; then
        info "DEBUG: Raw cryptocli output:"
        info "$metadata_output"
        error "Failed to parse encrypted metadata from cryptocli output."
    fi

    # Create the metadata JSON file required by arkfile-client
    local metadata_file="$TEMP_DIR/upload_metadata.json"
    jq -n \
        --arg filename_nonce "$filename_nonce" \
        --arg encrypted_filename "$encrypted_filename" \
        --arg sha256sum_nonce "$sha256sum_nonce" \
        --arg encrypted_sha256sum "$encrypted_sha256sum" \
        --arg encrypted_fek "$encrypted_fek" \
        '{
            filename_nonce: $filename_nonce,
            encrypted_filename: $encrypted_filename,
            sha256sum_nonce: $sha256sum_nonce,
            encrypted_sha256sum: $encrypted_sha256sum,
            encrypted_fek: $encrypted_fek,
            password_type: "account",
            password_hint: ""
        }' > "$metadata_file"

    success "Metadata JSON file created: $metadata_file"

    # Check JSON metadata file format first
    info "DEBUG: Checking metadata JSON format..."
    if [ -f "$metadata_file" ]; then
        info "DEBUG: Metadata JSON content:"
        info "$(cat "$metadata_file")"

        # Validate that all required fields are present and not null
        local validation_errors=""
        for field in filename_nonce encrypted_filename sha256sum_nonce encrypted_sha256sum encrypted_fek; do
            local value=$(jq -r ".$field" "$metadata_file" 2>/dev/null || echo "null")
            info "DEBUG: $field = '$value'"
            if [[ "$value" == "null" || -z "$value" ]]; then
                validation_errors="${validation_errors}$field is null/empty; "
            fi
        done
        if [[ -n "$validation_errors" ]]; then
            error "Metadata validation failed: $validation_errors"
        fi
    else
        error "Metadata JSON file was not created"
    fi
    info "Metadata validation passed"

    # Run upload command with proper flags including password type
    local upload_log="$TEMP_DIR/upload.log"
    info "Attempting upload... Log will be at $upload_log"

    echo "$TEST_PASSWORD" | /opt/arkfile/bin/arkfile-client \
        --config "$client_config_file" \
        --verbose \
        upload \
        --file "$encrypted_file" \
        --metadata "$metadata_file" \
        --progress=false 2>&1 | tee "$upload_log"

    # Check the exit code of the arkfile-client command
    local exit_code=$?
    if [ $exit_code -eq 0 ] && grep -q "File uploaded successfully" "$upload_log"; then
        success "File upload appears to be successful!"
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
