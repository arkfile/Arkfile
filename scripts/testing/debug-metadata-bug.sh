#!/bin/bash

# Debug Script for Metadata Double-Encoding Bug
# Isolates Steps 11 (list files) and 12 (decrypt metadata) for debugging
#
# Usage: ./debug-metadata-bug.sh [file-id]

set -eu

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration - Use deployed tools
ARKFILE_BASE_URL="${ARKFILE_BASE_URL:-https://localhost:4443}"
TEST_USERNAME="${TEST_USERNAME:-arkfile-dev-test-user}"
TEST_PASSWORD="${TEST_PASSWORD:-MyVacation2025PhotosForFamily!ExtraSecure}"
TEMP_DIR="/tmp/debug-metadata"
DEPLOYED_ARKFILE_CLIENT="/opt/arkfile/bin/arkfile-client"
DEPLOYED_CRYPTOCLI="/opt/arkfile/bin/cryptocli"

# Parse arguments
TARGET_FILE_ID=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Usage: $0 [file-id]"
            echo ""
            echo "Debug script for testing metadata double-encoding bug."
            echo "If no file-id provided, will try to find from /tmp/test-app-curl/uploaded_file_id.txt"
            echo ""
            echo "Environment Variables:"
            echo "  ARKFILE_BASE_URL     Base URL (default: https://localhost:4443)"
            echo "  TEST_USERNAME        Username for authentication"
            echo "  TEST_PASSWORD        Password for authentication"
            exit 0
            ;;
        *)
            if [ -z "$TARGET_FILE_ID" ]; then
                TARGET_FILE_ID="$1"
            else
                echo -e "${RED}[ERROR] Too many arguments. Expected at most one file-id.${NC}"
                exit 1
            fi
            ;;
    esac
    shift
done

# Ensure tools exist
if ! [ -x "$DEPLOYED_ARKFILE_CLIENT" ]; then
    echo -e "${RED}[ERROR] arkfile-client not found at $DEPLOYED_ARKFILE_CLIENT${NC}"
    echo -e "${YELLOW}[INFO] Make sure arkfile is properly deployed to /opt/arkfile${NC}"
    exit 1
fi

if ! [ -x "$DEPLOYED_CRYPTOCLI" ]; then
    echo -e "${RED}[ERROR] cryptocli not found at $DEPLOYED_CRYPTOCLI${NC}"
    echo -e "${YELLOW}[INFO] Make sure arkfile is properly deployed to /opt/arkfile${NC}"
    exit 1
fi

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
    echo -e "${CYAN}[TOTP Gen] Received secret: ${secret:0:4}...${secret: -4}, Timestamp: ${timestamp:-'current'}${NC}" >&2
    local padded_secret=$(fix_totp_secret_padding "$secret")
    echo -e "${CYAN}[TOTP Gen] Padded secret: ${padded_secret:0:4}...${padded_secret: -4}${NC}" >&2
    if [ ! -x "scripts/testing/totp-generator" ]; then
        echo -e "${CYAN}[TOTP Gen] Building totp-generator...${NC}" >&2
        (cd scripts/testing && go build -o totp-generator totp-generator.go) >/dev/null 2>&1
    fi
    local generated_code
    generated_code=$(scripts/testing/totp-generator "$padded_secret" "$timestamp")
    echo -e "${YELLOW}[TOTP Gen] Generated code: $generated_code${NC}" >&2
    echo "$generated_code"
}

# Authenticate admin user
authenticate_admin() {
    echo -e "${CYAN}[STEP 1] Authenticating admin user${NC}"

    # OPAQUE Authentication
    echo -e "${CYAN}[Admin Auth] Sending OPAQUE login request...${NC}"
    local admin_opaque_response
    admin_opaque_response=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
        -d "{\"username\": \"arkfile-dev-admin\", \"password\": \"DevAdmin2025!SecureInitialPassword\"}" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")

    echo -e "${YELLOW}[Admin Auth] OPAQUE Response: $admin_opaque_response${NC}"
    if [[ "$admin_opaque_response" == "ERROR" ]] || ! echo "$admin_opaque_response" | jq -e '.requires_totp' >/dev/null; then
        echo -e "${RED}[ERROR] Admin OPAQUE login failed: $admin_opaque_response${NC}"
        exit 1
    fi

    local admin_temp_token=$(echo "$admin_opaque_response" | jq -r '.temp_token')
    local admin_session_key=$(echo "$admin_opaque_response" | jq -r '.session_key')
    echo -e "${YELLOW}[Admin Auth] Temp Token: $admin_temp_token${NC}"
    echo -e "${YELLOW}[Admin Auth] Session Key: $admin_session_key${NC}"

    # TOTP Authentication
    echo -e "${CYAN}[Admin Auth] Performing TOTP authentication...${NC}"
    # Get current timestamp and generate fresh TOTP code
    local ts=$(date +%s)
    local code=$(generate_totp_code "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D" "$ts")

    local totp_request_payload
    totp_request_payload=$(jq -n --arg code "$code" --arg sessionKey "$admin_session_key" '{"code":$code,"session_key":$sessionKey,"is_backup":false}')
    echo -e "${CYAN}[Admin Auth] Sending TOTP auth request with code: $code (timestamp: $ts)${NC}"

    local admin_totp_response
    admin_totp_response=$(curl -s --insecure -X POST -H "Authorization: Bearer $admin_temp_token" -H "Content-Type: application/json" \
        -d "$totp_request_payload" "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")

    echo -e "${YELLOW}[Admin Auth] TOTP Response: $admin_totp_response${NC}"
    if [[ "$admin_totp_response" == "ERROR" ]] || ! echo "$admin_totp_response" | jq -e '.token' >/dev/null; then
        echo -e "${RED}[ERROR] Admin TOTP auth failed: $admin_totp_response${NC}"
        exit 1
    fi

    local admin_token=$(echo "$admin_totp_response" | jq -r '.token')
    echo "$admin_token" > "$TEMP_DIR/admin_token.txt"
    echo -e "${GREEN}[OK] Admin authenticated successfully.${NC}"
}

# Full user setup and authentication chain
setup_and_authenticate_user() {
    echo -e "${CYAN}[STEP 2] Setting up and authenticating test user${NC}"
    local admin_token=$(cat "$TEMP_DIR/admin_token.txt")

    # Cleanup
    echo -e "${CYAN}[User Setup] Cleaning up user...${NC}"
    curl -s --insecure -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" -d "{\"username\":\"$TEST_USERNAME\",\"confirm\":true}" "$ARKFILE_BASE_URL/api/admin/dev-test/user/cleanup" > /dev/null

    # Registration
    echo -e "${CYAN}[User Setup] Registering user...${NC}"
    local reg_req=$(jq -n --arg u "$TEST_USERNAME" --arg p "$TEST_PASSWORD" '{username:$u, password:$p}')
    local reg_resp=$(curl -s --insecure -X POST -H "Content-Type: application/json" -d "$reg_req" "$ARKFILE_BASE_URL/api/opaque/register")
    if ! echo "$reg_resp" | jq -e '.requires_totp_setup' >/dev/null; then
        echo -e "${RED}[ERROR] Registration failed: $reg_resp${NC}"
        exit 1
    fi
    local reg_temp_token=$(echo "$reg_resp" | jq -r '.temp_token')
    local reg_session_key=$(echo "$reg_resp" | jq -r '.session_key')

    # Approval
    echo -e "${CYAN}[User Setup] Approving user...${NC}"
    local approve_req=$(jq -n --arg approved_by "arkfile-dev-admin" '{approved_by:$approved_by}')
    curl -s --insecure -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" -d "$approve_req" "$ARKFILE_BASE_URL/api/admin/user/$TEST_USERNAME/approve" > /dev/null

    # TOTP Setup & Verify
    echo -e "${CYAN}[User Setup] Setting up and verifying TOTP...${NC}"
    local setup_req=$(jq -n --arg sessionKey "$reg_session_key" '{session_key:$sessionKey}')
    local setup_resp=$(curl -s --insecure -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$setup_req" "$ARKFILE_BASE_URL/api/totp/setup")
    local secret=$(echo "$setup_resp" | jq -r '.secret')
    if [[ "$secret" == "null" ]]; then
        echo -e "${RED}[ERROR] TOTP setup failed: $setup_resp${NC}"
        exit 1
    fi

    local verify_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg sessionKey "$reg_session_key" '{code:$code, session_key:$sessionKey}')
    local verify_resp=$(curl -s --insecure -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$verify_req" "$ARKFILE_BASE_URL/api/totp/verify")
    if ! echo "$verify_resp" | jq -e '.enabled' >/dev/null; then
        echo -e "${RED}[ERROR] TOTP verification failed: $verify_resp${NC}"
        exit 1
    fi

    # Login for 2FA
    echo -e "${CYAN}[User Setup] Logging in for 2FA...${NC}"
    local login_req=$(jq -n --arg u "$TEST_USERNAME" --arg p "$TEST_PASSWORD" '{username:$u, password:$p}')
    local login_resp=$(curl -s --insecure -X POST -H "Content-Type: application/json" -d "$login_req" "$ARKFILE_BASE_URL/api/opaque/login")
    local login_temp_token=$(echo "$login_resp" | jq -r '.temp_token')
    local login_session_key=$(echo "$login_resp" | jq -r '.session_key')

    # Final TOTP Auth
    echo -e "${CYAN}[User Setup] Finalizing 2FA...${NC}"
    local auth_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg session_key "$login_session_key" '{code:$code, session_key:$session_key, is_backup:false}')
    local auth_resp=$(curl -s --insecure -X POST -H "Authorization: Bearer $login_temp_token" -H "Content-Type: application/json" -d "$auth_req" "$ARKFILE_BASE_URL/api/totp/auth")
    local final_token=$(echo "$auth_resp" | jq -r '.token')
    if [[ "$final_token" == "null" ]]; then
        echo -e "${RED}[ERROR] Final user auth failed: $auth_resp${NC}"
        exit 1
    fi

    # Create client config
    echo -e "${CYAN}[User Setup] Creating client config...${NC}"
    local client_session_file="$TEMP_DIR/client_auth_session.json"
    local jwt_payload=$(echo "$final_token" | cut -d'.' -f2 | sed 's/-/+/g; s/_/\//g'); case $(( ${#jwt_payload} % 4 )) in 2) jwt_payload="${jwt_payload}==";; 3) jwt_payload="${jwt_payload}=";; esac
    local expiry_timestamp=$(echo "$jwt_payload" | base64 -d | jq .exp)
    local expires_at_iso=$(date -u -d "@$expiry_timestamp" +"%Y-%m-%dT%H:%M:%SZ")

    jq -n --arg u "$TEST_USERNAME" --arg at "$final_token" --arg rt "$(echo $auth_resp | jq -r .refresh_token)" --arg ea "$expires_at_iso" --arg su "$ARKFILE_BASE_URL" \
        '{username:$u, access_token:$at, refresh_token:$rt, expires_at:$ea, server_url:$su, session_created:"'$(date -u -d@$(date +%s) --iso-8601=seconds)'"}' > "$client_session_file"

    local client_config_file="$TEMP_DIR/client_config.json"
    jq -n --arg url "$ARKFILE_BASE_URL" --arg user "$TEST_USERNAME" --arg tf "$client_session_file" '{server_url:$url, username:$user, tls_insecure:true, token_file:$tf}' > "$client_config_file"
    echo "$client_config_file" > "$TEMP_DIR/client_config_path.txt"
    echo -e "${GREEN}[OK] Full user authentication complete.${NC}"
}

# Generate and upload 20MB test file
generate_and_upload_file() {
    echo -e "${CYAN}[STEP 3] Generating and uploading 20MB test file${NC}"

    # Generate 20MB test file
    local test_file="$TEMP_DIR/test-20mb-debug.dat"
    local file_size=20971520 # 20MB
    local expected_sha256="4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0"

    echo -e "${CYAN}[File Gen] Generating 20MB test file...${NC}"
    if ! "$DEPLOYED_CRYPTOCLI" generate-test-file --filename "$test_file" --size "$file_size" --pattern deterministic >/dev/null; then
        echo -e "${RED}[ERROR] Failed to generate test file${NC}"
        exit 1
    fi

    # Verify file size and hash
    local actual_size=$(stat -c%s "$test_file" 2>/dev/null || echo "0")
    local actual_sha256=$(sha256sum "$test_file" 2>/dev/null | awk '{print $1}' || echo "")
    echo -e "${GREEN}[OK] Generated $actual_size bytes test file${NC}"
    echo -e "${GREEN}[OK] SHA256: $actual_sha256${NC}"

    # Encrypt the file for upload
    echo -e "${CYAN}[Encryption] Encrypting test file for upload...${NC}"
    local encrypted_file="$TEMP_DIR/upload_test.enc"
    echo "$TEST_PASSWORD" | "$DEPLOYED_CRYPTOCLI" encrypt-password \
        --file "$test_file" \
        --output "$encrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account >/dev/null 2>&1

    if [ ! -f "$encrypted_file" ]; then
        echo -e "${RED}[ERROR] File encryption failed${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] File encrypted successfully${NC}"

    # Generate encrypted metadata
    echo -e "${CYAN}[Metadata] Generating encrypted metadata...${NC}"
    local metadata_output
    metadata_output=$(echo "$TEST_PASSWORD" | "$DEPLOYED_CRYPTOCLI" encrypt-metadata \
        --filename "debug-20mb-test.dat" \
        --sha256sum "$actual_sha256" \
        --username "$TEST_USERNAME")

    # Parse metadata
    local filename_nonce encrypted_filename sha256sum_nonce encrypted_sha256sum
    filename_nonce=$(echo "$metadata_output" | grep "Filename Nonce:" | cut -d' ' -f3)
    encrypted_filename=$(echo "$metadata_output" | grep "Encrypted Filename:" | cut -d' ' -f3)
    sha256sum_nonce=$(echo "$metadata_output" | grep "SHA256 Nonce:" | cut -d' ' -f3)
    encrypted_sha256sum=$(echo "$metadata_output" | grep "Encrypted SHA256:" | cut -d' ' -f3)

    if [[ -z "$encrypted_filename" ]]; then
        echo -e "${RED}[ERROR] Failed to parse encrypted metadata${NC}"
        echo -e "${YELLOW}[DEBUG] Raw cryptocli output:${NC}"
        echo -e "$metadata_output"
        exit 1
    fi

    # Generate FEK
    echo -e "${CYAN}[FEK] Generating and encrypting File Encryption Key...${NC}"
    local fek_hex encrypted_fek_output encrypted_fek
    fek_hex=$("$DEPLOYED_CRYPTOCLI" generate-key --size 32 --format hex | grep "Key (hex):" | cut -d' ' -f3)
    encrypted_fek_output=$(echo "$TEST_PASSWORD" | "$DEPLOYED_CRYPTOCLI" encrypt-fek \
        --fek "$fek_hex" \
        --username "$TEST_USERNAME" 2>&1)
    encrypted_fek=$(echo "$encrypted_fek_output" | grep "Encrypted FEK (base64):" | cut -d' ' -f4)

    # Create metadata JSON
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
    echo -e "${GREEN}[OK] Metadata JSON created${NC}"

    # Upload the file
    echo -e "${CYAN}[Upload] Uploading file to server...${NC}"
    local client_config_file=$(cat "$TEMP_DIR/client_config_path.txt")
    local upload_log="$TEMP_DIR/upload.log"

    echo "$TEST_PASSWORD" | "$DEPLOYED_ARKFILE_CLIENT" \
        --config "$client_config_file" \
        upload \
        --file "$encrypted_file" \
        --metadata "$metadata_file" \
        --progress=false 2>&1 | tee "$upload_log"

    local exit_code=$?
    if [ $exit_code -eq 0 ] && (grep -q "File uploaded successfully" "$upload_log" || grep -q "Upload completed successfully" "$upload_log"); then
        # Extract file ID from upload log - try multiple patterns
        TARGET_FILE_ID=$(grep "File ID:" "$upload_log" | head -1 | sed 's/.*File ID: //' | sed 's/ //g')
        if [ -z "$TARGET_FILE_ID" ]; then
            TARGET_FILE_ID=$(grep -o 'File ID: [a-f0-9-]*' "$upload_log" | head -1 | sed 's/File ID: //')
        fi
        if [ -z "$TARGET_FILE_ID" ]; then
            TARGET_FILE_ID=$(grep -o '[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}' "$upload_log" | head -1)
        fi

        echo "$TARGET_FILE_ID" > "$TEMP_DIR/uploaded_file_id.txt"
        echo -e "${GREEN}[SUCCESS] File uploaded! File ID: $TARGET_FILE_ID${NC}"
        expected_sha256="$actual_sha256" # Use actual SHA256 for this file
        echo -e "${GREEN}[DEBUG] Upload output:${NC}"
        cat "$upload_log"
    else
        echo -e "${RED}[ERROR] File upload failed (exit code: $exit_code)${NC}"
        echo -e "${YELLOW}[DEBUG] Upload log contents:${NC}"
        cat "$upload_log"
        exit 1
    fi

    # Update expected SHA256 for this specific upload
    echo "$expected_sha256" > "$TEMP_DIR/expected_sha256.txt"
}

# Check if we need to set up authentication and upload
SKIP_EXISTING="${SKIP_EXISTING:-false}"
if [ -z "$TARGET_FILE_ID" ] || [ ! -f "/tmp/test-app-curl/jwt_token" ]; then
    echo -e "${YELLOW}[INFO] Missing file-id or authentication tokens. Will perform full setup.${NC}"
    SKIP_EXISTING="false"
else
    echo -e "${YELLOW}[INFO] Found existing session, will try to use file-id: $TARGET_FILE_ID${NC}"
    SKIP_EXISTING="true"
fi

# Create temp directory
mkdir -p "$TEMP_DIR"

echo -e "${PURPLE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║         DEBUG SCRIPT: METADATA DOUBLE-ENCODING BUG       ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${CYAN}[INFO] Testing isolated Steps 11 & 12 from test-app-curl.sh${NC}"
echo -e "${CYAN}[INFO] Base URL: $ARKFILE_BASE_URL${NC}"
echo -e "${CYAN}[INFO] Target File: $TARGET_FILE_ID${NC}"
echo -e "${CYAN}[INFO] Temp Dir: $TEMP_DIR${NC}"
echo -e "${CYAN}[INFO] Using tools: $DEPLOYED_ARKFILE_CLIENT $DEPLOYED_CRYPTOCLI${NC}"
echo

# Setup authentication and upload if needed
if [ "$SKIP_EXISTING" = "false" ]; then
    authenticate_admin
    setup_and_authenticate_user
    generate_and_upload_file

    echo -e ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}    FULL SETUP COMPLETE - PROCEEDING WITH DEBUG TEST    ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo -e ""
else
    echo -e "${YELLOW}[INFO] Using existing session and file for debugging${NC}"
    echo -e ""
fi

CLIENT_CONFIG_FILE=$(cat "$TEMP_DIR/client_config_path.txt")
echo -e "${GREEN}[OK] Using client config: $CLIENT_CONFIG_FILE${NC}"

echo -e ""
echo -e "${WHITE}[STEP 11] ======================== LIST AND EXTRACT FILE METADATA ========================${NC}"

# List files with debug output
echo -e "${CYAN}[DEBUG] Executing: arkfile-client list-files --json${NC}"
echo -e "${CYAN}[DEBUG] Full command: $DEPLOYED_ARKFILE_CLIENT --config $CLIENT_CONFIG_FILE list-files --json${NC}"

RAW_LIST_OUTPUT=$(mktemp)
RAW_LIST_STDERR=$(mktemp)

# Capture both stdout and stderr
set +e
"$DEPLOYED_ARKFILE_CLIENT" --config "$CLIENT_CONFIG_FILE" list-files --json > "$RAW_LIST_OUTPUT" 2> "$RAW_LIST_STDERR"
ARKFILE_EXIT_CODE=$?
set -e

echo -e "${YELLOW}[DEBUG] arkfile-client exit code: $ARKFILE_EXIT_CODE${NC}"
echo -e "${YELLOW}[DEBUG] arkfile-client stderr:${NC}"
cat "$RAW_LIST_STDERR"

if [ $ARKFILE_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}[ERROR] arkfile-client list-files failed${NC}"
    echo -e "${RED}[DEBUG] stdout:${NC}"
    cat "$RAW_LIST_OUTPUT"
    exit 1
fi

# Extract target file from list response
echo -e "${CYAN}[DEBUG] Extracting file $TARGET_FILE_ID from list response...${NC}"

TARGET_FILE_DATA=$(jq -r ".files[] | select(.file_id == \"$TARGET_FILE_ID\")" "$RAW_LIST_OUTPUT")
if [ -z "$TARGET_FILE_DATA" ]; then
    echo -e "${RED}[ERROR] File $TARGET_FILE_ID not found in file list${NC}"
    echo -e "${RED}[DEBUG] Full list response:${NC}"
    cat "$RAW_LIST_OUTPUT"
    exit 1
fi

echo -e "${GREEN}[OK] Found uploaded file in metadata list${NC}"

# Extract individual metadata fields with debug output
echo -e ""
echo -e "${WHITE}[DEBUG] ======================== EXTRACTED METADATA FIELDS ========================${NC}"

ENCRYPTED_FILENAME=$(jq -r '.encrypted_filename' <<< "$TARGET_FILE_DATA" 2>/dev/null)
FILENAME_NONCE=$(jq -r '.filename_nonce' <<< "$TARGET_FILE_DATA" 2>/dev/null)
ENCRYPTED_SHA256=$(jq -r '.encrypted_sha256sum' <<< "$TARGET_FILE_DATA" 2>/dev/null)
SHA256SUM_NONCE=$(jq -r '.sha256sum_nonce' <<< "$TARGET_FILE_DATA" 2>/dev/null)

echo -e "${YELLOW}[DEBUG] Raw target file data from server:${NC}"
echo "$TARGET_FILE_DATA" | jq . >/tmp/test-debug-file-$TARGET_FILE_ID.json
echo -e ""
echo -e "${YELLOW}[DEBUG] Extracted metadata values:${NC}"
echo -e "${YELLOW}  filename_nonce (bio field): '$FILENAME_NONCE' (length: ${#FILENAME_NONCE})${NC}"
echo -e "${YELLOW}  encrypted_filename (bio field): '$ENCRYPTED_FILENAME' (length: ${#ENCRYPTED_FILENAME})${NC}"
echo -e "${YELLOW}  sha256sum_nonce (bio field): '$SHA256SUM_NONCE' (length: ${#SHA256SUM_NONCE})${NC}"
echo -e "${YELLOW}  encrypted_sha256sum (bio field): '$ENCRYPTED_SHA256' (length: ${#ENCRYPTED_SHA256})${NC}"

# Validate extracted metadata
if [ -z "$ENCRYPTED_FILENAME" ] || [ -z "$FILENAME_NONCE" ] || [ -z "$ENCRYPTED_SHA256" ] || [ -z "$SHA256SUM_NONCE" ]; then
    echo -e "${RED}[VALIDATION ERROR] Missing metadata fields${NC}"
    echo -e "${RED}  encrypted_filename: ${ENCRYPTED_FILENAME:-MISSING}${NC}"
    echo -e "${RED}  filename_nonce: ${FILENAME_NONCE:-MISSING}${NC}"
    echo -e "${RED}  encrypted_sha256sum: ${ENCRYPTED_SHA256:-MISSING}${NC}"
    echo -e "${RED}  sha256sum_nonce: ${SHA256SUM_NONCE:-MISSING}${NC}"
    exit 1
fi

# Test base64 decoding manually
echo -e ""
echo -e "${WHITE}[DEBUG] ======================== MANUAL BASE64 DECODE TEST ========================${NC}"

echo -e "${CYAN}[DEBUG] Testing base64 decode of filename_nonce...${NC}"
if ! echo "$FILENAME_NONCE" | base64 -d >/tmp/filename-nonce-decoded 2>&1; then
    echo -e "${RED}[ERROR] filename_nonce is not valid base64: $(cat /tmp/filename-nonce-decoded)${NC}"
    exit 1
else
    FILENAMEnonce_length=$(cat /tmp/filename-nonce-decoded | wc -c)
    echo -e "${GREEN}[OK] filename_nonce base64 decode successful, ${FILENAMEnonce_length} bytes${NC}"
fi

echo -e "${CYAN}[DEBUG] Testing base64 decode of encrypted_filename...${NC}"
if ! echo "$ENCRYPTED_FILENAME" | base64 -d >/tmp/encrypted-filename-decoded 2>&1; then
    echo -e "${RED}[ERROR] encrypted_filename is not valid base64: $(cat /tmp/encrypted-filename-decoded)${NC}"
    exit 1
else
    ENCRYPTED_FILENAME_LENGTH=$(cat /tmp/encrypted-filename-decoded | wc -c)
    echo -e "${GREEN}[OK] encrypted_filename base64 decode successful, ${ENCRYPTED_FILENAME_LENGTH} bytes${NC}"
fi

echo -e "${GREEN}[OK] All metadata fields present and appear to be valid base64${NC}"

echo -e ""
echo -e "${WHITE}[STEP 12] ======================== DECRYPT METADATA WITH CRYPTOCLI ========================${NC}"

# Decrypt metadata using cryptocli with extensive debugging
echo -e "${CYAN}[DEBUG] Executing cryptocli decrypt-metadata command:${NC}"
echo -e "${CYAN}[DEBUG]  --username=$TEST_USERNAME${NC}"
echo -e "${CYAN}[DEBUG]  --verbose (flag enabled)${NC}"
echo -e "${CYAN}[DEBUG] Full command: echo '***PASSWORD***' | $DEPLOYED_CRYPTOCLI decrypt-metadata --verbose --username $TEST_USERNAME --encrypted-filename-data *** --filename-nonce *** --encrypted-sha256sum-data *** --sha256sum-nonce ***${NC}"

# Execute cryptocli decrypt-metadata with debugging
set +e
CRYPTOCIFS_DEBUG_OUTPUT=$(mktemp)
CRYPTOCLI_STDERR=$(mktemp)

echo "$TEST_PASSWORD" | "$DEPLOYED_CRYPTOCLI" decrypt-metadata \
    --debug \
    --username "$TEST_USERNAME" \
    --encrypted-filename-data "$ENCRYPTED_FILENAME" \
    --filename-nonce "$FILENAME_NONCE" \
    --encrypted-sha256sum-data "$ENCRYPTED_SHA256" \
    --sha256sum-nonce "$SHA256SUM_NONCE" \
    > "$CRYPTOCIFS_DEBUG_OUTPUT" \
    2> "$CRYPTOCLI_STDERR"

CRYPTOCLI_EXIT_CODE=$?
set -e

echo -e ""
echo -e "${YELLOW}[DEBUG] cryptocli exit code: $CRYPTOCLI_EXIT_CODE${NC}"
echo -e "${YELLOW}[DEBUG] cryptocli standard output:${NC}"
cat "$CRYPTOCIFS_DEBUG_OUTPUT"

echo -e ""
echo -e "${YELLOW}[DEBUG] cryptocli standard error:${NC}"
cat "$CRYPTOCLI_STDERR"

if [ $CRYPTOCLI_EXIT_CODE -ne 0 ]; then
    echo -e ""
    echo -e "${RED}[FAILURE] cryptocli decrypt-metadata failed with exit code $CRYPTOCLI_EXIT_CODE${NC}"
    echo -e "${RED}[ANALYSIS] This indicates the double-encoding bug persists${NC}"
    echo -e "${RED}[SUGGESTION] Review the server logs and see why metadata is still being double-encoded${NC}"

    # Additional diagnostic output
    echo -e ""
    echo -e "${WHITE}[DIAGNOSTICS] ======================== DIAGNOSTIC INFORMATION ========================${NC}"
    echo -e "${YELLOW}[DEBUG] Server response contains double-encoded values that cryptocli cannot work with${NC}"
    echo -e "${YELLOW}[DEBUG] Check for calls to base64.StdEncoding.EncodeToString() in the server handlers${NC}"
    echo -e "${YELLOW}[DEBUG] Look for places where metadata is being stored/retrieved without proper conversion${NC}"
    echo -e "${YELLOW}[DEBUG] Models/file.go and handlers/uploads.go should have the fixes already applied${NC}"

    exit 1
fi

# Extract decrypted values
DECRYPTED_FILENAME=$(grep "Decrypted Filename:" "$CRYPTOCIFS_DEBUG_OUTPUT" | cut -d':' -f2- | sed 's/^ *//')
DECRYPTED_SHA256=$(grep "Decrypted SHA256:" "$CRYPTOCIFS_DEBUG_OUTPUT" | cut -d':' -f2- | sed 's/^ *//')

if [ -z "$DECRYPTED_FILENAME" ] || [ -z "$DECRYPTED_SHA256" ]; then
    echo -e "${RED}[ERROR] Failed to extract decrypted metadata from cryptocli output${NC}"
    echo -e "${RED}[DEBUG] Expected output lines not found${NC}"
    echo -e "${YELLOW}[DEBUG] Full output:${NC}"
    cat "$CRYPTOCIFS_DEBUG_OUTPUT"
    exit 1
fi

echo -e ""
echo -e "${WHITE}[RESULTS] ======================== DECRYPTION RESULTS ========================${NC}"
echo -e "${GREEN}[SUCCESS] Metadata decryption successful!${NC}"
echo -e "${GREEN}  Original filename: e2e-test-file.dat (expected)${NC}"
echo -e "${GREEN}  Decrypted filename: $DECRYPTED_FILENAME${NC}"
echo -e "${GREEN}  Test file SHA256: 4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0 (expected)${NC}"
echo -e "${GREEN}  Decrypted SHA256: $DECRYPTED_SHA256${NC}"

if [ "$DECRYPTED_SHA256" = "4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0" ]; then
    echo -e ""
    echo -e "${GREEN}[PERFECT] All metadata decryption tests passed! The double-encoding bug is FIXED!${NC}"
else
    echo -e ""
    echo -e "${YELLOW}[WARNING] SHA256 checksum mismatch detected${NC}"
    echo -e "${YELLOW}[DEBUG] Expected: 4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0${NC}"
    echo -e "${YELLOW}[DEBUG] Got:      $DECRYPTED_SHA256${NC}"
    echo -e "${YELLOW}[ANALYSIS] Metadata decryption may have worked but there's corruption in the data${NC}"
fi

# Cleanup temp files
rm -f "$RAW_LIST_OUTPUT" "$RAW_LIST_STDERR" "$CRYPTOCIFS_DEBUG_OUTPUT" "$CRYPTOCLI_STDERR"

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
    echo -e "${CYAN}[TOTP Gen] Received secret: ${secret:0:4}...${secret: -4}, Timestamp: ${timestamp:-'current'}${NC}" >&2
    local padded_secret=$(fix_totp_secret_padding "$secret")
    echo -e "${CYAN}[TOTP Gen] Padded secret: ${padded_secret:0:4}...${padded_secret: -4}${NC}" >&2
    if [ ! -x "scripts/testing/totp-generator" ]; then
        echo -e "${CYAN}[TOTP Gen] Building totp-generator...${NC}" >&2
        (cd scripts/testing && go build -o totp-generator totp-generator.go) >/dev/null 2>&1
    fi
    local generated_code
    generated_code=$(scripts/testing/totp-generator "$padded_secret" "$timestamp")
    echo -e "${YELLOW}[TOTP Gen] Generated code: $generated_code${NC}" >&2
    echo "$generated_code"
}

# Authenticate admin user
authenticate_admin() {
    echo -e "${CYAN}[STEP 1] Authenticating admin user${NC}"

    # OPAQUE Authentication
    echo -e "${CYAN}[Admin Auth] Sending OPAQUE login request...${NC}"
    local admin_opaque_response
    admin_opaque_response=$(curl -s --insecure -X POST -H "Content-Type: application/json" \
        -d "{\"username\": \"arkfile-dev-admin\", \"password\": \"DevAdmin2025!SecureInitialPassword\"}" \
        "$ARKFILE_BASE_URL/api/opaque/login" || echo "ERROR")

    echo -e "${YELLOW}[Admin Auth] OPAQUE Response: $admin_opaque_response${NC}"
    if [[ "$admin_opaque_response" == "ERROR" ]] || ! echo "$admin_opaque_response" | jq -e '.requires_totp' >/dev/null; then
        echo -e "${RED}[ERROR] Admin OPAQUE login failed: $admin_opaque_response${NC}"
        exit 1
    fi

    local admin_temp_token=$(echo "$admin_opaque_response" | jq -r '.temp_token')
    local admin_session_key=$(echo "$admin_opaque_response" | jq -r '.session_key')
    echo -e "${YELLOW}[Admin Auth] Temp Token: $admin_temp_token${NC}"
    echo -e "${YELLOW}[Admin Auth] Session Key: $admin_session_key${NC}"

    # TOTP Authentication
    echo -e "${CYAN}[Admin Auth] Performing TOTP authentication...${NC}"
    # Get current timestamp and generate fresh TOTP code
    local ts=$(date +%s)
    local code=$(generate_totp_code "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D" "$ts")

    local totp_request_payload
    totp_request_payload=$(jq -n --arg code "$code" --arg sessionKey "$admin_session_key" '{"code":$code,"session_key":$sessionKey,"is_backup":false}')
    echo -e "${CYAN}[Admin Auth] Sending TOTP auth request with code: $code (timestamp: $ts)${NC}"

    local admin_totp_response
    admin_totp_response=$(curl -s --insecure -X POST -H "Authorization: Bearer $admin_temp_token" -H "Content-Type: application/json" \
        -d "$totp_request_payload" "$ARKFILE_BASE_URL/api/totp/auth" || echo "ERROR")

    echo -e "${YELLOW}[Admin Auth] TOTP Response: $admin_totp_response${NC}"
    if [[ "$admin_totp_response" == "ERROR" ]] || ! echo "$admin_totp_response" | jq -e '.token' >/dev/null; then
        echo -e "${RED}[ERROR] Admin TOTP auth failed: $admin_totp_response${NC}"
        exit 1
    fi

    local admin_token=$(echo "$admin_totp_response" | jq -r '.token')
    echo "$admin_token" > "$TEMP_DIR/admin_token.txt"
    echo -e "${GREEN}[OK] Admin authenticated successfully.${NC}"
}

# Full user setup and authentication chain
setup_and_authenticate_user() {
    echo -e "${CYAN}[STEP 2] Setting up and authenticating test user${NC}"
    local admin_token=$(cat "$TEMP_DIR/admin_token.txt")

    # Cleanup
    echo -e "${CYAN}[User Setup] Cleaning up user...${NC}"
    curl -s --insecure -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" -d "{\"username\":\"$TEST_USERNAME\",\"confirm\":true}" "$ARKFILE_BASE_URL/api/admin/dev-test/user/cleanup" > /dev/null

    # Registration
    echo -e "${CYAN}[User Setup] Registering user...${NC}"
    local reg_req=$(jq -n --arg u "$TEST_USERNAME" --arg p "$TEST_PASSWORD" '{username:$u, password:$p}')
    local reg_resp=$(curl -s --insecure -X POST -H "Content-Type: application/json" -d "$reg_req" "$ARKFILE_BASE_URL/api/opaque/register")
    if ! echo "$reg_resp" | jq -e '.requires_totp_setup' >/dev/null; then
        echo -e "${RED}[ERROR] Registration failed: $reg_resp${NC}"
        exit 1
    fi
    local reg_temp_token=$(echo "$reg_resp" | jq -r '.temp_token')
    local reg_session_key=$(echo "$reg_resp" | jq -r '.session_key')

    # Approval
    echo -e "${CYAN}[User Setup] Approving user...${NC}"
    local approve_req=$(jq -n --arg approved_by "arkfile-dev-admin" '{approved_by:$approved_by}')
    curl -s --insecure -X POST -H "Authorization: Bearer $admin_token" -H "Content-Type: application/json" -d "$approve_req" "$ARKFILE_BASE_URL/api/admin/user/$TEST_USERNAME/approve" > /dev/null

    # TOTP Setup & Verify
    echo -e "${CYAN}[User Setup] Setting up and verifying TOTP...${NC}"
    local setup_req=$(jq -n --arg sessionKey "$reg_session_key" '{session_key:$sessionKey}')
    local setup_resp=$(curl -s --insecure -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$setup_req" "$ARKFILE_BASE_URL/api/totp/setup")
    local secret=$(echo "$setup_resp" | jq -r '.secret')
    if [[ "$secret" == "null" ]]; then
        echo -e "${RED}[ERROR] TOTP setup failed: $setup_resp${NC}"
        exit 1
    fi

    local verify_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg sessionKey "$reg_session_key" '{code:$code, session_key:$sessionKey}')
    local verify_resp=$(curl -s --insecure -X POST -H "Authorization: Bearer $reg_temp_token" -H "Content-Type: application/json" -d "$verify_req" "$ARKFILE_BASE_URL/api/totp/verify")
    if ! echo "$verify_resp" | jq -e '.enabled' >/dev/null; then
        echo -e "${RED}[ERROR] TOTP verification failed: $verify_resp${NC}"
        exit 1
    fi

    # Login for 2FA
    echo -e "${CYAN}[User Setup] Logging in for 2FA...${NC}"
    local login_req=$(jq -n --arg u "$TEST_USERNAME" --arg p "$TEST_PASSWORD" '{username:$u, password:$p}')
    local login_resp=$(curl -s --insecure -X POST -H "Content-Type: application/json" -d "$login_req" "$ARKFILE_BASE_URL/api/opaque/login")
    local login_temp_token=$(echo "$login_resp" | jq -r '.temp_token')
    local login_session_key=$(echo "$login_resp" | jq -r '.session_key')

    # Final TOTP Auth
    echo -e "${CYAN}[User Setup] Finalizing 2FA...${NC}"
    local auth_req=$(jq -n --arg code "$(generate_totp_code "$secret" "$(date +%s)")" --arg session_key "$login_session_key" '{code:$code, session_key:$session_key, is_backup:false}')
    local auth_resp=$(curl -s --insecure -X POST -H "Authorization: Bearer $login_temp_token" -H "Content-Type: application/json" -d "$auth_req" "$ARKFILE_BASE_URL/api/totp/auth")
    local final_token=$(echo "$auth_resp" | jq -r '.token')
    if [[ "$final_token" == "null" ]]; then
        echo -e "${RED}[ERROR] Final user auth failed: $auth_resp${NC}"
        exit 1
    fi

    # Create client config
    echo -e "${CYAN}[User Setup] Creating client config...${NC}"
    local client_session_file="$TEMP_DIR/client_auth_session.json"
    local jwt_payload=$(echo "$final_token" | cut -d'.' -f2 | sed 's/-/+/g; s/_/\//g'); case $(( ${#jwt_payload} % 4 )) in 2) jwt_payload="${jwt_payload}==";; 3) jwt_payload="${jwt_payload}=";; esac
    local expiry_timestamp=$(echo "$jwt_payload" | base64 -d | jq .exp)
    local expires_at_iso=$(date -u -d "@$expiry_timestamp" +"%Y-%m-%dT%H:%M:%SZ")

    jq -n --arg u "$TEST_USERNAME" --arg at "$final_token" --arg rt "$(echo $auth_resp | jq -r .refresh_token)" --arg ea "$expires_at_iso" --arg su "$ARKFILE_BASE_URL" \
        '{username:$u, access_token:$at, refresh_token:$rt, expires_at:$ea, server_url:$su, session_created:"'$(date -u -d@$(date +%s) --iso-8601=seconds)'"}' > "$client_session_file"

    local client_config_file="$TEMP_DIR/client_config.json"
    jq -n --arg url "$ARKFILE_BASE_URL" --arg user "$TEST_USERNAME" --arg tf "$client_session_file" '{server_url:$url, username:$user, tls_insecure:true, token_file:$tf}' > "$client_config_file"
    echo "$client_config_file" > "$TEMP_DIR/client_config_path.txt"
    echo -e "${GREEN}[OK] Full user authentication complete.${NC}"
}

# Generate and upload 20MB test file
generate_and_upload_file() {
    echo -e "${CYAN}[STEP 3] Generating and uploading 20MB test file${NC}"

    # Generate 20MB test file
    local test_file="$TEMP_DIR/test-20mb-debug.dat"
    local file_size=20971520 # 20MB
    local expected_sha256="4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0"

    echo -e "${CYAN}[File Gen] Generating 20MB test file...${NC}"
    if ! "$DEPLOYED_CRYPTOCLI" generate-test-file --filename "$test_file" --size "$file_size" --pattern deterministic >/dev/null; then
        echo -e "${RED}[ERROR] Failed to generate test file${NC}"
        exit 1
    fi

    # Verify file size and hash
    local actual_size=$(stat -c%s "$test_file" 2>/dev/null || echo "0")
    local actual_sha256=$(sha256sum "$test_file" 2>/dev/null | awk '{print $1}' || echo "")
    echo -e "${GREEN}[OK] Generated $actual_size bytes test file${NC}"
    echo -e "${GREEN}[OK] SHA256: $actual_sha256${NC}"

    # Encrypt the file for upload
    echo -e "${CYAN}[Encryption] Encrypting test file for upload...${NC}"
    local encrypted_file="$TEMP_DIR/upload_test.enc"
    echo "$TEST_PASSWORD" | "$DEPLOYED_CRYPTOCLI" encrypt-password \
        --file "$test_file" \
        --output "$encrypted_file" \
        --username "$TEST_USERNAME" \
        --key-type account >/dev/null 2>&1

    if [ ! -f "$encrypted_file" ]; then
        echo -e "${RED}[ERROR] File encryption failed${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] File encrypted successfully${NC}"

    # Generate encrypted metadata
    echo -e "${CYAN}[Metadata] Generating encrypted metadata...${NC}"
    local metadata_output
    metadata_output=$(echo "$TEST_PASSWORD" | "$DEPLOYED_CRYPTOCLI" encrypt-metadata \
        --filename "debug-20mb-test.dat" \
        --sha256sum "$actual_sha256" \
        --username "$TEST_USERNAME")

    # Parse metadata
    local filename_nonce encrypted_filename sha256sum_nonce encrypted_sha256sum
    filename_nonce=$(echo "$metadata_output" | grep "Filename Nonce:" | cut -d' ' -f3)
    encrypted_filename=$(echo "$metadata_output" | grep "Encrypted Filename:" | cut -d' ' -f3)
    sha256sum_nonce=$(echo "$metadata_output" | grep "SHA256 Nonce:" | cut -d' ' -f3)
    encrypted_sha256sum=$(echo "$metadata_output" | grep "Encrypted SHA256:" | cut -d' ' -f3)

    if [[ -z "$encrypted_filename" ]]; then
        echo -e "${RED}[ERROR] Failed to parse encrypted metadata${NC}"
        echo -e "${YELLOW}[DEBUG] Raw cryptocli output:${NC}"
        echo -e "$metadata_output"
        exit 1
    fi

    # Generate FEK
    echo -e "${CYAN}[FEK] Generating and encrypting File Encryption Key...${NC}"
    local fek_hex encrypted_fek_output encrypted_fek
    fek_hex=$("$DEPLOYED_CRYPTOCLI" generate-key --size 32 --format hex | grep "Key (hex):" | cut -d' ' -f3)
    encrypted_fek_output=$(echo "$TEST_PASSWORD" | "$DEPLOYED_CRYPTOCLI" encrypt-fek \
        --fek "$fek_hex" \
        --username "$TEST_USERNAME" 2>&1)
    encrypted_fek=$(echo "$encrypted_fek_output" | grep "Encrypted FEK (base64):" | cut -d' ' -f4)

    # Create metadata JSON
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
    echo -e "${GREEN}[OK] Metadata JSON created${NC}"

    # Upload the file
    echo -e "${CYAN}[Upload] Uploading file to server...${NC}"
    local client_config_file=$(cat "$TEMP_DIR/client_config_path.txt")
    local upload_log="$TEMP_DIR/upload.log"

    echo "$TEST_PASSWORD" | "$DEPLOYED_ARKFILE_CLIENT" \
        --config "$client_config_file" \
        upload \
        --file "$encrypted_file" \
        --metadata "$metadata_file" \
        --progress=false 2>&1 | tee "$upload_log"

    local exit_code=$?
    if [ $exit_code -eq 0 ] && grep -q "File uploaded successfully" "$upload_log"; then
        # Extract file ID from upload log
        TARGET_FILE_ID=$(grep "file ID:" "$upload_log" | head -1 | sed 's/.*file ID: //')
        if [ -z "$TARGET_FILE_ID" ]; then
            TARGET_FILE_ID=$(grep -o 'file ID: [a-f0-9-]*' "$upload_log" | head -1 | sed 's/file ID: //')
        fi
        echo "$TARGET_FILE_ID" > "$TEMP_DIR/uploaded_file_id.txt"
        echo -e "${GREEN}[SUCCESS] File uploaded! File ID: $TARGET_FILE_ID${NC}"
        expected_sha256="$actual_sha256" # Use actual SHA256 for this file
    else
        echo -e "${RED}[ERROR] File upload failed${NC}"
        cat "$upload_log"
        exit 1
    fi

    # Update expected SHA256 for this specific upload
    echo "$expected_sha256" > "$TEMP_DIR/expected_sha256.txt"
}

echo -e ""
echo -e "${WHITE}[DONE] ======================== DEBUG SESSION COMPLETE ========================${NC}"
