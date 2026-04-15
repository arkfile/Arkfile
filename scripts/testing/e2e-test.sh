#!/bin/bash

# e2e-test.sh - End-to-End Testing
# Uses arkfile-client and arkfile-admin CLI tools
#
# Flow:
#   1. Environment verification (server, CLI tools)
#   2. Admin authentication (login with TOTP)
#   3. Bootstrap protection (verify 2nd admin creation fails)
#   4. Regular user registration (using arkfile-client)
#   5. TOTP setup for regular user
#   6. Admin user management (list-users, user-status, approve-user)
#   7. Regular user login with TOTP
#   8. File operations (account-password, upload/download/integrity/privacy)
#   9. Custom-password file operations (custom-key upload/download/privacy)
#   10. Share operations (create/access/revoke/privacy)
#   11. Admin system status
#   12. Cleanup
#   13. Summary report

set -eo pipefail

# CONFIGURATION

# Parse arguments
BOOTSTRAP_TOKEN=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --bootstrap-token) BOOTSTRAP_TOKEN="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Test Credentials
# Account & Custom passwords: min 15 chars, any 2 of uppercase / lowercase / number / special
# Share passwords: min 20 chars, any 2 of uppercase / lowercase / number / special
# (See: crypto/password-requirements.json)

# Admin credentials
ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
ADMIN_TOTP_SECRET="ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"  # Fixed dev secret

# Regular test user credentials
TEST_USERNAME="${TEST_USERNAME:-arkfile-dev-test-user}"
TEST_PASSWORD="${TEST_PASSWORD:-MyVacation2025PhotosForFamily!ExtraSecure}"

# Bootstrap protection test (attacker simulation - tries to create 2nd admin)
ATTACKER_ADMIN_USERNAME="attacker-admin"
ATTACKER_ADMIN_PASSWORD="AttackerPass123!SecureEnough"

# Share passwords (20+ chars, meets share password requirements)
SHARE_A_PASSWORD='MyShareP@ssw0rd-789q&*(::1'
SHARE_B_PASSWORD='MyShareP@ssw0rd-789q&*(::2'
SHARE_C_PASSWORD='MyShareP@ssw0rd-789q&*(::3'

# Custom-password file flow
CUSTOM_FILE_PASSWORD='Tr0pic@lSunset2025!SecureCustomKey'
WRONG_CUSTOM_FILE_PASSWORD='WrongCust0mPwd2025!NotTheKey'

# Share D - created from custom-password-encrypted file
SHARE_D_PASSWORD='MyShareP@ssw0rd-789q&*(::4'

# Negative test data (non-existent share)
NONEXISTENT_SHARE_ID="nonexistent-share-id-that-does-not-exist"
DUMMY_SHARE_PASSWORD='DummyP@ssw0rd#2026!Nope'

# Server & Paths
SERVER_URL="${SERVER_URL:-https://localhost:8443}"

# Binary location - require deployed location
BUILD_DIR="/opt/arkfile/bin"
if [ ! -x "$BUILD_DIR/arkfile-client" ]; then
    echo "[X] arkfile-client binary not found or not executable at $BUILD_DIR/arkfile-client"
    echo "    Run 'sudo ./scripts/dev-reset.sh' to build and deploy first."
    exit 1
fi

CLIENT="$BUILD_DIR/arkfile-client"
ADMIN="$BUILD_DIR/arkfile-admin"

# Test Data Directory
# MUST be in /tmp
TEST_DATA_DIR="/tmp/arkfile-e2e-test-data"
mkdir -p "$TEST_DATA_DIR"
TOTP_SECRET_FILE="$TEST_DATA_DIR/totp-secret"
LOG_FILE="$TEST_DATA_DIR/e2e-test.log"

# Initialize log file
echo "=== ARKFILE E2E TEST LOG - $(date) ===" > "$LOG_FILE"

# COLOR OUTPUT

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

success() { echo -e "${GREEN}[OK] $1${NC}"; echo "[OK] $1" >> "$LOG_FILE"; }
error()   { echo -e "${RED}[X] $1${NC}"; echo "[ERROR] $1" >> "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[!] $1${NC}"; echo "[WARN] $1" >> "$LOG_FILE"; }
info()    { echo -e "${CYAN}[i] $1${NC}"; echo "[INFO] $1" >> "$LOG_FILE"; }
section() { echo -e "\n${BLUE}$1${NC}"; echo -e "\n=== $1 ===" >> "$LOG_FILE"; }
phase()   { echo -e "\n${CYAN}# $1${NC}\n"; echo -e "\n# $1" >> "$LOG_FILE"; }

# TEST RESULT TRACKING

declare -A TEST_RESULTS
declare -a TEST_ORDER
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

record_test() {
    local test_name="$1"
    local result="$2"  # "PASS" or "FAIL"

    TEST_RESULTS["$test_name"]="$result"
    TEST_ORDER+=("$test_name")
    TEST_COUNT=$((TEST_COUNT + 1))

    if [ "$result" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        success "$test_name"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        error "$test_name"
        error "CRITICAL FAILURE: Test '$test_name' failed. Stopping execution."
        exit 1
    fi
}

# HELPER FUNCTIONS

admin_login_with_totp() {
    local test_name="$1"
    wait_for_totp_window
    
    local out code
    safe_exec out code bash -c "printf '%s\n' '$ADMIN_PASSWORD' | $ADMIN \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        --username '$ADMIN_USERNAME' \
        login \
        --totp-secret '$ADMIN_TOTP_SECRET' \
        --save-session"
        
    if [ $code -eq 0 ] && echo "$out" | grep -q "Admin login successful"; then
        record_test "$test_name" "PASS"
        echo "$out"
    else
        error "$test_name failed with output:"
        echo "$out"
        record_test "$test_name" "FAIL"
    fi
}

user_login_with_totp() {
    local test_name="$1"
    wait_for_totp_window
    
    if [ -z "$TEST_USER_TOTP_SECRET" ]; then
        error "Missing TOTP secret from setup phase"
        record_test "$test_name" "FAIL"
        return
    fi

    local out code
    safe_exec out code bash -c "printf '%s\n' '$TEST_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        --username '$TEST_USERNAME' \
        login \
        --totp-secret '$TEST_USER_TOTP_SECRET' \
        --save-session \
        --cache-key"

    if [ $code -eq 0 ] && echo "$out" | grep -q "Login successful"; then
        record_test "$test_name" "PASS"
        echo "$out"
    else
        error "$test_name failed with output:"
        echo "$out"
        record_test "$test_name" "FAIL"
    fi
}

logout_user_session() {
    local test_name="$1"
    local out code
    safe_exec out code $CLIENT --server-url "$SERVER_URL" --tls-insecure logout
    if [ $code -eq 0 ]; then
        record_test "$test_name" "PASS"
    else
        error "$test_name failed:"
        echo "$out"
        record_test "$test_name" "FAIL"
    fi
}

logout_admin_session() {
    local test_name="$1"
    local out code
    safe_exec out code $ADMIN --server-url "$SERVER_URL" --tls-insecure logout
    if [ $code -eq 0 ]; then
        record_test "$test_name" "PASS"
    else
        error "$test_name failed:"
        echo "$out"
        record_test "$test_name" "FAIL"
    fi
}

assert_agent_running() {
    local test_name="$1"
    local status_out
    status_out=$("$CLIENT" agent status 2>&1) || true
    echo "[AGENT STATUS] $status_out" >> "$LOG_FILE"
    if echo "$status_out" | grep -q "NOT RUNNING"; then
        record_test "$test_name" "FAIL"
    else
        if echo "$status_out" | grep -q "RUNNING"; then
            record_test "$test_name" "PASS"
        else
            record_test "$test_name" "FAIL"
        fi
    fi
}

assert_agent_not_running() {
    local test_name="$1"
    local status_out
    status_out=$("$CLIENT" agent status 2>&1) || true
    echo "[AGENT STATUS] $status_out" >> "$LOG_FILE"
    if echo "$status_out" | grep -q "NOT RUNNING"; then
        record_test "$test_name" "PASS"
    else
        record_test "$test_name" "FAIL"
    fi
}

share_download_with_password() {
    local share_pass="$1"
    local share_id="$2"
    local output_file="$3"
    local test_name="$4"
    local expect_fail="${5:-false}"
    
    local out code
    safe_exec out code bash -c "printf '%s\n' '$share_pass' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share download \
        --share-id '$share_id' \
        --output '$output_file'"
        
    if [ "$expect_fail" = "true" ]; then
        if [ $code -ne 0 ]; then
            record_test "$test_name" "PASS"
        else
            error "Security failure: $test_name unexpectedly succeeded!"
            echo "$out"
            record_test "$test_name" "FAIL"
        fi
    else
        if [ $code -eq 0 ]; then
            record_test "$test_name" "PASS"
        else
            error "$test_name failed:"
            echo "$out"
            record_test "$test_name" "FAIL"
        fi
    fi
}

assert_output_file_absent_or_empty() {
    local file_path="$1"
    local test_name="$2"
    
    if [ ! -f "$file_path" ] || [ ! -s "$file_path" ]; then
        record_test "$test_name" "PASS"
        rm -f "$file_path"
    else
        error "Security failure: $test_name failed! File exists and has content."
        record_test "$test_name" "FAIL"
        rm -f "$file_path"
    fi
}

assert_sha256_matches() {
    local file_path="$1"
    local expected_hash="$2"
    local test_name="$3"
    
    local actual_hash
    actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
    if [ "$actual_hash" = "$expected_hash" ]; then
        record_test "$test_name" "PASS"
    else
        error "$test_name mismatch! Expected: $expected_hash, Got: $actual_hash"
        record_test "$test_name" "FAIL"
    fi
}

# Safe command execution - captures output and exit code without triggering set -e
safe_exec() {
    local output_var="$1"
    local exit_code_var="$2"
    shift 2

    local temp_output
    local temp_exit_code

    echo "[EXEC] $*" >> "$LOG_FILE"

    set +e
    temp_output=$("$@" 2>&1)
    temp_exit_code=$?
    set -e

    echo "$temp_output" >> "$LOG_FILE"
    echo "[EXIT] Code: $temp_exit_code" >> "$LOG_FILE"
    echo "----------------------------------------" >> "$LOG_FILE"

    eval "$output_var=\$temp_output"
    eval "$exit_code_var=\$temp_exit_code"
}

# TOTP WINDOW MANAGEMENT

# Wait for next TOTP window to avoid replay protection.
# The server records each used TOTP code and rejects reuse within the same
# 30-second window. This is needed before any login that uses --totp-secret,
# since a previous operation (e.g., server bootstrap validation, or a prior
# login in the same test run) may have consumed the current window.
wait_for_totp_window() {
    local current_seconds
    current_seconds=$(date +%s)
    local seconds_into_window=$((current_seconds % 30))
    local seconds_to_wait=$((30 - seconds_into_window))

    info "Waiting ${seconds_to_wait}s + 1s buffer for next TOTP window (replay protection)..."
    sleep "$((seconds_to_wait + 1))"
}

# AGENT LIFECYCLE

AGENT_PID=""

stop_agent() {
    info "Stopping agent (if running)..."

    # Send stop command (details go to log only)
    local stop_out stop_code
    safe_exec stop_out stop_code "$CLIENT" agent stop

    # Poll up to 5 seconds for daemon to fully exit
    for i in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.5
        local poll_status
        poll_status=$("$CLIENT" agent status 2>&1) || true
        if echo "$poll_status" | grep -q "NOT RUNNING"; then
            info "Agent stopped"
            return 0
        fi
    done
    warning "Agent may still be running after stop attempt"
}

# TEST PHASES

# Phase 1: Environment Verification
phase_1_environment_verification() {
    phase "1: ENVIRONMENT VERIFICATION"

    section "Checking server connectivity"
    if curl -sk --connect-timeout 5 "$SERVER_URL/health" >/dev/null 2>&1; then
        record_test "Server connectivity" "PASS"
    else
        record_test "Server connectivity" "FAIL"
    fi

    section "Checking CLI tools"

    if [ -x "$CLIENT" ]; then
        record_test "arkfile-client available" "PASS"
        info "Using arkfile-client from: $CLIENT"
    else
        record_test "arkfile-client available" "FAIL"
    fi

    if [ -x "$ADMIN" ]; then
        record_test "arkfile-admin available" "PASS"
        info "Using arkfile-admin from: $ADMIN"
    else
        record_test "arkfile-admin available" "FAIL"
    fi

    success "Environment verification complete"
}

# Phase 2: Admin Authentication
phase_2_admin_authentication() {
    phase "2: ADMIN AUTHENTICATION"

    section "Authenticating admin user: $ADMIN_USERNAME"
    admin_login_with_totp "Admin login"

    success "Admin authentication complete"
}

# Phase 3: Bootstrap Protection
phase_3_bootstrap_protection() {
    phase "3: BOOTSTRAP PROTECTION"

    if [ -z "$BOOTSTRAP_TOKEN" ]; then
        warning "Skipping Bootstrap Protection test (no token provided)"
        record_test "Bootstrap protection" "PASS"
        return 0
    fi

    section "Attempting to create second admin with bootstrap token"

    local boot_output
    local boot_exit_code

    safe_exec boot_output boot_exit_code \
        bash -c "printf '%s\n%s\n' '$ATTACKER_ADMIN_PASSWORD' '$ATTACKER_ADMIN_PASSWORD' | $ADMIN \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        bootstrap \
        --token '$BOOTSTRAP_TOKEN' \
        --username '$ATTACKER_ADMIN_USERNAME'"

    if [ $boot_exit_code -ne 0 ] && echo "$boot_output" | grep -E -q "already initialized|unauthorized"; then
        record_test "Bootstrap protection" "PASS"
        success "Bootstrap protection verified (request rejected)"
    else
        error "Security Vulnerability: Able to create second admin via bootstrap!"
        record_test "Bootstrap protection" "FAIL"
    fi
}

# Phase 4: Regular User Registration
phase_4_user_registration() {
    phase "4: REGULAR USER REGISTRATION"

    section "Registering user: $TEST_USERNAME"

    local reg_output
    local reg_exit_code

    safe_exec reg_output reg_exit_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$TEST_PASSWORD' | $CLIENT \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            register \
            --username '$TEST_USERNAME'"

    if [ $reg_exit_code -eq 0 ]; then
        if echo "$reg_output" | grep -q "Registration successful"; then
            record_test "User registration" "PASS"
        else
            error "User registration failed - unexpected output:"
            echo "$reg_output"
            record_test "User registration" "FAIL"
        fi
    else
        # Idempotency: user already exists is OK
        if echo "$reg_output" | grep -E -i -q "already exists|already registered|HTTP 409|conflict"; then
            info "User '$TEST_USERNAME' already exists. Proceeding..."
            record_test "User registration" "PASS"
        else
            error "User registration command failed (exit code: $reg_exit_code):"
            echo "$reg_output"
            record_test "User registration" "FAIL"
        fi
    fi

    success "User registration complete"
}

# Phase 5: TOTP Setup for Regular User
phase_5_totp_setup() {
    phase "5: TOTP SETUP FOR REGULAR USER"

    section "Setting up TOTP for user: $TEST_USERNAME"

    # Idempotency: check for existing saved secret
    if [ -f "$TOTP_SECRET_FILE" ]; then
        local secret
        secret=$(cat "$TOTP_SECRET_FILE")
        if [ -n "$secret" ]; then
            export TEST_USER_TOTP_SECRET="$secret"
            record_test "TOTP setup initiation" "PASS"
            info "Using existing TOTP secret: $secret"
            success "TOTP setup phase complete (skipped - using existing secret)"
            return 0
        fi
    fi

    # Step 1: Get the secret
    info "Initiating TOTP setup..."
    local setup_output
    local setup_exit_code

    safe_exec setup_output setup_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-totp --show-secret

    if [ $setup_exit_code -ne 0 ]; then
        error "Failed to initiate TOTP setup (exit code: $setup_exit_code):"
        echo "$setup_output"
        record_test "TOTP setup initiation" "FAIL"
    fi

    # Extract secret
    local secret
    secret=$(echo "$setup_output" | grep "TOTP_SECRET:" | cut -d':' -f2 | tr -d ' ')

    if [ -z "$secret" ]; then
        error "Failed to extract TOTP secret from output:"
        echo "$setup_output"
        record_test "TOTP setup initiation" "FAIL"
    fi

    echo "$secret" > "$TOTP_SECRET_FILE"
    export TEST_USER_TOTP_SECRET="$secret"
    record_test "TOTP setup initiation" "PASS"
    info "Got TOTP secret: $secret"

    # Step 2: Verify with a code (CLI generates it internally)
    local verify_output
    local verify_exit_code

    # Generate a TOTP code from the secret using the CLI
    local code
    code=$("$CLIENT" generate-totp --secret "$secret" 2>/dev/null)

    if [ -z "$code" ]; then
        error "Could not generate TOTP verification code"
        record_test "TOTP verification" "FAIL"
        return
    fi

    info "Generated verification code: $code"

    safe_exec verify_output verify_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-totp --verify "$code"

    if [ $verify_exit_code -eq 0 ] && echo "$verify_output" | grep -q "TOTP Setup Complete"; then
        record_test "TOTP verification" "PASS"
        echo "$verify_output"
    else
        error "TOTP verification failed:"
        echo "$verify_output"
        record_test "TOTP verification" "FAIL"
    fi

    success "TOTP setup phase complete"
}

# Phase 6: Admin User Management
phase_6_admin_approval() {
    phase "6: ADMIN USER MANAGEMENT"

    # 6.1: List all users
    section "Listing all users (admin)"

    local list_users_output
    local list_users_exit_code

    safe_exec list_users_output list_users_exit_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure list-users

    if [ $list_users_exit_code -eq 0 ] && echo "$list_users_output" | grep -q "$TEST_USERNAME"; then
        record_test "Admin list-users" "PASS"
        info "Test user '$TEST_USERNAME' found in user list"
    else
        error "list-users failed or test user not found:"
        echo "$list_users_output"
        record_test "Admin list-users" "FAIL"
    fi

    # 6.2: Get user status
    section "Getting user status for: $TEST_USERNAME"

    local user_status_output
    local user_status_exit_code

    safe_exec user_status_output user_status_exit_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            user-status --username "$TEST_USERNAME"

    if [ $user_status_exit_code -eq 0 ]; then
        record_test "Admin user-status" "PASS"
        echo "$user_status_output"
    else
        error "user-status command failed:"
        echo "$user_status_output"
        record_test "Admin user-status" "FAIL"
    fi

    # 6.3: Approve user
    section "Approving user via admin: $TEST_USERNAME"

    local approve_output
    local approve_exit_code

    safe_exec approve_output approve_exit_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            approve-user --username "$TEST_USERNAME" --storage "5GB"

    if [ $approve_exit_code -eq 0 ]; then
        if echo "$approve_output" | grep -q "approved successfully"; then
            record_test "User approval" "PASS"
        else
            error "User approval failed - unexpected output:"
            echo "$approve_output"
            record_test "User approval" "FAIL"
        fi
    else
        # Idempotency: already approved is OK
        if echo "$approve_output" | grep -q "already approved"; then
            info "User '$TEST_USERNAME' is already approved. Proceeding..."
            record_test "User approval" "PASS"
        else
            error "User approval command failed:"
            echo "$approve_output"
            record_test "User approval" "FAIL"
        fi
    fi

    success "User approval complete"
}

# Phase 7: Regular User Login with TOTP
phase_7_user_login() {
    phase "7: REGULAR USER LOGIN WITH TOTP"

    section "Logging in as user: $TEST_USERNAME"
    user_login_with_totp "User login"
    
    # Verify agent started automatically in the background
    assert_agent_running "Agent auto-start verification"

    success "User login phase complete"
}

# Global variables for file reuse between phases
UPLOADED_FILE_ID=""
UPLOADED_FILE_SHA256=""

# Custom-password file global variables (populated by phase_9)
CUSTOM_FILE_ID=""
CUSTOM_FILE_SHA256=""

# Share D ID - share created from custom-password file (populated by phase_10)
SHARE_D_ID=""

# Phase 9: Custom-Password File Operations
phase_9_custom_password_file_operations() {
    phase "9: CUSTOM-PASSWORD FILE OPERATIONS (account-key wrapped FEK)"

    local custom_test_file="$TEST_DATA_DIR/custom_test_file.bin"

    # 9.1: Generate a small test file
    section "Generating custom-password test file (1MB, random)"
    local gen_output gen_exit_code
    safe_exec gen_output gen_exit_code \
        $CLIENT generate-test-file \
        --filename "$custom_test_file" \
        --size 1048576 \
        --pattern random

    if [ $gen_exit_code -eq 0 ]; then
        record_test "Custom test file creation" "PASS"
        CUSTOM_FILE_SHA256=$(sha256sum "$custom_test_file" | awk '{print $1}')
        info "Custom file SHA-256: $CUSTOM_FILE_SHA256"
    else
        error "Failed to generate custom test file:"; echo "$gen_output"
        record_test "Custom test file creation" "FAIL"
    fi

    # 9.2: Upload with custom password
    # CLI prompts for: custom password (once) + confirmation (once)
    section "Uploading file with custom password"
    local custom_upload_output custom_upload_exit_code
    safe_exec custom_upload_output custom_upload_exit_code \
        bash -c "printf '%s\n%s\n' '$CUSTOM_FILE_PASSWORD' '$CUSTOM_FILE_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        upload \
        --file '$custom_test_file' \
        --password-type custom"

    if [ $custom_upload_exit_code -eq 0 ]; then
        CUSTOM_FILE_ID=$(echo "$custom_upload_output" | grep "File ID:" | awk '{print $3}' | tr -d ' ')
        info "Custom-password File ID: $CUSTOM_FILE_ID"
        if [ -z "$CUSTOM_FILE_ID" ]; then
            warning "Could not extract File ID from custom upload output"
        fi
        record_test "Custom file upload" "PASS"
    else
        error "Custom file upload failed:"; echo "$custom_upload_output"
        record_test "Custom file upload" "FAIL"
    fi

    # 9.3: Verify raw API privacy - plaintext filename must not appear in raw list output
    section "Verifying raw API privacy for custom-password file"
    local list_raw_output list_raw_exit_code
    safe_exec list_raw_output list_raw_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files --raw

    if echo "$list_raw_output" | grep -q "custom_test_file.bin" || echo "$list_raw_output" | grep -q "$CUSTOM_FILE_SHA256"; then
        error "Security failure: Raw list API exposed plaintext name or hash for custom-password file!"
        record_test "Raw List API Privacy (custom file)" "FAIL"
    else
        record_test "Raw List API Privacy (custom file)" "PASS"
    fi

    # 9.4: Verify custom file is accessible via normal list-files (account-key metadata context works)
    # This proves the server-side metadata record is reachable through the CLI's own decryption flow.
    section "Verifying custom-password file is accessible via list-files"
    local custom_list_output custom_list_exit_code
    safe_exec custom_list_output custom_list_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files

    if [ $custom_list_exit_code -eq 0 ] && echo "$custom_list_output" | grep -q "$CUSTOM_FILE_ID"; then
        record_test "Custom file accessible via list-files" "PASS"
        info "Custom-password file $CUSTOM_FILE_ID found in file list"
    else
        error "Custom file not found in list-files output:"
        echo "$custom_list_output"
        record_test "Custom file accessible via list-files" "FAIL"
    fi

    # 9.5: Download with correct custom password - owner round-trip
    section "Downloading custom-password file (correct password)"
    local custom_dl_file="$TEST_DATA_DIR/custom_downloaded.bin"
    local custom_dl_output custom_dl_exit_code
    safe_exec custom_dl_output custom_dl_exit_code \
        bash -c "printf '%s\n' '$CUSTOM_FILE_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        download \
        --file-id '$CUSTOM_FILE_ID' \
        --output '$custom_dl_file'"

    if [ $custom_dl_exit_code -eq 0 ]; then
        record_test "Custom file download (correct password)" "PASS"
    else
        error "Custom file download failed:"; echo "$custom_dl_output"
        record_test "Custom file download (correct password)" "FAIL"
    fi

    # 9.6: SHA-256 round-trip integrity
    assert_sha256_matches "$custom_dl_file" "$CUSTOM_FILE_SHA256" "Custom file SHA256 integrity"
    rm -f "$custom_dl_file"

    # 9.7: Download with wrong custom password - must fail
    section "Downloading custom-password file (wrong password - must fail)"
    local custom_dl_bad_file="$TEST_DATA_DIR/custom_bad_dl.bin"
    local custom_dl_bad_output custom_dl_bad_exit_code
    safe_exec custom_dl_bad_output custom_dl_bad_exit_code \
        bash -c "printf '%s\n' '$WRONG_CUSTOM_FILE_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        download \
        --file-id '$CUSTOM_FILE_ID' \
        --output '$custom_dl_bad_file'"

    if [ $custom_dl_bad_exit_code -ne 0 ]; then
        record_test "Custom file download rejected (wrong password)" "PASS"
    else
        error "Security failure: Custom file downloaded with wrong password!"
        record_test "Custom file download rejected (wrong password)" "FAIL"
    fi
    assert_output_file_absent_or_empty "$custom_dl_bad_file" "Custom file bad password hygiene"

    rm -f "$custom_test_file"

    success "Custom-password file operations phase complete"
}

# Phase 8: File Operations
phase_8_file_operations() {
    phase "8: FILE OPERATIONS"

    local test_file="$TEST_DATA_DIR/test_file.bin"

    # 8.1: Generate test file using arkfile-client
    section "Generating test file (50MB, sequential pattern)"
    local gen_output
    local gen_exit_code

    safe_exec gen_output gen_exit_code \
        $CLIENT generate-test-file \
        --filename "$test_file" \
        --size 52428800 \
        --pattern sequential

    if [ $gen_exit_code -eq 0 ]; then
        record_test "Test file creation" "PASS"
        UPLOADED_FILE_SHA256=$(sha256sum "$test_file" | awk '{print $1}')
        info "File SHA-256: $UPLOADED_FILE_SHA256"
        info "File size: $(stat -c%s "$test_file" 2>/dev/null || stat -f%z "$test_file" 2>/dev/null) bytes"
    else
        error "Failed to generate test file:"
        echo "$gen_output"
        record_test "Test file creation" "FAIL"
    fi

    # 8.2: Upload file
    section "Uploading file (encryption handled by arkfile-client)"
    local upload_output
    local upload_exit_code

    safe_exec upload_output upload_exit_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$test_file" \
        --password-type account

    if [ $upload_exit_code -eq 0 ]; then
        UPLOADED_FILE_ID=$(echo "$upload_output" | grep "File ID:" | awk '{print $3}' | tr -d ' ')
        info "Uploaded File ID: $UPLOADED_FILE_ID"
        if [ -z "$UPLOADED_FILE_ID" ]; then
            warning "Could not extract File ID from upload output"
        fi
        record_test "File upload" "PASS"
    else
        error "Upload failed with output:"
        echo "$upload_output"
        record_test "File upload" "FAIL"
    fi

    # 8.3: List files to verify upload
    section "Listing files to verify upload"
    local list_output
    local list_exit_code

    safe_exec list_output list_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files

    if [ $list_exit_code -eq 0 ] && [ -n "$UPLOADED_FILE_ID" ] && echo "$list_output" | grep -q "$UPLOADED_FILE_ID"; then
        record_test "File listing verification" "PASS"
        info "Verified File ID $UPLOADED_FILE_ID in file list"
    else
        error "File not found in list:"
        echo "$list_output"
        record_test "File listing verification" "FAIL"
    fi
    
    # 8.4: Verify raw API privacy
    section "Verifying list-files --raw API privacy"
    local list_raw_output list_raw_exit_code
    safe_exec list_raw_output list_raw_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files --raw
        
    if echo "$list_raw_output" | grep -q "$UPLOADED_FILE_SHA256" || echo "$list_raw_output" | grep -q "test_file.bin"; then
        error "Security failure: Raw API list exposed plaintext filename or hashes!"
        record_test "Raw List API Privacy" "FAIL"
    else
        record_test "Raw List API Privacy" "PASS"
    fi

    # 8.5: Download file
    section "Downloading file (decryption handled by arkfile-client)"
    local downloaded_file="$TEST_DATA_DIR/downloaded.bin"
    local download_output
    local download_exit_code

    safe_exec download_output download_exit_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download \
        --file-id "$UPLOADED_FILE_ID" \
        --output "$downloaded_file"

    if [ $download_exit_code -eq 0 ]; then
        record_test "File download" "PASS"
    else
        error "Download failed with output:"
        echo "$download_output"
        record_test "File download" "FAIL"
    fi

    # 8.6: Verify content integrity (SHA256 round-trip)
    assert_sha256_matches "$downloaded_file" "$UPLOADED_FILE_SHA256" "Content integrity (SHA256 round-trip)"

    rm -f "$downloaded_file"

    # 8.7: Export as .arkbackup bundle
    section "Exporting file as .arkbackup bundle"
    local export_bundle="$TEST_DATA_DIR/e2e-export-$$.arkbackup"
    local export_result export_exit_code
    safe_exec export_result export_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        export --file-id "$UPLOADED_FILE_ID" --output "$export_bundle"

    if [ $export_exit_code -eq 0 ]; then
        record_test "File export (.arkbackup)" "PASS"
    else
        error "File export failed:"; echo "$export_result"
        record_test "File export (.arkbackup)" "FAIL"
    fi

    # 8.8: Verify bundle size is reasonable
    local bundle_size
    bundle_size=$(stat -c%s "$export_bundle" 2>/dev/null || echo 0)
    if [ "$bundle_size" -gt 1000 ]; then
        record_test "Bundle size check" "PASS"
        info "Bundle created: $bundle_size bytes"
    else
        error "Bundle file too small: $bundle_size bytes"
        record_test "Bundle size check" "FAIL"
    fi

    # 8.9: Offline decrypt the bundle (no network needed for decryption)
    section "Decrypting bundle offline"
    local decrypt_output="$TEST_DATA_DIR/e2e-decrypt-$$.dat"
    local decrypt_result decrypt_exit_code
    safe_exec decrypt_result decrypt_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $CLIENT \
        decrypt-blob \
        --bundle '$export_bundle' \
        --username '$TEST_USERNAME' \
        --password-stdin \
        --output '$decrypt_output'"

    if [ $decrypt_exit_code -eq 0 ]; then
        record_test "Offline decrypt (.arkbackup)" "PASS"
    else
        error "Offline decrypt failed:"; echo "$decrypt_result"
        record_test "Offline decrypt (.arkbackup)" "FAIL"
    fi

    # 8.10: Verify decrypted file matches original plaintext
    assert_sha256_matches "$decrypt_output" "$UPLOADED_FILE_SHA256" "Offline decrypt SHA-256 integrity"

    local decrypted_size
    decrypted_size=$(stat -c%s "$decrypt_output" 2>/dev/null || echo 0)
    if [ "$decrypted_size" -eq 52428800 ]; then
        record_test "Offline decrypt file size" "PASS"
        info "Decrypted file size matches original: $decrypted_size bytes"
    else
        error "Size mismatch! Expected: 52428800, Got: $decrypted_size"
        record_test "Offline decrypt file size" "FAIL"
    fi

    rm -f "$export_bundle" "$decrypt_output"

    # 8.11: File deletion (upload a file, delete it, verify gone)
    # Uses 2MB to exercise rqlite float64 scanning (numbers > ~1M come back
    # in scientific notation; a 1024-byte file would not catch that bug).
    section "8.11: File deletion test"
    local delete_test_file="$TEST_DATA_DIR/delete_test.bin"
    $CLIENT generate-test-file --filename "$delete_test_file" --size 2097152 --pattern random >/dev/null 2>&1

    local del_upload_output del_upload_exit_code
    safe_exec del_upload_output del_upload_exit_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$delete_test_file" \
        --password-type account

    if [ $del_upload_exit_code -ne 0 ]; then
        error "Failed to upload file for deletion test"
        record_test "File deletion (upload)" "FAIL"
    else
        local delete_file_id=$(echo "$del_upload_output" | grep "File ID:" | awk '{print $3}' | tr -d ' ')
        info "Uploaded delete-test file: $delete_file_id"

        local del_output del_exit_code
        safe_exec del_output del_exit_code \
            $CLIENT \
            --server-url "$SERVER_URL" \
            --tls-insecure \
            delete-file \
            --file-id "$delete_file_id" \
            --confirm

        if [ $del_exit_code -eq 0 ] && echo "$del_output" | grep -q "deleted successfully"; then
            record_test "File deletion" "PASS"

            local post_del_list post_del_list_code
            safe_exec post_del_list post_del_list_code \
                $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files --json

            if [ $post_del_list_code -eq 0 ] && ! echo "$post_del_list" | grep -q "$delete_file_id"; then
                record_test "File deletion verified (not in list)" "PASS"
            else
                record_test "File deletion verified (not in list)" "FAIL"
            fi
        else
            error "File deletion failed:"
            echo "$del_output"
            record_test "File deletion" "FAIL"
        fi
    fi
    rm -f "$delete_test_file"

    # 8.12: Duplicate upload rejection (dedup via digest cache)
    # The test file was uploaded in 8.2 and its SHA-256 is in the agent's digest cache.
    # Re-uploading the same file without --force must fail.
    section "Re-uploading same file (dedup rejection expected)"
    local dedup_upload_output dedup_upload_exit_code
    safe_exec dedup_upload_output dedup_upload_exit_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$test_file" \
        --password-type account

    if [ $dedup_upload_exit_code -ne 0 ] && echo "$dedup_upload_output" | grep -q "duplicate"; then
        record_test "Duplicate upload rejected (dedup)" "PASS"
    else
        error "Dedup failure: re-upload of identical file was not rejected!"
        echo "$dedup_upload_output"
        record_test "Duplicate upload rejected (dedup)" "FAIL"
    fi

    rm -f "$test_file"

    success "File operations phase complete"
}

# Phase 10: Share Operations
#
# Share A: No limits (unlimited access, no expiry)
# Share B: max_accesses=2
# Share C: expires_after=1m
# Share D: from custom-password-encrypted file (no expiry)
#
# Each share uses a unique password meeting share password requirements.
phase_10_share_operations() {
    phase "10: SHARE OPERATIONS"

    local SHARE_A_ID=""
    local SHARE_B_ID=""
    local SHARE_C_ID=""

    if [ -z "$UPLOADED_FILE_ID" ]; then
        error "Missing file ID from Phase 8"
        record_test "Phase 8 file data available" "FAIL"
    fi
    record_test "Phase 8 file data available" "PASS"
    info "Using file from Phase 8: File ID=$UPLOADED_FILE_ID"

    # 10.1: Create Share A - no limits (--expires 0 = no expiry)
    section "10.1: Creating Share A (no limits)"

    local create_a_output create_a_exit_code
    safe_exec create_a_output create_a_exit_code \
        bash -c "printf '%s\n' '$SHARE_A_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share create \
        --file-id '$UPLOADED_FILE_ID' \
        --expires 0"

    if [ $create_a_exit_code -eq 0 ]; then
        SHARE_A_ID=$(echo "$create_a_output" | grep "Share ID:" | awk '{print $3}' | tr -d ' ')
        info "Share A created: $SHARE_A_ID"
        record_test "Share A creation (no limits)" "PASS"
    else
        error "Share A creation failed:"; echo "$create_a_output"
        record_test "Share A creation (no limits)" "FAIL"
    fi

    # 10.2: Create Share B - max_accesses=2
    section "10.2: Creating Share B (max_accesses=2)"

    local create_b_output create_b_exit_code
    safe_exec create_b_output create_b_exit_code \
        bash -c "printf '%s\n' '$SHARE_B_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share create \
        --file-id '$UPLOADED_FILE_ID' \
        --expires 0 \
        --max-downloads 2"

    if [ $create_b_exit_code -eq 0 ]; then
        SHARE_B_ID=$(echo "$create_b_output" | grep "Share ID:" | awk '{print $3}' | tr -d ' ')
        info "Share B created: $SHARE_B_ID"
        record_test "Share B creation (max_accesses=2)" "PASS"
    else
        error "Share B creation failed:"; echo "$create_b_output"
        record_test "Share B creation (max_accesses=2)" "FAIL"
    fi
    
    # 10.3: Create Share C - expires_after=1m
    section "10.3: Creating Share C (expires_after=1m)"

    local SHARE_C_CREATED_AT
    SHARE_C_CREATED_AT=$(date +%s)

    local create_c_output create_c_exit_code
    safe_exec create_c_output create_c_exit_code \
        bash -c "printf '%s\n' '$SHARE_C_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share create \
        --file-id '$UPLOADED_FILE_ID' \
        --expires 1m"

    if [ $create_c_exit_code -eq 0 ]; then
        SHARE_C_ID=$(echo "$create_c_output" | grep "Share ID:" | awk '{print $3}' | tr -d ' ')
        info "Share C created: $SHARE_C_ID (expires in 1 min)"
        record_test "Share C creation (expires_after=1m)" "PASS"
    else
        error "Share C creation failed:"; echo "$create_c_output"
        record_test "Share C creation (expires_after=1m)" "FAIL"
    fi

    # 10.4: Create Share D - from custom-password-encrypted file (no expiry)
    # CLI stdin order for a custom-file share: custom password first, share password second
    section "10.4: Creating Share D (custom-password file, no expiry)"

    local create_d_output create_d_exit_code
    safe_exec create_d_output create_d_exit_code \
        bash -c "printf '%s\n%s\n' '$CUSTOM_FILE_PASSWORD' '$SHARE_D_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share create \
        --file-id '$CUSTOM_FILE_ID' \
        --expires 0"

    if [ $create_d_exit_code -eq 0 ]; then
        SHARE_D_ID=$(echo "$create_d_output" | grep "Share ID:" | awk '{print $3}' | tr -d ' ')
        info "Share D created: $SHARE_D_ID (from custom-password file)"
        record_test "Share D creation (custom-password file)" "PASS"
    else
        error "Share D creation failed:"; echo "$create_d_output"
        record_test "Share D creation (custom-password file)" "FAIL"
    fi

    # 10.5: List shares - verify all 4 appear
    section "10.5: Listing shares"

    local list_shares_output list_shares_exit_code
    safe_exec list_shares_output list_shares_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure share list

    if [ $list_shares_exit_code -eq 0 ] \
        && echo "$list_shares_output" | grep -qF -- "$SHARE_A_ID" \
        && echo "$list_shares_output" | grep -qF -- "$SHARE_B_ID" \
        && echo "$list_shares_output" | grep -qF -- "$SHARE_C_ID" \
        && echo "$list_shares_output" | grep -qF -- "$SHARE_D_ID"; then
        record_test "Share listing (all 4 shares)" "PASS"
    else
        error "Not all shares found in list:"; echo "$list_shares_output"
        record_test "Share listing (all 4 shares)" "FAIL"
    fi

    # Enrichment assertions — all reuse the already-captured list_shares_output variable

    # Both locally decrypted filenames must appear (account-password and custom-password)
    if echo "$list_shares_output" | grep -q "test_file.bin" \
        && echo "$list_shares_output" | grep -q "custom_test_"; then
        record_test "Share list shows locally decrypted filenames" "PASS"
    else
        error "Share list missing locally decrypted filenames:"; echo "$list_shares_output"
        record_test "Share list shows locally decrypted filenames" "FAIL"
    fi

    # No share should fall back to [encrypted] — all 4 must have been successfully enriched
    if echo "$list_shares_output" | grep -q "\[encrypted\]"; then
        error "Share list shows [encrypted] for at least one share — metadata enrichment failed:"
        echo "$list_shares_output"
        record_test "Share list enrichment succeeded for all shares" "FAIL"
    else
        record_test "Share list enrichment succeeded for all shares" "PASS"
    fi

    # Both password types must appear in the TYPE column
    if echo "$list_shares_output" | grep -q "account" \
        && echo "$list_shares_output" | grep -q "custom"; then
        record_test "Share list shows both account and custom password types" "PASS"
    else
        error "Share list missing expected password type(s):"; echo "$list_shares_output"
        record_test "Share list shows both account and custom password types" "FAIL"
    fi

    # The locally decrypted SHA-256 must appear in full in the block-format output.
    # Use an 8-char prefix to keep the grep pattern concise and robust.
    local sha256_prefix
    sha256_prefix="${UPLOADED_FILE_SHA256:0:8}"
    if echo "$list_shares_output" | grep -q "$sha256_prefix"; then
        record_test "Share list shows locally decrypted SHA-256" "PASS"
    else
        error "Share list missing SHA-256 prefix ($sha256_prefix):"; echo "$list_shares_output"
        record_test "Share list shows locally decrypted SHA-256" "FAIL"
    fi

    # Print share list for manual inspection
    info "Share list output (10.5):"
    echo "$list_shares_output"

    # 10.6: Share List Privacy Checks
    section "10.6: Verifying share list --raw API privacy"
    
    local list_shares_raw_output list_shares_raw_exit_code
    safe_exec list_shares_raw_output list_shares_raw_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure share list --raw
        
    # Raw GET /api/shares must not expose plaintext filenames for either share type
    if echo "$list_shares_raw_output" | grep -q "test_file.bin" || echo "$list_shares_raw_output" | grep -q "custom_test_file.bin"; then
        error "Security failure: Raw shares API list exposed plaintext filename!"
        record_test "Raw Shares API Privacy" "FAIL"
    else
        record_test "Raw Shares API Privacy" "PASS"
    fi

    # 10.7: Logout for anonymous visitor tests
    section "10.7: Logging out for anonymous visitor tests"
    logout_user_session "Logout for visitor tests"

    # 10.8: Visitor - Share A (unlimited) - should succeed
    section "10.8: Visitor downloads Share A (unlimited)"

    local dl_a_file="$TEST_DATA_DIR/share_a_download.bin"
    share_download_with_password "$SHARE_A_PASSWORD" "$SHARE_A_ID" "$dl_a_file" "Visitor download Share A" "false"

    # Verify SHA256
    assert_sha256_matches "$dl_a_file" "$UPLOADED_FILE_SHA256" "Share A SHA256 integrity"
    rm -f "$dl_a_file"

    # 10.9: Visitor - Share D (from custom-password file) - correct share password
    section "10.9: Visitor downloads Share D (custom-password file, correct share password)"

    sleep 2 # Rate limit buffer

    local dl_d_file="$TEST_DATA_DIR/share_d_download.bin"
    share_download_with_password "$SHARE_D_PASSWORD" "$SHARE_D_ID" "$dl_d_file" "Visitor download Share D" "false"

    # Verify the downloaded file matches the original custom-password file
    assert_sha256_matches "$dl_d_file" "$CUSTOM_FILE_SHA256" "Share D SHA256 integrity"
    rm -f "$dl_d_file"

    # 10.10: Visitor - Share A - intentionally wrong weak password
    section "10.10: Visitor attempts Share A with wrong weak password"
    
    sleep 2 # Rate limit buffer
    
    local dl_a_bad_file="$TEST_DATA_DIR/share_a_bad.bin"
    share_download_with_password "weakpassword123" "$SHARE_A_ID" "$dl_a_bad_file" "Visitor rejected with wrong bad password" "true"
    assert_output_file_absent_or_empty "$dl_a_bad_file" "Share A bad password file hygiene"

    # 10.11: Visitor - Share B (max_accesses=2) - download twice OK, 3rd fails
    section "10.11: Visitor tests Share B (max_accesses=2)"

    # Download 1 of 2
    local dl_b1_file="$TEST_DATA_DIR/share_b_dl1.bin"
    share_download_with_password "$SHARE_B_PASSWORD" "$SHARE_B_ID" "$dl_b1_file" "Share B download 1/2" "false"
    rm -f "$dl_b1_file"

    sleep 2  # Rate limit buffer

    # Download 2 of 2
    local dl_b2_file="$TEST_DATA_DIR/share_b_dl2.bin"
    share_download_with_password "$SHARE_B_PASSWORD" "$SHARE_B_ID" "$dl_b2_file" "Share B download 2/2" "false"
    rm -f "$dl_b2_file"

    sleep 2  # Rate limit buffer

    # Download 3 - should FAIL (max_accesses exceeded)
    local dl_b3_file="$TEST_DATA_DIR/share_b_dl3.bin"
    share_download_with_password "$SHARE_B_PASSWORD" "$SHARE_B_ID" "$dl_b3_file" "Share B download 3 rejected (max_accesses)" "true"
    assert_output_file_absent_or_empty "$dl_b3_file" "Share B rejected file hygiene"

    # 10.12: Visitor - Share C (expires_after=1m) - download before expiry OK
    section "10.12: Visitor tests Share C (expires_after=1m)"

    # Download before expiry - should succeed
    local dl_c1_file="$TEST_DATA_DIR/share_c_dl1.bin"
    share_download_with_password "$SHARE_C_PASSWORD" "$SHARE_C_ID" "$dl_c1_file" "Share C download before expiry" "false"
    rm -f "$dl_c1_file"

    # Smart sleep: wait only the remaining time until 1 min after creation + 5s buffer
    local now_ts
    now_ts=$(date +%s)
    local expiry_ts=$((SHARE_C_CREATED_AT + 60 + 5))
    local wait_seconds=$((expiry_ts - now_ts))
    if [ $wait_seconds -lt 0 ]; then
        wait_seconds=0
    fi
    info "Smart sleep: waiting ${wait_seconds}s for Share C to expire..."
    sleep "$wait_seconds"

    # Download after expiry - should FAIL
    local dl_c2_file="$TEST_DATA_DIR/share_c_dl2.bin"
    share_download_with_password "$SHARE_C_PASSWORD" "$SHARE_C_ID" "$dl_c2_file" "Share C download after expiry rejected" "true"
    assert_output_file_absent_or_empty "$dl_c2_file" "Share C rejected file hygiene"

    # 10.13: Negative test - non-existent share
    section "10.13: Negative test - non-existent share"

    sleep 2  # Rate limit buffer

    share_download_with_password "$DUMMY_SHARE_PASSWORD" "$NONEXISTENT_SHARE_ID" "$TEST_DATA_DIR/nonexistent.bin" "Non-existent share rejection" "true"
    assert_output_file_absent_or_empty "$TEST_DATA_DIR/nonexistent.bin" "Non-existent share file hygiene"

    # 10.14: Re-login, revoke Share A, verify revoked share fails
    section "10.14: Re-authenticating to revoke Share A"
    user_login_with_totp "Re-authentication for revoke"

    # Revoke Share A
    local revoke_output revoke_exit_code
    safe_exec revoke_output revoke_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
            share revoke --share-id "$SHARE_A_ID"

    if [ $revoke_exit_code -eq 0 ]; then
        record_test "Share A revocation" "PASS"
        info "Share A revoked successfully"
    else
        error "Failed to revoke Share A:"; echo "$revoke_output"
        record_test "Share A revocation" "FAIL"
    fi

    # Verify revoked share cannot be downloaded
    sleep 2

    local revoked_dl_output revoked_dl_exit_code
    share_download_with_password "$SHARE_A_PASSWORD" "$SHARE_A_ID" "$TEST_DATA_DIR/revoked.bin" "Revoked Share A download rejected" "true"
    assert_output_file_absent_or_empty "$TEST_DATA_DIR/revoked.bin" "Revoked Share A file hygiene"

    # 10.15: Verify share list reflects revoked status for Share A
    section "10.15: Verifying revoked share state in share list"
    local share_list_post_revoke_output share_list_post_revoke_exit_code
    safe_exec share_list_post_revoke_output share_list_post_revoke_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure share list

    # The CLI now renders shares as a per-share block.
    # Assert the revoked Share A ID appears AND "Active:    no" appears in the output.
    if [ $share_list_post_revoke_exit_code -eq 0 ] \
        && echo "$share_list_post_revoke_output" | grep -qF -- "$SHARE_A_ID" \
        && echo "$share_list_post_revoke_output" | grep -q "Active:.*no"; then
        record_test "Share list reflects revoked state" "PASS"
        info "Revoked Share A shows Active: no in share list"
    else
        error "Share list does not show Share A as inactive:"
        echo "$share_list_post_revoke_output"
        record_test "Share list reflects revoked state" "FAIL"
    fi

    # Print post-revoke share list for manual inspection
    info "Post-revoke share list output (10.15):"
    echo "$share_list_post_revoke_output"

    # 10.16: Contact info lifecycle tests (within active user session)
    section "10.16: Contact info - verify empty initially"
    local ci_get_empty_output ci_get_empty_code
    safe_exec ci_get_empty_output ci_get_empty_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure contact-info get
    if [ $ci_get_empty_code -eq 0 ] && echo "$ci_get_empty_output" | grep -q "No contact information set"; then
        record_test "contact-info get (empty)" "PASS"
    else
        echo "$ci_get_empty_output"
        record_test "contact-info get (empty)" "FAIL"
    fi

    section "10.17: Contact info - set with 2 contacts (email + signal)"
    local CI_JSON_2='{"display_name":"Test User","contacts":[{"type":"email","value":"test@example.com"},{"type":"signal","value":"+1234567890"}],"notes":"Test notes for admin"}'
    local ci_set2_output ci_set2_code
    safe_exec ci_set2_output ci_set2_code \
        bash -c "echo '${CI_JSON_2}' | $CLIENT --server-url '$SERVER_URL' --tls-insecure contact-info set --json -"
    if [ $ci_set2_code -eq 0 ] && echo "$ci_set2_output" | grep -q "saved successfully"; then
        record_test "contact-info set (2 contacts)" "PASS"
    else
        echo "$ci_set2_output"
        record_test "contact-info set (2 contacts)" "FAIL"
    fi

    section "10.18: Contact info - verify 2 contacts"
    local ci_get2_output ci_get2_code
    safe_exec ci_get2_output ci_get2_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure contact-info get
    if [ $ci_get2_code -eq 0 ] \
        && echo "$ci_get2_output" | grep -q "Test User" \
        && echo "$ci_get2_output" | grep -q "test@example.com" \
        && echo "$ci_get2_output" | grep -q "signal"; then
        record_test "contact-info get (2 contacts)" "PASS"
    else
        echo "$ci_get2_output"
        record_test "contact-info get (2 contacts)" "FAIL"
    fi
    info "Contact info output (10.18):"
    echo "$ci_get2_output"

    section "10.19: Contact info - update to 3 contacts (add telegram)"
    local CI_JSON_3='{"display_name":"Test User","contacts":[{"type":"email","value":"test@example.com"},{"type":"signal","value":"+1234567890"},{"type":"telegram","value":"@testuser"}],"notes":"Updated notes"}'
    local ci_set3_output ci_set3_code
    safe_exec ci_set3_output ci_set3_code \
        bash -c "echo '${CI_JSON_3}' | $CLIENT --server-url '$SERVER_URL' --tls-insecure contact-info set --json -"
    if [ $ci_set3_code -eq 0 ] && echo "$ci_set3_output" | grep -q "saved successfully"; then
        record_test "contact-info set (3 contacts)" "PASS"
    else
        echo "$ci_set3_output"
        record_test "contact-info set (3 contacts)" "FAIL"
    fi

    section "10.20: Contact info - verify 3 contacts"
    local ci_get3_output ci_get3_code
    safe_exec ci_get3_output ci_get3_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure contact-info get
    if [ $ci_get3_code -eq 0 ] \
        && echo "$ci_get3_output" | grep -q "test@example.com" \
        && echo "$ci_get3_output" | grep -q "signal" \
        && echo "$ci_get3_output" | grep -q "telegram"; then
        record_test "contact-info get (3 contacts)" "PASS"
    else
        echo "$ci_get3_output"
        record_test "contact-info get (3 contacts)" "FAIL"
    fi

    section "10.21: Contact info - update to 2 contacts (remove signal, keep email + telegram)"
    local CI_JSON_FINAL='{"display_name":"Test User","contacts":[{"type":"email","value":"test@example.com"},{"type":"telegram","value":"@testuser"}],"notes":"Final notes for admin"}'
    local ci_set_final_output ci_set_final_code
    safe_exec ci_set_final_output ci_set_final_code \
        bash -c "echo '${CI_JSON_FINAL}' | $CLIENT --server-url '$SERVER_URL' --tls-insecure contact-info set --json -"
    if [ $ci_set_final_code -eq 0 ] && echo "$ci_set_final_output" | grep -q "saved successfully"; then
        record_test "contact-info set (final 2 contacts)" "PASS"
    else
        echo "$ci_set_final_output"
        record_test "contact-info set (final 2 contacts)" "FAIL"
    fi

    section "10.22: Contact info - verify final state (2 contacts, no signal)"
    local ci_get_final_output ci_get_final_code
    safe_exec ci_get_final_output ci_get_final_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure contact-info get
    if [ $ci_get_final_code -eq 0 ] \
        && echo "$ci_get_final_output" | grep -q "test@example.com" \
        && echo "$ci_get_final_output" | grep -q "telegram" \
        && ! echo "$ci_get_final_output" | grep -q "signal"; then
        record_test "contact-info get (final 2, no signal)" "PASS"
    else
        echo "$ci_get_final_output"
        record_test "contact-info get (final 2, no signal)" "FAIL"
    fi
    info "Final contact info output (10.22):"
    echo "$ci_get_final_output"

    # 10.23: Explicit user logout, then verify authenticated commands fail
    section "10.23: User logout and post-logout unauthorized-command checks"
    logout_user_session "User logout (post-revoke)"

    # 10.16.1: list-files must fail after logout
    local post_logout_list_output post_logout_list_exit_code
    safe_exec post_logout_list_output post_logout_list_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files
    if [ $post_logout_list_exit_code -ne 0 ]; then
        record_test "list-files rejected after logout" "PASS"
    else
        error "Security failure: list-files succeeded after logout!"
        record_test "list-files rejected after logout" "FAIL"
    fi

    # 10.16.2: download must fail after logout
    local post_logout_dl_output post_logout_dl_exit_code
    safe_exec post_logout_dl_output post_logout_dl_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        download --file-id "$UPLOADED_FILE_ID" \
        --output "$TEST_DATA_DIR/post_logout_dl.bin"
    if [ $post_logout_dl_exit_code -ne 0 ]; then
        record_test "download rejected after logout" "PASS"
    else
        error "Security failure: download succeeded after logout!"
        record_test "download rejected after logout" "FAIL"
    fi
    rm -f "$TEST_DATA_DIR/post_logout_dl.bin"

    # 10.16.3: share create must fail after logout
    local post_logout_share_create_output post_logout_share_create_exit_code
    safe_exec post_logout_share_create_output post_logout_share_create_exit_code \
        bash -c "printf '%s\n' 'SomeSharePwd2026!Test' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share create \
        --file-id '$UPLOADED_FILE_ID' \
        --expires 0"
    if [ $post_logout_share_create_exit_code -ne 0 ]; then
        record_test "share create rejected after logout" "PASS"
    else
        error "Security failure: share create succeeded after logout!"
        record_test "share create rejected after logout" "FAIL"
    fi

    # 10.16.4: share revoke must fail after logout
    local post_logout_share_revoke_output post_logout_share_revoke_exit_code
    safe_exec post_logout_share_revoke_output post_logout_share_revoke_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        share revoke --share-id "$SHARE_A_ID"
    if [ $post_logout_share_revoke_exit_code -ne 0 ]; then
        record_test "share revoke rejected after logout" "PASS"
    else
        error "Security failure: share revoke succeeded after logout!"
        record_test "share revoke rejected after logout" "FAIL"
    fi

    success "Share operations phase complete"
}

# Phase 11: Admin System Status and Negative-Access Tests
phase_11_admin_system_status() {
    phase "11: ADMIN SYSTEM STATUS"

    section "Retrieving system status via admin CLI"

    local system_status_output
    local system_status_exit_code

    safe_exec system_status_output system_status_exit_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure system-status

    if [ $system_status_exit_code -eq 0 ]; then
        record_test "Admin system-status" "PASS"
        info "System status retrieved successfully"
        echo "$system_status_output"
    else
        error "system-status command failed:"
        echo "$system_status_output"
        record_test "Admin system-status" "FAIL"
    fi

    # Verify storage stats reflect uploaded files (2 files: account + custom)
    if echo "$system_status_output" | grep -q "Total Files: 2"; then
        record_test "Admin system-status file count" "PASS"
    else
        error "Storage stats: expected Total Files: 2"
        record_test "Admin system-status file count" "FAIL"
    fi

    # Total Size must not be zero (encrypted blobs are on disk)
    if echo "$system_status_output" | grep -q "Total Size: 0 B"; then
        error "Storage stats: Total Size is zero (size_bytes not stored correctly)"
        record_test "Admin system-status storage size non-zero" "FAIL"
    else
        record_test "Admin system-status storage size non-zero" "PASS"
    fi

    # 11.1: Admin reads test user's contact info (should see final 2 contacts from phase 10)
    section "11.1: Admin reads user contact info"
    local admin_ci_output admin_ci_code
    safe_exec admin_ci_output admin_ci_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        user-contact-info --username "$TEST_USERNAME"
    if [ $admin_ci_code -eq 0 ] \
        && echo "$admin_ci_output" | grep -q "Test User" \
        && echo "$admin_ci_output" | grep -q "test@example.com" \
        && echo "$admin_ci_output" | grep -q "telegram" \
        && ! echo "$admin_ci_output" | grep -q "signal"; then
        record_test "Admin reads user contact info (2 contacts, no signal)" "PASS"
    else
        echo "$admin_ci_output"
        record_test "Admin reads user contact info (2 contacts, no signal)" "FAIL"
    fi
    info "Admin contact info output (11.1):"
    echo "$admin_ci_output"

    # 11.2: Admin cannot access user file list via user-facing client CLI
    # The admin binary has its own saved session but $CLIENT uses the user session context,
    # which was logged out in phase 10.16. These commands must fail.
    section "11.1: Admin cannot access user files via user client"
    local admin_list_files_output admin_list_files_exit_code
    safe_exec admin_list_files_output admin_list_files_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files

    if [ $admin_list_files_exit_code -ne 0 ]; then
        record_test "Admin cannot list user files via user client" "PASS"
    else
        error "Security failure: user file list accessible without valid user session!"
        record_test "Admin cannot list user files via user client" "FAIL"
    fi

    # 11.2: Admin cannot download user file via user-facing client CLI
    section "11.2: Admin cannot download user file via user client"
    local admin_download_output admin_download_exit_code
    safe_exec admin_download_output admin_download_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        download --file-id "$UPLOADED_FILE_ID" \
        --output "$TEST_DATA_DIR/admin_dl_attempt.bin"

    if [ $admin_download_exit_code -ne 0 ]; then
        record_test "Admin cannot download user file via user client" "PASS"
    else
        error "Security failure: user file downloadable without valid user session!"
        record_test "Admin cannot download user file via user client" "FAIL"
    fi
    rm -f "$TEST_DATA_DIR/admin_dl_attempt.bin"

    # 11.3: Admin cannot access user share list via user-facing client CLI
    section "11.3: Admin cannot access user share list via user client"
    local admin_share_list_output admin_share_list_exit_code
    safe_exec admin_share_list_output admin_share_list_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure share list

    if [ $admin_share_list_exit_code -ne 0 ]; then
        record_test "Admin cannot list user shares via user client" "PASS"
    else
        error "Security failure: user share list accessible without valid user session!"
        record_test "Admin cannot list user shares via user client" "FAIL"
    fi

    success "Admin system status phase complete"
}

# Phase 12: Cleanup
phase_12_cleanup() {
    phase "12: CLEANUP"

    section "Cleaning up test data"

    # User was already logged out at the end of phase 10 (section 10.16).
    # Attempt logout again; ignore failure since session may already be gone.
    local out code
    safe_exec out code $CLIENT --server-url "$SERVER_URL" --tls-insecure logout || true
    info "User logout (idempotent - may already be logged out)"

    logout_admin_session "Admin logout"

    stop_agent

    assert_agent_not_running "Agent graceful shutdown via CLI"

    # Print detailed agent status for manual audit
    section "Post-shutdown agent status"
    local final_status
    final_status=$("$CLIENT" agent status 2>&1) || true
    echo "$final_status"
    echo "$final_status" >> "$LOG_FILE"

    success "Cleanup complete"
}

# Phase 13: Summary Report
phase_13_summary() {
    phase "13: TEST SUMMARY"

    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}           TEST RESULTS                 ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    for test_name in "${TEST_ORDER[@]}"; do
        local result="${TEST_RESULTS[$test_name]}"
        if [ "$result" = "PASS" ]; then
            success "$test_name"
        else
            error "$test_name"
        fi
    done

    echo ""
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Total Tests: $TEST_COUNT${NC}"
    echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
    echo -e "${RED}Failed: $FAIL_COUNT${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    echo ""

    if [ $FAIL_COUNT -eq 0 ]; then
        echo -e "${GREEN}  ALL TESTS PASSED SUCCESSFULLY!       ${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}========================================${NC}"
        echo -e "${RED}  SOME TESTS FAILED - REVIEW ABOVE     ${NC}"
        echo -e "${RED}========================================${NC}"
        echo ""
        return 1
    fi
}

# MAIN EXECUTION

# Ensure agent is stopped on exit (covers error paths too)
trap stop_agent EXIT

main() {
    echo -e "${CYAN}  ARKFILE E2E GO CLI CLIENT TEST      ${NC}"
    echo ""

    info "Server URL: $SERVER_URL"
    info "Admin User: $ADMIN_USERNAME"
    info "Test User: $TEST_USERNAME"
    info "Build Directory: $BUILD_DIR"
    if [ -n "$BOOTSTRAP_TOKEN" ]; then
        info "Bootstrap Token: PROVIDED (Protection test enabled)"
    else
        info "Bootstrap Token: NOT PROVIDED (Protection test disabled)"
    fi
    echo ""

    # Start the persistent agent before any CLI commands
    # (Agent auto-starts on login now per improved behavior)

    # Execute test phases
    phase_1_environment_verification
    phase_2_admin_authentication
    phase_3_bootstrap_protection
    phase_4_user_registration
    phase_5_totp_setup
    phase_6_admin_approval
    phase_7_user_login
    phase_8_file_operations
    phase_9_custom_password_file_operations
    phase_10_share_operations
    phase_11_admin_system_status
    phase_12_cleanup

    # Show summary and exit with appropriate code
    if phase_13_summary; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
