#!/bin/bash

# e2e-test.sh - End-to-End Testing
# Uses arkfile-client and arkfile-admin CLI tools
#
# Flow:
#   1. Environment verification (server, CLI tools, TOTP generator)
#   2. Admin authentication (login with TOTP)
#   3. Bootstrap protection (verify 2nd admin creation fails)
#   4. Regular user registration (using arkfile-client)
#   5. TOTP setup for regular user
#   6. Admin user management (list-users, user-status, approve-user)
#   7. Regular user login with TOTP
#   8. File operations (upload/download/list/delete)
#   9. Share operations (create/access/revoke)
#   10. Admin system status
#   11. Cleanup
#   12. Summary report

set -eo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

# Parse arguments
BOOTSTRAP_TOKEN=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --bootstrap-token) BOOTSTRAP_TOKEN="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Test configuration - EXACT CREDENTIALS (as specified by user)
ADMIN_USERNAME="${ADMIN_USERNAME:-arkfile-dev-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-DevAdmin2025!SecureInitialPassword}"
ADMIN_TOTP_SECRET="ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"  # Fixed dev secret

TEST_USERNAME="${TEST_USERNAME:-arkfile-dev-test-user}"
TEST_PASSWORD="${TEST_PASSWORD:-MyVacation2025PhotosForFamily!ExtraSecure}"

SERVER_URL="${SERVER_URL:-https://localhost:8443}"

# Binary location detection - check local build first, then deployed location
if [ -d "./build/bin" ] && [ -x "./build/bin/arkfile-client" ]; then
    BUILD_DIR="./build/bin"
elif [ -d "./build" ] && [ -x "./build/arkfile-client" ]; then
    BUILD_DIR="./build"
elif [ -d "/opt/arkfile/bin" ] && [ -x "/opt/arkfile/bin/arkfile-client" ]; then
    BUILD_DIR="/opt/arkfile/bin"
else
    BUILD_DIR="./build"  # Default fallback
fi

CLIENT="$BUILD_DIR/arkfile-client"
ADMIN="$BUILD_DIR/arkfile-admin"

# Test Data Directory (for persistent secrets across runs)
# MUST be in /tmp as per user requirement
TEST_DATA_DIR="/tmp/arkfile-e2e-test-data"
mkdir -p "$TEST_DATA_DIR"
TOTP_SECRET_FILE="$TEST_DATA_DIR/totp-secret"
LOG_FILE="$TEST_DATA_DIR/e2e-test.log"

# Initialize log file
echo "=== ARKFILE E2E TEST LOG - $(date) ===" > "$LOG_FILE"

# ============================================================================
# COLOR OUTPUT
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

success() { echo -e "${GREEN}[OK] $1${NC}"; echo "[OK] $1" >> "$LOG_FILE"; }
error() { echo -e "${RED}[X] $1${NC}"; echo "[ERROR] $1" >> "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[!] $1${NC}"; echo "[WARN] $1" >> "$LOG_FILE"; }
info() { echo -e "${CYAN}[i] $1${NC}"; echo "[INFO] $1" >> "$LOG_FILE"; }
section() { echo -e "\n${BLUE}$1${NC}"; echo -e "\n=== $1 ===" >> "$LOG_FILE"; }
phase() { echo -e "\n${CYAN}>>> PHASE: $1${NC}\n"; echo -e "\n>>> PHASE: $1" >> "$LOG_FILE"; }

# ============================================================================
# TEST RESULT TRACKING
# ============================================================================

declare -A TEST_RESULTS
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

record_test() {
    local test_name="$1"
    local result="$2"  # "PASS" or "FAIL"
    
    TEST_RESULTS["$test_name"]="$result"
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

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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

# Generate TOTP code using the totp-generator utility
generate_totp() {
    local secret="$1"
    local timestamp="${2:-}"
    
    if [ -x "./scripts/testing/totp-generator" ]; then
        if [ -n "$timestamp" ]; then
            ./scripts/testing/totp-generator "$secret" "$timestamp" 2>/dev/null
        else
            ./scripts/testing/totp-generator "$secret" 2>/dev/null
        fi
    else
        error "TOTP generator not found at ./scripts/testing/totp-generator"
        return 1
    fi
}

# Build TOTP generator if needed
build_totp_generator() {
    if [ ! -x "./scripts/testing/totp-generator" ]; then
        if [ -f "./scripts/testing/totp-generator.go" ]; then
            info "Building TOTP generator..."
            cd scripts/testing && go build -o totp-generator totp-generator.go && cd - >/dev/null
            if [ -x "./scripts/testing/totp-generator" ]; then
                success "TOTP generator built successfully"
                return 0
            else
                error "Failed to build TOTP generator"
                return 1
            fi
        else
            error "TOTP generator source not found"
            return 1
        fi
    fi
    return 0
}

# Wait for next TOTP window to avoid replay protection
wait_for_totp_window() {
    local current_seconds=$(date +%s)
    local seconds_into_window=$((current_seconds % 30))
    local seconds_to_wait=$((30 - seconds_into_window))
    
    info "Waiting ${seconds_to_wait}s + 2s buffer for next TOTP window (replay protection)..."
    sleep "$((seconds_to_wait + 2))"
}

# ============================================================================
# TEST PHASES
# ============================================================================

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
    
    # Check arkfile-client
    if [ -x "$CLIENT" ]; then
        record_test "arkfile-client available" "PASS"
        info "Using arkfile-client from: $CLIENT"
    else
        record_test "arkfile-client available" "FAIL"
    fi
    
    # Check arkfile-admin
    if [ -x "$ADMIN" ]; then
        record_test "arkfile-admin available" "PASS"
        info "Using arkfile-admin from: $ADMIN"
    else
        record_test "arkfile-admin available" "FAIL"
    fi
    
    section "Checking TOTP generator"
    if build_totp_generator; then
        local test_code
        test_code=$(generate_totp "JBSWY3DPEHPK3PXP" "1609459200")
        if [ ${#test_code} -eq 6 ] && [[ "$test_code" =~ ^[0-9]+$ ]]; then
            record_test "TOTP generator working" "PASS"
        else
            record_test "TOTP generator working" "FAIL"
        fi
    else
        record_test "TOTP generator working" "FAIL"
    fi
    
    success "Environment verification complete"
}

# Phase 2: Admin Authentication
phase_2_admin_authentication() {
    phase "2: ADMIN AUTHENTICATION"
    
    section "Authenticating admin user: $ADMIN_USERNAME"
    
    wait_for_totp_window

    local admin_totp_code
    admin_totp_code=$(generate_totp "$ADMIN_TOTP_SECRET")
    
    if [ -z "$admin_totp_code" ] || [ ${#admin_totp_code} -ne 6 ]; then
        record_test "Admin TOTP generation" "FAIL"
    fi
    record_test "Admin TOTP generation" "PASS"
    
    info "Logging in as admin with TOTP code: $admin_totp_code"
    
    local login_output
    local login_exit_code
    
    safe_exec login_output login_exit_code \
        bash -c "printf '%s\n%s\n' '$ADMIN_PASSWORD' '$admin_totp_code' | $ADMIN \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            --username '$ADMIN_USERNAME' \
            login \
            --save-session"
    
    if [ $login_exit_code -eq 0 ] && echo "$login_output" | grep -q "Admin login successful"; then
        record_test "Admin login" "PASS"
        echo "$login_output"
    else
        error "Admin login failed:"
        echo "$login_output"
        record_test "Admin login" "FAIL"
    fi
    
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
        bash -c "printf 'AttackerPass123!\nAttackerPass123!\n' | $ADMIN \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        bootstrap \
        --token '$BOOTSTRAP_TOKEN' \
        --username 'attacker-admin'"
        
    if [ $boot_exit_code -eq 0 ]; then
        record_test "Bootstrap protection" "FAIL"
        error "Security Vulnerability: Able to create second admin via bootstrap!"
    else
        record_test "Bootstrap protection" "PASS"
        success "Bootstrap protection verified (request rejected)"
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
        record_test "TOTP setup initiation" "FAIL"
        error "Failed to extract TOTP secret from output:"
        echo "$setup_output"
        exit 1
    fi
    
    echo "$secret" > "$TOTP_SECRET_FILE"
    export TEST_USER_TOTP_SECRET="$secret"
    record_test "TOTP setup initiation" "PASS"
    info "Got TOTP secret: $secret"
    
    # Step 2: Generate code and verify
    local code
    code=$(generate_totp "$secret")
    
    if [ -z "$code" ]; then
        record_test "TOTP code generation" "FAIL"
        exit 1
    fi
    
    info "Generated verification code: $code"
    
    local verify_output
    local verify_exit_code
    
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

# Phase 6: Admin User Management (list-users, user-status, approve-user)
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
    
    if [ -z "$TEST_USER_TOTP_SECRET" ]; then
        record_test "User login" "FAIL"
        error "Missing TOTP secret from setup phase"
        exit 1
    fi

    wait_for_totp_window
    
    local user_totp_code
    user_totp_code=$(generate_totp "$TEST_USER_TOTP_SECRET")
    
    if [ -z "$user_totp_code" ]; then
        record_test "User TOTP generation" "FAIL"
        exit 1
    fi
    info "Generated TOTP code for login: $user_totp_code"
    
    local user_login_output
    local user_login_exit_code
    
    safe_exec user_login_output user_login_exit_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$user_totp_code' | $CLIENT \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            --username '$TEST_USERNAME' \
            login \
            --save-session"
    
    if [ $user_login_exit_code -eq 0 ] && echo "$user_login_output" | grep -q "Login successful"; then
        record_test "User login" "PASS"
        echo "$user_login_output"
    else
        error "User login failed:"
        echo "$user_login_output"
        record_test "User login" "FAIL"
    fi
    
    success "User login phase complete"
}

# Global variables for file reuse between phases
UPLOADED_FILE_ID=""
UPLOADED_FILE_SHA256=""

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
        
        # Capture SHA256 for later verification
        UPLOADED_FILE_SHA256=$(sha256sum "$test_file" | awk '{print $1}')
        info "File SHA-256: $UPLOADED_FILE_SHA256"
        info "File size: $(stat -c%s "$test_file" 2>/dev/null || stat -f%z "$test_file" 2>/dev/null) bytes"
    else
        record_test "Test file creation" "FAIL"
        error "Failed to generate test file"
        echo "$gen_output"
    fi

    # 8.2: Upload file (arkfile-client handles encryption internally)
    section "Uploading file (client-side encryption is automatic)"
    local upload_output
    local upload_exit_code
    
    safe_exec upload_output upload_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        upload \
        --file '$test_file' \
        --password-type account"
        
    if [ $upload_exit_code -eq 0 ]; then
        record_test "File upload (with auto-encryption)" "PASS"

        # Extract File ID from output
        UPLOADED_FILE_ID=$(echo "$upload_output" | grep "File ID:" | awk '{print $3}' | tr -d ' ')
        info "Uploaded File ID: $UPLOADED_FILE_ID"

        if [ -z "$UPLOADED_FILE_ID" ]; then
            warning "Could not extract File ID from upload output"
        fi
    else
        record_test "File upload (with auto-encryption)" "FAIL"
        error "Upload command failed:"
        echo "$upload_output"
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

    # 8.4: Download file (arkfile-client handles decryption internally)
    section "Downloading file (client-side decryption is automatic)"
    local downloaded_file="$TEST_DATA_DIR/downloaded.bin"
    local download_output
    local download_exit_code
    
    safe_exec download_output download_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        download \
        --file-id '$UPLOADED_FILE_ID' \
        --output '$downloaded_file'"
        
    if [ $download_exit_code -eq 0 ]; then
        record_test "File download (with auto-decryption)" "PASS"
    else
        record_test "File download (with auto-decryption)" "FAIL"
        error "Download failed"
        echo "$download_output"
    fi

    # 8.5: Verify content integrity (SHA256 round-trip)
    section "Verifying file content integrity"
    local downloaded_sha256=$(sha256sum "$downloaded_file" | awk '{print $1}')
    
    if [ "$UPLOADED_FILE_SHA256" == "$downloaded_sha256" ]; then
        record_test "Content integrity (SHA256 round-trip)" "PASS"
        info "SHA256 matches: $downloaded_sha256"
    else
        record_test "Content integrity (SHA256 round-trip)" "FAIL"
        error "SHA256 mismatch! Original: $UPLOADED_FILE_SHA256, Downloaded: $downloaded_sha256"
    fi
    
    # Cleanup local files (keep file on server for Phase 9)
    rm -f "$test_file" "$downloaded_file"
    
    success "File operations phase complete"
}

# Phase 9: Share Operations
# Uses arkfile-client which handles share envelope creation/decryption internally.
phase_9_share_operations() {
    phase "9: SHARE OPERATIONS"
    
    section "Testing share operations - using file from Phase 8"
    
    # Share password (distinct from user account password)
    local SHARE_PASSWORD="SecureFileShare#2026!TestEnv"
    local share_id=""
    
    # Verify we have the required data from Phase 8
    if [ -z "$UPLOADED_FILE_ID" ]; then
        record_test "Phase 8 file data available" "FAIL"
        error "Missing file ID from Phase 8"
        return 1
    fi
    record_test "Phase 8 file data available" "PASS"
    info "Using file from Phase 8: File ID=$UPLOADED_FILE_ID"
    
    # =========================================================================
    # 9.1: Create share (arkfile-client handles envelope creation internally)
    # =========================================================================
    section "9.1: Creating share (envelope creation is automatic)"
    
    local create_share_output
    local create_share_exit_code
    
    safe_exec create_share_output create_share_exit_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$SHARE_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share create \
        --file-id '$UPLOADED_FILE_ID'"
        
    if [ $create_share_exit_code -eq 0 ]; then
        record_test "Share creation" "PASS"

        # Extract share ID from output
        share_id=$(echo "$create_share_output" | grep "Share ID:" | awk '{print $3}' | tr -d ' ')
        info "Share created with ID: $share_id"

        if [ -z "$share_id" ]; then
            warning "Could not extract Share ID from share creation output"
        fi
    else
        record_test "Share creation" "FAIL"
        error "Share creation command failed:"
        echo "$create_share_output"
        return 1
    fi
    
    # =========================================================================
    # 9.2: List shares (authenticated)
    # =========================================================================
    section "9.2: Listing shares"
    
    local list_shares_output
    local list_shares_exit_code
    
    safe_exec list_shares_output list_shares_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure share list
        
    if [ $list_shares_exit_code -eq 0 ] && echo "$list_shares_output" | grep -q "$share_id"; then
        record_test "Share listing" "PASS"
        info "Share $share_id found in list"
    else
        record_test "Share listing" "FAIL"
        error "Share not found in list:"
        echo "$list_shares_output"
    fi
    
    # =========================================================================
    # 9.3: Logout and download share as visitor (unauthenticated)
    # =========================================================================
    section "9.3: Accessing share as visitor (unauthenticated)"
    
    info "Logging out to test visitor access..."
    local logout_output
    local logout_exit_code
    
    safe_exec logout_output logout_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure logout
    record_test "Logout for visitor test" "PASS"
    
    # Download shared file as visitor (arkfile-client handles envelope decryption)
    local shared_download_file="$TEST_DATA_DIR/shared_download.bin"
    local download_share_output
    local download_share_exit_code
    
    safe_exec download_share_output download_share_exit_code \
        bash -c "printf '%s\n' '$SHARE_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share download \
        --share-id '$share_id' \
        --output '$shared_download_file'"
        
    if [ $download_share_exit_code -eq 0 ]; then
        record_test "Visitor share download (with auto-decryption)" "PASS"
        info "Downloaded shared file to: $shared_download_file"
    else
        record_test "Visitor share download (with auto-decryption)" "FAIL"
        error "Visitor download failed:"
        echo "$download_share_output"
        return 1
    fi
    
    # =========================================================================
    # 9.4: Verify file integrity (SHA256)
    # =========================================================================
    section "9.4: Verifying shared file integrity"
    
    local decrypted_sha256=$(sha256sum "$shared_download_file" | awk '{print $1}')
    
    if [ "$decrypted_sha256" == "$UPLOADED_FILE_SHA256" ]; then
        record_test "Shared file SHA256 verification" "PASS"
        info "SHA256 matches: $decrypted_sha256"
    else
        record_test "Shared file SHA256 verification" "FAIL"
        error "SHA256 mismatch! Original: $UPLOADED_FILE_SHA256, Shared: $decrypted_sha256"
    fi
    
    # =========================================================================
    # 9.5: Negative tests
    # =========================================================================
    section "9.5: Negative tests"
    
    # Test: Non-existent share
    info "Testing non-existent share..."
    sleep 2  # Delay to avoid rate limiting
    
    local nonexistent_output
    local nonexistent_exit_code
    
    safe_exec nonexistent_output nonexistent_exit_code \
        bash -c "printf 'dummy\n' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share download \
        --share-id 'nonexistent-share-id-that-does-not-exist' \
        --output '$TEST_DATA_DIR/nonexistent.bin'"
        
    if [ $nonexistent_exit_code -ne 0 ]; then
        record_test "Non-existent share rejection" "PASS"
        info "Correctly rejected non-existent share"
    else
        record_test "Non-existent share rejection" "FAIL"
        error "Security failure: Non-existent share was accepted!"
    fi
    
    # =========================================================================
    # 9.6: Re-authenticate and revoke share
    # =========================================================================
    section "9.6: Re-authenticating and revoking share"
    
    wait_for_totp_window
    
    local user_totp_code
    user_totp_code=$(generate_totp "$TEST_USER_TOTP_SECRET")
    
    local relogin_output
    local relogin_exit_code
    
    safe_exec relogin_output relogin_exit_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$user_totp_code' | $CLIENT \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            --username '$TEST_USERNAME' \
            login \
            --save-session"
    
    if [ $relogin_exit_code -eq 0 ]; then
        record_test "Re-authentication for revoke" "PASS"
    else
        record_test "Re-authentication for revoke" "FAIL"
        error "Failed to re-authenticate:"
        echo "$relogin_output"
        return 1
    fi
    
    # Revoke share
    local revoke_output
    local revoke_exit_code
    
    safe_exec revoke_output revoke_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
            share delete --share-id "$share_id" --file-id "$UPLOADED_FILE_ID"
        
    if [ $revoke_exit_code -eq 0 ]; then
        record_test "Share revocation" "PASS"
        info "Share revoked successfully"
    else
        record_test "Share revocation" "FAIL"
        error "Failed to revoke share:"
        echo "$revoke_output"
    fi
    
    # Test that revoked share cannot be downloaded
    sleep 2  # Delay to avoid rate limiting
    
    local revoked_download_output
    local revoked_download_exit_code
    
    safe_exec revoked_download_output revoked_download_exit_code \
        bash -c "printf 'dummy\n' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        share download \
        --share-id '$share_id' \
        --output '$TEST_DATA_DIR/revoked.bin'"
        
    if [ $revoked_download_exit_code -ne 0 ]; then
        record_test "Revoked share rejection" "PASS"
        info "Correctly rejected revoked share download"
    else
        record_test "Revoked share rejection" "FAIL"
        error "Security failure: Revoked share was still accessible!"
    fi
    
    # Cleanup
    rm -f "$shared_download_file" "$TEST_DATA_DIR/nonexistent.bin" "$TEST_DATA_DIR/revoked.bin"
    
    success "Share operations phase complete"
}


# Phase 10: Admin System Status
phase_10_admin_system_status() {
    phase "10: ADMIN SYSTEM STATUS"
    
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
    
    success "Admin system status phase complete"
}

# Phase 11: Cleanup
phase_11_cleanup() {
    phase "11: CLEANUP"
    
    section "Cleaning up test data"
    
    # Logout user
    local user_logout_output
    local user_logout_exit_code
    
    safe_exec user_logout_output user_logout_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure logout
    record_test "User logout" "PASS"  # Not critical
    
    # Logout admin
    local admin_logout_output
    local admin_logout_exit_code
    
    safe_exec admin_logout_output admin_logout_exit_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure logout
    record_test "Admin logout" "PASS"  # Not critical
    
    success "Cleanup complete"
}

# Phase 12: Summary Report
phase_12_summary() {
    phase "12: TEST SUMMARY"
    
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}           TEST RESULTS                 ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    for test_name in "${!TEST_RESULTS[@]}"; do
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
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}  ALL TESTS PASSED SUCCESSFULLY!       ${NC}"
        echo -e "${GREEN}========================================${NC}"
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

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    echo -e "${CYAN}  ARKFILE E2E AUTHENTICATION TEST      ${NC}"
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
    
    # Execute test phases
    phase_1_environment_verification
    phase_2_admin_authentication
    phase_3_bootstrap_protection
    phase_4_user_registration
    phase_5_totp_setup
    phase_6_admin_approval
    phase_7_user_login
    phase_8_file_operations
    phase_9_share_operations
    phase_10_admin_system_status
    phase_11_cleanup
    
    # Show summary and exit with appropriate code
    if phase_12_summary; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
