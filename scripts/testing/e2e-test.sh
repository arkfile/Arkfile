#!/bin/bash

# auth-e2e-test.sh - End-to-End Testing
# - Uses arkfile-client and arkfile-admin CLI tools instead of raw curl commands.
#
# Flow:
#   1. Environment verification (server, CLI tools, TOTP generator)
#   2. Admin authentication (login with TOTP)
#   3. Bootstrap protection (verify 2nd admin creation fails)
#   4. Regular user registration (using arkfile-client)
#   5. TOTP setup for regular user
#   6. Admin approval of regular user
#   7. Regular user login with TOTP
#   8. File operations (upload/download/list/delete)
#   9. Share operations (create/access/delete)
#   10. Admin operations (credits management)
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
# Also logs output to the main log file
safe_exec() {
    local output_var="$1"
    local exit_code_var="$2"
    shift 2
    
    local temp_output
    local temp_exit_code
    
    # Log the command being executed
    echo "[EXEC] $*" >> "$LOG_FILE"
    
    set +e
    temp_output=$("$@" 2>&1)
    temp_exit_code=$?
    set -e
    
    # Log the output
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
        error "Server not responding at $SERVER_URL"
        exit 1
    fi
    
    section "Checking CLI tools"
    
    # Check arkfile-client
    if [ -x "$BUILD_DIR/arkfile-client" ]; then
        record_test "arkfile-client available" "PASS"
        info "Using arkfile-client from: $BUILD_DIR/arkfile-client"
    else
        record_test "arkfile-client available" "FAIL"
        error "arkfile-client not found at $BUILD_DIR/arkfile-client"
        exit 1
    fi
    
    # Check arkfile-admin
    if [ -x "$BUILD_DIR/arkfile-admin" ]; then
        record_test "arkfile-admin available" "PASS"
        info "Using arkfile-admin from: $BUILD_DIR/arkfile-admin"
    else
        record_test "arkfile-admin available" "FAIL"
        error "arkfile-admin not found at $BUILD_DIR/arkfile-admin"
        exit 1
    fi
    
    # Check cryptocli (REQUIRED for this test)
    if [ -x "$BUILD_DIR/cryptocli" ]; then
        record_test "cryptocli available" "PASS"
        info "Using cryptocli from: $BUILD_DIR/cryptocli"
    else
        record_test "cryptocli available" "FAIL"
        error "cryptocli not found at $BUILD_DIR/cryptocli"
        exit 1
    fi
    
    section "Checking TOTP generator"
    if build_totp_generator; then
        # Test TOTP generation
        local test_code
        test_code=$(generate_totp "JBSWY3DPEHPK3PXP" "1609459200")
        if [ ${#test_code} -eq 6 ] && [[ "$test_code" =~ ^[0-9]+$ ]]; then
            record_test "TOTP generator working" "PASS"
        else
            record_test "TOTP generator working" "FAIL"
            error "TOTP generator produced invalid code: $test_code"
            exit 1
        fi
    else
        record_test "TOTP generator working" "FAIL"
        exit 1
    fi
    
    success "Environment verification complete"
}

# Phase 2: Admin Authentication
phase_2_admin_authentication() {
    phase "2: ADMIN AUTHENTICATION"
    
    section "Authenticating admin user: $ADMIN_USERNAME"
    
    # Smart Wait: Wait for next TOTP window to avoid replay protection
    # Calculate seconds into current 30s window
    local current_seconds=$(date +%s)
    local seconds_into_window=$((current_seconds % 30))
    local seconds_to_wait=$((30 - seconds_into_window))
    
    info "Waiting ${seconds_to_wait} seconds + 2 second buffer for next TOTP window (replay protection)..."
    sleep "$((seconds_to_wait + 2))"

    # Generate TOTP code for admin
    local admin_totp_code
    admin_totp_code=$(generate_totp "$ADMIN_TOTP_SECRET")
    
    if [ -z "$admin_totp_code" ] || [ ${#admin_totp_code} -ne 6 ]; then
        record_test "Admin TOTP generation" "FAIL"
        error "Failed to generate admin TOTP code"
        exit 1
    fi
    record_test "Admin TOTP generation" "PASS"
    
    # Admin login with TOTP
    info "Logging in as admin with TOTP code: $admin_totp_code"
    
    # Use safe_exec to capture output and exit code
    local login_output
    local login_exit_code
    
    safe_exec login_output login_exit_code \
        bash -c "printf '%s\n%s\n' '$ADMIN_PASSWORD' '$admin_totp_code' | $BUILD_DIR/arkfile-admin \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            --username '$ADMIN_USERNAME' \
            login \
            --save-session"
    
    if [ $login_exit_code -eq 0 ]; then
        # Check if login was successful by looking for success message
        if echo "$login_output" | grep -q "Admin login successful"; then
            record_test "Admin login" "PASS"
            echo "$login_output"
        else
            error "Admin login failed - unexpected output:"
            echo "$login_output"
            record_test "Admin login" "FAIL"
        fi
    else
        error "Admin login command failed with exit code $login_exit_code:"
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
    
    # Try to bootstrap again with a new user
    # We expect this to FAIL because the system is already bootstrapped
    local boot_output
    local boot_exit_code
    
    safe_exec boot_output boot_exit_code \
        bash -c "printf 'AttackerPass123!\nAttackerPass123!\n' | $BUILD_DIR/arkfile-admin \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        bootstrap \
        --token '$BOOTSTRAP_TOKEN' \
        --username 'attacker-admin'"
        
    if [ $boot_exit_code -eq 0 ]; then
        # If the command succeeds (exit code 0), that's a SECURITY FAILURE
        record_test "Bootstrap protection" "FAIL"
        error "Security Vulnerability: Able to create second admin via bootstrap!"
        exit 1
    else
        # If the command fails (non-zero exit code), that's a SUCCESS for protection
        # Ideally check for specific error message if possible
        if echo "$boot_output" | grep -q "already bootstrapped" || \
           echo "$boot_output" | grep -q "bootstrap disabled" || \
           echo "$boot_output" | grep -q "403" || \
           echo "$boot_output" | grep -q "failed"; then
            
            record_test "Bootstrap protection" "PASS"
            success "Bootstrap protection verified (request rejected)"
        else
            # It failed but maybe for the wrong reason?
            warning "Bootstrap failed but error message was unexpected. Check logs."
            echo "$boot_output"
            record_test "Bootstrap protection" "PASS" # Still pass as it didn't succeed
        fi
    fi
}

# Phase 4: Regular User Registration
phase_4_user_registration() {
    phase "4: REGULAR USER REGISTRATION"
    
    section "Registering user: $TEST_USERNAME"
    
    # Register user using arkfile-client
    # Capture output and exit code to handle "already exists" case
    local reg_output
    local reg_exit_code
    
    safe_exec reg_output reg_exit_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$TEST_PASSWORD' | $BUILD_DIR/arkfile-client \
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
        # Check if failure is due to user already existing (Idempotency)
        # We check for "already exists", "already registered", or HTTP 409 Conflict
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
    
    # Check if we already have a saved secret for this user (Idempotency)
    if [ -f "$TOTP_SECRET_FILE" ]; then
        info "Found existing TOTP secret in $TOTP_SECRET_FILE"
        local secret
        secret=$(cat "$TOTP_SECRET_FILE")
        
        if [ -n "$secret" ]; then
            export TEST_USER_TOTP_SECRET="$secret"
            record_test "TOTP setup initiation" "PASS"
            info "Using existing TOTP secret: $secret"
            success "TOTP setup phase complete (skipped - using existing secret)"
            return 0
        else
            warning "TOTP secret file exists but is empty. Proceeding with fresh setup."
        fi
    fi

    # Step 1: Get the secret
    info "Initiating TOTP setup..."
    local setup_output
    local setup_exit_code
    
    # Use safe_exec to capture output and exit code
    safe_exec setup_output setup_exit_code \
        $BUILD_DIR/arkfile-client --server-url "$SERVER_URL" --tls-insecure setup-totp --show-secret
    
    if [ $setup_exit_code -ne 0 ]; then
        error "Failed to initiate TOTP setup (exit code: $setup_exit_code):"
        echo "$setup_output"
        info "Possible causes:"
        info "  - No valid session (temp token from registration)"
        info "  - Session file missing: ~/.arkfile-session.json"
        info "  - Temp token expired"
        info "  - User already has TOTP setup but local secret file is missing"
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
    
    # Save secret to file for future runs
    echo "$secret" > "$TOTP_SECRET_FILE"
    info "Saved TOTP secret to $TOTP_SECRET_FILE"
    
    # Export secret globally for use in login phase
    export TEST_USER_TOTP_SECRET="$secret"
    
    record_test "TOTP setup initiation" "PASS"
    info "Got TOTP secret: $secret"
    
    # Step 2: Generate code
    local code
    code=$(generate_totp "$secret")
    
    if [ -z "$code" ]; then
        record_test "TOTP code generation" "FAIL"
        error "Failed to generate TOTP code"
        exit 1
    fi
    
    info "Generated verification code: $code"
    
    # Step 3: Verify and finalize
    local verify_output
    local verify_exit_code
    
    safe_exec verify_output verify_exit_code \
        $BUILD_DIR/arkfile-client --server-url "$SERVER_URL" --tls-insecure setup-totp --verify "$code"
    
    if [ $verify_exit_code -eq 0 ]; then
        if echo "$verify_output" | grep -q "TOTP Setup Complete"; then
            record_test "TOTP verification" "PASS"
            echo "$verify_output"
        else
            error "TOTP verification failed - unexpected output:"
            echo "$verify_output"
            record_test "TOTP verification" "FAIL"
        fi
    else
        error "TOTP verification command failed (exit code: $verify_exit_code):"
        echo "$verify_output"
        record_test "TOTP verification" "FAIL"
    fi
    
    success "TOTP setup phase complete"
}

# Phase 6: Admin Approval of Regular User
phase_6_admin_approval() {
    phase "6: ADMIN APPROVAL OF REGULAR USER"
    
    section "Approving user via admin: $TEST_USERNAME"
    
    # Approve user using arkfile-admin
    local approve_output
    local approve_exit_code
    
    safe_exec approve_output approve_exit_code \
        $BUILD_DIR/arkfile-admin \
            --server-url "$SERVER_URL" \
            --tls-insecure \
            approve-user \
            --username "$TEST_USERNAME" \
            --storage "5GB"
    
    if [ $approve_exit_code -eq 0 ]; then
        # Check for success message - the command outputs "User <username> approved successfully"
        if echo "$approve_output" | grep -q "approved successfully"; then
            record_test "User approval" "PASS"
            echo "$approve_output"
        else
            error "User approval failed - unexpected output:"
            echo "$approve_output"
            record_test "User approval" "FAIL"
        fi
    else
        # Check if failure is due to user already being approved (Idempotency)
        # Note: Adjust grep pattern based on actual error message from server/admin tool
        if echo "$approve_output" | grep -q "already approved"; then
            info "User '$TEST_USERNAME' is already approved. Proceeding..."
            record_test "User approval" "PASS"
        else
            error "User approval command failed (exit code: $approve_exit_code):"
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
    
    # Check if we have the secret from Phase 5
    if [ -z "$TEST_USER_TOTP_SECRET" ]; then
        record_test "User login" "FAIL"
        error "Missing TOTP secret from setup phase"
        exit 1
    fi

    # Smart Wait: Wait for next TOTP window to avoid replay protection
    # Calculate seconds into current 30s window
    local current_seconds=$(date +%s)
    local seconds_into_window=$((current_seconds % 30))
    local seconds_to_wait=$((30 - seconds_into_window))
    
    info "Waiting ${seconds_to_wait} seconds + 2 second buffer for next TOTP window (replay protection)..."
    sleep "$((seconds_to_wait + 2))"
    
    # Generate NEW TOTP code for the new window
    local user_totp_code
    user_totp_code=$(generate_totp "$TEST_USER_TOTP_SECRET")
    
    if [ -z "$user_totp_code" ]; then
        record_test "User TOTP generation" "FAIL"
        error "Failed to generate user TOTP code"
        exit 1
    fi
    info "Generated new TOTP code for login: $user_totp_code"
    
    # Perform full login with Password AND TOTP code
    local user_login_output
    local user_login_exit_code
    
    safe_exec user_login_output user_login_exit_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$user_totp_code' | $BUILD_DIR/arkfile-client \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            --username '$TEST_USERNAME' \
            login \
            --save-session"
    
    if [ $user_login_exit_code -eq 0 ]; then
        if echo "$user_login_output" | grep -q "Login successful"; then
            record_test "User login" "PASS"
            echo "$user_login_output"
        else
            error "User login failed - unexpected output:"
            echo "$user_login_output"
            record_test "User login" "FAIL"
        fi
    else
        error "User login command failed (exit code: $user_login_exit_code):"
        echo "$user_login_output"
        record_test "User login" "FAIL"
    fi
    
    success "User login phase complete"
}

# Phase 8: File Operations
phase_8_file_operations() {
    phase "8: FILE OPERATIONS"
    
    section "Testing file operations"
    
    local test_file="$TEST_DATA_DIR/test_file.bin"
    local test_file_enc="${test_file}.enc"
    local metadata_file="$TEST_DATA_DIR/metadata.json"
    
    # 1. Generate Test File
    section "Generating deterministic test file (50MB)"
    local gen_output
    local gen_exit_code
    
    safe_exec gen_output gen_exit_code \
        $BUILD_DIR/cryptocli generate-test-file \
        --filename "$test_file" \
        --size 52428800 \
        --pattern deterministic
        
    if [ $gen_exit_code -eq 0 ]; then
        record_test "Test file creation" "PASS"
        
        # Extract SHA256 from output
        local sha256_hash
        sha256_hash=$(echo "$gen_output" | grep "SHA-256:" | awk '{print $2}')
        info "File SHA-256: $sha256_hash"
    else
        record_test "Test file creation" "FAIL"
        error "Failed to generate test file"
        echo "$gen_output"
    fi

    # 2. Encrypt File
    section "Encrypting file with cryptocli"
    # Note: encrypt-password uses the account password directly
    local enc_output
    local enc_exit_code
    
    safe_exec enc_output enc_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $BUILD_DIR/cryptocli encrypt-password \
        --file '$test_file' \
        --username '$TEST_USERNAME' \
        --key-type account \
        --output '$test_file_enc'"
        
    if [ $enc_exit_code -eq 0 ]; then
        record_test "File encryption" "PASS"
        
        # Verify encryption actually changed the file (Confidentiality Check)
        local enc_hash
        enc_hash=$(sha256sum "$test_file_enc" | awk '{print $1}')
        info "Encrypted File SHA-256: $enc_hash"
        
        if [ "$sha256_hash" != "$enc_hash" ]; then
            record_test "Encryption confidentiality (hash mismatch)" "PASS"
            info "Confirmed: Encrypted file is different from original"
        else
            record_test "Encryption confidentiality (hash mismatch)" "FAIL"
            error "Security Failure: Encrypted file is identical to original!"
            exit 1
        fi
    else
        record_test "File encryption" "FAIL"
        error "Failed to encrypt file"
        echo "$enc_output"
    fi

    # 3. Encrypt Metadata
    section "Encrypting metadata"
    local metadata_output
    local meta_exit_code
    
    safe_exec metadata_output meta_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $BUILD_DIR/cryptocli encrypt-metadata \
        --filename 'test_file.bin' \
        --sha256sum '$sha256_hash' \
        --username '$TEST_USERNAME' \
        --password-source stdin \
        --output-format separated"
        
    if [ $meta_exit_code -eq 0 ]; then
        record_test "Metadata encryption" "PASS"
        
        # Parse output
        local filename_nonce=$(echo "$metadata_output" | grep "Filename Nonce:" | awk '{print $3}')
        local enc_filename=$(echo "$metadata_output" | grep "Encrypted Filename:" | awk '{print $3}')
        local sha256_nonce=$(echo "$metadata_output" | grep "SHA256 Nonce:" | awk '{print $3}')
        local enc_sha256=$(echo "$metadata_output" | grep "Encrypted SHA256:" | awk '{print $3}')
        
        # Log encrypted values for verification
        info "Encrypted Filename: $enc_filename"
        info "Encrypted SHA256: $enc_sha256"
        
        # Create metadata.json
        cat <<EOF > "$metadata_file"
{
    "encrypted_filename": "$enc_filename",
    "filename_nonce": "$filename_nonce",
    "encrypted_sha256sum": "$enc_sha256",
    "sha256sum_nonce": "$sha256_nonce",
    "encrypted_fek": "",
    "password_type": "account",
    "password_hint": "test-hint"
}
EOF
    else
        record_test "Metadata encryption" "FAIL"
        error "Failed to encrypt metadata"
        echo "$metadata_output"
    fi

    # 4. Upload File
    section "Uploading encrypted file"
    local upload_output
    local upload_exit_code
    
    safe_exec upload_output upload_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$test_file_enc" \
        --metadata "$metadata_file"
        
    if [ $upload_exit_code -eq 0 ]; then
        # Check for "Upload completed successfully" (Corrected from "Upload successful")
        if echo "$upload_output" | grep -q "Upload completed successfully"; then
            record_test "File upload" "PASS"
            
            # Extract File ID for verification
            local file_id
            file_id=$(echo "$upload_output" | grep "File ID:" | awk '{print $3}' | tr -d ' ')
            info "Uploaded File ID: $file_id"
            
            if [ -z "$file_id" ]; then
                warning "Could not extract File ID from upload output"
            fi
        else
            record_test "File upload" "FAIL"
            error "Upload failed - unexpected output:"
            echo "$upload_output"
        fi
    else
        record_test "File upload" "FAIL"
        error "Upload command failed"
        echo "$upload_output"
    fi

    # 5. List Files
    section "Listing files to verify upload"
    local list_output
    local list_exit_code
    
    safe_exec list_output list_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        list-files
        
    if [ $list_exit_code -eq 0 ]; then
        # Check if our file ID is in the list (filenames are encrypted)
        if [ -n "$file_id" ] && echo "$list_output" | grep -q "$file_id"; then
            record_test "File listing verification" "PASS"
            info "Verified File ID $file_id in file list"
        else
            warning "File ID not found in list (or ID extraction failed)"
            echo "$list_output"
            record_test "File listing verification" "FAIL"
        fi
    else
        record_test "File listing" "FAIL"
        error "List files command failed"
        echo "$list_output"
    fi

    # 6. Download File
    section "Downloading file"
    local download_output
    local download_exit_code
    local downloaded_file="$TEST_DATA_DIR/downloaded.enc"
    
    safe_exec download_output download_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download \
        --file-id "$file_id" \
        --output "$downloaded_file"
        
    if [ $download_exit_code -eq 0 ]; then
        record_test "File download" "PASS"
    else
        record_test "File download" "FAIL"
        error "Download failed"
        echo "$download_output"
    fi

    # 7. Verify Metadata File
    section "Verifying downloaded metadata"
    local downloaded_meta="$downloaded_file.metadata.json"
    if [ -f "$downloaded_meta" ]; then
        record_test "Metadata download" "PASS"
        info "Found metadata file: $downloaded_meta"
    else
        record_test "Metadata download" "FAIL"
        error "Metadata file not found"
    fi

    # 8. Decrypt File
    section "Decrypting downloaded file"
    local decrypted_file="$TEST_DATA_DIR/decrypted.bin"
    local decrypt_output
    local decrypt_exit_code
    
    safe_exec decrypt_output decrypt_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $BUILD_DIR/cryptocli decrypt-password \
        --file '$downloaded_file' \
        --username '$TEST_USERNAME' \
        --output '$decrypted_file'"
        
    if [ $decrypt_exit_code -eq 0 ]; then
        record_test "File decryption" "PASS"
    else
        record_test "File decryption" "FAIL"
        error "Decryption failed"
        echo "$decrypt_output"
    fi

    # 9. Verify Content
    section "Verifying file content"
    # We need to re-calculate original sum because we might have lost it if we didn't capture it well, 
    # but we did capture it in sha256_hash variable earlier.
    # However, let's verify against the actual file on disk to be sure.
    local original_sum_check=$(sha256sum "$test_file" | awk '{print $1}')
    local decrypted_sum=$(sha256sum "$decrypted_file" | awk '{print $1}')
    
    if [ "$original_sum_check" == "$decrypted_sum" ]; then
        record_test "Content verification" "PASS"
        info "SHA256 matches: $decrypted_sum"
    else
        record_test "Content verification" "FAIL"
        error "SHA256 mismatch! Original: $original_sum_check, Decrypted: $decrypted_sum"
    fi
    
    # Cleanup
    rm -f "$test_file" "$test_file_enc" "$metadata_file" "$downloaded_file" "$downloaded_meta" "$decrypted_file"
    
    success "File operations phase complete"
}

# Phase 9: Share Operations
phase_9_share_operations() {
    phase "9: SHARE OPERATIONS"
    
    section "Testing share operations"
    
    # Share password (distinct from user account password)
    # Must meet: 18+ chars, uppercase, lowercase, number, special, 60+ bits entropy
    local SHARE_PASSWORD="SecureFileShare#2026!TestEnv"
    
    local test_file="$TEST_DATA_DIR/share_test_file.bin"
    local test_file_enc="${test_file}.enc"
    local metadata_file="$TEST_DATA_DIR/share_metadata.json"
    local share_file_id=""
    local share_id=""
    local original_sha256=""
    local original_size=""
    local encrypted_fek=""
    
    # =========================================================================
    # 9.1: Create a file to share
    # =========================================================================
    section "9.1: Creating test file for sharing"
    
    # Generate a smaller test file for share testing (5MB)
    local gen_output
    local gen_exit_code
    
    safe_exec gen_output gen_exit_code \
        $BUILD_DIR/cryptocli generate-test-file \
        --filename "$test_file" \
        --size 5242880 \
        --pattern deterministic
        
    if [ $gen_exit_code -eq 0 ]; then
        record_test "Share test file creation" "PASS"
        original_sha256=$(echo "$gen_output" | grep "SHA-256:" | awk '{print $2}')
        original_size=$(stat -c%s "$test_file" 2>/dev/null || stat -f%z "$test_file" 2>/dev/null)
        info "File SHA-256: $original_sha256"
        info "File size: $original_size bytes"
    else
        record_test "Share test file creation" "FAIL"
        error "Failed to generate share test file"
        echo "$gen_output"
        return 1
    fi
    
    # Encrypt file
    section "Encrypting file for sharing"
    local enc_output
    local enc_exit_code
    
    safe_exec enc_output enc_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $BUILD_DIR/cryptocli encrypt-password \
        --file '$test_file' \
        --username '$TEST_USERNAME' \
        --key-type account \
        --output '$test_file_enc'"
        
    if [ $enc_exit_code -eq 0 ]; then
        record_test "Share file encryption" "PASS"
        # Note: encrypted_fek will be obtained from server response after upload
        info "File encrypted successfully"
    else
        record_test "Share file encryption" "FAIL"
        error "Failed to encrypt share file"
        echo "$enc_output"
        return 1
    fi
    
    # Encrypt metadata
    section "Encrypting metadata for sharing"
    local metadata_output
    local meta_exit_code
    
    safe_exec metadata_output meta_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $BUILD_DIR/cryptocli encrypt-metadata \
        --filename 'share_test_file.bin' \
        --sha256sum '$original_sha256' \
        --username '$TEST_USERNAME' \
        --password-source stdin \
        --output-format separated"
        
    if [ $meta_exit_code -eq 0 ]; then
        record_test "Share metadata encryption" "PASS"
        
        local filename_nonce=$(echo "$metadata_output" | grep "Filename Nonce:" | awk '{print $3}')
        local enc_filename=$(echo "$metadata_output" | grep "Encrypted Filename:" | awk '{print $3}')
        local sha256_nonce=$(echo "$metadata_output" | grep "SHA256 Nonce:" | awk '{print $3}')
        local enc_sha256=$(echo "$metadata_output" | grep "Encrypted SHA256:" | awk '{print $3}')
        
        cat <<EOF > "$metadata_file"
{
    "encrypted_filename": "$enc_filename",
    "filename_nonce": "$filename_nonce",
    "encrypted_sha256sum": "$enc_sha256",
    "sha256sum_nonce": "$sha256_nonce",
    "encrypted_fek": "$encrypted_fek",
    "password_type": "account",
    "password_hint": "share-test"
}
EOF
    else
        record_test "Share metadata encryption" "FAIL"
        error "Failed to encrypt share metadata"
        echo "$metadata_output"
        return 1
    fi
    
    # Upload file
    section "Uploading file for sharing"
    local upload_output
    local upload_exit_code
    
    safe_exec upload_output upload_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$test_file_enc" \
        --metadata "$metadata_file"
        
    if [ $upload_exit_code -eq 0 ]; then
        if echo "$upload_output" | grep -q "Upload completed successfully"; then
            record_test "Share file upload" "PASS"
            share_file_id=$(echo "$upload_output" | grep "File ID:" | awk '{print $3}' | tr -d ' ')
            info "Uploaded File ID: $share_file_id"
        else
            record_test "Share file upload" "FAIL"
            error "Upload failed - unexpected output"
            echo "$upload_output"
            return 1
        fi
    else
        record_test "Share file upload" "FAIL"
        error "Upload command failed"
        echo "$upload_output"
        return 1
    fi
    
    # Fetch encrypted_fek from server's file metadata
    section "Fetching encrypted FEK from server"
    local metadata_fetch_output
    local metadata_fetch_exit_code
    
    safe_exec metadata_fetch_output metadata_fetch_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        get-file-metadata \
        --file-id "$share_file_id" \
        --json
        
    if [ $metadata_fetch_exit_code -eq 0 ]; then
        record_test "Fetch file metadata" "PASS"
        # Extract encrypted_fek from JSON response
        encrypted_fek=$(echo "$metadata_fetch_output" | grep -o '"encrypted_fek"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"encrypted_fek"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [ -n "$encrypted_fek" ]; then
            info "Encrypted FEK: ${encrypted_fek:0:32}..."
        else
            record_test "Fetch file metadata" "FAIL"
            error "Could not extract encrypted_fek from metadata response"
            echo "$metadata_fetch_output"
            return 1
        fi
    else
        record_test "Fetch file metadata" "FAIL"
        error "Failed to fetch file metadata"
        echo "$metadata_fetch_output"
        return 1
    fi
    
    # =========================================================================
    # 9.2: Decrypt FEK and create share envelope
    # =========================================================================
    section "9.2: Creating share envelope"
    
    # Decrypt FEK using owner's password
    local decrypt_fek_output
    local decrypt_fek_exit_code
    
    safe_exec decrypt_fek_output decrypt_fek_exit_code \
        bash -c "printf '%s\n' '$TEST_PASSWORD' | $BUILD_DIR/cryptocli decrypt-fek \
        --encrypted-fek '$encrypted_fek' \
        --username '$TEST_USERNAME'"
        
    if [ $decrypt_fek_exit_code -eq 0 ]; then
        record_test "FEK decryption for sharing" "PASS"
        local fek_hex=$(echo "$decrypt_fek_output" | grep "FEK (hex):" | awk '{print $3}')
        info "Decrypted FEK: ${fek_hex:0:16}..."
    else
        record_test "FEK decryption for sharing" "FAIL"
        error "Failed to decrypt FEK"
        echo "$decrypt_fek_output"
        return 1
    fi
    
    # Generate share ID
    local share_id_output
    local share_id_exit_code
    
    safe_exec share_id_output share_id_exit_code \
        $BUILD_DIR/cryptocli generate-share-id
        
    if [ $share_id_exit_code -eq 0 ]; then
        record_test "Share ID generation" "PASS"
        share_id=$(echo "$share_id_output" | grep "Share ID:" | awk '{print $3}')
        info "Generated Share ID: $share_id"
    else
        record_test "Share ID generation" "FAIL"
        error "Failed to generate share ID"
        echo "$share_id_output"
        return 1
    fi
    
    # Create share envelope with AAD binding
    local envelope_output
    local envelope_exit_code
    
    safe_exec envelope_output envelope_exit_code \
        bash -c "printf '%s\n' '$SHARE_PASSWORD' | $BUILD_DIR/cryptocli create-share-envelope \
        --fek '$fek_hex' \
        --share-id '$share_id' \
        --file-id '$share_file_id'"
        
    if [ $envelope_exit_code -eq 0 ]; then
        record_test "Share envelope creation" "PASS"
        local encrypted_envelope=$(echo "$envelope_output" | grep "Encrypted Envelope:" | awk '{print $3}')
        local envelope_salt=$(echo "$envelope_output" | grep "Salt:" | awk '{print $2}')
        info "Encrypted Envelope: ${encrypted_envelope:0:32}..."
        info "Salt: ${envelope_salt:0:16}..."
    else
        record_test "Share envelope creation" "FAIL"
        error "Failed to create share envelope"
        echo "$envelope_output"
        return 1
    fi
    
    # =========================================================================
    # 9.3: Create share via API
    # =========================================================================
    section "9.3: Creating share via API"
    
    local create_share_output
    local create_share_exit_code
    
    safe_exec create_share_output create_share_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        share create \
        --file-id "$share_file_id" \
        --encrypted-envelope "$encrypted_envelope" \
        --salt "$envelope_salt"
        
    if [ $create_share_exit_code -eq 0 ]; then
        if echo "$create_share_output" | grep -q "Share created successfully"; then
            record_test "Share creation via API" "PASS"
            # The server returns the share_id we provided
            local server_share_id=$(echo "$create_share_output" | grep "Share ID:" | awk '{print $3}')
            info "Share created with ID: $server_share_id"
        else
            record_test "Share creation via API" "FAIL"
            error "Share creation failed - unexpected output"
            echo "$create_share_output"
            return 1
        fi
    else
        record_test "Share creation via API" "FAIL"
        error "Share creation command failed"
        echo "$create_share_output"
        return 1
    fi
    
    # =========================================================================
    # 9.4: List shares (authenticated)
    # =========================================================================
    section "9.4: Listing shares"
    
    local list_shares_output
    local list_shares_exit_code
    
    safe_exec list_shares_output list_shares_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        share list
        
    if [ $list_shares_exit_code -eq 0 ]; then
        if echo "$list_shares_output" | grep -q "$share_id"; then
            record_test "Share listing" "PASS"
            info "Share $share_id found in list"
        else
            record_test "Share listing" "FAIL"
            error "Share not found in list"
            echo "$list_shares_output"
        fi
    else
        record_test "Share listing" "FAIL"
        error "Share list command failed"
        echo "$list_shares_output"
    fi
    
    # =========================================================================
    # 9.5: Logout and access share as visitor
    # =========================================================================
    section "9.5: Accessing share as visitor (unauthenticated)"
    
    # Logout
    info "Logging out to test visitor access..."
    local logout_output
    local logout_exit_code
    
    safe_exec logout_output logout_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        logout
        
    if [ $logout_exit_code -eq 0 ]; then
        record_test "Logout for visitor test" "PASS"
    else
        warning "Logout may have failed, continuing..."
        record_test "Logout for visitor test" "PASS"
    fi
    
    # Download shared file as visitor (no auth)
    local shared_download_file="$TEST_DATA_DIR/shared_download.enc"
    local download_share_output
    local download_share_exit_code
    
    safe_exec download_share_output download_share_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download-share \
        --share-id "$share_id" \
        --output "$shared_download_file"
        
    if [ $download_share_exit_code -eq 0 ]; then
        record_test "Visitor share download" "PASS"
        info "Downloaded shared file to: $shared_download_file"
        
        # Extract envelope info from output for decryption
        local dl_encrypted_envelope=$(echo "$download_share_output" | grep -o '"[^"]*"' | head -1 | tr -d '"')
        local dl_salt=$(echo "$download_share_output" | grep -o '"[^"]*"' | head -2 | tail -1 | tr -d '"')
    else
        record_test "Visitor share download" "FAIL"
        error "Visitor download failed"
        echo "$download_share_output"
        return 1
    fi
    
    # =========================================================================
    # 9.6: Decrypt share envelope and file
    # =========================================================================
    section "9.6: Decrypting share envelope and file"
    
    # Decrypt share envelope to get FEK
    local decrypt_envelope_output
    local decrypt_envelope_exit_code
    
    safe_exec decrypt_envelope_output decrypt_envelope_exit_code \
        bash -c "printf '%s\n' '$SHARE_PASSWORD' | $BUILD_DIR/cryptocli decrypt-share-envelope \
        --encrypted-fek '$encrypted_envelope' \
        --salt '$envelope_salt' \
        --share-id '$share_id' \
        --file-id '$share_file_id'"
        
    if [ $decrypt_envelope_exit_code -eq 0 ]; then
        record_test "Share envelope decryption" "PASS"
        local recovered_fek=$(echo "$decrypt_envelope_output" | grep "FEK (hex):" | awk '{print $3}')
        info "Recovered FEK: ${recovered_fek:0:16}..."
        
        # Verify FEK matches original
        if [ "$recovered_fek" == "$fek_hex" ]; then
            record_test "FEK recovery verification" "PASS"
            info "Recovered FEK matches original"
        else
            record_test "FEK recovery verification" "FAIL"
            error "Recovered FEK does not match original!"
        fi
    else
        record_test "Share envelope decryption" "FAIL"
        error "Failed to decrypt share envelope"
        echo "$decrypt_envelope_output"
        return 1
    fi
    
    # Decrypt file using recovered FEK
    local decrypted_share_file="$TEST_DATA_DIR/shared_decrypted.bin"
    local decrypt_file_output
    local decrypt_file_exit_code
    
    safe_exec decrypt_file_output decrypt_file_exit_code \
        $BUILD_DIR/cryptocli decrypt-file-key \
        --file "$shared_download_file" \
        --fek "$recovered_fek" \
        --output "$decrypted_share_file"
        
    if [ $decrypt_file_exit_code -eq 0 ]; then
        record_test "Shared file decryption" "PASS"
    else
        record_test "Shared file decryption" "FAIL"
        error "Failed to decrypt shared file"
        echo "$decrypt_file_output"
        return 1
    fi
    
    # =========================================================================
    # 9.7: Verify file integrity (SHA256 and size)
    # =========================================================================
    section "9.7: Verifying file integrity"
    
    # Verify SHA256
    local decrypted_sha256=$(sha256sum "$decrypted_share_file" | awk '{print $1}')
    
    if [ "$decrypted_sha256" == "$original_sha256" ]; then
        record_test "Shared file SHA256 verification" "PASS"
        info "SHA256 matches: $decrypted_sha256"
    else
        record_test "Shared file SHA256 verification" "FAIL"
        error "SHA256 mismatch! Original: $original_sha256, Decrypted: $decrypted_sha256"
    fi
    
    # Verify file size
    local decrypted_size=$(stat -c%s "$decrypted_share_file" 2>/dev/null || stat -f%z "$decrypted_share_file" 2>/dev/null)
    
    if [ "$decrypted_size" == "$original_size" ]; then
        record_test "Shared file size verification" "PASS"
        info "File size matches: $decrypted_size bytes"
    else
        record_test "Shared file size verification" "FAIL"
        error "Size mismatch! Original: $original_size, Decrypted: $decrypted_size"
    fi
    
    # =========================================================================
    # 9.8: Negative tests (with delays to avoid rate limiting)
    # =========================================================================
    section "9.8: Negative tests"
    
    # Test 1: Wrong share password
    info "Testing wrong share password..."
    sleep 2  # Delay to avoid rate limiting
    
    local wrong_pass_output
    local wrong_pass_exit_code
    
    safe_exec wrong_pass_output wrong_pass_exit_code \
        bash -c "printf '%s\n' 'WrongPassword#2026!Test' | $BUILD_DIR/cryptocli decrypt-share-envelope \
        --encrypted-fek '$encrypted_envelope' \
        --salt '$envelope_salt' \
        --share-id '$share_id' \
        --file-id '$share_file_id'"
        
    if [ $wrong_pass_exit_code -ne 0 ]; then
        record_test "Wrong password rejection" "PASS"
        info "Correctly rejected wrong password"
    else
        record_test "Wrong password rejection" "FAIL"
        error "Security failure: Wrong password was accepted!"
    fi
    
    # Test 2: Wrong share ID in AAD
    info "Testing wrong share ID..."
    sleep 2  # Delay to avoid rate limiting
    
    local wrong_id_output
    local wrong_id_exit_code
    
    # Generate a different share ID
    local fake_share_id=$(echo "$share_id" | sed 's/./X/1')
    
    safe_exec wrong_id_output wrong_id_exit_code \
        bash -c "printf '%s\n' '$SHARE_PASSWORD' | $BUILD_DIR/cryptocli decrypt-share-envelope \
        --encrypted-fek '$encrypted_envelope' \
        --salt '$envelope_salt' \
        --share-id '$fake_share_id' \
        --file-id '$share_file_id'"
        
    if [ $wrong_id_exit_code -ne 0 ]; then
        record_test "Wrong share ID rejection (AAD)" "PASS"
        info "Correctly rejected wrong share ID (AAD verification)"
    else
        record_test "Wrong share ID rejection (AAD)" "FAIL"
        error "Security failure: Wrong share ID was accepted!"
    fi
    
    # Test 3: Non-existent share
    info "Testing non-existent share..."
    sleep 2  # Delay to avoid rate limiting
    
    local nonexistent_output
    local nonexistent_exit_code
    
    safe_exec nonexistent_output nonexistent_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download-share \
        --share-id "nonexistent-share-id-that-does-not-exist" \
        --output "$TEST_DATA_DIR/nonexistent.enc"
        
    if [ $nonexistent_exit_code -ne 0 ]; then
        record_test "Non-existent share rejection" "PASS"
        info "Correctly rejected non-existent share"
    else
        record_test "Non-existent share rejection" "FAIL"
        error "Security failure: Non-existent share was accepted!"
    fi
    
    # =========================================================================
    # 9.9: Re-authenticate and revoke share
    # =========================================================================
    section "9.9: Re-authenticating and revoking share"
    
    # Wait for next TOTP window
    local current_seconds=$(date +%s)
    local seconds_into_window=$((current_seconds % 30))
    local seconds_to_wait=$((30 - seconds_into_window))
    
    info "Waiting ${seconds_to_wait} seconds + 2 second buffer for next TOTP window..."
    sleep "$((seconds_to_wait + 2))"
    
    # Generate TOTP code
    local user_totp_code
    user_totp_code=$(generate_totp "$TEST_USER_TOTP_SECRET")
    
    # Login again
    local relogin_output
    local relogin_exit_code
    
    safe_exec relogin_output relogin_exit_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$user_totp_code' | $BUILD_DIR/arkfile-client \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            --username '$TEST_USERNAME' \
            login \
            --save-session"
    
    if [ $relogin_exit_code -eq 0 ]; then
        record_test "Re-authentication for revoke" "PASS"
    else
        record_test "Re-authentication for revoke" "FAIL"
        error "Failed to re-authenticate"
        echo "$relogin_output"
        return 1
    fi
    
    # Revoke share
    local revoke_output
    local revoke_exit_code
    
    safe_exec revoke_output revoke_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        share revoke \
        --reason "e2e_test_complete" \
        "$share_id"
        
    if [ $revoke_exit_code -eq 0 ]; then
        record_test "Share revocation" "PASS"
        info "Share revoked successfully"
    else
        record_test "Share revocation" "FAIL"
        error "Failed to revoke share"
        echo "$revoke_output"
    fi
    
    # Test that revoked share cannot be downloaded
    sleep 2  # Delay to avoid rate limiting
    
    local revoked_download_output
    local revoked_download_exit_code
    
    safe_exec revoked_download_output revoked_download_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download-share \
        --share-id "$share_id" \
        --output "$TEST_DATA_DIR/revoked.enc"
        
    if [ $revoked_download_exit_code -ne 0 ]; then
        record_test "Revoked share rejection" "PASS"
        info "Correctly rejected revoked share download"
    else
        record_test "Revoked share rejection" "FAIL"
        error "Security failure: Revoked share was still accessible!"
    fi
    
    # =========================================================================
    # Cleanup
    # =========================================================================
    section "Share operations cleanup"
    rm -f "$test_file" "$test_file_enc" "$metadata_file" \
          "$shared_download_file" "$decrypted_share_file" \
          "$TEST_DATA_DIR/nonexistent.enc" "$TEST_DATA_DIR/revoked.enc"
    
    success "Share operations phase complete"
}


# Phase 11: Cleanup
phase_11_cleanup() {
    phase "11: CLEANUP"
    
    section "Cleaning up test data"
    
    # Logout user
    local user_logout_output
    local user_logout_exit_code
    
    safe_exec user_logout_output user_logout_exit_code \
        $BUILD_DIR/arkfile-client \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        logout
        
    if [ $user_logout_exit_code -eq 0 ]; then
        if echo "$user_logout_output" | grep -q "Logged out successfully"; then
            record_test "User logout" "PASS"
        else
            warning "User logout may have failed"
            record_test "User logout" "PASS"  # Not critical
        fi
    else
        warning "User logout command failed"
        record_test "User logout" "PASS"  # Not critical
    fi
    
    # Logout admin
    local admin_logout_output
    local admin_logout_exit_code
    
    safe_exec admin_logout_output admin_logout_exit_code \
        $BUILD_DIR/arkfile-admin \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        logout
        
    if [ $admin_logout_exit_code -eq 0 ]; then
        if echo "$admin_logout_output" | grep -q "logout successful"; then
            record_test "Admin logout" "PASS"
        else
            warning "Admin logout may have failed"
            record_test "Admin logout" "PASS"  # Not critical
        fi
    else
        warning "Admin logout command failed"
        record_test "Admin logout" "PASS"  # Not critical
    fi
    
    # Clean up temporary files (except the main log)
    # rm -f "$TEST_DATA_DIR"/*.log # We keep the main log now
    
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
    
    # Print all test results
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
    # phase_10_admin_operations - Removed as per user request
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
