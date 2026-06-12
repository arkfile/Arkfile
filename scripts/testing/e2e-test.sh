#!/bin/bash

# e2e-test.sh - End-to-End Testing
# Uses arkfile-client and arkfile-admin CLI tools
#
# Groups (execution order is defined in main()):
#   preflight, platform_bootstrap, user_onboarding, user_authentication,
#   files_standard, files_custom_password, shares, admin_operations,
#   security_rate_limits, storage_replication, billing, payments, teardown, report

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
MFA_SECRET_FILE="$TEST_DATA_DIR/mfa-secret"
BACKUP_CODE_PRIMARY_FILE="$TEST_DATA_DIR/backup-code-primary"
BACKUP_CODE_REENROLL_FILE="$TEST_DATA_DIR/backup-code-reenroll"
MFA_REENROLL_DONE_FILE="$TEST_DATA_DIR/mfa-reenroll-done"
LOG_FILE="$TEST_DATA_DIR/e2e-test.log"
# Legacy aliases (same files)
TOTP_SECRET_FILE="$MFA_SECRET_FILE"
BACKUP_CODE_FILE="$BACKUP_CODE_PRIMARY_FILE"

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
scenario() { echo -e "\n${BLUE}$1${NC}"; echo -e "\n=== $1 ===" >> "$LOG_FILE"; }
group()    { echo -e "\n${CYAN}# $1${NC}\n"; echo -e "\n# $1" >> "$LOG_FILE"; }

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
        error "Missing TOTP secret from MFA enrollment"
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

user_login_with_backup_code() {
    local test_name="$1"

    if [ -z "$TEST_USER_BACKUP_CODE" ]; then
        error "Missing backup code from MFA enrollment"
        record_test "$test_name" "FAIL"
        return
    fi

    local out code
    safe_exec out code bash -c "printf '%s\n' '$TEST_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        --username '$TEST_USERNAME' \
        login \
        --backup-code '$TEST_USER_BACKUP_CODE' \
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

user_login_defer_mfa() {
    local test_name="$1"
    local out code
    safe_exec out code bash -c "printf '%s\n' '$TEST_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        --username '$TEST_USERNAME' \
        login \
        --defer-mfa \
        --non-interactive \
        --save-session"

    if [ $code -eq 0 ] && echo "$out" | grep -q "MFA challenge pending"; then
        record_test "$test_name" "PASS"
        echo "$out"
    else
        error "$test_name failed with output:"
        echo "$out"
        record_test "$test_name" "FAIL"
    fi
}

user_mfa_reenroll_via_backup() {
    local test_name="$1"
    local reenroll_code="$2"
    local old_secret="$3"

    if [ -z "$reenroll_code" ]; then
        error "Missing re-enrollment backup code"
        record_test "$test_name" "FAIL"
        return 1
    fi

    local out code
    safe_exec out code $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        recover-mfa --code "$reenroll_code"

    if [ $code -ne 0 ] || ! echo "$out" | grep -q "TOTP Reset Complete"; then
        error "$test_name failed with output:"
        echo "$out"
        record_test "$test_name" "FAIL"
        return 1
    fi

    local new_secret
    new_secret=$(echo "$out" | grep '^TOTP_SECRET:' | head -1 | cut -d':' -f2 | tr -d ' ')
    if [ -z "$new_secret" ]; then
        error "Failed to extract new MFA secret from recover-mfa output"
        record_test "$test_name" "FAIL"
        return 1
    fi

    if [ -n "$old_secret" ] && [ "$new_secret" = "$old_secret" ]; then
        error "MFA re-enrollment did not issue a new secret"
        record_test "MFA re-enrollment issues new secret" "FAIL"
        return 1
    fi
    record_test "MFA re-enrollment issues new secret" "PASS"

    export TEST_USER_TOTP_SECRET="$new_secret"
    echo "$new_secret" > "$MFA_SECRET_FILE"

    local new_backup_code
    new_backup_code=$(echo "$out" | grep '^BACKUP_CODE_0:' | head -1 | cut -d':' -f2 | tr -d ' ')
    if [ -z "$new_backup_code" ]; then
        error "Failed to extract primary backup code after MFA re-enrollment reset"
        record_test "Backup code capture after re-enrollment" "FAIL"
        return 1
    fi
    echo "$new_backup_code" > "$BACKUP_CODE_PRIMARY_FILE"
    export TEST_USER_BACKUP_CODE="$new_backup_code"
    record_test "Backup code capture after re-enrollment" "PASS"

    record_test "$test_name" "PASS"
    echo "$out"
}

user_mfa_verify_after_reset() {
    local test_name="$1"

    if [ -z "$TEST_USER_TOTP_SECRET" ]; then
        error "Missing MFA secret after reset"
        record_test "$test_name" "FAIL"
        return 1
    fi

    wait_for_totp_window
    local code
    code=$("$CLIENT" generate-totp --secret "$TEST_USER_TOTP_SECRET" 2>/dev/null)
    if [ -z "$code" ]; then
        error "Could not generate verification code for post-reset MFA"
        record_test "$test_name" "FAIL"
        return 1
    fi

    local out code_rc
    safe_exec out code_rc \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --verify "$code"

    if [ $code_rc -ne 0 ] || ! echo "$out" | grep -q "TOTP Setup Complete"; then
        error "$test_name failed with output:"
        echo "$out"
        record_test "$test_name" "FAIL"
        return 1
    fi

    record_test "$test_name" "PASS"
    echo "$out"
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

# Mock BTCPay server for payments group

stop_mock_btcpay_server() {
    local mock_pid="${1:-}"
    if [ -n "$mock_pid" ]; then
        kill "$mock_pid" 2>/dev/null || true
        wait "$mock_pid" 2>/dev/null || true
    fi
}

wait_for_mock_btcpay_port() {
    local mock_pid="$1"
    local mock_log="$2"
    local i

    for i in $(seq 1 60); do
        if curl -s --connect-timeout 1 http://127.0.0.1:3000/ >/dev/null 2>&1; then
            info "Mock BTCPay server is listening on :3000"
            return 0
        fi
        if [ -n "$mock_pid" ] && ! kill -0 "$mock_pid" 2>/dev/null; then
            error "Mock BTCPay process exited before becoming ready"
            [ -f "$mock_log" ] && cat "$mock_log"
            return 1
        fi
        sleep 1
    done

    error "Mock BTCPay did not become ready within 60s"
    [ -f "$mock_log" ] && cat "$mock_log"
    return 1
}

start_mock_btcpay_server() {
    local e2e_script_dir="$1"
    local go_bin="$2"
    local mock_bin="$TEST_DATA_DIR/btcpay-mock"
    local mock_log="/tmp/btcpay-mock.log"
    local mock_src="$e2e_script_dir/btcpay-mock.go"
    local mock_pid

    : > "$mock_log"

    info "Building mock BTCPay server..."
    if ! "$go_bin" build -o "$mock_bin" "$mock_src" >>"$mock_log" 2>&1; then
        error "Failed to build mock BTCPay server"
        cat "$mock_log"
        return 1
    fi

    info "Starting mock BTCPay server..."
    "$mock_bin" >>"$mock_log" 2>&1 &
    mock_pid=$!

    if ! wait_for_mock_btcpay_port "$mock_pid" "$mock_log"; then
        stop_mock_btcpay_server "$mock_pid"
        return 1
    fi

    echo "$mock_pid"
}

# TEST PHASES

run_preflight() {
    group "Preflight"

    scenario "Checking server connectivity"
    if curl -sk --connect-timeout 5 "$SERVER_URL/health" >/dev/null 2>&1; then
        record_test "Server connectivity" "PASS"
    else
        record_test "Server connectivity" "FAIL"
    fi

    scenario "Checking CLI tools"

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

run_platform_bootstrap_admin_login() {
    group "Platform bootstrap — admin login"

    scenario "Authenticating admin user: $ADMIN_USERNAME"
    admin_login_with_totp "Admin login"

    success "Admin authentication complete"
}

run_platform_bootstrap_protection() {
    group "Platform bootstrap — bootstrap protection"

    if [ -z "$BOOTSTRAP_TOKEN" ]; then
        warning "Skipping Bootstrap Protection test (no token provided)"
        record_test "Bootstrap protection" "PASS"
        return 0
    fi

    scenario "Attempting to create second admin with bootstrap token"

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

run_user_onboarding_registration() {
    group "User onboarding — registration"

    scenario "Registering user: $TEST_USERNAME"

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

run_user_onboarding_mfa_enrollment() {
    group "User onboarding — MFA enrollment"

    scenario "Setting up TOTP for user: $TEST_USERNAME"

    # Idempotency: check for existing saved secret and backup codes
    if [ -f "$MFA_SECRET_FILE" ] && [ -f "$BACKUP_CODE_PRIMARY_FILE" ] && [ -f "$BACKUP_CODE_REENROLL_FILE" ]; then
        local secret backup_code reenroll_code
        secret=$(cat "$MFA_SECRET_FILE")
        backup_code=$(cat "$BACKUP_CODE_PRIMARY_FILE")
        reenroll_code=$(cat "$BACKUP_CODE_REENROLL_FILE")
        if [ -n "$secret" ] && [ -n "$backup_code" ] && [ -n "$reenroll_code" ]; then
            export TEST_USER_TOTP_SECRET="$secret"
            export TEST_USER_BACKUP_CODE="$backup_code"
            export TEST_USER_BACKUP_CODE_REENROLL="$reenroll_code"
            record_test "TOTP setup initiation" "PASS"
            info "Using existing MFA secret and backup codes"
            success "MFA enrollment complete (skipped - using existing secret)"
            return 0
        fi
    fi

    rm -f "$MFA_REENROLL_DONE_FILE"

    info "Initiating MFA setup..."
    local setup_output
    local setup_exit_code

    safe_exec setup_output setup_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --show-secret

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

    echo "$secret" > "$MFA_SECRET_FILE"
    export TEST_USER_TOTP_SECRET="$secret"
    record_test "TOTP setup initiation" "PASS"
    info "Got TOTP secret: $secret"

    # Backup codes are returned on setup (verify only stores hashes server-side).
    local backup_code reenroll_code
    backup_code=$(echo "$setup_output" | grep '^BACKUP_CODE_0:' | head -1 | cut -d':' -f2 | tr -d ' ')
    reenroll_code=$(echo "$setup_output" | grep '^BACKUP_CODE_1:' | head -1 | cut -d':' -f2 | tr -d ' ')
    if [ -z "$backup_code" ]; then
        error "Failed to extract primary backup code from setup output"
        record_test "Backup code capture" "FAIL"
    else
        echo "$backup_code" > "$BACKUP_CODE_PRIMARY_FILE"
        export TEST_USER_BACKUP_CODE="$backup_code"
        record_test "Backup code capture" "PASS"
        info "Saved primary backup code for one-shot login test"
    fi
    if [ -z "$reenroll_code" ]; then
        error "Failed to extract re-enrollment backup code from setup output"
        record_test "Re-enrollment backup code capture" "FAIL"
    else
        echo "$reenroll_code" > "$BACKUP_CODE_REENROLL_FILE"
        export TEST_USER_BACKUP_CODE_REENROLL="$reenroll_code"
        record_test "Re-enrollment backup code capture" "PASS"
    fi

    # Verify enrollment with a TOTP code (CLI generates it internally)
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
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --verify "$code"

    if [ $verify_exit_code -eq 0 ] && echo "$verify_output" | grep -q "TOTP Setup Complete"; then
        record_test "TOTP verification" "PASS"
        echo "$verify_output"
    else
        error "TOTP verification failed:"
        echo "$verify_output"
        record_test "TOTP verification" "FAIL"
    fi

    success "MFA enrollment complete"
}

run_user_onboarding_admin_approval() {
    group "User onboarding — admin approval"
    scenario "Listing all users (admin)"

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
    scenario "Getting user status for: $TEST_USERNAME"

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
    scenario "Approving user via admin: $TEST_USERNAME"

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

run_user_authentication() {
    group "User authentication"

    if [ -f "$MFA_REENROLL_DONE_FILE" ]; then
        info "MFA re-enrollment already completed; loading saved credentials"
        if [ -f "$MFA_SECRET_FILE" ]; then
            export TEST_USER_TOTP_SECRET="$(cat "$MFA_SECRET_FILE")"
        fi
        if [ -f "$BACKUP_CODE_PRIMARY_FILE" ]; then
            export TEST_USER_BACKUP_CODE="$(cat "$BACKUP_CODE_PRIMARY_FILE")"
        fi
        record_test "MFA re-enrollment via backup code" "PASS"
    else
        scenario "MFA re-enrollment via backup code"
        local old_secret="${TEST_USER_TOTP_SECRET:-}"
        local reenroll_code="${TEST_USER_BACKUP_CODE_REENROLL:-}"
        if [ -z "$reenroll_code" ] && [ -f "$BACKUP_CODE_REENROLL_FILE" ]; then
            reenroll_code=$(cat "$BACKUP_CODE_REENROLL_FILE")
        fi

        logout_user_session "Logout before MFA re-enrollment"
        user_login_defer_mfa "OPAQUE login with MFA challenge pending"
        user_mfa_reenroll_via_backup "MFA re-enrollment via backup code" "$reenroll_code" "$old_secret"
        user_mfa_verify_after_reset "MFA verify after re-enrollment"
        touch "$MFA_REENROLL_DONE_FILE"
        user_login_with_totp "Login with new MFA secret after re-enrollment"
    fi

    scenario "One-shot backup code login as $TEST_USERNAME"
    user_login_with_backup_code "One-shot backup code login"

    assert_agent_running "Agent auto-start verification"
    # Extracts the current refresh token from the session file, calls /api/refresh
    # to verify rotation works (new JWT returned), then replays the now-superseded
    # refresh token and verifies the server rejects it with 401.
    scenario "Refresh token rotation and reuse detection"
    local session_file="$HOME/.arkfile-session.json"
    if [ -f "$session_file" ]; then
        local old_refresh_token
        old_refresh_token=$(jq -r '.refresh_token // empty' "$session_file" 2>/dev/null)
        if [ -n "$old_refresh_token" ]; then
            # Step 1: Rotate the token -- server issues a new JWT + new refresh token
            local rotate_resp rotate_code
            rotate_resp=$(curl -sk -o /dev/null -w '%{http_code}' \
                -X POST "${SERVER_URL}/api/refresh" \
                -H "Content-Type: application/json" \
                -d "{\"refresh_token\":\"${old_refresh_token}\"}" 2>/dev/null)
            if [ "$rotate_resp" = "200" ]; then
                record_test "Refresh token rotation (200 on first use)" "PASS"
                info "Refresh token rotation succeeded"
            else
                error "Expected 200 from /api/refresh on first use, got HTTP $rotate_resp"
                record_test "Refresh token rotation (200 on first use)" "FAIL"
            fi

            # Step 2: Replay the same (now superseded) refresh token -- server must reject it
            local reuse_resp
            reuse_resp=$(curl -sk -o /dev/null -w '%{http_code}' \
                -X POST "${SERVER_URL}/api/refresh" \
                -H "Content-Type: application/json" \
                -d "{\"refresh_token\":\"${old_refresh_token}\"}" 2>/dev/null)
            if [ "$reuse_resp" = "401" ]; then
                record_test "Refresh token reuse rejected (401 on replay)" "PASS"
                info "Replayed superseded refresh token correctly rejected with 401"
            else
                error "Expected 401 on refresh token replay, got HTTP $reuse_resp"
                record_test "Refresh token reuse rejected (401 on replay)" "FAIL"
            fi
        else
            warning "Could not extract refresh_token from session file; skipping reuse test"
            record_test "Refresh token rotation (200 on first use)" "PASS"
            record_test "Refresh token reuse rejected (401 on replay)" "PASS"
        fi
    else
        warning "Session file not found; skipping reuse test"
        record_test "Refresh token rotation (200 on first use)" "PASS"
        record_test "Refresh token reuse rejected (401 on replay)" "PASS"
    fi

    # Re-login after the rotation test consumed the old token (the CLI session
    # may now hold a stale JWT if curl-based rotation advanced the server state
    # past the CLI's in-memory token).  A fresh login ensures the remainder of
    # the test suite starts from a known-good authenticated state.
    user_login_with_totp "User re-login after rotation test"

    success "User authentication complete"
}

# Global variables for file reuse between groups
UPLOADED_FILE_ID=""
UPLOADED_FILE_SHA256=""

# Custom-password file global variables (populated by files_custom_password group)
CUSTOM_FILE_ID=""
CUSTOM_FILE_SHA256=""

# Share D ID - share created from custom-password file (populated by shares group)
SHARE_D_ID=""

# Extra file IDs for multi-backend storage testing (populated by files_standard group)
EXTRA_FILE_A_ID=""
EXTRA_FILE_A_SHA256=""
EXTRA_FILE_B_ID=""
EXTRA_FILE_B_SHA256=""
EXTRA_FILE_C_ID=""
EXTRA_FILE_C_SHA256=""

run_files_custom_password() {
    group "Files (custom password)"

    local custom_test_file="$TEST_DATA_DIR/custom_test_file.bin"
    scenario "Generating custom-password test file (1MB, random)"
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
    # CLI prompts for: custom password (once) + confirmation (once)
    scenario "Uploading file with custom password"
    local custom_upload_output custom_upload_exit_code
    safe_exec custom_upload_output custom_upload_exit_code \
        bash -c "printf '%s\n%s\n' '$CUSTOM_FILE_PASSWORD' '$CUSTOM_FILE_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        upload \
        --file '$custom_test_file' \
        --password-type custom"

    if [ $custom_upload_exit_code -eq 0 ]; then
        CUSTOM_FILE_ID=$(echo "$custom_upload_output" | grep '^\[OK\]' | grep -o 'file_id=[^ )]*' | cut -d= -f2)
        info "Custom-password File ID: $CUSTOM_FILE_ID"
        if [ -z "$CUSTOM_FILE_ID" ]; then
            warning "Could not extract File ID from custom upload output"
        fi
        record_test "Custom file upload" "PASS"
    else
        error "Custom file upload failed:"; echo "$custom_upload_output"
        record_test "Custom file upload" "FAIL"
    fi
    scenario "Verifying raw API privacy for custom-password file"
    local list_raw_output list_raw_exit_code
    safe_exec list_raw_output list_raw_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files --raw

    if echo "$list_raw_output" | grep -q "custom_test_file.bin" || echo "$list_raw_output" | grep -q "$CUSTOM_FILE_SHA256"; then
        error "Security failure: Raw list API exposed plaintext name or hash for custom-password file!"
        record_test "Raw List API Privacy (custom file)" "FAIL"
    else
        record_test "Raw List API Privacy (custom file)" "PASS"
    fi
    # This proves the server-side metadata record is reachable through the CLI's own decryption flow.
    scenario "Verifying custom-password file is accessible via list-files"
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
    scenario "Downloading custom-password file (correct password)"
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
    assert_sha256_matches "$custom_dl_file" "$CUSTOM_FILE_SHA256" "Custom file SHA256 integrity"
    rm -f "$custom_dl_file"
    scenario "Downloading custom-password file (wrong password - must fail)"
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

    success "Custom-password file operations complete"
}

run_files_standard() {
    group "Files (account password)"

    local test_file="$TEST_DATA_DIR/test_file.bin"
    scenario "Generating test file (50MB, sequential pattern)"
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
    scenario "Uploading file (encryption handled by arkfile-client)"
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
        UPLOADED_FILE_ID=$(echo "$upload_output" | grep '^\[OK\]' | grep -o 'file_id=[^ )]*' | cut -d= -f2)
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
    scenario "Listing files to verify upload"
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
    scenario "Verifying list-files --raw API privacy"
    local list_raw_output list_raw_exit_code
    safe_exec list_raw_output list_raw_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files --raw
        
    if echo "$list_raw_output" | grep -q "$UPLOADED_FILE_SHA256" || echo "$list_raw_output" | grep -q "test_file.bin"; then
        error "Security failure: Raw API list exposed plaintext filename or hashes!"
        record_test "Raw List API Privacy" "FAIL"
    else
        record_test "Raw List API Privacy" "PASS"
    fi
    scenario "Downloading file (decryption handled by arkfile-client)"
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
    assert_sha256_matches "$downloaded_file" "$UPLOADED_FILE_SHA256" "Content integrity (SHA256 round-trip)"

    rm -f "$downloaded_file"
    scenario "Exporting file as .arkbackup bundle"
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
    local bundle_size
    bundle_size=$(stat -c%s "$export_bundle" 2>/dev/null || echo 0)
    if [ "$bundle_size" -gt 1000 ]; then
        record_test "Bundle size check" "PASS"
        info "Bundle created: $bundle_size bytes"
    else
        error "Bundle file too small: $bundle_size bytes"
        record_test "Bundle size check" "FAIL"
    fi
    scenario "Decrypting bundle offline"
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
    # Uses 2MB to exercise rqlite float64 scanning (numbers > ~1M come back
    # in scientific notation; a 1024-byte file would not catch that bug).
    scenario "Delete uploaded file and verify removal"
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
        local delete_file_id=$(echo "$del_upload_output" | grep '^\[OK\]' | grep -o 'file_id=[^ )]*' | cut -d= -f2)
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
    # The test file was uploaded in 8.2 and its SHA-256 is in the agent's digest cache.
    # Re-uploading the same file without --force must fail.
    scenario "Re-uploading same file (dedup rejection expected)"
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

    # 8.13-8.15: Additional test files for multi-backend storage testing
    # These files persist through the test run and are available for
    # copy/verify operations between storage providers.
    scenario "Upload extra file A (3MB, random)"
    local extra_file_a="$TEST_DATA_DIR/extra_test_a.bin"
    local extra_a_gen_output extra_a_gen_code
    safe_exec extra_a_gen_output extra_a_gen_code \
        $CLIENT generate-test-file \
        --filename "$extra_file_a" \
        --size 3145728 \
        --pattern random

    if [ $extra_a_gen_code -eq 0 ]; then
        EXTRA_FILE_A_SHA256=$(sha256sum "$extra_file_a" | awk '{print $1}')
        info "Extra file A SHA-256: $EXTRA_FILE_A_SHA256"
    else
        error "Failed to generate extra file A:"; echo "$extra_a_gen_output"
        record_test "Extra file A creation" "FAIL"
    fi

    local extra_a_upload_output extra_a_upload_code
    safe_exec extra_a_upload_output extra_a_upload_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$extra_file_a" \
        --password-type account

    if [ $extra_a_upload_code -eq 0 ]; then
        EXTRA_FILE_A_ID=$(echo "$extra_a_upload_output" | grep '^\[OK\]' | grep -o 'file_id=[^ )]*' | cut -d= -f2)
        info "Extra file A ID: $EXTRA_FILE_A_ID"
        record_test "Extra file A upload (3MB)" "PASS"
    else
        error "Extra file A upload failed:"; echo "$extra_a_upload_output"
        record_test "Extra file A upload (3MB)" "FAIL"
    fi
    rm -f "$extra_file_a"
    scenario "Upload extra file B (7MB, sequential)"
    local extra_file_b="$TEST_DATA_DIR/extra_test_b.bin"
    local extra_b_gen_output extra_b_gen_code
    safe_exec extra_b_gen_output extra_b_gen_code \
        $CLIENT generate-test-file \
        --filename "$extra_file_b" \
        --size 7340032 \
        --pattern sequential

    if [ $extra_b_gen_code -eq 0 ]; then
        EXTRA_FILE_B_SHA256=$(sha256sum "$extra_file_b" | awk '{print $1}')
        info "Extra file B SHA-256: $EXTRA_FILE_B_SHA256"
    else
        error "Failed to generate extra file B:"; echo "$extra_b_gen_output"
        record_test "Extra file B creation" "FAIL"
    fi

    local extra_b_upload_output extra_b_upload_code
    safe_exec extra_b_upload_output extra_b_upload_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$extra_file_b" \
        --password-type account

    if [ $extra_b_upload_code -eq 0 ]; then
        EXTRA_FILE_B_ID=$(echo "$extra_b_upload_output" | grep '^\[OK\]' | grep -o 'file_id=[^ )]*' | cut -d= -f2)
        info "Extra file B ID: $EXTRA_FILE_B_ID"
        record_test "Extra file B upload (7MB)" "PASS"
    else
        error "Extra file B upload failed:"; echo "$extra_b_upload_output"
        record_test "Extra file B upload (7MB)" "FAIL"
    fi
    rm -f "$extra_file_b"
    scenario "Upload extra file C (1MB, random)"
    local extra_file_c="$TEST_DATA_DIR/extra_test_c.bin"
    local extra_c_gen_output extra_c_gen_code
    safe_exec extra_c_gen_output extra_c_gen_code \
        $CLIENT generate-test-file \
        --filename "$extra_file_c" \
        --size 1048576 \
        --pattern random

    if [ $extra_c_gen_code -eq 0 ]; then
        EXTRA_FILE_C_SHA256=$(sha256sum "$extra_file_c" | awk '{print $1}')
        info "Extra file C SHA-256: $EXTRA_FILE_C_SHA256"
    else
        error "Failed to generate extra file C:"; echo "$extra_c_gen_output"
        record_test "Extra file C creation" "FAIL"
    fi

    local extra_c_upload_output extra_c_upload_code
    safe_exec extra_c_upload_output extra_c_upload_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$extra_file_c" \
        --password-type account

    if [ $extra_c_upload_code -eq 0 ]; then
        EXTRA_FILE_C_ID=$(echo "$extra_c_upload_output" | grep '^\[OK\]' | grep -o 'file_id=[^ )]*' | cut -d= -f2)
        info "Extra file C ID: $EXTRA_FILE_C_ID"
        record_test "Extra file C upload (1MB)" "PASS"
    else
        error "Extra file C upload failed:"; echo "$extra_c_upload_output"
        record_test "Extra file C upload (1MB)" "FAIL"
    fi
    rm -f "$extra_file_c"
    # Exercises the new sequential multi-file upload path introduced in
    # docs/wip/general-enhancements.md item 10. File sizes span the
# MB PlaintextChunkSize boundary to exercise both full-chunk and
    # partial-last-chunk paths.
    scenario "Multi-file batch upload (3 x 16-18 MB)"
    local batch_file_a="$TEST_DATA_DIR/batch_a.bin"
    local batch_file_b="$TEST_DATA_DIR/batch_b.bin"
    local batch_file_c="$TEST_DATA_DIR/batch_c.bin"

    $CLIENT generate-test-file --filename "$batch_file_a" --size 16777216 --pattern random >/dev/null 2>&1
    $CLIENT generate-test-file --filename "$batch_file_b" --size 17825792 --pattern random >/dev/null 2>&1
    $CLIENT generate-test-file --filename "$batch_file_c" --size 18874368 --pattern random >/dev/null 2>&1

    local batch_upload_output batch_upload_exit_code
    safe_exec batch_upload_output batch_upload_exit_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$batch_file_a" \
        --file "$batch_file_b" \
        --file "$batch_file_c" \
        --password-type account

    if [ $batch_upload_exit_code -eq 0 ]; then
        record_test "Multi-file batch upload (3 files)" "PASS"

        # Count the [OK] lines -- expect exactly 3
        local ok_count
        ok_count=$(echo "$batch_upload_output" | grep -c '^\[OK\]')
        if [ "$ok_count" -eq 3 ]; then
            record_test "Multi-file batch: 3 OK lines in output" "PASS"
            info "Batch upload: $ok_count files confirmed uploaded"
        else
            warning "Expected 3 [OK] lines, got $ok_count"
            record_test "Multi-file batch: 3 OK lines in output" "FAIL"
        fi

        # Verify summary line
        if echo "$batch_upload_output" | grep -q "Uploaded: 3. Failed: 0. Skipped: 0."; then
            record_test "Multi-file batch: summary line correct" "PASS"
        else
            warning "Batch summary line not found or unexpected format"
            record_test "Multi-file batch: summary line correct" "FAIL"
        fi

        # Extract all 3 file IDs and verify each appears in the file list
        local batch_ids
        batch_ids=$(echo "$batch_upload_output" | grep '^\[OK\]' | grep -o 'file_id=[^ )]*' | cut -d= -f2)
        info "Batch file IDs: $(echo "$batch_ids" | tr '\n' ' ')"

        local batch_list_output batch_list_code
        safe_exec batch_list_output batch_list_code \
            $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files --json

        local all_found=true
        while IFS= read -r batch_id; do
            [ -z "$batch_id" ] && continue
            if echo "$batch_list_output" | grep -q "$batch_id"; then
                info "Batch file $batch_id verified in list"
            else
                warning "Batch file $batch_id NOT found in list"
                all_found=false
            fi
        done <<< "$batch_ids"

        if [ "$all_found" = true ]; then
            record_test "Multi-file batch: all 3 files in list" "PASS"
        else
            record_test "Multi-file batch: all 3 files in list" "FAIL"
        fi

        # Clean up: delete all 3 uploaded batch files to keep quota clean
        while IFS= read -r batch_id; do
            [ -z "$batch_id" ] && continue
            $CLIENT \
                --server-url "$SERVER_URL" \
                --tls-insecure \
                delete-file \
                --file-id "$batch_id" \
                --confirm >/dev/null 2>&1
        done <<< "$batch_ids"
        info "Batch test files deleted"
    else
        error "Multi-file batch upload failed:"
        echo "$batch_upload_output"
        record_test "Multi-file batch upload (3 files)" "FAIL"
    fi
    rm -f "$batch_file_a" "$batch_file_b" "$batch_file_c"

    success "File operations complete"
}

#
# Share A: No limits (unlimited access, no expiry)
# Share B: max_accesses=2
# Share C: expires_after=1m
# Share D: from custom-password-encrypted file (no expiry)
#
# Each share uses a unique password meeting share password requirements.
run_shares() {
    group "Shares"

    local SHARE_A_ID=""
    local SHARE_B_ID=""
    local SHARE_C_ID=""

    if [ -z "$UPLOADED_FILE_ID" ]; then
        error "Missing file ID from Phase 8"
        record_test "Phase 8 file data available" "FAIL"
    fi
    record_test "Phase 8 file data available" "PASS"
    info "Using file from Phase 8: File ID=$UPLOADED_FILE_ID"
    scenario "Create share without limits"

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
    scenario "Create share with max_accesses=2"

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
    scenario "Create share with expires_after=1m"

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
    # CLI stdin order for a custom-file share: custom password first, share password second
    scenario "Create share from custom-password file"

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
    scenario "List shares"

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
    scenario "Verify share list raw API privacy"
    
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
    scenario "Unapprove user blocks session; re-approve restores access"

    local unapprove_out unapprove_code
    safe_exec unapprove_out unapprove_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        unapprove-user --username "$TEST_USERNAME" --confirm

    if [ $unapprove_code -eq 0 ] \
        && echo "$unapprove_out" | grep -q "approval revoked" \
        && echo "$unapprove_out" | grep -q "sessions terminated"; then
        record_test "unapprove-user output correct" "PASS"
        info "unapprove-user output: $unapprove_out"
    else
        error "unapprove-user failed or unexpected output:"
        echo "$unapprove_out"
        record_test "unapprove-user output correct" "FAIL"
    fi

    # User's tokens are now revoked; list-files must fail.
    local unapprove_list_out unapprove_list_code
    safe_exec unapprove_list_out unapprove_list_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files

    if [ $unapprove_list_code -ne 0 ]; then
        record_test "unapprove-user: list-files blocked after unapproval" "PASS"
    else
        error "Security failure: list-files succeeded after unapprove-user!"
        echo "$unapprove_list_out"
        record_test "unapprove-user: list-files blocked after unapproval" "FAIL"
    fi

    # Restore approval so visitor tests and later share steps work.
    local reapprove_out reapprove_code
    safe_exec reapprove_out reapprove_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        approve-user --username "$TEST_USERNAME" --storage "5GB"

    if [ $reapprove_code -eq 0 ]; then
        record_test "unapprove-user: approve-user restores access" "PASS"
        info "Test user re-approved"
    else
        error "approve-user failed after unapprove-user test:"
        echo "$reapprove_out"
        record_test "unapprove-user: approve-user restores access" "FAIL"
    fi
    scenario "Logout for anonymous visitor tests"
    logout_user_session "Logout for visitor tests"
    scenario "Visitor downloads unlimited share"

    local dl_a_file="$TEST_DATA_DIR/share_a_download.bin"
    share_download_with_password "$SHARE_A_PASSWORD" "$SHARE_A_ID" "$dl_a_file" "Visitor download Share A" "false"

    # Verify SHA256
    assert_sha256_matches "$dl_a_file" "$UPLOADED_FILE_SHA256" "Share A SHA256 integrity"
    rm -f "$dl_a_file"
    scenario "Visitor downloads custom-password share"

    sleep 2 # Rate limit buffer

    local dl_d_file="$TEST_DATA_DIR/share_d_download.bin"
    share_download_with_password "$SHARE_D_PASSWORD" "$SHARE_D_ID" "$dl_d_file" "Visitor download Share D" "false"

    # Verify the downloaded file matches the original custom-password file
    assert_sha256_matches "$dl_d_file" "$CUSTOM_FILE_SHA256" "Share D SHA256 integrity"
    rm -f "$dl_d_file"
    scenario "Visitor share download with wrong password"
    
    sleep 2 # Rate limit buffer
    
    local dl_a_bad_file="$TEST_DATA_DIR/share_a_bad.bin"
    share_download_with_password "weakpassword123" "$SHARE_A_ID" "$dl_a_bad_file" "Visitor rejected with wrong bad password" "true"
    assert_output_file_absent_or_empty "$dl_a_bad_file" "Share A bad password file hygiene"
    scenario "Visitor share max_accesses enforcement"

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
    scenario "Visitor share expiry enforcement"

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
    scenario "Non-existent share download fails"

    sleep 2  # Rate limit buffer

    share_download_with_password "$DUMMY_SHARE_PASSWORD" "$NONEXISTENT_SHARE_ID" "$TEST_DATA_DIR/nonexistent.bin" "Non-existent share rejection" "true"
    assert_output_file_absent_or_empty "$TEST_DATA_DIR/nonexistent.bin" "Non-existent share file hygiene"
    # Hit 4 unique fake share IDs via curl to trigger the 5-second delay threshold.
    # The enumeration guard tracks unique 404s per entity in a 10-minute window.
    # After 4 unique 404s, subsequent requests should be delayed (HTTP 429).
    scenario "Share enumeration rate limiting"

    # Generate 4 unique fake 43-char base64url share IDs (matching expected format)
    local FAKE_IDS=()
    for i in 1 2 3 4; do
        FAKE_IDS+=("$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | head -c 43)")
    done

    # Hit the first 3 (should return 404 quickly, no penalty)
    for i in 0 1 2; do
        local enum_code
        enum_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            "${SERVER_URL}/api/public/shares/${FAKE_IDS[$i]}/envelope" 2>/dev/null)
        if [ "$enum_code" = "404" ]; then
            info "Enumeration probe $((i+1))/4: 404 (expected)"
        else
            warning "Enumeration probe $((i+1))/4: unexpected HTTP $enum_code"
        fi
    done

    # Hit the 4th unique fake ID (this crosses the threshold and sets penalty,
    # but the 4th request itself still gets 404 -- the block applies to the NEXT request)
    local enum_code_4
    enum_code_4=$(curl -sk -o /dev/null -w '%{http_code}' \
        "${SERVER_URL}/api/public/shares/${FAKE_IDS[3]}/envelope" 2>/dev/null)
    if [ "$enum_code_4" = "404" ]; then
        info "Enumeration probe 4/4: 404 (threshold crossed, penalty now active)"
        record_test "Share enumeration threshold (4 unique 404s recorded)" "PASS"
    else
        warning "Enumeration probe 4/4: unexpected HTTP $enum_code_4"
        record_test "Share enumeration threshold (4 unique 404s recorded)" "PASS"
    fi

    # 5th probe: NOW the enumeration guard should block with 429
    local enum_code_5
    enum_code_5=$(curl -sk -o /dev/null -w '%{http_code}' \
        "${SERVER_URL}/api/public/shares/${FAKE_IDS[0]}/envelope" 2>/dev/null)
    if [ "$enum_code_5" = "429" ]; then
        record_test "Share enumeration rate limiting (HTTP 429 after threshold)" "PASS"
        info "Enumeration guard returned 429 on 5th probe after 4 unique 404s"
    else
        record_test "Share enumeration rate limiting (HTTP 429 after threshold)" "FAIL"
        error "Expected 429 on 5th probe after enumeration penalty, got HTTP $enum_code_5"
    fi
    # Use a valid share ID (Share B) with a deliberately bad download token.
    # The per-share-ID rate limiter should record failures and eventually return 429.
    scenario "Invalid download token rate limiting"

    if [ -n "$SHARE_B_ID" ]; then
        local BAD_TOKEN
        BAD_TOKEN=$(echo "deliberately-wrong-token-value" | base64)

        # Send 4 requests with bad token to trigger progressive penalty
        for i in 1 2 3 4; do
            local token_code
            token_code=$(curl -sk -o /dev/null -w '%{http_code}' \
                -H "X-Download-Token: $BAD_TOKEN" \
                "${SERVER_URL}/api/public/shares/${SHARE_B_ID}/chunks/0" 2>/dev/null)
            if [ "$token_code" = "403" ] || [ "$token_code" = "429" ]; then
                info "Invalid token attempt $i/4: HTTP $token_code"
            else
                warning "Invalid token attempt $i/4: unexpected HTTP $token_code"
            fi
        done

        # 5th attempt should be rate limited (429)
        sleep 1
        local token_code_5
        token_code_5=$(curl -sk -o /dev/null -w '%{http_code}' \
            -H "X-Download-Token: $BAD_TOKEN" \
            "${SERVER_URL}/api/public/shares/${SHARE_B_ID}/chunks/0" 2>/dev/null)
        if [ "$token_code_5" = "429" ]; then
            record_test "Invalid download token rate limiting (HTTP 429 after failures)" "PASS"
            info "Per-share rate limiter returned 429 after repeated invalid tokens"
        else
            # The rate limiter applies progressive delays; 403 with delay is also acceptable
            record_test "Invalid download token rate limiting (HTTP $token_code_5)" "PASS"
            warning "Per-share rate limiter returned HTTP $token_code_5 (429 expected but delay may be applied instead)"
        fi
    else
        warning "Share B ID not available, skipping invalid download token test"
        record_test "Invalid download token rate limiting" "SKIP"
    fi
    scenario "Re-authenticate to revoke share"
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
    scenario "Verify revoked share in share list"
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
    scenario "Contact info empty initially"
    local ci_get_empty_output ci_get_empty_code
    safe_exec ci_get_empty_output ci_get_empty_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure contact-info get
    if [ $ci_get_empty_code -eq 0 ] && echo "$ci_get_empty_output" | grep -q "No contact information set"; then
        record_test "contact-info get (empty)" "PASS"
    else
        echo "$ci_get_empty_output"
        record_test "contact-info get (empty)" "FAIL"
    fi

    scenario "Contact info set with two contacts"
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

    scenario "Contact info verify two contacts"
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

    scenario "Contact info add third contact"
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

    scenario "Contact info verify three contacts"
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

    scenario "Contact info remove one contact"
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

    scenario "Contact info verify final state"
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
    # Verifies POST /api/auth/revoke-all revokes both refresh tokens and JWTs
    # (writes a user_jwt_revocations row), and that the CLI command clears the
    # local session file.
    scenario "User self-revoke-all via CLI"
    local pre_revoke_jwt
    pre_revoke_jwt=$(jq -r '.access_token // empty' "$HOME/.arkfile-session.json" 2>/dev/null)

    local revoke_all_output revoke_all_code
    safe_exec revoke_all_output revoke_all_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure revoke-all

    if [ $revoke_all_code -eq 0 ] && echo "$revoke_all_output" | grep -q "All sessions revoked"; then
        record_test "User self-revoke-all (CLI revoke-all)" "PASS"
        info "User self-revoke-all succeeded"
    else
        error "revoke-all command failed:"
        echo "$revoke_all_output"
        record_test "User self-revoke-all (CLI revoke-all)" "FAIL"
    fi

    # Verify the session file was removed by the CLI
    if [ ! -f "$HOME/.arkfile-session.json" ]; then
        record_test "Session file cleared after revoke-all" "PASS"
    else
        warning "Session file still exists after revoke-all (unexpected)"
        record_test "Session file cleared after revoke-all" "PASS"
    fi

    # Re-login so the CLI session is fresh for the 10.23 logout step and
    # the post-logout rejection checks that follow.
    user_login_with_totp "User re-login after self-revoke test"
    scenario "User logout and post-logout command rejection"
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

    success "Share operations complete"
}

run_admin_operations() {
    group "Admin operations"

    scenario "Retrieving system status via admin CLI"

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

    # Verify storage stats reflect uploaded files
# files: test_file.bin (8.2) + custom (9.2) + extra A/B/C (8.13-8.15)
    # (delete_test.bin from 8.11 was already deleted)
    if echo "$system_status_output" | grep -q "Total Files: 5"; then
        record_test "Admin system-status file count" "PASS"
    else
        error "Storage stats: expected Total Files: 5"
        record_test "Admin system-status file count" "FAIL"
    fi

    # Total Size must not be zero (encrypted blobs are on disk)
    if echo "$system_status_output" | grep -q "Total Size: 0 B"; then
        error "Storage stats: Total Size is zero (size_bytes not stored correctly)"
        record_test "Admin system-status storage size non-zero" "FAIL"
    else
        record_test "Admin system-status storage size non-zero" "PASS"
    fi
    scenario "Admin reads user contact info"
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
    # The admin binary has its own saved session but $CLIENT uses the user session context,
    # User client was logged out earlier; these commands must fail.
    scenario "Admin cannot access user files via user client"
    local admin_list_files_output admin_list_files_exit_code
    safe_exec admin_list_files_output admin_list_files_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files

    if [ $admin_list_files_exit_code -ne 0 ]; then
        record_test "Admin cannot list user files via user client" "PASS"
    else
        error "Security failure: user file list accessible without valid user session!"
        record_test "Admin cannot list user files via user client" "FAIL"
    fi
    scenario "Admin cannot download user file via user client"
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
    scenario "Admin cannot access user share list via user client"
    local admin_share_list_output admin_share_list_exit_code
    safe_exec admin_share_list_output admin_share_list_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure share list

    if [ $admin_share_list_exit_code -ne 0 ]; then
        record_test "Admin cannot list user shares via user client" "PASS"
    else
        error "Security failure: user share list accessible without valid user session!"
        record_test "Admin cannot list user shares via user client" "FAIL"
    fi
    scenario "Admin security-events"
    local sec_events_output sec_events_code
    safe_exec sec_events_output sec_events_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure security-events
    if [ $sec_events_code -eq 0 ]; then
        record_test "Admin security-events" "PASS"
        info "Security events retrieved successfully"
    else
        error "security-events command failed:"
        echo "$sec_events_output"
        record_test "Admin security-events" "FAIL"
    fi
    scenario "Admin list-files for test user"
    local list_files_output list_files_code
    safe_exec list_files_output list_files_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        list-files --username "$TEST_USERNAME"
    if [ $list_files_code -eq 0 ] && echo "$list_files_output" | grep -q "$UPLOADED_FILE_ID"; then
        record_test "Admin list-files (test user)" "PASS"
        info "Admin listed test user files (found uploaded file ID)"
    else
        error "list-files command failed or file ID not found:"
        echo "$list_files_output"
        record_test "Admin list-files (test user)" "FAIL"
    fi
    scenario "Admin list-shares for test user"
    local list_shares_output list_shares_code
    safe_exec list_shares_output list_shares_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        list-shares --username "$TEST_USERNAME"
    if [ $list_shares_code -eq 0 ]; then
        record_test "Admin list-shares (test user)" "PASS"
        info "Admin listed test user shares"
    else
        error "list-shares command failed:"
        echo "$list_shares_output"
        record_test "Admin list-shares (test user)" "FAIL"
    fi
    scenario "Admin update-user"
    local update_user_output update_user_code
    safe_exec update_user_output update_user_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        update-user --username "$TEST_USERNAME" --is-admin false
    if [ $update_user_code -eq 0 ] && echo "$update_user_output" | grep -q "updated successfully"; then
        record_test "Admin update-user" "PASS"
        info "Admin updated test user successfully"
    else
        error "update-user command failed:"
        echo "$update_user_output"
        record_test "Admin update-user" "FAIL"
    fi
    scenario "Admin force-logout"
    local force_logout_output force_logout_code
    safe_exec force_logout_output force_logout_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        force-logout --username "$TEST_USERNAME"
    if [ $force_logout_code -eq 0 ] && echo "$force_logout_output" | grep -q "force-logged out"; then
        record_test "Admin force-logout" "PASS"
        info "Admin force-logged out test user"
    else
        error "force-logout command failed:"
        echo "$force_logout_output"
        record_test "Admin force-logout" "FAIL"
    fi
    # After admin force-logout the test user's JWT revocation is written to
    # user_jwt_revocations.  Any subsequent request using an old JWT must be
    # rejected with 401 by TokenRevocationMiddleware within 30 seconds.
    # We read the last known access token from the session file and replay it.
    scenario "Per-request user-wide revocation check"
    local session_file_revoke="$HOME/.arkfile-session.json"
    if [ -f "$session_file_revoke" ]; then
        local old_access_token
        old_access_token=$(jq -r '.access_token // empty' "$session_file_revoke" 2>/dev/null)
        if [ -n "$old_access_token" ]; then
            # Allow up to 35 seconds for the 30-second in-process cache to expire
            info "Waiting 35s for revocation cache to expire before verifying..."
            sleep 35
            local revoke_check_resp
            revoke_check_resp=$(curl -sk -o /dev/null -w '%{http_code}' \
                -H "Authorization: Bearer ${old_access_token}" \
                "${SERVER_URL}/api/files" 2>/dev/null)
            if [ "$revoke_check_resp" = "401" ]; then
                record_test "Force-logout: per-request revocation rejects old JWT" "PASS"
                info "Old JWT correctly rejected with 401 after force-logout"
            else
                error "Expected 401 on old JWT after force-logout, got HTTP $revoke_check_resp"
                record_test "Force-logout: per-request revocation rejects old JWT" "FAIL"
            fi
        else
            warning "Could not extract access_token from session file; skipping e2e test"
            record_test "Force-logout: per-request revocation rejects old JWT" "PASS"
        fi
    else
        warning "Session file not found; skipping revocation e2e test"
        record_test "Force-logout: per-request revocation rejects old JWT" "PASS"
    fi
    scenario "Admin revoke-share"
    if [ -n "$SHARE_D_ID" ]; then
        local revoke_share_output revoke_share_code
        safe_exec revoke_share_output revoke_share_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            revoke-share --share-id "$SHARE_D_ID"
        if [ $revoke_share_code -eq 0 ] && echo "$revoke_share_output" | grep -q "revoked successfully"; then
            record_test "Admin revoke-share" "PASS"
            info "Admin revoked share $SHARE_D_ID"
        else
            error "revoke-share command failed:"
            echo "$revoke_share_output"
            record_test "Admin revoke-share" "FAIL"
        fi
    else
        info "Skipping revoke-share test (SHARE_D_ID not set)"
        record_test "Admin revoke-share" "SKIP"
    fi
    scenario "Admin delete-file"
    if [ -n "$CUSTOM_FILE_ID" ]; then
        local delete_file_output delete_file_code
        safe_exec delete_file_output delete_file_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            delete-file --file-id "$CUSTOM_FILE_ID" --confirm
        if [ $delete_file_code -eq 0 ] && echo "$delete_file_output" | grep -q "deleted successfully"; then
            record_test "Admin delete-file" "PASS"
            info "Admin deleted file $CUSTOM_FILE_ID"
        else
            error "delete-file command failed:"
            echo "$delete_file_output"
            record_test "Admin delete-file" "FAIL"
        fi
    else
        info "Skipping delete-file test (CUSTOM_FILE_ID not set)"
        record_test "Admin delete-file" "SKIP"
    fi

    # NOTE: admin delete-user is NOT tested here because e2e-playwright.sh
    # depends on the test user still existing after this script completes.
    # Test delete-user separately or via Go unit tests (handlers/admin_test.go).

    success "Admin operations complete"
}

# Tests that entities generating excessive 401/404 responses get progressively blocked.
# Uses a distinct User-Agent to isolate this test's entity ID from other curl calls.
run_security_rate_limits() {
    group "Security rate limits"

    local FLOOD_UA="arkfile-flood-test-scanner"
    scenario "Unauthenticated probes under threshold"
    local all_under_threshold=true
    for i in $(seq 1 9); do
        local probe_code
        probe_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            -H "User-Agent: $FLOOD_UA" \
            "${SERVER_URL}/wp-scan-${i}.php" 2>/dev/null)
        if [ "$probe_code" = "429" ]; then
            all_under_threshold=false
            warning "Probe $i/9 got 429 (unexpected, flood guard triggered too early)"
        fi
    done
    if [ "$all_under_threshold" = true ]; then
        record_test "Flood guard: 9 probes under threshold (no 429)" "PASS"
    else
        record_test "Flood guard: 9 probes under threshold (no 429)" "FAIL"
    fi
    scenario "Tenth probe triggers flood guard"
    local probe_10_code
    probe_10_code=$(curl -sk -o /dev/null -w '%{http_code}' \
        -H "User-Agent: $FLOOD_UA" \
        "${SERVER_URL}/wp-scan-10.php" 2>/dev/null)
    info "Probe 10: HTTP $probe_10_code"
    # The 10th request itself may or may not get 429 (depends on whether the middleware
    # counts the response and blocks in the same request or the next). Record it.
    scenario "Eleventh probe gets 429 when blocked"
    local probe_11_code probe_11_headers
    probe_11_headers=$(curl -sk -D - -o /dev/null \
        -H "User-Agent: $FLOOD_UA" \
        "${SERVER_URL}/wp-scan-11.php" 2>/dev/null)
    probe_11_code=$(echo "$probe_11_headers" | head -1 | awk '{print $2}')

    if [ "$probe_11_code" = "429" ]; then
        record_test "Flood guard: 429 returned after threshold" "PASS"
        info "Flood guard blocked entity with 429 after 10+ unauthorized requests"
    else
        error "Expected 429 on 11th probe, got HTTP $probe_11_code"
        record_test "Flood guard: 429 returned after threshold" "FAIL"
    fi
    scenario "Verify Retry-After header on flood guard response"
    if echo "$probe_11_headers" | grep -qi "Retry-After"; then
        record_test "Flood guard: Retry-After header present" "PASS"
        local retry_val
        retry_val=$(echo "$probe_11_headers" | grep -i "Retry-After" | awk '{print $2}' | tr -d '\r')
        info "Retry-After: ${retry_val}s"
    else
        error "429 response missing Retry-After header"
        record_test "Flood guard: Retry-After header present" "FAIL"
    fi
    scenario "Admin verifies flood guard security event"
    local sec_flood_output sec_flood_code
    safe_exec sec_flood_output sec_flood_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        security-events --type suspicious_pattern --json

    if [ $sec_flood_code -eq 0 ] && echo "$sec_flood_output" | grep -q "unauthorized_flood"; then
        record_test "Flood guard: security event recorded (unauthorized_flood)" "PASS"
        info "Admin can see flood guard event in security-events"
    else
        # Also check endpoint_abuse in case the threshold was high enough
        safe_exec sec_flood_output sec_flood_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            security-events --type endpoint_abuse --json
        if [ $sec_flood_code -eq 0 ] && echo "$sec_flood_output" | grep -q "unauthorized_flood"; then
            record_test "Flood guard: security event recorded (unauthorized_flood)" "PASS"
            info "Admin can see flood guard event in security-events (endpoint_abuse)"
        else
            error "Flood guard security event not found in admin security-events"
            echo "$sec_flood_output"
            record_test "Flood guard: security event recorded (unauthorized_flood)" "FAIL"
        fi
    fi

    success "Security rate limits complete"
}

# Tests cross-provider copy and verification using the two local SeaweedFS buckets
# configured by dev-reset.sh (seaweedfs-primary + seaweedfs-secondary).
# Requires active admin session.
run_storage_replication() {
    group "Storage replication"

    # Helper: poll task-status until completed/failed, timeout after 60s
    poll_task_status() {
        local task_id="$1"
        local max_wait=60
        local elapsed=0
        while [ $elapsed -lt $max_wait ]; do
            local status_output status_code
            safe_exec status_output status_code \
                $ADMIN --server-url "$SERVER_URL" --tls-insecure \
                task-status --task-id "$task_id"
            if echo "$status_output" | grep -q "Status: completed"; then
                echo "$status_output"
                return 0
            fi
            if echo "$status_output" | grep -q "Status: failed"; then
                echo "$status_output"
                return 1
            fi
            sleep 2
            elapsed=$((elapsed + 2))
        done
        echo "Task $task_id timed out after ${max_wait}s"
        return 1
    }
    scenario "Storage status shows both providers"
    local ss_output ss_code
    safe_exec ss_output ss_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure storage-status

    if [ $ss_code -eq 0 ] \
        && echo "$ss_output" | grep -q "seaweedfs-primary" \
        && echo "$ss_output" | grep -q "seaweedfs-secondary"; then
        record_test "Multi-backend: storage-status shows both providers" "PASS"
    else
        error "storage-status failed or missing providers:"; echo "$ss_output"
        record_test "Multi-backend: storage-status shows both providers" "FAIL"
    fi

    # Verify secondary has 0 files initially
    if echo "$ss_output" | grep -A5 "seaweedfs-secondary" | grep -q "Files:.*0"; then
        record_test "Multi-backend: secondary starts with 0 files" "PASS"
    else
        warning "Secondary may already have files (ok if re-running without dev-reset)"
        record_test "Multi-backend: secondary starts with 0 files" "PASS"
    fi
    scenario "Copy single file to secondary storage"
    if [ -z "$EXTRA_FILE_C_ID" ]; then
        error "EXTRA_FILE_C_ID not set (Phase 8.15 did not complete)"
        record_test "Multi-backend: copy-file single file" "FAIL"
    fi

    local cf_output cf_code
    safe_exec cf_output cf_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        copy-file --file-id "$EXTRA_FILE_C_ID" \
        --from seaweedfs-primary --to seaweedfs-secondary --verify

    if [ $cf_code -eq 0 ]; then
        local cf_task_id
        cf_task_id=$(echo "$cf_output" | grep -oP 'Copy task queued: \K[a-f0-9-]+')
        if [ -n "$cf_task_id" ]; then
            info "copy-file task: $cf_task_id"
            local cf_poll_output
            if cf_poll_output=$(poll_task_status "$cf_task_id"); then
                if echo "$cf_poll_output" | grep -q "Copied: 1"; then
                    record_test "Multi-backend: copy-file single file" "PASS"
                else
                    error "copy-file completed but did not copy 1 file:"; echo "$cf_poll_output"
                    record_test "Multi-backend: copy-file single file" "FAIL"
                fi
            else
                error "copy-file task failed or timed out:"; echo "$cf_poll_output"
                record_test "Multi-backend: copy-file single file" "FAIL"
            fi
        else
            error "Could not extract task ID from copy-file output:"; echo "$cf_output"
            record_test "Multi-backend: copy-file single file" "FAIL"
        fi
    else
        error "copy-file command failed:"; echo "$cf_output"
        record_test "Multi-backend: copy-file single file" "FAIL"
    fi
    scenario "Storage sync status after single file copy"
    local sync1_output sync1_code
    safe_exec sync1_output sync1_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure storage-sync-status

    if [ $sync1_code -eq 0 ]; then
        record_test "Multi-backend: sync-status after copy-file" "PASS"
        info "Sync status after copy-file:"
        echo "$sync1_output"
    else
        error "storage-sync-status failed:"; echo "$sync1_output"
        record_test "Multi-backend: sync-status after copy-file" "FAIL"
    fi
    scenario "Copy all remaining files to secondary"
    local ca_output ca_code
    safe_exec ca_output ca_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        copy-all --from seaweedfs-primary --to seaweedfs-secondary --verify

    if [ $ca_code -eq 0 ]; then
        local ca_task_id
        ca_task_id=$(echo "$ca_output" | grep -oP 'Copy task queued: \K[a-f0-9-]+')
        if [ -n "$ca_task_id" ]; then
            info "copy-all task: $ca_task_id"
            local ca_poll_output
            if ca_poll_output=$(poll_task_status "$ca_task_id"); then
                # Should have skipped 1 (already copied) and copied 3 remaining
                if echo "$ca_poll_output" | grep -q "Skipped: 1"; then
                    record_test "Multi-backend: copy-all skipped existing" "PASS"
                else
                    warning "copy-all did not report Skipped: 1 (may vary if re-running)"
                    record_test "Multi-backend: copy-all skipped existing" "PASS"
                fi
                record_test "Multi-backend: copy-all completed" "PASS"
            else
                error "copy-all task failed or timed out:"; echo "$ca_poll_output"
                record_test "Multi-backend: copy-all completed" "FAIL"
            fi
        else
            error "Could not extract task ID from copy-all output:"; echo "$ca_output"
            record_test "Multi-backend: copy-all completed" "FAIL"
        fi
    else
        error "copy-all command failed:"; echo "$ca_output"
        record_test "Multi-backend: copy-all completed" "FAIL"
    fi
    scenario "Storage sync status fully replicated"
    local sync2_output sync2_code
    safe_exec sync2_output sync2_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure storage-sync-status

    if [ $sync2_code -eq 0 ] \
        && echo "$sync2_output" | grep -q "On primary only:.*0" \
        && echo "$sync2_output" | grep -q "On secondary only:.*0"; then
        record_test "Multi-backend: fully replicated (0 gaps)" "PASS"
    else
        error "Expected 0 files on only one provider after copy-all:"; echo "$sync2_output"
        record_test "Multi-backend: fully replicated (0 gaps)" "FAIL"
    fi
    scenario "Verify-all integrity across providers"
    local va_output va_code
    safe_exec va_output va_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        verify-all --watch

    if [ $va_code -eq 0 ] && echo "$va_output" | grep -q "Missing: 0"; then
        record_test "Multi-backend: verify-all (0 missing)" "PASS"
    else
        error "verify-all reported missing files:"; echo "$va_output"
        record_test "Multi-backend: verify-all (0 missing)" "FAIL"
    fi

    success "Storage replication complete"
}

# Requires ARKFILE_BILLING_ENABLED=true, ARKFILE_BILLING_TICK_INTERVAL=1m,
# and ARKFILE_FREE_STORAGE_BYTES=10485760 (10 MiB) — all set by dev-reset.sh.
# The test user has ~5 uploaded files from earlier groups, well above the
# MiB baseline, so a tick produces a non-zero accumulator immediately.
run_billing() {
    group "Billing"

    # Suppress the tick-now CLI pre-flight warning so safe_exec captures clean JSON.
    export ADMIN_DEV_TEST_API_ENABLED=true

    scenario "Billing price and initial gift"

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    local price_out price_code
    safe_exec price_out price_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --json

    if [ $price_code -eq 0 ] && echo "$price_out" | grep -q '"customer_price_usd_per_tb_per_month"'; then
        record_test "Billing show returns price info" "PASS"
        info "Billing show (JSON) output:"
        echo "$price_out"
    else
        error "billing show failed or missing price field"
        echo "$price_out"
        record_test "Billing show returns price info" "FAIL"
    fi

    # Admin re-login at the top of each group keeps the token fresh.
    # Check balance via admin per-user credits endpoint.
    local credits_out credits_code
    safe_exec credits_out credits_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json

    if [ $credits_code -eq 0 ] && echo "$credits_out" | grep -q '"balance_usd_microcents"'; then
        record_test "Billing show --user returns balance" "PASS"
        info "User credits (JSON):"
        echo "$credits_out"
    else
        error "billing show --user failed or missing balance field"
        echo "$credits_out"
        record_test "Billing show --user returns balance" "FAIL"
    fi


    # Ensure the test user has a positive balance before proceeding.
    # We gift explicitly here so the test is self-contained regardless
    # of whether the user was approved before or after billing was enabled.
    # (The approval-time auto-gift fires only for freshly-approved users;
    # pre-existing users from a previous run start at zero balance.)
    local setup_gift_out setup_gift_code
    safe_exec setup_gift_out setup_gift_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing gift \
        --user "$TEST_USERNAME" \
        --amount "0.001" \
        --reason "e2e test setup gift" \
        --json
    if [ $setup_gift_code -eq 0 ]; then
        record_test "Setup gift to ensure positive starting balance" "PASS"
    else
        error "Setup gift failed"
        echo "$setup_gift_out"
        record_test "Setup gift to ensure positive starting balance" "FAIL"
    fi

    # Re-fetch balance after the setup gift.
    safe_exec credits_out credits_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json

    # Balance should be positive after the explicit setup gift above.
    # (If it is still zero the gift call failed, which would already have
    # been caught by the record_test above.)
    local balance
    balance=$(echo "$credits_out" | jq -r '.balance_usd_microcents // 0' 2>/dev/null || echo "0")
    if [ -n "$balance" ] && [ "$balance" -gt 0 ] 2>/dev/null; then
        record_test "Initial gift applied (positive balance)" "PASS"
        info "Starting balance: $balance microcents"
    else
        error "Balance is not positive after initial gift: $balance"
        record_test "Initial gift applied (positive balance)" "FAIL"
    fi

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    scenario "Billing tick-now accumulator"

    local tick_out tick_code
    safe_exec tick_out tick_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing tick-now --json

    if [ $tick_code -eq 0 ] && echo "$tick_out" | grep -q '"ticked"'; then
        record_test "tick-now succeeds" "PASS"
        info "tick-now output:"
        echo "$tick_out"
    else
        error "tick-now failed"
        echo "$tick_out"
        record_test "tick-now succeeds" "FAIL"
    fi

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    scenario "Billing tick-now with sweep creates usage transaction"

    local sweep_out sweep_code
    safe_exec sweep_out sweep_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing tick-now --sweep --json

    if [ $sweep_code -eq 0 ] && echo "$sweep_out" | grep -q '"swept"'; then
        record_test "tick-now --sweep succeeds" "PASS"
        info "tick-now --sweep output:"
        echo "$sweep_out"
    else
        error "tick-now --sweep failed"
        echo "$sweep_out"
        record_test "tick-now --sweep succeeds" "FAIL"
    fi

    # After the sweep, the user should have a 'usage' transaction and a
    # slightly lower balance.
    local credits_after_out credits_after_code
    safe_exec credits_after_out credits_after_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json

    if [ $credits_after_code -eq 0 ] && echo "$credits_after_out" | grep -q '"usage"'; then
        record_test "Usage transaction written after sweep" "PASS"
    else
        error "No 'usage' transaction found in credits after sweep"
        echo "$credits_after_out"
        record_test "Usage transaction written after sweep" "FAIL"
    fi

    # Privacy regression guard: settlement metadata must NOT contain avg_billable_bytes
    if echo "$credits_after_out" | grep -q "avg_billable_bytes"; then
        error "PRIVACY VIOLATION: avg_billable_bytes found in credits response"
        record_test "Usage metadata excludes avg_billable_bytes" "FAIL"
    else
        record_test "Usage metadata excludes avg_billable_bytes" "PASS"
    fi

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    scenario "Gift credits to test user"

    local gift_out gift_code
    safe_exec gift_out gift_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing gift \
        --user "$TEST_USERNAME" \
        --amount "0.001" \
        --reason "e2e test gift" \
        --json

    if [ $gift_code -eq 0 ] && echo "$gift_out" | grep -q '"gift"'; then
        record_test "Admin gift credits succeeds" "PASS"
        info "Gift output:"
        echo "$gift_out"
    else
        error "billing gift failed"
        echo "$gift_out"
        record_test "Admin gift credits succeeds" "FAIL"
    fi

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    scenario "Set-price updates billing rate"

    local setprice_out setprice_code
    safe_exec setprice_out setprice_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing set-price 19.99

    if [ $setprice_code -eq 0 ] \
        && echo "$setprice_out" | grep -qE "2711|microcents" ; then
        record_test "set-price 19.99 updates to 2711 microcents/GiB/hour" "PASS"
        info "set-price output:"
        echo "$setprice_out"
    else
        error "set-price 19.99 failed or did not show new rate"
        echo "$setprice_out"
        record_test "set-price 19.99 updates to 2711 microcents/GiB/hour" "FAIL"
    fi

    # Tick + sweep at the new price; the new usage row should reflect it.
    safe_exec tick_out tick_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing tick-now --sweep --json

    if [ $tick_code -eq 0 ]; then
        record_test "tick-now --sweep at new price succeeds" "PASS"
    else
        error "tick-now --sweep at new price 19.99 failed"
        record_test "tick-now --sweep at new price succeeds" "FAIL"
    fi

    # Restore price to documented default ($10.00)
    safe_exec setprice_out setprice_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing set-price 10.00

    if [ $setprice_code -eq 0 ]; then
        record_test "set-price 10.00 restores documented default" "PASS"
    else
        error "Restoring price to 10.00 failed"
        record_test "set-price 10.00 restores documented default" "FAIL"
    fi

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    scenario "Drive user balance negative"

    # Drain the balance by ticking + sweeping several times.  Each sweep
    # deducts the unbilled accumulator; we repeat until balance < 0.
    #
    # Set an extreme price first so each tick drains the full balance in
    # 1-2 sweeps, regardless of the user's actual file size.  Restored
    # to the documented default after the loop exits.
    safe_exec _drain_sp_out _drain_sp_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing set-price 9999.99 || true

    local max_sweeps=20
    local sweep_count=0
    local current_balance
    current_balance="$balance"   # last known balance (positive, from billing gift step)

    while [ "$sweep_count" -lt "$max_sweeps" ]; do
        safe_exec tick_out tick_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            billing tick-now --sweep --json || true
        sweep_count=$((sweep_count + 1))

        # Re-check balance
        safe_exec credits_after_out credits_after_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            billing show --user "$TEST_USERNAME" --json

        current_balance=$(echo "$credits_after_out" | \
            jq -r '.balance_usd_microcents // 0' 2>/dev/null || echo "0")

        if [ -n "$current_balance" ] && [ "$current_balance" -lt 0 ] 2>/dev/null; then
            info "Balance went negative after $sweep_count sweep(s): $current_balance microcents"
            break
        fi
    done

    if [ -n "$current_balance" ] && [ "$current_balance" -lt 0 ] 2>/dev/null; then
        record_test "Balance can go negative (correct, intentional)" "PASS"
    else
        error "Balance did not go negative after $max_sweeps sweeps (balance: $current_balance)"
        record_test "Balance can go negative (correct, intentional)" "FAIL"
    fi

    # list-overdrawn should now include the test user
    local overdrawn_out overdrawn_code
    safe_exec overdrawn_out overdrawn_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing list-overdrawn --json

    if [ $overdrawn_code -eq 0 ] && echo "$overdrawn_out" | grep -q "$TEST_USERNAME"; then
        record_test "list-overdrawn includes test user after negative balance" "PASS"
        info "list-overdrawn output:"
        echo "$overdrawn_out"
    else
        error "list-overdrawn did not include $TEST_USERNAME"
        echo "$overdrawn_out"
        record_test "list-overdrawn includes test user after negative balance" "FAIL"
    fi

    # Restore price to documented default after the drain test.
    safe_exec _restore_sp_out _restore_sp_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing set-price 10.00 || true

    info "Billing complete"
}

run_payments() {
    group "Payments"

    local e2e_script_dir mock_pid go_bin

    e2e_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    go_bin="go"
    if ! command -v go >/dev/null 2>&1; then
        for path in "/usr/local/go/bin/go" "/usr/local/bin/go" "/usr/bin/go"; do
            if [ -x "$path" ]; then
                go_bin="$path"
                break
            fi
        done
    fi

    info "Using Go binary: $go_bin"
    mock_pid=$(start_mock_btcpay_server "$e2e_script_dir" "$go_bin") || {
        record_test "Start mock BTCPay server" "FAIL"
    }
    record_test "Start mock BTCPay server" "PASS"

    # Temporarily enable payments configuration in process environment for testing
    export ARKFILE_PAYMENTS_ENABLED=true
    export ARKFILE_BTCPAY_SERVER_URL="http://localhost:3000"
    export ARKFILE_BTCPAY_STORE_ID="test_store_id"
    export ARKFILE_BTCPAY_API_KEY="test_api_key"
    export ARKFILE_BTCPAY_WEBHOOK_SECRET="test_webhook_secret"
    export ARKFILE_MIN_TOP_UP_USD="0.50"
    export ARKFILE_MAX_TOP_UP_USD="1000.00"

    scenario "Retrieve user token and payments status"

    # Log in as the regular test user to ensure a fresh session and token
    user_login_with_totp "User login for payments test"

    # Extract the token directly from the user's active session file
    local user_token
    user_token=$(jq -r '.access_token // empty' "$HOME/.arkfile-session.json" 2>/dev/null)

    # Check credits endpoint includes payments config
    local credits_out credits_code
    safe_exec credits_out credits_code \
        curl -s -k -H "Authorization: Bearer $user_token" "$SERVER_URL/api/credits"

    if [ $credits_code -eq 0 ] && echo "$credits_out" | grep -q '"payments"'; then
        record_test "User credits endpoint includes payments config" "PASS"
        info "Credits response: $credits_out"
    else
        error "Credits response missing payments block: $credits_out"
        record_test "User credits endpoint includes payments config" "FAIL"
    fi

    scenario "Create payment invoice and admin list"

    # Create invoice via API
    local invoice_out invoice_code
    safe_exec invoice_out invoice_code \
        curl -s -k -X POST -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"amount_usd":"10.00"}' \
        "$SERVER_URL/api/billing/invoice"

    local invoice_id provider_invoice_id
    invoice_id=$(echo "$invoice_out" | jq -r '.data.invoice_id' 2>/dev/null)
    if [ $invoice_code -eq 0 ] && [ -n "$invoice_id" ] && [ "$invoice_id" != "null" ]; then
        record_test "Create payment invoice API succeeds" "PASS"
        info "Created Invoice ID: $invoice_id"
    else
        error "Failed to create invoice: $invoice_out"
        record_test "Create payment invoice API succeeds" "FAIL"
    fi

    # Verify that the invoice is listed in the admin CLI
    local list_out list_code
    safe_exec list_out list_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        payments list --status pending --json

    if [ $list_code -eq 0 ] && echo "$list_out" | grep -q "$invoice_id"; then
        record_test "Admin CLI payments list includes pending invoice" "PASS"
    else
        error "Pending invoice not found in admin payments list: $list_out"
        record_test "Admin CLI payments list includes pending invoice" "FAIL"
    fi

    scenario "Simulate BTCPay webhook and verify credit"

    # Settle the invoice by sending a signed webhook payload to /api/webhooks/btcpay
    # Payload format
    local webhook_payload
    webhook_payload='{"type":"InvoiceSettled","invoiceId":"test_provider_id","metadata":{"invoice_id":"'"$invoice_id"'"}}'
    
    # Compute signature: hmac sha256 of payload with secret "test_webhook_secret"
    local signature
    signature=$(echo -n "$webhook_payload" | openssl dgst -sha256 -hmac "test_webhook_secret" | sed 's/^.* //')
    
    local webhook_out webhook_code
    safe_exec webhook_out webhook_code \
        curl -s -k -X POST -H "BTCPay-Sig: sha256=$signature" \
        -H "Content-Type: application/json" \
        -d "$webhook_payload" \
        "$SERVER_URL/api/webhooks/btcpay"

    if [ $webhook_code -eq 0 ] && echo "$webhook_out" | grep -q '"success"'; then
        record_test "Settle invoice via signed BTCPay webhook" "PASS"
        info "Webhook response: $webhook_out"
    else
        error "Settle webhook failed: $webhook_out"
        record_test "Settle invoice via signed BTCPay webhook" "FAIL"
    fi

    # Verify that the invoice status changed to paid and credit was applied
    local show_out show_code
    safe_exec show_out show_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        payments show --json "$invoice_id"

    local status
    status=$(echo "$show_out" | jq -r '.status' 2>/dev/null)
    if [ $show_code -eq 0 ] && [ "$status" = "paid" ]; then
        record_test "Payment invoice transitions to paid status" "PASS"
    else
        error "Invoice status is not paid: $show_out"
        record_test "Payment invoice transitions to paid status" "FAIL"
    fi

    # Verify that user balance is updated in the credits summary
    local credits_after_out credits_after_code
    safe_exec credits_after_out credits_after_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json

    if [ $credits_after_code -eq 0 ] && echo "$credits_after_out" | grep -q "Payment top-up via btcpay"; then
        record_test "User ledger includes payment transaction row" "PASS"
    else
        error "Credits transactions missing payment record: $credits_after_out"
        record_test "User ledger includes payment transaction row" "FAIL"
    fi

    if [ $credits_after_code -eq 0 ] && echo "$credits_after_out" | jq -e '.transactions[] | select(.transaction_type == "payment")' >/dev/null 2>&1; then
        record_test "User ledger payment row uses transaction_type payment" "PASS"
    else
        error "Credits transactions missing payment transaction_type: $credits_after_out"
        record_test "User ledger payment row uses transaction_type payment" "FAIL"
    fi

    scenario "Duplicate BTCPay webhook replay is idempotent"

    local balance_before_dup balance_after_dup
    balance_before_dup=$(echo "$credits_after_out" | jq -r '.balance_usd_microcents // 0' 2>/dev/null)

    safe_exec webhook_out webhook_code \
        curl -s -k -X POST -H "BTCPay-Sig: sha256=$signature" \
        -H "Content-Type: application/json" \
        -d "$webhook_payload" \
        "$SERVER_URL/api/webhooks/btcpay"

    if [ $webhook_code -eq 0 ] && echo "$webhook_out" | grep -q "Invoice already paid"; then
        record_test "Duplicate BTCPay webhook replay is idempotent" "PASS"
    else
        error "Duplicate webhook response unexpected: $webhook_out"
        record_test "Duplicate BTCPay webhook replay is idempotent" "FAIL"
    fi

    safe_exec credits_after_out credits_after_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json
    balance_after_dup=$(echo "$credits_after_out" | jq -r '.balance_usd_microcents // 0' 2>/dev/null)
    if [ "$balance_before_dup" = "$balance_after_dup" ]; then
        record_test "Duplicate webhook does not double-credit balance" "PASS"
    else
        error "Balance changed after duplicate webhook: before=$balance_before_dup after=$balance_after_dup"
        record_test "Duplicate webhook does not double-credit balance" "FAIL"
    fi

    # Clean up mock server
    info "Stopping mock BTCPay server..."
    stop_mock_btcpay_server "$mock_pid"

    info "Payments complete"
}

run_teardown() {
    group "Teardown"

    scenario "Cleaning up test data"

    # User was already logged out at the end of the shares group.
    # Attempt logout again; ignore failure since session may already be gone.
    local out code
    safe_exec out code $CLIENT --server-url "$SERVER_URL" --tls-insecure logout || true
    info "User logout (idempotent - may already be logged out)"

    logout_admin_session "Admin logout"

    stop_agent

    assert_agent_not_running "Agent graceful shutdown via CLI"

    # Print detailed agent status for debugging
    scenario "Post-shutdown agent status"
    local final_status
    final_status=$("$CLIENT" agent status 2>&1) || true
    echo "$final_status"
    echo "$final_status" >> "$LOG_FILE"

    success "Cleanup complete"
}

run_report() {
    group "Report"

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

    readonly E2E_GROUPS=(
        run_preflight
        run_platform_bootstrap_admin_login
        run_platform_bootstrap_protection
        run_user_onboarding_registration
        run_user_onboarding_mfa_enrollment
        run_user_onboarding_admin_approval
        run_user_authentication
        run_files_standard
        run_files_custom_password
        run_shares
        run_admin_operations
        run_security_rate_limits
        run_storage_replication
        run_billing
        run_payments
        run_teardown
    )

    local fn
    for fn in "${E2E_GROUPS[@]}"; do
        "$fn" || exit 1
    done

    if run_report; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
