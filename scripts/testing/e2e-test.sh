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
umask 077
TEST_DATA_DIR="/tmp/arkfile-e2e-test-data"
mkdir -p "$TEST_DATA_DIR"
chmod 700 "$TEST_DATA_DIR"
MFA_SECRET_FILE="$TEST_DATA_DIR/mfa-secret"
BACKUP_CODE_PRIMARY_FILE="$TEST_DATA_DIR/backup-code-primary"
BACKUP_CODE_REENROLL_FILE="$TEST_DATA_DIR/backup-code-reenroll"
MFA_ADMIN_RESET_DONE_FILE="$TEST_DATA_DIR/mfa-admin-reset-done"
LOG_FILE="$TEST_DATA_DIR/e2e-test.log"

# Initialize log file
: > "$LOG_FILE"
chmod 600 "$LOG_FILE"
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

write_secret_file() {
    local file_path="$1"
    local value="$2"
    printf '%s\n' "$value" > "$file_path"
    chmod 600 "$file_path"
}

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
        printf '%s\n' "$out"
    else
        error "$test_name failed with output:"
        printf '%s\n' "$out"
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
        printf '%s\n' "$out"
    else
        error "$test_name failed with output:"
        printf '%s\n' "$out"
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
        printf '%s\n' "$out"
    else
        error "$test_name failed with output:"
        printf '%s\n' "$out"
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
        printf '%s\n' "$out"
    else
        error "$test_name failed with output:"
        printf '%s\n' "$out"
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
        recover-mfa --code "$reenroll_code" \
        --method-type totp --non-interactive --show-secret

    if [ $code -ne 0 ] || ! echo "$out" | grep -q "MFA Reset Complete"; then
        error "$test_name failed with output:"
        printf '%s\n' "$out"
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
    write_secret_file "$MFA_SECRET_FILE" "$new_secret"

    local new_backup_code
    new_backup_code=$(echo "$out" | grep '^BACKUP_CODE_0:' | head -1 | cut -d':' -f2 | tr -d ' ')
    if [ -z "$new_backup_code" ]; then
        error "Failed to extract primary backup code after MFA re-enrollment reset"
        record_test "Backup code capture after re-enrollment" "FAIL"
        return 1
    fi
    write_secret_file "$BACKUP_CODE_PRIMARY_FILE" "$new_backup_code"
    export TEST_USER_BACKUP_CODE="$new_backup_code"
    record_test "Backup code capture after re-enrollment" "PASS"

    record_test "$test_name" "PASS"
    printf '%s\n' "$out"
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
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --mfa-method totp --verify "$code"

    if [ $code_rc -ne 0 ] || ! echo "$out" | grep -q "MFA setup complete"; then
        error "$test_name failed with output:"
        printf '%s\n' "$out"
        record_test "$test_name" "FAIL"
        return 1
    fi

    record_test "$test_name" "PASS"
    printf '%s\n' "$out"
}

user_mfa_enroll_after_deferred_login() {
    local test_name="$1"

    info "Initiating MFA setup after admin reset..."
    local setup_output setup_exit_code
    safe_exec setup_output setup_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --mfa-method totp --show-secret

    if [ $setup_exit_code -ne 0 ]; then
        error "Failed to initiate MFA setup after admin reset:"
        printf '%s\n' "$setup_output"
        record_test "$test_name (setup initiation)" "FAIL"
        return 1
    fi

    local secret
    secret=$(echo "$setup_output" | grep "TOTP_SECRET:" | cut -d':' -f2 | tr -d ' ')
    if [ -z "$secret" ]; then
        error "Failed to extract TOTP secret after admin reset:"
        printf '%s\n' "$setup_output"
        record_test "$test_name (setup initiation)" "FAIL"
        return 1
    fi

    write_secret_file "$MFA_SECRET_FILE" "$secret"
    export TEST_USER_TOTP_SECRET="$secret"
    record_test "$test_name (setup initiation)" "PASS"

    local backup_code
    backup_code=$(echo "$setup_output" | grep '^BACKUP_CODE_0:' | head -1 | cut -d':' -f2 | tr -d ' ')
    if [ -n "$backup_code" ]; then
        write_secret_file "$BACKUP_CODE_PRIMARY_FILE" "$backup_code"
        export TEST_USER_BACKUP_CODE="$backup_code"
    fi

    wait_for_totp_window
    local code
    code=$("$CLIENT" generate-totp --secret "$secret" 2>/dev/null)
    if [ -z "$code" ]; then
        error "Could not generate verification code after admin reset"
        record_test "$test_name (verify)" "FAIL"
        return 1
    fi

    local verify_output verify_exit_code
    safe_exec verify_output verify_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --mfa-method totp --verify "$code"

    if [ $verify_exit_code -ne 0 ] || ! echo "$verify_output" | grep -q "MFA setup complete"; then
        error "MFA verification after admin reset failed:"
        printf '%s\n' "$verify_output"
        record_test "$test_name (verify)" "FAIL"
        return 1
    fi

    record_test "$test_name (verify)" "PASS"
    printf '%s\n' "$verify_output"
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
    local status_out status_code
    safe_exec status_out status_code "$CLIENT" agent status
    if [ $status_code -ne 0 ]; then
        record_test "$test_name" "FAIL"
    elif echo "$status_out" | grep -q "Agent Status: RUNNING"; then
        record_test "$test_name" "PASS"
    else
        record_test "$test_name" "FAIL"
    fi
}

assert_agent_not_running() {
    local test_name="$1"
    local status_out status_code
    safe_exec status_out status_code "$CLIENT" agent status
    if [ $status_code -eq 0 ] && echo "$status_out" | grep -q "Agent Status: NOT RUNNING"; then
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

    local command_name="${1##*/}"
    echo "[EXEC] $command_name (arguments omitted)" >> "$LOG_FILE"

    set +e
    temp_output=$("$@" 2>&1)
    temp_exit_code=$?
    set -e

    printf '%s\n' "$temp_output" >> "$LOG_FILE"
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
    local mock_log="$TEST_DATA_DIR/btcpay-mock.log"
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
    local readyz_body readyz_code
    readyz_body=$(curl -sk --connect-timeout 5 -w '\n%{http_code}' "$SERVER_URL/readyz" 2>/dev/null || echo -e '\n000')
    readyz_code=$(echo "$readyz_body" | tail -n1)
    readyz_body=$(echo "$readyz_body" | sed '$d')
    if [ "$readyz_code" = "200" ] && echo "$readyz_body" | jq -e '.status == "ready"' >/dev/null 2>&1; then
        record_test "Server connectivity (/readyz)" "PASS"
    else
        record_test "Server connectivity (/readyz)" "FAIL"
        error "Preflight /readyz failed (HTTP $readyz_code)"
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

    scenario "CLI version commands"
    local client_version_out client_version_code admin_version_out admin_version_code
    safe_exec client_version_out client_version_code "$CLIENT" version
    if [ $client_version_code -eq 0 ] && echo "$client_version_out" | grep -Eq '^arkfile-client .+'; then
        record_test "arkfile-client version" "PASS"
        info "Client version: $client_version_out"
    else
        error "arkfile-client version failed:"
        echo "$client_version_out"
        record_test "arkfile-client version" "FAIL"
    fi

    safe_exec admin_version_out admin_version_code "$ADMIN" version
    if [ $admin_version_code -eq 0 ] && echo "$admin_version_out" | grep -Eq '^arkfile-admin .+'; then
        record_test "arkfile-admin version" "PASS"
        info "Admin version: $admin_version_out"
    else
        error "arkfile-admin version failed:"
        echo "$admin_version_out"
        record_test "arkfile-admin version" "FAIL"
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

    info "Initiating MFA setup..."
    local setup_output
    local setup_exit_code

    safe_exec setup_output setup_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --mfa-method totp --show-secret

    if [ $setup_exit_code -ne 0 ]; then
        error "Failed to initiate TOTP setup (exit code: $setup_exit_code):"
        printf '%s\n' "$setup_output"
        record_test "TOTP setup initiation" "FAIL"
    fi

    # Extract secret
    local secret
    secret=$(echo "$setup_output" | grep "TOTP_SECRET:" | cut -d':' -f2 | tr -d ' ')

    if [ -z "$secret" ]; then
        error "Failed to extract TOTP secret from output:"
        printf '%s\n' "$setup_output"
        record_test "TOTP setup initiation" "FAIL"
    fi

    write_secret_file "$MFA_SECRET_FILE" "$secret"
    export TEST_USER_TOTP_SECRET="$secret"
    record_test "TOTP setup initiation" "PASS"
    info "Captured TOTP secret for automated verification"

    # Backup codes are returned on setup (verify only stores hashes server-side).
    local backup_code reenroll_code
    backup_code=$(echo "$setup_output" | grep '^BACKUP_CODE_0:' | head -1 | cut -d':' -f2 | tr -d ' ')
    reenroll_code=$(echo "$setup_output" | grep '^BACKUP_CODE_1:' | head -1 | cut -d':' -f2 | tr -d ' ')
    if [ -z "$backup_code" ]; then
        error "Failed to extract primary backup code from setup output"
        record_test "Backup code capture" "FAIL"
    else
        write_secret_file "$BACKUP_CODE_PRIMARY_FILE" "$backup_code"
        export TEST_USER_BACKUP_CODE="$backup_code"
        record_test "Backup code capture" "PASS"
        info "Saved primary backup code for one-shot login test"
    fi
    if [ -z "$reenroll_code" ]; then
        error "Failed to extract re-enrollment backup code from setup output"
        record_test "Re-enrollment backup code capture" "FAIL"
    else
        write_secret_file "$BACKUP_CODE_REENROLL_FILE" "$reenroll_code"
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

    safe_exec verify_output verify_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure setup-mfa --mfa-method totp --verify "$code"

    if [ $verify_exit_code -eq 0 ] && echo "$verify_output" | grep -q "MFA setup complete"; then
        record_test "TOTP verification" "PASS"
        printf '%s\n' "$verify_output"
    else
        error "TOTP verification failed:"
        printf '%s\n' "$verify_output"
        record_test "TOTP verification" "FAIL"
    fi

    success "MFA enrollment complete"
}

run_dual_mfa_api_checks() {
    group "Dual MFA — credential API checks"

    scenario "List enrolled MFA credentials after admin approval"

    # Requires RequireApproved: login fresh after approval, not the pre-approval MFA setup session.
    user_login_with_totp "Login after approval for MFA credential checks"
    local user_token
    user_token=$(jq -r '.access_token // empty' "$HOME/.arkfile-session.json" 2>/dev/null)

    if [ -z "$user_token" ]; then
        error "No access token available for MFA credential checks"
        record_test "MFA credentials list includes TOTP" "FAIL"
        record_test "Add-second TOTP rejected when TOTP enrolled" "FAIL"
        return
    fi

    local creds_body creds_http creds_out
    creds_body=$(mktemp)
    creds_http=$(curl -sk -o "$creds_body" -w '%{http_code}' \
        -H "Authorization: Bearer $user_token" \
        "$SERVER_URL/api/mfa/credentials")
    creds_out=$(cat "$creds_body")
    rm -f "$creds_body"

    if [ "$creds_http" = "200" ] && echo "$creds_out" | grep -q 'totp'; then
        record_test "MFA credentials list includes TOTP" "PASS"
        info "MFA credentials list returned TOTP enrollment metadata"
    else
        error "Expected HTTP 200 with TOTP credential; got HTTP $creds_http"
        record_test "MFA credentials list includes TOTP" "FAIL"
    fi

    local add_out add_code
    safe_exec add_out add_code \
        curl -s -k -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{}' \
        "$SERVER_URL/api/mfa/credentials/totp/add"

    if [ "$add_out" = "409" ]; then
        record_test "Add-second TOTP rejected when TOTP enrolled" "PASS"
    else
        error "Expected HTTP 409 when adding duplicate TOTP, got: $add_out"
        record_test "Add-second TOTP rejected when TOTP enrolled" "FAIL"
    fi

    info "WebAuthn add-second and dual-method login require hardware key; skipped in automated e2e"
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
    user_login_with_totp "Login with new MFA secret after re-enrollment"

    scenario "One-shot backup code login as $TEST_USERNAME"
    user_login_with_backup_code "One-shot backup code login"

    assert_agent_running "Agent auto-start verification"

    scenario "Refresh token rotation and reuse detection"
    local session_file="$HOME/.arkfile-session.json"
    if [ ! -f "$session_file" ]; then
        error "Session file missing immediately after successful backup-code login"
        record_test "Refresh token prerequisites" "FAIL"
    fi

    local old_refresh_token
    if ! old_refresh_token=$(jq -r '.refresh_token // empty' "$session_file" 2>/dev/null); then
        old_refresh_token=""
    fi
    if [ -z "$old_refresh_token" ]; then
        error "Refresh token missing immediately after successful backup-code login"
        record_test "Refresh token prerequisites" "FAIL"
    fi
    record_test "Refresh token prerequisites" "PASS"

    local rotate_body_file rotate_body rotate_http rotate_code
    rotate_body_file=$(mktemp "$TEST_DATA_DIR/refresh-rotate.XXXXXX")
    safe_exec rotate_http rotate_code \
        curl -skS -o "$rotate_body_file" -w '%{http_code}' \
        -X POST "${SERVER_URL}/api/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refresh_token\":\"${old_refresh_token}\"}"
    rotate_body=$(<"$rotate_body_file")
    rm -f "$rotate_body_file"

    local new_access_token new_refresh_token
    if ! new_access_token=$(echo "$rotate_body" | jq -r '.data.token // empty' 2>/dev/null); then
        new_access_token=""
    fi
    if ! new_refresh_token=$(echo "$rotate_body" | jq -r '.data.refresh_token // empty' 2>/dev/null); then
        new_refresh_token=""
    fi
    if [ $rotate_code -eq 0 ] \
        && [ "$rotate_http" = "200" ] \
        && [ -n "$new_access_token" ] \
        && [ -n "$new_refresh_token" ] \
        && [ "$new_refresh_token" != "$old_refresh_token" ]; then
        record_test "Refresh rotation returns a new token pair" "PASS"
    else
        error "Refresh rotation did not return HTTP 200 with a new JWT and refresh token"
        record_test "Refresh rotation returns a new token pair" "FAIL"
    fi

    local reuse_http reuse_code
    safe_exec reuse_http reuse_code \
        curl -skS -o /dev/null -w '%{http_code}' \
        -X POST "${SERVER_URL}/api/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refresh_token\":\"${old_refresh_token}\"}"
    if [ $reuse_code -eq 0 ] && [ "$reuse_http" = "401" ]; then
        record_test "Refresh token reuse rejected" "PASS"
    else
        error "Expected HTTP 401 on superseded refresh-token replay, got HTTP $reuse_http"
        record_test "Refresh token reuse rejected" "FAIL"
    fi

    local family_http family_code
    safe_exec family_http family_code \
        curl -skS -o /dev/null -w '%{http_code}' \
        -X POST "${SERVER_URL}/api/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refresh_token\":\"${new_refresh_token}\"}"
    if [ $family_code -eq 0 ] && [ "$family_http" = "401" ]; then
        record_test "Refresh-token family revoked after reuse" "PASS"
    else
        error "Expected HTTP 401 for refresh token in reused family, got HTTP $family_http"
        record_test "Refresh-token family revoked after reuse" "FAIL"
    fi

    local reused_jwt_http reused_jwt_code
    safe_exec reused_jwt_http reused_jwt_code \
        curl -skS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${new_access_token}" \
        "${SERVER_URL}/api/files"
    if [ $reused_jwt_code -eq 0 ] && [ "$reused_jwt_http" = "401" ]; then
        record_test "JWT revoked after refresh-token reuse" "PASS"
    else
        error "Expected HTTP 401 for JWT after refresh-token reuse, got HTTP $reused_jwt_http"
        record_test "JWT revoked after refresh-token reuse" "FAIL"
    fi

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
    # Unique sentinel hint: must never appear as plaintext in API/DB/list output.
    local CUSTOM_HINT_SENTINEL="e2e-hint-sentinel-$(date +%s)-$$"
    # CLI prompts for: custom password (once) + confirmation (once)
    scenario "Uploading file with custom password"
    local custom_upload_output custom_upload_exit_code
    safe_exec custom_upload_output custom_upload_exit_code \
        bash -c "printf '%s\n%s\n' '$CUSTOM_FILE_PASSWORD' '$CUSTOM_FILE_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        upload \
        --file '$custom_test_file' \
        --password-type custom \
        --hint '$CUSTOM_HINT_SENTINEL'"

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
    elif echo "$list_raw_output" | grep -Fq "$CUSTOM_HINT_SENTINEL"; then
        error "Security failure: Raw list API exposed plaintext password hint sentinel!"
        record_test "Raw List API Privacy (custom file)" "FAIL"
    elif echo "$list_raw_output" | grep -q '"password_hint"'; then
        error "Security failure: Raw list API still exposes password_hint field!"
        record_test "Raw List API Privacy (custom file)" "FAIL"
    elif echo "$list_raw_output" | jq -e --arg fid "$CUSTOM_FILE_ID" '
        .files[]
        | select(.file_id == $fid)
        | (.encrypted_password_hint | type == "string" and length > 0)
          and (.password_hint_nonce | type == "string" and length > 0)
          and (.encrypted_filename != null and .encrypted_filename != "")
      ' >/dev/null 2>&1; then
        record_test "Raw List API Privacy (custom file)" "PASS"
    else
        error "Security failure: Raw list API missing encrypted metadata/hint fields for custom-password file!"
        echo "$list_raw_output" | head -c 2000
        record_test "Raw List API Privacy (custom file)" "FAIL"
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

    scenario "Agent digest privacy and session enforcement"
    local agent_default_out agent_default_code
    safe_exec agent_default_out agent_default_code "$CLIENT" agent status
    if [ $agent_default_code -eq 0 ] \
        && ! echo "$agent_default_out" | grep -Fq "$UPLOADED_FILE_ID" \
        && ! echo "$agent_default_out" | grep -Fq "$UPLOADED_FILE_SHA256"; then
        record_test "Agent status hides file IDs and digests by default" "PASS"
    else
        error "Default agent status exposed a file ID or plaintext digest"
        record_test "Agent status hides file IDs and digests by default" "FAIL"
    fi

    local agent_digests_out agent_digests_code
    safe_exec agent_digests_out agent_digests_code "$CLIENT" agent status --show-digests
    if [ $agent_digests_code -eq 0 ] \
        && echo "$agent_digests_out" | grep -Fq "$UPLOADED_FILE_ID" \
        && echo "$agent_digests_out" | grep -Fq "$UPLOADED_FILE_SHA256"; then
        record_test "Agent diagnostic status shows bound digest cache" "PASS"
    else
        error "Diagnostic agent status did not show the expected bound digest entry"
        record_test "Agent diagnostic status shows bound digest cache" "FAIL"
    fi

    local client_session_file="$HOME/.arkfile-session.json"
    local session_backup="$TEST_DATA_DIR/client-session-backup.json"
    local expired_session="$TEST_DATA_DIR/client-session-expired.json"
    if [ ! -f "$client_session_file" ]; then
        error "Client session file missing before expiry enforcement tests"
        record_test "Client session expiry prerequisites" "FAIL"
    fi
    cp "$client_session_file" "$session_backup"
    if ! jq '.expires_at = "2000-01-01T00:00:00Z"' "$client_session_file" > "$expired_session"; then
        rm -f "$session_backup" "$expired_session"
        error "Could not construct an expired client session"
        record_test "Client session expiry prerequisites" "FAIL"
    fi
    mv "$expired_session" "$client_session_file"
    chmod 600 "$client_session_file"

    local expired_digest_out expired_digest_code
    safe_exec expired_digest_out expired_digest_code "$CLIENT" agent status --show-digests
    local expired_list_out expired_list_code
    safe_exec expired_list_out expired_list_code \
        "$CLIENT" --server-url "$SERVER_URL" --tls-insecure list-files

    mv "$session_backup" "$client_session_file"
    chmod 600 "$client_session_file"

    if [ $expired_digest_code -ne 0 ] && echo "$expired_digest_out" | grep -qi "session expired"; then
        record_test "Agent digest diagnostics reject expired session" "PASS"
    else
        error "Agent digest diagnostics did not reject an expired session"
        record_test "Agent digest diagnostics reject expired session" "FAIL"
    fi
    if [ $expired_list_code -ne 0 ] && echo "$expired_list_out" | grep -qi "session expired"; then
        record_test "Authenticated client command rejects expired session" "PASS"
    else
        error "list-files did not reject an expired client session"
        record_test "Authenticated client command rejects expired session" "FAIL"
    fi

    scenario "Verifying list-files --raw API privacy"
    local list_raw_output list_raw_exit_code
    safe_exec list_raw_output list_raw_exit_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure list-files --raw
        
    if echo "$list_raw_output" | jq -e '.files[] | select(.encrypted_filename != null and .encrypted_filename != "")' >/dev/null 2>&1 \
        && ! echo "$list_raw_output" | jq -e '.files[] | select(.filename != null)' >/dev/null 2>&1 \
        && ! echo "$list_raw_output" | grep -q "$UPLOADED_FILE_SHA256" \
        && ! echo "$list_raw_output" | grep -q "test_file.bin"; then
        record_test "Raw List API Privacy" "PASS"
    else
        error "Security failure: Raw API list exposed plaintext filename or hashes!"
        record_test "Raw List API Privacy" "FAIL"
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
    # Exercises sequential multi-file upload. File sizes span the plaintext
    # chunk-size boundary to cover both full-chunk and partial-last-chunk paths.
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
        error "Missing uploaded file ID from files_standard group"
        record_test "Prior upload file ID available for shares" "FAIL"
    fi
    record_test "Prior upload file ID available for shares" "PASS"
    info "Using uploaded file for shares: File ID=$UPLOADED_FILE_ID"
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
    # Share C expiry: run immediately after create — expires_at is 1m from creation.
    scenario "Visitor share expiry enforcement"

    local dl_c1_file="$TEST_DATA_DIR/share_c_dl1.bin"
    share_download_with_password "$SHARE_C_PASSWORD" "$SHARE_C_ID" "$dl_c1_file" "Share C download before expiry" "false"
    rm -f "$dl_c1_file"

    local now_ts
    now_ts=$(date +%s)
    local expiry_ts=$((SHARE_C_CREATED_AT + 60 + 5))
    local wait_seconds=$((expiry_ts - now_ts))
    if [ $wait_seconds -lt 0 ]; then
        wait_seconds=0
    fi
    info "Smart sleep: waiting ${wait_seconds}s for Share C to expire..."
    sleep "$wait_seconds"

    local dl_c2_file="$TEST_DATA_DIR/share_c_dl2.bin"
    share_download_with_password "$SHARE_C_PASSWORD" "$SHARE_C_ID" "$dl_c2_file" "Share C download after expiry rejected" "true"
    assert_output_file_absent_or_empty "$dl_c2_file" "Share C rejected file hygiene"
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
        
    if echo "$list_shares_raw_output" | grep -q "test_file.bin" || echo "$list_shares_raw_output" | grep -q "custom_test_file.bin"; then
        error "Security failure: Raw shares API list exposed plaintext filename!"
        record_test "Raw Shares API Privacy" "FAIL"
    elif echo "$list_shares_raw_output" | jq -e '.shares[] | select(.share_id != null and .file_id != null)' >/dev/null 2>&1; then
        record_test "Raw Shares API Privacy" "PASS"
    else
        error "Security failure: Raw shares API missing expected share metadata!"
        record_test "Raw Shares API Privacy" "FAIL"
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

    scenario "Share download ticket endpoint validation"
    # The ticket issuance endpoint (/api/public/shares/:id/ticket) replaces the
    # never-rotated static download token as the per-chunk credential. These
    # anonymous curl checks (no login) confirm the endpoint exists, requires a
    # download_token, and rejects a garbage token with 403 rather than leaking
    # state via 404/500.
    #
    # ORDERING NOTE: this scenario MUST run before the "Share enumeration rate
    # limiting" sub-test below (and before invalid-token probes, which now run
    # immediately after non-existent share download). ShareEnumerationMiddleware
    # keys on the loopback test entity and blocks the entire /api/public/shares/*
    # namespace once ~4 unique 404s accumulate in a 10-minute window. Running
    # handler probes after the enumeration flood would receive 429 from the
    # guard instead of the real 400/403/404 from the handler, masking the
    # behavior under test. Here the entity is clean (only successful downloads
    # so far), so the handler responses are genuine. We also keep to a single
    # unknown-share probe so we add only one unique 404 to the entity's counter
    # before the invalid-token and enumeration sub-tests begin.
    if [ -n "$SHARE_A_ID" ]; then
        local ticket_ep="${SERVER_URL}/api/public/shares/${SHARE_A_ID}/ticket"

        # Empty token -> 400 Bad Request.
        local empty_code
        empty_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            -X POST -H 'Content-Type: application/json' \
            -d '{"download_token":""}' "$ticket_ep" 2>/dev/null)
        if [ "$empty_code" = "400" ]; then
            record_test "Ticket endpoint rejects empty token (HTTP 400)" "PASS"
            info "Ticket endpoint empty-token -> 400 (expected)"
        else
            record_test "Ticket endpoint rejects empty token (HTTP $empty_code)" "FAIL"
            warning "Expected 400 for empty token, got $empty_code"
        fi

        # Garbage token -> 403 Forbidden (NOT 404/500, which would leak state).
        # A bad token does NOT record a share-enumeration 404 hit, so this probe
        # does not advance the enumeration counter.
        local bad_code
        bad_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            -X POST -H 'Content-Type: application/json' \
            -d '{"download_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' \
            "$ticket_ep" 2>/dev/null)
        if [ "$bad_code" = "403" ]; then
            record_test "Ticket endpoint rejects bad token (HTTP 403)" "PASS"
            info "Ticket endpoint garbage-token -> 403 (expected, no state leak)"
        else
            record_test "Ticket endpoint rejects bad token (HTTP $bad_code)" "FAIL"
            warning "Expected 403 for bad token, got $bad_code"
        fi

        # Non-existent share ID -> 404 NotFound (and must NOT be a 500). This is
        # the single unique 404 this scenario contributes to the entity counter.
        local fake_id
        fake_id="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | head -c 43)"
        local nf_code
        nf_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            -X POST -H 'Content-Type: application/json' \
            -d '{"download_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' \
            "${SERVER_URL}/api/public/shares/${fake_id}/ticket" 2>/dev/null)
        if [ "$nf_code" = "404" ]; then
            record_test "Ticket endpoint unknown share -> 404" "PASS"
            info "Ticket endpoint unknown share -> 404 (expected)"
        else
            record_test "Ticket endpoint unknown share -> HTTP $nf_code" "FAIL"
            warning "Expected 404 for unknown share, got $nf_code"
        fi
    else
        error "Share A ID not available for ticket endpoint validation"
        record_test "Share download ticket endpoint validation" "FAIL"
    fi
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
    scenario "Non-existent share download fails"

    sleep 2  # Rate limit buffer

    share_download_with_password "$DUMMY_SHARE_PASSWORD" "$NONEXISTENT_SHARE_ID" "$TEST_DATA_DIR/nonexistent.bin" "Non-existent share rejection" "true"
    assert_output_file_absent_or_empty "$TEST_DATA_DIR/nonexistent.bin" "Non-existent share file hygiene"
    # ORDERING NOTE: invalid-download-token rate limiting MUST run before
    # "Share enumeration rate limiting" below. ShareEnumerationMiddleware blocks
    # the entire /api/public/shares/* namespace once ~4 unique 404s accumulate;
    # running these probes after that flood would get 429 from the enumeration
    # guard instead of 403/429 from the per-share token limiter.
    #
    # Contract: the static download_token is accepted only at ticket issuance
    # (POST .../ticket). Chunk downloads require X-Share-Ticket; a missing
    # ticket is 403 without recording a per-share failure. Probe bad tokens on
    # the ticket endpoint of a non-exhausted share whose failure counter was
    # not already advanced (Share D). Share A already recorded one bad-token
    # failure in ticket-endpoint validation; Share B is exhausted.
    scenario "Invalid download token rate limiting (ticket issuance)"

    if [ -n "$SHARE_D_ID" ]; then
        local BAD_TOKEN
        BAD_TOKEN=$(echo "deliberately-wrong-token-value" | base64)
        local ticket_rl_ep="${SERVER_URL}/api/public/shares/${SHARE_D_ID}/ticket"

        # Missing ticket on chunks: fail closed with 403, no rate-limit counter.
        local missing_ticket_code
        missing_ticket_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            "${SERVER_URL}/api/public/shares/${SHARE_D_ID}/chunks/0" 2>/dev/null)
        if [ "$missing_ticket_code" = "403" ]; then
            record_test "Chunk download without X-Share-Ticket returns 403" "PASS"
            info "Missing share ticket on chunk -> 403 (expected; does not arm per-share limiter)"
        else
            record_test "Chunk download without X-Share-Ticket returns 403" "FAIL"
            warning "Expected 403 for missing ticket, got $missing_ticket_code"
        fi

        local token_fail=0
        for i in 1 2 3 4; do
            local token_code
            token_code=$(curl -sk -o /dev/null -w '%{http_code}' \
                -X POST -H 'Content-Type: application/json' \
                -d "{\"download_token\":\"${BAD_TOKEN}\"}" \
                "$ticket_rl_ep" 2>/dev/null)
            if [ "$token_code" = "403" ]; then
                info "Invalid ticket-token attempt $i/4: HTTP $token_code"
            else
                warning "Invalid ticket-token attempt $i/4: expected HTTP 403, got $token_code"
                token_fail=1
            fi
        done

        if [ "$token_fail" -eq 0 ]; then
            record_test "Invalid download token attempts 1-4 return 403" "PASS"
        else
            record_test "Invalid download token attempts 1-4 return 403" "FAIL"
        fi

        # 4th failure arms a 30s penalty; 5th request should be rate limited (429).
        sleep 1
        local token_code_5
        token_code_5=$(curl -sk -o /dev/null -w '%{http_code}' \
            -X POST -H 'Content-Type: application/json' \
            -d "{\"download_token\":\"${BAD_TOKEN}\"}" \
            "$ticket_rl_ep" 2>/dev/null)
        if [ "$token_code_5" = "429" ]; then
            record_test "Invalid download token rate limiting (HTTP 429 after failures)" "PASS"
            info "Per-share rate limiter returned 429 after repeated invalid ticket tokens"
        else
            record_test "Invalid download token rate limiting (HTTP 429 after failures)" "FAIL"
            error "Per-share rate limiter returned HTTP $token_code_5 (expected 429)"
        fi
    else
        error "Share D ID not available for invalid download token test"
        record_test "Invalid download token rate limiting" "FAIL"
    fi
    # Hit unique fake share IDs via curl to trigger the enumeration threshold.
    # The enumeration guard tracks unique 404s per entity in a 10-minute window
    # and blocks (429) after ~4 unique 404s. Earlier sub-tests (Non-existent
    # share download, ticket endpoint unknown-share probe, and the timing-floor
    # probe below) may already have added a few unique 404s to the entity's
    # counter, so we do NOT assume a pristine counter. Instead we probe fresh
    # unique IDs until the guard returns 429 (or we hit a safety cap), which
    # proves the enumeration guard is active regardless of starting state.
    scenario "Share enumeration rate limiting"

    # Timing-protection regression: a 404 on the public share envelope endpoint
    # MUST be padded to the 1-second minimum so a fast 404 does not leak share-ID
    # existence at line rate. Use a fresh fake ID so this measurement is not
    # served from cache. Anonymous curl, no login cycle. (This probe also adds
    # one unique 404 to the entity's enumeration counter, which the loop below
    # tolerates.)
    scenario "Share envelope timing protection floor"
    local timing_id
    timing_id="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | head -c 43)"
    local timing_start timing_end timing_elapsed
    timing_start=$(date +%s%N)
    local timing_code
    timing_code=$(curl -sk -o /dev/null -w '%{http_code}' \
        "${SERVER_URL}/api/public/shares/${timing_id}/envelope" 2>/dev/null)
    timing_end=$(date +%s%N)
    timing_elapsed_ms=$(( (timing_end - timing_start) / 1000000 ))
    if [ "$timing_code" = "404" ] && [ "$timing_elapsed_ms" -ge 1000 ]; then
        record_test "Share envelope 404 padded to >=1s (elapsed ${timing_elapsed_ms}ms)" "PASS"
        info "Envelope 404 padded: ${timing_elapsed_ms}ms (HTTP $timing_code)"
    else
        record_test "Share envelope 404 padded to >=1s (elapsed ${timing_elapsed_ms}ms, code $timing_code)" "FAIL"
        warning "Expected padded 404 >=1000ms, got ${timing_elapsed_ms}ms (HTTP $timing_code)"
    fi

    # Probe fresh unique share IDs until the enumeration guard blocks (429) or
    # we exceed a safety cap. The guard blocks after ~4 unique 404s in a
    # 10-minute window; with a handful of prior 404s already counted, this
    # typically triggers within the first few probes.
    local enum_blocked=0
    local enum_probes=0
    local enum_max_probes=12
    while [ "$enum_probes" -lt "$enum_max_probes" ]; do
        enum_probes=$((enum_probes + 1))
        local enum_id enum_code
        enum_id="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | head -c 43)"
        enum_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            "${SERVER_URL}/api/public/shares/${enum_id}/envelope" 2>/dev/null)
        if [ "$enum_code" = "429" ]; then
            enum_blocked=1
            info "Enumeration guard returned 429 on probe ${enum_probes} (unique-404 threshold reached)"
            break
        elif [ "$enum_code" = "404" ]; then
            info "Enumeration probe ${enum_probes}: 404 (counting toward threshold)"
        else
            warning "Enumeration probe ${enum_probes}: unexpected HTTP $enum_code"
        fi
    done

    if [ "$enum_blocked" = "1" ]; then
        record_test "Share enumeration threshold (429 after unique 404s)" "PASS"
        record_test "Share enumeration rate limiting (HTTP 429 after threshold)" "PASS"
        info "Enumeration guard returned 429 after ${enum_probes} unique-404 probes"
    else
        record_test "Share enumeration threshold (429 after unique 404s)" "FAIL"
        record_test "Share enumeration rate limiting (HTTP 429 after threshold)" "FAIL"
        error "Enumeration guard did not return 429 after ${enum_max_probes} unique-404 probes"
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
        error "Session file still exists after revoke-all (expected removal)"
        record_test "Session file cleared after revoke-all" "FAIL"
    fi

    # Re-login so the CLI session is fresh for the post-logout rejection checks.
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

    scenario "Admin health-check (no placeholder disk metrics)"
    local health_out health_code
    safe_exec health_out health_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure health-check --detailed
    if [ $health_code -eq 0 ] \
        && ! echo "$health_out" | grep -qi "disk" \
        && echo "$health_out" | grep -qi "healthy"; then
        record_test "Admin health-check --detailed (no disk placeholders)" "PASS"
    else
        error "health-check --detailed failed or contained disk section"
        echo "$health_out"
        record_test "Admin health-check --detailed (no disk placeholders)" "FAIL"
    fi

    scenario "Admin contacts API contract"
    local contacts_body contacts_code
    contacts_body=$(curl -sk -w '\n%{http_code}' "${SERVER_URL}/api/admin-contacts" 2>/dev/null || echo -e '\n000')
    contacts_code=$(echo "$contacts_body" | tail -n1)
    contacts_body=$(echo "$contacts_body" | sed '$d')
    if [ "$contacts_code" = "200" ] \
        && echo "$contacts_body" | jq -e '.configured == true' >/dev/null 2>&1 \
        && ! echo "$contacts_body" | grep -q "admin@example.com" \
        && ! echo "$contacts_body" | grep -q "default-admin"; then
        record_test "Admin contacts API (configured, no fake defaults)" "PASS"
    else
        error "Admin contacts API contract failed"
        echo "$contacts_body"
        record_test "Admin contacts API (configured, no fake defaults)" "FAIL"
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
    scenario "Establish active user JWT before admin MFA reset"
    user_login_with_totp "User login before admin MFA reset"
    local pre_reset_access_token
    if ! pre_reset_access_token=$(jq -r '.access_token // empty' "$HOME/.arkfile-session.json" 2>/dev/null); then
        pre_reset_access_token=""
    fi
    if [ -z "$pre_reset_access_token" ]; then
        error "Could not extract an access token before admin MFA reset"
        record_test "MFA reset JWT revocation prerequisite" "FAIL"
    fi

    local pre_reset_http pre_reset_code
    safe_exec pre_reset_http pre_reset_code \
        curl -skS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${pre_reset_access_token}" \
        "${SERVER_URL}/api/files"
    if [ $pre_reset_code -eq 0 ] && [ "$pre_reset_http" = "200" ]; then
        record_test "JWT valid immediately before admin MFA reset" "PASS"
    else
        error "Expected HTTP 200 before admin MFA reset, got HTTP $pre_reset_http"
        record_test "JWT valid immediately before admin MFA reset" "FAIL"
    fi

    scenario "Admin reset-user-mfa"
    local reset_mfa_output reset_mfa_code
    safe_exec reset_mfa_output reset_mfa_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        reset-user-mfa --username "$TEST_USERNAME" --confirm
    if [ $reset_mfa_code -eq 0 ] && echo "$reset_mfa_output" | grep -q "MFA reset completed"; then
        record_test "Admin reset-user-mfa" "PASS"
        info "Admin reset MFA for test user"
        touch "$MFA_ADMIN_RESET_DONE_FILE"
    else
        error "reset-user-mfa command failed:"
        echo "$reset_mfa_output"
        record_test "Admin reset-user-mfa" "FAIL"
    fi
    scenario "Per-request user-wide revocation check"
    local revoke_check_http revoke_check_code
    safe_exec revoke_check_http revoke_check_code \
        curl -skS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${pre_reset_access_token}" \
        "${SERVER_URL}/api/files"
    if [ $revoke_check_code -eq 0 ] && [ "$revoke_check_http" = "401" ]; then
        record_test "MFA reset immediately revokes active JWT" "PASS"
        info "Active JWT rejected immediately after MFA reset"
    else
        error "Expected HTTP 401 immediately after MFA reset, got HTTP $revoke_check_http"
        record_test "MFA reset immediately revokes active JWT" "FAIL"
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
        error "SHARE_D_ID not set for admin revoke-share test"
        record_test "Admin revoke-share" "FAIL"
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
        error "CUSTOM_FILE_ID not set for admin delete-file test"
        record_test "Admin delete-file" "FAIL"
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
    # Isolate this test's entity ID from other curl probes. The entity ID is
    # HMAC(key, "anon:" + IP + "|" + uaBucket + "|" + langBucket). On loopback
    # the IP is fixed, and the custom UA above collapses into the "other" UA
    # bucket (shared with curl's own UA), so the only remaining axis we control
    # is the Accept-Language bucket. A distinct primary language ("xx") yields a
    # distinct langBucket, giving this test a fresh flood-guard counter that
    # other UA-less curl probes in the suite do not pollute. See
    # logging/entity_id.go acceptLanguageBucket.
    local FLOOD_LANG="xx"
    scenario "Unauthenticated probes under threshold"
    local all_under_threshold=true
    for i in $(seq 1 9); do
        local probe_code
        probe_code=$(curl -sk -o /dev/null -w '%{http_code}' \
            -H "User-Agent: $FLOOD_UA" \
            -H "Accept-Language: $FLOOD_LANG" \
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
        -H "Accept-Language: $FLOOD_LANG" \
        "${SERVER_URL}/wp-scan-10.php" 2>/dev/null)
    info "Probe 10: HTTP $probe_10_code"
    # The 10th request itself may or may not get 429 (depends on whether the middleware
    # counts the response and blocks in the same request or the next). Record it.
    scenario "Eleventh probe gets 429 when blocked"
    local probe_11_code probe_11_headers
    probe_11_headers=$(curl -sk -D - -o /dev/null \
        -H "User-Agent: $FLOOD_UA" \
        -H "Accept-Language: $FLOOD_LANG" \
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
        error "Flood guard security event not found in admin security-events (suspicious_pattern)"
        echo "$sec_flood_output"
        record_test "Flood guard: security event recorded (unauthorized_flood)" "FAIL"
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

    # Verify secondary has 0 files initially (JSON avoids brittle human-output parsing).
    local ss_json ss_json_code secondary_objects
    safe_exec ss_json ss_json_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure storage-status --json
    secondary_objects=$(echo "$ss_json" | jq -r \
        '.providers[]? | select(.provider_id == "seaweedfs-secondary") | .total_objects // empty' \
        2>/dev/null)
    if [ $ss_json_code -eq 0 ] && [ "$secondary_objects" = "0" ]; then
        record_test "Multi-backend: secondary starts with 0 files" "PASS"
    else
        error "Secondary seaweedfs-secondary total_objects is not 0 (run dev-reset before e2e):"
        if [ $ss_json_code -eq 0 ]; then
            echo "$ss_json" | jq '.providers[]? | select(.provider_id == "seaweedfs-secondary")' 2>/dev/null \
                || echo "$ss_json"
        else
            echo "$ss_json"
        fi
        record_test "Multi-backend: secondary starts with 0 files" "FAIL"
    fi
    scenario "Copy single file to secondary storage"
    if [ -z "$EXTRA_FILE_C_ID" ]; then
        error "EXTRA_FILE_C_ID not set (extra 1MB upload in files_standard did not complete)"
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
                    error "copy-all did not report Skipped: 1:"
                    echo "$ca_poll_output"
                    record_test "Multi-backend: copy-all skipped existing" "FAIL"
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
        billing set-price --json 19.99

    local setprice_rate
    setprice_rate=$(echo "$setprice_out" | jq -r '.microcents_per_gib_per_hour // empty' 2>/dev/null)
    if [ $setprice_code -eq 0 ] && [ "$setprice_rate" = "2711" ]; then
        record_test "set-price --json 19.99 updates to 2711 microcents/GiB/hour" "PASS"
        info "set-price output:"
        echo "$setprice_out"
    else
        error "set-price --json 19.99 failed or did not return microcents_per_gib_per_hour=2711"
        echo "$setprice_out"
        record_test "set-price --json 19.99 updates to 2711 microcents/GiB/hour" "FAIL"
    fi

    local setprice_trailing_out setprice_trailing_code setprice_trailing_rate
    safe_exec setprice_trailing_out setprice_trailing_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing set-price 19.99 --json

    setprice_trailing_rate=$(echo "$setprice_trailing_out" | jq -r '.microcents_per_gib_per_hour // empty' 2>/dev/null)
    if [ $setprice_trailing_code -eq 0 ] && [ "$setprice_trailing_rate" = "2711" ]; then
        record_test "set-price 19.99 --json accepts trailing --json flag" "PASS"
    else
        error "set-price 19.99 --json failed or did not return microcents_per_gib_per_hour=2711"
        echo "$setprice_trailing_out"
        record_test "set-price 19.99 --json accepts trailing --json flag" "FAIL"
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
        billing set-price 9999.99
    if [ $_drain_sp_code -ne 0 ]; then
        error "Failed to set extreme price for balance drain test:"
        echo "$_drain_sp_out"
        record_test "Set extreme price for balance drain" "FAIL"
    fi

    local max_sweeps=20
    local sweep_count=0
    local current_balance
    current_balance="$balance"   # last known balance (positive, from billing gift step)

    while [ "$sweep_count" -lt "$max_sweeps" ]; do
        safe_exec tick_out tick_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            billing tick-now --sweep --json
        if [ $tick_code -ne 0 ]; then
            error "tick-now --sweep failed during balance drain (sweep $((sweep_count + 1))):"
            echo "$tick_out"
            record_test "Balance drain tick-now --sweep" "FAIL"
        fi
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
        billing set-price 10.00
    if [ $_restore_sp_code -ne 0 ]; then
        error "Failed to restore price to 10.00 after balance drain test:"
        echo "$_restore_sp_out"
        record_test "Restore price after balance drain" "FAIL"
    fi

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

    if [ -f "$MFA_ADMIN_RESET_DONE_FILE" ]; then
        user_login_defer_mfa "OPAQUE login after admin MFA reset"
        user_mfa_enroll_after_deferred_login "MFA re-enrollment after admin reset"
        user_login_with_totp "Login after admin MFA reset re-enrollment"
        rm -f "$MFA_ADMIN_RESET_DONE_FILE"
    else
        # Log in as the regular test user to ensure a fresh session and token
        user_login_with_totp "User login for payments test"
    fi

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    scenario "PAYG negative-balance upload cap"

    # Billing (admin-only) leaves the test user slightly negative.  User CLI
    # steps run here — after post-admin-reset MFA re-enrollment — so upload
    # and download probes have a valid session.  Invoice top-up below restores
    # balance afterward.
    local cap_microcents=1000000000   # $10.00 in microcents
    local cap_test_file="$TEST_DATA_DIR/payg_cap_probe.bin"
    head -c 2048 /dev/urandom > "$cap_test_file" 2>/dev/null || \
        printf 'x%.0s' $(seq 1 2048) > "$cap_test_file"

    # --- Step 1: small negative balance does NOT block uploads ---------
    local cap_small_out cap_small_code
    safe_exec cap_small_out cap_small_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$cap_test_file" \
        --password-type account

    if [ $cap_small_code -eq 0 ] \
        && ! echo "$cap_small_out" | grep -qi "payment_required" \
        && ! echo "$cap_small_out" | grep -qi "HTTP 402"; then
        record_test "Small negative balance does not block upload" "PASS"
    else
        error "Upload blocked or failed at small negative balance (within cap):"
        echo "$cap_small_out"
        record_test "Small negative balance does not block upload" "FAIL"
    fi

    # --- Step 2: drive balance below the -$10 cap ----------------------
    # Each tick-now --sweep bills only one simulated hour (~5.5-7M µ¢ at
    # dev storage + 999999.99 price). Batch tick-only calls fill the
    # accumulator, then one sweep settles each round.
    safe_exec _cap_sp_out _cap_sp_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing set-price 999999.99
    if [ $_cap_sp_code -ne 0 ]; then
        error "Failed to set extreme price for PAYG cap drain:"
        echo "$_cap_sp_out"
        record_test "Set extreme price for PAYG cap drain" "FAIL"
    fi

    local cap_drain_round=0
    local cap_max_drain_rounds=5
    local cap_ticks_per_round=150
    local cap_balance
    safe_exec credits_after_out credits_after_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json
    cap_balance=$(echo "$credits_after_out" | \
        jq -r '.balance_usd_microcents // 0' 2>/dev/null || echo "0")
    while [ "$cap_drain_round" -lt "$cap_max_drain_rounds" ]; do
        if [ -n "$cap_balance" ] && [ "$cap_balance" -le "-$cap_microcents" ] 2>/dev/null; then
            break
        fi
        local cap_tick_i
        for cap_tick_i in $(seq 1 "$cap_ticks_per_round"); do
            safe_exec tick_out tick_code \
                $ADMIN --server-url "$SERVER_URL" --tls-insecure \
                billing tick-now --json
            if [ $tick_code -ne 0 ]; then
                error "tick-now failed during PAYG cap drain (round $((cap_drain_round + 1)), tick $cap_tick_i):"
                echo "$tick_out"
                record_test "PAYG cap drain tick-now" "FAIL"
            fi
        done
        safe_exec tick_out tick_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            billing tick-now --sweep --json
        if [ $tick_code -ne 0 ]; then
            error "tick-now --sweep failed during PAYG cap drain (round $((cap_drain_round + 1))):"
            echo "$tick_out"
            record_test "PAYG cap drain tick-now --sweep" "FAIL"
        fi
        cap_drain_round=$((cap_drain_round + 1))
        safe_exec credits_after_out credits_after_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            billing show --user "$TEST_USERNAME" --json
        cap_balance=$(echo "$credits_after_out" | \
            jq -r '.balance_usd_microcents // 0' 2>/dev/null || echo "0")
    done
    info "Balance after cap drain: $cap_balance microcents (target <= -$cap_microcents)"

    if [ -n "$cap_balance" ] && [ "$cap_balance" -le "-$cap_microcents" ] 2>/dev/null; then
        record_test "Balance driven to/below negative cap (-\$10)" "PASS"
    else
        error "Balance did not reach negative cap after $cap_drain_round drain round(s): $cap_balance"
        record_test "Balance driven to/below negative cap (-\$10)" "FAIL"
    fi

    # --- Step 2b: upload now blocked at/under the cap ------------------
    head -c 2048 /dev/urandom > "$cap_test_file" 2>/dev/null || \
        printf 'y%.0s' $(seq 1 2048) > "$cap_test_file"
    local cap_block_out cap_block_code
    safe_exec cap_block_out cap_block_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        upload \
        --file "$cap_test_file" \
        --password-type account

    if [ $cap_block_code -ne 0 ] \
        && echo "$cap_block_out" | grep -qi "payment_required" \
        && echo "$cap_block_out" | grep -qi "HTTP 402"; then
        record_test "Upload blocked at negative cap (402 payment_required)" "PASS"
        info "Blocked upload output:"
        echo "$cap_block_out"
    else
        error "Upload was NOT blocked at negative cap (expected non-zero exit and 402 payment_required):"
        echo "$cap_block_out"
        record_test "Upload blocked at negative cap (402 payment_required)" "FAIL"
    fi

    # --- Step 3: download still works while at the cap -----------------
    local cap_dl_file="$TEST_DATA_DIR/payg_cap_download.bin"
    local cap_dl_out cap_dl_code
    safe_exec cap_dl_out cap_dl_code \
        $CLIENT \
        --server-url "$SERVER_URL" \
        --tls-insecure \
        download \
        --file-id "$UPLOADED_FILE_ID" \
        --output "$cap_dl_file"

    if [ $cap_dl_code -eq 0 ]; then
        record_test "Download still works while at negative cap" "PASS"
    else
        error "Download failed while at negative cap:"
        echo "$cap_dl_out"
        record_test "Download still works while at negative cap" "FAIL"
    fi

    rm -f "$cap_test_file" "$cap_dl_file"

    safe_exec _cap_restore_sp_out _cap_restore_sp_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing set-price 10.00
    if [ $_cap_restore_sp_code -ne 0 ]; then
        error "Failed to restore price to 10.00 after PAYG cap test:"
        echo "$_cap_restore_sp_out"
        record_test "Restore price after PAYG cap test" "FAIL"
    fi

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
    local provider_invoice_id="btcpay_mock_${invoice_id}"
    local webhook_payload
    webhook_payload='{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"'"$provider_invoice_id"'","metadata":{"invoice_id":"'"$invoice_id"'"}}'
    
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

start_mock_subscription_bridge() {
    local e2e_script_dir="$1"
    local go_bin="$2"
    local mock_bin="$TEST_DATA_DIR/subscription-bridge-mock"
    local mock_log="$TEST_DATA_DIR/subscription-bridge-mock.log"
    local mock_src="$e2e_script_dir/subscription-bridge-mock.go"
    local mock_pid

    : > "$mock_log"
    export SUBSCRIPTION_BRIDGE_PAIRING_ROOT="${SUBSCRIPTION_BRIDGE_PAIRING_ROOT:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
    export ARKFILE_WEBHOOK_URL="${SERVER_URL}/api/webhooks/subscription-bridge"

    info "Building mock Subscription Bridge..."
    if ! "$go_bin" build -o "$mock_bin" "$mock_src" >>"$mock_log" 2>&1; then
        error "Failed to build mock Subscription Bridge"
        cat "$mock_log"
        return 1
    fi

    info "Starting mock Subscription Bridge on :8081..."
    "$mock_bin" >>"$mock_log" 2>&1 &
    mock_pid=$!

    local i
    for i in $(seq 1 60); do
        if curl -s --connect-timeout 1 http://127.0.0.1:8081/health >/dev/null 2>&1; then
            info "Mock Subscription Bridge is listening on :8081"
            echo "$mock_pid"
            return 0
        fi
        if ! kill -0 "$mock_pid" 2>/dev/null; then
            error "Mock Subscription Bridge exited early"
            cat "$mock_log"
            return 1
        fi
        sleep 1
    done
    error "Mock Subscription Bridge did not become ready"
    cat "$mock_log"
    kill "$mock_pid" 2>/dev/null || true
    return 1
}

stop_mock_subscription_bridge() {
    local mock_pid="$1"
    if [ -n "$mock_pid" ] && kill -0 "$mock_pid" 2>/dev/null; then
        kill "$mock_pid" 2>/dev/null || true
        wait "$mock_pid" 2>/dev/null || true
    fi
}

user_access_token() {
    jq -r '.access_token // empty' "$HOME/.arkfile-session.json" 2>/dev/null
}

ensure_user_session() {
    local tok http_code
    tok=$(user_access_token)
    if [ -z "$tok" ]; then
        user_login_with_totp "User login (subscriptions session missing)"
        return
    fi
    http_code=$(curl -sk -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $tok" "$SERVER_URL/api/credits")
    if [ "$http_code" = "401" ]; then
        user_login_with_totp "User login (subscriptions session expired)"
    fi
}

user_credits_json() {
    curl -sk -H "Authorization: Bearer $(user_access_token)" "$SERVER_URL/api/credits"
}

mock_bridge_activate() {
    local checkout_id="$1"
    local username="$2"
    curl -s -X POST "http://127.0.0.1:8081/v1/mock/activate" \
        -H "Content-Type: application/json" \
        -d "{\"checkout_id\":\"$checkout_id\",\"username\":\"$username\"}"
}

mock_bridge_expire() {
    local subscription_ref="$1"
    curl -s -X POST "http://127.0.0.1:8081/v1/mock/expire" \
        -H "Content-Type: application/json" \
        -d "{\"subscription_ref\":\"$subscription_ref\"}"
}

mock_bridge_replay() {
    local subscription_ref="$1"
    curl -s -X POST "http://127.0.0.1:8081/v1/mock/replay" \
        -H "Content-Type: application/json" \
        -d "{\"subscription_ref\":\"$subscription_ref\"}"
}

run_subscriptions() {
    group "Subscriptions"

    local e2e_script_dir go_bin mock_pid btcpay_mock_pid
    local dev_plan_storage_bytes=268435456000
    local user_token credits_json billing_mode effective_limit sub_source
    local tx_count_before tx_count_after checkout_id checkout_out checkout_http
    local invoice_http invoice_body topup_out topup_code bridge_sub_ref

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

    export ARKFILE_SUBSCRIPTIONS_ENABLED=true
    export ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED=true
    export ARKFILE_BILLING_PAYG_ENABLED=true
    export ARKFILE_SUBSCRIPTION_BRIDGE_URL="http://127.0.0.1:8081"
    export ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    export ADMIN_DEV_TEST_API_ENABLED=true

    mock_pid=$(start_mock_subscription_bridge "$e2e_script_dir" "$go_bin") || {
        record_test "Start mock Subscription Bridge" "FAIL"
        return 0
    }
    record_test "Start mock Subscription Bridge" "PASS"

    scenario "Dev subscription plan exists"
    local plans_out plans_code
    safe_exec plans_out plans_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        subscriptions list-plans --json
    if [ $plans_code -eq 0 ] && echo "$plans_out" | grep -q 'plan_dev_250gb'; then
        record_test "Dev plan plan_dev_250gb present" "PASS"
    else
        record_test "Dev plan plan_dev_250gb present" "FAIL"
    fi

    scenario "Grant gift subscription"
    safe_exec gift_out gift_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        subscriptions grant-gift-subscription --user "$TEST_USERNAME" --plan-id plan_dev_250gb --days 30 --note "e2e gift"
    if [ $gift_code -eq 0 ]; then
        record_test "Grant gift subscription" "PASS"
    else
        error "Gift grant failed: $gift_out"
        record_test "Grant gift subscription" "FAIL"
    fi

    # Reuse the user session left by run_payments when still valid.
    ensure_user_session

    scenario "Credits API subscribed after gift grant"
    credits_json=$(user_credits_json)
    billing_mode=$(echo "$credits_json" | jq -r '.billing_mode // empty' 2>/dev/null)
    sub_source=$(echo "$credits_json" | jq -r '.subscription.source // empty' 2>/dev/null)
    effective_limit=$(echo "$credits_json" | jq -r '.subscription.effective_storage_limit_bytes // 0' 2>/dev/null)
    if [ "$billing_mode" = "subscribed" ] && [ "$sub_source" = "gift" ] \
        && [ "$effective_limit" = "$dev_plan_storage_bytes" ]; then
        record_test "Credits API subscribed after gift grant" "PASS"
    else
        error "Unexpected credits after gift grant: $credits_json"
        record_test "Credits API subscribed after gift grant" "FAIL"
    fi

    scenario "Admin subscriptions show gift subscription"
    local admin_sub_out admin_sub_code
    safe_exec admin_sub_out admin_sub_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        subscriptions show --user "$TEST_USERNAME" --json
    if [ $admin_sub_code -eq 0 ] \
        && echo "$admin_sub_out" | jq -e '.billing_mode == "subscribed" and .subscription.source == "gift"' >/dev/null 2>&1 \
        && echo "$admin_sub_out" | jq -e ".effective_storage_limit_bytes == $dev_plan_storage_bytes" >/dev/null 2>&1; then
        record_test "Admin subscriptions show gift subscription" "PASS"
    else
        error "Admin subscriptions show unexpected: $admin_sub_out"
        record_test "Admin subscriptions show gift subscription" "FAIL"
    fi

    scenario "CLI billing show while subscribed"
    local billing_show_out billing_show_code
    safe_exec billing_show_out billing_show_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        billing show
    if [ $billing_show_code -eq 0 ] && echo "$billing_show_out" | grep -qi "subscribed"; then
        record_test "CLI billing show while subscribed" "PASS"
    else
        record_test "CLI billing show while subscribed" "FAIL"
    fi

    scenario "CLI subscription status while subscribed"
    local sub_status_out sub_status_code
    safe_exec sub_status_out sub_status_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        subscription status
    if [ $sub_status_code -eq 0 ] \
        && echo "$sub_status_out" | grep -qi "250 GB" \
        && echo "$sub_status_out" | grep -qi "active"; then
        record_test "CLI subscription status while subscribed" "PASS"
    else
        record_test "CLI subscription status while subscribed" "FAIL"
    fi

    scenario "CLI subscription plans while subscribed"
    local sub_plans_out sub_plans_code
    safe_exec sub_plans_out sub_plans_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        subscription plans
    if [ $sub_plans_code -eq 0 ] && echo "$sub_plans_out" | grep -q 'plan_dev_250gb'; then
        record_test "CLI subscription plans while subscribed" "PASS"
    else
        record_test "CLI subscription plans while subscribed" "FAIL"
    fi

    scenario "Invoice API rejects top-up while gift subscribed"
    user_token=$(user_access_token)
    invoice_body=$(curl -sk -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"amount_usd":"1.00"}' \
        "$SERVER_URL/api/billing/invoice")
    invoice_http=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"amount_usd":"1.00"}' \
        "$SERVER_URL/api/billing/invoice")
    if [ "$invoice_http" = "409" ] && echo "$invoice_body" | grep -qi "subscription"; then
        record_test "Invoice API 409 while gift subscribed" "PASS"
    else
        error "Expected invoice 409 while gift subscribed (http=$invoice_http): $invoice_body"
        record_test "Invoice API 409 while gift subscribed" "FAIL"
    fi

    scenario "CLI top-up rejected while gift subscribed"
    safe_exec topup_out topup_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        billing top-up --amount 1.00
    if [ $topup_code -ne 0 ] && echo "$topup_out" | grep -qi "subscription"; then
        record_test "Top-up rejected while gift subscribed" "PASS"
    else
        record_test "Top-up rejected while gift subscribed" "FAIL"
    fi

    scenario "Billing tick does not add usage while gift subscribed"
    local tx_before_out tx_before_code tick_sub_out tick_sub_code tx_after_out tx_after_code
    safe_exec tx_before_out tx_before_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json
    tx_count_before=$(echo "$tx_before_out" | jq -r '.pagination.count // 0' 2>/dev/null)
    safe_exec tick_sub_out tick_sub_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing tick-now --json
    safe_exec tx_after_out tx_after_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        billing show --user "$TEST_USERNAME" --json
    tx_count_after=$(echo "$tx_after_out" | jq -r '.pagination.count // 0' 2>/dev/null)
    if [ $tx_before_code -eq 0 ] && [ $tx_after_code -eq 0 ] && [ $tick_sub_code -eq 0 ] \
        && [ "$tx_count_before" = "$tx_count_after" ]; then
        record_test "tick-now skips usage while gift subscribed" "PASS"
    else
        if [ $tx_before_code -ne 0 ]; then
            error "billing show before gift tick failed:"
            echo "$tx_before_out"
        fi
        if [ $tick_sub_code -ne 0 ]; then
            error "tick-now failed while gift subscribed:"
            echo "$tick_sub_out"
        fi
        if [ $tx_after_code -ne 0 ]; then
            error "billing show after gift tick failed:"
            echo "$tx_after_out"
        fi
        error "Usage tx count changed while subscribed: before=$tx_count_before after=$tx_count_after"
        record_test "tick-now skips usage while gift subscribed" "FAIL"
    fi

    scenario "Cancel gift subscription"
    safe_exec cancel_out cancel_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        subscriptions cancel-gift-subscription --user "$TEST_USERNAME" --immediate
    if [ $cancel_code -eq 0 ]; then
        record_test "Cancel gift subscription" "PASS"
    else
        record_test "Cancel gift subscription" "FAIL"
    fi

    scenario "Credits API not subscribed after gift cancel"
    credits_json=$(user_credits_json)
    billing_mode=$(echo "$credits_json" | jq -r '.billing_mode // empty' 2>/dev/null)
    if [ "$billing_mode" != "subscribed" ]; then
        record_test "Credits API not subscribed after gift cancel" "PASS"
    else
        error "Still subscribed after gift cancel: $credits_json"
        record_test "Credits API not subscribed after gift cancel" "FAIL"
    fi

    scenario "Start mock BTCPay for post-cancel top-up checks"
    btcpay_mock_pid=$(start_mock_btcpay_server "$e2e_script_dir" "$go_bin") || {
        record_test "Start mock BTCPay for subscription top-up checks" "FAIL"
        btcpay_mock_pid=""
    }
    if [ -n "$btcpay_mock_pid" ]; then
        record_test "Start mock BTCPay for subscription top-up checks" "PASS"
    fi

    scenario "Invoice API allowed after gift cancel"
    user_token=$(user_access_token)
    local post_cancel_invoice_raw post_cancel_invoice_out post_cancel_invoice_http post_cancel_invoice_id
    post_cancel_invoice_raw=$(curl -sk -w '\n%{http_code}' -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"amount_usd":"1.00"}' \
        "$SERVER_URL/api/billing/invoice")
    post_cancel_invoice_http=$(echo "$post_cancel_invoice_raw" | tail -n1)
    post_cancel_invoice_out=$(echo "$post_cancel_invoice_raw" | sed '$d')
    post_cancel_invoice_id=$(echo "$post_cancel_invoice_out" | jq -r '.data.invoice_id // empty' 2>/dev/null)
    if [ "$post_cancel_invoice_http" = "200" ] && [ -n "$post_cancel_invoice_id" ]; then
        record_test "Invoice API allowed after gift cancel" "PASS"
        info "Post-cancel invoice id: $post_cancel_invoice_id"
    else
        error "Expected invoice API HTTP 200 after gift cancel (http=$post_cancel_invoice_http): $post_cancel_invoice_out"
        record_test "Invoice API allowed after gift cancel" "FAIL"
    fi

    scenario "CLI top-up allowed after gift cancel"
    safe_exec topup_out topup_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        billing top-up --amount 1.00
    if [ $topup_code -eq 0 ]; then
        record_test "CLI top-up allowed after gift cancel" "PASS"
    else
        error "CLI top-up failed after gift cancel (expected exit 0): $topup_out"
        record_test "CLI top-up allowed after gift cancel" "FAIL"
    fi

    scenario "Subscription checkout returns checkout id"
    user_token=$(user_access_token)
    checkout_out=$(curl -sk -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"plan_id":"plan_dev_250gb"}' \
        "$SERVER_URL/api/subscriptions/checkout")
    checkout_http=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"plan_id":"plan_dev_250gb"}' \
        "$SERVER_URL/api/subscriptions/checkout")
    checkout_id=$(echo "$checkout_out" | jq -r '.data.checkout_id // empty' 2>/dev/null)
    if [ "$checkout_http" = "200" ] && [ -n "$checkout_id" ]; then
        record_test "Subscription checkout returns checkout id" "PASS"
        info "Bridge checkout id: $checkout_id"
    else
        error "Checkout failed (http=$checkout_http): $checkout_out"
        record_test "Subscription checkout returns checkout id" "FAIL"
        checkout_id=""
    fi

    scenario "Bridge activate webhook subscribes user"
    local activate_out activate_code
    if [ -n "$checkout_id" ]; then
        activate_out=$(mock_bridge_activate "$checkout_id" "$TEST_USERNAME")
        bridge_sub_ref=$(echo "$activate_out" | jq -r '.subscription_ref // empty' 2>/dev/null)
        if [ -n "$bridge_sub_ref" ] && echo "$activate_out" | jq -e '.status == "delivered"' >/dev/null 2>&1; then
            credits_json=$(user_credits_json)
            billing_mode=$(echo "$credits_json" | jq -r '.billing_mode // empty' 2>/dev/null)
            sub_source=$(echo "$credits_json" | jq -r '.subscription.source // empty' 2>/dev/null)
            effective_limit=$(echo "$credits_json" | jq -r '.subscription.effective_storage_limit_bytes // 0' 2>/dev/null)
            if [ "$billing_mode" = "subscribed" ] && [ "$sub_source" = "bridge" ] \
                && [ "$effective_limit" = "$dev_plan_storage_bytes" ]; then
                record_test "Bridge activate webhook subscribes user" "PASS"
            else
                error "Credits after bridge activate: $credits_json"
                record_test "Bridge activate webhook subscribes user" "FAIL"
            fi
        else
            error "Mock bridge activate failed: $activate_out"
            record_test "Bridge activate webhook subscribes user" "FAIL"
        fi
    else
        record_test "Bridge activate webhook subscribes user" "FAIL"
    fi

    scenario "CLI subscription status after bridge activate"
    safe_exec sub_status_out sub_status_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        subscription status
    if [ $sub_status_code -eq 0 ] \
        && echo "$sub_status_out" | grep -qi "250 GB" \
        && echo "$sub_status_out" | grep -qi "active"; then
        record_test "CLI subscription status after bridge activate" "PASS"
    else
        record_test "CLI subscription status after bridge activate" "FAIL"
    fi

    scenario "Grant gift rejected with bridge subscription"
    safe_exec gift_dup_out gift_dup_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        subscriptions grant-gift-subscription --user "$TEST_USERNAME" --plan-id plan_dev_250gb --days 30 --note "e2e duplicate gift"
    if [ $gift_dup_code -ne 0 ] && echo "$gift_dup_out" | grep -Eiq "active|subscription|already"; then
        record_test "Grant gift rejected with bridge subscription" "PASS"
    else
        error "Expected grant gift rejection with bridge sub: $gift_dup_out"
        record_test "Grant gift rejected with bridge subscription" "FAIL"
    fi

    scenario "Cancel gift rejected for bridge subscription"
    safe_exec cancel_bridge_out cancel_bridge_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        subscriptions cancel-gift-subscription --user "$TEST_USERNAME" --immediate
    if [ $cancel_bridge_code -ne 0 ] && echo "$cancel_bridge_out" | grep -Eiq "paid|portal|processor|bridge"; then
        record_test "Cancel gift rejected for bridge subscription" "PASS"
    else
        error "Expected cancel-gift rejection for bridge sub: $cancel_bridge_out"
        record_test "Cancel gift rejected for bridge subscription" "FAIL"
    fi

    scenario "Invoice API rejects top-up while bridge subscribed"
    user_token=$(user_access_token)
    invoice_http=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"amount_usd":"1.00"}' \
        "$SERVER_URL/api/billing/invoice")
    if [ "$invoice_http" = "409" ]; then
        record_test "Invoice API 409 while bridge subscribed" "PASS"
    else
        record_test "Invoice API 409 while bridge subscribed" "FAIL"
    fi

    scenario "CLI top-up rejected while bridge subscribed"
    safe_exec topup_out topup_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        billing top-up --amount 1.00
    if [ $topup_code -ne 0 ] && echo "$topup_out" | grep -qi "subscription"; then
        record_test "Top-up rejected while bridge subscribed" "PASS"
    else
        record_test "Top-up rejected while bridge subscribed" "FAIL"
    fi

    scenario "Duplicate subscription bridge webhook is idempotent"
    local dup_wh1 dup_wh2 admin_sub_before admin_sub_after
    if [ -n "$bridge_sub_ref" ]; then
        safe_exec admin_sub_before admin_sub_before_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            subscriptions show --user "$TEST_USERNAME" --json
        dup_wh1=$(mock_bridge_replay "$bridge_sub_ref")
        dup_wh2=$(mock_bridge_replay "$bridge_sub_ref")
        safe_exec admin_sub_after admin_sub_after_code \
            $ADMIN --server-url "$SERVER_URL" --tls-insecure \
            subscriptions show --user "$TEST_USERNAME" --json
        if [ $admin_sub_before_code -eq 0 ] && [ $admin_sub_after_code -eq 0 ] \
            && echo "$dup_wh1" | jq -e '.success == true' >/dev/null 2>&1 \
            && echo "$dup_wh2" | jq -e '.success == true' >/dev/null 2>&1 \
            && [ "$admin_sub_before" = "$admin_sub_after" ]; then
            record_test "Duplicate subscription bridge webhook idempotent" "PASS"
        else
            error "Duplicate webhook unexpected: wh1=$dup_wh1 wh2=$dup_wh2"
            record_test "Duplicate subscription bridge webhook idempotent" "FAIL"
        fi
    else
        record_test "Duplicate subscription bridge webhook idempotent" "FAIL"
    fi

    scenario "Bridge expire webhook ends subscription"
    local expire_out
    if [ -n "$bridge_sub_ref" ]; then
        expire_out=$(mock_bridge_expire "$bridge_sub_ref")
        credits_json=$(user_credits_json)
        billing_mode=$(echo "$credits_json" | jq -r '.billing_mode // empty' 2>/dev/null)
        if echo "$expire_out" | jq -e '.status == "expired"' >/dev/null 2>&1 && [ "$billing_mode" != "subscribed" ]; then
            record_test "Bridge expire webhook ends subscription" "PASS"
        else
            error "Expire failed or still subscribed: expire=$expire_out credits=$credits_json"
            record_test "Bridge expire webhook ends subscription" "FAIL"
        fi
    else
        record_test "Bridge expire webhook ends subscription" "FAIL"
    fi

    scenario "Invoice API allowed after bridge expire"
    user_token=$(user_access_token)
    invoice_http=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $user_token" \
        -H "Content-Type: application/json" \
        -d '{"amount_usd":"1.00"}' \
        "$SERVER_URL/api/billing/invoice")
    if [ "$invoice_http" != "409" ]; then
        record_test "Invoice API allowed after bridge expire" "PASS"
    else
        record_test "Invoice API allowed after bridge expire" "FAIL"
    fi

    if [ -n "$btcpay_mock_pid" ]; then
        info "Stopping mock BTCPay server..."
        stop_mock_btcpay_server "$btcpay_mock_pid"
    fi
    stop_mock_subscription_bridge "$mock_pid"
    info "Subscriptions complete"
}

run_registration_throttle() {
    group "Registration throttle"

    # Isolated, deterministic test of the positive registration throttle:
    # 7 successful registrations per entityID are free; the 8th is rejected
    # with HTTP 429 + Retry-After.  All registrations in the e2e run originate
    # from the same host, so they share one entityID.
    #
    # We reset registration_attempts before (known state) and after (so the
    # test host is not left in a multi-hour cooldown that would block manual
    # testing).  The reset endpoint is dev/test-only.

    scenario "Reset registration throttle (pre-test)"
    local reset_out reset_code
    safe_exec reset_out reset_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        reset-registration-throttle --json
    if [ $reset_code -eq 0 ]; then
        record_test "reset-registration-throttle (pre)" "PASS"
    else
        error "reset-registration-throttle (pre) failed (is ADMIN_DEV_TEST_API_ENABLED=true on the server?):"
        echo "$reset_out"
        record_test "reset-registration-throttle (pre)" "FAIL"
    fi

    scenario "Register 7 users (free allowance)"
    local throttle_prefix="e2e-throttle-$$"
    local i out code ok_count=0
    for i in $(seq 1 7); do
        safe_exec out code \
            bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$TEST_PASSWORD' | $CLIENT \
                --server-url '$SERVER_URL' \
                --tls-insecure \
                register \
                --username '${throttle_prefix}-${i}'"
        if [ $code -eq 0 ] && echo "$out" | grep -q "Registration successful"; then
            ok_count=$((ok_count + 1))
        else
            error "Registration #$i unexpectedly failed:"
            echo "$out"
        fi
    done

    if [ "$ok_count" -eq 7 ]; then
        record_test "7 free registrations succeed" "PASS"
    else
        error "Only $ok_count/7 free registrations succeeded"
        record_test "7 free registrations succeed" "FAIL"
    fi

    scenario "8th registration is throttled (429 + Retry-After)"
    local eighth_out eighth_code
    safe_exec eighth_out eighth_code \
        bash -c "printf '%s\n%s\n' '$TEST_PASSWORD' '$TEST_PASSWORD' | $CLIENT \
            --server-url '$SERVER_URL' \
            --tls-insecure \
            register \
            --username '${throttle_prefix}-8'"

    if [ $eighth_code -ne 0 ] \
        && echo "$eighth_out" | grep -qi "HTTP 429" \
        && echo "$eighth_out" | grep -qi "rate_limited"; then
        record_test "8th registration blocked with 429 + Retry-After" "PASS"
        info "Throttled response:"
        echo "$eighth_out"
    else
        error "8th registration was not throttled as expected:"
        echo "$eighth_out"
        record_test "8th registration blocked with 429 + Retry-After" "FAIL"
    fi

    scenario "Reset registration throttle (cleanup)"
    safe_exec reset_out reset_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        reset-registration-throttle --json
    if [ $reset_code -eq 0 ]; then
        record_test "reset-registration-throttle (cleanup)" "PASS"
    else
        error "reset-registration-throttle (cleanup) failed:"
        echo "$reset_out"
        record_test "reset-registration-throttle (cleanup)" "FAIL"
    fi

    success "Registration throttle complete"
}

run_enable_auto_approval() {
    group "Enable auto-approval (post-test setup)"

    # Required setup for subsequent Playwright registration and manual testing
    # in the dev-reset environment: set require_approval=false so newly
    # registered users are auto-approved. Failure fails the suite via
    # record_test (same as other groups).
    scenario "Set approval policy: require-approval=false (auto-approve on)"
    local flip_out flip_code
    safe_exec flip_out flip_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        set-approval-policy --require-approval false
    if [ $flip_code -eq 0 ]; then
        record_test "set-approval-policy --require-approval false" "PASS"
        info "$flip_out"
    else
        error "set-approval-policy --require-approval false failed:"
        echo "$flip_out"
        record_test "set-approval-policy --require-approval false" "FAIL"
    fi

    success "Auto-approval enabled for Playwright and manual testing"
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

# OPAQUE re-registration: an operator flags the existing user for a one-time
# OPAQUE credential rotation, then the user re-registers transparently within a
# single login attempt and their existing file remains decryptable. Reuses the
# user and file from the Files phase and adds no extra login/logout cycles
# beyond the one re-registration login (plus one rejected wrong-password login).
run_opaque_reregistration() {
    group "OPAQUE re-registration (admin-initiated credential rotation)"

    if [ -z "${UPLOADED_FILE_ID:-}" ] || [ -z "${UPLOADED_FILE_SHA256:-}" ]; then
        error "Re-registration test requires an uploaded file from the Files phase"
        record_test "OPAQUE re-registration preconditions" "FAIL"
        return 0
    fi
    if [ -z "${TEST_USER_TOTP_SECRET:-}" ]; then
        error "Re-registration test requires the user's TOTP secret"
        record_test "OPAQUE re-registration preconditions" "FAIL"
        return 0
    fi

    # Operator flags the account: deletes only the OPAQUE record, sets
    # requires_reregistration, and force-logs-out the user. Files, shares, MFA
    # enrollment, and settings are all preserved.
    admin_login_with_totp "Admin login (re-registration flag)" >/dev/null

    scenario "Flagging $TEST_USERNAME for OPAQUE re-registration"
    local flag_out flag_code
    safe_exec flag_out flag_code \
        $ADMIN --server-url "$SERVER_URL" --tls-insecure \
        flag-user-reregistration --username "$TEST_USERNAME" --confirm
    if [ $flag_code -eq 0 ]; then
        record_test "Admin flag-user-reregistration" "PASS"
    else
        error "flag-user-reregistration failed:"; echo "$flag_out"
        record_test "Admin flag-user-reregistration" "FAIL"
        return 0
    fi

    # Negative: a WRONG password must be rejected by the client's pre-finalize
    # password-match check (the user owns files), leaving the account flagged
    # and unchanged so the correct password can still re-register afterward.
    scenario "Re-registration rejects an incorrect password (no changes made)"
    local bad_out bad_code
    safe_exec bad_out bad_code bash -c "printf '%s\n' 'WrongPassword2026!DoesNotMatch' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        --username '$TEST_USERNAME' \
        login \
        --totp-secret '$TEST_USER_TOTP_SECRET' \
        --non-interactive"
    if [ $bad_code -ne 0 ] && echo "$bad_out" | grep -qi "does not match"; then
        record_test "Re-registration wrong-password rejected" "PASS"
    else
        error "Wrong-password re-registration was not rejected as expected:"; echo "$bad_out"
        record_test "Re-registration wrong-password rejected" "FAIL"
    fi

    # Positive: the correct password runs the ceremony inline and continues
    # straight into the existing MFA flow within the same login attempt.
    scenario "Re-registering $TEST_USERNAME with the correct password"
    wait_for_totp_window
    local rr_out rr_code
    safe_exec rr_out rr_code bash -c "printf '%s\n' '$TEST_PASSWORD' | $CLIENT \
        --server-url '$SERVER_URL' \
        --tls-insecure \
        --username '$TEST_USERNAME' \
        login \
        --totp-secret '$TEST_USER_TOTP_SECRET' \
        --save-session \
        --cache-key"
    if [ $rr_code -eq 0 ] && echo "$rr_out" | grep -q "Login successful"; then
        record_test "OPAQUE re-registration + login" "PASS"
    else
        error "Re-registration login failed:"; echo "$rr_out"
        record_test "OPAQUE re-registration + login" "FAIL"
        return 0
    fi

    # The existing file must remain decryptable with the same password, proving
    # the Account Key (and therefore all account-wrapped data) is unchanged.
    scenario "Verifying the existing file still decrypts after re-registration"
    local rr_dl="$TEST_DATA_DIR/reregistration-download.bin"
    local dl_out dl_code
    safe_exec dl_out dl_code \
        $CLIENT --server-url "$SERVER_URL" --tls-insecure \
        download --file-id "$UPLOADED_FILE_ID" --output "$rr_dl"
    if [ $dl_code -eq 0 ]; then
        record_test "Post-re-registration file download" "PASS"
    else
        error "Post-re-registration download failed:"; echo "$dl_out"
        record_test "Post-re-registration file download" "FAIL"
    fi
    assert_sha256_matches "$rr_dl" "$UPLOADED_FILE_SHA256" "Post-re-registration content integrity"
    rm -f "$rr_dl"

    success "OPAQUE re-registration flow complete"
}

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
        run_dual_mfa_api_checks
        run_user_authentication
        run_files_standard
        run_opaque_reregistration
        run_files_custom_password
        run_shares
        run_admin_operations
        run_security_rate_limits
        run_storage_replication
        run_billing
        run_payments
        run_subscriptions
        run_registration_throttle
        run_enable_auto_approval
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
