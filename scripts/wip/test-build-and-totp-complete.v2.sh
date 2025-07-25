#!/bin/bash
# Comprehensive TOTP System Validation Tool (v2)
# Handles dependencies, build, service checks, and a full, state-aware auth flow.

# --- Configuration ---
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_FILE="/tmp/totp-test-harness-$(date +%s).log"
JS_DIR="client/static/js"
API_BASE_URL="http://localhost:8080"
DB_PATH="/var/lib/arkfile/database/db.sqlite"

TEST_EMAIL="test@example.com"
TEST_PASSWORD="ThisIsAValidPassword14+"

# --- Utility Functions ---
info() { echo -e "${CYAN}➜ $1${NC}"; }
success() { echo -e "${GREEN}✓ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️ $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; tee -a "$LOG_FILE"; exit 1; }
prompt_confirm() { read -p "$1 [y/N] " -r answer; [[ "$answer" == "y" ]]; }

# --- Phase 0: Pre-flight Checks ---
preflight_checks() {
    info "Running pre-flight dependency checks..."
    if ! command -v bun &>/dev/null; then
        warn "Bun not found."
        if prompt_confirm "Install Bun now?"; then
            curl -fsSL https://bun.sh/install | bash >> "$LOG_FILE" 2>&1
            export PATH="$HOME/.bun/bin:$PATH"
            success "Bun installed."
        else
            fail "Bun is required to proceed."
        fi
    fi
    if ! command -v jq &>/dev/null; then fail "jq is not installed. Please install it (e.g., 'sudo apt-get install jq')."; fi
    if [ ! -f "scripts/totp-generator" ]; then
        warn "TOTP generator not built."
        if (cd scripts/ && go build -o ../totp-generator totp-generator.go); then
            success "Built TOTP generator."
        else
            fail "Failed to build totp-generator."
        fi
    fi
    success "All dependencies are met."
}

# --- Phase 1.5: Service Health Check ---
check_service_health() {
    info "Checking Arkfile service health at $API_BASE_URL/health..."
    local health_response=$(curl -s -o /dev/null -w "%{http_code}" --insecure "$API_BASE_URL/health")
    
    if [[ "$health_response" == "200" ]]; then
        success "Arkfile service is up and running."
    else
        fail "Arkfile service is not responding correctly. HTTP status: $health_response"
    fi
}

# --- Phase 1: Build ---
build_frontend() {
    info "Starting TypeScript build process..."
    (
        cd "$JS_DIR" || fail "Could not find JS directory at $JS_DIR"
        info "Cleaning old artifacts..."
        rm -rf dist/*
        info "Installing dependencies..."
        bun install --frozen-lockfile >> "$LOG_FILE" 2>&1
        info "Building production assets..."
        bun run build:prod >> "$LOG_FILE" 2>&1
    ) || fail "Subshell for build failed."

    if [ -f "$JS_DIR/dist/app.js" ]; then
        success "TypeScript build complete. Output: $JS_DIR/dist/app.js"
    else
        fail "Build process did not create app.js."
    fi
}

# --- Phase 2: User & Service Management ---
handle_test_user() {
    TEMP_TOKEN="" # Global variable to store the token

    if [[ "$1" == "--cleanup" ]]; then
        # ... (cleanup logic remains the same)
        exit 0
    fi

    info "Checking status of test user '$TEST_EMAIL'..."
    local login_response_body=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}" \
        "$API_BASE_URL/api/opaque/login")
    local login_code=$(echo "$login_response_body" | tail -n1)
    
    if [[ "$login_code" == "200" ]]; then
        success "Test user already exists and is fully configured."
        # If user exists, we get a normal session token to proceed
        TEMP_TOKEN=$(echo "$login_response_body" | sed '$d' | jq -r .token)
    elif [[ "$login_code" == "401" ]]; then
        warn "User does not exist or requires TOTP. Attempting registration..."
        local reg_response_body=$(curl -s -w "\n%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}" \
            "$API_BASE_URL/api/opaque/register")
        local reg_code=$(echo "$reg_response_body" | tail -n1)
        local reg_body=$(echo "$reg_response_body" | sed '$d')

        if [[ "$reg_code" == "201" ]]; then
            success "User registered successfully (HTTP $reg_code). TOTP setup required."
            TEMP_TOKEN=$(echo "$reg_body" | jq -r .tempToken)
            if [[ -z "$TEMP_TOKEN" || "$TEMP_TOKEN" == "null" ]]; then
                fail "Registration succeeded but tempToken was not returned."
            fi
        else
            fail "User registration failed with HTTP status $reg_code. Body: $reg_body"
        fi
    else
        fail "Failed to check user status. Arkfile service might be down. (HTTP $login_code)"
    fi
}

# --- Phase 3: End-to-End TOTP Validation ---
validate_totp_flow() {
    info "Initiating end-to-end TOTP validation..."

    if [[ -z "$TEMP_TOKEN" ]]; then
        fail "TEMP_TOKEN not set. Cannot proceed with TOTP flow."
    fi
    local session_token="$TEMP_TOKEN" # Use the provided token

    # 1. Setup TOTP to get the secret
    info "Requesting TOTP setup secret..."
    local setup_json=$(curl -s -X POST \
        -H "Authorization: Bearer $session_token" \
        "$API_BASE_URL/api/totp/setup")
    local totp_secret=$(echo "$setup_json" | jq -r .secret)
    if [[ -z "$totp_secret" || "$totp_secret" == "null" ]]; then fail "Failed to retrieve TOTP secret."; fi
    success "Got TOTP secret."

    # 3. Generate a valid TOTP code
    info "Generating a real-time TOTP code..."
    local totp_code=$(./scripts/totp-generator -secret "$totp_secret")
    if [[ -z "$totp_code" ]]; then fail "Failed to generate TOTP code."; fi
    success "Generated TOTP code: $totp_code"

    # 4. Verify the code to enable TOTP
    info "Verifying TOTP code to enable 2FA..."
    local verify_response_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Authorization: Bearer $session_token" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$totp_code\"}" \
        "$API_BASE_URL/api/totp/verify")
    if [[ "$verify_response_code" != "200" ]]; then fail "Failed to verify TOTP code. HTTP status: $verify_response_code"; fi
    success "TOTP enabled successfully."

    # 5. Final, fully authenticated login
    info "Performing final login with TOTP code..."
    local final_login_response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\", \"totp_code\":\"$totp_code\"}" \
        "$API_BASE_URL/api/opaque/login")
    local final_login_code=$(echo "$final_login_response" | tail -n1)
    local final_login_body=$(echo "$final_login_response" | sed '$d')

    if [[ "$final_login_code" != "200" ]]; then
        fail "Final authenticated login failed with HTTP $final_login_code. Body: $final_login_body"
    fi
    
    local final_token=$(echo "$final_login_body" | jq -r .token)
    if [[ -z "$final_token" || "$final_token" == "null" ]]; then 
        fail "Final login responded with 200 OK, but no token was found."
    fi
    success "End-to-end TOTP authentication successful!"
}


# --- Main Execution ---
main() {
    echo "--- Arkfile TOTP Test Harness v2 ---" > "$LOG_FILE"
    echo "Starting test at $(date)" >> "$LOG_FILE"
    
    if [[ "$1" == "--cleanup" ]]; then
        handle_test_user "--cleanup"
        exit 0
    fi
    
    preflight_checks
    check_service_health # Added health check
    build_frontend
    handle_test_user
    validate_totp_flow

    success "All phases completed successfully!"
}

main "$@"
