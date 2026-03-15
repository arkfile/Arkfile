#!/bin/bash

# e2e-playwright.sh - Playwright Frontend E2E Test Wrapper
#
# Runs after e2e-test.sh has completed successfully.
# Exercises the web frontend via Playwright against the live local server.
#
# Prerequisites:
#   - Server deployed via scripts/dev-reset.sh
#   - scripts/testing/e2e-test.sh has run (test user exists, approved, TOTP configured)
#   - bun available as runtime
#   - TOTP secret at /tmp/arkfile-e2e-test-data/totp-secret

set -eo pipefail

# COLOR OUTPUT

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

success() { echo -e "${GREEN}[OK] $1${NC}"; }
error()   { echo -e "${RED}[X] $1${NC}"; }
warning() { echo -e "${YELLOW}[!] $1${NC}"; }
info()    { echo -e "${CYAN}[i] $1${NC}"; }
section() { echo -e "\n${BLUE}$1${NC}"; }
phase()   { echo -e "\n${CYAN}# $1${NC}\n"; }

# CONFIGURATION

SERVER_URL="${SERVER_URL:-https://localhost:8443}"
TEST_DATA_DIR="/tmp/arkfile-e2e-test-data"
TOTP_SECRET_FILE="$TEST_DATA_DIR/totp-secret"
PLAYWRIGHT_TEMP_DIR="$TEST_DATA_DIR/playwright"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Test credentials (must match e2e-test.sh)
TEST_USERNAME="arkfile-dev-test-user"
TEST_PASSWORD='MyVacation2025PhotosForFamily!ExtraSecure'
CUSTOM_FILE_PASSWORD='Tr0pic@lSunset2025!SecureCustomKey'
SHARE_A_PASSWORD='MyShareP@ssw0rd-789q&*(::1'
SHARE_B_PASSWORD='MyShareP@ssw0rd-789q&*(::2'
SHARE_C_PASSWORD='MyShareP@ssw0rd-789q&*(::3'

# CLI binary
CLIENT="/opt/arkfile/bin/arkfile-client"

# PREFLIGHT CHECKS

phase "PREFLIGHT CHECKS"

# Check server connectivity
section "Checking server connectivity"
if curl -sk --connect-timeout 5 "$SERVER_URL/health" >/dev/null 2>&1; then
    success "Server is running at $SERVER_URL"
else
    error "Server not reachable at $SERVER_URL"
    error "Run 'sudo bash scripts/dev-reset.sh' first."
    exit 1
fi

# Check TOTP secret
section "Checking TOTP secret"
if [ -f "$TOTP_SECRET_FILE" ]; then
    TOTP_SECRET=$(cat "$TOTP_SECRET_FILE")
    if [ -z "$TOTP_SECRET" ]; then
        error "TOTP secret file is empty: $TOTP_SECRET_FILE"
        exit 1
    fi
    success "TOTP secret loaded from $TOTP_SECRET_FILE"
else
    error "TOTP secret file not found: $TOTP_SECRET_FILE"
    error "Run 'sudo bash scripts/testing/e2e-test.sh' first."
    exit 1
fi

# Check arkfile-client
section "Checking arkfile-client"
if [ -x "$CLIENT" ]; then
    success "arkfile-client available at $CLIENT"
else
    error "arkfile-client not found at $CLIENT"
    exit 1
fi

# Check bun
section "Checking bun runtime"
if command -v bun >/dev/null 2>&1; then
    success "bun available: $(bun --version)"
else
    error "bun not found. Install bun first."
    exit 1
fi

# INSTALL PLAYWRIGHT (if needed)

phase "DEPENDENCY SETUP"

cd "$PROJECT_DIR"

section "Checking Playwright installation"
if [ ! -d "node_modules/@playwright/test" ]; then
    info "Installing @playwright/test..."
    bun add -d @playwright/test
    success "Playwright installed"
else
    success "Playwright already installed"
fi

# Install browser if needed
section "Checking Playwright browsers"
if ! bunx playwright install --dry-run chromium >/dev/null 2>&1; then
    info "Installing Chromium browser for Playwright..."
    bunx playwright install chromium
    success "Chromium installed"
else
    # Always try to install to ensure it's available
    bunx playwright install chromium >/dev/null 2>&1 || true
    success "Chromium browser available"
fi

# GENERATE TEST FILES

phase "GENERATING TEST FILES"

mkdir -p "$PLAYWRIGHT_TEMP_DIR"

TEST_FILE_PATH="$PLAYWRIGHT_TEMP_DIR/pw_test_upload.txt"
CUSTOM_FILE_PATH="$PLAYWRIGHT_TEMP_DIR/pw_custom_upload.txt"

section "Creating test files"

# Generate a small test file with known content (account-password upload)
echo "Arkfile Playwright E2E Test File - Account Password" > "$TEST_FILE_PATH"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$TEST_FILE_PATH"
echo "Purpose: Verify upload/download/integrity via browser frontend" >> "$TEST_FILE_PATH"
# Add some random data to make the hash unique per run
head -c 512 /dev/urandom | base64 >> "$TEST_FILE_PATH"

TEST_FILE_SHA256=$(sha256sum "$TEST_FILE_PATH" | awk '{print $1}')
TEST_FILE_NAME=$(basename "$TEST_FILE_PATH")
success "Test file created: $TEST_FILE_PATH (SHA-256: ${TEST_FILE_SHA256:0:16}...)"

# Generate a different test file for custom-password upload
echo "Arkfile Playwright E2E Test File - Custom Password" > "$CUSTOM_FILE_PATH"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CUSTOM_FILE_PATH"
echo "Purpose: Verify custom-password upload/download via browser frontend" >> "$CUSTOM_FILE_PATH"
head -c 512 /dev/urandom | base64 >> "$CUSTOM_FILE_PATH"

CUSTOM_FILE_SHA256=$(sha256sum "$CUSTOM_FILE_PATH" | awk '{print $1}')
CUSTOM_FILE_NAME=$(basename "$CUSTOM_FILE_PATH")
success "Custom file created: $CUSTOM_FILE_PATH (SHA-256: ${CUSTOM_FILE_SHA256:0:16}...)"

# RUN PLAYWRIGHT TESTS

phase "RUNNING PLAYWRIGHT TESTS"

info "Server URL: $SERVER_URL"
info "Test User: $TEST_USERNAME"
info "Test File: $TEST_FILE_NAME ($TEST_FILE_SHA256)"
info "Custom File: $CUSTOM_FILE_NAME ($CUSTOM_FILE_SHA256)"
echo ""

export SERVER_URL
export TOTP_SECRET
export TEST_FILE_PATH
export TEST_FILE_SHA256
export TEST_FILE_NAME
export CUSTOM_FILE_PATH
export CUSTOM_FILE_SHA256
export CUSTOM_FILE_NAME
export TEST_USERNAME
export TEST_PASSWORD
export CUSTOM_FILE_PASSWORD
export SHARE_A_PASSWORD
export SHARE_B_PASSWORD
export SHARE_C_PASSWORD
export PLAYWRIGHT_TEMP_DIR

# Run Playwright
PLAYWRIGHT_EXIT_CODE=0
bunx playwright test --config playwright.config.ts || PLAYWRIGHT_EXIT_CODE=$?

# CLEANUP

phase "CLEANUP"

section "Cleaning up test files"
rm -f "$TEST_FILE_PATH" "$CUSTOM_FILE_PATH"
rm -rf "$PLAYWRIGHT_TEMP_DIR/downloads" 2>/dev/null || true
success "Temp files cleaned up"

# RESULTS

phase "RESULTS"

if [ $PLAYWRIGHT_EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}  PLAYWRIGHT E2E TESTS PASSED!${NC}"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}  PLAYWRIGHT E2E TESTS FAILED (exit code: $PLAYWRIGHT_EXIT_CODE)${NC}"
    echo ""
    exit $PLAYWRIGHT_EXIT_CODE
fi
