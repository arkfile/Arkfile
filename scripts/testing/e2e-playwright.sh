#!/bin/bash

# e2e-playwright.sh - Playwright Frontend E2E Test Wrapper
#
# Runs after e2e-test.sh has completed successfully.
# Exercises the web frontend via Playwright against the live local server.
#
# Run as your regular user (no sudo): bash scripts/testing/e2e-playwright.sh
#
# Prerequisites:
#   - Server deployed via scripts/dev-reset.sh
#   - scripts/testing/e2e-test.sh has run as the same user (test user exists,
#     approved, MFA configured; writes /tmp/arkfile-e2e-test-data)
#   - Bun 1.3.x (last Zig-built line, currently 1.3.14) installed for this user
#   - Root workspace dependencies installed (dev-reset.sh does this; otherwise
#     run `bun install --frozen-lockfile` from the repo root)
#   - Playwright Chromium installed once for this user: bunx playwright install chromium
#
# All Playwright output (traces, screenshots, .last-run.json) is written under
# /tmp/arkfile-e2e-test-data/playwright, never into the repository.

set -eo pipefail

# Runs as the developer, never root. See scripts/testing/testing-common.sh.
# shellcheck source=testing-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/testing-common.sh"
testing_refuse_root "e2e-playwright.sh"

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
section() { echo -e "\n${CYAN}$1${NC}\n"; }

# CONFIGURATION

SERVER_URL="${SERVER_URL:-https://localhost:8443}"
TEST_DATA_DIR="/tmp/arkfile-e2e-test-data"
MFA_SECRET_FILE="$TEST_DATA_DIR/mfa-secret"
PLAYWRIGHT_TEMP_DIR="$TEST_DATA_DIR/playwright"
# Playwright outputDir (read by playwright.config.ts). Fixed location so traces
# are always in the same place; Playwright clears it at the start of each run.
PLAYWRIGHT_OUTPUT_DIR="$PLAYWRIGHT_TEMP_DIR/results"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../setup/build-config.sh
source "$PROJECT_DIR/scripts/setup/build-config.sh"

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

section "PREFLIGHT CHECKS"

# Check server connectivity
section "Checking server connectivity"
if curl -sk --connect-timeout 5 -f "$SERVER_URL/readyz" >/dev/null 2>&1; then
    success "Server is running at $SERVER_URL"
else
    error "Server not reachable at $SERVER_URL"
    error "Run 'sudo bash scripts/dev-reset.sh' first."
    exit 1
fi

# Check MFA secret (post–re-enrollment secret when shell e2e completed auth group)
section "Checking MFA secret"
testing_require_owned_dir "$TEST_DATA_DIR" "e2e-test.sh"
if [ -f "$MFA_SECRET_FILE" ]; then
    MFA_SECRET=$(cat "$MFA_SECRET_FILE")
    if [ -z "$MFA_SECRET" ]; then
        error "MFA secret file is empty: $MFA_SECRET_FILE"
        exit 1
    fi
    success "MFA secret loaded from $MFA_SECRET_FILE"
else
    error "MFA secret file not found: $MFA_SECRET_FILE"
    error "Run 'sudo bash scripts/testing/e2e-test.sh' first."
    exit 1
fi

# Shared multi-download corpus seeded by e2e-test.sh (left on the test user)
MULTI_DL_CORPUS_PATH="$TEST_DATA_DIR/multi-dl-corpus.json"
section "Checking multi-download corpus manifest"
if [ -f "$MULTI_DL_CORPUS_PATH" ]; then
    CORPUS_COUNT=$(jq '.files | length' "$MULTI_DL_CORPUS_PATH" 2>/dev/null || echo 0)
    if [ "$CORPUS_COUNT" -lt 16 ]; then
        error "multi-dl corpus has $CORPUS_COUNT files (need at least 16): $MULTI_DL_CORPUS_PATH"
        error "Re-run 'sudo bash scripts/testing/e2e-test.sh' after a fresh dev-reset."
        exit 1
    fi
    success "Multi-dl corpus loaded ($CORPUS_COUNT files) from $MULTI_DL_CORPUS_PATH"
else
    error "Multi-dl corpus manifest not found: $MULTI_DL_CORPUS_PATH"
    error "Run 'sudo bash scripts/testing/e2e-test.sh' first (corpus is seeded in files_custom_password)."
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

# Check bun (per-user install at ~/.bun/bin; find_bun_binary is from build-config.sh)
section "Checking bun runtime"
BUN_CMD="$(find_bun_binary || true)"
if [ -z "$BUN_CMD" ]; then
    error "bun not found. Install Bun ${BUN_ZIG_VERSION} (Zig) for this user first."
    print_bun_install_hint
    exit 1
fi
export PATH="$(dirname "$BUN_CMD"):${PATH}"
if ! require_bun_zig_build "$BUN_CMD"; then
    error "Bun 1.3.x (last Zig-built line) is required"
    exit 1
fi
success "bun available: $(bun --version) at $BUN_CMD"

# DEPENDENCY PREFLIGHT (no installs at test time)

section "DEPENDENCY PREFLIGHT"

cd "$PROJECT_DIR"

section "Checking Playwright installation"
if [ -d "node_modules/@playwright/test" ]; then
    success "@playwright/test present in node_modules"
else
    error "@playwright/test is not installed in $PROJECT_DIR/node_modules"
    error "dev-reset.sh installs it; otherwise run from the repo root: bun install --frozen-lockfile"
    exit 1
fi

section "Checking Playwright Chromium"
PLAYWRIGHT_BROWSERS_DIR="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
if compgen -G "$PLAYWRIGHT_BROWSERS_DIR/chromium-*" >/dev/null; then
    success "Chromium present under $PLAYWRIGHT_BROWSERS_DIR"
else
    error "Playwright Chromium is not installed for $(id -un) under $PLAYWRIGHT_BROWSERS_DIR"
    error "Install it once (needs network): bunx playwright install chromium"
    exit 1
fi

# GENERATE TEST FILES

section "GENERATING TEST FILES"

# Fresh Playwright workspace under the developer-owned e2e directory.
rm -rf "$PLAYWRIGHT_TEMP_DIR"
mkdir -p "$PLAYWRIGHT_TEMP_DIR" "$PLAYWRIGHT_OUTPUT_DIR"
chmod 700 "$PLAYWRIGHT_TEMP_DIR"

TEST_FILE_PATH="$PLAYWRIGHT_TEMP_DIR/pw_test_upload.bin"
CUSTOM_FILE_PATH="$PLAYWRIGHT_TEMP_DIR/pw_custom_upload.bin"
REG_FLOW_FILE_PATH="$PLAYWRIGHT_TEMP_DIR/pw_reg_flow_upload.bin"

# Isolated registration-flow credentials (unique username per run)
REG_FLOW_USERNAME="pwregflow$(date +%s)"
REG_FLOW_PASSWORD='RegFlowTest2026!SecurePass'
REG_FLOW_CUSTOM_PASSWORD='RegFlowCustom2026!SecureKey'

section "Creating test files via arkfile-client"

# Account-password test file: 100KB, sequential pattern (deterministic, reproducible)
$CLIENT generate-test-file \
    --filename "$TEST_FILE_PATH" \
    --size 102400 \
    --pattern sequential

TEST_FILE_SHA256=$(sha256sum "$TEST_FILE_PATH" | awk '{print $1}')
TEST_FILE_NAME=$(basename "$TEST_FILE_PATH")
success "Test file: $TEST_FILE_PATH (SHA-256: ${TEST_FILE_SHA256:0:16}...)"

# Custom-password test file: 50KB, zeros pattern (deterministic, different from above)
$CLIENT generate-test-file \
    --filename "$CUSTOM_FILE_PATH" \
    --size 51200 \
    --pattern zeros

CUSTOM_FILE_SHA256=$(sha256sum "$CUSTOM_FILE_PATH" | awk '{print $1}')
CUSTOM_FILE_NAME=$(basename "$CUSTOM_FILE_PATH")
success "Custom file: $CUSTOM_FILE_PATH (SHA-256: ${CUSTOM_FILE_SHA256:0:16}...)"

# Registration-flow custom-password file: 25 MB (26214400 bytes)
$CLIENT generate-test-file \
    --filename "$REG_FLOW_FILE_PATH" \
    --size 26214400 \
    --pattern sequential

REG_FLOW_FILE_SHA256=$(sha256sum "$REG_FLOW_FILE_PATH" | awk '{print $1}')
REG_FLOW_FILE_NAME=$(basename "$REG_FLOW_FILE_PATH")
success "Reg-flow file: $REG_FLOW_FILE_PATH (SHA-256: ${REG_FLOW_FILE_SHA256:0:16}...)"

# RUN PLAYWRIGHT TESTS

section "RUNNING PLAYWRIGHT TESTS"

info "Server URL: $SERVER_URL"
info "Test User: $TEST_USERNAME"
info "Test File: $TEST_FILE_NAME ($TEST_FILE_SHA256)"
info "Custom File: $CUSTOM_FILE_NAME ($CUSTOM_FILE_SHA256)"
info "Reg-flow User: $REG_FLOW_USERNAME"
info "Reg-flow File: $REG_FLOW_FILE_NAME ($REG_FLOW_FILE_SHA256)"
echo ""

export SERVER_URL
export MFA_SECRET
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
export PLAYWRIGHT_OUTPUT_DIR
export REG_FLOW_FILE_PATH
export REG_FLOW_FILE_SHA256
export REG_FLOW_FILE_NAME
export REG_FLOW_USERNAME
export REG_FLOW_PASSWORD
export REG_FLOW_CUSTOM_PASSWORD
export MULTI_DL_CORPUS_PATH

# Run Playwright
PLAYWRIGHT_EXIT_CODE=0
bunx playwright test --config playwright.config.ts || PLAYWRIGHT_EXIT_CODE=$?

# CLEANUP

section "CLEANUP"

section "Cleaning up test files"
rm -f "$TEST_FILE_PATH" "$CUSTOM_FILE_PATH" "$REG_FLOW_FILE_PATH"
rm -rf "$PLAYWRIGHT_TEMP_DIR/downloads" 2>/dev/null || true
if [ $PLAYWRIGHT_EXIT_CODE -eq 0 ]; then
    rm -rf "$PLAYWRIGHT_OUTPUT_DIR" 2>/dev/null || true
    success "Temp files and Playwright output cleaned up"
else
    success "Temp files cleaned up; Playwright traces and screenshots kept in $PLAYWRIGHT_OUTPUT_DIR"
fi

# RESULTS

section "RESULTS"

if [ $PLAYWRIGHT_EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}  PLAYWRIGHT E2E TESTS PASSED!${NC}"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}  PLAYWRIGHT E2E TESTS FAILED (exit code: $PLAYWRIGHT_EXIT_CODE)${NC}"
    echo -e "${YELLOW}  Failure artifacts: $PLAYWRIGHT_OUTPUT_DIR${NC}"
    echo ""
    exit $PLAYWRIGHT_EXIT_CODE
fi
