#!/bin/bash

# Arkfile Helper Script: Full Development Reset & End-to-End Test Script
#
# Usage: sudo bash fdre2e.sh   (from the repository root)
#
# Root is required only for dev-reset.sh. The two test scripts run as the
# developer who invoked sudo, so /tmp/arkfile-e2e-test-data and all Playwright
# output are owned by that developer. Run the test scripts on their own without
# sudo: bash scripts/testing/e2e-test.sh, bash scripts/testing/e2e-playwright.sh

set -e

# shellcheck source=scripts/testing/testing-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/testing/testing-common.sh"
DEV_USER="$(testing_sudo_developer_or_die "fdre2e.sh")"

# Run a test script as the developer. sudo resets the environment, so forward
# the documented e2e overrides explicitly when the caller set them.
run_as_developer() {
    local -a forwarded=()
    local name
    for name in SERVER_URL ADMIN_USERNAME ADMIN_PASSWORD TEST_USERNAME TEST_PASSWORD; do
        if [ -n "${!name:-}" ]; then
            forwarded+=("${name}=${!name}")
        fi
    done
    sudo -u "$DEV_USER" -H env "${forwarded[@]}" bash "$@"
}

echo "WARNING: This script deletes ALL Arkfile data from the local system!"
echo "Initiating FULL DEV RESET in 5 seconds..."
echo "...5"
sleep 1
echo "...4"
sleep 1
echo "...3"
sleep 1
echo "...2"
sleep 1
echo "...1"
sleep 1
echo "...Go!"
sleep 2

echo " "
echo "--- INIT dev-reset.sh (root) ---"

echo "NUKE" | bash scripts/dev-reset.sh

echo " "
sleep 3

echo "--- INIT e2e-test.sh (as $DEV_USER) ---"

run_as_developer scripts/testing/e2e-test.sh

echo " "
sleep 3

echo "--- INIT e2e-playwright.sh (as $DEV_USER) ---"

run_as_developer scripts/testing/e2e-playwright.sh

echo " "
echo "--- END ---"
