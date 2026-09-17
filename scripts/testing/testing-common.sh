#!/bin/bash

# testing-common.sh - Shared identity and ownership checks for scripts/testing/.
#
# Rule: scripts that change the deployment or read root-only deployment state
# (dev-reset.sh, local-deploy.sh, *-update.sh, online-integrity-test.sh,
# cli-rss-baseline.sh, fdre2e.sh) require sudo. Every other test script runs as
# the developer, refuses root, and writes only under /tmp/arkfile-* directories
# owned by that developer. Test scripts never write into the repository.
#
# Source this file; do not execute it.

# Exit with guidance when a developer-mode test script is started as root.
testing_refuse_root() {
    local script_name="$1"
    if [ "$(id -u)" -ne 0 ]; then
        return 0
    fi
    echo "[X] ${script_name} must run as your regular user, not root." >&2
    echo "    Run: bash scripts/testing/${script_name}" >&2
    echo "    Test artifacts live under /tmp/arkfile-* and must be owned by you." >&2
    echo "    Only deployment scripts and online-integrity-test.sh use sudo." >&2
    exit 1
}

# Exit with guidance when an existing test directory is owned by another user.
# Arg 1: directory; arg 2: script that is expected to create it.
testing_require_owned_dir() {
    local dir="$1"
    local creator="$2"
    local owner_uid
    if [ ! -d "$dir" ]; then
        return 0
    fi
    owner_uid="$(stat -c '%u' "$dir" 2>/dev/null || stat -f '%u' "$dir" 2>/dev/null)"
    if [ "$owner_uid" = "$(id -u)" ]; then
        return 0
    fi
    echo "[X] ${dir} is owned by uid ${owner_uid}, not by you ($(id -un))." >&2
    echo "    It was probably created by an older run under sudo." >&2
    echo "    Remove it with: sudo rm -rf ${dir}" >&2
    echo "    Then re-run ${creator} as your regular user." >&2
    exit 1
}

# Print the invoking developer for a script that runs under sudo. Exits when
# the caller is not root, was not invoked through sudo, or is root/arkfile.
testing_sudo_developer_or_die() {
    local script_name="$1"
    local dev="${SUDO_USER:-}"
    if [ "$(id -u)" -ne 0 ]; then
        echo "[X] ${script_name} must run with sudo." >&2
        echo "    Run: sudo bash ${script_name}" >&2
        exit 1
    fi
    if [ -z "$dev" ] || [ "$dev" = root ] || [ "$dev" = arkfile ]; then
        echo "[X] ${script_name} must be started with sudo from a regular developer account." >&2
        echo "    It drops to that account for the test steps so test artifacts are owned by you." >&2
        exit 1
    fi
    printf '%s\n' "$dev"
}
