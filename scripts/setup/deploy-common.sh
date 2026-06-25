#!/bin/bash
# Shared helpers for the Arkfile deploy/update scripts.
#
# Source this from scripts/test-deploy.sh, test-update.sh, prod-deploy.sh,
# prod-update.sh, local-deploy.sh, and local-update.sh AFTER sourcing
# build-config.sh. It expects the following variables to already be set by
# the caller:
#
#   ARKFILE_DIR        install root (e.g. /opt/arkfile)
#   ARKFILE_USER       service user  (arkfile)
#   ARKFILE_GROUP      service group (arkfile)
#
# and (for scripts that render the Caddyfile) SCRIPT_DIR pointing at scripts/.
#
# It does NOT redefine ARKFILE_DIR / ARKFILE_USER / ARKFILE_GROUP; callers
# own those so that local vs test vs prod defaults stay where they are.

# Colored status output. The six deploy/update scripts share this exact body.
print_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "INFO")    echo -e "  ${BLUE}INFO:${NC} ${message}" ;;
        "SUCCESS") echo -e "  ${GREEN}SUCCESS:${NC} ${message}" ;;
        "WARNING") echo -e "  ${YELLOW}WARNING:${NC} ${message}" ;;
        "ERROR")   echo -e "  ${RED}ERROR:${NC} ${message}" ;;
    esac
}

# Run a command as the original (pre-sudo) user so Go build artifacts are not
# root-owned. Falls back to running directly when not root.
run_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H "$@"
    else
        "$@"
    fi
}

# Stop a systemd service if it is running; fall back to kill on graceful failure.
# Named stop_service_if_running in the deploy scripts and stop_service_gracefully
# in the update scripts; both names are exported so either script can source this
# file without renaming their call sites.
stop_service_if_running() {
    local service_name="$1"
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        print_status "INFO" "Stopping $service_name..."
        systemctl stop "$service_name" || {
            print_status "WARNING" "Failed to stop $service_name gracefully, trying force stop..."
            systemctl kill "$service_name" 2>/dev/null || true
            sleep 2
        }
        print_status "SUCCESS" "$service_name stopped"
    else
        print_status "INFO" "$service_name not running"
    fi
}
stop_service_gracefully() { stop_service_if_running "$@"; }

# Fail if any file under a directory is root-owned (catches stray root writes).
verify_ownership() {
    local check_dir="$1"
    print_status "INFO" "Verifying directory ownership for $check_dir..."
    local root_owned
    root_owned=$(find "$check_dir" -user root 2>/dev/null | grep -v "^$" || true)
    if [ -n "$root_owned" ]; then
        print_status "ERROR" "Found root-owned files/directories:"
        echo "$root_owned" | while read -r file; do
            echo "  - $file"
        done
        return 1
    fi
    print_status "SUCCESS" "All files in $check_dir owned by arkfile user"
    return 0
}

# Username rules mirror the Go validator in utils/username_validator.go.
validate_username() {
    local username="$1"
    local len=${#username}

    if [ "$len" -lt 10 ]; then
        echo "ERROR: Username must be at least 10 characters (got $len)"
        return 1
    fi
    if [ "$len" -gt 50 ]; then
        echo "ERROR: Username must be at most 50 characters (got $len)"
        return 1
    fi
    if ! echo "$username" | grep -qE '^[a-z0-9_.,-]{10,50}$'; then
        echo "ERROR: Username can only contain lowercase letters, numbers, underscores, hyphens, periods, and commas"
        return 1
    fi
    if echo "$username" | grep -qE '^[-_.,]'; then
        echo "ERROR: Username cannot start with a special character"
        return 1
    fi
    if echo "$username" | grep -qE '[-_.,]$'; then
        echo "ERROR: Username cannot end with a special character"
        return 1
    fi
    if echo "$username" | grep -qE '\.\.|--|__|,,'; then
        echo "ERROR: Username cannot contain consecutive special characters"
        return 1
    fi
    return 0
}

validate_storage_backend() {
    case "$1" in
        local-seaweedfs|wasabi|backblaze|vultr|hetzner|cloudflare-r2|aws-s3|generic-s3)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Read a KEY=value line out of secrets.env (returns empty if absent).
read_secrets_env_value() {
    local key="$1"
    grep "^${key}=" "$SECRETS_ENV" 2>/dev/null | head -1 | cut -d'=' -f2-
}
