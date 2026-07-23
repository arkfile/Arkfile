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
# Color variables (RED/GREEN/YELLOW/BLUE/CYAN/NC) must be set by the caller.
# SECRETS_ENV must be set for read_secrets_env_value and update scripts.
#
# It does NOT redefine ARKFILE_DIR / ARKFILE_USER / ARKFILE_GROUP; callers
# own those so that local vs test vs prod defaults stay where they are.
#
# Also provides shared build wipe/run/verify helpers and update backup/static
# sync used by VPS and local update/deploy paths. VPS-specific first-deploy
# and update bodies live in setup/vps-first-deploy.sh and setup/vps-update.sh.

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

# Clear TypeScript / service-worker build caches so the next build regenerates bundles.
clear_frontend_build_caches() {
    rm -f client/static/js/.buildcache
    rm -rf client/static/js/dist/*
    rm -f client/static/js/sw-download.js client/static/js/sw-download.js.map
}

# Wipe binary/static/schema build outputs. When SKIP_C_LIBS=true, preserve C libs under BUILD_CLIBS.
wipe_build_artifacts_preserving_c_libs_if_skipping() {
    if [ ! -d "$BUILD_ROOT" ]; then
        return 0
    fi
    if [ "$SKIP_C_LIBS" = "true" ]; then
        rm -rf "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT" 2>/dev/null || true
        rm -f "$BUILD_ROOT/version.json" 2>/dev/null || true
    else
        rm -rf "$BUILD_ROOT"
    fi
}

# First-time deploy: default to rebuilding C libs unless they already exist (unless --force-rebuild-all).
decide_skip_c_libs_for_first_deploy() {
    SKIP_C_LIBS=false
    if [ "$FORCE_REBUILD_ALL" = "true" ]; then
        print_status "INFO" "--force-rebuild-all: deleting entire build directory"
        rm -rf "$BUILD_ROOT"
    elif c_libs_exist; then
        SKIP_C_LIBS=true
        print_status "INFO" "Found existing C libraries, will skip rebuild"
    fi
}

# Update path: prefer reusing existing C libs; rebuild when forced or missing.
decide_skip_c_libs_for_update() {
    SKIP_C_LIBS=true
    if [ "$FORCE_REBUILD_ALL" = "true" ]; then
        print_status "INFO" "--force-rebuild-all: will rebuild C libraries and WASM"
        SKIP_C_LIBS=false
        if [ -d "$BUILD_ROOT" ]; then
            rm -rf "$BUILD_ROOT"
        fi
    elif c_libs_exist; then
        print_status "INFO" "Existing C libraries found, skipping C rebuild (use --force-rebuild-all to override)"
    else
        print_status "WARNING" "C libraries not found, will build them"
        SKIP_C_LIBS=false
    fi
}

# Run scripts/setup/build.sh as the original user. Remaining args are forwarded after --build-only
# (pass --production for VPS builds; omit for local).
run_application_build() {
    local version="$1"
    shift
    export VERSION="$version"
    export SKIP_C_LIBS="$SKIP_C_LIBS"
    fix_go_ownership
    if ! run_as_user ./scripts/setup/build.sh --build-only "$@"; then
        print_status "ERROR" "Build failed"
        exit 1
    fi
    fix_go_ownership
}

# Verify critical outputs under BUILD_* after a successful build.
verify_build_tree_artifacts() {
    [ -f "$BUILD_BIN/arkfile" ] || { print_status "ERROR" "arkfile binary missing after build"; exit 1; }
    [ -f "$BUILD_BIN/arkfile-client" ] || { print_status "ERROR" "arkfile-client binary missing after build"; exit 1; }
    [ -f "$BUILD_BIN/arkfile-admin" ] || { print_status "ERROR" "arkfile-admin binary missing after build"; exit 1; }
    [ -f "$BUILD_CLIENT/static/js/dist/app.js" ] || { print_status "ERROR" "TypeScript bundle missing after build"; exit 1; }
    [ -f "$BUILD_CLIENT/static/js/libopaque.js" ] || { print_status "ERROR" "libopaque.js missing after build"; exit 1; }
}

# Verify critical files under ARKFILE_DIR after deploy.sh (or equivalent install).
verify_deployed_app_artifacts() {
    [ -x "$ARKFILE_DIR/bin/arkfile" ] || { print_status "ERROR" "arkfile binary missing"; exit 1; }
    [ -x "$ARKFILE_DIR/bin/arkfile-client" ] || { print_status "ERROR" "arkfile-client binary missing"; exit 1; }
    [ -x "$ARKFILE_DIR/bin/arkfile-admin" ] || { print_status "ERROR" "arkfile-admin binary missing"; exit 1; }
    [ -f "$ARKFILE_DIR/client/static/js/dist/app.js" ] || { print_status "ERROR" "TypeScript bundle missing"; exit 1; }
    [ -f "$ARKFILE_DIR/client/static/js/libopaque.js" ] || { print_status "ERROR" "libopaque.js missing"; exit 1; }
}

# Backup live binaries (and rqlite data if running), prune to 3 backups, install rollback trap.
# Arg 1: space-separated systemd units to stop/start on rollback (e.g. "arkfile" or "caddy arkfile").
backup_binaries_before_overwrite() {
    local rollback_services="${1:-arkfile}"

    if [ ! -x "$ARKFILE_DIR/bin/arkfile" ]; then
        return 0
    fi

    BACKUP_DIR="$ARKFILE_DIR/backups/bin-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp "$ARKFILE_DIR/bin/arkfile" "$ARKFILE_DIR/bin/arkfile-client" "$ARKFILE_DIR/bin/arkfile-admin" "$BACKUP_DIR/" 2>/dev/null || true

    if systemctl is-active --quiet rqlite 2>/dev/null; then
        print_status "INFO" "Backing up rqlite physical database..."
        systemctl stop rqlite || { print_status "WARNING" "Failed to stop rqlite for backup; continuing anyway"; }
        if [ -d "$ARKFILE_DIR/var/lib/rqlite" ]; then
            cp -r "$ARKFILE_DIR/var/lib/rqlite" "$BACKUP_DIR/"
        fi
        systemctl start rqlite || { print_status "ERROR" "Failed to restart rqlite after backup"; exit 1; }
        print_status "SUCCESS" "rqlite physical database backed up"
    fi

    chown -R "$ARKFILE_USER:$ARKFILE_GROUP" "$ARKFILE_DIR/backups"
    print_status "SUCCESS" "Current version backed up to $BACKUP_DIR"

    # Globals so the EXIT trap can see them after this function returns.
    BACKUP_ROLLBACK_SERVICES="$rollback_services"

    rollback_on_failure() {
        local exit_code=$?
        if [ $exit_code -ne 0 ]; then
            print_status "ERROR" "Update failed with exit code $exit_code! Triggering automatic rollback to previous version..."
            # shellcheck disable=SC2086
            systemctl stop $BACKUP_ROLLBACK_SERVICES 2>/dev/null || true
            if [ -d "$BACKUP_DIR" ]; then
                cp "$BACKUP_DIR"/arkfile* "$ARKFILE_DIR/bin/" 2>/dev/null || true
                chown -R "$ARKFILE_USER:$ARKFILE_GROUP" "$ARKFILE_DIR/bin"
                if [ -d "$BACKUP_DIR/rqlite" ]; then
                    systemctl stop rqlite 2>/dev/null || true
                    rm -rf "$ARKFILE_DIR/var/lib/rqlite" 2>/dev/null || true
                    cp -r "$BACKUP_DIR/rqlite" "$ARKFILE_DIR/var/lib/rqlite"
                    chown -R "$ARKFILE_USER:$ARKFILE_GROUP" "$ARKFILE_DIR/var/lib/rqlite"
                    systemctl start rqlite 2>/dev/null || true
                fi
            fi
            # shellcheck disable=SC2086
            systemctl start $BACKUP_ROLLBACK_SERVICES 2>/dev/null || true
            print_status "SUCCESS" "Rollback complete"
            exit "$exit_code"
        fi
    }
    trap 'rollback_on_failure' EXIT

    local backup_count
    backup_count=$(ls -1d "$ARKFILE_DIR/backups/bin-"* 2>/dev/null | wc -l)
    if [ "$backup_count" -gt 3 ]; then
        ls -1d "$ARKFILE_DIR/backups/bin-"* 2>/dev/null | head -n -3 | xargs rm -rf
        print_status "INFO" "Pruned old backups (kept 3 most recent)"
    fi
}

install_binaries_from_build() {
    print_status "INFO" "Deploying Go binaries..."
    install -m 755 -o "$ARKFILE_USER" -g "$ARKFILE_GROUP" "$BUILD_BIN/arkfile"        "$ARKFILE_DIR/bin/arkfile"
    install -m 755 -o "$ARKFILE_USER" -g "$ARKFILE_GROUP" "$BUILD_BIN/arkfile-client" "$ARKFILE_DIR/bin/arkfile-client"
    install -m 755 -o "$ARKFILE_USER" -g "$ARKFILE_GROUP" "$BUILD_BIN/arkfile-admin"  "$ARKFILE_DIR/bin/arkfile-admin"
    print_status "SUCCESS" "Binaries deployed"
}

sync_static_assets_from_build() {
    print_status "INFO" "Deploying static assets (with directory cleanup for stale assets)..."
    rm -rf "$ARKFILE_DIR/client/static/js/dist" 2>/dev/null || true
    cp -r "$BUILD_CLIENT/static/." "$ARKFILE_DIR/client/static/"
    chown -R "$ARKFILE_USER:$ARKFILE_GROUP" "$ARKFILE_DIR/client"
    print_status "SUCCESS" "Static assets deployed"
}

sync_database_schema_from_build() {
    print_status "INFO" "Deploying updated database schema..."
    if [ -d "$BUILD_ROOT/database" ]; then
        cp -r "$BUILD_ROOT/database/." "$ARKFILE_DIR/database/"
        chown -R "$ARKFILE_USER:$ARKFILE_GROUP" "$ARKFILE_DIR/database"
    fi
}
