#!/bin/bash

# Arkfile Test Update Script
# Rebuilds and redeploys app binaries and static assets WITHOUT touching data, keys, or config.
# Use this to apply code changes to an existing test deployment (test.arkfile.net or similar).
# Does NOT wipe data, does NOT require re-bootstrapping the admin account.
# Requires: an existing deployment written by test-deploy.sh

set -e

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/setup/build-config.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

ARKFILE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"
SECRETS_ENV="$ARKFILE_DIR/etc/secrets.env"

FORCE_REBUILD_ALL=false

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

show_help() {
    cat << EOF2
Arkfile Test Update Script

Rebuilds Go binaries, TypeScript frontend, and static assets, then redeploys them
to an existing test deployment without touching data, keys, or configuration.

Usage:
  sudo bash scripts/test-update.sh [OPTIONS]

Options:
  --force-rebuild-all    Force rebuild of C libraries (libopaque/liboprf) and WASM.
                         Use this when libopaque or liboprf source has changed.
                         By default, existing C libraries are reused (fast update).
  -h, --help             Show this help message

Requirements:
  - An existing deployment written by test-deploy.sh
  - /opt/arkfile/etc/secrets.env must exist and contain BASE_URL=https://<domain>
  - The repo must be checked out on the VPS at the current working directory
EOF2
}

run_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H "$@"
    else
        "$@"
    fi
}

stop_service_gracefully() {
    local service_name="$1"
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        print_status "INFO" "Stopping $service_name..."
        systemctl stop "$service_name" || {
            print_status "WARNING" "Graceful stop failed for $service_name, trying kill..."
            systemctl kill "$service_name" 2>/dev/null || true
            sleep 2
        }
        print_status "SUCCESS" "$service_name stopped"
    else
        print_status "INFO" "$service_name is not running"
    fi
}

read_secrets_env_value() {
    local key="$1"
    grep "^${key}=" "$SECRETS_ENV" 2>/dev/null | head -1 | cut -d'=' -f2-
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force-rebuild-all)
            FORCE_REBUILD_ALL=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    print_status "ERROR" "This script must be run with sudo privileges"
    show_help
    exit 1
fi

echo -e "${CYAN}Pre-flight checks${NC}"

if [ ! -f "$SECRETS_ENV" ]; then
    print_status "ERROR" "No existing deployment found: $SECRETS_ENV does not exist"
    print_status "ERROR" "Run scripts/test-deploy.sh first to create a deployment"
    exit 1
fi

if ! systemctl list-unit-files arkfile.service >/dev/null 2>&1; then
    print_status "ERROR" "arkfile.service not found in systemd"
    print_status "ERROR" "Run scripts/test-deploy.sh first to create a deployment"
    exit 1
fi

# Read domain from existing secrets.env via BASE_URL
BASE_URL_VALUE=$(read_secrets_env_value "BASE_URL")
if [ -z "$BASE_URL_VALUE" ]; then
    print_status "ERROR" "BASE_URL is not set in $SECRETS_ENV"
    print_status "ERROR" "Add BASE_URL=https://<your-domain> to $SECRETS_ENV before running this script"
    exit 1
fi

# Strip trailing slash if present
DOMAIN="${BASE_URL_VALUE%/}"
# Strip scheme
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN#http://}"

print_status "INFO" "Existing deployment detected for: $DOMAIN"

if ! GO_BINARY=$(find_go_binary); then
    print_status "ERROR" "Go compiler not found"
    exit 1
fi
print_status "SUCCESS" "Found Go at: $GO_BINARY"
export GO_BINARY="$GO_BINARY"

echo
echo -e "${BLUE}ARKFILE TEST UPDATE${NC}"
echo
echo -e "${BLUE}Configuration:${NC}"
echo "  Domain:             $DOMAIN"
echo "  Force rebuild C:    $FORCE_REBUILD_ALL"
echo "  Data:               PRESERVED (not touched)"
echo "  Config/keys:        PRESERVED (not touched)"
echo
echo -e "${YELLOW}This will: rebuild binaries/frontend, stop arkfile+caddy, deploy, restart.${NC}"
echo -e "${YELLOW}rqlite and seaweedfs will NOT be stopped.${NC}"
echo
read -r -p "Type UPDATE to proceed (anything else cancels): "
if [[ $REPLY != "UPDATE" ]]; then
    echo "Cancelled. Nothing was changed."
    exit 0
fi

echo
echo -e "${CYAN}Step 1: Build${NC}"

fix_go_ownership

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

# Always do a fresh TypeScript build
rm -f client/static/js/.buildcache
rm -rf client/static/js/dist/*

# Clean build artifacts (binaries/static only), preserving C libraries if skipping
if [ -d "$BUILD_ROOT" ]; then
    if [ "$SKIP_C_LIBS" = "true" ]; then
        rm -rf "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT" 2>/dev/null || true
        rm -f "$BUILD_ROOT/version.json" 2>/dev/null || true
    else
        rm -rf "$BUILD_ROOT"
    fi
fi

unset LIBOPAQUE_DEFINES

export VERSION="update-$(date +%Y%m%d-%H%M%S)"
export SKIP_C_LIBS="$SKIP_C_LIBS"

fix_go_ownership
if ! run_as_user ./scripts/setup/build.sh --build-only; then
    print_status "ERROR" "Build failed"
    exit 1
fi
fix_go_ownership

# Verify critical build artifacts
[ -f "$BUILD_BIN/arkfile" ]          || { print_status "ERROR" "arkfile binary missing after build"; exit 1; }
[ -f "$BUILD_BIN/arkfile-client" ]   || { print_status "ERROR" "arkfile-client binary missing after build"; exit 1; }
[ -f "$BUILD_BIN/arkfile-admin" ]    || { print_status "ERROR" "arkfile-admin binary missing after build"; exit 1; }
[ -f "$BUILD_CLIENT/static/js/dist/app.js" ] || { print_status "ERROR" "TypeScript bundle missing after build"; exit 1; }
[ -f "$BUILD_CLIENT/static/js/libopaque.js" ] || { print_status "ERROR" "libopaque.js missing after build"; exit 1; }

print_status "SUCCESS" "Build complete"

echo
echo -e "${CYAN}Step 2: Stop services (caddy + arkfile)${NC}"

stop_service_gracefully "caddy"
stop_service_gracefully "arkfile"

# Brief pause to ensure the binary is not in use
sleep 2

echo
echo -e "${CYAN}Step 3: Deploy binaries and static assets${NC}"

print_status "INFO" "Deploying Go binaries..."
install -m 755 -o "$USER" -g "$GROUP" "$BUILD_BIN/arkfile"        "$ARKFILE_DIR/bin/arkfile"
install -m 755 -o "$USER" -g "$GROUP" "$BUILD_BIN/arkfile-client" "$ARKFILE_DIR/bin/arkfile-client"
install -m 755 -o "$USER" -g "$GROUP" "$BUILD_BIN/arkfile-admin"  "$ARKFILE_DIR/bin/arkfile-admin"
print_status "SUCCESS" "Binaries deployed"

print_status "INFO" "Deploying static assets..."
# Sync client/static tree (HTML, CSS, JS, WASM, errors)
# Using cp -a to preserve structure; chown after to ensure correct ownership
cp -r "$BUILD_CLIENT/static/." "$ARKFILE_DIR/client/static/"
chown -R "$USER:$GROUP" "$ARKFILE_DIR/client"
print_status "SUCCESS" "Static assets deployed"

print_status "INFO" "Deploying updated systemd service files..."
if [ -d "$BUILD_ROOT/systemd" ]; then
    cp "$BUILD_ROOT/systemd/arkfile.service"   /etc/systemd/system/ 2>/dev/null || true
    cp "$BUILD_ROOT/systemd/caddy.service"     /etc/systemd/system/ 2>/dev/null || true
    cp "$BUILD_ROOT/systemd/rqlite.service"    /etc/systemd/system/ 2>/dev/null || true
    cp "$BUILD_ROOT/systemd/seaweedfs.service" /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
    print_status "SUCCESS" "Systemd services updated"
else
    print_status "WARNING" "No systemd directory in build, skipping service file update"
fi

print_status "INFO" "Deploying updated database schema..."
if [ -d "$BUILD_ROOT/database" ]; then
    cp -r "$BUILD_ROOT/database/." "$ARKFILE_DIR/database/"
    chown -R "$USER:$GROUP" "$ARKFILE_DIR/database"
fi

echo
echo -e "${CYAN}Step 4: Restart services${NC}"

print_status "INFO" "Starting Arkfile..."
systemctl start arkfile
arkfile_ready=false
for _ in $(seq 1 15); do
    if curl -sk https://localhost:8443/readyz 2>/dev/null | grep -q '"status":"ready"'; then
        arkfile_ready=true
        break
    fi
    sleep 3
done
if [ "$arkfile_ready" != "true" ]; then
    print_status "ERROR" "Arkfile failed to become ready within timeout"
    print_status "ERROR" "Check logs: sudo journalctl -u arkfile -f"
    exit 1
fi
print_status "SUCCESS" "Arkfile is ready on localhost:8443"

print_status "INFO" "Starting Caddy..."
systemctl start caddy
caddy_ready=false
for _ in $(seq 1 15); do
    if curl -sk "https://${DOMAIN}/readyz" 2>/dev/null | grep -q '"status":"ready"'; then
        caddy_ready=true
        break
    fi
    sleep 3
done
if [ "$caddy_ready" != "true" ]; then
    print_status "ERROR" "Caddy failed to pass health check within timeout"
    print_status "ERROR" "Check logs: sudo journalctl -u caddy -f"
    exit 1
fi
print_status "SUCCESS" "Public HTTPS endpoint is ready at https://${DOMAIN}"

echo
echo -e "${CYAN}Step 5: Health verification${NC}"

if curl -sk https://localhost:8443/api/config/argon2 2>/dev/null | grep -q '"memoryCostKiB"'; then
    print_status "SUCCESS" "Argon2 config endpoint responding"
else
    print_status "WARNING" "Argon2 config endpoint may not be responding"
fi
if curl -sk https://localhost:8443/api/config/password-requirements 2>/dev/null | grep -q '"minAccountPasswordLength"'; then
    print_status "SUCCESS" "Password requirements endpoint responding"
else
    print_status "WARNING" "Password requirements endpoint may not be responding"
fi
if curl -sk https://localhost:8443/api/config/chunking 2>/dev/null | grep -q '"plaintextChunkSizeBytes"'; then
    print_status "SUCCESS" "Chunking config endpoint responding"
else
    print_status "WARNING" "Chunking config endpoint may not be responding"
fi

print_status "INFO" "Service status:"
echo "    arkfile:   $(systemctl is-active arkfile 2>/dev/null || echo 'failed')"
echo "    caddy:     $(systemctl is-active caddy 2>/dev/null || echo 'failed')"
echo "    rqlite:    $(systemctl is-active rqlite 2>/dev/null || echo 'unknown')"
echo "    seaweedfs: $(systemctl is-active seaweedfs 2>/dev/null || echo 'unknown')"

echo
echo -e "${GREEN}UPDATE COMPLETE${NC}"
echo
echo -e "${BLUE}Your Arkfile instance at https://${DOMAIN} has been updated.${NC}"
echo "Data, keys, and configuration were not modified."
echo

exit 0
