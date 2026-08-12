#!/bin/bash

# Arkfile Local Update Script
# Rebuilds and redeploys app binaries and static assets WITHOUT touching data, keys, or config.
# Use this to apply code changes to an existing local deployment.
# Does NOT wipe data, does NOT require re-bootstrapping the admin account.
# Requires: an existing deployment written by local-deploy.sh

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
ARKFILE_USER="arkfile"
ARKFILE_GROUP="arkfile"
SECRETS_ENV="$ARKFILE_DIR/etc/secrets.env"
TLS_PORT="8443"

FORCE_REBUILD_ALL=false

# Shared helpers (print_status, run_as_user, stop_service_*, verify_ownership,
# validate_username, validate_storage_backend, read_secrets_env_value).
# Color vars above and SECRETS_ENV must be set before this is sourced.
source "$SCRIPT_DIR/setup/deploy-common.sh"

show_help() {
    cat << EOF2
Arkfile Local Update Script

Rebuilds Go binaries, TypeScript frontend, and static assets, then redeploys them
to an existing local deployment without touching data, keys, or configuration.

Usage:
  sudo bash scripts/local-update.sh [OPTIONS]

Options:
  --force-rebuild-all    Force rebuild of C libraries (libopaque/liboprf) and WASM.
                         Use this when libopaque or liboprf source has changed.
                         By default, existing C libraries are reused (fast update).
  -h, --help             Show this help message

Requirements:
  - An existing deployment written by local-deploy.sh
  - /opt/arkfile/etc/secrets.env must exist
  - The repo must be checked out at the current working directory
EOF2
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
    print_status "ERROR" "Run scripts/local-deploy.sh first to create a deployment"
    exit 1
fi

if ! systemctl list-unit-files arkfile.service >/dev/null 2>&1; then
    print_status "ERROR" "arkfile.service not found in systemd"
    print_status "ERROR" "Run scripts/local-deploy.sh first to create a deployment"
    exit 1
fi

# Read TLS port from existing secrets.env
TLS_PORT_VALUE=$(read_secrets_env_value "TLS_PORT")
if [ -n "$TLS_PORT_VALUE" ]; then
    TLS_PORT="$TLS_PORT_VALUE"
fi

# ARKFILE_DOMAIN binds the OPAQUE server identity (idS); it is REQUIRED.
# Update scripts assume a complete secrets.env and hard-fail if it is missing
# rather than silently backfilling (which could change idS out from under
# existing user records).
ARKFILE_DOMAIN_VALUE=$(read_secrets_env_value "ARKFILE_DOMAIN")
if [ -z "$ARKFILE_DOMAIN_VALUE" ]; then
    print_status "ERROR" "ARKFILE_DOMAIN is not set in $SECRETS_ENV"
    print_status "ERROR" "It is required (OPAQUE server identity). Add 'ARKFILE_DOMAIN=localhost' (or your chosen idS) and retry."
    exit 1
fi

# Detect storage backends from existing secrets.env
STORAGE_PROVIDER=$(read_secrets_env_value "STORAGE_PROVIDER_1")
if [ -z "$STORAGE_PROVIDER" ]; then
    STORAGE_PROVIDER="generic-s3"
fi
STORAGE_PROVIDER_ID=$(read_secrets_env_value "STORAGE_PROVIDER_1_ID")
STORAGE_PROVIDER_2=$(read_secrets_env_value "STORAGE_PROVIDER_2")
STORAGE_PROVIDER_2_ID=$(read_secrets_env_value "STORAGE_PROVIDER_2_ID")
STORAGE_PROVIDER_3=$(read_secrets_env_value "STORAGE_PROVIDER_3")
STORAGE_PROVIDER_3_ID=$(read_secrets_env_value "STORAGE_PROVIDER_3_ID")

# Build a display string for all configured providers
STORAGE_DISPLAY="$STORAGE_PROVIDER"
if [ -n "$STORAGE_PROVIDER_ID" ]; then
    STORAGE_DISPLAY="${STORAGE_PROVIDER_ID} (${STORAGE_PROVIDER})"
fi
if [ -n "$STORAGE_PROVIDER_2" ]; then
    SECONDARY_LABEL="$STORAGE_PROVIDER_2"
    if [ -n "$STORAGE_PROVIDER_2_ID" ]; then
        SECONDARY_LABEL="${STORAGE_PROVIDER_2_ID} (${STORAGE_PROVIDER_2})"
    fi
    STORAGE_DISPLAY="${STORAGE_DISPLAY} + ${SECONDARY_LABEL}"
fi
if [ -n "$STORAGE_PROVIDER_3" ]; then
    TERTIARY_LABEL="$STORAGE_PROVIDER_3"
    if [ -n "$STORAGE_PROVIDER_3_ID" ]; then
        TERTIARY_LABEL="${STORAGE_PROVIDER_3_ID} (${STORAGE_PROVIDER_3})"
    fi
    STORAGE_DISPLAY="${STORAGE_DISPLAY} + ${TERTIARY_LABEL}"
fi
MULTI_BACKEND=false
if [ -n "$STORAGE_PROVIDER_2" ]; then
    MULTI_BACKEND=true
fi

# Determine if storage is local SeaweedFS or external.
# Local SeaweedFS deployments use STORAGE_PROVIDER=generic-s3 with S3_ENDPOINT pointing to localhost.
# External providers use non-localhost endpoints or non-generic-s3 provider names.
IS_LOCAL_SEAWEEDFS=false
if [ "$STORAGE_PROVIDER" = "generic-s3" ]; then
    S3_ENDPOINT_VALUE=$(read_secrets_env_value "STORAGE_1_ENDPOINT")
    if echo "$S3_ENDPOINT_VALUE" | grep -qE '(localhost|127\.0\.0\.1)'; then
        IS_LOCAL_SEAWEEDFS=true
    fi
fi
print_status "INFO" "Existing deployment detected (storage: $STORAGE_DISPLAY, TLS port: $TLS_PORT)"
if [ "$MULTI_BACKEND" = "true" ]; then
    print_status "INFO" "Primary role is DB-authoritative (use arkfile-admin storage-status after restart)"
fi

if ! GO_BINARY=$(find_go_binary); then
    print_status "ERROR" "Go compiler not found"
    exit 1
fi
print_status "SUCCESS" "Found Go at: $GO_BINARY"
export GO_BINARY="$GO_BINARY"

if ! ensure_emsdk_python; then
    print_status "ERROR" "Python ${EMSDK_MIN_PYTHON_MAJOR}.${EMSDK_MIN_PYTHON_MINOR}+ is required for emsdk (libopaque WASM)"
    print_emsdk_python_install_hint
    exit 1
fi
print_status "INFO" "emsdk Python: $EMSDK_PYTHON ($("$EMSDK_PYTHON" --version 2>&1))"

if ! emsdk_libatomic_available; then
    print_status "ERROR" "libatomic.so.1 is required by emsdk's Binaryen tools"
    print_emsdk_libatomic_install_hint
    exit 1
fi

echo
echo -e "${BLUE}ARKFILE LOCAL UPDATE${NC}"
echo
echo -e "${BLUE}Configuration:${NC}"
echo "  TLS port:           $TLS_PORT"
echo "  Storage providers:  $STORAGE_DISPLAY"
if [ "$MULTI_BACKEND" = "true" ]; then
echo "  Primary role:       DB-authoritative (check with arkfile-admin storage-status)"
fi
echo "  Force rebuild C:    $FORCE_REBUILD_ALL"
echo "  Data:               PRESERVED (not touched)"
echo "  Config/keys:        PRESERVED (not touched)"
echo
echo -e "${YELLOW}This will: rebuild binaries/frontend, stop arkfile, deploy, restart.${NC}"
if [ "$IS_LOCAL_SEAWEEDFS" = "true" ]; then
    echo -e "${YELLOW}rqlite and seaweedfs will NOT be stopped.${NC}"
else
    echo -e "${YELLOW}rqlite will NOT be stopped. Storage backend (${STORAGE_PROVIDER}) is external.${NC}"
fi
echo
read -r -p "Type UPDATE to proceed (anything else cancels): "
if [[ $REPLY != "UPDATE" ]]; then
    echo "Cancelled. Nothing was changed."
    exit 0
fi

echo
echo -e "${CYAN}Step 1: Build${NC}"

fix_go_ownership

decide_skip_c_libs_for_update
# Rebuild WASM so a prior development trace build cannot be reused.
SKIP_C_LIBS=false

# Always do a fresh TypeScript build
clear_frontend_build_caches
wipe_build_artifacts_preserving_c_libs_if_skipping

# No WASM trace logging for local deployment
unset LIBOPAQUE_DEFINES

run_application_build "update-$(date +%Y%m%d-%H%M%S)"
verify_build_tree_artifacts
print_status "SUCCESS" "Build complete"

prepare_update_rollback "arkfile"

echo
echo -e "${CYAN}Step 2: Stop arkfile service${NC}"

stop_service_gracefully "arkfile"

# Brief pause to ensure the binary is not in use
sleep 2

echo
echo -e "${CYAN}Step 3: Deploy binaries and static assets${NC}"

backup_binaries_before_overwrite "arkfile"
install_binaries_from_build
sync_static_assets_from_build

print_status "INFO" "Deploying updated systemd service files (fail closed on copy failure)..."
# Caddy is not used by local deployments (self-signed TLS served by Arkfile directly),
# so caddy.service is intentionally not copied here.
if [ -d "$BUILD_ROOT/systemd" ]; then
    cp "$BUILD_ROOT/systemd/arkfile.service"   /etc/systemd/system/
    cp "$BUILD_ROOT/systemd/rqlite.service"    /etc/systemd/system/
    cp "$BUILD_ROOT/systemd/seaweedfs.service" /etc/systemd/system/
    systemctl daemon-reload
    print_status "SUCCESS" "Systemd services updated"
else
    print_status "ERROR" "No systemd directory in build, systemd service file update failed"
    exit 1
fi

sync_database_schema_from_build

echo
echo -e "${CYAN}Step 4: Restart arkfile${NC}"

print_status "INFO" "Starting Arkfile..."
systemctl start arkfile
arkfile_ready=false
for _ in $(seq 1 15); do
    if curl -sk https://localhost:${TLS_PORT}/readyz 2>/dev/null | grep -q '"status":"ready"'; then
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
print_status "SUCCESS" "Arkfile is ready on localhost:${TLS_PORT}"

commit_update_rollback

echo
echo -e "${CYAN}Step 5: Health verification${NC}"

if curl -sk https://localhost:${TLS_PORT}/api/config/argon2 2>/dev/null | grep -q '"memoryCostKiB"'; then
    print_status "SUCCESS" "Argon2 config endpoint responding"
else
    print_status "WARNING" "Argon2 config endpoint may not be responding"
fi
if curl -sk https://localhost:${TLS_PORT}/api/config/password-requirements 2>/dev/null | grep -q '"minAccountPasswordLength"'; then
    print_status "SUCCESS" "Password requirements endpoint responding"
else
    print_status "WARNING" "Password requirements endpoint may not be responding"
fi
if curl -sk https://localhost:${TLS_PORT}/api/config/chunking 2>/dev/null | grep -q '"plaintextChunkSizeBytes"'; then
    print_status "SUCCESS" "Chunking config endpoint responding"
else
    print_status "WARNING" "Chunking config endpoint may not be responding"
fi

print_status "INFO" "Service status:"
echo "    arkfile:   $(systemctl is-active arkfile 2>/dev/null || echo 'failed')"
echo "    rqlite:    $(systemctl is-active rqlite 2>/dev/null || echo 'unknown')"
if [ "$IS_LOCAL_SEAWEEDFS" = "true" ]; then
    echo "    seaweedfs: $(systemctl is-active seaweedfs 2>/dev/null || echo 'unknown')"
fi
echo "    storage:   ${STORAGE_DISPLAY}"

echo
echo -e "${GREEN}UPDATE COMPLETE${NC}"
echo
echo -e "${BLUE}Your Arkfile instance at https://localhost:${TLS_PORT} has been updated.${NC}"
echo "Data, keys, and configuration were not modified."
echo

exit 0
