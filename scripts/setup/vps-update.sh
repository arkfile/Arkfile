#!/bin/bash
# Shared VPS update body for prod-update.sh and test-update.sh.
# Source AFTER profile vars + build-config.sh + deploy-common.sh.
#
# Required profile variables:
#   UPDATE_KIND_LABEL       Production | Test
#   UPDATE_SCRIPT_NAME      prod-update.sh | test-update.sh
#   PRIOR_DEPLOY_SCRIPT     prod-deploy.sh | test-deploy.sh
#   CADDYFILE_TEMPLATE      Caddyfile.prod | Caddyfile.test
#   BANNER_TITLE
#   COMPLETE_TITLE
#   INSTANCE_PHRASE         e.g. "production instance" | "instance"
#   SECRETS_ENV, SCRIPT_DIR, ARKFILE_*, colors

FORCE_REBUILD_ALL="${FORCE_REBUILD_ALL:-false}"

show_help() {
    cat << EOF2
Arkfile ${UPDATE_KIND_LABEL} Update Script

Rebuilds Go binaries, TypeScript frontend, and static assets, then redeploys them
to an existing ${UPDATE_KIND_LABEL_LOWER} deployment without touching data, keys, or configuration.

Usage:
  sudo bash scripts/${UPDATE_SCRIPT_NAME} [OPTIONS]

Options:
  --force-rebuild-all    Force rebuild of C libraries (libopaque/liboprf) and WASM.
                         Use this when libopaque or liboprf source has changed.
                         By default, existing C libraries are reused (fast update).
  -h, --help             Show this help message

Requirements:
  - An existing deployment written by ${PRIOR_DEPLOY_SCRIPT}
  - /opt/arkfile/etc/secrets.env must exist and contain BASE_URL=https://<domain>
  - The repo must be checked out on the VPS at the current working directory
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
    print_status "ERROR" "Run scripts/${PRIOR_DEPLOY_SCRIPT} first to create a deployment"
    exit 1
fi

if ! systemctl list-unit-files arkfile.service >/dev/null 2>&1; then
    print_status "ERROR" "arkfile.service not found in systemd"
    print_status "ERROR" "Run scripts/${PRIOR_DEPLOY_SCRIPT} first to create a deployment"
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

# ARKFILE_DOMAIN binds the OPAQUE server identity (idS); it is REQUIRED.
# Update scripts assume a complete secrets.env and hard-fail if it is missing
# rather than silently backfilling (which could change idS out from under
# existing user records).
ARKFILE_DOMAIN_VALUE=$(read_secrets_env_value "ARKFILE_DOMAIN")
if [ -z "$ARKFILE_DOMAIN_VALUE" ]; then
    print_status "ERROR" "ARKFILE_DOMAIN is not set in $SECRETS_ENV"
    print_status "ERROR" "It is required (OPAQUE server identity). Add 'ARKFILE_DOMAIN=${DOMAIN}' and retry."
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
# Local SeaweedFS deployments use STORAGE_PROVIDER_1=generic-s3 with STORAGE_1_ENDPOINT pointing to localhost.
# External providers use non-localhost endpoints or non-generic-s3 provider names.
IS_LOCAL_SEAWEEDFS=false
if [ "$STORAGE_PROVIDER" = "generic-s3" ]; then
    S3_ENDPOINT_VALUE=$(read_secrets_env_value "STORAGE_1_ENDPOINT")
    if echo "$S3_ENDPOINT_VALUE" | grep -qE '(localhost|127\.0\.0\.1)'; then
        IS_LOCAL_SEAWEEDFS=true
    fi
fi

print_status "INFO" "Existing deployment detected for: $DOMAIN (storage: $STORAGE_DISPLAY)"
if [ -f "$ARKFILE_DIR/etc/deployed-version" ]; then
    CURRENT_VERSION=$(cat "$ARKFILE_DIR/etc/deployed-version")
    print_status "INFO" "Currently deployed version: $CURRENT_VERSION"
fi
if [ "$MULTI_BACKEND" = "true" ]; then
    print_status "INFO" "Primary role is DB-authoritative (use arkfile-admin storage-status after restart)"
fi

if ! GO_BINARY=$(find_go_binary); then
    print_status "ERROR" "Go compiler not found"
    exit 1
fi
print_status "SUCCESS" "Found Go at: $GO_BINARY"
export GO_BINARY="$GO_BINARY"

echo
echo -e "${BLUE}${BANNER_TITLE}${NC}"
echo
echo -e "${BLUE}Configuration:${NC}"
echo "  Domain:             $DOMAIN"
echo "  Storage providers:  $STORAGE_DISPLAY"
if [ "$MULTI_BACKEND" = "true" ]; then
echo "  Primary role:       DB-authoritative (check with arkfile-admin storage-status)"
fi
echo "  Force rebuild C:    $FORCE_REBUILD_ALL"
echo "  Data:               PRESERVED (not touched)"
echo "  Config/keys:        PRESERVED (not touched)"
echo
echo -e "${YELLOW}This will: rebuild binaries/frontend, stop arkfile+caddy, deploy, restart.${NC}"
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

# Always do a fresh TypeScript build
clear_frontend_build_caches
wipe_build_artifacts_preserving_c_libs_if_skipping

unset LIBOPAQUE_DEFINES

run_application_build "update-$(date +%Y%m%d-%H%M%S)" --production
verify_build_tree_artifacts
print_status "SUCCESS" "Build complete"

echo
echo -e "${CYAN}Step 2: Stop services (caddy + arkfile)${NC}"

stop_service_gracefully "caddy"
stop_service_gracefully "arkfile"

# Brief pause to ensure the binary is not in use
sleep 2

echo
echo -e "${CYAN}Step 3: Backup and deploy binaries and static assets${NC}"

backup_binaries_before_overwrite "caddy arkfile"

install_binaries_from_build
sync_static_assets_from_build

print_status "INFO" "Deploying updated systemd service files (fail closed on copy failure)..."
if [ -d "$BUILD_ROOT/systemd" ]; then
    cp "$BUILD_ROOT/systemd/arkfile.service"   /etc/systemd/system/
    cp "$BUILD_ROOT/systemd/caddy.service"     /etc/systemd/system/
    cp "$BUILD_ROOT/systemd/rqlite.service"    /etc/systemd/system/
    cp "$BUILD_ROOT/systemd/seaweedfs.service" /etc/systemd/system/
    systemctl daemon-reload
    print_status "SUCCESS" "Systemd services updated"
else
    print_status "ERROR" "No systemd directory in build, systemd service file update failed"
    exit 1
fi

sync_database_schema_from_build

print_status "INFO" "Regenerating Caddyfile from ${CADDYFILE_TEMPLATE} template..."
# Read DESEC_TOKEN from caddy-env (where ${PRIOR_DEPLOY_SCRIPT} stores it), not secrets.env
DESEC_TOKEN_VALUE=""
if [ -f /var/lib/caddy/caddy-env ]; then
    DESEC_TOKEN_VALUE=$(grep "^DESEC_TOKEN=" /var/lib/caddy/caddy-env 2>/dev/null | head -1 | cut -d'=' -f2- || true)
fi
ACME_EMAIL_VALUE=$(read_secrets_env_value "CADDY_EMAIL" 2>/dev/null || true)

repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
tmp_global=$(mktemp)

if [ -n "$ACME_EMAIL_VALUE" ]; then
    cat > "$tmp_global" <<GLOBALEOF
{
	email ${ACME_EMAIL_VALUE}

	servers {
		protocols h1 h2 h3
		strict_sni_host
	}
}
GLOBALEOF
else
    cat > "$tmp_global" <<GLOBALEOF
{
	servers {
		protocols h1 h2 h3
		strict_sni_host
	}
}
GLOBALEOF
fi

awk -v gfile="$tmp_global" '
    /\{GLOBAL_BLOCK\}/ {
        while ((getline line < gfile) > 0) print line
        close(gfile)
        next
    }
    { print }
' "$repo_root/${CADDYFILE_TEMPLATE}" | sed "s|{DOMAIN}|${DOMAIN}|g" > /etc/caddy/Caddyfile

rm -f "$tmp_global"

if [ -f /etc/caddy/Caddyfile ]; then
    print_status "INFO" "Validating Caddyfile configurations..."
    if ! DESEC_TOKEN="$DESEC_TOKEN_VALUE" /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile; then
        print_status "ERROR" "Caddyfile updated but validation failed"
        exit 1
    fi
    print_status "SUCCESS" "Caddyfile successfully updated and validated"
else
    print_status "ERROR" "Could not write /etc/caddy/Caddyfile"
    exit 1
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
if [ "$IS_LOCAL_SEAWEEDFS" = "true" ]; then
    echo "    seaweedfs: $(systemctl is-active seaweedfs 2>/dev/null || echo 'unknown')"
fi
echo "    storage:   ${STORAGE_DISPLAY}"

# Record deployed version
echo "$VERSION" > "$ARKFILE_DIR/etc/deployed-version"
chown "$ARKFILE_USER:$ARKFILE_GROUP" "$ARKFILE_DIR/etc/deployed-version"
chmod 644 "$ARKFILE_DIR/etc/deployed-version"
print_status "SUCCESS" "Deployed version: $VERSION"

echo
echo -e "${GREEN}${COMPLETE_TITLE}${NC}"
echo
echo -e "${BLUE}Your Arkfile ${INSTANCE_PHRASE} at https://${DOMAIN} has been updated.${NC}"
echo "Data, keys, and configuration were not modified."
echo

exit 0
