#!/bin/bash

# Arkfile Test Deployment Script
# First-time VPS deployment for a real domain using Caddy + Let's Encrypt + deSEC

set -e

# ensure standard locations always in path regardless of sudo stripping PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:${PATH}"

# Source shared build configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/setup/build-config.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration defaults
ARKFILE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"

DOMAIN=""
DESEC_TOKEN=""
ADMIN_USERNAME=""
STORAGE_BACKEND="local-seaweedfs"
ACME_EMAIL=""
FORCE_REBUILD_ALL=false
FORCE_REBUILD_RQLITE=false

S3_ENDPOINT=""
S3_REGION=""
S3_ACCESS_KEY=""
S3_SECRET_KEY=""
S3_BUCKET=""
S3_FORCE_PATH_STYLE="true"
BACKBLAZE_ENDPOINT=""
BACKBLAZE_KEY_ID=""
BACKBLAZE_APPLICATION_KEY=""
BACKBLAZE_BUCKET_NAME=""
CLOUDFLARE_ENDPOINT=""
CLOUDFLARE_ACCESS_KEY_ID=""
CLOUDFLARE_SECRET_ACCESS_KEY=""
CLOUDFLARE_BUCKET_NAME=""

# Preserve original user context for Go operations
ORIGINAL_USER="${SUDO_USER:-$USER}"
ORIGINAL_UID="${SUDO_UID:-$(id -u)}"
ORIGINAL_GID="${SUDO_GID:-$(id -g)}"

print_status() {
    local status="$1"
    local message="$2"

    case "$status" in
        "INFO") echo -e "  ${BLUE}INFO:${NC} ${message}" ;;
        "SUCCESS") echo -e "  ${GREEN}SUCCESS:${NC} ${message}" ;;
        "WARNING") echo -e "  ${YELLOW}WARNING:${NC} ${message}" ;;
        "ERROR") echo -e "  ${RED}ERROR:${NC} ${message}" ;;
    esac
}

show_help() {
    cat << EOF2
Arkfile Test Deployment Script

Usage:
  sudo bash scripts/test-deploy.sh --domain <domain> --desec-token <token> --admin-username <name> [OPTIONS]

Required:
  --domain <domain>             Real domain name, e.g. test.arkfile.net
  --desec-token <token>         deSEC API token for DNS-01 challenge
  --admin-username <name>       Admin username for bootstrap

Optional:
  --storage-backend <type>      Storage backend (default: local-seaweedfs)
  --acme-email <email>          ACME email for Let's Encrypt notices
  --force-rebuild-all           Force rebuild of all C libraries and rqlite
  --force-rebuild-rqlite        Force rebuild of rqlite
  -h, --help                    Show this help message
EOF2
}

run_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H "$@"
    else
        "$@"
    fi
}

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

verify_ownership() {
    local check_dir="$1"
    print_status "INFO" "Verifying directory ownership for $check_dir..."
    local root_owned=$(find "$check_dir" -user root 2>/dev/null | grep -v "^$" || true)
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

detect_os_family() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

detect_public_ip() {
    local public_ip=""
    public_ip=$(curl -fsS https://api.ipify.org 2>/dev/null || true)
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -fsS https://ifconfig.me 2>/dev/null || true)
    fi
    echo "$public_ip"
}

resolve_domain_ip() {
    local domain="$1"
    local resolved_ip=""
    if command -v dig >/dev/null 2>&1; then
        resolved_ip=$(dig +short A "$domain" | head -1)
    else
        resolved_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    echo "$resolved_ip"
}

check_port_free() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"
    else
        return 0
    fi
}

configure_firewall() {
    local os_family="$1"

    print_status "INFO" "Configuring firewall..."

    if [ "$os_family" = "rhel" ] && command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --set-default-zone=drop >/dev/null
        firewall-cmd --permanent --add-service=ssh >/dev/null
        firewall-cmd --permanent --add-service=http >/dev/null
        firewall-cmd --permanent --add-service=https >/dev/null
        firewall-cmd --reload >/dev/null
        print_status "SUCCESS" "firewalld configured for ssh/http/https only"
        return 0
    fi

    if [ "$os_family" = "debian" ] && command -v ufw >/dev/null 2>&1; then
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow 22/tcp >/dev/null
        ufw allow 80/tcp >/dev/null
        ufw allow 443/tcp >/dev/null
        ufw --force enable >/dev/null
        print_status "SUCCESS" "ufw configured for ssh/http/https only"
        return 0
    fi

    print_status "WARNING" "No supported firewall tool detected; continuing without firewall changes"
}

ensure_caddy_user_and_dirs() {
    if ! getent group caddy >/dev/null; then
        groupadd -r caddy
    fi
    if ! getent passwd caddy >/dev/null; then
        useradd -r -g caddy -d /var/lib/caddy -s /sbin/nologin -c "Caddy Service Account" caddy
    fi

    install -d -m 755 -o caddy -g caddy /var/lib/caddy
    install -d -m 755 -o caddy -g caddy /var/log/caddy
    install -d -m 755 -o root -g root /etc/caddy
}

build_application() {
    print_status "INFO" "Preparing build artifacts..."

    fix_go_ownership

    SKIP_C_LIBS=false
    if [ "$FORCE_REBUILD_ALL" = "true" ]; then
        print_status "INFO" "--force-rebuild-all: deleting entire build directory"
        rm -rf "$BUILD_ROOT"
    elif c_libs_exist; then
        SKIP_C_LIBS=true
        print_status "INFO" "Found existing C libraries, will skip rebuild"
    fi

    unset LIBOPAQUE_DEFINES
    print_status "INFO" "WASM trace logging disabled for test deployment"

    rm -f client/static/js/.buildcache
    rm -rf client/static/js/dist/*

    if [ -d "$BUILD_ROOT" ]; then
        if [ "$SKIP_C_LIBS" = "true" ]; then
            rm -rf "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT" 2>/dev/null || true
            rm -f "$BUILD_ROOT/version.json" 2>/dev/null || true
        else
            rm -rf "$BUILD_ROOT"
        fi
    fi

    export VERSION="test-$(date +%Y%m%d-%H%M%S)"
    export SKIP_C_LIBS="$SKIP_C_LIBS"

    fix_go_ownership
    if ! run_as_user ./scripts/setup/build.sh --build-only; then
        print_status "ERROR" "Build failed"
        exit 1
    fi
    fix_go_ownership
    print_status "SUCCESS" "Application build complete"
}

deploy_build_artifacts() {
    print_status "INFO" "Deploying build artifacts..."
    if ! ./scripts/setup/deploy.sh; then
        print_status "ERROR" "Deployment failed"
        exit 1
    fi

    [ -x "$ARKFILE_DIR/bin/arkfile" ] || { print_status "ERROR" "arkfile binary missing"; exit 1; }
    [ -x "$ARKFILE_DIR/bin/arkfile-client" ] || { print_status "ERROR" "arkfile-client binary missing"; exit 1; }
    [ -x "$ARKFILE_DIR/bin/arkfile-admin" ] || { print_status "ERROR" "arkfile-admin binary missing"; exit 1; }
    [ -f "$ARKFILE_DIR/client/static/js/dist/app.js" ] || { print_status "ERROR" "TypeScript bundle missing"; exit 1; }
    [ -f "$ARKFILE_DIR/client/static/js/libopaque.js" ] || { print_status "ERROR" "libopaque.js missing"; exit 1; }

    print_status "SUCCESS" "Build artifacts deployed and verified"
}

write_test_configuration() {
    local rqlite_password="$1"
    local s3_password="$2"

    print_status "INFO" "Writing deployment configuration..."

    cat > "$ARKFILE_DIR/etc/secrets.env" <<EOF2
# Test Deployment Configuration
# Generated: $(date)
# Domain: ${DOMAIN}

# Database Configuration
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
RQLITE_USERNAME=test-user
RQLITE_PASSWORD=${rqlite_password}

# Arkfile Application Configuration
PORT=8080
CORS_ALLOWED_ORIGINS=https://${DOMAIN}

# TLS Configuration
TLS_ENABLED=true
TLS_PORT=8443
TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.crt
TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.key

EOF2

    case "$STORAGE_BACKEND" in
        local-seaweedfs)
            cat >> "$ARKFILE_DIR/etc/secrets.env" <<EOF2
# Storage Configuration
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=http://localhost:9332
S3_ACCESS_KEY=arkfile-test
S3_SECRET_KEY=${s3_password}
S3_BUCKET=arkfile-test
S3_REGION=us-east-1
S3_FORCE_PATH_STYLE=true

EOF2

            cat > "$ARKFILE_DIR/etc/seaweedfs-s3.json" <<EOF2
{
  "identities": [
    {
      "name": "arkfile",
      "credentials": [
        {
          "accessKey": "arkfile-test",
          "secretKey": "${s3_password}"
        }
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF2
            chown "$USER:$GROUP" "$ARKFILE_DIR/etc/seaweedfs-s3.json"
            chmod 640 "$ARKFILE_DIR/etc/seaweedfs-s3.json"
            ;;
        wasabi|vultr|aws-s3)
            cat >> "$ARKFILE_DIR/etc/secrets.env" <<EOF2
# Storage Configuration
STORAGE_PROVIDER=${STORAGE_BACKEND}
S3_REGION=${S3_REGION}
S3_ACCESS_KEY=${S3_ACCESS_KEY}
S3_SECRET_KEY=${S3_SECRET_KEY}
S3_BUCKET=${S3_BUCKET}

EOF2
            ;;
        backblaze)
            cat >> "$ARKFILE_DIR/etc/secrets.env" <<EOF2
# Storage Configuration
STORAGE_PROVIDER=backblaze
BACKBLAZE_ENDPOINT=${BACKBLAZE_ENDPOINT}
BACKBLAZE_KEY_ID=${BACKBLAZE_KEY_ID}
BACKBLAZE_APPLICATION_KEY=${BACKBLAZE_APPLICATION_KEY}
BACKBLAZE_BUCKET_NAME=${BACKBLAZE_BUCKET_NAME}

EOF2
            ;;
        cloudflare-r2)
            cat >> "$ARKFILE_DIR/etc/secrets.env" <<EOF2
# Storage Configuration
STORAGE_PROVIDER=cloudflare-r2
CLOUDFLARE_ENDPOINT=${CLOUDFLARE_ENDPOINT}
CLOUDFLARE_ACCESS_KEY_ID=${CLOUDFLARE_ACCESS_KEY_ID}
CLOUDFLARE_SECRET_ACCESS_KEY=${CLOUDFLARE_SECRET_ACCESS_KEY}
CLOUDFLARE_BUCKET_NAME=${CLOUDFLARE_BUCKET_NAME}

EOF2
            ;;
        generic-s3)
            cat >> "$ARKFILE_DIR/etc/secrets.env" <<EOF2
# Storage Configuration
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=${S3_ENDPOINT}
S3_REGION=${S3_REGION}
S3_ACCESS_KEY=${S3_ACCESS_KEY}
S3_SECRET_KEY=${S3_SECRET_KEY}
S3_BUCKET=${S3_BUCKET}
S3_FORCE_PATH_STYLE=${S3_FORCE_PATH_STYLE}

EOF2
            ;;
    esac

    cat >> "$ARKFILE_DIR/etc/secrets.env" <<EOF2
# Admin Configuration
ADMIN_USERNAMES=${ADMIN_USERNAME}

# Bootstrap mode
ARKFILE_FORCE_ADMIN_BOOTSTRAP=true

# Security settings
ADMIN_DEV_TEST_API_ENABLED=false
REQUIRE_APPROVAL=true
ENABLE_REGISTRATION=true
DEBUG_MODE=false
LOG_LEVEL=info
EOF2

    chown "$USER:$GROUP" "$ARKFILE_DIR/etc/secrets.env"
    chmod 640 "$ARKFILE_DIR/etc/secrets.env"

    cat > "$ARKFILE_DIR/etc/rqlite-auth.json" <<EOF2
[
  {
    "username": "test-user",
    "password": "${rqlite_password}",
    "perms": ["all"]
  }
]
EOF2
    chown "$USER:$GROUP" "$ARKFILE_DIR/etc/rqlite-auth.json"
    chmod 640 "$ARKFILE_DIR/etc/rqlite-auth.json"

    print_status "SUCCESS" "Configuration files written"
}

generate_crypto_material() {
    print_status "INFO" "Generating master key..."
    ./scripts/setup/03-setup-master-key.sh
    print_status "INFO" "Generating internal TLS certificates..."
    ./scripts/setup/04-setup-tls-certs.sh
    chown -R "$USER:$GROUP" "$ARKFILE_DIR"
    chmod 700 "$ARKFILE_DIR/etc/keys"
    [ -d "$ARKFILE_DIR/etc/keys/tls" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls"
    verify_ownership "$ARKFILE_DIR"
    print_status "SUCCESS" "Cryptographic material ready"
}

verify_storage_backend_roundtrip() {
    if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
        return 0
    fi

    print_status "INFO" "Verifying external storage backend with arkfile-admin verify-storage..."
    if ! "$ARKFILE_DIR/bin/arkfile-admin" verify-storage --secrets-env "$ARKFILE_DIR/etc/secrets.env"; then
        print_status "ERROR" "External storage verification failed"
        exit 1
    fi
    print_status "SUCCESS" "External storage backend verification passed"
}

render_caddyfile() {
    local email_line=""
    if [ -n "$ACME_EMAIL" ]; then
        email_line="email ${ACME_EMAIL}"
    fi

    local repo_root
    repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"

    sed \
        -e "s|{DOMAIN}|${DOMAIN}|g" \
        -e "s|{EMAIL_LINE}|${email_line}|g" \
        "$repo_root/Caddyfile.test" > /etc/caddy/Caddyfile
}

build_and_install_caddy() {
    print_status "INFO" "Installing xcaddy build tool..."
    if ! run_as_user "$GO_BINARY" install github.com/caddyserver/xcaddy/cmd/xcaddy@latest; then
        print_status "ERROR" "Failed to install xcaddy"
        exit 1
    fi

    local xcaddy_bin=""
    if [ -n "$SUDO_USER" ] && [ -x "/home/$SUDO_USER/go/bin/xcaddy" ]; then
        xcaddy_bin="/home/$SUDO_USER/go/bin/xcaddy"
    elif [ -x "/root/go/bin/xcaddy" ]; then
        xcaddy_bin="/root/go/bin/xcaddy"
    elif command -v xcaddy >/dev/null 2>&1; then
        xcaddy_bin="$(command -v xcaddy)"
    else
        print_status "ERROR" "xcaddy binary not found after installation"
        exit 1
    fi

    print_status "INFO" "Building Caddy with deSEC module..."
    rm -f caddy 2>/dev/null || true
    if ! run_as_user env PATH="$PATH" "$xcaddy_bin" build --with github.com/caddy-dns/desec; then
        print_status "ERROR" "Failed to build Caddy"
        exit 1
    fi

    install -m 755 caddy /usr/local/bin/caddy
    rm -f caddy
    print_status "SUCCESS" "Custom Caddy installed at /usr/local/bin/caddy"
}

configure_caddy() {
    ensure_caddy_user_and_dirs
    render_caddyfile

    cat > "$ARKFILE_DIR/etc/caddy-env" <<EOF2
DESEC_TOKEN=${DESEC_TOKEN}
EOF2
    chown caddy:arkfile "$ARKFILE_DIR/etc/caddy-env"
    chmod 640 "$ARKFILE_DIR/etc/caddy-env"

    if command -v getenforce >/dev/null 2>&1; then
        SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Disabled")
        if [ "$SELINUX_STATUS" = "Enforcing" ]; then
            print_status "INFO" "Applying SELinux settings for Caddy..."
            setsebool -P httpd_can_network_connect 1 || true
            if command -v semanage >/dev/null 2>&1; then
                semanage fcontext -a -t httpd_config_t "/etc/caddy(/.*)?" 2>/dev/null || true
                semanage fcontext -a -t httpd_var_lib_t "/var/lib/caddy(/.*)?" 2>/dev/null || true
                semanage fcontext -a -t httpd_log_t "/var/log/caddy(/.*)?" 2>/dev/null || true
                semanage fcontext -a -t httpd_exec_t "/usr/local/bin/caddy" 2>/dev/null || true
            fi
            restorecon -R /etc/caddy /var/lib/caddy /var/log/caddy 2>/dev/null || true
            restorecon /usr/local/bin/caddy 2>/dev/null || true
        fi
    fi

    if ! DESEC_TOKEN="$DESEC_TOKEN" /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile; then
        print_status "ERROR" "Caddyfile validation failed"
        exit 1
    fi

    print_status "SUCCESS" "Caddy configuration ready"
}

setup_storage_services() {
    if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
        print_status "INFO" "Setting up local SeaweedFS..."
        ./scripts/setup/05-setup-seaweedfs.sh
    fi

    print_status "INFO" "Setting up rqlite..."
    local rqlite_args=""
    if [ "$FORCE_REBUILD_RQLITE" = "true" ]; then
        rqlite_args="--force"
    fi
    ./scripts/setup/06-setup-rqlite-build.sh $rqlite_args
}

start_and_verify_services() {
    systemctl daemon-reload

    if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
        print_status "INFO" "Starting SeaweedFS..."
        systemctl enable seaweedfs
        systemctl start seaweedfs
        local swfs_ready=false
        for _ in $(seq 1 20); do
            if curl -s http://localhost:9332/status >/dev/null 2>&1; then
                swfs_ready=true
                break
            fi
            sleep 2
        done
        if [ "$swfs_ready" != "true" ]; then
            print_status "ERROR" "SeaweedFS S3 gateway failed to respond within timeout"
            print_status "ERROR" "Check logs: sudo journalctl -u seaweedfs -f"
            exit 1
        fi
        print_status "SUCCESS" "SeaweedFS S3 gateway ready"
    fi

    print_status "INFO" "Starting rqlite..."
    systemctl enable rqlite
    systemctl start rqlite
    local rqlite_ready=false
    for _ in $(seq 1 30); do
        if curl -u "test-user:${RQLITE_PASSWORD}" http://localhost:4001/status 2>/dev/null | grep -q '"ready":true'; then
            rqlite_ready=true
            break
        fi
        sleep 2
    done
    if [ "$rqlite_ready" != "true" ]; then
        print_status "ERROR" "rqlite failed to become ready within timeout"
        print_status "ERROR" "Check logs: sudo journalctl -u rqlite -f"
        exit 1
    fi
    print_status "SUCCESS" "rqlite is ready"

    print_status "INFO" "Starting Arkfile..."
    systemctl enable arkfile
    systemctl start arkfile
    local arkfile_ready=false
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

    print_status "INFO" "Starting Caddy (DNS-01 cert acquisition may take 30-60s)..."
    systemctl enable caddy
    systemctl start caddy
    local caddy_ready=false
    for _ in $(seq 1 30); do
        if curl -sk "https://${DOMAIN}/readyz" 2>/dev/null | grep -q '"status":"ready"'; then
            caddy_ready=true
            break
        fi
        sleep 3
    done
    if [ "$caddy_ready" != "true" ]; then
        print_status "ERROR" "Timed out waiting for public HTTPS endpoint"
        print_status "ERROR" "Check logs: sudo journalctl -u caddy -f"
        exit 1
    fi
    print_status "SUCCESS" "Public HTTPS endpoint is ready at https://${DOMAIN}"
}

prompt_nonempty() {
    local prompt_text="$1"
    local value=""
    while true; do
        read -r -p "$prompt_text" value
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        fi
        print_status "WARNING" "A value is required"
    done
}

prompt_secret_nonempty() {
    local prompt_text="$1"
    local value=""
    while true; do
        read -r -s -p "$prompt_text" value
        echo
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        fi
        print_status "WARNING" "A value is required"
    done
}

prompt_storage_backend_config() {
    case "$STORAGE_BACKEND" in
        local-seaweedfs)
            print_status "INFO" "Using local SeaweedFS backend"
            ;;
        wasabi)
            S3_REGION=$(prompt_nonempty "Wasabi region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "Wasabi access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "Wasabi secret key: ")
            S3_BUCKET=$(prompt_nonempty "Wasabi bucket name: ")
            ;;
        backblaze)
            BACKBLAZE_ENDPOINT=$(prompt_nonempty "Backblaze endpoint: ")
            BACKBLAZE_KEY_ID=$(prompt_nonempty "Backblaze key ID: ")
            BACKBLAZE_APPLICATION_KEY=$(prompt_secret_nonempty "Backblaze application key: ")
            BACKBLAZE_BUCKET_NAME=$(prompt_nonempty "Backblaze bucket name: ")
            ;;
        vultr)
            S3_REGION=$(prompt_nonempty "Vultr region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "Vultr access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "Vultr secret key: ")
            S3_BUCKET=$(prompt_nonempty "Vultr bucket name: ")
            ;;
        cloudflare-r2)
            CLOUDFLARE_ENDPOINT=$(prompt_nonempty "Cloudflare R2 endpoint: ")
            CLOUDFLARE_ACCESS_KEY_ID=$(prompt_nonempty "Cloudflare R2 access key ID: ")
            CLOUDFLARE_SECRET_ACCESS_KEY=$(prompt_secret_nonempty "Cloudflare R2 secret access key: ")
            CLOUDFLARE_BUCKET_NAME=$(prompt_nonempty "Cloudflare R2 bucket name: ")
            ;;
        aws-s3)
            S3_REGION=$(prompt_nonempty "AWS region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "AWS access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "AWS secret key: ")
            S3_BUCKET=$(prompt_nonempty "AWS bucket name: ")
            ;;
        generic-s3)
            S3_ENDPOINT=$(prompt_nonempty "S3 endpoint URL: ")
            S3_REGION=$(prompt_nonempty "S3 region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "S3 access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "S3 secret key: ")
            S3_BUCKET=$(prompt_nonempty "S3 bucket name: ")
            read -r -p "Force path style? [Y/n]: " force_path_style
            if [[ "$force_path_style" =~ ^[Nn]$ ]]; then
                S3_FORCE_PATH_STYLE="false"
            fi
            ;;
        *)
            print_status "ERROR" "Unsupported storage backend: $STORAGE_BACKEND"
            exit 1
            ;;
    esac
}

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
    if ! echo "$username" | grep -qE '^[a-zA-Z0-9_.,-]{10,50}$'; then
        echo "ERROR: Username can only contain letters, numbers, underscores, hyphens, periods, and commas"
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
        local-seaweedfs|wasabi|backblaze|vultr|cloudflare-r2|aws-s3|generic-s3)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --desec-token)
            DESEC_TOKEN="$2"
            shift 2
            ;;
        --admin-username)
            ADMIN_USERNAME="$2"
            shift 2
            ;;
        --storage-backend)
            STORAGE_BACKEND="$2"
            shift 2
            ;;
        --acme-email)
            ACME_EMAIL="$2"
            shift 2
            ;;
        --force-rebuild-all)
            FORCE_REBUILD_ALL=true
            FORCE_REBUILD_RQLITE=true
            shift
            ;;
        --force-rebuild-rqlite)
            FORCE_REBUILD_RQLITE=true
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

if [ -z "$DOMAIN" ] || [ -z "$DESEC_TOKEN" ] || [ -z "$ADMIN_USERNAME" ]; then
    print_status "ERROR" "--domain, --desec-token, and --admin-username are required"
    show_help
    exit 1
fi

if ! validate_username "$ADMIN_USERNAME"; then
    echo
    echo "Username requirements: 10-50 characters, letters/numbers/underscore/hyphen/period/comma"
    echo "Cannot start or end with special characters, no consecutive special characters"
    exit 1
fi

if ! validate_storage_backend "$STORAGE_BACKEND"; then
    print_status "ERROR" "Unsupported storage backend: $STORAGE_BACKEND"
    echo "Supported backends: local-seaweedfs, wasabi, backblaze, vultr, cloudflare-r2, aws-s3, generic-s3"
    exit 1
fi

echo -e "${CYAN}Step 0: Pre-flight checks${NC}"
echo "=========================="

echo -e "${YELLOW}Detecting Go installation...${NC}"
if ! GO_BINARY=$(find_go_binary); then
    print_status "ERROR" "Go compiler not found in standard locations"
    echo "   Checked: PATH, /usr/bin/go, /usr/local/bin/go, /usr/local/go/bin/go"
    exit 1
fi
print_status "SUCCESS" "Found Go at: $GO_BINARY"
export GO_BINARY="$GO_BINARY"

OS_FAMILY=$(detect_os_family)
print_status "INFO" "Detected OS family: $OS_FAMILY"

print_status "INFO" "Checking system dependencies..."
MISSING_DEPS=""
for cmd in gcc make cmake pkg-config git openssl curl bun; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_DEPS="$MISSING_DEPS $cmd"
    fi
done

if ! pkg-config --exists libsodium 2>/dev/null; then
    if [ "$OS_FAMILY" = "debian" ]; then
        MISSING_DEPS="$MISSING_DEPS libsodium-dev"
    else
        MISSING_DEPS="$MISSING_DEPS libsodium-devel"
    fi
fi

if [ -n "$MISSING_DEPS" ]; then
    print_status "ERROR" "Missing required dependencies:$MISSING_DEPS"
    exit 1
fi
print_status "SUCCESS" "All required dependencies found"

PUBLIC_IP=$(detect_public_ip)
if [ -z "$PUBLIC_IP" ]; then
    print_status "ERROR" "Failed to detect this VPS public IP"
    exit 1
fi
print_status "INFO" "Detected public IP: $PUBLIC_IP"

DOMAIN_IP=$(resolve_domain_ip "$DOMAIN")
if [ -z "$DOMAIN_IP" ]; then
    print_status "ERROR" "Failed to resolve A record for $DOMAIN"
    exit 1
fi
print_status "INFO" "Resolved $DOMAIN to: $DOMAIN_IP"

if [ "$PUBLIC_IP" != "$DOMAIN_IP" ]; then
    print_status "ERROR" "DNS mismatch: $DOMAIN resolves to $DOMAIN_IP but this VPS public IP is $PUBLIC_IP"
    exit 1
fi
print_status "SUCCESS" "DNS A record matches this VPS public IP"

if ! check_port_free 80; then
    print_status "WARNING" "Port 80 appears to already be in use"
fi
if ! check_port_free 443; then
    print_status "WARNING" "Port 443 appears to already be in use"
fi

EXISTING_DEPLOYMENT=false
if [ -f "$ARKFILE_DIR/etc/secrets.env" ]; then
    EXISTING_DEPLOYMENT=true
fi
if systemctl is-active --quiet arkfile 2>/dev/null; then
    EXISTING_DEPLOYMENT=true
fi

if [ "$EXISTING_DEPLOYMENT" = "true" ]; then
    echo
    echo -e "${YELLOW}WARNING: An existing Arkfile deployment was detected.${NC}"
    echo -e "${YELLOW}This script is intended for first-time deployment.${NC}"
    echo
    echo "  To update an existing deployment, use a future test-update.sh"
    echo "  To restart services: sudo systemctl restart arkfile"
    echo
    echo -e "${RED}To wipe and reinstall, type REINSTALL:${NC}"
    read -p "> " -r
    if [[ $REPLY != "REINSTALL" ]]; then
        echo "Cancelled. Nothing was changed."
        exit 0
    fi

    echo
    echo -e "${RED}Wiping existing deployment...${NC}"

    stop_service_if_running "caddy"
    stop_service_if_running "arkfile"
    stop_service_if_running "seaweedfs"
    stop_service_if_running "rqlite"

    pkill -f "/opt/arkfile/bin/arkfile" 2>/dev/null || true
    pkill -f "weed " 2>/dev/null || true
    pkill -f "rqlited " 2>/dev/null || true
    pkill -f "/usr/local/bin/caddy" 2>/dev/null || true
    sleep 2

    if [ -d "$ARKFILE_DIR" ]; then
        rm -rf "$ARKFILE_DIR/var/lib/seaweedfs/data"/* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/var/lib/"*/storage/* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/var/lib/"*/rqlite/* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/var/lib/database/data"* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/var/lib/"*/database/* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/database"* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/var/log/"* 2>/dev/null || true
        rm -f "$ARKFILE_DIR/etc/secrets.env" 2>/dev/null || true
        rm -f "$ARKFILE_DIR/etc/rqlite-auth.json" 2>/dev/null || true
        rm -f "$ARKFILE_DIR/etc/seaweedfs-s3.json" 2>/dev/null || true
        rm -f "$ARKFILE_DIR/etc/caddy-env" 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/etc/keys/jwt"* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/etc/keys/opaque"* 2>/dev/null || true
        rm -f "$ARKFILE_DIR/etc/keys/totp_master.key" 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/etc/keys/tls"* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/client/static/js/dist"* 2>/dev/null || true
    fi

    rm -f /etc/caddy/Caddyfile 2>/dev/null || true
    print_status "SUCCESS" "Existing deployment wiped"
fi

echo
echo -e "${CYAN}Step 0a: Storage backend configuration${NC}"
echo "====================================="
prompt_storage_backend_config

echo
echo -e "${BLUE}ARKFILE TEST DEPLOYMENT${NC}"
echo
echo -e "${BLUE}Configuration:${NC}"
echo "  Domain:           $DOMAIN"
echo "  Admin username:   $ADMIN_USERNAME"
echo "  Storage backend:  $STORAGE_BACKEND"
if [ -n "$ACME_EMAIL" ]; then
    echo "  ACME email:       $ACME_EMAIL"
else
    echo "  ACME email:       (not set)"
fi
echo "  Public IP:        $PUBLIC_IP"
echo
read -p "Type DEPLOY to proceed (anything else cancels): " -r
if [[ $REPLY != "DEPLOY" ]]; then
    echo "Cancelled. Nothing was changed."
    exit 0
fi

echo
echo -e "${CYAN}Step 1: Firewall configuration${NC}"
echo "=============================="
configure_firewall "$OS_FAMILY"

echo
echo -e "${CYAN}Step 2: System users and directories${NC}"
echo "===================================="
./scripts/setup/01-setup-users.sh
./scripts/setup/02-setup-directories.sh
ensure_caddy_user_and_dirs

echo
echo -e "${CYAN}Step 3: Build application${NC}"
echo "========================="
build_application

echo
echo -e "${CYAN}Step 4: Deploy build artifacts and set ownership${NC}"
echo "================================================="
deploy_build_artifacts

chown -R "$USER:$GROUP" "$ARKFILE_DIR"
chmod 700 "$ARKFILE_DIR/etc/keys"
[ -d "$ARKFILE_DIR/etc/keys/jwt" ] && chmod 700 "$ARKFILE_DIR/etc/keys/jwt"
[ -d "$ARKFILE_DIR/etc/keys/jwt/current" ] && chmod 700 "$ARKFILE_DIR/etc/keys/jwt/current"
[ -d "$ARKFILE_DIR/etc/keys/jwt/backup" ] && chmod 700 "$ARKFILE_DIR/etc/keys/jwt/backup"
[ -d "$ARKFILE_DIR/etc/keys/opaque" ] && chmod 700 "$ARKFILE_DIR/etc/keys/opaque"
[ -d "$ARKFILE_DIR/etc/keys/tls" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls"
[ -d "$ARKFILE_DIR/etc/keys/tls/ca" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls/ca"
[ -d "$ARKFILE_DIR/etc/keys/tls/arkfile" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls/arkfile"
[ -d "$ARKFILE_DIR/etc/keys/tls/rqlite" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls/rqlite"
[ -d "$ARKFILE_DIR/etc/keys/tls/seaweedfs" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls/seaweedfs"
[ -d "$ARKFILE_DIR/etc/keys/backups" ] && chmod 700 "$ARKFILE_DIR/etc/keys/backups"
[ -d "$ARKFILE_DIR/etc/keys/totp" ] && chmod 700 "$ARKFILE_DIR/etc/keys/totp"

mkdir -p "$ARKFILE_DIR/var/log"
chown "$USER:$GROUP" "$ARKFILE_DIR/var/log"
chmod 775 "$ARKFILE_DIR/var/log"
print_status "SUCCESS" "Ownership and permissions set"

echo
echo -e "${CYAN}Step 5: Write configuration and secrets${NC}"
echo "======================================="
RQLITE_PASSWORD="$(openssl rand -hex 16)"
if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
    S3_PASSWORD="$(openssl rand -hex 16)"
else
    S3_PASSWORD=""
fi
write_test_configuration "$RQLITE_PASSWORD" "$S3_PASSWORD"

echo
echo -e "${CYAN}Step 6: Generate cryptographic material${NC}"
echo "========================================"
generate_crypto_material

echo
echo -e "${CYAN}Step 7: Verify external storage if needed${NC}"
echo "========================================="
verify_storage_backend_roundtrip

echo
echo -e "${CYAN}Step 8: Setup storage services${NC}"
echo "=============================="
setup_storage_services

echo
echo -e "${CYAN}Step 9: Build and configure Caddy${NC}"
echo "================================="
build_and_install_caddy
configure_caddy

echo
echo -e "${CYAN}Step 10: Start and verify services${NC}"
echo "=================================="
start_and_verify_services

echo
echo -e "${CYAN}Step 11: Health verification${NC}"
echo "============================="

print_status "INFO" "Testing configuration API endpoints..."
if curl -sk https://localhost:8443/api/config/argon2 2>/dev/null | grep -q '"memoryCostKiB"'; then
    print_status "SUCCESS" "Argon2 config endpoint responding"
else
    print_status "WARNING" "Argon2 config endpoint may not be working"
fi
if curl -sk https://localhost:8443/api/config/password-requirements 2>/dev/null | grep -q '"minAccountPasswordLength"'; then
    print_status "SUCCESS" "Password requirements endpoint responding"
else
    print_status "WARNING" "Password requirements endpoint may not be working"
fi
if curl -sk https://localhost:8443/api/config/chunking 2>/dev/null | grep -q '"plaintextChunkSizeBytes"'; then
    print_status "SUCCESS" "Chunking config endpoint responding"
else
    print_status "WARNING" "Chunking config endpoint may not be working"
fi

print_status "INFO" "Service status:"
seaweedfs_status="skipped"
if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
    seaweedfs_status=$(systemctl is-active seaweedfs 2>/dev/null || echo "failed")
fi
rqlite_status=$(systemctl is-active rqlite 2>/dev/null || echo "failed")
arkfile_status=$(systemctl is-active arkfile 2>/dev/null || echo "failed")
caddy_status=$(systemctl is-active caddy 2>/dev/null || echo "failed")

echo "    SeaweedFS: ${seaweedfs_status}"
echo "    rqlite:    ${rqlite_status}"
echo "    Arkfile:   ${arkfile_status}"
echo "    Caddy:     ${caddy_status}"

if ! verify_ownership "$ARKFILE_DIR"; then
    print_status "WARNING" "Some files may have incorrect ownership"
else
    print_status "SUCCESS" "All ownership checks passed"
fi

echo
echo -e "${GREEN}TEST DEPLOYMENT COMPLETE${NC}"
echo
echo -e "${BLUE}Your Arkfile test instance is running at:${NC}"
echo -e "${GREEN}  HTTPS: https://${DOMAIN}${NC}"
echo
echo -e "${YELLOW}NEXT: Bootstrap your admin account${NC}"
echo
echo "  1. Check Arkfile logs for the bootstrap token:"
echo "     sudo journalctl -u arkfile --no-pager -n 250 | grep BOOTSTRAP"
echo
echo "  2. Bootstrap the admin account:"
echo "     /opt/arkfile/bin/arkfile-admin \\
       --server-url https://localhost:8443 --tls-insecure \\
       bootstrap --token <BOOTSTRAP_TOKEN> --username ${ADMIN_USERNAME}"
echo
echo "  3. Setup TOTP:"
echo "     /opt/arkfile/bin/arkfile-admin \\
       --server-url https://localhost:8443 --tls-insecure \\
       setup-totp"
echo
echo "  4. Verify admin login:"
echo "     /opt/arkfile/bin/arkfile-admin \\"
echo "       --server-url https://localhost:8443 --tls-insecure \\"
echo "       login --username ${ADMIN_USERNAME}"
echo
echo "  5. After successful admin login, disable force bootstrap:"
echo "     - Edit /opt/arkfile/etc/secrets.env"
echo "     - Set ARKFILE_FORCE_ADMIN_BOOTSTRAP=false"
echo "     - Restart: sudo systemctl restart arkfile"
echo
echo -e "${BLUE}Useful commands:${NC}"
echo "  View arkfile logs: sudo journalctl -u arkfile -f"
echo "  View caddy logs:   sudo journalctl -u caddy -f"
echo "  Restart all:       sudo systemctl restart caddy arkfile rqlite"
if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
    echo "  Restart SeaweedFS: sudo systemctl restart seaweedfs"
fi
echo

exit 0
