#!/bin/bash

# Arkfile Local/LAN Deployment Script
# First-time constructive deployment for local machines and LANs
# Uses self-signed TLS, admin bootstrap flow, no Caddy
# See docs/wip/local-deploy.md for full design document

set -e

# Ensure standard tool locations are in PATH regardless of sudo stripping it
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:${PATH}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31mERROR: This script must be run with sudo privileges\033[0m"
    echo "Usage: sudo bash scripts/local-deploy.sh --admin-username <name> [OPTIONS]"
    exit 1
fi

# Defaults
ADMIN_USERNAME=""
ADMIN_CONTACT=""
FORCE_REBUILD_ALL=false
FORCE_REBUILD_RQLITE=false
BIND_ADDRESS="0.0.0.0"
TLS_PORT="8443"
HTTP_PORT="8080"
ADD_IPS=()
STORAGE_BACKEND="local-seaweedfs"
S3_FORCE_PATH_STYLE="true"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --admin-username)
            ADMIN_USERNAME="$2"
            shift 2
            ;;
        --admin-contact)
            ADMIN_CONTACT="$2"
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
        --bind-address)
            BIND_ADDRESS="$2"
            shift 2
            ;;
        --tls-port)
            TLS_PORT="$2"
            shift 2
            ;;
        --http-port)
            HTTP_PORT="$2"
            shift 2
            ;;
        --add-ip)
            ADD_IPS+=("$2")
            shift 2
            ;;
        --storage-backend)
            STORAGE_BACKEND="$2"
            shift 2
            ;;
        -h|--help)
            echo "Arkfile Local/LAN Deployment Script"
            echo ""
            echo "Usage: sudo bash scripts/local-deploy.sh --admin-username <name> [OPTIONS]"
            echo ""
            echo "Required:"
            echo "  --admin-username <name>       Admin username for bootstrap"
            echo ""
            echo "Optional:"
            echo "  --admin-contact <email>       Admin contact email shown to pending users (recommended)"
            echo "  --force-rebuild-all           Force rebuild of ALL C libraries"
            echo "  --force-rebuild-rqlite        Force rebuild of rqlite"
            echo "  --bind-address <ip>           IP address to bind to (default: 0.0.0.0)"
            echo "  --tls-port <port>             TLS port (default: 8443)"
            echo "  --http-port <port>            HTTP port (default: 8080)"
            echo "  --add-ip <ip>                 Additional IP for TLS cert SANs (repeatable, e.g. VPS public IP, LAN IP)"
            echo "  --storage-backend <type>      Storage backend (default: local-seaweedfs)"
            echo "                                Options: local-seaweedfs, wasabi, backblaze, vultr,"
            echo "                                         cloudflare-r2, aws-s3, generic-s3"
            echo "  -h, --help                    Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: sudo bash scripts/local-deploy.sh --admin-username <name> [OPTIONS]"
            exit 1
            ;;
    esac
done

# Validate --admin-username is provided
if [ -z "$ADMIN_USERNAME" ]; then
    echo -e "\033[0;31mERROR: --admin-username is required\033[0m"
    echo "Usage: sudo bash scripts/local-deploy.sh --admin-username <name> [OPTIONS]"
    exit 1
fi

# Username validation (mirrors Go validator in utils/username_validator.go)
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
    # Cannot start or end with special characters
    if echo "$username" | grep -qE '^[-_.,]'; then
        echo "ERROR: Username cannot start with a special character"
        return 1
    fi
    if echo "$username" | grep -qE '[-_.,]$'; then
        echo "ERROR: Username cannot end with a special character"
        return 1
    fi
    # No consecutive special characters
    if echo "$username" | grep -qE '\.\.|--|__|,,'; then
        echo "ERROR: Username cannot contain consecutive special characters"
        return 1
    fi
    return 0
}

if ! validate_username "$ADMIN_USERNAME"; then
    echo ""
    echo "Username requirements: 10-50 characters, letters/numbers/underscore/hyphen/period/comma"
    echo "Cannot start or end with special characters, no consecutive special characters"
    exit 1
fi

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

# Configuration
ARKFILE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"

# Preserve original user context for Go operations
ORIGINAL_USER="${SUDO_USER:-$USER}"
ORIGINAL_UID="${SUDO_UID:-$(id -u)}"
ORIGINAL_GID="${SUDO_GID:-$(id -g)}"

# Helper: print status messages
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")    echo -e "  ${BLUE}INFO:${NC} ${message}" ;;
        "SUCCESS") echo -e "  ${GREEN}SUCCESS:${NC} ${message}" ;;
        "WARNING") echo -e "  ${YELLOW}WARNING:${NC} ${message}" ;;
        "ERROR")   echo -e "  ${RED}ERROR:${NC} ${message}" ;;
    esac
}

# Helper: verify no root-owned files in a directory
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

# Helper: run commands as original user (not root)
run_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H "$@"
    else
        "$@"
    fi
}

# Helper: fix Go file ownership (verbose wrapper)
fix_go_ownership() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        print_status "INFO" "Fixing Go file ownership for user $SUDO_USER..."
        chown -R "$SUDO_USER:$SUDO_USER" go.mod go.sum 2>/dev/null || true
        [ -d "vendor" ] && chown -R "$SUDO_USER:$SUDO_USER" vendor/ 2>/dev/null || true
        [ -f ".vendor_cache" ] && chown "$SUDO_USER:$SUDO_USER" .vendor_cache 2>/dev/null || true
        [ -d "$BUILD_ROOT" ] && chown -R "$SUDO_USER:$SUDO_USER" "$BUILD_ROOT/" 2>/dev/null || true
        print_status "SUCCESS" "Go file ownership restored"
    fi
}

# Helper: safely stop a service if running
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

# Helper: detect LAN IP address
# Prefers a private RFC 1918 IP (192.168.x.x, 10.x.x.x, 172.16-31.x.x) on a
# physical interface (eth*, enp*, wlan*, wlp*), skipping VPN/tunnel interfaces
# (wg*, tun*, tap*) which can mislead ip-route-based detection.
detect_lan_ip() {
    local lan_ip=""

    # Method 1: Look for a private IP on a physical network interface
    # Parse 'ip -4 addr' for interfaces that look like physical ethernet or wifi
    lan_ip=$(ip -4 addr show 2>/dev/null \
        | awk '/^[0-9]+:/ { iface=$2; gsub(/:/, "", iface) }
               /inet / {
                   # Skip loopback, VPN/tunnel interfaces
                   if (iface ~ /^(lo|wg|tun|tap|veth|docker|br-)/) next
                   split($2, a, "/")
                   ip = a[1]
                   # Match RFC 1918 private ranges
                   if (ip ~ /^192\.168\./ || ip ~ /^10\./ || ip ~ /^172\.(1[6-9]|2[0-9]|3[01])\./)
                       print ip
               }' \
        | head -1)

    # Method 2: Fallback to ip route (may return VPN IP if VPN is active)
    if [ -z "$lan_ip" ]; then
        lan_ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' || true)
    fi

    # Method 3: Fallback to hostname -I
    if [ -z "$lan_ip" ]; then
        lan_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    fi

    if [ -z "$lan_ip" ]; then
        lan_ip="127.0.0.1"
    fi
    echo "$lan_ip"
}

# Storage backend validation
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

# Prompt helpers for interactive credential collection
prompt_nonempty() {
    local prompt_text="$1"
    local value=""
    while [ -z "$value" ]; do
        read -r -p "  $prompt_text" value
        if [ -z "$value" ]; then
            echo "  Value cannot be empty."
        fi
    done
    echo "$value"
}

prompt_secret_nonempty() {
    local prompt_text="$1"
    local value=""
    while [ -z "$value" ]; do
        read -r -s -p "  $prompt_text" value
        echo ""
        if [ -z "$value" ]; then
            echo "  Value cannot be empty."
        fi
    done
    echo "$value"
}

# Prompt for storage backend credentials based on provider type
prompt_storage_backend_config() {
    case "$STORAGE_BACKEND" in
        local-seaweedfs)
            print_status "INFO" "Using local SeaweedFS backend"
            ;;
        wasabi)
            echo ""
            echo -e "${BLUE}Wasabi Storage Configuration${NC}"
            S3_REGION=$(prompt_nonempty "Wasabi region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "Wasabi access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "Wasabi secret key: ")
            S3_BUCKET=$(prompt_nonempty "Wasabi bucket name: ")
            ;;
        backblaze)
            echo ""
            echo -e "${BLUE}Backblaze B2 Storage Configuration${NC}"
            BACKBLAZE_ENDPOINT=$(prompt_nonempty "Backblaze endpoint: ")
            BACKBLAZE_KEY_ID=$(prompt_nonempty "Backblaze key ID: ")
            BACKBLAZE_APPLICATION_KEY=$(prompt_secret_nonempty "Backblaze application key: ")
            BACKBLAZE_BUCKET_NAME=$(prompt_nonempty "Backblaze bucket name: ")
            ;;
        vultr)
            echo ""
            echo -e "${BLUE}Vultr Object Storage Configuration${NC}"
            S3_REGION=$(prompt_nonempty "Vultr region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "Vultr access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "Vultr secret key: ")
            S3_BUCKET=$(prompt_nonempty "Vultr bucket name: ")
            ;;
        cloudflare-r2)
            echo ""
            echo -e "${BLUE}Cloudflare R2 Storage Configuration${NC}"
            CLOUDFLARE_ENDPOINT=$(prompt_nonempty "Cloudflare R2 endpoint: ")
            CLOUDFLARE_ACCESS_KEY_ID=$(prompt_nonempty "Cloudflare R2 access key ID: ")
            CLOUDFLARE_SECRET_ACCESS_KEY=$(prompt_secret_nonempty "Cloudflare R2 secret access key: ")
            CLOUDFLARE_BUCKET_NAME=$(prompt_nonempty "Cloudflare R2 bucket name: ")
            ;;
        aws-s3)
            echo ""
            echo -e "${BLUE}AWS S3 Storage Configuration${NC}"
            S3_REGION=$(prompt_nonempty "AWS region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "AWS access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "AWS secret key: ")
            S3_BUCKET=$(prompt_nonempty "AWS bucket name: ")
            ;;
        generic-s3)
            echo ""
            echo -e "${BLUE}Generic S3 Storage Configuration${NC}"
            S3_ENDPOINT=$(prompt_nonempty "S3 endpoint URL: ")
            S3_REGION=$(prompt_nonempty "S3 region: ")
            S3_ACCESS_KEY=$(prompt_nonempty "S3 access key: ")
            S3_SECRET_KEY=$(prompt_secret_nonempty "S3 secret key: ")
            S3_BUCKET=$(prompt_nonempty "S3 bucket name: ")
            read -r -p "  Force path style? [Y/n]: " force_path_style
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

# Verify external storage backend with round-trip test
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

# Validate storage backend
if ! validate_storage_backend "$STORAGE_BACKEND"; then
    print_status "ERROR" "Unsupported storage backend: $STORAGE_BACKEND"
    echo "Supported backends: local-seaweedfs, wasabi, backblaze, vultr, cloudflare-r2, aws-s3, generic-s3"
    exit 1
fi

# Step 0: Pre-flight checks
echo -e "${CYAN}Step 0: Pre-flight checks${NC}"
echo "=========================="

# Detect Go binary
echo -e "${YELLOW}Detecting Go installation...${NC}"
if ! GO_BINARY=$(find_go_binary); then
    echo -e "${RED}[X] Go compiler not found in standard locations${NC}"
    echo "   Checked: PATH, /usr/bin/go, /usr/local/bin/go, /usr/local/go/bin/go"
    echo "   Please install Go via package manager or from https://golang.org"
    exit 1
fi
echo -e "${GREEN}[OK] Found Go at: $GO_BINARY${NC}"
export GO_BINARY="$GO_BINARY"

# Detect OS family
if [ -f /etc/debian_version ]; then
    OS_FAMILY="debian"
elif [ -f /etc/redhat-release ]; then
    OS_FAMILY="rhel"
else
    OS_FAMILY="unknown"
    print_status "WARNING" "Unknown OS family. Script may not work correctly."
fi
print_status "INFO" "Detected OS family: $OS_FAMILY"

# Verify system dependencies
print_status "INFO" "Checking system dependencies..."
MISSING_DEPS=""
for cmd in gcc make cmake pkg-config git openssl curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_DEPS="$MISSING_DEPS $cmd"
    fi
done

# Check libsodium
if ! pkg-config --exists libsodium 2>/dev/null; then
    if [ "$OS_FAMILY" = "debian" ]; then
        MISSING_DEPS="$MISSING_DEPS libsodium-dev"
    else
        MISSING_DEPS="$MISSING_DEPS libsodium-devel"
    fi
fi

# Check bun
if ! command -v bun >/dev/null 2>&1; then
    MISSING_DEPS="$MISSING_DEPS bun"
fi

if [ -n "$MISSING_DEPS" ]; then
    print_status "ERROR" "Missing required dependencies:$MISSING_DEPS"
    echo ""
    if [ "$OS_FAMILY" = "debian" ]; then
        echo "  Install with: sudo apt install$MISSING_DEPS"
    elif [ "$OS_FAMILY" = "rhel" ]; then
        echo "  Install with: sudo dnf install$MISSING_DEPS"
    fi
    echo "  For bun: curl -fsSL https://bun.sh/install | bash"
    exit 1
fi
print_status "SUCCESS" "All system dependencies found"

# Guard against re-running on existing deployment
EXISTING_DEPLOYMENT=false
if [ -f "$ARKFILE_DIR/etc/secrets.env" ]; then
    EXISTING_DEPLOYMENT=true
fi
if systemctl is-active --quiet arkfile 2>/dev/null; then
    EXISTING_DEPLOYMENT=true
fi

if [ "$EXISTING_DEPLOYMENT" = "true" ]; then
    echo ""
    echo -e "${YELLOW}WARNING: An existing Arkfile deployment was detected.${NC}"
    echo -e "${YELLOW}This script is intended for first-time deployment.${NC}"
    echo ""
    echo "  To update an existing deployment: sudo bash scripts/local-update.sh"
    echo "  To restart services: sudo systemctl restart arkfile"
    echo ""
    echo -e "${RED}To wipe and reinstall, type REINSTALL (this destroys all data):${NC}"
    read -p "> " -r
    if [[ $REPLY != "REINSTALL" ]]; then
        echo "Cancelled. Nothing was changed."
        exit 0
    fi

    echo ""
    echo -e "${RED}Wiping existing deployment...${NC}"

    # Stop services
    stop_service_if_running "arkfile"
    stop_service_if_running "seaweedfs"
    stop_service_if_running "rqlite"

    # Kill lingering service processes (exclude this script's own PID)
    pkill -f "/opt/arkfile/bin/arkfile" 2>/dev/null || true
    pkill -f "weed " 2>/dev/null || true
    pkill -f "rqlited " 2>/dev/null || true
    sleep 2

    # Wipe data (preserve downloaded binaries and C libraries)
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
        rm -rf "$ARKFILE_DIR/etc/keys/jwt"* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/etc/keys/opaque"* 2>/dev/null || true
        rm -f "$ARKFILE_DIR/etc/keys/totp_master.key" 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/etc/keys/tls"* 2>/dev/null || true
        rm -rf "$ARKFILE_DIR/client/static/js/dist"* 2>/dev/null || true
    fi
    print_status "SUCCESS" "Existing deployment wiped"
fi

# Detect LAN IP
LAN_IP=$(detect_lan_ip)
print_status "INFO" "Detected LAN IP: $LAN_IP"

# Prompt for storage backend credentials (interactive)
prompt_storage_backend_config

# Display deployment summary
echo ""
echo -e "${BLUE}ARKFILE LOCAL DEPLOYMENT${NC}"
echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  Admin username:  $ADMIN_USERNAME"
if [ -n "$ADMIN_CONTACT" ]; then
    echo "  Admin contact:   $ADMIN_CONTACT"
else
    echo "  Admin contact:   (not set - pending users won't have contact info)"
fi
echo "  Storage backend: $STORAGE_BACKEND"
echo "  Bind address:    $BIND_ADDRESS"
echo "  TLS port:        $TLS_PORT"
echo "  HTTP port:       $HTTP_PORT"
echo "  LAN IP:          $LAN_IP"
echo "  Access URL:      https://localhost:${TLS_PORT}"
echo "  LAN URL:         https://${LAN_IP}:${TLS_PORT}"
echo ""
echo -e "${BLUE}This will:${NC}"
echo "  - Create arkfile system user and directories"
echo "  - Build Arkfile from source"
echo "  - Generate self-signed TLS certificates"
echo "  - Configure and start all services"
echo "  - Enable admin bootstrap mode"
echo ""
read -p "Type DEPLOY to proceed (anything else cancels): " -r
if [[ $REPLY != "DEPLOY" ]]; then
    echo "Cancelled. Nothing was changed."
    exit 0
fi
echo ""

# Step 1: System user and directory structure
echo -e "${CYAN}Step 1: System user and directory structure${NC}"
echo "============================================="

print_status "INFO" "Creating system user and directories..."
if ! ./scripts/setup/01-setup-users.sh; then
    print_status "ERROR" "User setup failed"
    exit 1
fi
if ! ./scripts/setup/02-setup-directories.sh; then
    print_status "ERROR" "Directory setup failed"
    exit 1
fi
print_status "SUCCESS" "System user and directory structure ready"
echo ""

# Step 2: Build application
echo -e "${CYAN}Step 2: Building application${NC}"
echo "============================="

fix_go_ownership

# Check C libraries
SKIP_C_LIBS=false
if [ "$FORCE_REBUILD_ALL" = "true" ]; then
    print_status "INFO" "--force-rebuild-all: Deleting entire build directory"
    rm -rf "$BUILD_ROOT"
    print_status "SUCCESS" "Build directory deleted"
elif c_libs_exist; then
    SKIP_C_LIBS=true
    print_status "INFO" "Found existing C libraries, will skip rebuild"
    print_status "INFO" "Use --force-rebuild-all to force C library rebuild"
fi

# Do NOT set LIBOPAQUE_DEFINES (no WASM trace logging for local deployment)
unset LIBOPAQUE_DEFINES
print_status "INFO" "WASM trace logging disabled (production build)"

# Force fresh TypeScript rebuild
print_status "INFO" "Forcing fresh TypeScript rebuild..."
rm -f client/static/js/.buildcache
rm -rf client/static/js/dist/*

# Clean build artifacts (preserve C libraries)
print_status "INFO" "Cleaning build artifacts..."
if [ -d "$BUILD_ROOT" ]; then
    if [ "$SKIP_C_LIBS" = "true" ]; then
        print_status "INFO" "Preserving C libraries in $BUILD_CLIBS"
        rm -rf "$BUILD_BIN" "$BUILD_CLIENT" "$BUILD_DATABASE" "$BUILD_SYSTEMD" "$BUILD_WEBROOT" 2>/dev/null || true
        rm -f "$BUILD_ROOT/version.json" 2>/dev/null || true
        print_status "SUCCESS" "Build artifacts cleaned (C libraries preserved)"
    else
        rm -rf "$BUILD_ROOT"
        print_status "SUCCESS" "Build artifacts cleaned (including C libraries)"
    fi
fi

# Set version and build
FALLBACK_VERSION="local-$(date +%Y%m%d-%H%M%S)"
export VERSION="$FALLBACK_VERSION"
export SKIP_C_LIBS="$SKIP_C_LIBS"

fix_go_ownership

# Run build as original user
if ! run_as_user ./scripts/setup/build.sh --build-only; then
    print_status "ERROR" "Build failed"
    exit 1
fi

fix_go_ownership
print_status "SUCCESS" "Application build complete"
echo ""

# Step 3: Deploy build artifacts
echo -e "${CYAN}Step 3: Deploying build artifacts${NC}"
echo "=================================="

if ! ./scripts/setup/deploy.sh; then
    print_status "ERROR" "Deployment failed"
    exit 1
fi

# Verify critical files
print_status "INFO" "Verifying critical files..."

if [ ! -f "$ARKFILE_DIR/client/static/js/libopaque.js" ]; then
    print_status "ERROR" "libopaque.js missing from $ARKFILE_DIR"
    exit 1
fi
print_status "SUCCESS" "libopaque.js verified"

if [ ! -f "$ARKFILE_DIR/client/static/js/dist/app.js" ]; then
    print_status "ERROR" "TypeScript bundle missing from $ARKFILE_DIR"
    exit 1
fi
print_status "SUCCESS" "TypeScript bundle verified"

if [ ! -x "$ARKFILE_DIR/bin/arkfile" ]; then
    print_status "ERROR" "arkfile binary missing or not executable"
    exit 1
fi
print_status "SUCCESS" "arkfile binary verified"

if [ ! -x "$ARKFILE_DIR/bin/arkfile-client" ]; then
    print_status "ERROR" "arkfile-client binary missing or not executable"
    exit 1
fi
print_status "SUCCESS" "arkfile-client binary verified"

if [ ! -x "$ARKFILE_DIR/bin/arkfile-admin" ]; then
    print_status "ERROR" "arkfile-admin binary missing or not executable"
    exit 1
fi
print_status "SUCCESS" "arkfile-admin binary verified"

print_status "SUCCESS" "All critical files in place"
echo ""

# Step 4: Ensure correct ownership
echo -e "${CYAN}Step 4: Ensuring correct ownership${NC}"
echo "===================================="

chown -R arkfile:arkfile "$ARKFILE_DIR"

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

# Create and permission log directory
mkdir -p "$ARKFILE_DIR/var/log"
chown "$USER:$GROUP" "$ARKFILE_DIR/var/log"
chmod 775 "$ARKFILE_DIR/var/log"

print_status "SUCCESS" "Ownership and permissions set"
echo ""

# Step 5: Generate secrets and configuration
# NOTE: secrets.env MUST be written before Step 6 (master key generation),
# because 03-setup-master-key.sh appends ARKFILE_MASTER_KEY to secrets.env.
# Writing secrets.env after would overwrite the master key.
echo -e "${CYAN}Step 5: Generating local deployment configuration${NC}"
echo "==================================================="

RQLITE_PASSWORD="$(openssl rand -hex 16)"
S3_PASSWORD="$(openssl rand -hex 16)"

print_status "SUCCESS" "Generated fresh database password"
print_status "SUCCESS" "Generated fresh S3 password"

# Write base secrets.env (common to all backends)
cat > "$ARKFILE_DIR/etc/secrets.env" << EOF
# Local Deployment Configuration
# Generated: $(date)
# Access: https://${BIND_ADDRESS}:${TLS_PORT}

# Database Configuration
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
RQLITE_USERNAME=local-user
RQLITE_PASSWORD=${RQLITE_PASSWORD}

# Arkfile Application Configuration
PORT=${HTTP_PORT}
CORS_ALLOWED_ORIGINS=https://localhost:${TLS_PORT},https://${LAN_IP}:${TLS_PORT}

# TLS Configuration (Arkfile serves its own TLS directly)
TLS_ENABLED=true
TLS_PORT=${TLS_PORT}
TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.crt
TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.key

EOF

# Append storage configuration based on backend type
case "$STORAGE_BACKEND" in
    local-seaweedfs)
        cat >> "$ARKFILE_DIR/etc/secrets.env" << EOF
# Storage Configuration - Generic S3 (local SeaweedFS backend)
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=http://localhost:9332
S3_ACCESS_KEY=arkfile-local
S3_SECRET_KEY=${S3_PASSWORD}
S3_BUCKET=arkfile-local
S3_REGION=us-east-1
S3_FORCE_PATH_STYLE=true
S3_USE_SSL=false

EOF

        # SeaweedFS S3 auth config
        cat > "$ARKFILE_DIR/etc/seaweedfs-s3.json" << EOF
{
  "identities": [
    {
      "name": "arkfile",
      "credentials": [
        {
          "accessKey": "arkfile-local",
          "secretKey": "${S3_PASSWORD}"
        }
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF
        chown "$USER:$GROUP" "$ARKFILE_DIR/etc/seaweedfs-s3.json"
        chmod 640 "$ARKFILE_DIR/etc/seaweedfs-s3.json"
        print_status "SUCCESS" "SeaweedFS S3 auth configuration created"
        ;;
    wasabi|vultr|aws-s3)
        cat >> "$ARKFILE_DIR/etc/secrets.env" << EOF
# Storage Configuration - ${STORAGE_BACKEND}
STORAGE_PROVIDER=${STORAGE_BACKEND}
S3_REGION=${S3_REGION}
S3_ACCESS_KEY=${S3_ACCESS_KEY}
S3_SECRET_KEY=${S3_SECRET_KEY}
S3_BUCKET=${S3_BUCKET}

EOF
        ;;
    backblaze)
        cat >> "$ARKFILE_DIR/etc/secrets.env" << EOF
# Storage Configuration - Backblaze B2
STORAGE_PROVIDER=backblaze
BACKBLAZE_ENDPOINT=${BACKBLAZE_ENDPOINT}
BACKBLAZE_KEY_ID=${BACKBLAZE_KEY_ID}
BACKBLAZE_APPLICATION_KEY=${BACKBLAZE_APPLICATION_KEY}
BACKBLAZE_BUCKET_NAME=${BACKBLAZE_BUCKET_NAME}

EOF
        ;;
    cloudflare-r2)
        cat >> "$ARKFILE_DIR/etc/secrets.env" << EOF
# Storage Configuration - Cloudflare R2
STORAGE_PROVIDER=cloudflare-r2
CLOUDFLARE_ENDPOINT=${CLOUDFLARE_ENDPOINT}
CLOUDFLARE_ACCESS_KEY_ID=${CLOUDFLARE_ACCESS_KEY_ID}
CLOUDFLARE_SECRET_ACCESS_KEY=${CLOUDFLARE_SECRET_ACCESS_KEY}
CLOUDFLARE_BUCKET_NAME=${CLOUDFLARE_BUCKET_NAME}

EOF
        ;;
    generic-s3)
        cat >> "$ARKFILE_DIR/etc/secrets.env" << EOF
# Storage Configuration - Generic S3
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=${S3_ENDPOINT}
S3_REGION=${S3_REGION}
S3_ACCESS_KEY=${S3_ACCESS_KEY}
S3_SECRET_KEY=${S3_SECRET_KEY}
S3_BUCKET=${S3_BUCKET}
S3_FORCE_PATH_STYLE=${S3_FORCE_PATH_STYLE}

EOF
        ;;
esac

# Append remaining configuration (common to all backends)
cat >> "$ARKFILE_DIR/etc/secrets.env" << EOF
# Admin Configuration
ADMIN_USERNAMES=${ADMIN_USERNAME}
ARKFILE_ADMIN_CONTACT=${ADMIN_CONTACT}

# Admin Bootstrap Mode (true for first-time setup)
ARKFILE_FORCE_ADMIN_BOOTSTRAP=true

# Dev/Test API DISABLED
ADMIN_DEV_TEST_API_ENABLED=false

# Local Deployment Settings (NOT development)
REQUIRE_APPROVAL=true
ENABLE_REGISTRATION=true
DEBUG_MODE=false
LOG_LEVEL=info
EOF

chown "$USER:$GROUP" "$ARKFILE_DIR/etc/secrets.env"
chmod 640 "$ARKFILE_DIR/etc/secrets.env"
print_status "SUCCESS" "secrets.env created"

# rqlite auth file
cat > "$ARKFILE_DIR/etc/rqlite-auth.json" << EOF
[
  {
    "username": "local-user",
    "password": "${RQLITE_PASSWORD}",
    "perms": ["all"]
  }
]
EOF

chown "$USER:$GROUP" "$ARKFILE_DIR/etc/rqlite-auth.json"
chmod 640 "$ARKFILE_DIR/etc/rqlite-auth.json"
print_status "SUCCESS" "rqlite auth file created"

print_status "SUCCESS" "All configuration files generated"
echo ""

# Step 6: Generate cryptographic material
# Master key appends to secrets.env (written in Step 5). TLS certs are idempotent.
echo -e "${CYAN}Step 6: Generating cryptographic material${NC}"
echo "==========================================="

print_status "INFO" "Generating Master Key..."
if ! ./scripts/setup/03-setup-master-key.sh; then
    print_status "ERROR" "Master Key generation failed"
    exit 1
fi
print_status "SUCCESS" "Master Key generated"

print_status "INFO" "Generating TLS certificates..."

# Build list of extra IPs for TLS certificate SANs:
# Always include detected LAN IP, plus any user-specified --add-ip values
ALL_EXTRA_IPS=()
if [ "$LAN_IP" != "127.0.0.1" ]; then
    ALL_EXTRA_IPS+=("$LAN_IP")
fi
for ip in "${ADD_IPS[@]}"; do
    ALL_EXTRA_IPS+=("$ip")
done
if [ ${#ALL_EXTRA_IPS[@]} -gt 0 ]; then
    export ARKFILE_EXTRA_IPS=$(IFS=,; echo "${ALL_EXTRA_IPS[*]}")
    print_status "INFO" "TLS cert extra IP SANs: $ARKFILE_EXTRA_IPS"
fi

if ! ./scripts/setup/04-setup-tls-certs.sh; then
    print_status "ERROR" "TLS certificate generation failed"
    exit 1
fi
print_status "SUCCESS" "TLS certificates generated"

# Fix ownership after key generation
chown -R arkfile:arkfile "$ARKFILE_DIR"
chmod 700 "$ARKFILE_DIR/etc/keys"
[ -d "$ARKFILE_DIR/etc/keys/tls" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls"
[ -d "$ARKFILE_DIR/etc/keys/tls/ca" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls/ca"
[ -d "$ARKFILE_DIR/etc/keys/tls/arkfile" ] && chmod 700 "$ARKFILE_DIR/etc/keys/tls/arkfile"

if ! verify_ownership "$ARKFILE_DIR"; then
    print_status "WARNING" "Fixing ownership after key generation..."
    chown -R arkfile:arkfile "$ARKFILE_DIR"
    if ! verify_ownership "$ARKFILE_DIR"; then
        print_status "ERROR" "Failed to fix ownership"
        exit 1
    fi
fi

print_status "SUCCESS" "Cryptographic material ready"
echo ""

# Step 7: Setup storage services and rqlite
echo -e "${CYAN}Step 7: Setting up storage services and rqlite${NC}"
echo "================================================="

if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
    print_status "INFO" "Setting up SeaweedFS..."
    if ! ./scripts/setup/05-setup-seaweedfs.sh; then
        print_status "ERROR" "SeaweedFS setup failed"
        exit 1
    fi
    print_status "SUCCESS" "SeaweedFS setup complete"
else
    print_status "INFO" "Skipping SeaweedFS setup (using external backend: $STORAGE_BACKEND)"
fi

RQLITE_BUILD_ARGS=""
if [ "$FORCE_REBUILD_RQLITE" = "true" ]; then
    RQLITE_BUILD_ARGS="--force"
    print_status "INFO" "Setting up rqlite (forced rebuild)..."
else
    print_status "INFO" "Setting up rqlite..."
fi
if ! ./scripts/setup/06-setup-rqlite-build.sh $RQLITE_BUILD_ARGS; then
    print_status "ERROR" "rqlite setup failed"
    exit 1
fi
print_status "SUCCESS" "rqlite setup complete"
echo ""

# Step 8: Start services
echo -e "${CYAN}Step 8: Starting services${NC}"
echo "=========================="

systemctl daemon-reload

# A. Start SeaweedFS (only for local-seaweedfs backend)
if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
    print_status "INFO" "Starting SeaweedFS..."
    systemctl start seaweedfs
    systemctl enable seaweedfs

    if ! systemctl is-active --quiet seaweedfs; then
        print_status "ERROR" "SeaweedFS failed to start"
        exit 1
    fi
    print_status "SUCCESS" "SeaweedFS started"

    # Wait for SeaweedFS S3 gateway
    print_status "INFO" "Waiting for SeaweedFS S3 gateway..."
    max_attempts=20
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:9332/status >/dev/null 2>&1; then
            print_status "SUCCESS" "SeaweedFS S3 gateway ready on port 9332"
            break
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    if [ $attempt -eq $max_attempts ]; then
        print_status "ERROR" "SeaweedFS S3 gateway failed to respond within timeout"
        print_status "ERROR" "Check logs: sudo journalctl -u seaweedfs -f"
        exit 1
    fi
else
    print_status "INFO" "Skipping SeaweedFS startup (using external backend: $STORAGE_BACKEND)"
fi

# B. Start rqlite
print_status "INFO" "Starting rqlite..."
systemctl start rqlite
systemctl enable rqlite

sleep 2
if ! systemctl is-active --quiet rqlite; then
    print_status "ERROR" "rqlite failed to start"
    exit 1
fi
print_status "SUCCESS" "rqlite started"

# Wait for rqlite leadership
print_status "INFO" "Waiting for rqlite to establish leadership..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -u "local-user:${RQLITE_PASSWORD}" http://localhost:4001/status 2>/dev/null | grep -q '"ready":true'; then
        print_status "SUCCESS" "rqlite is ready and established as leader"
        break
    fi
    sleep 2
    attempt=$((attempt + 1))
done
if [ $attempt -eq $max_attempts ]; then
    print_status "ERROR" "rqlite failed to become ready within timeout"
    exit 1
fi

# C. Start Arkfile
print_status "INFO" "Starting Arkfile..."
systemctl start arkfile
systemctl enable arkfile

sleep 2
if ! systemctl is-active --quiet arkfile; then
    print_status "ERROR" "Arkfile failed to start"
    exit 1
fi
print_status "SUCCESS" "Arkfile started"

# Verify external storage backend (after Arkfile is running)
verify_storage_backend_roundtrip

echo ""

# Step 9: Health verification
echo -e "${CYAN}Step 9: Health verification${NC}"
echo "============================="

# Wait for Arkfile readiness
print_status "INFO" "Waiting for Arkfile to be ready..."
max_attempts=15
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sk https://localhost:${TLS_PORT}/readyz 2>/dev/null | grep -q '"status":"ready"'; then
        print_status "SUCCESS" "Arkfile is running and ready"
        break
    fi
    sleep 3
    attempt=$((attempt + 1))
done
if [ $attempt -eq $max_attempts ]; then
    print_status "ERROR" "Arkfile failed to become ready within timeout"
    print_status "ERROR" "Check logs: sudo journalctl -u arkfile -f"
    exit 1
fi

# Test config endpoints
print_status "INFO" "Testing configuration API endpoints..."

if curl -sk https://localhost:${TLS_PORT}/api/config/argon2 2>/dev/null | grep -q '"memoryCostKiB"'; then
    print_status "SUCCESS" "Argon2 config endpoint responding"
else
    print_status "WARNING" "Argon2 config endpoint may not be working"
fi

if curl -sk https://localhost:${TLS_PORT}/api/config/password-requirements 2>/dev/null | grep -q '"minAccountPasswordLength"'; then
    print_status "SUCCESS" "Password requirements endpoint responding"
else
    print_status "WARNING" "Password requirements endpoint may not be working"
fi

if curl -sk https://localhost:${TLS_PORT}/api/config/chunking 2>/dev/null | grep -q '"plaintextChunkSizeBytes"'; then
    print_status "SUCCESS" "Chunking config endpoint responding"
else
    print_status "WARNING" "Chunking config endpoint may not be working"
fi

# Service status check
rqlite_status=$(systemctl is-active rqlite 2>/dev/null || echo "failed")
arkfile_status=$(systemctl is-active arkfile 2>/dev/null || echo "failed")

print_status "INFO" "Service status:"
if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
    seaweedfs_status=$(systemctl is-active seaweedfs 2>/dev/null || echo "failed")
    echo "    SeaweedFS: ${seaweedfs_status}"
else
    seaweedfs_status="n/a"
    echo "    Storage:   ${STORAGE_BACKEND} (external)"
fi
echo "    rqlite:    ${rqlite_status}"
echo "    Arkfile:   ${arkfile_status}"

if [ "$rqlite_status" != "active" ] || [ "$arkfile_status" != "active" ]; then
    print_status "ERROR" "One or more services failed to start"
    exit 1
fi
if [ "$STORAGE_BACKEND" = "local-seaweedfs" ] && [ "$seaweedfs_status" != "active" ]; then
    print_status "ERROR" "SeaweedFS failed to start"
    exit 1
fi

# Final ownership verification
if ! verify_ownership "$ARKFILE_DIR"; then
    print_status "WARNING" "Some files may have incorrect ownership"
else
    print_status "SUCCESS" "All ownership checks passed"
fi
echo ""

# Step 10: Output admin bootstrap instructions
echo -e "${GREEN}LOCAL DEPLOYMENT COMPLETE${NC}"
echo ""
echo -e "${BLUE}Your Arkfile instance is running at:${NC}"
echo -e "${GREEN}  HTTPS: https://localhost:${TLS_PORT}${NC}"
echo -e "${GREEN}  HTTPS (LAN): https://${LAN_IP}:${TLS_PORT}${NC}"
echo -e "${BLUE}  (Accept self-signed certificate warning in browser)${NC}"
echo ""
echo -e "${BLUE}Services:${NC}"
if [ "$STORAGE_BACKEND" = "local-seaweedfs" ]; then
    echo "  SeaweedFS: ${seaweedfs_status}"
else
    echo "  Storage:   ${STORAGE_BACKEND} (external)"
fi
echo "  rqlite:    ${rqlite_status}"
echo "  Arkfile:   ${arkfile_status}"
echo ""
echo -e "${YELLOW}NEXT: Bootstrap your admin account${NC}"
echo ""
echo "  1. Check Arkfile logs for the bootstrap token:"
echo "     sudo journalctl -u arkfile --no-pager -n 250 | grep BOOTSTRAP"
echo ""
echo "  2. Bootstrap the admin account (from this machine):"
echo "     /opt/arkfile/bin/arkfile-admin \\"
echo "       --server-url https://localhost:${TLS_PORT} --tls-insecure \\"
echo "       bootstrap --token <BOOTSTRAP_TOKEN> --username ${ADMIN_USERNAME}"
echo ""
echo "  3. Setup TOTP for the admin account:"
echo "     /opt/arkfile/bin/arkfile-admin \\"
echo "       --server-url https://localhost:${TLS_PORT} --tls-insecure \\"
echo "       setup-totp"
echo ""
echo "  4. Verify admin login:"
echo "     /opt/arkfile/bin/arkfile-admin \\"
echo "       --server-url https://localhost:${TLS_PORT} --tls-insecure \\"
echo "       verify-login --username ${ADMIN_USERNAME}"
echo ""
echo "  5. After successful admin login, disable force bootstrap:"
echo "     - Edit /opt/arkfile/etc/secrets.env"
echo "     - Set ARKFILE_FORCE_ADMIN_BOOTSTRAP=false"
echo "     - Restart: sudo systemctl restart arkfile"
echo ""
echo "  6. Access the web interface:"
echo "     https://localhost:${TLS_PORT}"
echo "     https://${LAN_IP}:${TLS_PORT} (from other devices on your network)"
echo "     (Accept the self-signed certificate warning)"
echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo "  View logs:       sudo journalctl -u arkfile -f"
echo "  Restart:         sudo systemctl restart arkfile"
echo "  Stop all:        sudo systemctl stop arkfile seaweedfs rqlite"
echo "  Start all:       sudo systemctl start seaweedfs rqlite arkfile"
echo ""

exit 0
