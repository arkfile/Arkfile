#!/bin/bash

# Arkfile Development Reset Script
# Fast reset for development iteration - nukes data but preserves binaries

set -e

# Check if running as root first
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31mERROR: This script must be run with sudo privileges\033[0m"
    echo "Usage: sudo ./scripts/dev-reset.sh"
    exit 1
fi

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

echo -e "${RED}ARKFILE DEVELOPMENT RESET${NC}"
echo -e "${RED}===========================================================${NC}"
echo
echo -e "${YELLOW}WARNING: This will PERMANENTLY DELETE:${NC}"
echo -e "${RED}    • ALL USER DATA (uploaded files, shares)${NC}"
echo -e "${RED}    • ENTIRE DATABASE (users, files, shares)${NC}"
echo -e "${RED}    • ALL SECRETS (JWT keys, OPAQUE keys)${NC}"
echo -e "${RED}    • ALL CREDENTIALS (passwords, tokens)${NC}"
echo -e "${RED}    • ALL LOGS${NC}"
echo
echo -e "${BLUE}This will PRESERVE (for speed):${NC}"
echo -e "${GREEN}    • Downloaded MinIO/rqlite binaries${NC}"
echo -e "${GREEN}    • Compiled libopaque libraries${NC}"
echo -e "${GREEN}    • System users and directory structure${NC}"
echo
echo -e "${RED}ARE YOU ABSOLUTELY SURE YOU WANT TO NUKE EVERYTHING?${NC}"
echo -e "${RED}THERE IS NO GOING BACK!${NC}"
echo
read -p "Type 'NUKE' to confirm (anything else cancels): " -r
if [[ $REPLY != "NUKE" ]]; then
    echo "Cancelled. Nothing was changed."
    exit 0
fi

echo
echo -e "${YELLOW}Starting destruction in 5 seconds...${NC}"
echo -e "${YELLOW}Press Ctrl+C now to abort!${NC}"
for i in {5..1}; do
    echo -ne "${RED}${i}...${NC}"
    sleep 1
done
echo
echo -e "${RED}NUKING EVERYTHING!${NC}"
echo

# POSIX-compatible Go detection with fallbacks
find_go_binary() {
    # Try command -v first (respects PATH, aliases, functions)
    if command -v go >/dev/null 2>&1; then
        command -v go
        return 0
    fi
    
    # Fallback to common installation paths
    local go_candidates=(
        "/usr/bin/go"                       # Linux package managers
        "/usr/local/bin/go"                 # BSD package managers  
        "/usr/local/go/bin/go"              # Manual golang.org installs
    )
    
    for go_path in "${go_candidates[@]}"; do
        if [ -x "$go_path" ]; then
            echo "$go_path"
            return 0
        fi
    done
    
    return 1
}

# Function to print status messages
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "INFO")
            echo -e "  ${BLUE}INFO:${NC} ${message}"
            ;;
        "SUCCESS")
            echo -e "  ${GREEN}SUCCESS:${NC} ${message}"
            ;;
        "WARNING")
            echo -e "  ${YELLOW}WARNING:${NC} ${message}"
            ;;
        "ERROR")
            echo -e "  ${RED}ERROR:${NC} ${message}"
            ;;
    esac
}

# Find and verify Go binary before proceeding
echo -e "${YELLOW}Detecting Go installation...${NC}"
if ! GO_BINARY=$(find_go_binary); then
    echo -e "${RED}❌ Go compiler not found in standard locations${NC}"
    echo "   Checked: PATH, /usr/bin/go, /usr/local/bin/go, /usr/local/go/bin/go"
    echo "   Please install Go via package manager or from https://golang.org"
    exit 1
fi

echo -e "${GREEN}✅ Found Go at: $GO_BINARY${NC}"
export GO_BINARY="$GO_BINARY"

# Function to run commands as original user (not root)
run_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H "$@"
    else
        "$@"
    fi
}

# Function to run Go commands with proper user context and binary path
run_go_as_user() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" -H "$GO_BINARY" "$@"
    else
        "$GO_BINARY" "$@"
    fi
}

# Function to fix ownership of Go-related files
fix_go_ownership() {
    if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
        print_status "INFO" "Fixing Go file ownership for user $SUDO_USER..."
        chown -R "$SUDO_USER:$SUDO_USER" go.mod go.sum 2>/dev/null || true
        [ -d "vendor" ] && chown -R "$SUDO_USER:$SUDO_USER" vendor/ 2>/dev/null || true
        [ -f ".vendor_cache" ] && chown "$SUDO_USER:$SUDO_USER" .vendor_cache 2>/dev/null || true
        print_status "SUCCESS" "Go file ownership restored"
    fi
}

# Function to safely stop a service if it exists and is running
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

# Step 1: Aggressive service shutdown
echo -e "${CYAN}Step 1: Stopping all services aggressively${NC}"
echo "=================================================="

# Stop services using the proven pattern from quick-start.sh
stop_service_if_running "arkfile"
stop_service_if_running "minio"
stop_service_if_running "rqlite"
stop_service_if_running "caddy"

# Kill any lingering arkfile processes
print_status "INFO" "Killing any lingering arkfile processes..."
pkill -f "arkfile" 2>/dev/null || true
pkill -f "minio" 2>/dev/null || true
pkill -f "rqlited" 2>/dev/null || true
sleep 2

# Force kill if still running
if pgrep -f "arkfile\|minio\|rqlited" > /dev/null; then
    print_status "WARNING" "Force killing remaining processes..."
    pkill -9 -f "arkfile\|minio\|rqlited" 2>/dev/null || true
    sleep 1
fi

print_status "SUCCESS" "All services stopped"
echo

# Step 2: Selective data destruction
echo -e "${CYAN}Step 2: Nuking data and secrets${NC}"
echo "================================="

if [ -d "$ARKFILE_DIR" ]; then
    # Delete user data (MinIO storage)
    print_status "INFO" "Nuking user data..."
    rm -rf "$ARKFILE_DIR/var/lib/"*/minio/data/* 2>/dev/null || true
    rm -rf "$ARKFILE_DIR/var/lib/"*/storage/* 2>/dev/null || true
    
    # Delete database
    print_status "INFO" "Nuking database..."
    rm -rf "$ARKFILE_DIR/var/lib/"*/rqlite/* 2>/dev/null || true
    rm -rf "$ARKFILE_DIR/var/lib/database/data"* 2>/dev/null || true
    rm -rf "$ARKFILE_DIR/var/lib/"*/database/* 2>/dev/null || true
    rm -rf "$ARKFILE_DIR/database"* 2>/dev/null || true
    
    # Delete all logs
    print_status "INFO" "Nuking logs..."
    rm -rf "$ARKFILE_DIR/var/log/"* 2>/dev/null || true
    
    # Delete all secrets and credentials
    print_status "INFO" "Nuking secrets and credentials..."
    rm -f "$ARKFILE_DIR/etc/secrets.env" 2>/dev/null || true
    rm -f "$ARKFILE_DIR/etc/"*/secrets.env 2>/dev/null || true
    rm -f "$ARKFILE_DIR/etc/rqlite-auth.json" 2>/dev/null || true
    
    # Delete all keys (they'll be regenerated)
    print_status "INFO" "Nuking cryptographic keys..."
    rm -rf "$ARKFILE_DIR/etc/keys/jwt"* 2>/dev/null || true
    rm -rf "$ARKFILE_DIR/etc/keys/opaque"* 2>/dev/null || true
    rm -f "$ARKFILE_DIR/etc/keys/totp_master.key" 2>/dev/null || true
    
    print_status "SUCCESS" "Data and secrets destroyed"
else
    print_status "WARNING" "Arkfile directory not found, skipping data destruction"
fi
echo

# Step 3: Build application in user directory
echo -e "${CYAN}Step 3: Building application${NC}"
echo "==========================="

print_status "INFO" "Building application in current directory..."

# Step 3.1: Pre-build Go module resolution
echo -e "${YELLOW}Step 3.1: Resolving Go dependencies${NC}"
print_status "INFO" "Ensuring Go dependencies are properly resolved with correct permissions..."

# Fix any existing ownership issues first
fix_go_ownership

# Resolve Go module dependencies as the original user (not root)
print_status "INFO" "Running go mod download as user $ORIGINAL_USER..."
if ! run_go_as_user mod download; then
    print_status "WARNING" "go mod download failed, attempting go mod tidy..."
    if ! run_go_as_user mod tidy; then
        print_status "ERROR" "Failed to resolve Go module dependencies"
        exit 1
    fi
    # Try download again after tidy
    if ! run_go_as_user mod download; then
        print_status "ERROR" "Still unable to download dependencies after go mod tidy"
        exit 1
    fi
fi

# Ensure all internal packages are available (including auth)
print_status "INFO" "Verifying internal package availability..."
if ! run_go_as_user list -m github.com/84adam/Arkfile >/dev/null 2>&1; then
    print_status "WARNING" "Main module not properly recognized, running go mod tidy..."
    run_go_as_user mod tidy
fi

# Verify the auth package is accessible
print_status "INFO" "Verifying auth package accessibility..."
if run_go_as_user list ./auth >/dev/null 2>&1; then
    print_status "SUCCESS" "Auth package is accessible"
else
    print_status "WARNING" "Auth package not immediately accessible - will be resolved during build"
fi

# Fix ownership again after Go operations
fix_go_ownership

print_status "SUCCESS" "Go dependencies resolved successfully"
echo

# Set a fallback version for development
FALLBACK_VERSION="dev-$(date +%Y%m%d-%H%M%S)"

# Check if C libraries already exist to skip expensive rebuild
SKIP_C_LIBS=false
if [ -f "vendor/stef/liboprf/src/liboprf.so" ] && [ -f "vendor/stef/libopaque/src/libopaque.so" ]; then
    SKIP_C_LIBS=true
    print_status "INFO" "Found existing C libraries - will skip rebuild for faster development iteration"
fi

# Build using existing build script
export VERSION="$FALLBACK_VERSION"
export SKIP_C_LIBS="$SKIP_C_LIBS"

# Ensure ownership is correct before build
fix_go_ownership

if ! ./scripts/setup/build.sh; then
    print_status "ERROR" "Build script failed - this is CRITICAL"
    exit 1
fi

# Fix ownership after build as well
fix_go_ownership

print_status "SUCCESS" "Application build and deployment complete"

# Verify critical files are in place and fix if needed
print_status "INFO" "Verifying critical files are in place..."

# Ensure WASM binary is available in working directory
if [ ! -f "$ARKFILE_DIR/client/main.wasm" ]; then
    print_status "WARNING" "WASM binary missing from working directory, copying from release..."
    if [ -f "$ARKFILE_DIR/releases/current/client/main.wasm" ]; then
        cp "$ARKFILE_DIR/releases/current/client/main.wasm" "$ARKFILE_DIR/client/main.wasm"
        chown "$USER:$GROUP" "$ARKFILE_DIR/client/main.wasm"
        print_status "SUCCESS" "WASM binary copied to working directory"
    else
        print_status "ERROR" "WASM binary not found in release either - build may have failed"
        exit 1
    fi
else
    print_status "SUCCESS" "WASM binary verified in working directory"
fi

# Ensure wasm_exec.js is available
if [ ! -f "$ARKFILE_DIR/client/wasm_exec.js" ]; then
    print_status "WARNING" "wasm_exec.js missing from working directory, copying from release..."
    if [ -f "$ARKFILE_DIR/releases/current/client/wasm_exec.js" ]; then
        cp "$ARKFILE_DIR/releases/current/client/wasm_exec.js" "$ARKFILE_DIR/client/wasm_exec.js"
        chown "$USER:$GROUP" "$ARKFILE_DIR/client/wasm_exec.js"
        print_status "SUCCESS" "wasm_exec.js copied to working directory"
    else
        print_status "WARNING" "wasm_exec.js not found in release - may affect WASM functionality"
    fi
fi

print_status "SUCCESS" "Critical file verification complete"
echo

# Step 3.5: Update systemd service file
echo -e "${CYAN}Step 3.5: Updating systemd service file${NC}"
echo "========================================"

print_status "INFO" "Checking systemd service file consistency..."

# Define paths
REPO_SERVICE_FILE="systemd/arkfile.service"
SYSTEM_SERVICE_FILE="/etc/systemd/system/arkfile.service"

# Check if repository service file exists
if [ ! -f "$REPO_SERVICE_FILE" ]; then
    print_status "ERROR" "Repository service file not found: $REPO_SERVICE_FILE"
    exit 1
fi

# Check if system service file needs updating
needs_update=false
daemon_reload_needed=false

if [ ! -f "$SYSTEM_SERVICE_FILE" ]; then
    print_status "INFO" "System service file does not exist, will create it"
    needs_update=true
    daemon_reload_needed=true
else
    # Compare files to see if they differ
    if ! cmp -s "$REPO_SERVICE_FILE" "$SYSTEM_SERVICE_FILE"; then
        print_status "INFO" "System service file differs from repository version, will update it"
        needs_update=true
        daemon_reload_needed=true
    else
        print_status "SUCCESS" "System service file is up to date"
    fi
fi

# Update service file if needed
if [ "$needs_update" = true ]; then
    print_status "INFO" "Copying updated service file to system location..."
    cp "$REPO_SERVICE_FILE" "$SYSTEM_SERVICE_FILE"
    print_status "SUCCESS" "Service file updated"
fi

# Reload systemd daemon if needed
if [ "$daemon_reload_needed" = true ]; then
    print_status "INFO" "Reloading systemd daemon..."
    systemctl daemon-reload
    print_status "SUCCESS" "Systemd daemon reloaded"
fi

print_status "SUCCESS" "Systemd service file verification complete"
echo

# Step 4: Ensure directory structure exists
echo -e "${CYAN}Step 4: Ensuring directory structure${NC}"
echo "======================================"

# Ensure all directories exist before trying to write files
print_status "INFO" "Setting up directory structure via external scripts..."
if ! ./scripts/setup/01-setup-users.sh; then
    print_status "ERROR" "User setup failed - this is CRITICAL"
    exit 1
fi
if ! ./scripts/setup/02-setup-directories.sh; then
    print_status "ERROR" "Directory setup failed - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "Base directory structure created"

# Explicitly create and permission the log directory
print_status "INFO" "Ensuring log directory exists and has correct permissions..."
mkdir -p "$ARKFILE_DIR/var/log"
chown "$USER:$GROUP" "$ARKFILE_DIR/var/log"
chmod 775 "$ARKFILE_DIR/var/log"
print_status "SUCCESS" "Log directory configured at $ARKFILE_DIR/var/log"
echo

# Step 5: Generate fresh secrets
echo -e "${CYAN}Step 5: Generating fresh secrets${NC}"
echo "================================="

# Generate random JWT secret for security
JWT_SECRET=$(openssl rand -hex 32)
print_status "SUCCESS" "Generated fresh JWT secret"

# Create fresh secrets file
print_status "INFO" "Creating fresh configuration..."
cat > "$ARKFILE_DIR/etc/secrets.env" << EOF
# DEVELOPMENT RESET CONFIGURATION
# Generated: $(date)
# This is a fast development configuration - NOT FOR PRODUCTION

# Database Configuration
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
RQLITE_USERNAME=dev-user
RQLITE_PASSWORD=DevPassword123_$(openssl rand -hex 8)

# Arkfile Application Configuration
PORT=8080
JWT_SECRET=${JWT_SECRET}

# TLS Configuration
TLS_ENABLED=true
TLS_PORT=4443
TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/arkfile/server-cert.pem
TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/arkfile/server-key.pem

# Storage Configuration (Local MinIO for dev)
STORAGE_PROVIDER=local
MINIO_ROOT_USER=arkfile-dev
MINIO_ROOT_PASSWORD=DevPassword123_$(openssl rand -hex 8)
LOCAL_STORAGE_PATH=/opt/arkfile/var/lib/dev/minio/data

# Disable MinIO's automatic server-side encryption to preserve hash integrity.
MINIO_SSE_AUTO_ENCRYPTION=off

# Admin Configuration - DEV ONLY
ADMIN_USERNAMES=arkfile-dev-admin

# Dev/Test Admin API Configuration (CRITICAL: Must be false in production)
ADMIN_DEV_TEST_API_ENABLED=true

# Development Settings
REQUIRE_APPROVAL=false
ENABLE_REGISTRATION=true
DEBUG_MODE=true
LOG_LEVEL=info
EOF

chown "$USER:$GROUP" "$ARKFILE_DIR/etc/secrets.env"
chmod 640 "$ARKFILE_DIR/etc/secrets.env"
print_status "SUCCESS" "Fresh configuration created"

# Create fresh rqlite auth
RQLITE_PASSWORD=$(grep RQLITE_PASSWORD "$ARKFILE_DIR/etc/secrets.env" | cut -d= -f2)
cat > "$ARKFILE_DIR/etc/rqlite-auth.json" << EOF
[
  {
    "username": "dev-user",
    "password": "${RQLITE_PASSWORD}",
    "perms": ["all"]
  }
]
EOF

chown "$USER:$GROUP" "$ARKFILE_DIR/etc/rqlite-auth.json"
chmod 640 "$ARKFILE_DIR/etc/rqlite-auth.json"
print_status "SUCCESS" "Fresh rqlite authentication created"

print_status "SUCCESS" "Secret generation complete"
echo

# Step 6: Generate cryptographic keys
echo -e "${CYAN}Step 6: Generate cryptographic keys${NC}"
echo "====================================="

# Generate OPAQUE server keys
print_status "INFO" "Generating OPAQUE server keys..."
if ! ./scripts/setup/03-setup-opaque-keys.sh; then
    print_status "ERROR" "OPAQUE key generation failed - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "OPAQUE server keys generated"

# Generate JWT signing keys
print_status "INFO" "Generating JWT signing keys..."
if ! ./scripts/setup/04-setup-jwt-keys.sh; then
    print_status "ERROR" "JWT key generation failed - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "JWT signing keys generated"

# Generate TOTP master key
print_status "INFO" "Generating TOTP master key..."
if ! ./scripts/setup/06-setup-totp-keys.sh; then
    print_status "ERROR" "TOTP key generation failed - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "TOTP master key generated"

# Generate TLS certificates
print_status "INFO" "Generating TLS certificates..."
if ! ./scripts/setup/05-setup-tls-certs.sh; then
    print_status "ERROR" "TLS certificate generation failed - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "TLS certificates generated"

print_status "SUCCESS" "Cryptographic key generation complete"
echo

# Step 7: Setup MinIO and rqlite
echo -e "${CYAN}Step 7: Setting up MinIO and rqlite${NC}"
echo "==================================="

# Setup MinIO directories and service
print_status "INFO" "Setting up MinIO..."
if ! ./scripts/setup/07-setup-minio.sh; then
    print_status "ERROR" "MinIO setup failed - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "MinIO setup complete"

# Setup rqlite service
print_status "INFO" "Setting up rqlite..."
if ! ./scripts/setup/08-setup-rqlite.sh; then
    print_status "ERROR" "rqlite setup failed - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "rqlite setup complete"
echo

# Step 8: Start services
echo -e "${CYAN}Step 8: Starting services${NC}"
echo "========================="

# Install/update systemd service file
systemctl daemon-reload

# Start MinIO
print_status "INFO" "Starting MinIO..."
systemctl start minio
systemctl enable minio

if systemctl is-active --quiet minio; then
    print_status "SUCCESS" "MinIO started"
else
    print_status "ERROR" "MinIO failed to start"
    exit 1
fi

# Start rqlite
print_status "INFO" "Starting rqlite..."
systemctl start rqlite
systemctl enable rqlite

sleep 2
if systemctl is-active --quiet rqlite; then
    print_status "SUCCESS" "rqlite started"
else
    print_status "ERROR" "rqlite failed to start"
    exit 1
fi

# Wait for rqlite to be ready
print_status "INFO" "Waiting for rqlite to establish leadership..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -u "dev-user:${RQLITE_PASSWORD}" http://localhost:4001/status 2>/dev/null | grep -q '"ready":true'; then
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

# Database schema will be handled by the application using unified schema
print_status "INFO" "Database schema will be created by arkfile application on startup..."
print_status "INFO" "Using unified schema approach - no separate database setup needed"
print_status "SUCCESS" "Database setup delegated to application"

# Start Arkfile
print_status "INFO" "Starting Arkfile application..."
systemctl start arkfile
systemctl enable arkfile

sleep 2
if systemctl is-active --quiet arkfile; then
    print_status "SUCCESS" "Arkfile started"
else
    print_status "ERROR" "Arkfile failed to start"
    exit 1
fi
echo

# Step 9: Health verification
echo -e "${CYAN}Step 9: Health verification${NC}"
echo "==========================="

# Wait for Arkfile to be ready
print_status "INFO" "Waiting for Arkfile to start and be ready..."
max_attempts=15
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s http://localhost:8080/health 2>/dev/null | grep -q '"status":"ok"'; then
        print_status "SUCCESS" "Arkfile is running and responding"
        break
    fi
    sleep 3
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    print_status "ERROR" "Arkfile failed to start or respond within timeout"
    exit 1
fi

# Service status check
minio_status=$(systemctl is-active minio 2>/dev/null || echo "failed")
rqlite_status=$(systemctl is-active rqlite 2>/dev/null || echo "failed")
arkfile_status=$(systemctl is-active arkfile 2>/dev/null || echo "failed")

print_status "INFO" "Final service status:"
echo "    MinIO: ${minio_status}"
echo "    rqlite: ${rqlite_status}"
echo "    Arkfile: ${arkfile_status}"

# Verify all services are actually active
if [ "$minio_status" != "active" ] || [ "$rqlite_status" != "active" ] || [ "$arkfile_status" != "active" ]; then
    print_status "ERROR" "One or more services failed to start properly"
    exit 1
fi

echo

# Success message
echo -e "${GREEN}DEVELOPMENT RESET COMPLETE${NC}"
echo "=========================="
echo
echo -e "${BLUE}Your fresh Arkfile system is now running:${NC}"
echo -e "${GREEN}  HTTP Interface: http://localhost:8080${NC}"
echo -e "${GREEN}  HTTPS Interface: https://localhost:4443${NC}"
echo -e "${BLUE}     (Accept self-signed certificate warning)${NC}"
echo
echo -e "${BLUE}What was nuked:${NC}"
echo -e "${RED}  All user data and files${NC}"
echo -e "${RED}  All database content${NC}"
echo -e "${RED}  All secrets and credentials${NC}"
echo -e "${RED}  All logs${NC}"
echo
echo -e "${BLUE}What was preserved:${NC}"
echo -e "${GREEN}  Downloaded binaries (MinIO, rqlite)${NC}"
echo -e "${GREEN}  Compiled libraries (libopaque) - CACHED for speed${NC}"
echo -e "${GREEN}  System users and directory structure${NC}"
echo
echo -e "${BLUE}Build approach:${NC}"
echo -e "${GREEN}  Built directly in user directory${NC}"
echo -e "${GREEN}  Preserves libopaque libraries for faster rebuilds${NC}"
echo -e "${GREEN}  Uses existing Git submodules and vendor directory${NC}"
echo
echo -e "${BLUE}Ready for development testing!${NC}"
echo -e "${YELLOW}Admin user: arkfile-dev-admin${NC}"
echo -e "${YELLOW}Check logs: sudo journalctl -u arkfile -f${NC}"
echo

exit 0
