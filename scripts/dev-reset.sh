#!/bin/bash

# Arkfile Development Reset Script
# Fast reset for development iteration - nukes data but preserves binaries

set -e

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run with sudo privileges${NC}"
    exit 1
fi

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
    rm -rf "$ARKFILE_DIR/var/lib/"*/rqlite/data/* 2>/dev/null || true
    rm -rf "$ARKFILE_DIR/var/lib/"*/database/* 2>/dev/null || true
    
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
    
    print_status "SUCCESS" "Data and secrets destroyed"
else
    print_status "WARNING" "Arkfile directory not found, skipping data destruction"
fi
echo

# Step 3: Build application directly in current directory
echo -e "${CYAN}Step 3: Building application directly${NC}"
echo "====================================="

print_status "INFO" "Building application in current directory..."

# Set a fallback version for development
FALLBACK_VERSION="dev-$(date +%Y%m%d-%H%M%S)"

# Build directly without user switching
if ! bash -c "
    export VERSION='$FALLBACK_VERSION' &&
    ./scripts/setup/build.sh
"; then
    print_status "ERROR" "Build script failed - this is CRITICAL"
    exit 1
fi

print_status "SUCCESS" "Application build and asset compilation complete"

# Copy built binary to arkfile location
print_status "INFO" "Deploying built binary to arkfile location..."
mkdir -p "$ARKFILE_DIR/bin"
cp arkfile "$ARKFILE_DIR/bin/" 2>/dev/null || true
chown "$USER:$GROUP" "$ARKFILE_DIR/bin/arkfile" 2>/dev/null || true
chmod 755 "$ARKFILE_DIR/bin/arkfile" 2>/dev/null || true
print_status "SUCCESS" "Binary deployed"
echo

# Step 6: Generate fresh secrets
echo -e "${CYAN}Step 6: Generating fresh secrets${NC}"
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

# Admin Configuration
ADMIN_EMAILS=admin@dev.local

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

# Step 7: Start services
echo -e "${CYAN}Step 7: Starting services${NC}"
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

# Set up fresh database schema
print_status "INFO" "Setting up database schema with improved script..."
if ! ./scripts/setup/06-setup-database-improved.sh; then
    print_status "ERROR" "Database schema setup FAILED - this is CRITICAL"
    exit 1
fi
print_status "SUCCESS" "Database schema created successfully"

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

# Step 8: Health verification
echo -e "${CYAN}Step 8: Health verification${NC}"
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
echo -e "${GREEN}  Compiled libraries (libopaque)${NC}"
echo -e "${GREEN}  System users and directory structure${NC}"
echo
echo -e "${BLUE}Build approach:${NC}"
echo -e "${GREEN}  Clean source copy to /opt/arkfile/src/current/${NC}"
echo -e "${GREEN}  Built by arkfile user with its own Go/bun${NC}"
echo -e "${GREEN}  No user directory modification${NC}"
echo
echo -e "${BLUE}Ready for development testing!${NC}"
echo -e "${YELLOW}Admin user: admin@dev.local${NC}"
echo -e "${YELLOW}Check logs: sudo journalctl -u arkfile -f${NC}"
echo

exit 0
