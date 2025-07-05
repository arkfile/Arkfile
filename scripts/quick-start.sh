#!/bin/bash

# Quick Start Script for Arkfile - Get everything running quickly
# This script sets up a complete working Arkfile system for testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 Arkfile Quick Start${NC}"
echo -e "${BLUE}Setting up a complete working system...${NC}"
echo
echo -e "${RED}⚠️  SECURITY WARNING - DEMO CONFIGURATION ⚠️${NC}"
echo -e "${YELLOW}This quick-start creates a demo system with default credentials.${NC}"
echo -e "${YELLOW}This is NOT suitable for production use without security hardening.${NC}"
echo -e "${YELLOW}For production, regenerate ALL credentials and certificates.${NC}"
echo
echo -e "${BLUE}Demo credentials will be created:${NC}"
echo -e "${YELLOW}  • MinIO: arkfile-demo / TestPassword123_SecureMinIO${NC}"
echo -e "${YELLOW}  • JWT: demo-jwt-secret-change-for-production-use${NC}"
echo -e "${YELLOW}  • Admin: admin@arkfile.demo${NC}"
echo
read -p "Continue with demo setup? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Exiting. For production setup, see ./scripts/setup-foundation.sh"
    exit 0
fi
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}❌ Do not run this script as root${NC}"
    echo "Run as a regular user with sudo access"
    exit 1
fi

# Step 0: Stop any running Arkfile services
echo -e "${YELLOW}Step 0: Stopping any running Arkfile services...${NC}"

# Function to safely stop a service if it exists and is running
stop_service_if_running() {
    local service_name="$1"
    if sudo systemctl is-active --quiet "$service_name" 2>/dev/null; then
        echo "  Stopping $service_name..."
        sudo systemctl stop "$service_name" || {
            echo -e "${YELLOW}    Warning: Failed to stop $service_name gracefully, trying force stop...${NC}"
            sudo systemctl kill "$service_name" 2>/dev/null || true
            sleep 2
        }
    else
        echo "  $service_name is not running or doesn't exist"
    fi
}

# Function to safely disable a service if it exists
disable_service_if_exists() {
    local service_name="$1"
    if sudo systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
        echo "  Disabling $service_name..."
        sudo systemctl disable "$service_name" || echo -e "${YELLOW}    Warning: Failed to disable $service_name${NC}"
    fi
}

echo "Stopping Arkfile-related services..."

# Stop main Arkfile application
stop_service_if_running "arkfile"

# Stop MinIO and rqlite services
stop_service_if_running "minio"
stop_service_if_running "rqlite"

# Stop Caddy if it's running (reverse proxy)
stop_service_if_running "caddy"

echo "Waiting for services to fully stop..."
sleep 3

# Kill any remaining arkfile processes that might be lingering
echo "Checking for lingering arkfile processes..."
if pgrep -f "arkfile" > /dev/null; then
    echo "  Found running arkfile processes, terminating..."
    sudo pkill -f "arkfile" 2>/dev/null || true
    sleep 2
    
    # Force kill if still running
    if pgrep -f "arkfile" > /dev/null; then
        echo "  Force killing remaining arkfile processes..."
        sudo pkill -9 -f "arkfile" 2>/dev/null || true
        sleep 1
    fi
fi

echo -e "${GREEN}✅ Service cleanup completed${NC}"
echo

# Step 1: Foundation setup
echo -e "${YELLOW}Step 1: Setting up foundation (users, directories, keys, TLS)...${NC}"
./scripts/setup-foundation.sh --skip-tests
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Foundation setup failed${NC}"
    exit 1
fi

# Step 2: Set up services (MinIO and rqlite)
echo -e "${YELLOW}Step 2: Setting up storage and database services...${NC}"
sudo ./scripts/setup-minio.sh
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ MinIO setup failed${NC}"
    exit 1
fi

sudo ./scripts/setup-rqlite.sh
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ rqlite setup failed${NC}"
    exit 1
fi

# Step 3: Start services
echo -e "${YELLOW}Step 3: Starting services...${NC}"
echo "Creating demo environment configuration..."
sudo tee /opt/arkfile/etc/secrets.env > /dev/null << 'EOF'
# ⚠️  DEMO CONFIGURATION - NOT FOR PRODUCTION ⚠️
#
# This file contains demo credentials for quick-start testing.
# 
# 🔒 SECURITY WARNING: 
# These are DEFAULT DEMO VALUES and MUST be changed for production use!
#
# Before production deployment, run:
#   ./scripts/security-audit.sh
#   ./scripts/rotate-jwt-keys.sh
#   ./scripts/setup-tls-certs.sh --production

# Database Configuration
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
RQLITE_USERNAME=demo-user
RQLITE_PASSWORD=TestPassword123_Secure

# Arkfile Application Configuration
JWT_SECRET=demo-jwt-secret-change-for-production-use

# Storage Configuration (Local MinIO for demo)
STORAGE_PROVIDER=local
MINIO_ROOT_USER=arkfile-demo
MINIO_ROOT_PASSWORD=TestPassword123_SecureMinIO
LOCAL_STORAGE_PATH=/opt/arkfile/var/lib/minio/data

# Admin Configuration (comma-separated list)
ADMIN_EMAILS=admin@arkfile.demo

# Security Settings for Demo
REQUIRE_APPROVAL=false
ENABLE_REGISTRATION=true

# Development/Demo Settings
DEBUG_MODE=true
LOG_LEVEL=info
EOF

sudo chown arkfile:arkfile /opt/arkfile/etc/secrets.env
sudo chmod 640 /opt/arkfile/etc/secrets.env

echo "Creating rqlite authentication file..."
sudo tee /opt/arkfile/etc/rqlite-auth.json > /dev/null << 'EOF'
[
  {
    "username": "demo-user",
    "password": "TestPassword123_Secure",
    "perms": ["all"]
  }
]
EOF
sudo chown arkfile:arkfile /opt/arkfile/etc/rqlite-auth.json
sudo chmod 640 /opt/arkfile/etc/rqlite-auth.json

echo "Installing arkfile systemd service..."
sudo cp /opt/arkfile/releases/current/systemd/arkfile.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "Starting MinIO..."
sudo systemctl start minio
sudo systemctl enable minio

echo "Starting rqlite database..."
sudo systemctl start rqlite
sudo systemctl enable rqlite

# Wait for rqlite to be ready and establish leadership
echo "Waiting for rqlite to establish leadership..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -u demo-user:TestPassword123_Secure http://localhost:4001/status 2>/dev/null | grep -q '"ready":true'; then
        echo "  ✅ rqlite is ready and established as leader"
        break
    fi
    echo "  ⏳ Waiting for rqlite to be ready... (attempt $((attempt + 1))/$max_attempts)"
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}❌ rqlite failed to become ready within timeout${NC}"
    echo "Check rqlite status: sudo systemctl status rqlite"
    echo "Check rqlite logs: sudo journalctl -u rqlite -n 20"
    exit 1
fi

# Set up the database schema
echo "Setting up database schema..."
sudo ./scripts/setup-database.sh
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Database setup failed${NC}"
    exit 1
fi

echo "Starting Arkfile application..."
sudo systemctl start arkfile
sudo systemctl enable arkfile

# Wait for Arkfile to be ready
echo "Waiting for Arkfile to start and be ready..."
max_attempts=15
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s http://localhost:8080/health 2>/dev/null | grep -q '"status":"ok"'; then
        echo "  ✅ Arkfile is running and responding"
        break
    fi
    echo "  ⏳ Waiting for Arkfile to be ready... (attempt $((attempt + 1))/$max_attempts)"
    sleep 3
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}❌ Arkfile failed to start or respond within timeout${NC}"
    echo "Check Arkfile status: sudo systemctl status arkfile"
    echo "Check Arkfile logs: sudo journalctl -u arkfile -n 20"
    exit 1
fi

# Step 4: Verify everything is working
echo -e "${YELLOW}Step 4: Verifying system health...${NC}"

# Check service status
minio_status=$(sudo systemctl is-active minio || echo "failed")
rqlite_status=$(sudo systemctl is-active rqlite || echo "failed")
arkfile_status=$(sudo systemctl is-active arkfile || echo "failed")

echo "Service Status:"
echo "  MinIO: ${minio_status}"
echo "  rqlite: ${rqlite_status}"
echo "  Arkfile: ${arkfile_status}"

# Validate TLS certificates
echo -e "${YELLOW}Validating TLS certificates for secure local network access...${NC}"
if ./scripts/validate-certificates.sh >/dev/null 2>&1; then
    echo -e "${GREEN}✅ TLS certificates validated successfully${NC}"
    TLS_STATUS="✅ Available"
else
    echo -e "${YELLOW}⚠️  TLS certificate validation had warnings (non-critical)${NC}"
    TLS_STATUS="⚠️  Available with warnings"
fi

if [ "$arkfile_status" = "active" ]; then
    echo -e "${GREEN}✅ Arkfile is running!${NC}"
    
    # Get the port from config or use default
    arkfile_port=$(grep -o 'PORT=[0-9]*' /opt/arkfile/releases/current/.env 2>/dev/null | cut -d= -f2 || echo "8080")
    
    # Get local IP for network access
    local_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "192.168.x.x")
    
    echo
    echo -e "${GREEN}🎉 SETUP COMPLETE! 🎉${NC}"
    echo "================================"
    echo
    echo -e "${BLUE}Your Arkfile system is now running at:${NC}"
    echo -e "${GREEN}  📱 HTTP Interface: http://localhost:${arkfile_port}${NC}"
    echo -e "${GREEN}  🔒 HTTPS Interface: https://localhost:${arkfile_port}${NC}"
    echo -e "${BLUE}     (Accept self-signed certificate warning)${NC}"
    echo
    echo -e "${BLUE}🌐 Local Network Access:${NC}"
    echo -e "${GREEN}  📱 HTTP: http://${local_ip}:${arkfile_port}${NC}"
    echo -e "${GREEN}  🔒 HTTPS: https://${local_ip}:${arkfile_port}${NC}"
    echo -e "${BLUE}     (TLS Status: ${TLS_STATUS})${NC}"
    echo
    echo -e "${BLUE}Next Steps - Test Your System:${NC}"
    echo "1. Open your web browser"
    echo "2. Go to: https://localhost:${arkfile_port} (recommended) or http://localhost:${arkfile_port}"
    echo "   • For HTTPS: Accept the self-signed certificate warning"
    echo "3. Register a new account (e.g., admin@example.com)"
    echo "4. Upload a test file to verify encryption works"
    echo "5. Create a file share to test sharing functionality"
    echo
    echo -e "${BLUE}Administrative Commands:${NC}"
    echo "• View logs: sudo journalctl -u arkfile -f"
    echo "• Restart services: sudo systemctl restart arkfile"
    echo "• Check status: sudo systemctl status arkfile"
    echo "• Security audit: ./scripts/security-audit.sh"
    echo
    echo -e "${BLUE}Configuration Files:${NC}"
    echo "• Main config: /opt/arkfile/releases/current/.env"
    echo "• Service logs: /opt/arkfile/var/log/"
    echo "• Database: rqlite cluster (port 4001)"
    echo "• Object storage: /opt/arkfile/var/lib/prod/minio/"
    echo
    echo -e "${GREEN}✅ System is ready for use!${NC}"
    
else
    echo -e "${RED}❌ Arkfile failed to start${NC}"
    echo
    echo "Troubleshooting:"
    echo "1. Check logs: sudo journalctl -u arkfile --no-pager"
    echo "2. Check service status: sudo systemctl status arkfile"
    echo "3. Verify dependencies are running:"
    echo "   - MinIO: sudo systemctl status minio"
    echo "   - rqlite: sudo systemctl status rqlite"
    echo
    echo "Configuration check:"
    echo "4. Verify config file: cat /opt/arkfile/releases/current/.env"
    echo
    exit 1
fi
