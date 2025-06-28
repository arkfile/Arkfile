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

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}❌ Do not run this script as root${NC}"
    echo "Run as a regular user with sudo access"
    exit 1
fi

# Step 1: Foundation setup
echo -e "${YELLOW}Step 1: Setting up foundation (users, directories, keys)...${NC}"
./scripts/setup-foundation.sh --skip-tests --skip-tls
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
echo "Starting MinIO..."
sudo systemctl start minio@node1
sudo systemctl enable minio@node1

echo "Starting rqlite database..."
sudo systemctl start rqlite@node1
sudo systemctl enable rqlite@node1

echo "Starting Arkfile application..."
sudo systemctl start arkfile
sudo systemctl enable arkfile

# Wait a moment for services to start
echo "Waiting for services to initialize..."
sleep 5

# Step 4: Verify everything is working
echo -e "${YELLOW}Step 4: Verifying system health...${NC}"

# Check service status
minio_status=$(sudo systemctl is-active minio@node1 || echo "failed")
rqlite_status=$(sudo systemctl is-active rqlite@node1 || echo "failed")
arkfile_status=$(sudo systemctl is-active arkfile || echo "failed")

echo "Service Status:"
echo "  MinIO: ${minio_status}"
echo "  rqlite: ${rqlite_status}"
echo "  Arkfile: ${arkfile_status}"

if [ "$arkfile_status" = "active" ]; then
    echo -e "${GREEN}✅ Arkfile is running!${NC}"
    
    # Get the port from config or use default
    arkfile_port=$(grep -o 'PORT=[0-9]*' /opt/arkfile/releases/current/.env 2>/dev/null | cut -d= -f2 || echo "8080")
    
    echo
    echo -e "${GREEN}🎉 SETUP COMPLETE! 🎉${NC}"
    echo "================================"
    echo
    echo -e "${BLUE}Your Arkfile system is now running at:${NC}"
    echo -e "${GREEN}  📱 Web Interface: http://localhost:${arkfile_port}${NC}"
    echo
    echo -e "${BLUE}Next Steps - Test Your System:${NC}"
    echo "1. Open your web browser"
    echo "2. Go to: http://localhost:${arkfile_port}"
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
    echo "   - MinIO: sudo systemctl status minio@node1"
    echo "   - rqlite: sudo systemctl status rqlite@node1"
    echo
    echo "Configuration check:"
    echo "4. Verify config file: cat /opt/arkfile/releases/current/.env"
    echo
    exit 1
fi
