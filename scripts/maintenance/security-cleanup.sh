#!/bin/bash

# Security Cleanup Script for Arkfile
# This script forces invalidation of all existing tokens and clears browser storage

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}[LOCK] Arkfile Security Cleanup${NC}"
echo -e "${RED}This script will invalidate ALL existing tokens and sessions${NC}"
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}[X] Do not run this script as root${NC}"
    echo "Run as a regular user with sudo access"
    exit 1
fi

# Step 1: Stop Arkfile service
echo -e "${YELLOW}Step 1: Stopping Arkfile service...${NC}"
if sudo systemctl is-active --quiet arkfile; then
    sudo systemctl stop arkfile
    echo -e "${GREEN}[OK] Arkfile service stopped${NC}"
else
    echo -e "${YELLOW}[i] Arkfile service was not running${NC}"
fi

# Step 2: Generate new JWT secret
echo -e "${YELLOW}Step 2: Generating new JWT secret...${NC}"
NEW_JWT_SECRET=$(openssl rand -hex 32)

# Update the secrets file
SECRETS_FILE="/opt/arkfile/etc/secrets.env"
if [ -f "$SECRETS_FILE" ]; then
    sudo cp "$SECRETS_FILE" "$SECRETS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    sudo sed -i "s/JWT_SECRET=.*/JWT_SECRET=${NEW_JWT_SECRET}/" "$SECRETS_FILE"
    echo -e "${GREEN}[OK] JWT secret updated (old secret backed up)${NC}"
else
    echo -e "${YELLOW}[WARNING]  Secrets file not found at $SECRETS_FILE${NC}"
fi

# Step 3: Clear database token tables
echo -e "${YELLOW}Step 3: Clearing all authentication tokens from database...${NC}"

# Get database connection info
RQLITE_ADDRESS=$(sudo grep -o 'RQLITE_ADDRESS=.*' "$SECRETS_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "http://localhost:4001")
RQLITE_USERNAME=$(sudo grep -o 'RQLITE_USERNAME=.*' "$SECRETS_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "demo-user")
RQLITE_PASSWORD=$(sudo grep -o 'RQLITE_PASSWORD=.*' "$SECRETS_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "TestPassword123_Secure")

# Clear all authentication-related tables
echo "Clearing revoked_tokens table..."
curl -s -u "$RQLITE_USERNAME:$RQLITE_PASSWORD" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '["DELETE FROM revoked_tokens"]' \
    "$RQLITE_ADDRESS/db/execute" > /dev/null

echo "Clearing refresh_tokens table..."
curl -s -u "$RQLITE_USERNAME:$RQLITE_PASSWORD" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '["DELETE FROM refresh_tokens"]' \
    "$RQLITE_ADDRESS/db/execute" > /dev/null

echo "Clearing totp_usage_log table..."
curl -s -u "$RQLITE_USERNAME:$RQLITE_PASSWORD" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '["DELETE FROM totp_usage_log"]' \
    "$RQLITE_ADDRESS/db/execute" > /dev/null

echo "Clearing totp_recovery_log table..."
curl -s -u "$RQLITE_USERNAME:$RQLITE_PASSWORD" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '["DELETE FROM totp_recovery_log"]' \
    "$RQLITE_ADDRESS/db/execute" > /dev/null

echo -e "${GREEN}[OK] Database authentication tables cleared${NC}"

# Step 4: Update session security version
echo -e "${YELLOW}Step 4: Updating session security version...${NC}"
SECURITY_VERSION=$(date +%s)
curl -s -u "$RQLITE_USERNAME:$RQLITE_PASSWORD" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "[\"INSERT OR REPLACE INTO system_config (key, value) VALUES ('security_version', '$SECURITY_VERSION')\"]" \
    "$RQLITE_ADDRESS/db/execute" > /dev/null
echo -e "${GREEN}[OK] Security version updated to $SECURITY_VERSION${NC}"

# Step 5: Restart Arkfile service
echo -e "${YELLOW}Step 5: Restarting Arkfile service...${NC}"
sudo systemctl start arkfile

# Wait for service to be ready
echo "Waiting for Arkfile to start..."
max_attempts=10
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s http://localhost:8080/health 2>/dev/null | grep -q '"status":"ok"'; then
        echo -e "${GREEN}[OK] Arkfile is running and responding${NC}"
        break
    fi
    echo "  Waiting for Arkfile to be ready... (attempt $((attempt + 1))/$max_attempts)"
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}[X] Arkfile failed to start within timeout${NC}"
    echo "Check status: sudo systemctl status arkfile"
    exit 1
fi

# Step 6: Display browser cleanup instructions
echo
echo -e "${RED}CRITICAL SECURITY NOTICE ${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
echo
echo -e "${YELLOW}ALL EXISTING TOKENS HAVE BEEN INVALIDATED${NC}"
echo
echo -e "${RED}USERS MUST CLEAR THEIR BROWSER STORAGE:${NC}"
echo
echo -e "${BLUE}For Chrome/Edge/Brave:${NC}"
echo "1. Open Developer Tools (F12)"
echo "2. Go to Application tab"
echo "3. Select 'Local Storage' → 'https://localhost:4443'"
echo "4. Delete 'token' and 'refreshToken' entries"
echo "5. Refresh the page"
echo
echo -e "${BLUE}For Firefox:${NC}"
echo "1. Open Developer Tools (F12)"
echo "2. Go to Storage tab"
echo "3. Select 'Local Storage' → 'https://localhost:4443'"
echo "4. Delete 'token' and 'refreshToken' entries"
echo "5. Refresh the page"
echo
echo -e "${BLUE}Alternative (clears all site data):${NC}"
echo "1. Go to your browser settings"
echo "2. Find 'Site Settings' or 'Privacy and Security'"
echo "3. Search for 'localhost' or your domain"
echo "4. Click 'Clear data' or 'Remove all data'"
echo
echo -e "${RED}OR USERS CAN USE INCOGNITO/PRIVATE BROWSING MODE${NC}"
echo
echo -e "${YELLOW}ADMINISTRATORS SHOULD NOTIFY ALL USERS TO:${NC}"
echo "- Clear their browser storage (instructions above)"
echo "- Log in again with their credentials"
echo "- Set up TOTP again if they had it enabled"
echo
echo -e "${GREEN}[OK] Security cleanup completed successfully${NC}"
echo -e "${BLUE}New JWT secret: ${NEW_JWT_SECRET:0:16}... (truncated for security)${NC}"
echo -e "${BLUE}Security version: $SECURITY_VERSION${NC}"
