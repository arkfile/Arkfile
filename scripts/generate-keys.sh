#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to generate a new key
generate_key() {
    openssl rand -hex 32
}

echo -e "${GREEN}Generating encryption keys for Arkfile environments${NC}"
echo -e "${YELLOW}Note: Save these keys securely. They cannot be recovered if lost.${NC}\n"

echo "Production Environment Keys:"
echo "--------------------------"
echo -e "DB_ENCRYPTION_KEY=${GREEN}$(generate_key)${NC}"
echo -e "JWT_SECRET=${GREEN}$(generate_key)${NC}"
echo

echo "Test Environment Keys:"
echo "--------------------"
echo -e "DB_ENCRYPTION_KEY=${GREEN}$(generate_key)${NC}"
echo -e "JWT_SECRET=${GREEN}$(generate_key)${NC}"
echo

echo -e "${YELLOW}Instructions:${NC}"
echo "1. Copy these keys to their respective environment files:"
echo "   - Production: /opt/arkfile/etc/prod/secrets.env"
echo "   - Test: /opt/arkfile/etc/test/secrets.env"
echo "2. Keep a secure backup of these keys"
echo "3. Never share or commit these keys to version control"
echo
echo -e "${YELLOW}Security Note:${NC}"
echo "- These keys are used to encrypt sensitive data"
echo "- Loss of DB_ENCRYPTION_KEY will make encrypted databases inaccessible"
echo "- Keep keys separate between environments for security"
