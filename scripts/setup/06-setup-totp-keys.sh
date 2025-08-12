#!/bin/bash

# TOTP Key Setup Script
# Sets up TOTP master key for encryption/decryption of user TOTP secrets

set -e

# Configuration
ARKFILE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"
KEYS_DIR="$ARKFILE_DIR/etc/keys"
TOTP_KEY_FILE="$KEYS_DIR/totp_master.key"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Setting up TOTP master key...${NC}"

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_status "ERROR" "This script must be run as root"
    exit 1
fi

# Verify arkfile user exists
if ! id "$USER" >/dev/null 2>&1; then
    print_status "ERROR" "User $USER does not exist. Run setup scripts in order."
    exit 1
fi

# Ensure keys directory exists
if [ ! -d "$KEYS_DIR" ]; then
    print_status "INFO" "Creating keys directory..."
    mkdir -p "$KEYS_DIR"
    chown "$USER:$GROUP" "$KEYS_DIR"
    chmod 750 "$KEYS_DIR"
fi

# Check if TOTP master key already exists
if [ -f "$TOTP_KEY_FILE" ]; then
    print_status "WARNING" "TOTP master key already exists"
    print_status "INFO" "Key file: $TOTP_KEY_FILE"
    print_status "INFO" "Key size: $(wc -c < "$TOTP_KEY_FILE") bytes"
    print_status "INFO" "Permissions: $(stat -c %a "$TOTP_KEY_FILE")"
    print_status "INFO" "Owner: $(stat -c %U:%G "$TOTP_KEY_FILE")"
    
    # Validate existing key
    KEY_SIZE=$(wc -c < "$TOTP_KEY_FILE")
    if [ "$KEY_SIZE" -eq 32 ]; then
        print_status "SUCCESS" "Existing TOTP master key is valid (32 bytes)"
        echo -e "${GREEN}✓ TOTP master key setup complete!${NC}"
        exit 0
    else
        print_status "WARNING" "Existing TOTP master key has invalid size ($KEY_SIZE bytes, expected 32)"
        print_status "INFO" "Regenerating TOTP master key..."
        rm -f "$TOTP_KEY_FILE"
    fi
fi

# Generate new TOTP master key
print_status "INFO" "Generating TOTP master key..."

if ! command -v openssl >/dev/null 2>&1; then
    print_status "ERROR" "OpenSSL is required but not installed"
    exit 1
fi

# Always generate a secure random key - the application will handle dev vs prod logic
# This ensures the setup script never hardcodes keys that could leak into production
if ! openssl rand -out "$TOTP_KEY_FILE" 32; then
    print_status "ERROR" "Failed to generate TOTP master key"
    exit 1
fi

print_status "SUCCESS" "TOTP master key generated"
print_status "INFO" "The application will handle dev/prod key logic at runtime"

# Set secure permissions
chmod 600 "$TOTP_KEY_FILE"
chown "$USER:$GROUP" "$TOTP_KEY_FILE"

# Verify the generated key
KEY_SIZE=$(wc -c < "$TOTP_KEY_FILE")
if [ "$KEY_SIZE" -ne 32 ]; then
    print_status "ERROR" "Generated key has wrong size: $KEY_SIZE bytes (expected 32)"
    rm -f "$TOTP_KEY_FILE"
    exit 1
fi

print_status "SUCCESS" "TOTP master key secured"

# Validation and reporting
echo
print_status "INFO" "Validating key setup..."
echo -e "  ${GREEN}✓${NC} $TOTP_KEY_FILE: $(stat -c %a "$TOTP_KEY_FILE") $(stat -c %U:%G "$TOTP_KEY_FILE")"

# Test key readability by arkfile user
if sudo -u "$USER" test -r "$TOTP_KEY_FILE"; then
    print_status "SUCCESS" "TOTP master key is readable by $USER"
else
    print_status "ERROR" "TOTP master key is not readable by $USER"
    exit 1
fi

# Summary
echo
echo -e "${GREEN}✓ TOTP master key generated and secured${NC}"
echo -e "${BLUE}Location:${NC} $TOTP_KEY_FILE"
echo -e "${BLUE}Size:${NC} 32 bytes (256-bit key)"
echo -e "${BLUE}Permissions:${NC} Private key (600)"
echo -e "${BLUE}Owner:${NC} $USER:$GROUP"
echo

print_status "SUCCESS" "TOTP key setup complete!"

echo
echo -e "${YELLOW}Note:${NC} This master key is used to encrypt/decrypt user TOTP secrets."
echo -e "${YELLOW}      Keep this key secure and back it up in production environments.${NC}"
echo -e "${YELLOW}      If this key is lost, all user TOTP setups will become unusable.${NC}"
