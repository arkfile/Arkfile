#!/bin/bash

# Source common variables and functions
source "$(dirname "$0")/../utils/common.sh" 2>/dev/null || source "$(dirname "$0")/../../utils/common.sh" 2>/dev/null || {
    # Fallback if common.sh cannot be found
    ARKFILE_DIR="/opt/arkfile"
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    NC='\033[0m'
    print_status() {
        echo -e "${GREEN}[$1] $2${NC}"
    }
    print_error() {
        echo -e "${RED}[ERROR] $1${NC}"
    }
}

MASTER_KEY_FILE="$ARKFILE_DIR/etc/keys/master.key"

print_status "INFO" "Setting up Master Key..."

# Ensure directory exists
if [ ! -d "$(dirname "$MASTER_KEY_FILE")" ]; then
    mkdir -p "$(dirname "$MASTER_KEY_FILE")"
    chown arkfile:arkfile "$(dirname "$MASTER_KEY_FILE")"
    chmod 700 "$(dirname "$MASTER_KEY_FILE")"
fi

# Check if Master Key file exists
if [ -f "$MASTER_KEY_FILE" ]; then
    print_status "INFO" "Master Key file already exists"
else
    print_status "INFO" "Generating new Master Key..."
    # Generate 32-byte hex-encoded key (64 hex characters)
    MASTER_KEY=$(openssl rand -hex 32)
    
    # Write to separate key file
    echo "ARKFILE_MASTER_KEY=$MASTER_KEY" > "$MASTER_KEY_FILE"
    
    print_status "SUCCESS" "Master Key generated and stored securely in $MASTER_KEY_FILE"
fi

# Ensure correct permissions
chown arkfile:arkfile "$MASTER_KEY_FILE"
chmod 400 "$MASTER_KEY_FILE" # Read-only for owner, no access for others
