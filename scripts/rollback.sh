#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
BASE_DIR="/opt/arkfile"
ENVIRONMENT=${1:-prod}  # Default to prod if no environment specified

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(prod|test)$ ]]; then
    echo -e "${RED}Invalid environment: ${ENVIRONMENT}. Must be 'prod' or 'test'${NC}"
    exit 1
fi

echo -e "${YELLOW}Starting rollback process for ${ENVIRONMENT} environment...${NC}"

# Get current and previous release directories
CURRENT_RELEASE=$(readlink -f "${BASE_DIR}/releases/current")
if [ ! -d "$CURRENT_RELEASE" ]; then
    echo -e "${RED}Error: Could not determine current release${NC}"
    exit 1
fi

# List all releases and find the previous one
PREVIOUS_RELEASE=$(ls -dt ${BASE_DIR}/releases/*/ | grep -v "$(basename ${CURRENT_RELEASE})" | head -1)
if [ -z "$PREVIOUS_RELEASE" ]; then
    echo -e "${RED}Error: No previous release found to roll back to${NC}"
    exit 1
fi

echo "Rolling back from $(basename ${CURRENT_RELEASE}) to $(basename ${PREVIOUS_RELEASE})"

# Update the current symlink
echo "Updating current symlink..."
sudo ln -snf "${PREVIOUS_RELEASE}" "${BASE_DIR}/releases/current"
sudo chown -h arkadmin:arkfile "${BASE_DIR}/releases/current"

# Copy binary to bin directory
echo "Restoring previous binary..."
sudo cp "${PREVIOUS_RELEASE}/${APP_NAME}" "${BASE_DIR}/bin/"
sudo chown arkadmin:arkfile "${BASE_DIR}/bin/${APP_NAME}"
sudo chmod 755 "${BASE_DIR}/bin/${APP_NAME}"

# Restart the service
echo "Restarting service..."
sudo systemctl restart "arkfile@${ENVIRONMENT}"

# Verify rollback
echo "Verifying rollback..."
systemctl status "arkfile@${ENVIRONMENT}" --no-pager

echo -e "${GREEN}Rollback complete!${NC}"
echo "Previous version: $(basename ${CURRENT_RELEASE})"
echo "Current version: $(basename ${PREVIOUS_RELEASE})"
echo -e "${YELLOW}Monitor the application logs:${NC}"
echo "  sudo journalctl -u arkfile@${ENVIRONMENT} -f"

# Optional: Mark the current release as a rollback
ROLLBACK_MARKER="${PREVIOUS_RELEASE}/ROLLBACK"
if [ ! -f "$ROLLBACK_MARKER" ]; then
    echo "$(date): Rolled back from $(basename ${CURRENT_RELEASE})" | sudo tee "$ROLLBACK_MARKER" > /dev/null
fi
