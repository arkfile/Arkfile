#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
REMOTE_USER="app"
REMOTE_HOST="arkfile.net"
REMOTE_DIR="/opt/${APP_NAME}"
BUILD_DIR="build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if host is provided
if [ "$1" != "" ]; then
    REMOTE_HOST=$1
fi

echo -e "${GREEN}Deploying ${APP_NAME} to ${REMOTE_HOST}...${NC}"

# Build the application first
echo "Building application..."
./scripts/build.sh

# Create remote directory if it doesn't exist
echo "Preparing remote directory..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo mkdir -p ${REMOTE_DIR} && sudo chown ${REMOTE_USER}:${REMOTE_USER} ${REMOTE_DIR}"

# Copy files to remote server
echo "Copying files to remote server..."
rsync -avz --progress ${BUILD_DIR}/ ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/

# Set up systemd services
echo "Setting up systemd services..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo cp ${REMOTE_DIR}/systemd/*.service /etc/systemd/system/ && \
    sudo systemctl daemon-reload"

# Install or update application
echo "Installing application..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "cd ${REMOTE_DIR} && \
    [ -f .env ] || cp .env.example .env && \
    sudo systemctl restart ${APP_NAME} && \
    sudo systemctl restart caddy"

# Verify deployment
echo "Verifying deployment..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "systemctl status ${APP_NAME} --no-pager && \
    systemctl status caddy --no-pager"

echo -e "${GREEN}Deployment complete!${NC}"
echo -e "${YELLOW}Remember to check the logs:${NC}"
echo "  sudo journalctl -u ${APP_NAME} -f"
echo "  sudo journalctl -u caddy -f"
