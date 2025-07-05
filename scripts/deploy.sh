#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
BASE_DIR="/opt/arkfile"
REMOTE_USER="arkadmin"
REMOTE_HOST="arkfile.net"
BUILD_DIR="build"
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

# Set environment-specific variables
if [ "$ENVIRONMENT" = "test" ]; then
    REMOTE_HOST="test.arkfile.net"
fi

echo -e "${GREEN}Deploying ${APP_NAME} to ${ENVIRONMENT} environment on ${REMOTE_HOST}...${NC}"

# Build the application first
echo "Building application..."
./scripts/build.sh

# Ensure remote directory structure exists
echo "Checking remote directory structure..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo /opt/arkfile/scripts/setup-directories.sh"

# Copy deployment scripts first
echo "Copying setup scripts..."
scp scripts/setup-*.sh ${REMOTE_USER}@${REMOTE_HOST}:${BASE_DIR}/scripts/

# Make scripts executable
ssh ${REMOTE_USER}@${REMOTE_HOST} "chmod +x ${BASE_DIR}/scripts/setup-*.sh"

# Create new release directory on remote
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RELEASE_DIR="${BASE_DIR}/releases/${TIMESTAMP}"
echo "Creating release directory: ${RELEASE_DIR}"

# Copy files to remote server
echo "Copying files to remote server..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo mkdir -p ${RELEASE_DIR}"
rsync -avz --progress ${BUILD_DIR}/ ${REMOTE_USER}@${REMOTE_HOST}:${RELEASE_DIR}/

# Update permissions on remote
echo "Setting permissions..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo chown -R arkadmin:arkfile ${RELEASE_DIR} && \
    sudo chmod 755 ${RELEASE_DIR}/${APP_NAME}"

# Update the current symlink
echo "Updating current symlink..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo ln -snf ${RELEASE_DIR} ${BASE_DIR}/releases/current && \
    sudo chown -h arkadmin:arkfile ${BASE_DIR}/releases/current"

# Copy binary to bin directory
echo "Installing binary..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo cp ${RELEASE_DIR}/${APP_NAME} ${BASE_DIR}/bin/ && \
    sudo chown arkadmin:arkfile ${BASE_DIR}/bin/${APP_NAME} && \
    sudo chmod 755 ${BASE_DIR}/bin/${APP_NAME}"

# Set up storage and database services
echo "Setting up rqlite..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo ${BASE_DIR}/scripts/setup-rqlite.sh"
echo "Setting up MinIO..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo ${BASE_DIR}/scripts/setup-minio.sh"

# Copy and update service files
echo "Setting up systemd services..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo cp ${RELEASE_DIR}/systemd/arkfile.service /etc/systemd/system/ && \
    sudo cp ${RELEASE_DIR}/systemd/rqlite.service /etc/systemd/system/ && \
    sudo cp ${RELEASE_DIR}/systemd/rqlite /etc/systemd/system/ && \
    sudo cp ${RELEASE_DIR}/systemd/minio.service /etc/systemd/system/ && \
    sudo cp ${RELEASE_DIR}/systemd/minio /etc/systemd/system/ && \
    sudo systemctl daemon-reload"

# Start and enable infrastructure services
echo "Starting infrastructure services..."
# Start rqlite services
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo systemctl enable rqlite${ENVIRONMENT} && \
    sudo systemctl start rqlite${ENVIRONMENT} || true && \
    sudo systemctl enable rqlite && \
    sudo systemctl start rqlite"

# Start MinIO services if using local/cluster storage
if [[ $(ssh ${REMOTE_USER}@${REMOTE_HOST} "grep '^STORAGE_PROVIDER=\(local\|cluster\)' ${BASE_DIR}/etc/${ENVIRONMENT}/secrets.env") ]]; then
    echo "Starting MinIO services..."
    ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo systemctl enable minio${ENVIRONMENT} && \
        sudo systemctl start minio${ENVIRONMENT} || true && \
        sudo systemctl enable minio && \
        sudo systemctl start minio"
fi

# Wait for services to be ready
echo "Waiting for services to be ready..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sleep 5"

# Restart application services
echo "Restarting services..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "sudo systemctl restart arkfile${ENVIRONMENT} && \
    sudo systemctl restart caddy"

# Verify deployment
echo "Verifying deployment..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "systemctl status rqlite${ENVIRONMENT} --no-pager && \
    systemctl status arkfile${ENVIRONMENT} --no-pager && \
    systemctl status caddy --no-pager"

# Verify MinIO if using local/cluster storage
if [[ $(ssh ${REMOTE_USER}@${REMOTE_HOST} "grep '^STORAGE_PROVIDER=\(local\|cluster\)' ${BASE_DIR}/etc/${ENVIRONMENT}/secrets.env") ]]; then
    ssh ${REMOTE_USER}@${REMOTE_HOST} "systemctl status minio${ENVIRONMENT} --no-pager"
fi

# Clean up old releases (keep last 5)
echo "Cleaning up old releases..."
ssh ${REMOTE_USER}@${REMOTE_HOST} "cd ${BASE_DIR}/releases && \
    ls -t | tail -n +6 | xargs -I {} sudo rm -rf {}"

echo -e "${GREEN}Deployment complete!${NC}"
echo -e "${YELLOW}Service Stack:${NC}"
echo "  1. rqlite: Distributed database cluster"
echo "  2. arkfile: Main application service"
echo "  3. Caddy: Web server and reverse proxy"

echo -e "${YELLOW}Useful commands:${NC}"
echo "  View database logs: sudo journalctl -u rqlite${ENVIRONMENT} -f"
echo "  View application logs: sudo journalctl -u arkfile${ENVIRONMENT} -f"
echo "  View Caddy logs: sudo journalctl -u caddy -f"
echo "  Check rqlite status: systemctl status rqlite${ENVIRONMENT}"
echo "  Check app status: systemctl status arkfile${ENVIRONMENT}"
echo "  Check full stack: systemctl status rqlite${ENVIRONMENT} arkfile${ENVIRONMENT} caddy"
echo "  Rollback to previous version: ${BASE_DIR}/scripts/rollback.sh ${ENVIRONMENT}"
