#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
GROUP_NAME="arkfile"
SERVICE_USER="arkfile"
BASE_DIR="/opt/arkfile"

echo -e "${GREEN}Setting up Arkfile service user...${NC}"

# Create service group
if ! getent group ${GROUP_NAME} >/dev/null; then
    echo -e "${YELLOW}Creating service group ${GROUP_NAME}...${NC}"
    sudo groupadd -r ${GROUP_NAME}
else
    echo "Group ${GROUP_NAME} already exists"
fi

# Create single service user
if ! getent passwd ${SERVICE_USER} >/dev/null; then
    echo -e "${YELLOW}Creating service user ${SERVICE_USER}...${NC}"
    sudo useradd -r \
        -g ${GROUP_NAME} \
        -d ${BASE_DIR} \
        -s /sbin/nologin \
        -c "Arkfile Service Account" \
        ${SERVICE_USER}
else
    echo "User ${SERVICE_USER} already exists"
fi

echo -e "${GREEN}User setup complete!${NC}"
echo "Created group: ${GROUP_NAME}"
echo "Created service user: ${SERVICE_USER}"
echo "Home directory: ${BASE_DIR}"
echo "Shell: /sbin/nologin (security)"
