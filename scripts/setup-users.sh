#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
GROUP_NAME="arkfile"
ADMIN_USER="arkadmin"
ENV_USERS=("arkprod" "arktest")
BASE_DIR="/opt/arkfile"

echo -e "${GREEN}Setting up Arkfile users and permissions...${NC}"

# Create service group
if ! getent group ${GROUP_NAME} >/dev/null; then
    echo -e "${YELLOW}Creating service group ${GROUP_NAME}...${NC}"
    sudo groupadd -r ${GROUP_NAME}
else
    echo "Group ${GROUP_NAME} already exists"
fi

# Create main service user
if ! getent passwd ${ADMIN_USER} >/dev/null; then
    echo -e "${YELLOW}Creating main service user ${ADMIN_USER}...${NC}"
    sudo useradd -r \
        -g ${GROUP_NAME} \
        -d ${BASE_DIR} \
        -s /sbin/nologin \
        -c "Arkfile Service Account" \
        ${ADMIN_USER}
else
    echo "User ${ADMIN_USER} already exists"
fi

# Create environment-specific users
for user in "${ENV_USERS[@]}"; do
    env=${user#ark}  # Remove 'ark' prefix to get environment name
    if ! getent passwd ${user} >/dev/null; then
        echo -e "${YELLOW}Creating ${env} service user ${user}...${NC}"
        sudo useradd -r \
            -g ${GROUP_NAME} \
            -d "${BASE_DIR}/${env}" \
            -s /sbin/nologin \
            -c "Arkfile ${env^} Service Account" \
            ${user}
    else
        echo "User ${user} already exists"
    fi
done

echo -e "${GREEN}User setup complete!${NC}"
echo "Created group: ${GROUP_NAME}"
echo "Created admin user: ${ADMIN_USER}"
echo "Created environment users: ${ENV_USERS[*]}"
