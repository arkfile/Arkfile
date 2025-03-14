#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BASE_DIR="/opt/arkfile"
GROUP_NAME="arkfile"
ADMIN_USER="arkadmin"
ENVIRONMENTS=("prod" "test")

echo -e "${GREEN}Setting up Arkfile directory structure...${NC}"

# Create base directory structure
echo "Creating main directories..."
sudo install -d -m 755 -o ${ADMIN_USER} -g ${GROUP_NAME} ${BASE_DIR}
sudo install -d -m 755 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/bin"
sudo install -d -m 750 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/etc"
sudo install -d -m 750 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/var"
sudo install -d -m 750 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/var/lib"
sudo install -d -m 750 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/var/log"
sudo install -d -m 755 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/var/run"
sudo install -d -m 755 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/webroot"
sudo install -d -m 755 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/releases"

# Create environment-specific directories
for env in "${ENVIRONMENTS[@]}"; do
    echo "Creating ${env} environment directories..."
    user="ark${env}"
    
    # Configuration directories
    sudo install -d -m 750 -o ${user} -g ${GROUP_NAME} "${BASE_DIR}/etc/${env}"
    sudo install -d -m 750 -o ${user} -g ${GROUP_NAME} "${BASE_DIR}/var/lib/${env}"
    sudo install -d -m 750 -o ${user} -g ${GROUP_NAME} "${BASE_DIR}/var/log/${env}"
    
    # rqlite data directories
    sudo install -d -m 750 -o ${user} -g ${GROUP_NAME} "${BASE_DIR}/var/lib/${env}/rqlite"
    sudo install -d -m 750 -o ${user} -g ${GROUP_NAME} "${BASE_DIR}/var/lib/${env}/rqlite/data"
    
    # MinIO data directories
    sudo install -d -m 750 -o ${user} -g ${GROUP_NAME} "${BASE_DIR}/var/lib/${env}/minio"
    sudo install -d -m 750 -o ${user} -g ${GROUP_NAME} "${BASE_DIR}/var/lib/${env}/minio/data"
done

# Create the configs directory for environment-specific configurations
sudo install -d -m 750 -o ${ADMIN_USER} -g ${GROUP_NAME} "${BASE_DIR}/configs"
for env in "${ENVIRONMENTS[@]}"; do
    sudo install -d -m 750 -o "ark${env}" -g ${GROUP_NAME} "${BASE_DIR}/configs/${env}"
done

echo -e "${GREEN}Directory setup complete!${NC}"
echo "Base directory: ${BASE_DIR}"
echo "Created directories for environments: ${ENVIRONMENTS[*]}"

# Display directory structure
echo -e "${YELLOW}Directory structure:${NC}"
tree -L 4 --dirsfirst ${BASE_DIR}
