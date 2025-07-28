#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Setting up database schema...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This script must be run with sudo${NC}"
    exit 1
fi

# Check if arkfile user exists
if ! id arkfile >/dev/null 2>&1; then
    echo -e "${RED}arkfile user does not exist. Run setup-users.sh first.${NC}"
    exit 1
fi

# Check if rqlite is running
if ! systemctl is-active --quiet rqlite; then
    echo -e "${RED}rqlite service is not running. Start it first with: sudo systemctl start rqlite${NC}"
    exit 1
fi

# Wait for rqlite to be ready
echo "Waiting for rqlite to be ready..."
sleep 3

# Check if database schema file exists
SCHEMA_FILE="/opt/arkfile/database/schema_extensions.sql"
if [ ! -f "$SCHEMA_FILE" ]; then
    echo -e "${RED}Schema file not found: $SCHEMA_FILE${NC}"
    echo "Make sure to run the build script first to deploy database files."
    exit 1
fi

echo "Found schema file: $SCHEMA_FILE"

# Get database credentials
USERNAME=$(grep "RQLITE_USERNAME=" /opt/arkfile/etc/secrets.env | cut -d'=' -f2)
PASSWORD=$(grep "RQLITE_PASSWORD=" /opt/arkfile/etc/secrets.env | cut -d'=' -f2)

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo -e "${RED}Could not find database credentials in /opt/arkfile/etc/secrets.env${NC}"
    exit 1
fi

echo "Using database credentials for user: $USERNAME"

# Function to print a failure message and exit
fail() {
    echo -e "${RED}❌ $1${NC}" >&2
    exit 1
}

# Function to execute SQL statements via rqlite HTTP API
execute_sql_rqlite() {
    local sql="$1"
    local response
    response=$(curl -s -H "Content-Type: application/json" \
        -X POST "http://$USERNAME:$PASSWORD@localhost:4001/db/execute" \
        -d "[\"$sql\"]")
    
    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}    -> rqlite command failed for statement:${NC}"
        echo -e "${YELLOW}       $sql${NC}"
        echo -e "${RED}       Response: $response${NC}"
        return 1
    fi
    return 0
}

# Test database connectivity
echo "Testing rqlite database connectivity..."
test_response=$(curl -s -H "Content-Type: application/json" \
    -X POST "http://$USERNAME:$PASSWORD@localhost:4001/db/query" \
    -d '[["SELECT 1 as test"]]')

if echo "$test_response" | grep -q '"values":\[\[1\]\]'; then
    echo -e "${GREEN}✅ rqlite database connection successful!${NC}"
else
    fail "Could not connect to rqlite database. Response: $test_response"
fi

echo -e "${GREEN}✅ Database setup completed successfully!${NC}"

echo -e "${YELLOW}📝 Note: Schema creation will be handled automatically by arkfile service${NC}"
echo "   Base tables and extensions will be created when arkfile starts."

echo "Database connectivity verified. Ready for arkfile service to start."
