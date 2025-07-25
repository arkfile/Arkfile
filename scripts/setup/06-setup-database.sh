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

# Apply schema extensions to rqlite distributed database
echo "Applying schema extensions to rqlite database..."
echo "Processing schema file: $SCHEMA_FILE"

# Read the entire schema file and process it statement by statement.
# This handles multi-line statements correctly.
sed 's/--.*//' "$SCHEMA_FILE" | tr -s '\n' ' ' | sed 's/;/;\n/g' | while read -r sql_statement; do
    sql_statement=$(echo "$sql_statement" | tr -s ' ' | sed 's/^ *//;s/ *$//')
    if [[ -n "$sql_statement" ]]; then
        if ! execute_sql_rqlite "$sql_statement"; then
            fail "Could not apply schema statement: $sql_statement"
        fi
    fi
done

echo -e "${GREEN}✅ Database schema initialization completed successfully!${NC}"

# Verify critical tables exist using rqlite queries
echo "Verifying OPAQUE tables..."
opaque_response=$(curl -s -H "Content-Type: application/json" \
    -X POST "http://$USERNAME:$PASSWORD@localhost:4001/db/query" \
    -d '[["SELECT name FROM sqlite_master WHERE type='\''table'\'' AND name IN ('\''opaque_user_data'\'', '\''opaque_server_keys'\'')"]]')

opaque_count=$(echo "$opaque_response" | jq -r '.results[0].values | length // 0')
if [[ "$opaque_count" -ge 1 ]]; then
    echo -e "${GREEN}✅ OPAQUE tables verified successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  OPAQUE tables may not have been created properly${NC}"
fi

echo "Verifying TOTP tables..."
totp_response=$(curl -s -H "Content-Type: application/json" \
    -X POST "http://$USERNAME:$PASSWORD@localhost:4001/db/query" \
    -d '[["SELECT count(*) FROM sqlite_master WHERE type='\''table'\'' AND name LIKE '\''%totp%'\''"]]')

totp_count=$(echo "$totp_response" | jq -r '.results[0].values[0][0] // 0')
if [[ "$totp_count" -eq 3 ]]; then
    echo -e "${GREEN}✅ All TOTP tables verified successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  TOTP tables may be incomplete (found: $totp_count/3)${NC}"
fi

echo "Database setup complete."
