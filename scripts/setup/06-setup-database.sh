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

# Function to execute SQL statements directly via sqlite3 CLI
# This is more robust than using the rqlite HTTP API for complex schema init.
execute_sql_direct() {
    local sql="$1"
    if ! echo "$sql" | sudo -u arkfile sqlite3 "/opt/arkfile/var/lib/database/db.sqlite"; then
        echo -e "${RED}    -> Direct SQL command failed for statement:${NC}"
        echo -e "${YELLOW}       $sql${NC}"
        return 1
    fi
    return 0
}

# All schema will be applied directly from the file.
# No need for basic tables here.
echo "Applying all schema directly to the database file..."

# Now execute the extended schema
echo "Applying extended schema from $SCHEMA_FILE..."

# Function to print a failure message and exit
fail() {
    echo -e "${RED}❌ $1${NC}" >&2
    exit 1
}

# Read the entire schema file and process it statement by statement.
# This handles multi-line statements correctly.
sed 's/--.*//' "$SCHEMA_FILE" | tr -s '\n' ' ' | sed 's/;/;\n/g' | while read -r sql_statement; do
    if [[ -n "$sql_statement" ]]; then
        if ! echo "$sql_statement" | sudo -u arkfile sqlite3 "/opt/arkfile/var/lib/database/db.sqlite"; then
            fail "Could not apply schema statement: $sql_statement"
        fi
    fi
done

echo -e "${GREEN}✅ Database schema initialization completed successfully!${NC}"

# Verify critical tables exist using direct sqlite3 queries
echo "Verifying OPAQUE tables..."
opaque_check=$(sudo -u arkfile sqlite3 "/opt/arkfile/var/lib/database/db.sqlite" "SELECT name FROM sqlite_master WHERE type='table' AND name='opaque_user_data';")

if [[ "$opaque_check" == "opaque_user_data" ]]; then
    echo -e "${GREEN}✅ OPAQUE tables verified successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  OPAQUE tables may not have been created properly${NC}"
fi

echo "Verifying TOTP tables..."
totp_count=$(sudo -u arkfile sqlite3 "/opt/arkfile/var/lib/database/db.sqlite" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE '%totp%';")

if [[ "$totp_count" -eq 3 ]]; then
    echo -e "${GREEN}✅ All TOTP tables verified successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  TOTP tables may be incomplete (found: $totp_count/3)${NC}"
fi

echo "Database setup complete."
