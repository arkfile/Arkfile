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

# Function to execute SQL statements
execute_sql() {
    local sql="$1"
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -u "$USERNAME:$PASSWORD" \
        -d "[\"$sql\"]" \
        "http://localhost:4001/db/execute" > /dev/null 2>&1
}

# Create basic tables first
echo "Creating basic database tables..."

# Users table
execute_sql "CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_storage_bytes BIGINT NOT NULL DEFAULT 0,
    storage_limit_bytes BIGINT NOT NULL DEFAULT 10737418240,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    approved_by TEXT,
    approved_at TIMESTAMP,
    is_admin BOOLEAN NOT NULL DEFAULT false
);"

# File metadata table
execute_sql "CREATE TABLE IF NOT EXISTS file_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT UNIQUE NOT NULL,
    owner_email TEXT NOT NULL,
    password_hint TEXT,
    password_type TEXT NOT NULL DEFAULT 'custom',
    sha256sum CHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_email) REFERENCES users(email)
);"

execute_sql "CREATE INDEX IF NOT EXISTS idx_file_metadata_sha256sum ON file_metadata(sha256sum);"

# User activity table
execute_sql "CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email)
);"

# Access logs table
execute_sql "CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    filename TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email)
);"

# Admin logs table
execute_sql "CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_email TEXT NOT NULL,
    action TEXT NOT NULL,
    target_email TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_email) REFERENCES users(email),
    FOREIGN KEY (target_email) REFERENCES users(email)
);"

echo "Basic tables created successfully."

# Now execute the extended schema
echo "Applying extended schema from $SCHEMA_FILE..."

# Read and process the schema file - improved parsing
sql_statement=""
while IFS= read -r line; do
    # Skip empty lines and comments
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*-- ]]; then
        continue
    fi
    
    # Accumulate SQL statements until we hit a semicolon
    if [[ -z "$sql_statement" ]]; then
        sql_statement="$line"
    else
        sql_statement="$sql_statement $line"
    fi
    
    # Check if the line contains a semicolon (more flexible than end-of-line check)
    if [[ "$line" == *";"* ]]; then
        # Clean up the statement and remove extra whitespace
        cleaned_sql=$(echo "$sql_statement" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | xargs)
        
        # Execute the statement if it's not empty
        if [ -n "$cleaned_sql" ]; then
            echo "Executing: ${cleaned_sql:0:80}..." # Show first 80 chars for debugging
            if ! execute_sql "$cleaned_sql"; then
                echo -e "${YELLOW}⚠️  Warning: Failed to execute SQL statement${NC}"
            fi
        fi
        
        # Reset for next statement
        sql_statement=""
    fi
done < "$SCHEMA_FILE"

echo -e "${GREEN}✅ Database schema initialization completed successfully!${NC}"

# Verify critical tables exist
echo "Verifying OPAQUE tables..."
result=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -u "$USERNAME:$PASSWORD" \
    -d "[\"SELECT name FROM sqlite_master WHERE type='table' AND name='opaque_user_data';\"]" \
    "http://localhost:4001/db/query")

if [[ "$result" == *"opaque_user_data"* ]]; then
    echo -e "${GREEN}✅ OPAQUE tables verified successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  OPAQUE tables may not have been created properly${NC}"
fi

echo "Verifying TOTP tables..."
totp_result=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -u "$USERNAME:$PASSWORD" \
    -d "[\"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%totp%' ORDER BY name;\"]" \
    "http://localhost:4001/db/query")

# Count TOTP tables (should be 3: user_totp, totp_usage_log, totp_backup_usage)
totp_count=$(echo "$totp_result" | grep -o '"user_totp"\|"totp_usage_log"\|"totp_backup_usage"' | wc -l)

if [[ "$totp_count" -eq 3 ]]; then
    echo -e "${GREEN}✅ All TOTP tables verified successfully!${NC}"
    echo "Found tables: user_totp, totp_usage_log, totp_backup_usage"
else
    echo -e "${YELLOW}⚠️  TOTP tables may be incomplete (found: $totp_count/3)${NC}"
    echo "TOTP response: $totp_result"
fi

echo "Database setup complete."
