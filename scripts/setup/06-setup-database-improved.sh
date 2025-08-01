#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}Setting up database schema (improved version)...${NC}"

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
sleep 5

# Get database credentials
USERNAME=$(grep "RQLITE_USERNAME=" /opt/arkfile/etc/secrets.env | cut -d'=' -f2)
PASSWORD=$(grep "RQLITE_PASSWORD=" /opt/arkfile/etc/secrets.env | cut -d'=' -f2)

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo -e "${RED}Could not find database credentials in /opt/arkfile/etc/secrets.env${NC}"
    exit 1
fi

echo "Using database credentials for user: $USERNAME"

# Function to execute SQL statements via rqlite HTTP API
execute_sql() {
    local sql="$1"
    local description="$2"
    local response
    
    echo -e "${BLUE}  Executing: $description${NC}"
    response=$(curl -s -H "Content-Type: application/json" \
        -X POST "http://$USERNAME:$PASSWORD@localhost:4001/db/execute" \
        -d "[\"$sql\"]")
    
    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}    ❌ Failed: $description${NC}"
        echo -e "${RED}       SQL: $sql${NC}"
        echo -e "${RED}       Response: $response${NC}"
        return 1
    else
        echo -e "${GREEN}    ✅ Success: $description${NC}"
        return 0
    fi
}

# Test database connectivity
echo -e "${BLUE}Testing rqlite database connectivity...${NC}"
test_response=$(curl -s -H "Content-Type: application/json" \
    -X POST "http://$USERNAME:$PASSWORD@localhost:4001/db/query" \
    -d '[["SELECT 1 as test"]]')

if echo "$test_response" | grep -q '"values":\[\[1\]\]'; then
    echo -e "${GREEN}✅ rqlite database connection successful!${NC}"
else
    echo -e "${RED}❌ Could not connect to rqlite database. Response: $test_response${NC}"
    exit 1
fi

echo -e "${YELLOW}=== Phase 1: Creating Base Tables ===${NC}"

# Create users table (base requirement)
execute_sql "CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_storage_bytes BIGINT NOT NULL DEFAULT 0,
    storage_limit_bytes BIGINT NOT NULL DEFAULT 10737418240,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    approved_by TEXT,
    approved_at TIMESTAMP,
    is_admin BOOLEAN NOT NULL DEFAULT false
)" "Create users table"

# Create file_metadata table
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
)" "Create file_metadata table"

# Create file_metadata index
execute_sql "CREATE INDEX IF NOT EXISTS idx_file_metadata_sha256sum ON file_metadata(sha256sum)" "Create file_metadata hash index"

echo -e "${YELLOW}=== Phase 2: Creating Essential Share System Tables ===${NC}"

# Create file_share_keys table (essential for share system)
execute_sql "CREATE TABLE IF NOT EXISTS file_share_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL UNIQUE,
    file_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    salt BLOB NOT NULL,
    encrypted_fek BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (owner_email) REFERENCES users(email) ON DELETE CASCADE
)" "Create file_share_keys table"

# Create share access attempts table (required for rate limiting)
execute_sql "CREATE TABLE IF NOT EXISTS share_access_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    failed_count INTEGER DEFAULT 0 NOT NULL,
    last_failed_attempt DATETIME,
    next_allowed_attempt DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE(share_id, entity_id)
)" "Create share_access_attempts table"

echo -e "${YELLOW}=== Phase 3: Creating Security and Logging Tables ===${NC}"

# Create security events table
execute_sql "CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    time_window TEXT NOT NULL,
    user_email TEXT,
    device_profile TEXT,
    severity TEXT NOT NULL DEFAULT 'INFO',
    details JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)" "Create security_events table"

# Create rate_limit_state table
execute_sql "CREATE TABLE IF NOT EXISTS rate_limit_state (
    entity_id TEXT NOT NULL,
    time_window TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    device_profile TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    last_request DATETIME NOT NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    penalty_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (entity_id, time_window, endpoint)
)" "Create rate_limit_state table"

echo -e "${YELLOW}=== Phase 4: Creating Authentication Tables ===${NC}"

# Create OPAQUE server keys table
execute_sql "CREATE TABLE IF NOT EXISTS opaque_server_keys (
    id INTEGER PRIMARY KEY,
    server_secret_key BLOB NOT NULL,
    server_public_key BLOB NOT NULL,
    oprf_seed BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)" "Create opaque_server_keys table"

# Create OPAQUE user data table
execute_sql "CREATE TABLE IF NOT EXISTS opaque_user_data (
    user_email TEXT PRIMARY KEY,
    serialized_record BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
)" "Create opaque_user_data table"

echo -e "${YELLOW}=== Phase 5: Creating Indexes for Performance ===${NC}"

# Create essential indexes
execute_sql "CREATE INDEX IF NOT EXISTS idx_file_share_keys_share_id ON file_share_keys(share_id)" "Create share_id index"
execute_sql "CREATE INDEX IF NOT EXISTS idx_share_access_share_entity ON share_access_attempts(share_id, entity_id)" "Create share access compound index"
execute_sql "CREATE INDEX IF NOT EXISTS idx_security_events_window ON security_events(time_window, event_type)" "Create security events index"
execute_sql "CREATE INDEX IF NOT EXISTS idx_rate_limit_cleanup ON rate_limit_state(time_window)" "Create rate limit cleanup index"

echo -e "${YELLOW}=== Phase 6: Creating Triggers and Views ===${NC}"

# Create update trigger for share_access_attempts
execute_sql "CREATE TRIGGER IF NOT EXISTS update_share_access_attempts_updated_at
    AFTER UPDATE ON share_access_attempts
    FOR EACH ROW
BEGIN
    UPDATE share_access_attempts 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END" "Create share access update trigger"

echo -e "${YELLOW}=== Phase 7: Verifying Table Creation ===${NC}"

# Verify critical tables exist
verify_table() {
    local table_name="$1"
    local response
    response=$(curl -s -H "Content-Type: application/json" \
        -X POST "http://$USERNAME:$PASSWORD@localhost:4001/db/query" \
        -d "[\"SELECT name FROM sqlite_master WHERE type='table' AND name='$table_name'\"]")
    
    if echo "$response" | grep -q '"values":\[\["'$table_name'"\]\]'; then
        echo -e "${GREEN}  ✅ Table verified: $table_name${NC}"
        return 0
    else
        echo -e "${RED}  ❌ Table missing: $table_name${NC}"
        return 1
    fi
}

TABLES_TO_VERIFY=(
    "users"
    "file_metadata"
    "file_share_keys"
    "share_access_attempts"
    "security_events"
    "rate_limit_state"
    "opaque_server_keys"
    "opaque_user_data"
)

ALL_TABLES_OK=true
for table in "${TABLES_TO_VERIFY[@]}"; do
    if ! verify_table "$table"; then
        ALL_TABLES_OK=false
    fi
done

if [ "$ALL_TABLES_OK" = true ]; then
    echo -e "${GREEN}✅ All critical tables verified successfully!${NC}"
else
    echo -e "${RED}❌ Some tables are missing. Database setup incomplete.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Database setup completed successfully!${NC}"
echo -e "${BLUE}📊 Database Summary:${NC}"
echo "  • Base tables: users, file_metadata"
echo "  • Share system: file_share_keys, share_access_attempts"
echo "  • Security: security_events, rate_limit_state"
echo "  • Authentication: opaque_server_keys, opaque_user_data"
echo "  • Indexes and triggers: Created for performance"
echo ""
echo -e "${YELLOW}📝 Note: Additional tables will be created by arkfile service if needed${NC}"
echo "   The service can now start safely with all required tables in place."
