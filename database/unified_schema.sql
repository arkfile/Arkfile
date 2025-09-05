-- Arkfile Complete Database Schema
-- Single comprehensive schema with proper dependency ordering

-- =====================================================
-- PHASE 1: CORE USER AND FILE MANAGEMENT TABLES
-- =====================================================

-- Users table (foundation for all other tables)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_storage_bytes BIGINT NOT NULL DEFAULT 0,
    storage_limit_bytes BIGINT NOT NULL DEFAULT 10737418240,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    approved_by TEXT,
    approved_at TIMESTAMP,
    is_admin BOOLEAN NOT NULL DEFAULT false
);

-- File metadata table (core file information with encrypted metadata)
CREATE TABLE IF NOT EXISTS file_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id VARCHAR(36) UNIQUE NOT NULL,        -- UUID v4 for file identification
    storage_id VARCHAR(36) UNIQUE NOT NULL,     -- UUID v4 for storage backend
    owner_username TEXT NOT NULL,
    password_hint TEXT,
    password_type TEXT NOT NULL DEFAULT 'custom',
    filename_nonce BINARY(12) NOT NULL,         -- 12-byte nonce for filename encryption
    encrypted_filename BLOB NOT NULL,           -- AES-GCM encrypted filename
    sha256sum_nonce BINARY(12) NOT NULL,        -- 12-byte nonce for sha256 encryption
    encrypted_sha256sum BLOB NOT NULL,          -- AES-GCM encrypted sha256 hash
    encrypted_file_sha256sum CHAR(64),          -- sha256sum of the final encrypted file in storage
    encrypted_fek BLOB,                         -- AES-GCM encrypted File Encryption Key
    size_bytes BIGINT NOT NULL DEFAULT 0,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_username) REFERENCES users(username)
);

-- =====================================================
-- PHASE 2: AUTHENTICATION AND SECURITY TABLES
-- =====================================================

-- OPAQUE server keys (single row table for server-wide keys)
CREATE TABLE IF NOT EXISTS opaque_server_keys (
    id INTEGER PRIMARY KEY,
    server_secret_key BLOB NOT NULL,
    server_public_key BLOB NOT NULL,
    oprf_seed BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- OPAQUE user authentication records
CREATE TABLE IF NOT EXISTS opaque_user_data (
    username TEXT PRIMARY KEY,
    serialized_record BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- OPAQUE password records for files and accounts
CREATE TABLE IF NOT EXISTS opaque_password_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_type TEXT NOT NULL,           -- 'account', 'file_custom' (NO 'share' type)
    record_identifier TEXT NOT NULL UNIQUE, -- username, 'user:file:filename'
    opaque_user_record BLOB NOT NULL,    -- OPAQUE registration data
    associated_file_id TEXT,             -- NULL for account, filename for file_custom
    associated_username TEXT,            -- User who created this record
    key_label TEXT,                      -- Human-readable label
    password_hint_encrypted BLOB,        -- Encrypted with export key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- JWT token management
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE,
    is_used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL UNIQUE,  -- the jti claim value
    username TEXT NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    reason TEXT,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 3: TOTP TWO-FACTOR AUTHENTICATION
-- =====================================================

CREATE TABLE IF NOT EXISTS user_totp (
    username TEXT PRIMARY KEY,
    secret_encrypted BLOB NOT NULL,           -- AES-GCM encrypted with user-specific TOTP key
    backup_codes_encrypted BLOB,              -- JSON array of codes, encrypted
    enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    setup_completed BOOLEAN DEFAULT FALSE,    -- Two-phase setup
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- TOTP Usage Log for Replay Protection (90-second window)
CREATE TABLE IF NOT EXISTS totp_usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    code_hash TEXT NOT NULL,                  -- SHA-256 hash of used code
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    window_start INTEGER NOT NULL,            -- Unix timestamp of 30s window
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Backup Code Usage Log
CREATE TABLE IF NOT EXISTS totp_backup_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    code_hash TEXT NOT NULL,                  -- SHA-256 hash of used backup code
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 4: FILE SHARING AND ENCRYPTION
-- =====================================================

-- File share keys (Argon2id-based anonymous shares)
CREATE TABLE IF NOT EXISTS file_share_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL UNIQUE,        -- 256-bit crypto-secure identifier
    file_id TEXT NOT NULL,                -- Reference to the shared file
    owner_username TEXT NOT NULL,         -- User who created the share
    salt BLOB NOT NULL,                   -- 32-byte random salt for Argon2id
    encrypted_fek BLOB NOT NULL,          -- FEK encrypted with Argon2id-derived share key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,                  -- Optional expiration
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE
);

-- File encryption keys
CREATE TABLE IF NOT EXISTS file_encryption_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_type TEXT NOT NULL,  -- 'account' or 'custom'
    key_label TEXT NOT NULL, -- User-friendly name
    password_hint TEXT,      -- Optional hint for custom passwords
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_primary BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 5: CHUNKED UPLOAD SYSTEM
-- =====================================================

-- Upload sessions for chunked uploads
CREATE TABLE IF NOT EXISTS upload_sessions (
    id TEXT PRIMARY KEY,
    file_id VARCHAR(36) NOT NULL,
    encrypted_filename BLOB NOT NULL,
    filename_nonce BINARY(12) NOT NULL,
    encrypted_sha256sum BLOB NOT NULL,
    sha256sum_nonce BINARY(12) NOT NULL,
    owner_username TEXT NOT NULL,
    total_size BIGINT NOT NULL,
    chunk_size INTEGER NOT NULL,
    total_chunks INTEGER NOT NULL,
    password_hint TEXT,
    password_type TEXT NOT NULL,
    storage_upload_id TEXT,
    storage_id VARCHAR(36),
    padded_size BIGINT,
    status TEXT NOT NULL DEFAULT 'in_progress',
    encrypted_hash CHAR(64),
    encrypted_fek BLOB,
    -- Crypto envelope support
    envelope_data BLOB,
    envelope_version TINYINT,
    envelope_key_type TINYINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (owner_username) REFERENCES users(username)
);

-- Individual chunk tracking
CREATE TABLE IF NOT EXISTS upload_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    chunk_number INTEGER NOT NULL,
    chunk_hash CHAR(64) NOT NULL,
    chunk_size BIGINT NOT NULL,
    etag TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES upload_sessions(id) ON DELETE CASCADE,
    UNIQUE(session_id, chunk_number)
);

-- =====================================================
-- PHASE 6: SECURITY AND MONITORING
-- =====================================================

-- Security events with privacy-preserving entity identification
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,           -- HMAC-based, privacy-preserving
    time_window TEXT NOT NULL,         -- "2025-06-20"
    username TEXT,                     -- Only for authenticated events
    device_profile TEXT,               -- Argon2ID profile
    severity TEXT NOT NULL DEFAULT 'INFO',
    details TEXT,                      -- Changed from JSON to TEXT for rqlite compatibility
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Rate limiting state with entity ID privacy protection
CREATE TABLE IF NOT EXISTS rate_limit_state (
    entity_id TEXT NOT NULL,
    time_window TEXT NOT NULL,         -- "2025-06-20"
    endpoint TEXT NOT NULL,
    device_profile TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    last_request DATETIME NOT NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    penalty_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (entity_id, time_window, endpoint)
);

-- Share access rate limiting
CREATE TABLE IF NOT EXISTS share_access_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,                    -- Privacy-preserving entity identifier
    failed_count INTEGER NOT NULL DEFAULT 0,
    last_failed_attempt DATETIME,
    next_allowed_attempt DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(share_id, entity_id)
);

-- =====================================================
-- PHASE 7: OPERATIONAL MONITORING
-- =====================================================

-- Entity ID configuration and master secret storage
CREATE TABLE IF NOT EXISTS entity_id_config (
    id INTEGER PRIMARY KEY,
    master_secret_hash TEXT NOT NULL,  -- Hash of master secret for health checks
    rotation_schedule TEXT NOT NULL,   -- "daily"
    last_rotation DATETIME,
    next_rotation DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Key health monitoring status
CREATE TABLE IF NOT EXISTS key_health_status (
    component TEXT PRIMARY KEY,
    status TEXT NOT NULL,              -- "healthy", "warning", "critical"
    last_checked DATETIME NOT NULL,
    next_check DATETIME NOT NULL,
    details TEXT,                      -- Changed from JSON to TEXT
    alert_level TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Security alerts and escalation
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity_id TEXT,                    -- Optional entity association
    time_window TEXT,
    message TEXT NOT NULL,
    details TEXT,                      -- Changed from JSON to TEXT
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by TEXT,
    acknowledged_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- PHASE 8: ACTIVITY LOGGING
-- =====================================================

-- User activity tracking
CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
);

-- Admin actions logs
CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target_username TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_username) REFERENCES users(username),
    FOREIGN KEY (target_username) REFERENCES users(username)
);

-- =====================================================
-- PHASE 9: INDEXES FOR PERFORMANCE
-- =====================================================

-- Core table indexes
CREATE INDEX IF NOT EXISTS idx_file_metadata_file_id ON file_metadata(file_id);
CREATE INDEX IF NOT EXISTS idx_file_metadata_storage_id ON file_metadata(storage_id);
CREATE INDEX IF NOT EXISTS idx_file_metadata_owner ON file_metadata(owner_username);
CREATE INDEX IF NOT EXISTS idx_file_metadata_upload_date ON file_metadata(upload_date);

-- Authentication indexes
CREATE INDEX IF NOT EXISTS idx_opaque_user_data_username ON opaque_user_data(username);
CREATE INDEX IF NOT EXISTS idx_opaque_passwords_type ON opaque_password_records(record_type);
CREATE INDEX IF NOT EXISTS idx_opaque_passwords_identifier ON opaque_password_records(record_identifier);
CREATE INDEX IF NOT EXISTS idx_opaque_passwords_file ON opaque_password_records(associated_file_id);
CREATE INDEX IF NOT EXISTS idx_opaque_passwords_user ON opaque_password_records(associated_username);
CREATE INDEX IF NOT EXISTS idx_opaque_passwords_active ON opaque_password_records(is_active);

-- Token management indexes
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(username);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens(token_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user ON revoked_tokens(username);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- TOTP indexes
CREATE INDEX IF NOT EXISTS idx_user_totp_username ON user_totp(username);
CREATE INDEX IF NOT EXISTS idx_totp_usage_cleanup ON totp_usage_log(used_at);
CREATE INDEX IF NOT EXISTS idx_totp_usage_user_window ON totp_usage_log(username, window_start);
CREATE INDEX IF NOT EXISTS idx_totp_backup_user ON totp_backup_usage(username);
CREATE INDEX IF NOT EXISTS idx_totp_backup_cleanup ON totp_backup_usage(used_at);

-- File sharing indexes
CREATE INDEX IF NOT EXISTS idx_file_share_keys_share_id ON file_share_keys(share_id);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_file_id ON file_share_keys(file_id);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_owner ON file_share_keys(owner_username);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_expires_at ON file_share_keys(expires_at);

-- File encryption keys indexes
CREATE INDEX IF NOT EXISTS idx_file_encryption_keys_file ON file_encryption_keys(file_id);
CREATE INDEX IF NOT EXISTS idx_file_encryption_keys_key ON file_encryption_keys(key_id);

-- Upload session indexes
CREATE INDEX IF NOT EXISTS idx_upload_sessions_owner ON upload_sessions(owner_username);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status);
CREATE INDEX IF NOT EXISTS idx_upload_chunks_session ON upload_chunks(session_id);

-- Security and monitoring indexes
CREATE INDEX IF NOT EXISTS idx_events_window ON security_events(time_window, event_type);
CREATE INDEX IF NOT EXISTS idx_events_entity ON security_events(entity_id, time_window);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type, timestamp);

-- Rate limiting indexes
CREATE INDEX IF NOT EXISTS idx_rate_limit_cleanup ON rate_limit_state(time_window);
CREATE INDEX IF NOT EXISTS idx_rate_limit_entity ON rate_limit_state(entity_id, time_window);
CREATE INDEX IF NOT EXISTS idx_rate_limit_penalties ON rate_limit_state(penalty_until);

-- Share access attempts indexes
CREATE INDEX IF NOT EXISTS idx_share_access_share_id ON share_access_attempts(share_id);
CREATE INDEX IF NOT EXISTS idx_share_access_entity_id ON share_access_attempts(entity_id);
CREATE INDEX IF NOT EXISTS idx_share_access_next_allowed ON share_access_attempts(next_allowed_attempt);
CREATE INDEX IF NOT EXISTS idx_share_access_cleanup ON share_access_attempts(created_at);

-- Security alerts indexes
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_unack ON security_alerts(acknowledged, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_entity ON security_alerts(entity_id, time_window);


-- =====================================================
-- PHASE 10: TRIGGERS FOR AUTOMATIC UPDATES
-- =====================================================

-- Update trigger to maintain updated_at timestamp for share_access_attempts
CREATE TRIGGER IF NOT EXISTS update_share_access_attempts_updated_at
    AFTER UPDATE ON share_access_attempts
    FOR EACH ROW
BEGIN
    UPDATE share_access_attempts 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END;


-- =====================================================
-- PHASE 11: CREDITS AND BILLING SYSTEM
-- =====================================================

-- User credits balance table
CREATE TABLE IF NOT EXISTS user_credits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    balance_usd_cents INTEGER NOT NULL DEFAULT 0,  -- Store as cents to avoid floating point issues
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
    UNIQUE(username)
);

-- Credit transactions log with full audit trail
CREATE TABLE IF NOT EXISTS credit_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT,                          -- External transaction ID (Bitcoin, PayPal, etc.)
    username TEXT NOT NULL,
    amount_usd_cents INTEGER NOT NULL,            -- Positive for credits, negative for debits
    balance_after_usd_cents INTEGER NOT NULL,     -- Balance after this transaction
    transaction_type TEXT NOT NULL,               -- 'credit', 'debit', 'adjustment', 'refund'
    reason TEXT,                                  -- Human-readable reason for transaction
    admin_username TEXT,                          -- NULL for user transactions, filled for admin adjustments
    metadata TEXT,                                -- JSON for additional details
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Credits system indexes
CREATE INDEX IF NOT EXISTS idx_user_credits_username ON user_credits(username);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_username ON credit_transactions(username);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_transaction_id ON credit_transactions(transaction_id);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_type ON credit_transactions(transaction_type);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_created_at ON credit_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_admin ON credit_transactions(admin_username);

-- Update trigger to maintain updated_at timestamp for user_credits
CREATE TRIGGER IF NOT EXISTS update_user_credits_updated_at
    AFTER UPDATE ON user_credits
    FOR EACH ROW
BEGIN
    UPDATE user_credits 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END;

-- =====================================================
-- PHASE 12: MONITORING VIEWS
-- =====================================================

-- View for monitoring rate limiting activity
CREATE VIEW IF NOT EXISTS share_rate_limit_stats AS
SELECT 
    COUNT(*) as total_entries,
    COUNT(CASE WHEN failed_count > 0 THEN 1 END) as entries_with_failures,
    COUNT(CASE WHEN next_allowed_attempt > CURRENT_TIMESTAMP THEN 1 END) as currently_blocked,
    AVG(failed_count) as avg_failure_count,
    MAX(failed_count) as max_failure_count,
    COUNT(CASE WHEN failed_count >= 10 THEN 1 END) as entries_at_max_penalty
FROM share_access_attempts;

-- View for monitoring share access patterns
CREATE VIEW IF NOT EXISTS share_access_monitoring AS
SELECT 
    share_id,
    COUNT(DISTINCT entity_id) as unique_entities,
    COUNT(*) as total_attempts,
    SUM(failed_count) as total_failures,
    COUNT(CASE WHEN next_allowed_attempt > CURRENT_TIMESTAMP THEN 1 END) as currently_blocked_entities,
    MAX(failed_count) as max_failures_by_entity,
    MIN(created_at) as first_attempt,
    MAX(COALESCE(last_failed_attempt, created_at)) as last_activity
FROM share_access_attempts
GROUP BY share_id
ORDER BY total_failures DESC, total_attempts DESC;
