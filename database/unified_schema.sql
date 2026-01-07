-- Arkfile Complete Database Schema

-- =====================================================
-- PHASE 1: CORE USER AND FILE MANAGEMENT TABLES
-- =====================================================

-- Users table (foundation for all other tables)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_storage_bytes BIGINT NOT NULL DEFAULT 0,
    storage_limit_bytes BIGINT NOT NULL DEFAULT 10737418240,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    approved_by TEXT,
    approved_at TIMESTAMP,
    is_admin BOOLEAN NOT NULL DEFAULT false,
    last_login TIMESTAMP,
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- File metadata table (core file information with encrypted metadata)
CREATE TABLE IF NOT EXISTS file_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id VARCHAR(36) UNIQUE NOT NULL,        -- UUID v4 for file identification
    storage_id VARCHAR(36) UNIQUE NOT NULL,     -- UUID v4 for storage backend
    owner_username TEXT NOT NULL,
    password_hint TEXT,
    password_type TEXT NOT NULL DEFAULT 'custom',
    filename_nonce TEXT NOT NULL,               -- base64-encoded 12-byte nonce for filename encryption
    encrypted_filename TEXT NOT NULL,           -- base64-encoded AES-GCM encrypted filename
    sha256sum_nonce TEXT NOT NULL,              -- base64-encoded 12-byte nonce for sha256 encryption  
    encrypted_sha256sum TEXT NOT NULL,          -- base64-encoded AES-GCM encrypted sha256 hash
    encrypted_file_sha256sum CHAR(64),          -- sha256sum of the final encrypted file in storage
    encrypted_fek TEXT,                         -- base64-encoded AES-GCM encrypted File Encryption Key
    size_bytes BIGINT NOT NULL DEFAULT 0,
    padded_size BIGINT,                         -- Size with padding for privacy/security
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 2: SYSTEM SECRETS (MASTER KEY ARCHITECTURE)
-- =====================================================

-- Encrypted system keys (JWT, TOTP, OPAQUE, Bootstrap)
-- Encrypted using Envelope Encryption with ARKFILE_MASTER_KEY
CREATE TABLE IF NOT EXISTS system_keys (
    key_id TEXT PRIMARY KEY,      -- e.g., "jwt_signing_key_v1", "bootstrap_token"
    key_type TEXT NOT NULL,       -- e.g., "jwt", "totp", "opaque", "bootstrap"
    encrypted_data BLOB NOT NULL, -- The encrypted secret
    nonce BLOB NOT NULL,          -- The nonce used for encryption (AES-GCM)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP          -- Optional (for Bootstrap Token)
);

-- =====================================================
-- PHASE 3: RFC-COMPLIANT OPAQUE AUTHENTICATION
-- =====================================================

-- OPAQUE server keys (single row table for server-wide keys)
CREATE TABLE IF NOT EXISTS opaque_server_keys (
    id INTEGER PRIMARY KEY CHECK (id = 1),      -- Enforce single row
    server_secret_key BLOB NOT NULL,
    server_public_key BLOB NOT NULL,
    oprf_seed BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- RFC-compliant OPAQUE user authentication records
-- This is the ONLY table for OPAQUE user data - no file-specific OPAQUE records
CREATE TABLE IF NOT EXISTS opaque_user_data (
    username TEXT PRIMARY KEY,
    opaque_user_record BLOB NOT NULL,           -- Serialized OPAQUE registration record
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Multi-step OPAQUE authentication sessions
-- Stores intermediate state during the 3-step authentication protocol
CREATE TABLE IF NOT EXISTS opaque_auth_sessions (
    session_id TEXT PRIMARY KEY,                -- UUID for session identification
    username TEXT NOT NULL,
    session_type TEXT NOT NULL,                 -- 'user_authentication', 'admin_authentication'
    auth_u_server BLOB NOT NULL,                -- Server's authentication state
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,              -- Sessions expire after 15 minutes
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 4: JWT TOKEN MANAGEMENT
-- =====================================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    last_used TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL UNIQUE,              -- the jti claim value
    username TEXT NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    reason TEXT,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 5: TOTP TWO-FACTOR AUTHENTICATION
-- =====================================================

CREATE TABLE IF NOT EXISTS user_totp (
    username TEXT PRIMARY KEY,
    secret_encrypted BLOB NOT NULL,             -- AES-GCM encrypted with user-specific TOTP key
    backup_codes_encrypted BLOB,                -- JSON array of codes, encrypted
    enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    setup_completed BOOLEAN DEFAULT FALSE,      -- Two-phase setup
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- TOTP Usage Log for Replay Protection (90-second window)
CREATE TABLE IF NOT EXISTS totp_usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    code_hash TEXT NOT NULL,                    -- SHA-256 hash of used code
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    window_start INTEGER NOT NULL,              -- Unix timestamp of 30s window
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Backup Code Usage Log
CREATE TABLE IF NOT EXISTS totp_backup_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    code_hash TEXT NOT NULL,                    -- SHA-256 hash of used backup code
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 6: FILE SHARING AND ENCRYPTION
-- =====================================================

-- File share keys (Argon2id-based anonymous shares)
CREATE TABLE IF NOT EXISTS file_share_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL UNIQUE,              -- 256-bit crypto-secure identifier (Client-generated)
    file_id TEXT NOT NULL,                      -- Reference to the shared file
    owner_username TEXT NOT NULL,               -- User who created the share
    salt TEXT NOT NULL,                         -- base64-encoded 32-byte random salt for Argon2id
    encrypted_fek TEXT NOT NULL,                -- base64-encoded Share Envelope (FEK + Download Token) encrypted with AAD
    download_token_hash TEXT NOT NULL,          -- SHA-256 hash of the Download Token (REQUIRED for bandwidth protection)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,                        -- Optional expiration
    access_count INTEGER DEFAULT 0,             -- Track number of accesses
    max_accesses INTEGER,                       -- Optional access limit
    revoked_at DATETIME,                        -- Timestamp when the share was revoked
    revoked_reason TEXT,                        -- Reason for revocation (e.g., 'manual_revocation', 'max_downloads_reached')
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE
);

-- File shares (legacy table for compatibility - may be deprecated in future)
CREATE TABLE IF NOT EXISTS file_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL UNIQUE,
    file_id TEXT NOT NULL,
    owner_username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 7: CHUNKED UPLOAD SYSTEM
-- =====================================================

-- Upload sessions for chunked uploads
CREATE TABLE IF NOT EXISTS upload_sessions (
    id TEXT PRIMARY KEY,
    file_id VARCHAR(36) NOT NULL,
    encrypted_filename TEXT NOT NULL,
    filename_nonce TEXT NOT NULL,
    encrypted_sha256sum TEXT NOT NULL,
    sha256sum_nonce TEXT NOT NULL,
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
    encrypted_fek TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE
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
-- PHASE 8: SECURITY AND MONITORING
-- =====================================================

-- Security events with privacy-preserving entity identification
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,                    -- HMAC-based, privacy-preserving
    time_window TEXT NOT NULL,                  -- "2025-06-20"
    username TEXT,                              -- Only for authenticated events
    device_profile TEXT,                        -- Argon2ID profile
    severity TEXT NOT NULL DEFAULT 'INFO',
    details TEXT,                               -- JSON stored as TEXT for rqlite compatibility
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Rate limiting state with entity ID privacy protection
CREATE TABLE IF NOT EXISTS rate_limit_state (
    entity_id TEXT NOT NULL,
    time_window TEXT NOT NULL,                  -- "2025-06-20"
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
-- PHASE 9: OPERATIONAL MONITORING
-- =====================================================

-- Entity ID configuration and master secret storage
CREATE TABLE IF NOT EXISTS entity_id_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),      -- Enforce single row
    master_secret_hash TEXT NOT NULL,           -- Hash of master secret for health checks
    rotation_schedule TEXT NOT NULL,            -- "daily"
    last_rotation DATETIME,
    next_rotation DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Key health monitoring status
CREATE TABLE IF NOT EXISTS key_health_status (
    component TEXT PRIMARY KEY,
    status TEXT NOT NULL,                       -- "healthy", "warning", "critical"
    last_checked DATETIME NOT NULL,
    next_check DATETIME NOT NULL,
    details TEXT,                               -- JSON stored as TEXT
    alert_level TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Security alerts and escalation
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity_id TEXT,                             -- Optional entity association
    time_window TEXT,
    message TEXT NOT NULL,
    details TEXT,                               -- JSON stored as TEXT
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by TEXT,
    acknowledged_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- PHASE 10: ACTIVITY LOGGING
-- =====================================================

-- User activity tracking
CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Admin actions logs
CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_username TEXT NOT NULL,
    action TEXT NOT NULL,
    target_username TEXT,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_username) REFERENCES users(username) ON DELETE CASCADE
);

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
    transaction_id TEXT,                        -- External transaction ID (Bitcoin, PayPal, etc.)
    username TEXT NOT NULL,
    amount_usd_cents INTEGER NOT NULL,          -- Positive for credits, negative for debits
    balance_after_usd_cents INTEGER NOT NULL,   -- Balance after this transaction
    transaction_type TEXT NOT NULL,             -- 'credit', 'debit', 'adjustment', 'refund'
    reason TEXT,                                -- Human-readable reason for transaction
    admin_username TEXT,                        -- NULL for user transactions, filled for admin adjustments
    metadata TEXT,                              -- JSON for additional details
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- =====================================================
-- PHASE 12: INDEXES FOR PERFORMANCE
-- =====================================================

-- Core table indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_is_approved ON users(is_approved);
CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin);

CREATE INDEX IF NOT EXISTS idx_file_metadata_file_id ON file_metadata(file_id);
CREATE INDEX IF NOT EXISTS idx_file_metadata_storage_id ON file_metadata(storage_id);
CREATE INDEX IF NOT EXISTS idx_file_metadata_owner ON file_metadata(owner_username);
CREATE INDEX IF NOT EXISTS idx_file_metadata_upload_date ON file_metadata(upload_date);

-- OPAQUE authentication indexes
CREATE INDEX IF NOT EXISTS idx_opaque_user_data_username ON opaque_user_data(username);
CREATE INDEX IF NOT EXISTS idx_opaque_auth_sessions_username ON opaque_auth_sessions(username);
CREATE INDEX IF NOT EXISTS idx_opaque_auth_sessions_expires ON opaque_auth_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_opaque_auth_sessions_type ON opaque_auth_sessions(session_type);

-- Token management indexes
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(username);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens(token_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user ON revoked_tokens(username);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- TOTP indexes
CREATE INDEX IF NOT EXISTS idx_user_totp_username ON user_totp(username);
CREATE INDEX IF NOT EXISTS idx_user_totp_enabled ON user_totp(enabled);
CREATE INDEX IF NOT EXISTS idx_totp_usage_cleanup ON totp_usage_log(used_at);
CREATE INDEX IF NOT EXISTS idx_totp_usage_user_window ON totp_usage_log(username, window_start);
CREATE INDEX IF NOT EXISTS idx_totp_backup_user ON totp_backup_usage(username);
CREATE INDEX IF NOT EXISTS idx_totp_backup_cleanup ON totp_backup_usage(used_at);

-- File sharing indexes
CREATE INDEX IF NOT EXISTS idx_file_share_keys_share_id ON file_share_keys(share_id);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_file_id ON file_share_keys(file_id);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_owner ON file_share_keys(owner_username);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_expires_at ON file_share_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_revoked ON file_share_keys(revoked_at);
CREATE INDEX IF NOT EXISTS idx_file_share_keys_token_hash ON file_share_keys(download_token_hash);
CREATE INDEX IF NOT EXISTS idx_file_shares_share_id ON file_shares(share_id);
CREATE INDEX IF NOT EXISTS idx_file_shares_file_id ON file_shares(file_id);
CREATE INDEX IF NOT EXISTS idx_file_shares_owner ON file_shares(owner_username);

-- Upload session indexes
CREATE INDEX IF NOT EXISTS idx_upload_sessions_owner ON upload_sessions(owner_username);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_expires ON upload_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_upload_chunks_session ON upload_chunks(session_id);

-- Security and monitoring indexes
CREATE INDEX IF NOT EXISTS idx_events_window ON security_events(time_window, event_type);
CREATE INDEX IF NOT EXISTS idx_events_entity ON security_events(entity_id, time_window);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_username ON security_events(username);

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

-- Activity logging indexes
CREATE INDEX IF NOT EXISTS idx_user_activity_username ON user_activity(username);
CREATE INDEX IF NOT EXISTS idx_user_activity_timestamp ON user_activity(timestamp);
CREATE INDEX IF NOT EXISTS idx_admin_logs_admin ON admin_logs(admin_username);
CREATE INDEX IF NOT EXISTS idx_admin_logs_target ON admin_logs(target_username);
CREATE INDEX IF NOT EXISTS idx_admin_logs_timestamp ON admin_logs(timestamp);

-- Credits system indexes
CREATE INDEX IF NOT EXISTS idx_user_credits_username ON user_credits(username);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_username ON credit_transactions(username);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_transaction_id ON credit_transactions(transaction_id);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_type ON credit_transactions(transaction_type);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_created_at ON credit_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_admin ON credit_transactions(admin_username);

-- =====================================================
-- PHASE 13: TRIGGERS FOR AUTOMATIC UPDATES
-- =====================================================

-- Update trigger for opaque_user_data
CREATE TRIGGER IF NOT EXISTS update_opaque_user_data_updated_at
    AFTER UPDATE ON opaque_user_data
    FOR EACH ROW
BEGIN
    UPDATE opaque_user_data 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE username = NEW.username;
END;

-- Update trigger for opaque_server_keys
CREATE TRIGGER IF NOT EXISTS update_opaque_server_keys_updated_at
    AFTER UPDATE ON opaque_server_keys
    FOR EACH ROW
BEGIN
    UPDATE opaque_server_keys 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END;

-- Update trigger for upload_sessions
CREATE TRIGGER IF NOT EXISTS update_upload_sessions_updated_at
    AFTER UPDATE ON upload_sessions
    FOR EACH ROW
BEGIN
    UPDATE upload_sessions 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END;

-- Update trigger for share_access_attempts
CREATE TRIGGER IF NOT EXISTS update_share_access_attempts_updated_at
    AFTER UPDATE ON share_access_attempts
    FOR EACH ROW
BEGIN
    UPDATE share_access_attempts 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END;

-- Update trigger for user_credits
CREATE TRIGGER IF NOT EXISTS update_user_credits_updated_at
    AFTER UPDATE ON user_credits
    FOR EACH ROW
BEGIN
    UPDATE user_credits 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END;

-- Update trigger for rate_limit_state
CREATE TRIGGER IF NOT EXISTS update_rate_limit_state_updated_at
    AFTER UPDATE ON rate_limit_state
    FOR EACH ROW
BEGIN
    UPDATE rate_limit_state 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE entity_id = NEW.entity_id 
      AND time_window = NEW.time_window 
      AND endpoint = NEW.endpoint;
END;

-- =====================================================
-- PHASE 14: MONITORING VIEWS
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

-- View for user authentication status
CREATE VIEW IF NOT EXISTS user_auth_status AS
SELECT 
    u.username,
    u.is_approved,
    u.is_admin,
    u.created_at as user_created_at,
    u.last_login,
    CASE WHEN oud.username IS NOT NULL THEN 1 ELSE 0 END as has_opaque_account,
    CASE WHEN ut.username IS NOT NULL THEN 1 ELSE 0 END as has_totp,
    ut.enabled as totp_enabled,
    ut.setup_completed as totp_setup_completed
FROM users u
LEFT JOIN opaque_user_data oud ON u.username = oud.username
LEFT JOIN user_totp ut ON u.username = ut.username;
