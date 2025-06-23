-- Database schema extensions for chunked uploads and file sharing

-- Table to track upload sessions
CREATE TABLE IF NOT EXISTS upload_sessions (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    total_size BIGINT NOT NULL,
    chunk_size INTEGER NOT NULL,
    total_chunks INTEGER NOT NULL,
    original_hash CHAR(64) NOT NULL,
    encrypted_hash CHAR(64),
    password_hint TEXT,
    password_type TEXT NOT NULL DEFAULT 'custom',
    storage_upload_id TEXT,
    status TEXT NOT NULL DEFAULT 'in_progress',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (owner_email) REFERENCES users(email)
);

-- Index for looking up upload sessions by user
CREATE INDEX IF NOT EXISTS idx_upload_sessions_owner ON upload_sessions(owner_email);
-- Index for looking up upload sessions by status
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status);

-- Table to track individual chunk uploads
CREATE TABLE IF NOT EXISTS upload_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    chunk_number INTEGER NOT NULL,
    chunk_hash CHAR(64) NOT NULL,
    chunk_size BIGINT NOT NULL,
    iv TEXT NOT NULL,
    etag TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES upload_sessions(id) ON DELETE CASCADE,
    UNIQUE(session_id, chunk_number)
);

-- Index for looking up chunks by session
CREATE INDEX IF NOT EXISTS idx_upload_chunks_session ON upload_chunks(session_id);

-- Table to store file sharing information
CREATE TABLE IF NOT EXISTS file_shares (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    is_password_protected BOOLEAN NOT NULL DEFAULT false,
    password_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_accessed TIMESTAMP,
    FOREIGN KEY (owner_email) REFERENCES users(email)
);

-- Index for finding shares by owner
CREATE INDEX IF NOT EXISTS idx_file_shares_owner ON file_shares(owner_email);
-- Index for finding shares by file
CREATE INDEX IF NOT EXISTS idx_file_shares_file ON file_shares(file_id);

-- Table to track encryption keys for files
CREATE TABLE IF NOT EXISTS file_encryption_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_type TEXT NOT NULL,  -- 'account' or 'custom'
    key_label TEXT NOT NULL, -- User-friendly name
    password_hint TEXT,      -- Optional hint for custom passwords
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_primary BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (file_id) REFERENCES file_metadata(filename) ON DELETE CASCADE
);

-- Index for finding encryption keys by file
CREATE INDEX IF NOT EXISTS idx_file_encryption_keys_file ON file_encryption_keys(file_id);
-- Index for finding encryption keys by key ID
CREATE INDEX IF NOT EXISTS idx_file_encryption_keys_key ON file_encryption_keys(key_id);

-- Add multi-key support column to upload_sessions
ALTER TABLE upload_sessions ADD COLUMN multi_key BOOLEAN DEFAULT FALSE;

-- Table for refresh tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE,
    is_used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
);

-- Indexes for refresh tokens
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_email);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token_hash);

-- Table for revoked JWT tokens
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL UNIQUE,  -- the jti claim value
    user_email TEXT NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    reason TEXT,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
);

-- Indexes for revoked tokens
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens(token_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user ON revoked_tokens(user_email);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- Note: password_salt columns are now part of the base schema
-- Users table: password_hash, password_salt
-- File_shares table: password_hash, password_salt

-- OPAQUE Authentication Tables
CREATE TABLE IF NOT EXISTS opaque_server_keys (
    id INTEGER PRIMARY KEY,
    server_secret_key BLOB NOT NULL,
    server_public_key BLOB NOT NULL,
    oprf_seed BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS opaque_user_data (
    user_email TEXT PRIMARY KEY,
    client_argon_salt BLOB NOT NULL,
    server_argon_salt BLOB NOT NULL,
    hardened_envelope BLOB NOT NULL,
    device_profile TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
);

-- Indexes for OPAQUE tables
CREATE INDEX IF NOT EXISTS idx_opaque_user_data_email ON opaque_user_data(user_email);
CREATE INDEX IF NOT EXISTS idx_opaque_user_data_device_profile ON opaque_user_data(device_profile);

-- Phase 3: Security Hardening and Operational Infrastructure Tables

-- Security events with privacy-preserving entity identification
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,           -- HMAC-based, privacy-preserving
    time_window TEXT NOT NULL,         -- "2025-06-20"
    user_email TEXT,                   -- Only for authenticated events
    device_profile TEXT,               -- Argon2ID profile
    severity TEXT NOT NULL DEFAULT 'INFO',
    details JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_events_window (time_window, event_type),
    INDEX idx_events_entity (entity_id, time_window),
    INDEX idx_events_severity (severity, timestamp),
    INDEX idx_events_type (event_type, timestamp)
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
    
    PRIMARY KEY (entity_id, time_window, endpoint),
    INDEX idx_rate_limit_cleanup (time_window),
    INDEX idx_rate_limit_entity (entity_id, time_window),
    INDEX idx_rate_limit_penalties (penalty_until)
);

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
    details JSON,
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
    details JSON,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by TEXT,
    acknowledged_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_alerts_severity (severity, created_at),
    INDEX idx_alerts_unack (acknowledged, created_at),
    INDEX idx_alerts_entity (entity_id, time_window)
);
