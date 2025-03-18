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
