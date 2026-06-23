package auth

// MFATestSchemaDDL is the in-memory SQLite schema for MFA unit tests.
const MFATestSchemaDDL = `
	CREATE TABLE user_mfa_credentials (
		credential_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		method_type TEXT NOT NULL DEFAULT 'totp',
		credential_data BLOB NOT NULL,
		enabled BOOLEAN DEFAULT FALSE,
		setup_completed BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME,
		UNIQUE (username, method_type)
	);

	CREATE TABLE user_mfa_lockout (
		username TEXT PRIMARY KEY,
		failed_attempts_in_window INTEGER NOT NULL DEFAULT 0,
		window_started_at DATETIME,
		last_failed_attempt_at DATETIME
	);

	CREATE TABLE user_mfa_backup_codes (
		username TEXT NOT NULL,
		code_index INTEGER NOT NULL,
		code_hash BLOB NOT NULL,
		used_at TIMESTAMP,
		PRIMARY KEY (username, code_index),
		UNIQUE (username, code_hash)
	);

	CREATE TABLE mfa_usage_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		code_hash TEXT NOT NULL,
		window_start INTEGER NOT NULL,
		used_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE mfa_backup_usage (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		code_hash TEXT NOT NULL,
		used_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
`
