package auth

import (
	"database/sql"
	"encoding/base64"
	"testing"

	"github.com/84adam/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

func setupAdminResetTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	schema := `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			username_folded TEXT UNIQUE NOT NULL,
			storage_limit_bytes INTEGER NOT NULL DEFAULT 1073741824,
			is_approved BOOLEAN DEFAULT FALSE,
			is_admin BOOLEAN DEFAULT FALSE,
			deleted_at TIMESTAMP
		);
	` + MFATestSchemaDDL + `
		CREATE TABLE user_contact_info (
			username TEXT PRIMARY KEY,
			encrypted_data BLOB NOT NULL,
			nonce TEXT NOT NULL
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedAdminResetUser(t *testing.T, db *sql.DB, username string) {
	t.Helper()
	crypto.SetUserSecretMasterForTest(make([]byte, 32))
	if _, err := db.Exec(`INSERT INTO users (username, username_folded) VALUES (?, ?)`, username, username); err != nil {
		t.Fatal(err)
	}

	oldMaster := make([]byte, 32)
	copy(oldMaster, []byte("test-user-secret-master-materil"))
	key, err := crypto.DeriveMFAUserKeyFromMaster(oldMaster, username)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.EncryptGCM([]byte("SECRET"), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO user_mfa_credentials (credential_id, username, method_type, credential_data, enabled, setup_completed) VALUES (?, ?, 'totp', ?, 1, 1)`, newCredentialID(), username, enc); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO user_mfa_backup_codes (username, code_index, code_hash) VALUES (?, 0, ?)`, username, []byte("hash")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mfa_usage_log (username, code_hash, window_start) VALUES (?, 'abc', 1)`, username); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mfa_backup_usage (username, code_hash) VALUES (?, 'def')`, username); err != nil {
		t.Fatal(err)
	}

	contactKey, err := crypto.DeriveUserSecretSubkeyFromMaster(oldMaster, []byte("contact_info"))
	if err != nil {
		t.Fatal(err)
	}
	encContact, err := crypto.EncryptGCM([]byte(`{"display_name":"Alice"}`), contactKey)
	if err != nil {
		t.Fatal(err)
	}
	nonceSize := crypto.AesGcmNonceSize()
	if _, err := db.Exec(
		`INSERT INTO user_contact_info (username, encrypted_data, nonce) VALUES (?, ?, ?)`,
		username,
		base64.StdEncoding.EncodeToString(encContact[nonceSize:]),
		base64.StdEncoding.EncodeToString(encContact[:nonceSize]),
	); err != nil {
		t.Fatal(err)
	}
}

func TestAdminFullResetUserMFA_DeletesAllMFARows(t *testing.T) {
	db := setupAdminResetTestDB(t)
	defer db.Close()

	const username = "reset-target"
	seedAdminResetUser(t, db, username)

	stats, err := AdminFullResetUserMFA(db, username)
	if err != nil {
		t.Fatal(err)
	}
	if stats.AlreadyReset || stats.CredentialsDeleted != 1 || stats.BackupCodesDeleted != 1 ||
		stats.UsageLogsDeleted != 1 || stats.BackupUsageDeleted != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	enabled, err := IsUserMFAEnabled(db, username)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("MFA should be disabled after admin reset")
	}

	var contactCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_contact_info WHERE username = ?`, username).Scan(&contactCount); err != nil {
		t.Fatal(err)
	}
	if contactCount != 1 {
		t.Fatal("contact info must remain after MFA reset")
	}
}

func TestAdminFullResetUserMFA_IdempotentWhenAlreadyReset(t *testing.T) {
	db := setupAdminResetTestDB(t)
	defer db.Close()

	const username = "already-reset"
	if _, err := db.Exec(`INSERT INTO users (username, username_folded) VALUES (?, ?)`, username, username); err != nil {
		t.Fatal(err)
	}

	stats, err := AdminFullResetUserMFA(db, username)
	if err != nil {
		t.Fatal(err)
	}
	if !stats.AlreadyReset {
		t.Fatalf("expected already_reset, got %+v", stats)
	}
}

func TestAdminFullResetUserMFA_RejectsEmptyUsername(t *testing.T) {
	db := setupAdminResetTestDB(t)
	defer db.Close()

	if _, err := AdminFullResetUserMFA(db, ""); err == nil {
		t.Fatal("expected error for empty username")
	}
}
