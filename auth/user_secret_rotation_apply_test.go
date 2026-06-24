package auth

import (
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkfile/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

func setupApplyRotationDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	schema := `
		CREATE TABLE user_secret_rotation_mandates (
			nonce TEXT PRIMARY KEY,
			admin_username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			consumed_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE user_mfa_credentials (
			credential_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			method_type TEXT NOT NULL DEFAULT 'totp',
			credential_data BLOB NOT NULL
		);
		CREATE TABLE user_contact_info (
			username TEXT PRIMARY KEY,
			encrypted_data BLOB NOT NULL,
			nonce TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedUserSecretWrappedRows(t *testing.T, db *sql.DB, oldMaster []byte, username string) {
	t.Helper()
	oldMFAKey, err := crypto.DeriveMFAUserKeyFromMaster(oldMaster, username)
	if err != nil {
		t.Fatal(err)
	}
	encMFA, err := crypto.EncryptGCM([]byte("ROTATION-SECRET"), oldMFAKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO user_mfa_credentials (credential_id, username, method_type, credential_data) VALUES (?, ?, 'totp', ?)`,
		"cred-rotation", username, encMFA,
	); err != nil {
		t.Fatal(err)
	}

	contactKey, err := crypto.DeriveUserSecretSubkeyFromMaster(oldMaster, []byte("contact_info"))
	if err != nil {
		t.Fatal(err)
	}
	encContact, err := crypto.EncryptGCM([]byte(`{"display_name":"Rotate","contacts":[],"notes":""}`), contactKey)
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

func TestApplyUserSecretMasterRotation_FullPath(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	db := setupApplyRotationDB(t)
	defer db.Close()

	oldMaster := make([]byte, 32)
	copy(oldMaster, []byte("old-user-secret-master-material"))

	mandate, _, err := IssueUserSecretRotationMandate(db, "rotation-admin")
	if err != nil {
		t.Fatal(err)
	}

	const username = "rotation-user"
	seedUserSecretWrappedRows(t, db, oldMaster, username)

	tmpDir := t.TempDir()
	masterPath := filepath.Join(tmpDir, "etc", "keys", "user-secret-master.bin")
	if err := os.MkdirAll(filepath.Dir(masterPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := crypto.WriteUserSecretMasterFile(masterPath, oldMaster, -1, -1); err != nil {
		t.Fatal(err)
	}

	stats, err := ApplyUserSecretMasterRotation(ApplyUserSecretMasterRotationOptions{
		BaseDir:          tmpDir,
		MasterKeyPath:    masterPath,
		Mandate:          mandate,
		DB:               db,
		SkipServiceCheck: true,
		BackupDirectory:  filepath.Join(tmpDir, "backups"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.MFACredentials != 1 || stats.ContactInfo != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	newMaster, err := crypto.ReadUserSecretMasterFile(masterPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(newMaster) == string(oldMaster) {
		t.Fatal("master key file was not rotated")
	}

	newMFAKey, err := crypto.DeriveMFAUserKeyFromMaster(newMaster, username)
	if err != nil {
		t.Fatal(err)
	}
	var storedMFA []byte
	if err := db.QueryRow(`SELECT credential_data FROM user_mfa_credentials WHERE username = ?`, username).Scan(&storedMFA); err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.DecryptGCM(storedMFA, newMFAKey)
	if err != nil || string(pt) != "ROTATION-SECRET" {
		t.Fatalf("MFA decrypt after apply failed: %v %q", err, pt)
	}

	backupEntries, err := os.ReadDir(filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	if len(backupEntries) != 1 {
		t.Fatalf("expected one backup file, got %d", len(backupEntries))
	}
}

func TestApplyUserSecretMasterRotation_RejectsReplay(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	db := setupApplyRotationDB(t)
	defer db.Close()

	oldMaster := make([]byte, 32)
	copy(oldMaster, []byte("old-user-secret-master-material"))

	mandate, _, err := IssueUserSecretRotationMandate(db, "rotation-admin")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	masterPath := filepath.Join(tmpDir, "user-secret-master.bin")
	if err := crypto.WriteUserSecretMasterFile(masterPath, oldMaster, -1, -1); err != nil {
		t.Fatal(err)
	}

	opts := ApplyUserSecretMasterRotationOptions{
		BaseDir:          tmpDir,
		MasterKeyPath:    masterPath,
		Mandate:          mandate,
		DB:               db,
		SkipServiceCheck: true,
		BackupDirectory:  filepath.Join(tmpDir, "backups"),
	}

	if _, err := ApplyUserSecretMasterRotation(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyUserSecretMasterRotation(opts); err == nil {
		t.Fatal("expected replay apply to fail")
	}
}

func TestApplyUserSecretMasterRotation_RejectsInvalidMandate(t *testing.T) {
	db := setupApplyRotationDB(t)
	defer db.Close()

	tmpDir := t.TempDir()
	masterPath := filepath.Join(tmpDir, "user-secret-master.bin")
	oldMaster := make([]byte, 32)
	if err := crypto.WriteUserSecretMasterFile(masterPath, oldMaster, -1, -1); err != nil {
		t.Fatal(err)
	}

	_, err := ApplyUserSecretMasterRotation(ApplyUserSecretMasterRotationOptions{
		MasterKeyPath:    masterPath,
		Mandate:          "not-a-valid-mandate",
		DB:               db,
		SkipServiceCheck: true,
		BackupDirectory:  filepath.Join(tmpDir, "backups"),
	})
	if err == nil {
		t.Fatal("expected invalid mandate to fail")
	}
}
