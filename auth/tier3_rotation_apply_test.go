package auth

import (
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/84adam/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

func setupApplyRotationDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	schema := `
		CREATE TABLE tier3_rotation_mandates (
			nonce TEXT PRIMARY KEY,
			admin_username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			consumed_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE user_mfa_credentials (
			username TEXT PRIMARY KEY,
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

func seedTier3WrappedRows(t *testing.T, db *sql.DB, oldMaster []byte, username string) {
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
		`INSERT INTO user_mfa_credentials (username, credential_data) VALUES (?, ?)`,
		username, encMFA,
	); err != nil {
		t.Fatal(err)
	}

	contactKey, err := crypto.DeriveTier3SubkeyFromMaster(oldMaster, []byte("contact_info"))
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

func TestApplyTier3MasterRotation_FullPath(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	db := setupApplyRotationDB(t)
	defer db.Close()

	oldMaster := make([]byte, 32)
	copy(oldMaster, []byte("old-tier3-master-key-material!!"))

	mandate, _, err := IssueTier3RotationMandate(db, "rotation-admin")
	if err != nil {
		t.Fatal(err)
	}

	const username = "rotation-user"
	seedTier3WrappedRows(t, db, oldMaster, username)

	tmpDir := t.TempDir()
	masterPath := filepath.Join(tmpDir, "etc", "keys", "user-secret-master.bin")
	if err := os.MkdirAll(filepath.Dir(masterPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := crypto.WriteTier3MasterFile(masterPath, oldMaster, -1, -1); err != nil {
		t.Fatal(err)
	}

	stats, err := ApplyTier3MasterRotation(ApplyTier3MasterRotationOptions{
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

	newMaster, err := crypto.ReadTier3MasterFile(masterPath)
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

func TestApplyTier3MasterRotation_RejectsReplay(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	db := setupApplyRotationDB(t)
	defer db.Close()

	oldMaster := make([]byte, 32)
	copy(oldMaster, []byte("old-tier3-master-key-material!!"))

	mandate, _, err := IssueTier3RotationMandate(db, "rotation-admin")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	masterPath := filepath.Join(tmpDir, "user-secret-master.bin")
	if err := crypto.WriteTier3MasterFile(masterPath, oldMaster, -1, -1); err != nil {
		t.Fatal(err)
	}

	opts := ApplyTier3MasterRotationOptions{
		BaseDir:          tmpDir,
		MasterKeyPath:    masterPath,
		Mandate:          mandate,
		DB:               db,
		SkipServiceCheck: true,
		BackupDirectory:  filepath.Join(tmpDir, "backups"),
	}

	if _, err := ApplyTier3MasterRotation(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyTier3MasterRotation(opts); err == nil {
		t.Fatal("expected replay apply to fail")
	}
}

func TestApplyTier3MasterRotation_RejectsInvalidMandate(t *testing.T) {
	db := setupApplyRotationDB(t)
	defer db.Close()

	tmpDir := t.TempDir()
	masterPath := filepath.Join(tmpDir, "user-secret-master.bin")
	oldMaster := make([]byte, 32)
	if err := crypto.WriteTier3MasterFile(masterPath, oldMaster, -1, -1); err != nil {
		t.Fatal(err)
	}

	_, err := ApplyTier3MasterRotation(ApplyTier3MasterRotationOptions{
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
