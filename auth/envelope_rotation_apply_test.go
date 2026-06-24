package auth

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arkfile/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

func setupEnvelopeApplyDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	schema := `
		CREATE TABLE envelope_master_rotation_mandates (
			nonce TEXT PRIMARY KEY,
			admin_username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			consumed_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			consumed_at TIMESTAMP
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedEnvelopeSystemKey(t *testing.T, db *sql.DB, master []byte, keyID, keyType string, raw []byte) {
	t.Helper()
	enc, nonce, err := crypto.EncryptSystemKeyWithMaster(master, raw, keyType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO system_keys (key_id, key_type, encrypted_data, nonce) VALUES (?, ?, ?, ?)`,
		keyID, keyType, hex.EncodeToString(enc), hex.EncodeToString(nonce),
	); err != nil {
		t.Fatal(err)
	}
}

func writeTestSecretsEnv(t *testing.T, dir string, masterHex string) string {
	t.Helper()
	etc := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etc, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(etc, "secrets.env")
	content := "# Arkfile secrets\n" +
		"OTHER_SETTING=keepme\n" +
		"ARKFILE_MASTER_KEY=" + masterHex + "\n" +
		"TRAILING_SETTING=alsokeep\n"
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyEnvelopeMasterRotation_FullPath(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	db := setupEnvelopeApplyDB(t)
	defer db.Close()

	oldMaster := bytes.Repeat([]byte{0x07}, 32)
	jwtRaw := bytes.Repeat([]byte{0x33}, 32)
	entityOld := bytes.Repeat([]byte{0xAA}, 32)
	seedEnvelopeSystemKey(t, db, oldMaster, "jwt_signing_key_full_v1", "jwt", jwtRaw)
	seedEnvelopeSystemKey(t, db, oldMaster, "opaque_server_private_key", "opaque", []byte("opaque-private-material"))
	seedEnvelopeSystemKey(t, db, oldMaster, crypto.EntityIDMasterKeyID, crypto.EntityIDKeyType, entityOld)

	mandate, _, err := IssueEnvelopeRotationMandate(db, "rotation-admin")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	secretsPath := writeTestSecretsEnv(t, tmpDir, hex.EncodeToString(oldMaster))

	stats, err := ApplyEnvelopeMasterRotation(ApplyEnvelopeMasterRotationOptions{
		BaseDir:          tmpDir,
		SecretsEnvPath:   secretsPath,
		Mandate:          mandate,
		DB:               db,
		SkipServiceCheck: true,
		BackupDirectory:  filepath.Join(tmpDir, "backups"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.RowsRewrapped != 3 || !stats.EntityIDRegenerated {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// secrets.env should now carry a different master and preserve other lines.
	newMaster := readMasterFromTestSecrets(t, secretsPath)
	if bytes.Equal(newMaster, oldMaster) {
		t.Fatal("master key in secrets.env was not rotated")
	}
	content, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "OTHER_SETTING=keepme") || !strings.Contains(string(content), "TRAILING_SETTING=alsokeep") {
		t.Fatalf("secrets.env lost unrelated lines:\n%s", content)
	}

	// Rows must decrypt under the new master; JWT value preserved, EntityID changed.
	if _, err := crypto.VerifyAllSystemKeysDecryptable(db, newMaster); err != nil {
		t.Fatalf("rows do not verify under new master: %v", err)
	}

	// Recovery file and secrets.env backup must both exist.
	entries, err := os.ReadDir(filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	var sawRecovery, sawSecretsBackup bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "envelope-master-") && strings.HasSuffix(e.Name(), ".new") {
			sawRecovery = true
		}
		if strings.HasPrefix(e.Name(), "secrets.env-") {
			sawSecretsBackup = true
		}
	}
	if !sawRecovery || !sawSecretsBackup {
		t.Fatalf("expected recovery file and secrets.env backup, got entries: %v", entries)
	}
}

func readMasterFromTestSecrets(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ARKFILE_MASTER_KEY=") {
			hexVal := strings.TrimPrefix(line, "ARKFILE_MASTER_KEY=")
			b, derr := hex.DecodeString(hexVal)
			if derr != nil {
				t.Fatal(derr)
			}
			return b
		}
	}
	t.Fatal("ARKFILE_MASTER_KEY not found after rotation")
	return nil
}

func TestApplyEnvelopeMasterRotation_RejectsReplay(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	db := setupEnvelopeApplyDB(t)
	defer db.Close()

	oldMaster := bytes.Repeat([]byte{0x09}, 32)
	seedEnvelopeSystemKey(t, db, oldMaster, "jwt_signing_key_full_v1", "jwt", bytes.Repeat([]byte{0x33}, 32))

	mandate, _, err := IssueEnvelopeRotationMandate(db, "rotation-admin")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	secretsPath := writeTestSecretsEnv(t, tmpDir, hex.EncodeToString(oldMaster))

	opts := ApplyEnvelopeMasterRotationOptions{
		BaseDir:          tmpDir,
		SecretsEnvPath:   secretsPath,
		Mandate:          mandate,
		DB:               db,
		SkipServiceCheck: true,
		BackupDirectory:  filepath.Join(tmpDir, "backups"),
	}

	if _, err := ApplyEnvelopeMasterRotation(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyEnvelopeMasterRotation(opts); err == nil {
		t.Fatal("expected replay apply to fail (mandate already consumed)")
	}
}

func TestApplyEnvelopeMasterRotation_RejectsInvalidMandate(t *testing.T) {
	db := setupEnvelopeApplyDB(t)
	defer db.Close()

	oldMaster := bytes.Repeat([]byte{0x0a}, 32)
	tmpDir := t.TempDir()
	secretsPath := writeTestSecretsEnv(t, tmpDir, hex.EncodeToString(oldMaster))

	_, err := ApplyEnvelopeMasterRotation(ApplyEnvelopeMasterRotationOptions{
		BaseDir:          tmpDir,
		SecretsEnvPath:   secretsPath,
		Mandate:          "not-a-valid-mandate",
		DB:               db,
		SkipServiceCheck: true,
		BackupDirectory:  filepath.Join(tmpDir, "backups"),
	})
	if err == nil {
		t.Fatal("expected invalid mandate to fail")
	}
}
