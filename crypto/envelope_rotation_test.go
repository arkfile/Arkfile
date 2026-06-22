package crypto

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func newSystemKeysDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			consumed_at TIMESTAMP
		);
	`); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedSystemKey(t *testing.T, db *sql.DB, master []byte, keyID, keyType string, raw []byte) {
	t.Helper()
	enc, nonce, err := EncryptSystemKeyWithMaster(master, raw, keyType)
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

func readSystemKeyPlaintext(t *testing.T, db *sql.DB, master []byte, keyID, keyType string) []byte {
	t.Helper()
	var encHex, nonceHex string
	if err := db.QueryRow(`SELECT encrypted_data, nonce FROM system_keys WHERE key_id = ?`, keyID).Scan(&encHex, &nonceHex); err != nil {
		t.Fatal(err)
	}
	enc, err := hex.DecodeString(encHex)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptSystemKeyWithMaster(master, enc, nonce, keyType)
	if err != nil {
		t.Fatalf("decrypt %s under provided master: %v", keyID, err)
	}
	return pt
}

func TestReencryptAllSystemKeys_RewrapsAndRegeneratesEntityID(t *testing.T) {
	db := newSystemKeysDB(t)
	defer db.Close()

	oldMaster := bytes.Repeat([]byte{0x01}, 32)
	newMaster := bytes.Repeat([]byte{0x02}, 32)

	jwtRaw := bytes.Repeat([]byte{0x33}, 32)
	opaqueRaw := []byte("opaque-server-private-key-material-xyz")
	entityOld := bytes.Repeat([]byte{0xAA}, 32)

	seedSystemKey(t, db, oldMaster, "jwt_signing_key_full_v1", "jwt", jwtRaw)
	seedSystemKey(t, db, oldMaster, "opaque_server_private_key", "opaque", opaqueRaw)
	seedSystemKey(t, db, oldMaster, EntityIDMasterKeyID, EntityIDKeyType, entityOld)

	stats, err := ReencryptAllSystemKeys(db, oldMaster, newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if stats.RowsRewrapped != 3 {
		t.Fatalf("expected 3 rows re-wrapped, got %d", stats.RowsRewrapped)
	}
	if !stats.EntityIDRegenerated {
		t.Fatal("expected EntityID master to be regenerated")
	}

	// Non-EntityID rows keep their value but now decrypt under the new master.
	if got := readSystemKeyPlaintext(t, db, newMaster, "jwt_signing_key_full_v1", "jwt"); !bytes.Equal(got, jwtRaw) {
		t.Fatal("JWT key value changed during re-wrap")
	}
	if got := readSystemKeyPlaintext(t, db, newMaster, "opaque_server_private_key", "opaque"); !bytes.Equal(got, opaqueRaw) {
		t.Fatal("OPAQUE key value changed during re-wrap")
	}

	// EntityID master is replaced with fresh 32-byte material.
	entityNew := readSystemKeyPlaintext(t, db, newMaster, EntityIDMasterKeyID, EntityIDKeyType)
	if len(entityNew) != 32 {
		t.Fatalf("expected 32-byte EntityID master, got %d", len(entityNew))
	}
	if bytes.Equal(entityNew, entityOld) {
		t.Fatal("EntityID master was not regenerated")
	}

	// Old master can no longer decrypt the re-wrapped rows.
	if _, err := VerifyAllSystemKeysDecryptable(db, oldMaster); err == nil {
		t.Fatal("expected verification under old master to fail after rotation")
	}

	count, err := VerifyAllSystemKeysDecryptable(db, newMaster)
	if err != nil {
		t.Fatalf("full-table verification under new master failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 rows verified, got %d", count)
	}
}

func TestReencryptAllSystemKeys_NoEntityIDRow(t *testing.T) {
	db := newSystemKeysDB(t)
	defer db.Close()

	oldMaster := bytes.Repeat([]byte{0x05}, 32)
	newMaster := bytes.Repeat([]byte{0x06}, 32)

	seedSystemKey(t, db, oldMaster, "jwt_signing_key_temp_v1", "jwt", bytes.Repeat([]byte{0x44}, 32))

	stats, err := ReencryptAllSystemKeys(db, oldMaster, newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if stats.RowsRewrapped != 1 {
		t.Fatalf("expected 1 row re-wrapped, got %d", stats.RowsRewrapped)
	}
	if stats.EntityIDRegenerated {
		t.Fatal("expected EntityID not regenerated when no row is present")
	}
}

func TestReencryptAllSystemKeys_RejectsBadMasterLength(t *testing.T) {
	db := newSystemKeysDB(t)
	defer db.Close()

	if _, err := ReencryptAllSystemKeys(db, make([]byte, 16), make([]byte, 32)); err == nil {
		t.Fatal("expected error for short old master")
	}
	if _, err := ReencryptAllSystemKeys(db, make([]byte, 32), make([]byte, 31)); err == nil {
		t.Fatal("expected error for short new master")
	}
}
