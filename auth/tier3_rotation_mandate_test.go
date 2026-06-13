package auth

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/84adam/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

func setupMandateTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE tier3_rotation_mandates (
			nonce TEXT PRIMARY KEY,
			admin_username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			consumed_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestTier3RotationMandate_IssueVerifyConsume(t *testing.T) {
	crypto.SetTier3MasterForTest(make([]byte, 32))
	db := setupMandateTestDB(t)
	defer db.Close()

	os.Setenv("ARKFILE_MASTER_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	defer os.Unsetenv("ARKFILE_MASTER_KEY")

	if err := crypto.InitKeyManager(db); err != nil {
		t.Fatal(err)
	}
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	mandate, expiresAt, err := IssueTier3RotationMandate(db, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if mandate == "" || expiresAt.Before(time.Now()) {
		t.Fatal("expected non-empty mandate with future expiry")
	}

	payload, err := VerifyTier3RotationMandate(mandate, GetJWTFullPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if payload.AdminUsername != "admin" || payload.Purpose != Tier3RotationMandatePurpose {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	if err := ConsumeTier3RotationMandate(db, payload.Nonce); err != nil {
		t.Fatal(err)
	}
	if err := ConsumeTier3RotationMandate(db, payload.Nonce); err == nil {
		t.Fatal("expected replay consumption to fail")
	}
}

func TestTier3RotationMandate_RejectsTampered(t *testing.T) {
	crypto.SetTier3MasterForTest(make([]byte, 32))
	db := setupMandateTestDB(t)
	defer db.Close()

	os.Setenv("ARKFILE_MASTER_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	defer os.Unsetenv("ARKFILE_MASTER_KEY")

	if err := crypto.InitKeyManager(db); err != nil {
		t.Fatal(err)
	}
	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	mandate, _, err := IssueTier3RotationMandate(db, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTier3RotationMandate(mandate+"tampered", GetJWTFullPublicKey()); err == nil {
		t.Fatal("expected tampered mandate to fail verification")
	}
}
