package auth

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupEnvelopeMandateTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE envelope_master_rotation_mandates (
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

func TestEnvelopeRotationMandate_IssueVerifyConsume(t *testing.T) {
	db := setupEnvelopeMandateTestDB(t)
	defer db.Close()

	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	mandate, expiresAt, err := IssueEnvelopeRotationMandate(db, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if mandate == "" || expiresAt.Before(time.Now()) {
		t.Fatal("expected non-empty mandate with future expiry")
	}

	payload, err := VerifyEnvelopeRotationMandate(mandate, GetJWTFullPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if payload.AdminUsername != "admin" || payload.Purpose != EnvelopeRotationMandatePurpose {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	if err := ConsumeEnvelopeRotationMandate(db, payload.Nonce); err != nil {
		t.Fatal(err)
	}
	if err := ConsumeEnvelopeRotationMandate(db, payload.Nonce); err == nil {
		t.Fatal("expected replay consumption to fail")
	}
}

func TestEnvelopeRotationMandate_RejectsTampered(t *testing.T) {
	db := setupEnvelopeMandateTestDB(t)
	defer db.Close()

	ResetKeysForTest()
	if err := LoadJWTFullKeys(); err != nil {
		t.Fatal(err)
	}

	mandate, _, err := IssueEnvelopeRotationMandate(db, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnvelopeRotationMandate(mandate+"tampered", GetJWTFullPublicKey()); err == nil {
		t.Fatal("expected tampered mandate to fail verification")
	}
}
