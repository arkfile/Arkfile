package auth

import (
	"bytes"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestWebAuthnPendingBlobRoundTrip(t *testing.T) {
	setupTOTPTestEnvironment(t)

	username := "webauthn-pending-user"
	encrypted, err := encryptWebAuthnBlob(username, webAuthnPendingBlob)
	if err != nil {
		t.Fatalf("encrypt pending blob: %v", err)
	}

	plaintext, err := decryptWebAuthnBlob(username, encrypted)
	if err != nil {
		t.Fatalf("decrypt pending blob: %v", err)
	}
	if !bytes.Equal(plaintext, webAuthnPendingBlob) {
		t.Fatal("pending blob round-trip mismatch")
	}
}

func TestStoreWebAuthnPendingSetup(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "webauthn-enroll-user"
	codes := []string{"ABCDEFGHIJ", "KLMNOPQRST"}

	if err := StoreWebAuthnPendingSetup(db, username, codes); err != nil {
		t.Fatalf("StoreWebAuthnPendingSetup: %v", err)
	}

	method, err := GetPendingMFAMethodType(db, username)
	if err != nil {
		t.Fatalf("GetPendingMFAMethodType: %v", err)
	}
	if method != MFAMethodWebAuthn {
		t.Fatalf("expected pending webauthn, got %q", method)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_mfa_backup_codes WHERE username = ?`, username).Scan(&count); err != nil {
		t.Fatalf("count backup codes: %v", err)
	}
	if count != len(codes) {
		t.Fatalf("expected %d backup code rows, got %d", len(codes), count)
	}
}

func TestWebAuthnRegisterBegin_RejectsWhenAlreadyEnabled(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "enabled-webauthn-user"
	setup, err := GenerateMFASetup(username)
	if err != nil {
		t.Fatalf("GenerateMFASetup: %v", err)
	}
	if err := StoreMFASetup(db, username, setup); err != nil {
		t.Fatalf("StoreMFASetup: %v", err)
	}

	currentCode, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	if err := CompleteMFASetup(db, username, currentCode); err != nil {
		t.Fatalf("CompleteMFASetup: %v", err)
	}

	_, _, err = WebAuthnRegisterBegin(db, username)
	if err == nil || err.Error() != "MFA already enabled" {
		t.Fatalf("expected MFA already enabled error, got %v", err)
	}
}

func TestGetUserMFAMethodType_PendingWebAuthn(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "method-type-user"

	method, err := GetUserMFAMethodType(db, username)
	if err != nil {
		t.Fatalf("GetUserMFAMethodType empty: %v", err)
	}
	if method != "" {
		t.Fatalf("expected empty method, got %q", method)
	}

	if err := StoreWebAuthnPendingSetup(db, username, []string{"ABCDEFGHIJ"}); err != nil {
		t.Fatalf("StoreWebAuthnPendingSetup: %v", err)
	}

	pending, err := GetPendingMFAMethodType(db, username)
	if err != nil {
		t.Fatalf("GetPendingMFAMethodType: %v", err)
	}
	if pending != MFAMethodWebAuthn {
		t.Fatalf("expected pending webauthn, got %q", pending)
	}
}

func TestGetWebAuthnConfig(t *testing.T) {
	setupTOTPTestEnvironment(t)

	w, err := GetWebAuthn()
	if err != nil {
		t.Fatalf("GetWebAuthn: %v", err)
	}
	if w == nil {
		t.Fatal("GetWebAuthn returned nil")
	}
}
