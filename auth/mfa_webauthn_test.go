package auth

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
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
	if !bytesEqual(plaintext, webAuthnPendingBlob) {
		t.Fatal("pending blob round-trip mismatch")
	}
}

func TestStoreWebAuthnPendingSetup(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "webauthn-enroll-user"
	codes := []string{"ABCDEFGHIJ", "KLMNOPQRST"}

	if _, err := StoreWebAuthnPendingSetup(db, username, codes, true); err != nil {
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

func TestWebAuthnRegisterBegin_AllowsSecondMethodWhenTOTPEnrolled(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "dual-method-user"
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

	_, codes, _, err := WebAuthnRegisterBegin(db, username)
	if err != nil {
		t.Fatalf("WebAuthnRegisterBegin after TOTP: %v", err)
	}
	if len(codes) != 0 {
		t.Fatalf("expected no backup codes when adding second method, got %d", len(codes))
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

	if _, err := StoreWebAuthnPendingSetup(db, username, []string{"ABCDEFGHIJ"}, true); err != nil {
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

func TestValidateWebAuthnUserLabel(t *testing.T) {
	if err := ValidateWebAuthnUserLabel("Desk Nitrokey"); err != nil {
		t.Fatalf("valid label rejected: %v", err)
	}
	if err := ValidateWebAuthnUserLabel(""); err != nil {
		t.Fatalf("empty label should be allowed: %v", err)
	}
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'A'
	}
	if err := ValidateWebAuthnUserLabel(string(long)); err == nil {
		t.Fatal("expected length error")
	}
	if err := ValidateWebAuthnUserLabel("café"); err == nil {
		t.Fatal("expected non-ascii rejection")
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
	if w.Config.AuthenticatorSelection.UserVerification != protocol.VerificationDiscouraged {
		t.Fatalf("expected userVerification discouraged, got %q", w.Config.AuthenticatorSelection.UserVerification)
	}
}
