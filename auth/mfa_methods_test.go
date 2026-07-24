package auth

import (
	"encoding/json"
	"testing"
)

func TestApplyMFAChallengeSetup(t *testing.T) {
	dst := map[string]interface{}{"temp_token": "t"}
	ApplyMFAChallenge(dst, &MFAChallenge{
		RequiresSetup: true,
		Methods:       []MFALoginMethod{},
		PendingMethod: MFAMethodWebAuthn,
	})

	if dst["requires_mfa"] != true || dst["requires_mfa_setup"] != true {
		t.Fatalf("unexpected flags: %+v", dst)
	}
	if dst["pending_mfa_method"] != MFAMethodWebAuthn {
		t.Fatalf("expected pending webauthn, got %v", dst["pending_mfa_method"])
	}
	methods, ok := dst["mfa_methods"].([]MFALoginMethod)
	if !ok || len(methods) != 0 {
		t.Fatalf("expected empty mfa_methods slice, got %T %+v", dst["mfa_methods"], dst["mfa_methods"])
	}
	if _, exists := dst["mfa_method"]; exists {
		t.Fatal("singular mfa_method must not be present")
	}
}

func TestApplyMFAChallengeSingleEnrolled(t *testing.T) {
	dst := map[string]interface{}{}
	ApplyMFAChallenge(dst, &MFAChallenge{
		RequiresSetup: false,
		Methods: []MFALoginMethod{
			{Type: MFAMethodWebAuthn, CredentialID: "cred-1", Label: "Key"},
		},
	})

	if dst["requires_mfa_setup"] != false {
		t.Fatalf("expected requires_mfa_setup false, got %v", dst["requires_mfa_setup"])
	}
	if _, exists := dst["pending_mfa_method"]; exists {
		t.Fatal("pending_mfa_method must not appear when setup is complete")
	}
	methods, ok := dst["mfa_methods"].([]MFALoginMethod)
	if !ok || len(methods) != 1 || methods[0].Type != MFAMethodWebAuthn || methods[0].CredentialID != "cred-1" {
		t.Fatalf("unexpected mfa_methods: %+v", dst["mfa_methods"])
	}

	raw, err := json.Marshal(dst)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !json.Valid(raw) {
		t.Fatal("invalid JSON")
	}
}

func TestBuildMFAChallengeWebAuthnOnly(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "challenge-webauthn-user"
	codes := []string{"ABCDEFGHIJ", "KLMNOPQRST"}
	pending, err := StoreWebAuthnPendingSetup(db, username, codes, true)
	if err != nil {
		t.Fatalf("StoreWebAuthnPendingSetup: %v", err)
	}

	ch, err := BuildMFAChallenge(db, username)
	if err != nil {
		t.Fatalf("BuildMFAChallenge pending: %v", err)
	}
	if !ch.RequiresSetup || ch.PendingMethod != MFAMethodWebAuthn || len(ch.Methods) != 0 {
		t.Fatalf("unexpected pending challenge: %+v", ch)
	}

	if _, err := db.Exec(`
		UPDATE user_mfa_credentials
		SET setup_completed = 1, enabled = 1
		WHERE username = ? AND credential_id = ?`, username, pending); err != nil {
		t.Fatalf("complete pending: %v", err)
	}

	ch, err = BuildMFAChallenge(db, username)
	if err != nil {
		t.Fatalf("BuildMFAChallenge enrolled: %v", err)
	}
	if ch.RequiresSetup || len(ch.Methods) != 1 || ch.Methods[0].Type != MFAMethodWebAuthn {
		t.Fatalf("unexpected enrolled challenge: %+v", ch)
	}
}
