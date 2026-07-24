package mfa

import "testing"

func TestExtractOptionsJSON(t *testing.T) {
	raw, err := extractOptionsJSON(map[string]interface{}{
		"options": map[string]interface{}{
			"challenge": "abc",
			"rpId":      "localhost",
		},
	})
	if err != nil {
		t.Fatalf("extractOptionsJSON: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty JSON")
	}

	if _, err := extractOptionsJSON(nil); err == nil {
		t.Fatal("expected error for nil data")
	}
}

func TestPickLoginMethodEmptyFailsClosed(t *testing.T) {
	_, _, err := PickLoginMethod(false, nil, "", "")
	if err == nil {
		t.Fatal("expected error for empty methods")
	}
}

func TestPickLoginMethodSingleWebAuthn(t *testing.T) {
	methods := []map[string]string{
		{"type": "webauthn", "credential_id": "cred-1", "label": "Key"},
	}
	got, cred, err := PickLoginMethod(false, methods, "", "")
	if err != nil {
		t.Fatalf("PickLoginMethod: %v", err)
	}
	if got != MethodWebAuthn || cred != "cred-1" {
		t.Fatalf("got %q/%q", got, cred)
	}
}

func TestPickLoginMethodExplicitMustBeEnrolled(t *testing.T) {
	methods := []map[string]string{
		{"type": "webauthn", "credential_id": "cred-1"},
	}
	_, _, err := PickLoginMethod(true, methods, MethodTOTP, "")
	if err == nil {
		t.Fatal("expected error when requested method is not enrolled")
	}
}
