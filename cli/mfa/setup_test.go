package mfa

import "testing"

func TestParseMFAMethod(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
		want Method
	}{
		{"nil", nil, MethodTOTP},
		{"webauthn", map[string]interface{}{"mfa_method": "webauthn"}, MethodWebAuthn},
		{"totp", map[string]interface{}{"mfa_method": "totp"}, MethodTOTP},
		{"unknown", map[string]interface{}{"mfa_method": "sms"}, MethodTOTP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseMFAMethod(tc.data); got != tc.want {
				t.Fatalf("ParseMFAMethod() = %q, want %q", got, tc.want)
			}
		})
	}
}

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
	if _, err := extractOptionsJSON(map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing options")
	}
}
