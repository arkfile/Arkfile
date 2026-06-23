package mfa

import "testing"

func TestParseCredentialSummaries(t *testing.T) {
	creds := parseCredentialSummaries(map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"credential_id": "cred-totp",
				"method_type":   "totp",
				"created_at":    "2026-06-23T12:00:00Z",
			},
			map[string]interface{}{
				"credential_id": "cred-web",
				"method_type":   "webauthn",
				"label":         "Desk key",
			},
		},
	})
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	if creds[0].CredentialID != "cred-totp" || creds[0].MethodType != "totp" {
		t.Fatalf("unexpected first credential: %+v", creds[0])
	}
	if creds[1].Label != "Desk key" {
		t.Fatalf("expected webauthn label, got %q", creds[1].Label)
	}
}

func TestParseAdminCredentialSummaries(t *testing.T) {
	creds := parseAdminCredentialSummaries(map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"credential_id": "cred-1",
				"method_type":   "webauthn",
			},
		},
	})
	if len(creds) != 1 || creds[0].CredentialID != "cred-1" {
		t.Fatalf("unexpected admin credentials: %+v", creds)
	}
}

func TestPickResetMethodExplicit(t *testing.T) {
	method, err := PickResetMethod(true, MethodWebAuthn)
	if err != nil {
		t.Fatalf("PickResetMethod: %v", err)
	}
	if method != MethodWebAuthn {
		t.Fatalf("got %q", method)
	}
}

func TestParseMFAMethods(t *testing.T) {
	methods := ParseMFAMethods(map[string]interface{}{
		"mfa_methods": []interface{}{
			map[string]interface{}{
				"type":          "webauthn",
				"credential_id": "abc",
				"label":         "YubiKey",
			},
		},
	})
	if len(methods) != 1 || methods[0]["credential_id"] != "abc" {
		t.Fatalf("unexpected methods: %+v", methods)
	}
}
