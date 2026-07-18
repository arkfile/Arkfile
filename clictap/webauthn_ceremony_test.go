package clictap

import (
	"encoding/json"
	"testing"
)

func TestOriginFromServerURL(t *testing.T) {
	if got := OriginFromServerURL("https://localhost:8443/"); got != "https://localhost:8443" {
		t.Fatalf("OriginFromServerURL() = %q", got)
	}
}

func TestBuildClientDataCreate(t *testing.T) {
	raw := buildClientDataCreate("challenge-b64", "https://localhost:8443")
	var parsed map[string]string
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["type"] != "webauthn.create" {
		t.Fatalf("type = %q", parsed["type"])
	}
	if parsed["challenge"] != "challenge-b64" {
		t.Fatalf("challenge = %q", parsed["challenge"])
	}
	if parsed["origin"] != "https://localhost:8443" {
		t.Fatalf("origin = %q", parsed["origin"])
	}
}

func TestMapUserVerification(t *testing.T) {
	if mapUserVerification("required") != OptTrue {
		t.Fatal("required should map to OptTrue")
	}
	if mapUserVerification("discouraged") != OptFalse {
		t.Fatal("discouraged should map to OptFalse")
	}
	if mapUserVerification("preferred") != OptFalse {
		t.Fatal("preferred should map to OptFalse (touch-only policy)")
	}
	if mapUserVerification("") != OptFalse {
		t.Fatal("empty should map to OptFalse")
	}
	if mapUserVerification("unknown") != OptFalse {
		t.Fatal("unknown should map to OptFalse")
	}
}

func TestUvFromCreation(t *testing.T) {
	if got := uvFromCreation(creationOptions{}); got != "discouraged" {
		t.Fatalf("nil selection = %q, want discouraged", got)
	}

	var emptyUV creationOptions
	if err := json.Unmarshal([]byte(`{"authenticatorSelection":{"userVerification":""}}`), &emptyUV); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := uvFromCreation(emptyUV); got != "discouraged" {
		t.Fatalf("empty uv = %q, want discouraged", got)
	}

	var explicit creationOptions
	if err := json.Unmarshal([]byte(`{"authenticatorSelection":{"userVerification":"discouraged"}}`), &explicit); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := uvFromCreation(explicit); got != "discouraged" {
		t.Fatalf("explicit discouraged = %q", got)
	}
}

func TestBuildAttestationObject(t *testing.T) {
	authData := []byte{0x01, 0x02}
	raw, err := buildAttestationObject(authData)
	if err != nil {
		t.Fatalf("buildAttestationObject: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected CBOR output")
	}
}
