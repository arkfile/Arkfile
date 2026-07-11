package subbridge

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type protocolFixture struct {
	PairingRoot struct {
		ConfiguredHex string `json:"configured_hex"`
		Keys          struct {
			Token struct {
				DerivedKeyHex string `json:"derived_key_hex"`
			} `json:"token"`
			Callback struct {
				DerivedKeyHex string `json:"derived_key_hex"`
			} `json:"callback"`
			Reconcile struct {
				DerivedKeyHex string `json:"derived_key_hex"`
			} `json:"reconcile"`
		} `json:"keys"`
	} `json:"pairing_root"`
	StartToken struct {
		PayloadJSON string `json:"payload_json_utf8"`
		Token       string `json:"token"`
	} `json:"start_token"`
	PortalToken struct {
		PayloadJSON string `json:"payload_json_utf8"`
		Token       string `json:"token"`
	} `json:"portal_token"`
	Callback struct {
		BodyJSON           string `json:"body_json_utf8"`
		SignatureTimestamp int64  `json:"signature_timestamp"`
		SignatureHeader    string `json:"signature_header"`
	} `json:"callback"`
	ReconciliationRequest struct {
		Method             string `json:"method"`
		Path               string `json:"path"`
		SignatureTimestamp int64  `json:"signature_timestamp"`
		Authorization      string `json:"authorization_header"`
	} `json:"reconciliation_request"`
	Snapshot struct {
		BodyJSON string `json:"body_json_utf8"`
	} `json:"snapshot"`
}

func loadProtocolFixture(t *testing.T) protocolFixture {
	t.Helper()
	body, err := os.ReadFile("testdata/protocol-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture protocolFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestProtocolV1Fixture(t *testing.T) {
	fixture := loadProtocolFixture(t)
	keys, err := DeriveKeys(fixture.PairingRoot.ConfiguredHex)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(keys.Token[:]) != fixture.PairingRoot.Keys.Token.DerivedKeyHex ||
		hex.EncodeToString(keys.Callback[:]) != fixture.PairingRoot.Keys.Callback.DerivedKeyHex ||
		hex.EncodeToString(keys.Reconcile[:]) != fixture.PairingRoot.Keys.Reconcile.DerivedKeyHex {
		t.Fatal("derived keys do not match canonical fixture")
	}

	var start StartTokenPayload
	if err := json.Unmarshal([]byte(fixture.StartToken.PayloadJSON), &start); err != nil {
		t.Fatal(err)
	}
	startToken, err := SignStartToken(keys.Token, start)
	if err != nil || startToken != fixture.StartToken.Token {
		t.Fatalf("start token mismatch: %v", err)
	}
	if _, err := verifyTokenAt(keys.Token, startToken, &StartTokenPayload{},
		[]string{"checkout_id", "plan_id", "return_url", "iat", "exp"},
		time.Unix(start.Iat, 0).UTC()); err != nil {
		t.Fatalf("verify fixture start token: %v", err)
	}

	var portal PortalTokenPayload
	if err := json.Unmarshal([]byte(fixture.PortalToken.PayloadJSON), &portal); err != nil {
		t.Fatal(err)
	}
	portalToken, err := SignPortalToken(keys.Token, portal)
	if err != nil || portalToken != fixture.PortalToken.Token {
		t.Fatalf("portal token mismatch: %v", err)
	}

	if got := signWebhookAt(keys.Callback, []byte(fixture.Callback.BodyJSON), fixture.Callback.SignatureTimestamp); got != fixture.Callback.SignatureHeader {
		t.Fatalf("callback signature = %q, want %q", got, fixture.Callback.SignatureHeader)
	}
	var callback CallbackPayload
	if err := DecodeCallback([]byte(fixture.Callback.BodyJSON), &callback); err != nil {
		t.Fatalf("decode fixture callback: %v", err)
	}

	request := fixture.ReconciliationRequest
	if got := signBridgeGETAt(keys.Reconcile, request.Method, request.Path, request.SignatureTimestamp); got != request.Authorization {
		t.Fatalf("reconcile signature = %q, want %q", got, request.Authorization)
	}
	var snapshot SnapshotPayload
	if err := DecodeSnapshot([]byte(fixture.Snapshot.BodyJSON), &snapshot); err != nil {
		t.Fatalf("decode fixture snapshot: %v", err)
	}
}

func TestDeriveKeysRejectsInvalidRootEncoding(t *testing.T) {
	for _, root := range []string{
		"",
		"00",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		" 00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	} {
		if _, err := DeriveKeys(root); err == nil {
			t.Fatalf("expected invalid root %q to fail", root)
		}
	}
}

func TestDecodeCallbackRejectsMissingUnknownAndDuplicateFields(t *testing.T) {
	fixture := loadProtocolFixture(t)
	valid := fixture.Callback.BodyJSON
	var payload CallbackPayload
	if err := DecodeCallback([]byte(valid), &payload); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"missing":   `{"protocol":"subscription-bridge"}`,
		"unknown":   valid[:len(valid)-1] + `,"extra":true}`,
		"duplicate": valid[:len(valid)-1] + `,"status":"expired"}`,
	} {
		if err := DecodeCallback([]byte(body), &payload); err == nil {
			t.Fatalf("%s payload should fail", name)
		}
	}
}

func TestDecodeCallbackAcceptsAnyKeyOrderAndRejectsInvalidUTF8(t *testing.T) {
	fixture := loadProtocolFixture(t)
	var unordered map[string]interface{}
	if err := json.Unmarshal([]byte(fixture.Callback.BodyJSON), &unordered); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(unordered)
	if err != nil {
		t.Fatal(err)
	}
	var payload CallbackPayload
	if err := DecodeCallback(reordered, &payload); err != nil {
		t.Fatalf("reordered callback keys should be accepted: %v", err)
	}

	invalid := bytes.Replace(
		[]byte(fixture.Callback.BodyJSON),
		[]byte("plan_500gb"),
		[]byte{'p', 'l', 'a', 'n', '_', 0xff},
		1,
	)
	if err := DecodeCallback(invalid, &payload); err == nil {
		t.Fatal("invalid UTF-8 callback should fail")
	}
}

func TestFetchSubscriptionSnapshotPreservesExactBody(t *testing.T) {
	fixture := loadProtocolFixture(t)
	keys, err := DeriveKeys(fixture.PairingRoot.ConfiguredHex)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscriptions/sub_a8f3c1d2" {
			http.NotFound(w, r)
			return
		}
		if err := VerifyBridgeGET(keys.Reconcile, r.Method, r.URL.RequestURI(), r.Header.Get("Authorization")); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture.Snapshot.BodyJSON))
	}))
	defer server.Close()

	response, err := FetchSubscriptionSnapshot(server.URL, keys.Reconcile, "sub_a8f3c1d2")
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != fixture.Snapshot.BodyJSON {
		t.Fatal("snapshot body bytes changed")
	}
	if response.Payload.SubscriptionRef != "sub_a8f3c1d2" {
		t.Fatalf("unexpected snapshot: %+v", response.Payload)
	}
}
