package subbridge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testPairingRoot = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func testKeys(t *testing.T) DerivedKeys {
	t.Helper()
	keys, err := DeriveKeys(testPairingRoot)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestDeriveKeys_GoldenVector(t *testing.T) {
	keys, err := DeriveKeys(testPairingRoot)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{
		hex.EncodeToString(keys.Token[:]),
		hex.EncodeToString(keys.Callback[:]),
		hex.EncodeToString(keys.Reconcile[:]),
	}
	want := []string{
		"1c3ffa613421f6a4958704b3090e9b970af7dd9107ce328cc9c5d33546701fa2",
		"069dddf506c40199b88267dbc754808242339730f5cb042f3d72e4e19dbe946d",
		"c090ac1d8b5c248d45c8ce7ca9f9b463b1f6ad4a2086061d53111214e24a433c",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("derived key %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestSignAndVerifyStartToken(t *testing.T) {
	keys := testKeys(t)
	iat := time.Now().UTC().Unix()
	want := StartTokenPayload{
		CheckoutID: "subchk_test",
		PlanID:     "plan_dev_250gb",
		ReturnURL:  "https://example.com/?subscription=return",
		Iat:        iat,
		Exp:        iat + 300,
	}
	token, err := SignStartToken(keys.Token, want)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	got, err := VerifyStartToken(keys.Token, token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.CheckoutID != want.CheckoutID || got.PlanID != want.PlanID {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestVerifyToken_RejectsBadSignature(t *testing.T) {
	keys := testKeys(t)
	iat := time.Now().UTC().Unix()
	token, err := SignStartToken(keys.Token, StartTokenPayload{CheckoutID: "x", PlanID: "y", ReturnURL: "https://example.com/", Iat: iat, Exp: iat + 300})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	parts[1] = strings.Repeat("0", len(parts[1]))
	if _, err := VerifyStartToken(keys.Token, parts[0]+"."+parts[1]); err == nil {
		t.Fatal("expected bad signature error")
	}
}

func TestVerifyToken_RejectsExpired(t *testing.T) {
	keys := testKeys(t)
	iat := time.Now().UTC().Add(-2 * time.Hour).Unix()
	token, err := SignPortalToken(keys.Token, PortalTokenPayload{SubscriptionRef: "sub_x", ReturnURL: "https://example.com/", Iat: iat, Exp: iat + 300})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPortalToken(keys.Token, token); err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestVerifyToken_RejectsNonCanonicalPayloads(t *testing.T) {
	keys := testKeys(t)
	iat := time.Now().UTC().Unix()
	validPrefix := `{"checkout_id":"x","plan_id":"y","return_url":"https://example.com/","iat":`
	for name, body := range map[string]string{
		"missing":   `{"checkout_id":"x","plan_id":"y","return_url":"https://example.com/","exp":9999999999}`,
		"unknown":   validPrefix + strconv.FormatInt(iat, 10) + `,"exp":` + strconv.FormatInt(iat+300, 10) + `,"extra":true}`,
		"duplicate": validPrefix + strconv.FormatInt(iat, 10) + `,"exp":` + strconv.FormatInt(iat+300, 10) + `,"plan_id":"z"}`,
		"too_long":  validPrefix + strconv.FormatInt(iat, 10) + `,"exp":` + strconv.FormatInt(iat+int64(TokenLifetime.Seconds())+1, 10) + `}`,
	} {
		token := signRawToken(keys.Token, []byte(body))
		if _, err := VerifyStartToken(keys.Token, token); err == nil {
			t.Fatalf("%s token should fail", name)
		}
	}
}

func TestWebhookSignatureRoundTrip(t *testing.T) {
	keys := testKeys(t)
	body := []byte(`{"protocol":"subscription-bridge","version":1,"event_id":"evt_1"}`)
	header := SignWebhook(keys.Callback, body)
	if err := VerifyWebhookSignature(keys.Callback, body, header); err != nil {
		t.Fatalf("VerifyWebhookSignature: %v", err)
	}
}

func TestVerifyWebhookSignatureRejectsNonCanonicalHeaders(t *testing.T) {
	keys := testKeys(t)
	body := []byte(`{"event_id":"evt_header"}`)
	valid := SignWebhook(keys.Callback, body)
	parts := strings.Split(valid, ",")
	for name, header := range map[string]string{
		"reordered":  parts[1] + "," + parts[0],
		"whitespace": parts[0] + ", " + parts[1],
		"duplicate":  valid + "," + parts[1],
		"uppercase":  parts[0] + ",v1=" + strings.ToUpper(strings.TrimPrefix(parts[1], "v1=")),
		"unknown":    valid + ",v2=00",
	} {
		if err := VerifyWebhookSignature(keys.Callback, body, header); err == nil {
			t.Fatalf("%s header should fail", name)
		}
	}
}

func TestVerifyWebhookSignature_RejectsStaleTimestamp(t *testing.T) {
	keys := testKeys(t)
	body := []byte(`{"event_id":"evt_stale"}`)
	stale := strconv.FormatInt(time.Now().UTC().Add(-10*time.Minute).Unix(), 10)
	mac := hmac.New(sha256.New, keys.Callback[:])
	mac.Write([]byte(stale + "."))
	mac.Write(body)
	header := "t=" + stale + ",v1=" + hex.EncodeToString(mac.Sum(nil))
	if err := VerifyWebhookSignature(keys.Callback, body, header); err == nil {
		t.Fatal("expected replay window rejection")
	}
}

func TestBridgeGETAuthRoundTrip(t *testing.T) {
	keys := testKeys(t)
	path := "/v1/subscriptions/sub_abc"
	auth := SignBridgeGET(keys.Reconcile, "GET", path)
	if err := VerifyBridgeGET(keys.Reconcile, "GET", path, auth); err != nil {
		t.Fatalf("VerifyBridgeGET: %v", err)
	}
}

func TestSignWebhookFormat(t *testing.T) {
	keys := testKeys(t)
	body, _ := json.Marshal(CallbackPayload{EventID: "evt_fmt"})
	header := SignWebhook(keys.Callback, body)
	if !strings.Contains(header, "t=") || !strings.Contains(header, "v1=") {
		t.Fatalf("unexpected header format: %q", header)
	}
}

func signRawToken(key Key, body []byte) string {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + hex.EncodeToString(mac.Sum(nil))
}
