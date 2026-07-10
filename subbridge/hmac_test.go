package subbridge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSecret = "test_subscription_bridge_secret"

func TestDeriveKeys_GoldenVector(t *testing.T) {
	keys, err := DeriveKeys("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{
		hex.EncodeToString([]byte(keys.Token)),
		hex.EncodeToString([]byte(keys.Callback)),
		hex.EncodeToString([]byte(keys.Reconcile)),
	}
	want := []string{
		"d4c6d2a424e79004575dfb6eab85d0563a16d21ff3b8b24a67f7b61768cf0684",
		"82764734bee59c2e91e6c1e2a2adca2ba734282e9bf86f650108aec28c6f286f",
		"36bda83be5fd1fd170ae5bac3f6e79a12a299bb930653b8cf28e5d9122b28dbf",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("derived key %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestSignAndVerifyStartToken(t *testing.T) {
	exp := time.Now().UTC().Add(5 * time.Minute).Unix()
	want := StartTokenPayload{
		CheckoutID: "subchk_test",
		PlanID:     "plan_dev_250gb",
		ReturnURL:  "https://example.com/?subscription=return",
		Exp:        exp,
	}
	token, err := SignToken(testSecret, want)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	var got StartTokenPayload
	if err := VerifyToken(testSecret, token, &got); err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.CheckoutID != want.CheckoutID || got.PlanID != want.PlanID {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestVerifyToken_RejectsBadSignature(t *testing.T) {
	exp := time.Now().UTC().Add(5 * time.Minute).Unix()
	token, err := SignToken(testSecret, StartTokenPayload{CheckoutID: "x", PlanID: "y", Exp: exp})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	parts[1] = strings.Repeat("0", len(parts[1]))
	if err := VerifyToken(testSecret, parts[0]+"."+parts[1], &StartTokenPayload{}); err == nil {
		t.Fatal("expected bad signature error")
	}
}

func TestVerifyToken_RejectsExpired(t *testing.T) {
	exp := time.Now().UTC().Add(-time.Hour).Unix()
	token, err := SignToken(testSecret, PortalTokenPayload{SubscriptionRef: "sub_x", Exp: exp})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyToken(testSecret, token, &PortalTokenPayload{}); err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestWebhookSignatureRoundTrip(t *testing.T) {
	body := []byte(`{"protocol":"subscription-bridge","version":1,"event_id":"evt_1"}`)
	header := SignWebhook(testSecret, body)
	if err := VerifyWebhookSignature(testSecret, body, header); err != nil {
		t.Fatalf("VerifyWebhookSignature: %v", err)
	}
}

func TestVerifyWebhookSignature_RejectsStaleTimestamp(t *testing.T) {
	body := []byte(`{"event_id":"evt_stale"}`)
	stale := strconv.FormatInt(time.Now().UTC().Add(-10*time.Minute).Unix(), 10)
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(stale + "."))
	mac.Write(body)
	header := "t=" + stale + ",v1=" + hex.EncodeToString(mac.Sum(nil))
	if err := VerifyWebhookSignature(testSecret, body, header); err == nil {
		t.Fatal("expected replay window rejection")
	}
}

func TestBridgeGETAuthRoundTrip(t *testing.T) {
	path := "/v1/subscriptions/sub_abc"
	auth := SignBridgeGET(testSecret, "GET", path)
	if err := VerifyBridgeGET(testSecret, "GET", path, auth); err != nil {
		t.Fatalf("VerifyBridgeGET: %v", err)
	}
}

func TestSignWebhookFormat(t *testing.T) {
	body, _ := json.Marshal(CallbackPayload{EventID: "evt_fmt"})
	header := SignWebhook(testSecret, body)
	if !strings.Contains(header, "t=") || !strings.Contains(header, "v1=") {
		t.Fatalf("unexpected header format: %q", header)
	}
}
