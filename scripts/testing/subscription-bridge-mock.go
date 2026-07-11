//go:build ignore

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arkfile/Arkfile/subbridge"
	"github.com/google/uuid"
)

var (
	bridgeKeys    subbridge.DerivedKeys
	subscriptions sync.Map // subscription_ref -> snapshot
	checkouts     sync.Map // checkout_id -> plan_id
)

type mockSubscription struct {
	Callback map[string]interface{}
	Body     []byte
}

func main() {
	pairingRoot := os.Getenv("SUBSCRIPTION_BRIDGE_PAIRING_ROOT")
	if pairingRoot == "" {
		pairingRoot = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	}
	var err error
	bridgeKeys, err = subbridge.DeriveKeys(pairingRoot)
	if err != nil {
		log.Fatal(err)
	}
	consumerURL := os.Getenv("CONSUMER_WEBHOOK_URL")
	if consumerURL == "" {
		consumerURL = os.Getenv("ARKFILE_WEBHOOK_URL")
	}
	if consumerURL == "" {
		consumerURL = "https://localhost:8443/api/webhooks/subscription-bridge"
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/v1/start", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		payload, err := subbridge.VerifyStartToken(bridgeKeys.Token, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		checkouts.Store(payload.CheckoutID, payload.PlanID)
		redirectURL, err := url.Parse(payload.ReturnURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		query := redirectURL.Query()
		query.Set("checkout_id", payload.CheckoutID)
		query.Set("mock", "1")
		redirectURL.RawQuery = query.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	})

	http.HandleFunc("/v1/portal", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		payload, err := subbridge.VerifyPortalToken(bridgeKeys.Token, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, payload.ReturnURL, http.StatusFound)
	})

	http.HandleFunc("/v1/subscriptions/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
		if ref == "" {
			http.Error(w, "missing subscription_ref", http.StatusBadRequest)
			return
		}
		if err := subbridge.VerifyBridgeGET(bridgeKeys.Reconcile, r.Method, r.URL.Path, r.Header.Get("Authorization")); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if v, ok := subscriptions.Load(ref); ok {
			stored, _ := v.(mockSubscription)
			snapshot := make(map[string]interface{}, len(stored.Callback))
			for key, value := range stored.Callback {
				snapshot[key] = value
			}
			delete(snapshot, "event_id")
			delete(snapshot, "event_type")
			writeJSON(w, snapshot)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	// Test helper: simulate checkout completion and fire webhook to consumer app.
	http.HandleFunc("/v1/mock/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			CheckoutID string `json:"checkout_id"`
			Username   string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		planID, _ := checkouts.Load(req.CheckoutID)
		planStr, _ := planID.(string)
		if planStr == "" {
			planStr = "plan_dev_250gb"
		}
		subRef := "sub_" + strings.ReplaceAll(uuid.New().String(), "-", "")
		now := time.Now().UTC().Truncate(time.Second)
		end := now.Add(30 * 24 * time.Hour)
		snap := map[string]interface{}{
			"protocol":             "subscription-bridge",
			"version":              1,
			"event_id":             "evt_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
			"event_type":           "subscription.activated",
			"checkout_id":          req.CheckoutID,
			"subscription_ref":     subRef,
			"plan_id":              planStr,
			"state_version":        1,
			"status":               "active",
			"current_period_start": now.Format(time.RFC3339),
			"current_period_end":   end.Format(time.RFC3339),
			"cancel_at_period_end": false,
			"state_changed_at":     now.Format(time.RFC3339),
		}
		body, err := json.Marshal(snap)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		subscriptions.Store(subRef, mockSubscription{Callback: snap, Body: body})
		if err := postSubscriptionBridgeWebhook(consumerURL, body); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]interface{}{"subscription_ref": subRef, "status": "delivered"})
	})

	http.HandleFunc("/v1/mock/expire", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SubscriptionRef string `json:"subscription_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		v, ok := subscriptions.Load(req.SubscriptionRef)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		stored, _ := v.(mockSubscription)
		snap := make(map[string]interface{}, len(stored.Callback))
		for key, value := range stored.Callback {
			snap[key] = value
		}
		snap["event_id"] = "evt_" + strings.ReplaceAll(uuid.New().String(), "-", "")
		snap["event_type"] = "subscription.expired"
		snap["status"] = "expired"
		snap["state_version"] = 2
		snap["cancel_at_period_end"] = false
		snap["state_changed_at"] = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
		body, err := json.Marshal(snap)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		subscriptions.Store(req.SubscriptionRef, mockSubscription{Callback: snap, Body: body})
		if err := postSubscriptionBridgeWebhook(consumerURL, body); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"status": "expired"})
	})

	// Test helper: replay the last stored callback for idempotency checks.
	http.HandleFunc("/v1/mock/replay", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SubscriptionRef string `json:"subscription_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		v, ok := subscriptions.Load(req.SubscriptionRef)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		stored, _ := v.(mockSubscription)
		if err := postSubscriptionBridgeWebhook(consumerURL, stored.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]interface{}{
			"success":          true,
			"subscription_ref": req.SubscriptionRef,
			"status":           "delivered",
		})
	})

	log.Println("Starting mock Subscription Bridge on :8081...")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}

func postSubscriptionBridgeWebhook(url string, body []byte) error {
	sig := subbridge.SignWebhook(bridgeKeys.Callback, body)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Subscription-Bridge-Signature", sig)
	req.Header.Set("User-Agent", "subscription-bridge-mock/1.0")

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local e2e mock only
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("consumer webhook %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
