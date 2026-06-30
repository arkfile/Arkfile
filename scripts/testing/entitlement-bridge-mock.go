//go:build ignore

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	webhookSecret string
	entitlements  sync.Map // entitlement_ref -> snapshot
	checkouts     sync.Map // checkout_id -> plan_id
)

func main() {
	webhookSecret = os.Getenv("ENTITLEMENT_BRIDGE_WEBHOOK_SECRET")
	if webhookSecret == "" {
		webhookSecret = "test_entitlement_bridge_secret"
	}
	arkfileURL := os.Getenv("ARKFILE_WEBHOOK_URL")
	if arkfileURL == "" {
		arkfileURL = "https://localhost:8443/api/webhooks/entitlements"
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/v1/start", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		payload, err := verifyToken(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		checkoutID, _ := payload["checkout_id"].(string)
		planID, _ := payload["plan_id"].(string)
		returnURL, _ := payload["return_url"].(string)
		if checkoutID == "" || planID == "" {
			http.Error(w, "missing checkout_id or plan_id", http.StatusBadRequest)
			return
		}
		checkouts.Store(checkoutID, planID)
		redirect := fmt.Sprintf("%s&checkout_id=%s&mock=1", strings.TrimRight(returnURL, "&"), checkoutID)
		http.Redirect(w, r, redirect, http.StatusFound)
	})

	http.HandleFunc("/v1/portal", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		payload, err := verifyToken(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		returnURL, _ := payload["return_url"].(string)
		if returnURL == "" {
			returnURL = "/"
		}
		http.Redirect(w, r, returnURL, http.StatusFound)
	})

	http.HandleFunc("/v1/entitlements/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v1/entitlements/")
		if ref == "" {
			http.Error(w, "missing entitlement_ref", http.StatusBadRequest)
			return
		}
		if v, ok := entitlements.Load(ref); ok {
			writeJSON(w, v)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	// Test helper: simulate checkout completion and fire webhook to Arkfile.
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
		entRef := "ent_" + strings.ReplaceAll(uuid.New().String(), "-", "")
		now := time.Now().UTC()
		end := now.Add(30 * 24 * time.Hour)
		snap := map[string]interface{}{
			"protocol":             "entitlement-bridge",
			"version":              1,
			"event_id":             "evt_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
			"event_type":           "entitlement.activated",
			"checkout_id":          req.CheckoutID,
			"entitlement_ref":      entRef,
			"plan_id":              planStr,
			"status":               "active",
			"current_period_start": now.Format(time.RFC3339),
			"current_period_end":   end.Format(time.RFC3339),
			"cancel_at_period_end": false,
			"processor_family":     "mock",
			"occurred_at":          now.Format(time.RFC3339),
		}
		entitlements.Store(entRef, snap)
		if err := postEntitlementWebhook(arkfileURL, snap); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]interface{}{"entitlement_ref": entRef, "status": "delivered"})
	})

	http.HandleFunc("/v1/mock/expire", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EntitlementRef string `json:"entitlement_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		v, ok := entitlements.Load(req.EntitlementRef)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		snap, _ := v.(map[string]interface{})
		snap["event_id"] = "evt_" + strings.ReplaceAll(uuid.New().String(), "-", "")
		snap["event_type"] = "entitlement.expired"
		snap["status"] = "expired"
		entitlements.Store(req.EntitlementRef, snap)
		if err := postEntitlementWebhook(arkfileURL, snap); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"status": "expired"})
	})

	log.Println("Starting mock Entitlement Bridge on :8081...")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}

func verifyToken(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token")
	}
	body, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, fmt.Errorf("bad signature")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func postEntitlementWebhook(url string, payload map[string]interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	sig := "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Entitlement-Bridge-Signature", sig)
	req.Header.Set("User-Agent", "entitlement-bridge-mock/1.0")

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
		return fmt.Errorf("arkfile webhook %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
