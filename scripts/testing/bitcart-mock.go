//go:build ignore

// Mock of the Bitcart Merchants API subset used by Arkfile, for e2e tests only.
// Listens on 127.0.0.1:8082. Real endpoints: POST /api/invoices (bearer token),
// GET /api/invoices/{id}, GET /i/{id}. Test controls live under /mock/.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type invoice struct {
	ID              string  `json:"id"`
	Status          string  `json:"status"`
	ExceptionStatus string  `json:"exception_status"`
	OrderID         string  `json:"order_id"`
	StoreID         *string `json:"store_id"`
	Price           string  `json:"price"`
	Currency        string  `json:"currency"`
	NotificationURL string  `json:"notification_url"`
	RedirectURL     string  `json:"redirect_url"`
	CreatedAt       string  `json:"created"`
}

var (
	mu       sync.Mutex
	invoices = map[string]*invoice{}
	lastID   string
	token    = envOr("BITCART_MOCK_TOKEN", "dev-bitcart-token")
	notifier = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "mock" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func snapshot(inv *invoice) invoice {
	c := *inv
	return c
}

// notify posts the unsigned {"id","status"} body Bitcart sends to notification_url.
func notify(inv invoice, status string) int {
	if inv.NotificationURL == "" {
		return 0
	}
	body, _ := json.Marshal(map[string]string{"id": inv.ID, "status": status})
	resp, err := notifier.Post(inv.NotificationURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("notify %s failed: %v", inv.ID, err)
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

type controlRequest struct {
	ID       string `json:"id"`
	OrderID  string `json:"order_id"`
	Status   string `json:"status"`
	Price    string `json:"price"`
	StoreID  string `json:"store_id"`
	Currency string `json:"currency"`
	Notify   *bool  `json:"notify"`
}

func lookup(req controlRequest) *invoice {
	if req.ID != "" {
		return invoices[req.ID]
	}
	if req.OrderID != "" {
		for _, inv := range invoices {
			if inv.OrderID == req.OrderID {
				return inv
			}
		}
	}
	return nil
}

func control(handler func(inv *invoice, req controlRequest) (bool, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req controlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		inv := lookup(req)
		if inv == nil {
			mu.Unlock()
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		send, status := handler(inv, req)
		snap := snapshot(inv)
		mu.Unlock()
		code := 0
		if send && (req.Notify == nil || *req.Notify) {
			code = notify(snap, status)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"invoice": snap, "notify_http": code})
	}
}

func main() {
	addr := envOr("BITCART_MOCK_ADDR", "127.0.0.1:8082")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/api/invoices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Unauthorized"})
			return
		}
		var body struct {
			Price           json.RawMessage `json:"price"`
			Currency        string          `json:"currency"`
			StoreID         string          `json:"store_id"`
			OrderID         string          `json:"order_id"`
			NotificationURL string          `json:"notification_url"`
			RedirectURL     string          `json:"redirect_url"`
			BuyerEmail      string          `json:"buyer_email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusUnprocessableEntity)
			return
		}
		if body.BuyerEmail != "" {
			log.Printf("unexpected buyer_email sent to Bitcart mock")
			http.Error(w, "buyer_email must not be sent", http.StatusUnprocessableEntity)
			return
		}
		price := strings.Trim(string(body.Price), `"`)
		store := body.StoreID
		inv := &invoice{
			ID: newID(), Status: "pending", ExceptionStatus: "none",
			OrderID: body.OrderID, StoreID: &store, Price: price, Currency: body.Currency,
			NotificationURL: body.NotificationURL, RedirectURL: body.RedirectURL,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		mu.Lock()
		invoices[inv.ID] = inv
		lastID = inv.ID
		snap := snapshot(inv)
		mu.Unlock()
		writeJSON(w, http.StatusOK, snap)
	})

	http.HandleFunc("/api/invoices/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/invoices/")
		mu.Lock()
		inv, ok := invoices[id]
		var snap invoice
		if ok {
			snap = snapshot(inv)
		}
		mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Object not found"})
			return
		}
		writeJSON(w, http.StatusOK, snap)
	})

	http.HandleFunc("/i/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/i/")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Mock Bitcart checkout</title><h1>Mock Bitcart checkout</h1><p id=\"invoice\">" + html.EscapeString(id) + "</p>"))
	})

	http.HandleFunc("/mock/last-invoice", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inv, ok := invoices[lastID]
		var snap invoice
		if ok {
			snap = snapshot(inv)
		}
		mu.Unlock()
		if !ok {
			http.Error(w, "no invoices", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, snap)
	})

	// Changes the invoice status and sends the notification Bitcart would send.
	http.HandleFunc("/mock/set-status", control(func(inv *invoice, req controlRequest) (bool, string) {
		inv.Status = req.Status
		return true, req.Status
	}))

	// Changes invoice fields Arkfile verifies, without notifying.
	http.HandleFunc("/mock/tamper", control(func(inv *invoice, req controlRequest) (bool, string) {
		if req.Price != "" {
			inv.Price = req.Price
		}
		if req.StoreID != "" {
			s := req.StoreID
			inv.StoreID = &s
		}
		if req.Currency != "" {
			inv.Currency = req.Currency
		}
		if req.OrderID != "" && req.ID != "" {
			inv.OrderID = req.OrderID
		}
		return false, ""
	}))

	// Sends a notification claiming req.Status without changing the stored status.
	http.HandleFunc("/mock/send-notification", control(func(inv *invoice, req controlRequest) (bool, string) {
		return true, req.Status
	}))

	// Closes every open invoice so the Arkfile reconciler has nothing left to poll:
	// pending becomes expired, payment-seen states become invalid.
	http.HandleFunc("/mock/close-all", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		var changed []invoice
		for _, inv := range invoices {
			switch inv.Status {
			case "pending":
				inv.Status = "expired"
			case "paid", "unconfirmed", "confirmed":
				inv.Status = "invalid"
			default:
				continue
			}
			changed = append(changed, snapshot(inv))
		}
		mu.Unlock()
		for _, inv := range changed {
			notify(inv, inv.Status)
		}
		writeJSON(w, http.StatusOK, map[string]int{"closed": len(changed)})
	})

	log.Printf("Bitcart mock listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
