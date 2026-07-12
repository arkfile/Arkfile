package payments

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBTCPayClient_CreateInvoice(t *testing.T) {
	var mockServer *httptest.Server
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert request headers
		if r.Header.Get("Authorization") != "token test_api_key" {
			t.Errorf("expected Authorization: token test_api_key, got: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type: application/json, got: %s", r.Header.Get("Content-Type"))
		}

		var raw map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if len(raw) != 4 {
			t.Errorf("request contains unexpected top-level fields: %#v", raw)
		}
		for _, field := range []string{"amount", "currency", "metadata", "checkout"} {
			if _, ok := raw[field]; !ok {
				t.Errorf("request omitted %s", field)
			}
		}

		var payload struct {
			Amount   string            `json:"amount"`
			Currency string            `json:"currency"`
			Metadata map[string]string `json:"metadata"`
			Checkout struct {
				ExpirationMinutes int    `json:"expirationMinutes"`
				SpeedPolicy       string `json:"speedPolicy"`
				RedirectURL       string `json:"redirectURL"`
			} `json:"checkout"`
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("failed to re-encode request body: %v", err)
		}
		if err := json.Unmarshal(encoded, &payload); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if payload.Amount != "10.00" {
			t.Errorf("expected amount 10.00, got: %s", payload.Amount)
		}
		if payload.Currency != "USD" {
			t.Errorf("expected currency USD, got: %s", payload.Currency)
		}
		if payload.Metadata["invoice_id"] != "inv_test123" {
			t.Errorf("expected metadata invoice_id inv_test123, got: %s", payload.Metadata["invoice_id"])
		}
		if len(payload.Metadata) != 1 {
			t.Errorf("metadata contains unexpected fields: %#v", payload.Metadata)
		}
		if payload.Checkout.ExpirationMinutes != DefaultInvoiceExpirationMinutes {
			t.Errorf("expected expirationMinutes %d, got: %d", DefaultInvoiceExpirationMinutes, payload.Checkout.ExpirationMinutes)
		}
		if payload.Checkout.SpeedPolicy != "LowMediumSpeed" {
			t.Errorf("speedPolicy = %q, want LowMediumSpeed", payload.Checkout.SpeedPolicy)
		}
		if payload.Checkout.RedirectURL != "https://arkfile.example.com/?success=true&invoice=inv_test123" {
			t.Errorf("redirectURL = %q", payload.Checkout.RedirectURL)
		}

		// Send success response
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"id": "btcpay_invoice_abc123",
			"checkoutLink": "` + mockServer.URL + `/checkout/abc123"
		}`))
	}))
	defer mockServer.Close()

	client := NewBTCPayClient(mockServer.URL, "test_store_id", "test_api_key")
	provInv, err := client.CreateInvoice(context.Background(), "inv_test123", 1000000000, "https://arkfile.example.com/?success=true&invoice=inv_test123")
	if err != nil {
		t.Fatalf("unexpected error creating invoice: %v", err)
	}

	if provInv.ProviderInvoiceID != "btcpay_invoice_abc123" {
		t.Errorf("expected provider invoice ID btcpay_invoice_abc123, got: %s", provInv.ProviderInvoiceID)
	}
	if provInv.CheckoutURL != mockServer.URL+"/checkout/abc123" {
		t.Errorf("unexpected checkout URL: %s", provInv.CheckoutURL)
	}
}

func TestBTCPayClient_CreateInvoiceExactCents(t *testing.T) {
	var mockServer *httptest.Server
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Amount string `json:"amount"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Amount != "1.23" {
			t.Errorf("amount = %q, want 1.23", payload.Amount)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"provider-123","checkoutLink":"` + mockServer.URL + `/checkout/provider-123"}`))
	}))
	defer mockServer.Close()

	client := NewBTCPayClient(mockServer.URL, "store", "key")
	if _, err := client.CreateInvoice(context.Background(), "inv_123", 123_000_000, "https://arkfile.example/?success=true"); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	if _, err := client.CreateInvoice(context.Background(), "inv_bad", 123_450_000, "https://arkfile.example/"); err == nil {
		t.Fatal("sub-cent top-up should be rejected before provider request")
	}
}

func TestValidateCheckoutURLRejectsDifferentOrigin(t *testing.T) {
	if err := validateCheckoutURL("https://pay.example.com", "http://127.0.0.1:8080/checkout/invoice"); err == nil {
		t.Fatal("AlmaPay loopback checkout origin should be rejected")
	}
}

func TestBTCPayClient_GetInvoiceStatus(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "token test_api_key" {
			t.Errorf("expected Authorization header")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "Settled"})
	}))
	defer mockServer.Close()

	client := NewBTCPayClient(mockServer.URL, "test_store_id", "test_api_key")
	status, err := client.GetInvoiceStatus(context.Background(), "btcpay_invoice_abc123")
	if err != nil {
		t.Fatalf("GetInvoiceStatus: %v", err)
	}
	if status != "Settled" {
		t.Errorf("status = %q, want Settled", status)
	}
}

func TestBTCPayClient_GetInvoiceStatusRejectsAPIKeyFailure(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer mockServer.Close()
	client := NewBTCPayClient(mockServer.URL, "store", "wrong-key")
	if _, err := client.GetInvoiceStatus(context.Background(), "provider-id"); err == nil {
		t.Fatal("API-key failure should return an error")
	}
}

func TestBTCPayClient_CreateInvoice_BadStatus(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mockServer.Close()

	client := NewBTCPayClient(mockServer.URL, "test_store_id", "test_api_key")
	_, err := client.CreateInvoice(context.Background(), "inv_bad", 100_000_000, "https://redirect.example.com")
	if err == nil {
		t.Fatal("expected error for non-201 response")
	}
	if !strings.Contains(err.Error(), "bad status") {
		t.Errorf("error = %q, want bad status mention", err)
	}
}
