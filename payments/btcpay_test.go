package payments

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBTCPayClient_CreateInvoice(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert request headers
		if r.Header.Get("Authorization") != "token test_api_key" {
			t.Errorf("expected Authorization: token test_api_key, got: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type: application/json, got: %s", r.Header.Get("Content-Type"))
		}

		// Decode body
		var payload struct {
			Amount   string            `json:"amount"`
			Currency string            `json:"currency"`
			Metadata map[string]string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
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

		// Send success response
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"id": "btcpay_invoice_abc123",
			"checkoutLink": "https://btcpayserver.example.com/checkout/abc123"
		}`))
	}))
	defer mockServer.Close()

	client := NewBTCPayClient(mockServer.URL, "test_store_id", "test_api_key")
	provInv, err := client.CreateInvoice(context.Background(), "inv_test123", 1000000000, "https://redirect.example.com")
	if err != nil {
		t.Fatalf("unexpected error creating invoice: %v", err)
	}

	if provInv.ProviderInvoiceID != "btcpay_invoice_abc123" {
		t.Errorf("expected provider invoice ID btcpay_invoice_abc123, got: %s", provInv.ProviderInvoiceID)
	}
	if provInv.CheckoutURL != "https://btcpayserver.example.com/checkout/abc123" {
		t.Errorf("expected checkout URL https://btcpayserver.example.com/checkout/abc123, got: %s", provInv.CheckoutURL)
	}
}
