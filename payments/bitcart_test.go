package payments

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/models"
)

const (
	testBitcartToken   = "test-token"
	testBitcartStoreID = "store_1"
	testNotifyURL      = "https://arkfile.test/api/webhooks/bitcart"
)

type fakeBitcart struct {
	mu       sync.Mutex
	invoices map[string]map[string]interface{}
	lastBody map[string]interface{}
	authErrs int
}

func newFakeBitcart(t *testing.T) (*fakeBitcart, *httptest.Server) {
	t.Helper()
	fb := &fakeBitcart{invoices: map[string]map[string]interface{}{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.mu.Lock()
		defer fb.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testBitcartToken {
			fb.authErrs++
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/invoices":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			fb.lastBody = body
			inv := map[string]interface{}{
				"id":       "bc_inv_1",
				"status":   "pending",
				"order_id": body["order_id"],
				"store_id": body["store_id"],
				"price":    body["price"],
				"currency": body["currency"],
			}
			fb.invoices["bc_inv_1"] = inv
			_ = json.NewEncoder(w).Encode(inv)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/invoices/"):
			inv, ok := fb.invoices[strings.TrimPrefix(r.URL.Path, "/api/invoices/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(inv)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return fb, srv
}

func (fb *fakeBitcart) set(id, field string, value interface{}) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.invoices[id][field] = value
}

func newTestBitcartProvider(t *testing.T, srv *httptest.Server) *BitcartProvider {
	t.Helper()
	p, err := NewBitcartProvider(config.PaymentsConfig{
		BitcartAPIURL:      srv.URL + "/api/",
		BitcartCheckoutURL: "https://pay.example.com/",
		BitcartAPIToken:    testBitcartToken,
		BitcartStoreID:     testBitcartStoreID,
	}, testNotifyURL)
	if err != nil {
		t.Fatalf("NewBitcartProvider: %v", err)
	}
	return p
}

func localInvoice(providerID string) *models.PaymentInvoice {
	return &models.PaymentInvoice{
		InvoiceID:           "inv_abc",
		Username:            "alice",
		AmountUSDMicrocents: 1_250_000_000,
		Status:              models.PaymentStatusPending,
		Provider:            bitcartProviderName,
		ProviderInvoiceID:   providerID,
	}
}

func TestBitcartCreateInvoice_SendsOnlyOrderAndPrice(t *testing.T) {
	fb, srv := newFakeBitcart(t)
	p := newTestBitcartProvider(t, srv)

	inv, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000)
	if err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	if inv.ProviderInvoiceID != "bc_inv_1" {
		t.Errorf("provider id = %q", inv.ProviderInvoiceID)
	}
	if inv.CheckoutURL != "https://pay.example.com/i/bc_inv_1" {
		t.Errorf("checkout url = %q", inv.CheckoutURL)
	}
	want := map[string]interface{}{
		"price":            "12.50",
		"currency":         "USD",
		"store_id":         testBitcartStoreID,
		"order_id":         "inv_abc",
		"notification_url": testNotifyURL,
	}
	if len(fb.lastBody) != len(want) {
		t.Fatalf("request body fields = %v, want exactly %v", fb.lastBody, want)
	}
	for k, v := range want {
		if fb.lastBody[k] != v {
			t.Errorf("body[%s] = %v, want %v", k, fb.lastBody[k], v)
		}
	}
}

func TestBitcartGetInvoiceStatus_MapsStatuses(t *testing.T) {
	fb, srv := newFakeBitcart(t)
	p := newTestBitcartProvider(t, srv)
	if _, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"pending":     models.PaymentStatusPending,
		"paid":        models.PaymentStatusConfirming,
		"unconfirmed": models.PaymentStatusConfirming,
		"confirmed":   models.PaymentStatusConfirming,
		"complete":    models.PaymentStatusPaid,
		"expired":     models.PaymentStatusExpired,
		"invalid":     models.PaymentStatusFailed,
		"refunded":    models.PaymentStatusFailed,
	}
	for remote, want := range cases {
		fb.set("bc_inv_1", "status", remote)
		got, err := p.GetInvoiceStatus(context.Background(), localInvoice("bc_inv_1"))
		if err != nil {
			t.Fatalf("status %s: %v", remote, err)
		}
		if got != want {
			t.Errorf("bitcart %s mapped to %s, want %s", remote, got, want)
		}
	}
	fb.set("bc_inv_1", "status", "something-new")
	if _, err := p.GetInvoiceStatus(context.Background(), localInvoice("bc_inv_1")); err == nil {
		t.Error("expected error for an unknown Bitcart status")
	}
}

func TestBitcartGetInvoiceStatus_RejectsMismatchedInvoice(t *testing.T) {
	cases := []struct {
		field string
		value interface{}
	}{
		{"order_id", "inv_other"},
		{"store_id", "store_other"},
		{"store_id", nil},
		{"price", "1.00"},
		{"currency", "EUR"},
	}
	for _, tc := range cases {
		fb, srv := newFakeBitcart(t)
		p := newTestBitcartProvider(t, srv)
		if _, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000); err != nil {
			t.Fatal(err)
		}
		fb.set("bc_inv_1", "status", "complete")
		fb.set("bc_inv_1", tc.field, tc.value)
		_, err := p.GetInvoiceStatus(context.Background(), localInvoice("bc_inv_1"))
		if !errors.Is(err, ErrBitcartInvoiceMismatch) {
			t.Errorf("%s=%v: err = %v, want ErrBitcartInvoiceMismatch", tc.field, tc.value, err)
		}
	}
}

func TestBitcartGetInvoiceStatus_AcceptsNumericAndPaddedPrice(t *testing.T) {
	fb, srv := newFakeBitcart(t)
	p := newTestBitcartProvider(t, srv)
	if _, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000); err != nil {
		t.Fatal(err)
	}
	for _, price := range []interface{}{12.5, "12.500000"} {
		fb.set("bc_inv_1", "price", price)
		if _, err := p.GetInvoiceStatus(context.Background(), localInvoice("bc_inv_1")); err != nil {
			t.Errorf("price %v: %v", price, err)
		}
	}
}

func TestBitcartRequestsFailWithoutValidToken(t *testing.T) {
	fb, srv := newFakeBitcart(t)
	p := newTestBitcartProvider(t, srv)
	p.token = "wrong"
	if _, err := p.CreateInvoice(context.Background(), "inv_abc", 100_000_000); err == nil {
		t.Fatal("expected error with a rejected API token")
	}
	if fb.authErrs != 1 {
		t.Errorf("auth errors = %d, want 1", fb.authErrs)
	}
}

func TestFormatUSDPrice(t *testing.T) {
	cases := map[int64]string{
		50_000_000:     "0.50",
		100_000_000:    "1.00",
		1_234_000_000:  "12.34",
		99_999_000_000: "999.99",
	}
	for micro, want := range cases {
		got, err := formatUSDPrice(micro)
		if err != nil || got != want {
			t.Errorf("formatUSDPrice(%d) = %q, %v; want %q", micro, got, err, want)
		}
	}
	for _, bad := range []int64{0, -100_000_000, 1} {
		if _, err := formatUSDPrice(bad); err == nil {
			t.Errorf("formatUSDPrice(%d): expected error", bad)
		}
	}
}
