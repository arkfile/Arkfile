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

// fakeBitcart models a store with anonymous invoice creation off: creating
// invoices and counting them need the token, reading an invoice or the store
// does not.
type fakeBitcart struct {
	mu             sync.Mutex
	invoices       map[string]map[string]interface{}
	lastBody       map[string]interface{}
	authErrs       int
	createConfs    int
	createPayments []interface{}
	store          map[string]interface{}
}

func recommendedCheckoutSettings() map[string]interface{} {
	return map[string]interface{}{
		"expiration":                       15,
		"transaction_speed":                1,
		"underpaid_percentage":             0,
		"email_required":                   false,
		"allow_anonymous_invoice_creation": false,
	}
}

func newFakeBitcart(t *testing.T) (*fakeBitcart, *httptest.Server) {
	t.Helper()
	fb := &fakeBitcart{
		invoices:    map[string]map[string]interface{}{},
		createConfs: 1,
		store: map[string]interface{}{
			"id":                testBitcartStoreID,
			"name":              "Test store",
			"checkout_settings": recommendedCheckoutSettings(),
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.mu.Lock()
		defer fb.mu.Unlock()
		authorized := r.Header.Get("Authorization") == "Bearer "+testBitcartToken
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/invoices":
			if !authorized {
				fb.authErrs++
				http.Error(w, "anonymous invoice creation is disabled", http.StatusForbidden)
				return
			}
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			fb.lastBody = body
			payments := fb.createPayments
			if payments == nil {
				payments = []interface{}{
					map[string]interface{}{"id": "pm1", "currency": "btc", "lightning": false, "required_confirmations": fb.createConfs},
					map[string]interface{}{"id": "pm2", "currency": "btc", "lightning": true, "required_confirmations": 0},
				}
			}
			inv := map[string]interface{}{
				"id":         "bc_inv_1",
				"status":     "pending",
				"order_id":   body["order_id"],
				"store_id":   body["store_id"],
				"price":      body["price"],
				"currency":   body["currency"],
				"payments":   payments,
				"payment_id": "pm1",
			}
			fb.invoices["bc_inv_1"] = inv
			_ = json.NewEncoder(w).Encode(inv)
		case r.Method == http.MethodGet && r.URL.Path == "/api/invoices/count":
			if !authorized {
				fb.authErrs++
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(len(fb.invoices))
		case r.Method == http.MethodGet && r.URL.Path == "/api/stores/"+testBitcartStoreID:
			_ = json.NewEncoder(w).Encode(fb.store)
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

func TestBitcartCreateInvoiceFailsWithoutValidToken(t *testing.T) {
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

func TestBitcartCreateInvoice_RefusesZeroConfirmationStore(t *testing.T) {
	fb, srv := newFakeBitcart(t)
	fb.createConfs = 0
	p := newTestBitcartProvider(t, srv)
	_, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000)
	if !errors.Is(err, ErrBitcartUnconfirmedPayments) {
		t.Fatalf("err = %v, want ErrBitcartUnconfirmedPayments", err)
	}
}

func TestBitcartCreateInvoice_RequiresFiveConfirmationsForXMR(t *testing.T) {
	for _, xmrConfs := range []int{0, 1, 4} {
		fb, srv := newFakeBitcart(t)
		fb.createPayments = []interface{}{
			map[string]interface{}{"id": "pm_btc", "currency": "btc", "lightning": false, "required_confirmations": 1},
			map[string]interface{}{"id": "pm_xmr", "currency": "xmr", "lightning": false, "required_confirmations": xmrConfs},
		}
		p := newTestBitcartProvider(t, srv)
		_, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000)
		if !errors.Is(err, ErrBitcartUnconfirmedPayments) {
			t.Fatalf("xmr required_confirmations=%d: err = %v, want ErrBitcartUnconfirmedPayments", xmrConfs, err)
		}
	}

	for _, xmrConfs := range []int{5, 10} {
		fb, srv := newFakeBitcart(t)
		fb.createPayments = []interface{}{
			map[string]interface{}{"id": "pm_btc", "currency": "btc", "lightning": false, "required_confirmations": 1},
			map[string]interface{}{"id": "pm_xmr", "currency": "XMR", "lightning": false, "required_confirmations": xmrConfs},
		}
		p := newTestBitcartProvider(t, srv)
		if _, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000); err != nil {
			t.Fatalf("xmr required_confirmations=%d: unexpected error %v", xmrConfs, err)
		}
	}

	// Pre-existing invoices created before the 5-confirmation XMR floor must
	// still settle cleanly on reconciliation as long as they required >= 1 confirmation.
	fb, srv := newFakeBitcart(t)
	fb.createPayments = []interface{}{
		map[string]interface{}{"id": "pm_xmr", "currency": "xmr", "lightning": false, "required_confirmations": 5},
	}
	p := newTestBitcartProvider(t, srv)
	if _, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000); err != nil {
		t.Fatal(err)
	}
	fb.set("bc_inv_1", "status", "complete")
	fb.set("bc_inv_1", "payment_id", "pm_xmr")
	fb.set("bc_inv_1", "payments", []interface{}{
		map[string]interface{}{"id": "pm_xmr", "currency": "xmr", "lightning": false, "required_confirmations": 1},
	})
	got, err := p.GetInvoiceStatus(context.Background(), localInvoice("bc_inv_1"))
	if err != nil || got != models.PaymentStatusPaid {
		t.Fatalf("legacy 1-conf xmr invoice: got %q, %v; want paid", got, err)
	}
}

func TestBitcartGetInvoiceStatus_RequiresConfirmedCompletion(t *testing.T) {
	unconfirmed := []interface{}{
		map[string]interface{}{"id": "pm1", "lightning": false, "required_confirmations": 0},
		map[string]interface{}{"id": "pm2", "lightning": true, "required_confirmations": 0},
	}
	cases := []struct {
		name      string
		paymentID interface{}
		payments  interface{}
		wantErr   bool
	}{
		{"on-chain with confirmations", "pm1", nil, false},
		{"lightning", "pm2", nil, false},
		{"on-chain without confirmations", "pm1", unconfirmed, true},
		{"no paid method reported", nil, nil, true},
		{"paid method missing", "pm9", nil, true},
	}
	for _, tc := range cases {
		fb, srv := newFakeBitcart(t)
		p := newTestBitcartProvider(t, srv)
		if _, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000); err != nil {
			t.Fatal(err)
		}
		fb.set("bc_inv_1", "status", "complete")
		fb.set("bc_inv_1", "payment_id", tc.paymentID)
		if tc.payments != nil {
			fb.set("bc_inv_1", "payments", tc.payments)
		}
		got, err := p.GetInvoiceStatus(context.Background(), localInvoice("bc_inv_1"))
		if tc.wantErr {
			if !errors.Is(err, ErrBitcartUnconfirmedPayments) {
				t.Errorf("%s: err = %v, want ErrBitcartUnconfirmedPayments", tc.name, err)
			}
			continue
		}
		if err != nil || got != models.PaymentStatusPaid {
			t.Errorf("%s: got %q, %v; want paid", tc.name, got, err)
		}
	}

	fb, srv := newFakeBitcart(t)
	p := newTestBitcartProvider(t, srv)
	if _, err := p.CreateInvoice(context.Background(), "inv_abc", 1_250_000_000); err != nil {
		t.Fatal(err)
	}
	fb.set("bc_inv_1", "payment_id", nil)
	fb.set("bc_inv_1", "status", "expired")
	if got, err := p.GetInvoiceStatus(context.Background(), localInvoice("bc_inv_1")); err != nil || got != models.PaymentStatusExpired {
		t.Errorf("expired without a paid method: got %q, %v", got, err)
	}
}

func checkStatuses(checks []ProviderCheck) map[string]string {
	out := map[string]string{}
	for _, c := range checks {
		out[c.Name] = c.Status
	}
	return out
}

func TestBitcartCheckConfiguration_RecommendedStorePasses(t *testing.T) {
	_, srv := newFakeBitcart(t)
	p := newTestBitcartProvider(t, srv)
	got := checkStatuses(p.CheckConfiguration(context.Background()))
	for _, name := range []string{"api_token", "store", "transaction_speed", "underpaid_percentage", "email_required", "anonymous_invoice_creation", "expiration"} {
		if got[name] != ProviderCheckOK {
			t.Errorf("%s = %q, want ok (all: %v)", name, got[name], got)
		}
	}
}

func TestBitcartCheckConfiguration_FlagsRiskySettings(t *testing.T) {
	fb, srv := newFakeBitcart(t)
	fb.store["checkout_settings"] = map[string]interface{}{
		"transaction_speed":                0,
		"underpaid_percentage":             5,
		"email_required":                   true,
		"allow_anonymous_invoice_creation": true,
	}
	p := newTestBitcartProvider(t, srv)
	p.token = "wrong"
	got := checkStatuses(p.CheckConfiguration(context.Background()))
	want := map[string]string{
		"api_token":                  ProviderCheckFail,
		"store":                      ProviderCheckOK,
		"transaction_speed":          ProviderCheckFail,
		"underpaid_percentage":       ProviderCheckFail,
		"email_required":             ProviderCheckWarn,
		"anonymous_invoice_creation": ProviderCheckWarn,
	}
	for name, status := range want {
		if got[name] != status {
			t.Errorf("%s = %q, want %q", name, got[name], status)
		}
	}
	if _, ok := got["expiration"]; ok {
		t.Error("expiration should be omitted when Bitcart does not report it")
	}
}

func TestBitcartCheckConfiguration_UnknownStoreFails(t *testing.T) {
	_, srv := newFakeBitcart(t)
	p := newTestBitcartProvider(t, srv)
	p.storeID = "store_missing"
	got := checkStatuses(p.CheckConfiguration(context.Background()))
	if got["store"] != ProviderCheckFail {
		t.Errorf("store = %q, want fail", got["store"])
	}
	if _, ok := got["transaction_speed"]; ok {
		t.Error("settings checks should stop when the store cannot be read")
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
