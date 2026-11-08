package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/models"
)

const (
	bitcartTestToken = "handler-test-token"
	bitcartTestStore = "store_handlers"
)

// handlerFakeBitcart serves the subset of the Bitcart Merchants API that Arkfile uses.
type handlerFakeBitcart struct {
	mu       sync.Mutex
	invoices map[string]map[string]interface{}
	gets     int
	nextID   int
}

func (f *handlerFakeBitcart) set(id, field string, value interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invoices[id][field] = value
}

func (f *handlerFakeBitcart) add(id, orderID, price string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invoices[id] = map[string]interface{}{
		"id": id, "status": "pending", "order_id": orderID,
		"store_id": bitcartTestStore, "price": price, "currency": "USD",
	}
}

func withBitcartTestEnv(t *testing.T) (*sql.DB, *handlerFakeBitcart, func()) {
	t.Helper()
	db, cleanup := withPaymentsTestEnv(t)

	fake := &handlerFakeBitcart{invoices: map[string]map[string]interface{}{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+bitcartTestToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/invoices":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			fake.nextID++
			id := "bc_" + string(rune('a'+fake.nextID))
			inv := map[string]interface{}{
				"id": id, "status": "pending", "order_id": body["order_id"],
				"store_id": body["store_id"], "price": body["price"], "currency": body["currency"],
			}
			fake.invoices[id] = inv
			_ = json.NewEncoder(w).Encode(inv)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/invoices/"):
			fake.gets++
			inv, ok := fake.invoices[strings.TrimPrefix(r.URL.Path, "/api/invoices/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(inv)
		default:
			http.NotFound(w, r)
		}
	}))

	config.ResetConfigForTest()
	t.Setenv("ARKFILE_PAYMENTS_ENABLED", "true")
	t.Setenv("ARKFILE_BITCART_API_URL", srv.URL+"/api")
	t.Setenv("ARKFILE_BITCART_CHECKOUT_URL", "https://pay.arkfile.test")
	t.Setenv("ARKFILE_BITCART_API_TOKEN", bitcartTestToken)
	t.Setenv("ARKFILE_BITCART_STORE_ID", bitcartTestStore)
	if _, err := config.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig with Bitcart: %v", err)
	}
	resetPaymentThrottles()

	return db, fake, func() {
		srv.Close()
		resetPaymentThrottles()
		cleanup()
	}
}

func resetPaymentThrottles() {
	paymentRefreshThrottle = &invoiceThrottle{interval: 10 * time.Second, last: map[string]time.Time{}}
	paymentNotificationThrottle = &invoiceThrottle{interval: 2 * time.Second, last: map[string]time.Time{}}
}

func seedBitcartInvoice(t *testing.T, db *sql.DB, fake *handlerFakeBitcart, invoiceID, providerID string, amount int64, price string) {
	t.Helper()
	require.NoError(t, models.CreatePaymentInvoice(db, &models.PaymentInvoice{
		InvoiceID: invoiceID, Username: paymentsTestUser, AmountUSDMicrocents: amount,
		Status: models.PaymentStatusPending, Provider: "bitcart", ProviderInvoiceID: providerID,
	}))
	fake.add(providerID, invoiceID, price)
}

func postBitcartNotification(t *testing.T, providerID string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"id": providerID, "status": "complete"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/webhooks/bitcart", bytes.NewReader(body), "")
	return rec, BitcartWebhookHandler(c)
}

func localStatus(t *testing.T, db *sql.DB, invoiceID string) string {
	t.Helper()
	inv, err := models.GetPaymentInvoice(db, invoiceID)
	require.NoError(t, err)
	return inv.Status
}

func paymentCredits(t *testing.T, db *sql.DB, providerID string) (int, int64) {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(1) FROM credit_transactions WHERE transaction_id = ?`, providerID).Scan(&count))
	var balance int64
	_ = db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, paymentsTestUser).Scan(&balance)
	return count, balance
}

func TestBitcartWebhook_ConfirmingThenPaidCreditsOnce(t *testing.T) {
	db, fake, cleanup := withBitcartTestEnv(t)
	defer cleanup()
	seedBitcartInvoice(t, db, fake, "inv_wh1", "bc_wh1", 1_000_000_000, "10.00")

	fake.set("bc_wh1", "status", "paid")
	rec, err := postBitcartNotification(t, "bc_wh1")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, models.PaymentStatusConfirming, localStatus(t, db, "inv_wh1"))
	count, _ := paymentCredits(t, db, "bc_wh1")
	assert.Equal(t, 0, count, "a seen but unconfirmed payment must not credit")

	resetPaymentThrottles()
	fake.set("bc_wh1", "status", "complete")
	_, err = postBitcartNotification(t, "bc_wh1")
	require.NoError(t, err)
	assert.Equal(t, models.PaymentStatusPaid, localStatus(t, db, "inv_wh1"))
	count, balance := paymentCredits(t, db, "bc_wh1")
	assert.Equal(t, 1, count)
	assert.Equal(t, int64(1_000_000_000), balance)

	resetPaymentThrottles()
	_, err = postBitcartNotification(t, "bc_wh1")
	require.NoError(t, err)
	count, balance = paymentCredits(t, db, "bc_wh1")
	assert.Equal(t, 1, count, "replayed notification must not credit twice")
	assert.Equal(t, int64(1_000_000_000), balance)
}

func TestBitcartWebhook_IgnoresBodyStatusAndUnknownInvoice(t *testing.T) {
	db, fake, cleanup := withBitcartTestEnv(t)
	defer cleanup()
	seedBitcartInvoice(t, db, fake, "inv_wh2", "bc_wh2", 500_000_000, "5.00")

	// Body claims complete; Bitcart still reports pending.
	rec, err := postBitcartNotification(t, "bc_wh2")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, models.PaymentStatusPending, localStatus(t, db, "inv_wh2"))

	gets := fake.gets
	rec, err = postBitcartNotification(t, "bc_unknown")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, gets, fake.gets, "unknown invoice ids must not trigger a Bitcart lookup")
}

func TestBitcartWebhook_TamperedInvoiceNotCredited(t *testing.T) {
	db, fake, cleanup := withBitcartTestEnv(t)
	defer cleanup()
	seedBitcartInvoice(t, db, fake, "inv_wh3", "bc_wh3", 1_000_000_000, "10.00")
	fake.set("bc_wh3", "price", "1.00")
	fake.set("bc_wh3", "status", "complete")

	_, err := postBitcartNotification(t, "bc_wh3")
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadGateway, he.Code)
	assert.Equal(t, models.PaymentStatusPending, localStatus(t, db, "inv_wh3"))
	count, _ := paymentCredits(t, db, "bc_wh3")
	assert.Equal(t, 0, count)
}

func TestBitcartWebhook_ThrottlesRepeatedLookups(t *testing.T) {
	db, fake, cleanup := withBitcartTestEnv(t)
	defer cleanup()
	seedBitcartInvoice(t, db, fake, "inv_wh4", "bc_wh4", 100_000_000, "1.00")

	for i := 0; i < 5; i++ {
		_, err := postBitcartNotification(t, "bc_wh4")
		require.NoError(t, err)
	}
	assert.Equal(t, 1, fake.gets)
}

func TestBitcartWebhook_DisabledReturnsNotFound(t *testing.T) {
	_, cleanup := withPaymentsTestEnv(t)
	defer cleanup()

	_, err := postBitcartNotification(t, "bc_any")
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, he.Code)
}

func TestGetInvoiceStatusHandler_RefreshesFromBitcart(t *testing.T) {
	db, fake, cleanup := withBitcartTestEnv(t)
	defer cleanup()
	seedBitcartInvoice(t, db, fake, "inv_poll", "bc_poll", 200_000_000, "2.00")
	fake.set("bc_poll", "status", "confirmed")

	c, rec := newPaymentsEchoContext(t, http.MethodGet, "/api/billing/invoice/inv_poll", nil, paymentsTestUser)
	c.SetParamNames("invoice_id")
	c.SetParamValues("inv_poll")
	require.NoError(t, GetInvoiceStatusHandler(c))
	data := parseJSONResponse(t, rec)["data"].(map[string]interface{})
	assert.Equal(t, models.PaymentStatusConfirming, data["status"])
	assert.Equal(t, "https://pay.arkfile.test/i/bc_poll", data["checkout_url"])

	resetPaymentThrottles()
	fake.set("bc_poll", "status", "complete")
	c, rec = newPaymentsEchoContext(t, http.MethodGet, "/api/billing/invoice/inv_poll", nil, paymentsTestUser)
	c.SetParamNames("invoice_id")
	c.SetParamValues("inv_poll")
	require.NoError(t, GetInvoiceStatusHandler(c))
	data = parseJSONResponse(t, rec)["data"].(map[string]interface{})
	assert.Equal(t, models.PaymentStatusPaid, data["status"])
	_, hasCheckout := data["checkout_url"]
	assert.False(t, hasCheckout, "checkout_url is only returned while the invoice is open")
	count, _ := paymentCredits(t, db, "bc_poll")
	assert.Equal(t, 1, count)
}

func TestCreateInvoiceHandler_Bitcart(t *testing.T) {
	db, fake, cleanup := withBitcartTestEnv(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "12.50"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)
	require.NoError(t, CreateInvoiceHandler(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	data := parseJSONResponse(t, rec)["data"].(map[string]interface{})
	invoiceID, _ := data["invoice_id"].(string)
	require.NotEmpty(t, invoiceID)
	assert.Equal(t, "bitcart", data["provider"])
	assert.True(t, strings.HasPrefix(data["checkout_url"].(string), "https://pay.arkfile.test/i/"))

	inv, err := models.GetPaymentInvoice(db, invoiceID)
	require.NoError(t, err)
	assert.Equal(t, models.PaymentStatusPending, inv.Status)
	assert.Equal(t, int64(1_250_000_000), inv.AmountUSDMicrocents)
	fake.mu.Lock()
	remote := fake.invoices[inv.ProviderInvoiceID]
	fake.mu.Unlock()
	require.NotNil(t, remote)
	assert.Equal(t, invoiceID, remote["order_id"])
	assert.Equal(t, "12.50", remote["price"])
}

func TestAdminSyncInvoiceHandler_BitcartSettles(t *testing.T) {
	db, fake, cleanup := withBitcartTestEnv(t)
	defer cleanup()
	seedBitcartInvoice(t, db, fake, "inv_admsync", "bc_admsync", 300_000_000, "3.00")
	fake.set("bc_admsync", "status", "complete")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/payments/invoice/inv_admsync/sync", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("invoice_id")
	c.SetParamValues("inv_admsync")
	require.NoError(t, AdminSyncInvoiceHandler(c))
	assert.Equal(t, models.PaymentStatusPaid, localStatus(t, db, "inv_admsync"))
	count, _ := paymentCredits(t, db, "bc_admsync")
	assert.Equal(t, 1, count)
}
