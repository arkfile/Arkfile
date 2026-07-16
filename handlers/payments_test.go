package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/arkfile/Arkfile/billing"
	"github.com/arkfile/Arkfile/models"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signedWebhookRequest(t *testing.T, payload string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(paymentsWebhookSecret))
	mac.Write([]byte(payload))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/btcpay", strings.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("BTCPay-Sig", sig)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestCreateInvoiceHandler_Success(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "10.00"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)

	err := CreateInvoiceHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := parseJSONResponse(t, rec)
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, data["invoice_id"])
	assert.Contains(t, data["checkout_url"], mock.URL+"/checkout/")
	assert.Equal(t, "btcpay", data["provider"])
	csp := buildContentSecurityPolicy()
	assert.Contains(t, csp, "frame-src 'self' "+mock.URL)
	assert.NotContains(t, csp, "127.0.0.1:8080")
}

func TestCreateInvoiceHandler_RequiresAuth(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "10.00"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), "")

	err := CreateInvoiceHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, he.Code)
	_ = rec
}

func TestCreateInvoiceHandler_PaymentsDisabled(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, false)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "10.00"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)

	err := CreateInvoiceHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, he.Code)
	_ = rec
}

func TestCreateInvoiceHandler_RejectsBelowMinTopUp(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "0.10"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)

	err := CreateInvoiceHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, he.Code)
	_ = rec
}

func TestCreateInvoiceHandler_ExactCentsAndRejectsExcessPrecision(t *testing.T) {
	var createCalls int
	var mock *httptest.Server
	mock = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		createCalls++
		var payload struct {
			Amount string `json:"amount"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, "1.23", payload.Amount)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":           "provider-exact",
			"checkoutLink": mock.URL + "/checkout/provider-exact",
		})
	}))
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "1.23"})
	c, _ := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)
	require.NoError(t, CreateInvoiceHandler(c))

	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"provider-exact"}`
	webhookContext, _ := signedWebhookRequest(t, payload)
	require.NoError(t, BTCPayWebhookHandler(webhookContext))
	var balance int64
	require.NoError(t, db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, paymentsTestUser).Scan(&balance))
	assert.Equal(t, int64(123_000_000), balance)

	body, _ = json.Marshal(map[string]string{"amount_usd": "1.2345"})
	c, _ = newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)
	err := CreateInvoiceHandler(c)
	require.Error(t, err)
	assert.Equal(t, 1, createCalls)
	var invoiceCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM payment_invoices`).Scan(&invoiceCount))
	assert.Equal(t, 1, invoiceCount)
	var creditCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM credit_transactions`).Scan(&creditCount))
	assert.Equal(t, 1, creditCount)
}

func TestCreateInvoiceHandler_PersistsBeforeRemoteAndMarksProviderFailure(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "1.00"})
	c, _ := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)
	err := CreateInvoiceHandler(c)
	require.Error(t, err)
	var status string
	require.NoError(t, db.QueryRow(`SELECT status FROM payment_invoices`).Scan(&status))
	assert.Equal(t, "failed", status)
}

func TestCreateInvoiceHandler_AssociationFailureRecoversFromWebhook(t *testing.T) {
	var mock *httptest.Server
	mock = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Metadata map[string]string `json:"metadata"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":           "provider-recover",
			"checkoutLink": mock.URL + "/checkout/provider-recover",
		})
	}))
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()
	_, err := db.Exec(`CREATE TRIGGER fail_provider_attach BEFORE UPDATE OF provider_invoice_id ON payment_invoices BEGIN SELECT RAISE(FAIL, 'attach failure'); END`)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"amount_usd": "1.00"})
	c, _ := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)
	err = CreateInvoiceHandler(c)
	require.Error(t, err)
	var invoiceID, status string
	require.NoError(t, db.QueryRow(`SELECT invoice_id, status FROM payment_invoices`).Scan(&invoiceID, &status))
	assert.Equal(t, "creating", status)

	_, err = db.Exec(`DROP TRIGGER fail_provider_attach`)
	require.NoError(t, err)
	payload := fmt.Sprintf(`{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"provider-recover","metadata":{"invoice_id":%q}}`, invoiceID)
	webhookContext, _ := signedWebhookRequest(t, payload)
	require.NoError(t, BTCPayWebhookHandler(webhookContext))
	invoice, err := models.GetPaymentInvoice(db, invoiceID)
	require.NoError(t, err)
	assert.Equal(t, "paid", invoice.Status)
}

func TestCreateInvoiceHandler_RepeatedRequestDoesNotCreateSecondRemoteInvoice(t *testing.T) {
	var createCalls int
	var mock *httptest.Server
	mock = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		createCalls++
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":           "provider-repeat",
			"checkoutLink": mock.URL + "/checkout/provider-repeat",
		})
	}))
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	request := map[string]string{
		"amount_usd": "2.00",
		"request_id": "9280cfe6-a8bc-4c70-8568-564837ecf251",
	}
	for attempt := 0; attempt < 2; attempt++ {
		body, _ := json.Marshal(request)
		c, _ := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)
		err := CreateInvoiceHandler(c)
		if attempt == 0 {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			assert.Equal(t, http.StatusConflict, err.(*echo.HTTPError).Code)
		}
	}
	assert.Equal(t, 1, createCalls)
	var invoices int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM payment_invoices`).Scan(&invoices))
	assert.Equal(t, 1, invoices)
}

func TestBTCPayWebhookHandler_SettlesInvoiceAndCreditsUser(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_webhook1", paymentsTestUser, "prov_webhook1", 1_000_000_000)

	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_webhook1","metadata":{"invoice_id":"inv_webhook1"}}`
	c, rec := signedWebhookRequest(t, payload)

	err := BTCPayWebhookHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	inv, err := models.GetPaymentInvoice(db, "inv_webhook1")
	require.NoError(t, err)
	assert.Equal(t, "paid", inv.Status)

	var balance int64
	require.NoError(t, db.QueryRow(
		`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, paymentsTestUser,
	).Scan(&balance))
	assert.Equal(t, int64(1_000_000_000), balance)

	var reason, txType string
	require.NoError(t, db.QueryRow(
		`SELECT reason, transaction_type FROM credit_transactions WHERE transaction_id = 'prov_webhook1'`,
	).Scan(&reason, &txType))
	assert.Equal(t, "Payment top-up via btcpay", reason)
	assert.Equal(t, "payment", txType)
}

func TestBTCPayWebhookHandler_RejectsInvalidSignature(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	payload := `{"type":"InvoiceSettled","invoiceId":"prov_x","metadata":{"invoice_id":"inv_x"}}`
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/btcpay", strings.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("BTCPay-Sig", "sha256=deadbeef")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := BTCPayWebhookHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, he.Code)
}

func TestBTCPayWebhookHandler_RejectsUnsignedMalformedAndUnknownPayloads(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/btcpay", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	err := BTCPayWebhookHandler(e.NewContext(req, rec))
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)

	c, _ := signedWebhookRequest(t, `{`)
	err = BTCPayWebhookHandler(c)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)

	c, _ = signedWebhookRequest(t, `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"unknown","metadata":{"invoice_id":"inv_unknown"}}`)
	err = BTCPayWebhookHandler(c)
	require.Error(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, err.(*echo.HTTPError).Code)

	var credits int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM credit_transactions`).Scan(&credits))
	assert.Zero(t, credits)
}

func TestBTCPayWebhookHandler_IgnoresUnhandledEventType(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	payload := `{"type":"InvoiceCreated","storeId":"test_store_id","invoiceId":"prov_x","metadata":{"invoice_id":"inv_x"}}`
	c, rec := signedWebhookRequest(t, payload)

	err := BTCPayWebhookHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	resp := parseJSONResponse(t, rec)
	assert.Equal(t, "Ignored event type", resp["message"])
}

func TestBTCPayWebhookHandler_IgnoresInvoiceCompleted(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()
	seedPendingInvoice(t, db, "inv_completed", paymentsTestUser, "prov_completed", 100_000_000)

	payload := `{"type":"InvoiceCompleted","storeId":"test_store_id","invoiceId":"prov_completed","metadata":{"invoice_id":"inv_completed"}}`
	c, rec := signedWebhookRequest(t, payload)
	require.NoError(t, BTCPayWebhookHandler(c))
	assert.Equal(t, http.StatusOK, rec.Code)
	invoice, err := models.GetPaymentInvoice(db, "inv_completed")
	require.NoError(t, err)
	assert.Equal(t, "pending", invoice.Status)
}

func TestBTCPayWebhookHandler_RejectsMissingOrWrongStoreAndIdentifierConflict(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()
	seedPendingInvoice(t, db, "inv_store", paymentsTestUser, "prov_store", 100_000_000)
	seedPendingInvoice(t, db, "inv_other", paymentsTestOtherUser, "prov_other", 100_000_000)

	missingStore := `{"type":"InvoiceSettled","invoiceId":"prov_store","metadata":{"invoice_id":"inv_store"}}`
	c, _ := signedWebhookRequest(t, missingStore)
	err := BTCPayWebhookHandler(c)
	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, err.(*echo.HTTPError).Code)

	wrongStore := `{"type":"InvoiceSettled","storeId":"wrong","invoiceId":"prov_store","metadata":{"invoice_id":"inv_store"}}`
	c, _ = signedWebhookRequest(t, wrongStore)
	err = BTCPayWebhookHandler(c)
	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, err.(*echo.HTTPError).Code)

	conflict := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_other","metadata":{"invoice_id":"inv_store"}}`
	c, _ = signedWebhookRequest(t, conflict)
	err = BTCPayWebhookHandler(c)
	require.Error(t, err)
	assert.Equal(t, http.StatusConflict, err.(*echo.HTTPError).Code)

	var credits int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM credit_transactions`).Scan(&credits))
	assert.Zero(t, credits)
}

func TestBTCPayWebhookHandler_RejectsOversizedBody(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	payload := `{"type":"InvoiceSettled","padding":"` + strings.Repeat("a", (64<<10)+1) + `"}`
	c, _ := signedWebhookRequest(t, payload)
	err := BTCPayWebhookHandler(c)
	require.Error(t, err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, err.(*echo.HTTPError).Code)
}

func TestBTCPayWebhookHandler_SignedReplayCreditsOnce(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()
	seedPendingInvoice(t, db, "inv_replay", paymentsTestUser, "prov_replay", 123_000_000)
	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_replay","metadata":{"invoice_id":"inv_replay"}}`

	for i := 0; i < 2; i++ {
		c, _ := signedWebhookRequest(t, payload)
		require.NoError(t, BTCPayWebhookHandler(c))
	}
	var balance int64
	require.NoError(t, db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, paymentsTestUser).Scan(&balance))
	assert.Equal(t, int64(123_000_000), balance)
	var credits int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM credit_transactions WHERE transaction_id = 'prov_replay'`).Scan(&credits))
	assert.Equal(t, 1, credits)
}

func TestBTCPayWebhookHandler_ConcurrentDeliveryCreditsOnce(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()
	seedPendingInvoice(t, db, "inv_concurrent", paymentsTestUser, "prov_concurrent", 250_000_000)
	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_concurrent","metadata":{"invoice_id":"inv_concurrent"}}`

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			c, _ := signedWebhookRequest(t, payload)
			errs <- BTCPayWebhookHandler(c)
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var balance int64
	require.NoError(t, db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, paymentsTestUser).Scan(&balance))
	assert.Equal(t, int64(250_000_000), balance)
	var credits int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM credit_transactions WHERE transaction_id = 'prov_concurrent'`).Scan(&credits))
	assert.Equal(t, 1, credits)
}

func TestBTCPayWebhookHandler_IdempotentWhenAlreadyPaid(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_paid1", paymentsTestUser, "prov_paid1", 500_000_000)
	require.NoError(t, models.UpdatePaymentInvoiceStatus(db, "inv_paid1", "paid"))
	_, err := billing.ProcessPayment(db, paymentsTestUser, 500_000_000, "prov_paid1", "btcpay")
	require.NoError(t, err)

	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_paid1","metadata":{"invoice_id":"inv_paid1"}}`
	c, rec := signedWebhookRequest(t, payload)

	err = BTCPayWebhookHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	resp := parseJSONResponse(t, rec)
	assert.Equal(t, "Invoice already paid", resp["message"])
}

func TestBTCPayWebhookHandler_SettlementFailureLeavesInvoicePending(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	origSettle := SettlePaymentInvoiceFunc
	SetSettlePaymentInvoiceFunc(func(db *sql.DB, invoice *models.PaymentInvoice, paymentType string) (*models.CreditTransaction, error) {
		return nil, fmt.Errorf("simulated credit failure")
	})
	defer SetSettlePaymentInvoiceFunc(origSettle)

	seedPendingInvoice(t, db, "inv_fail1", paymentsTestUser, "prov_fail1", 100_000_000)

	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_fail1","metadata":{"invoice_id":"inv_fail1"}}`
	c, rec := signedWebhookRequest(t, payload)

	err := BTCPayWebhookHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, he.Code)
	_ = rec

	inv, err := models.GetPaymentInvoice(db, "inv_fail1")
	require.NoError(t, err)
	assert.Equal(t, "pending", inv.Status)

	var creditCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(1) FROM credit_transactions WHERE transaction_id = 'prov_fail1'`).Scan(&creditCount))
	assert.Equal(t, 0, creditCount)
}

func TestBTCPayWebhookHandler_RecoversPaidInvoiceMissingCredit(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_recover1", paymentsTestUser, "prov_recover1", 300_000_000)
	require.NoError(t, models.UpdatePaymentInvoiceStatus(db, "inv_recover1", "paid"))

	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_recover1","metadata":{"invoice_id":"inv_recover1"}}`
	c, rec := signedWebhookRequest(t, payload)

	err := BTCPayWebhookHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var balance int64
	require.NoError(t, db.QueryRow(
		`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, paymentsTestUser,
	).Scan(&balance))
	assert.Equal(t, int64(300_000_000), balance)
}

func TestGetInvoiceStatusHandler_EnforcesOwnership(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_own1", paymentsTestOtherUser, "prov_own1", 100_000_000)

	c, rec := newPaymentsEchoContext(t, http.MethodGet, "/api/billing/invoice/inv_own1", nil, paymentsTestUser)
	c.SetParamNames("invoice_id")
	c.SetParamValues("inv_own1")

	err := GetInvoiceStatusHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, he.Code)
	_ = rec
}

func TestGetInvoiceStatusHandler_ReturnsOwnInvoice(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_own2", paymentsTestUser, "prov_own2", 100_000_000)

	c, rec := newPaymentsEchoContext(t, http.MethodGet, "/api/billing/invoice/inv_own2", nil, paymentsTestUser)
	c.SetParamNames("invoice_id")
	c.SetParamValues("inv_own2")

	err := GetInvoiceStatusHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	resp := parseJSONResponse(t, rec)
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "pending", data["status"])
}

func TestAdminSyncInvoiceHandler_SettlesFromBTCPay(t *testing.T) {
	statusByProvider := map[string]string{"prov_sync1": "Settled"}
	mock := startMockBTCPayServer(t, statusByProvider)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_sync1", paymentsTestUser, "prov_sync1", 250_000_000)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/payments/invoice/inv_sync1/sync", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("invoice_id")
	c.SetParamValues("inv_sync1")

	err := AdminSyncInvoiceHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	inv, err := models.GetPaymentInvoice(db, "inv_sync1")
	require.NoError(t, err)
	assert.Equal(t, "paid", inv.Status)
}

func TestAdminReconcilePaymentsHandler_MissedWebhookIsIdempotent(t *testing.T) {
	statusByProvider := map[string]string{"prov_missed": "Settled"}
	mock := startMockBTCPayServer(t, statusByProvider)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()
	seedPendingInvoice(t, db, "inv_missed", paymentsTestUser, "prov_missed", 175_000_000)

	for i := 0; i < 2; i++ {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/admin/payments/reconcile", nil)
		rec := httptest.NewRecorder()
		require.NoError(t, AdminReconcilePaymentsHandler(e.NewContext(req, rec)))
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	payload := `{"type":"InvoiceSettled","storeId":"test_store_id","invoiceId":"prov_missed","metadata":{"invoice_id":"inv_missed"}}`
	c, _ := signedWebhookRequest(t, payload)
	require.NoError(t, BTCPayWebhookHandler(c))

	var balance int64
	require.NoError(t, db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, paymentsTestUser).Scan(&balance))
	assert.Equal(t, int64(175_000_000), balance)
	var credits int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM credit_transactions WHERE transaction_id = 'prov_missed'`).Scan(&credits))
	assert.Equal(t, 1, credits)
}

func TestGetUserCredits_IncludesPaymentsConfigWhenEnabled(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	c, rec := newPaymentsEchoContext(t, http.MethodGet, "/api/credits", nil, paymentsTestUser)

	err := GetUserCredits(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := parseJSONResponse(t, rec)
	payments, ok := resp["payments"].(map[string]interface{})
	require.True(t, ok, "expected payments block in response")
	assert.Equal(t, true, payments["enabled"])
	assert.Equal(t, "0.50", payments["min_top_up"])
	assert.Equal(t, "1000.00", payments["max_top_up"])
}

func TestCreateUploadSession_SoftBlockNegativeBalance(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	// Balance of -$11.00 is beyond the $10.00 PAYG negative-balance cap, so
	// uploads must be soft-blocked (login/downloads remain available).
	if _, err := db.Exec(
		`INSERT INTO user_credits (username, balance_usd_microcents) VALUES (?, ?)`,
		paymentsTestUser, -1_100_000_000,
	); err != nil {
		t.Fatalf("seed credits: %v", err)
	}

	payload := buildValidInitPayload(validTestFileID)
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/uploads/init", bytes.NewReader(body), paymentsTestUser)

	err = CreateUploadSession(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusPaymentRequired, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	assert.Equal(t, "payment_required", resp.Error)
}

// TestCreateUploadSession_AllowsWithinNegativeCap verifies that a small
// negative balance within the $10.00 PAYG cap does NOT trigger the upload
// soft-block. The handler may still error later (the test schema omits the
// upload_sessions table); the assertion is only that the payment_required gate
// did not fire.
func TestCreateUploadSession_AllowsWithinNegativeCap(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	// -$0.001 is negative but well within the $10.00 cap.
	if _, err := db.Exec(
		`INSERT INTO user_credits (username, balance_usd_microcents) VALUES (?, ?)`,
		paymentsTestUser, -100_000,
	); err != nil {
		t.Fatalf("seed credits: %v", err)
	}

	payload := buildValidInitPayload(validTestFileID)
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/uploads/init", bytes.NewReader(body), paymentsTestUser)

	defer func() {
		if r := recover(); r != nil {
			// Proceeding past the PAYG gate is sufficient; storage is not wired in this harness.
			return
		}
	}()
	_ = CreateUploadSession(c)
	assert.NotEqual(t, http.StatusPaymentRequired, rec.Code, "small negative balance must not trigger the upload soft-block")
}
