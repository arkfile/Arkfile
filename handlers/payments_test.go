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
	"testing"

	"github.com/84adam/Arkfile/billing"
	"github.com/84adam/Arkfile/models"
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
	assert.Contains(t, data["checkout_url"], "https://btcpay.test/checkout/")
	assert.Equal(t, "btcpay", data["provider"])
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

func TestBTCPayWebhookHandler_SettlesInvoiceAndCreditsUser(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_webhook1", paymentsTestUser, "prov_webhook1", 1_000_000_000)

	payload := `{"type":"InvoiceSettled","invoiceId":"prov_webhook1","metadata":{"invoice_id":"inv_webhook1"}}`
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

func TestBTCPayWebhookHandler_IgnoresUnhandledEventType(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withPaymentsTestEnv(t, mock.URL, true)
	defer cleanup()

	payload := `{"type":"InvoiceCreated","invoiceId":"prov_x","metadata":{"invoice_id":"inv_x"}}`
	c, rec := signedWebhookRequest(t, payload)

	err := BTCPayWebhookHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	resp := parseJSONResponse(t, rec)
	assert.Equal(t, "Ignored event type", resp["message"])
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

	payload := `{"type":"InvoiceSettled","invoiceId":"prov_paid1","metadata":{"invoice_id":"inv_paid1"}}`
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

	payload := `{"type":"InvoiceSettled","invoiceId":"prov_fail1","metadata":{"invoice_id":"inv_fail1"}}`
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

	payload := `{"type":"InvoiceSettled","invoiceId":"prov_recover1","metadata":{"invoice_id":"inv_recover1"}}`
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

	if _, err := db.Exec(
		`INSERT INTO user_credits (username, balance_usd_microcents) VALUES (?, ?)`,
		paymentsTestUser, -1000,
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
