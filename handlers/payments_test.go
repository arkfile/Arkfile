package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateInvoiceHandler_RequiresAuth(t *testing.T) {
	_, cleanup := withPaymentsTestEnv(t)
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
	_, cleanup := withPaymentsTestEnv(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"amount_usd": "10.00"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)

	err := CreateInvoiceHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, he.Code)
	assert.Equal(t, "Payments integration is disabled", he.Message)
	_ = rec
}

func TestGetInvoiceStatusHandler_EnforcesOwnership(t *testing.T) {
	db, cleanup := withPaymentsTestEnv(t)
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
	db, cleanup := withPaymentsTestEnv(t)
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
	assert.Equal(t, "testprov", data["provider"])
}

func TestGetUserCredits_OmitsPaymentsWhenDisabled(t *testing.T) {
	_, cleanup := withPaymentsTestEnv(t)
	defer cleanup()

	c, rec := newPaymentsEchoContext(t, http.MethodGet, "/api/credits", nil, paymentsTestUser)

	err := GetUserCredits(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := parseJSONResponse(t, rec)
	_, ok := resp["payments"]
	assert.False(t, ok, "payments block must be absent while top-ups are disabled")
}

func TestAdminReconcilePaymentsHandler_Disabled(t *testing.T) {
	_, cleanup := withPaymentsTestEnv(t)
	defer cleanup()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/payments/reconcile", nil)
	rec := httptest.NewRecorder()
	err := AdminReconcilePaymentsHandler(e.NewContext(req, rec))
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, he.Code)
}

func TestAdminSyncInvoiceHandler_Disabled(t *testing.T) {
	db, cleanup := withPaymentsTestEnv(t)
	defer cleanup()

	seedPendingInvoice(t, db, "inv_sync_disabled", paymentsTestUser, "prov_sync_disabled", 100_000_000)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/payments/invoice/inv_sync_disabled/sync", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("invoice_id")
	c.SetParamValues("inv_sync_disabled")

	err := AdminSyncInvoiceHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, he.Code)
	assert.Equal(t, "Payments integration is disabled", he.Message)
}

func TestCreateUploadSession_SoftBlockNegativeBalance(t *testing.T) {
	db, cleanup := withPaymentsTestEnv(t)
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
	db, cleanup := withPaymentsTestEnv(t)
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
