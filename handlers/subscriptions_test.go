package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/entitlements"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signedEntitlementWebhookContext(t *testing.T, payload entitlements.CallbackPayload, secret string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	sig := entitlements.SignWebhook(secret, body)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/entitlements", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(entitlements.SignatureHeaderName, sig)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func handlerEntitlementPayload(eventType, eventID, checkoutID, entRef string) entitlements.CallbackPayload {
	now := time.Now().UTC()
	return entitlements.CallbackPayload{
		Protocol:           "entitlement-bridge",
		Version:            1,
		EventID:            eventID,
		EventType:          eventType,
		CheckoutID:         checkoutID,
		EntitlementRef:     entRef,
		PlanID:             subscriptionsTestPlanID,
		Status:             "active",
		CurrentPeriodStart: now.Format(time.RFC3339),
		CurrentPeriodEnd:   now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		OccurredAt:         now.Format(time.RFC3339),
	}
}

func TestEntitlementWebhookHandler_ValidSignature(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	checkoutID := "subchk_webhook_ok"
	entRef := "ent_webhook_ok"
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status) VALUES (?, ?, ?, 'pending')`,
		checkoutID, paymentsTestUser, subscriptionsTestPlanID,
	); err != nil {
		t.Fatal(err)
	}

	eventID := "evt_" + uuid.New().String()
	payload := handlerEntitlementPayload("entitlement.activated", eventID, checkoutID, entRef)
	c, rec := signedEntitlementWebhookContext(t, payload, subscriptionsTestSecret)

	err := EntitlementWebhookHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM subscription_events WHERE event_id = ?`, eventID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, eventCount)
}

func TestEntitlementWebhookHandler_RejectsBadSignature(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	payload := handlerEntitlementPayload("entitlement.activated", "evt_bad", "subchk_bad", "ent_bad")
	body, _ := json.Marshal(payload)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/entitlements", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(entitlements.SignatureHeaderName, "t=1,v1=deadbeef")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := EntitlementWebhookHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, he.Code)
}

func TestEntitlementWebhookHandler_Idempotent(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	checkoutID := "subchk_webhook_idem"
	entRef := "ent_webhook_idem"
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status) VALUES (?, ?, ?, 'pending')`,
		checkoutID, paymentsTestUser, subscriptionsTestPlanID,
	); err != nil {
		t.Fatal(err)
	}

	eventID := "evt_" + uuid.New().String()
	payload := handlerEntitlementPayload("entitlement.activated", eventID, checkoutID, entRef)
	c1, _ := signedEntitlementWebhookContext(t, payload, subscriptionsTestSecret)
	require.NoError(t, EntitlementWebhookHandler(c1))

	c2, rec := signedEntitlementWebhookContext(t, payload, subscriptionsTestSecret)
	require.NoError(t, EntitlementWebhookHandler(c2))
	assert.Equal(t, http.StatusOK, rec.Code)

	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM subscription_events WHERE event_id = ?`, eventID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, eventCount)
}

func TestCreateInvoiceHandler_ConflictWhenSubscribed(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	seedHandlerGiftSubscription(t, db, paymentsTestUser)

	body, _ := json.Marshal(map[string]string{"amount_usd": "10.00"})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/billing/invoice", bytes.NewReader(body), paymentsTestUser)

	err := CreateInvoiceHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusConflict, he.Code)
	_ = rec
}

func TestCreateSubscriptionCheckoutHandler_ConflictWhenEntitled(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	seedHandlerGiftSubscription(t, db, paymentsTestUser)

	body, _ := json.Marshal(map[string]string{"plan_id": subscriptionsTestPlanID})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/subscriptions/checkout", bytes.NewReader(body), paymentsTestUser)

	err := CreateSubscriptionCheckoutHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusConflict, he.Code)
	_ = rec
}

func TestCreateSubscriptionCheckoutHandler_Success(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"plan_id": subscriptionsTestPlanID})
	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/subscriptions/checkout", bytes.NewReader(body), paymentsTestUser)

	err := CreateSubscriptionCheckoutHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := parseJSONResponse(t, rec)
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, data["checkout_url"], "/v1/start?token=")
}

func TestCreateUploadSession_SubscribedSkipsPaygCap(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	seedHandlerGiftSubscription(t, db, paymentsTestUser)
	if _, err := db.Exec(
		`INSERT INTO user_credits (username, balance_usd_microcents) VALUES (?, ?)`,
		paymentsTestUser, -11_000_000,
	); err != nil {
		t.Fatalf("seed credits: %v", err)
	}

	payload := buildValidInitPayload(validTestFileID)
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/uploads/init", bytes.NewReader(body), paymentsTestUser)
	_ = CreateUploadSession(c)
	assert.NotEqual(t, http.StatusPaymentRequired, rec.Code, "subscribed user must skip PAYG negative-balance upload cap")
}

func TestCreateUploadSession_BlocksPastDueBeyondGrace(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	checkoutID := "subchk_pastdue_upload"
	entRef := "ent_pastdue_upload"
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status, entitlement_ref)
		 VALUES (?, ?, ?, 'completed', ?)`,
		checkoutID, paymentsTestUser, subscriptionsTestPlanID, entRef,
	); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-8 * 24 * time.Hour)
	if _, err := db.Exec(`
		INSERT INTO user_subscriptions
		  (username, plan_id, checkout_id, entitlement_ref, status, source, current_period_start, current_period_end, past_due_since)
		VALUES (?, ?, ?, ?, 'past_due', 'bridge', datetime('now', '-60 days'), datetime('now', '+1 day'), ?)`,
		paymentsTestUser, subscriptionsTestPlanID, checkoutID, entRef, old,
	); err != nil {
		t.Fatal(err)
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
	assert.Equal(t, "subscription_past_due", resp.Error)
}

func TestListSubscriptionPlansHandler_ReturnsPublicPlans(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	c, rec := newPaymentsEchoContext(t, http.MethodGet, "/api/subscriptions/plans", nil, paymentsTestUser)
	err := ListSubscriptionPlansHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := parseJSONResponse(t, rec)
	plans, ok := resp["plans"].([]interface{})
	require.True(t, ok)
	assert.Len(t, plans, 1)
}
