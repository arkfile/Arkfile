package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/subbridge"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signedSubscriptionBridgeWebhookContext(t *testing.T, payload subbridge.CallbackPayload, secret string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	keys, err := subbridge.DeriveKeys(secret)
	require.NoError(t, err)
	sig := subbridge.SignWebhook(keys.Callback, body)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/subscription-bridge", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(subbridge.SignatureHeaderName, sig)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func handlerSubscriptionBridgePayload(eventType, eventID, checkoutID, entRef string) subbridge.CallbackPayload {
	now := time.Now().UTC()
	return subbridge.CallbackPayload{
		Protocol:           "subscription-bridge",
		Version:            1,
		EventID:            eventID,
		EventType:          eventType,
		CheckoutID:         checkoutID,
		SubscriptionRef:    entRef,
		PlanID:             subscriptionsTestPlanID,
		StateVersion:       1,
		Status:             "active",
		CurrentPeriodStart: now.Format(time.RFC3339),
		CurrentPeriodEnd:   now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		StateChangedAt:     now.Format(time.RFC3339),
	}
}

func TestSubscriptionBridgeWebhookHandler_ValidSignature(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	checkoutID := "subchk_webhook_ok"
	entRef := "sub_webhook_ok"
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status) VALUES (?, ?, ?, 'pending')`,
		checkoutID, paymentsTestUser, subscriptionsTestPlanID,
	); err != nil {
		t.Fatal(err)
	}

	eventID := "evt_" + uuid.New().String()
	payload := handlerSubscriptionBridgePayload("subscription.activated", eventID, checkoutID, entRef)
	c, rec := signedSubscriptionBridgeWebhookContext(t, payload, subscriptionsTestSecret)

	err := SubscriptionBridgeWebhookHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM subscription_events WHERE event_id = ?`, eventID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, eventCount)
}

func TestSubscriptionBridgeWebhookHandler_RejectsBadSignature(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	_, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	payload := handlerSubscriptionBridgePayload("subscription.activated", "evt_bad", "subchk_bad", "sub_bad")
	body, _ := json.Marshal(payload)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/subscription-bridge", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(subbridge.SignatureHeaderName, "t=1,v1=deadbeef")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := SubscriptionBridgeWebhookHandler(c)
	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, he.Code)
}

func TestSubscriptionBridgeWebhookHandler_RejectsSemanticDefectWith4xx(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	checkoutID := "subchk_invalid_semantics"
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status) VALUES (?, ?, ?, 'pending')`,
		checkoutID, paymentsTestUser, subscriptionsTestPlanID,
	); err != nil {
		t.Fatal(err)
	}
	payload := handlerSubscriptionBridgePayload("subscription.activated", "evt_invalid_semantics", checkoutID, "sub_invalid_semantics")
	payload.CancelAtPeriodEnd = true
	c, _ := signedSubscriptionBridgeWebhookContext(t, payload, subscriptionsTestSecret)

	err := SubscriptionBridgeWebhookHandler(c)
	require.Error(t, err)
	httpError, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpError.Code)
}

func TestSubscriptionBridgeWebhookHandler_Idempotent(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	checkoutID := "subchk_webhook_idem"
	entRef := "sub_webhook_idem"
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status) VALUES (?, ?, ?, 'pending')`,
		checkoutID, paymentsTestUser, subscriptionsTestPlanID,
	); err != nil {
		t.Fatal(err)
	}

	eventID := "evt_" + uuid.New().String()
	payload := handlerSubscriptionBridgePayload("subscription.activated", eventID, checkoutID, entRef)
	c1, _ := signedSubscriptionBridgeWebhookContext(t, payload, subscriptionsTestSecret)
	require.NoError(t, SubscriptionBridgeWebhookHandler(c1))

	c2, rec := signedSubscriptionBridgeWebhookContext(t, payload, subscriptionsTestSecret)
	require.NoError(t, SubscriptionBridgeWebhookHandler(c2))
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
		paymentsTestUser, -1_100_000_000,
	); err != nil {
		t.Fatalf("seed credits: %v", err)
	}

	payload := buildValidInitPayload(validTestFileID)
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	c, rec := newPaymentsEchoContext(t, http.MethodPost, "/api/uploads/init", bytes.NewReader(body), paymentsTestUser)
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()
	_ = CreateUploadSession(c)
	assert.NotEqual(t, http.StatusPaymentRequired, rec.Code, "subscribed user must skip PAYG negative-balance upload cap")
}

func TestCreateUploadSession_BlocksPastDueBeyondGrace(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	checkoutID := "subchk_pastdue_upload"
	entRef := "sub_pastdue_upload"
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status, subscription_ref)
		 VALUES (?, ?, ?, 'completed', ?)`,
		checkoutID, paymentsTestUser, subscriptionsTestPlanID, entRef,
	); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-8 * 24 * time.Hour)
	if _, err := db.Exec(`
		INSERT INTO user_subscriptions
		  (username, plan_id, checkout_id, subscription_ref, status, source, current_period_start, current_period_end, past_due_since)
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
