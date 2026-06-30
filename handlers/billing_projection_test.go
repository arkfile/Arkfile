package handlers

import (
	"testing"

	"github.com/arkfile/Arkfile/billing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSubscriptionProjection_SubscribedUser(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	seedHandlerGiftSubscription(t, db, paymentsTestUser)

	block, mode := buildSubscriptionProjection(db, paymentsTestUser)
	require.NotNil(t, block)
	assert.Equal(t, "subscribed", mode)
	assert.Equal(t, true, block["enabled"])
	assert.Equal(t, "active", block["status"])
	assert.Equal(t, subscriptionsTestPlanID, block["plan_id"])
	assert.Equal(t, "gift", block["source"])

	effectiveLimit, ok := block["effective_storage_limit_bytes"].(int64)
	require.True(t, ok)
	assert.Equal(t, int64(250)<<30, effectiveLimit)
}

func TestBuildBillingProjection_SubscribedUserZeroCost(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	if _, err := db.Exec(`UPDATE users SET total_storage_bytes = ? WHERE username = ?`, 300<<30, paymentsTestUser); err != nil {
		t.Fatal(err)
	}
	seedHandlerGiftSubscription(t, db, paymentsTestUser)

	currentUsage, _ := buildBillingProjection(db, paymentsTestUser, 1_000_000)
	assert.Equal(t, int64(0), currentUsage["current_cost_per_month_microcents"])
	billable, ok := currentUsage["billable_bytes"].(int64)
	require.True(t, ok)
	assert.Greater(t, billable, int64(0), "user above plan baseline should still have billable bytes")

	freeBaseline, ok := currentUsage["free_baseline_bytes"].(int64)
	require.True(t, ok)
	assert.Equal(t, int64(250)<<30, freeBaseline)

	assert.Equal(t, billing.BillingModeSubscribed, billing.EffectiveBillingMode(db, paymentsTestUser))
}

func TestGetUserCredits_IncludesSubscriptionBlock(t *testing.T) {
	mock := startMockBTCPayServer(t, nil)
	defer mock.Close()
	db, cleanup := withSubscriptionsTestEnv(t, mock.URL)
	defer cleanup()

	seedHandlerGiftSubscription(t, db, paymentsTestUser)

	c, rec := newPaymentsEchoContext(t, "GET", "/api/credits", nil, paymentsTestUser)
	err := GetUserCredits(c)
	require.NoError(t, err)

	resp := parseJSONResponse(t, rec)
	assert.Equal(t, "subscribed", resp["billing_mode"])
	sub, ok := resp["subscription"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "active", sub["status"])
}
