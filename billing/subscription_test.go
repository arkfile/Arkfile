package billing

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/subbridge"
)

func TestValidateSubscriptionBridgePayloadRejectsMalformedWireValues(t *testing.T) {
	base := testSubscriptionBridgePayload("subscription.activated", "evt_valid", "subchk_valid", "sub_valid", "active")
	tests := map[string]func(*subbridge.CallbackPayload){
		"event identifier": func(payload *subbridge.CallbackPayload) { payload.EventID = "evt_bad/value" },
		"timestamp offset": func(payload *subbridge.CallbackPayload) { payload.StateChangedAt = "2026-01-01T01:00:00+01:00" },
		"fractional time":  func(payload *subbridge.CallbackPayload) { payload.CurrentPeriodStart = "2026-01-01T00:00:00.1Z" },
		"cancel mismatch":  func(payload *subbridge.CallbackPayload) { payload.CancelAtPeriodEnd = true },
		"blank plan":       func(payload *subbridge.CallbackPayload) { payload.PlanID = "\u2003" },
		"overlong plan":    func(payload *subbridge.CallbackPayload) { payload.PlanID = strings.Repeat("a", 129) },
	}
	for name, mutate := range tests {
		payload := *base
		mutate(&payload)
		if _, _, _, err := validateSubscriptionBridgePayload(&payload); err == nil {
			t.Fatalf("%s should fail", name)
		}
	}
}

func TestProcessSubscriptionBridgeCallback_ActivatedCreatesSubscription(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 2<<30)
	checkoutID := "subchk_activate"
	entRef := "sub_activate"
	seedPendingCheckout(t, db, checkoutID, "alice")

	eventID := newEventID()
	payload := testSubscriptionBridgePayload("subscription.activated", eventID, checkoutID, entRef, "active")
	if err := ProcessSubscriptionBridgeCallback(db, payload); err != nil {
		t.Fatalf("ProcessSubscriptionBridgeCallback: %v", err)
	}

	sub, err := models.GetUserSubscriptionBySubscriptionRef(db, entRef)
	if err != nil {
		t.Fatalf("GetUserSubscriptionBySubscriptionRef: %v", err)
	}
	if sub.Status != "active" || sub.Source != "bridge" {
		t.Fatalf("unexpected subscription: %+v", sub)
	}

	var checkoutStatus string
	if err := db.QueryRow(`SELECT status FROM subscription_checkouts WHERE checkout_id = ?`, checkoutID).Scan(&checkoutStatus); err != nil {
		t.Fatal(err)
	}
	if checkoutStatus != "completed" {
		t.Fatalf("checkout status = %q, want completed", checkoutStatus)
	}
	if countSubscriptionEvents(t, db, eventID) != 1 {
		t.Fatal("expected one subscription event row")
	}
}

func TestProcessSubscriptionBridgeCallback_Idempotent(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_idem"
	entRef := "sub_idem"
	seedPendingCheckout(t, db, checkoutID, "alice")

	eventID := newEventID()
	payload := testSubscriptionBridgePayload("subscription.activated", eventID, checkoutID, entRef, "active")
	if err := ProcessSubscriptionBridgeCallback(db, payload); err != nil {
		t.Fatal(err)
	}
	if err := ProcessSubscriptionBridgeCallback(db, payload); err != nil {
		t.Fatalf("duplicate callback should be no-op: %v", err)
	}
	if countSubscriptionEvents(t, db, eventID) != 1 {
		t.Fatal("idempotent replay must not insert duplicate event")
	}
}

func TestProcessSubscriptionBridgeCallback_ConcurrentIdempotency(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_concurrent"
	subscriptionRef := "sub_concurrent"
	seedPendingCheckout(t, db, checkoutID, "alice")
	payload := testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, subscriptionRef, "active")

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ProcessSubscriptionBridgeCallback(db, payload)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent callback: %v", err)
		}
	}
	if countSubscriptionEvents(t, db, payload.EventID) != 1 {
		t.Fatal("concurrent replay must produce one event")
	}
}

func TestProcessSubscriptionBridgeCallback_RejectsCheckoutMismatch(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	seedPendingCheckout(t, db, "subchk_expected", "alice")
	payload := testSubscriptionBridgePayload("subscription.activated", newEventID(), "subchk_other", "sub_mismatch", "active")
	if err := ProcessSubscriptionBridgeCallback(db, payload); err == nil {
		t.Fatal("expected unknown checkout to be rejected")
	}
	if countSubscriptionEvents(t, db, payload.EventID) != 0 {
		t.Fatal("rejected callback must not create an event")
	}
}

func TestProcessSubscriptionBridgeCallback_PastDueSetsTimestamp(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_pastdue"
	entRef := "sub_pastdue"
	seedPendingCheckout(t, db, checkoutID, "alice")

	activate := testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, entRef, "active")
	activate.StateChangedAt = time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if err := ProcessSubscriptionBridgeCallback(db, activate); err != nil {
		t.Fatal(err)
	}

	pastDue := testSubscriptionBridgePayload("subscription.past_due", newEventID(), checkoutID, entRef, "past_due")
	pastDue.StateVersion = 2
	occurredAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	pastDue.StateChangedAt = occurredAt.Format(time.RFC3339)
	if err := ProcessSubscriptionBridgeCallback(db, pastDue); err != nil {
		t.Fatal(err)
	}

	sub, err := models.GetUserSubscriptionBySubscriptionRef(db, entRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "past_due" || sub.PastDueSince == nil {
		t.Fatalf("expected past_due with timestamp, got %+v", sub)
	}
	if !sub.PastDueSince.Equal(occurredAt) {
		t.Fatalf("past_due_since = %s, want event time %s", sub.PastDueSince, occurredAt)
	}
}

func TestProcessSubscriptionBridgeCallback_IgnoresOutOfOrderAndFindsExpiredRow(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_ordered"
	subscriptionRef := "sub_ordered"
	seedPendingCheckout(t, db, checkoutID, "alice")

	activated := testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, subscriptionRef, "active")
	if err := ProcessSubscriptionBridgeCallback(db, activated); err != nil {
		t.Fatal(err)
	}
	expired := testSubscriptionBridgePayload("subscription.expired", newEventID(), checkoutID, subscriptionRef, "expired")
	expired.StateVersion = 3
	if err := ProcessSubscriptionBridgeCallback(db, expired); err != nil {
		t.Fatal(err)
	}
	stale := testSubscriptionBridgePayload("subscription.past_due", newEventID(), checkoutID, subscriptionRef, "past_due")
	stale.StateVersion = 2
	if err := ProcessSubscriptionBridgeCallback(db, stale); err != nil {
		t.Fatal(err)
	}

	sub, err := models.GetUserSubscriptionBySubscriptionRef(db, subscriptionRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "expired" || sub.IsCurrent {
		t.Fatalf("stale callback changed expired row: %+v", sub)
	}
	var disposition string
	if err := db.QueryRow(`SELECT disposition FROM subscription_events WHERE event_id = ?`, stale.EventID).Scan(&disposition); err != nil {
		t.Fatal(err)
	}
	if disposition != "ignored_stale" {
		t.Fatalf("stale event disposition = %q", disposition)
	}
}

func TestProcessSubscriptionBridgeCallback_RenewedClearsPastDue(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_renew"
	entRef := "sub_renew"
	seedPendingCheckout(t, db, checkoutID, "alice")

	if err := ProcessSubscriptionBridgeCallback(db, testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, entRef, "active")); err != nil {
		t.Fatal(err)
	}
	pastDue := testSubscriptionBridgePayload("subscription.past_due", newEventID(), checkoutID, entRef, "past_due")
	pastDue.StateVersion = 2
	if err := ProcessSubscriptionBridgeCallback(db, pastDue); err != nil {
		t.Fatal(err)
	}
	renewed := testSubscriptionBridgePayload("subscription.renewed", newEventID(), checkoutID, entRef, "active")
	renewed.StateVersion = 3
	if err := ProcessSubscriptionBridgeCallback(db, renewed); err != nil {
		t.Fatal(err)
	}

	sub, err := models.GetUserSubscriptionBySubscriptionRef(db, entRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "active" || sub.PastDueSince != nil {
		t.Fatalf("renewed subscription should clear past_due, got %+v", sub)
	}
}

func TestProcessSubscriptionBridgeCallback_CanceledAndExpired(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_cancel"
	entRef := "sub_cancel"
	seedPendingCheckout(t, db, checkoutID, "alice")

	if err := ProcessSubscriptionBridgeCallback(db, testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, entRef, "active")); err != nil {
		t.Fatal(err)
	}
	canceled := testSubscriptionBridgePayload("subscription.canceled", newEventID(), checkoutID, entRef, "canceled")
	canceled.StateVersion = 2
	canceled.CancelAtPeriodEnd = true
	if err := ProcessSubscriptionBridgeCallback(db, canceled); err != nil {
		t.Fatal(err)
	}
	sub, err := models.GetUserSubscriptionBySubscriptionRef(db, entRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "canceled" || sub.CanceledAt == nil {
		t.Fatalf("expected canceled with timestamp, got %+v", sub)
	}

	renewed := testSubscriptionBridgePayload("subscription.renewed", newEventID(), checkoutID, entRef, "active")
	renewed.StateVersion = 3
	if err := ProcessSubscriptionBridgeCallback(db, renewed); err != nil {
		t.Fatal(err)
	}
	sub, err = models.GetUserSubscriptionBySubscriptionRef(db, entRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "active" || sub.CancelAtPeriodEnd || sub.CanceledAt != nil {
		t.Fatalf("expected authoritative cancellation reversal, got %+v", sub)
	}

	canceled = testSubscriptionBridgePayload("subscription.canceled", newEventID(), checkoutID, entRef, "canceled")
	canceled.StateVersion = 4
	canceled.CancelAtPeriodEnd = true
	if err := ProcessSubscriptionBridgeCallback(db, canceled); err != nil {
		t.Fatal(err)
	}
	expired := testSubscriptionBridgePayload("subscription.expired", newEventID(), checkoutID, entRef, "expired")
	expired.StateVersion = 5
	if err := ProcessSubscriptionBridgeCallback(db, expired); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM user_subscriptions WHERE subscription_ref = ?`, entRef).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "expired" {
		t.Fatalf("expected expired status, got %q", status)
	}
}

func TestProcessSubscriptionBridgeCallback_StoresExactRawBodyHash(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_raw_hash"
	subscriptionRef := "sub_raw_hash"
	seedPendingCheckout(t, db, checkoutID, "alice")
	payload := testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, subscriptionRef, "active")
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := ProcessSubscriptionBridgeCallbackBody(db, payload, body); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(body)
	var gotHash string
	if err := db.QueryRow(`SELECT payload_hash FROM subscription_events WHERE event_id = ?`, payload.EventID).Scan(&gotHash); err != nil {
		t.Fatal(err)
	}
	if gotHash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("payload hash = %q, want exact raw body hash", gotHash)
	}
	if err := ProcessSubscriptionBridgeCallbackBody(db, payload, append(body, ' ')); err == nil {
		t.Fatal("expected event_id reuse with different raw body to fail")
	}
}

func TestProcessSubscriptionBridgeSnapshot_LifecycleAndReplay(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_snapshot"
	subscriptionRef := "sub_snapshot"
	seedPendingCheckout(t, db, checkoutID, "alice")
	activated := testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, subscriptionRef, "active")
	if err := ProcessSubscriptionBridgeCallback(db, activated); err != nil {
		t.Fatal(err)
	}

	snapshot := subbridge.SnapshotPayload{
		Protocol:           activated.Protocol,
		Version:            activated.Version,
		CheckoutID:         checkoutID,
		SubscriptionRef:    subscriptionRef,
		PlanID:             activated.PlanID,
		StateVersion:       2,
		Status:             "past_due",
		CurrentPeriodStart: activated.CurrentPeriodStart,
		CurrentPeriodEnd:   activated.CurrentPeriodEnd,
		CancelAtPeriodEnd:  false,
		StateChangedAt:     activated.StateChangedAt,
	}
	applySnapshot := func() error {
		body, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		return ProcessSubscriptionBridgeSnapshot(db, &snapshot, body)
	}
	if err := applySnapshot(); err != nil {
		t.Fatal(err)
	}
	if err := applySnapshot(); err != nil {
		t.Fatalf("snapshot replay: %v", err)
	}

	snapshot.StateVersion = 3
	snapshot.Status = "canceled"
	snapshot.CancelAtPeriodEnd = true
	if err := applySnapshot(); err != nil {
		t.Fatal(err)
	}
	snapshot.StateVersion = 4
	snapshot.Status = "expired"
	snapshot.CancelAtPeriodEnd = false
	if err := applySnapshot(); err != nil {
		t.Fatal(err)
	}
	subscription, err := models.GetUserSubscriptionBySubscriptionRef(db, subscriptionRef)
	if err != nil {
		t.Fatal(err)
	}
	if subscription.Status != "expired" || subscription.IsCurrent {
		t.Fatalf("snapshot lifecycle ended at %+v", subscription)
	}
}

func TestGrantGiftSubscription_DefaultAndMaxDays(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)

	sub, err := GrantGiftSubscription(db, "alice", subTestPlanID, 0, "welcome", "admin")
	if err != nil {
		t.Fatalf("GrantGiftSubscription default days: %v", err)
	}
	if sub.Source != "gift" || sub.Status != "active" {
		t.Fatalf("unexpected gift sub: %+v", sub)
	}
	days := sub.CurrentPeriodEnd.Sub(sub.CurrentPeriodStart).Hours() / 24
	if days < 29 || days > 31 {
		t.Fatalf("expected ~30 day gift, got %.1f days", days)
	}

	_, err = GrantGiftSubscription(db, "alice", subTestPlanID, 91, "", "admin")
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected max days error, got %v", err)
	}
}

func TestGrantGiftSubscription_RejectsDuplicateActive(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	if _, err := GrantGiftSubscription(db, "alice", subTestPlanID, 30, "", "admin"); err != nil {
		t.Fatal(err)
	}
	_, err := GrantGiftSubscription(db, "alice", subTestPlanID, 30, "", "admin")
	if err == nil || !strings.Contains(err.Error(), "already has an active subscription") {
		t.Fatalf("expected duplicate active error, got %v", err)
	}
}

func TestCancelGiftSubscription_RejectsBridgeSource(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_bridge"
	entRef := "sub_bridge"
	seedPendingCheckout(t, db, checkoutID, "alice")
	if err := ProcessSubscriptionBridgeCallback(db, testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, entRef, "active")); err != nil {
		t.Fatal(err)
	}

	err := CancelGiftSubscription(db, "alice", false)
	if err == nil || !strings.Contains(err.Error(), "paid subscriptions") {
		t.Fatalf("expected bridge cancel rejection, got %v", err)
	}
}

func TestCancelGiftSubscription_Immediate(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	if _, err := GrantGiftSubscription(db, "alice", subTestPlanID, 30, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := CancelGiftSubscription(db, "alice", true); err != nil {
		t.Fatal(err)
	}
	sub, err := GetActiveSubscription(db, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if sub != nil {
		t.Fatal("immediate cancel should expire gift subscription")
	}
}

func TestFinalizePaygBeforeSubscribe_SettlesAccumulator(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	freeBaseline := int64(1073741824)
	seedSubscriptionUser(t, db, "alice", freeBaseline+(5<<30))
	if _, err := db.Exec(
		`INSERT INTO storage_usage_accumulator (username, unbilled_microcents, last_tick_at) VALUES ('alice', 5000, datetime('now'))`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO user_credits (username, balance_usd_microcents) VALUES ('alice', 1000000)`); err != nil {
		t.Fatal(err)
	}

	if err := FinalizePaygBeforeSubscribe(db, "alice"); err != nil {
		t.Fatalf("FinalizePaygBeforeSubscribe: %v", err)
	}

	var unbilled int64
	err := db.QueryRow(`SELECT unbilled_microcents FROM storage_usage_accumulator WHERE username = 'alice'`).Scan(&unbilled)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if unbilled > 0 {
		t.Fatalf("accumulator should be drained, got %d", unbilled)
	}
	var usageCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM credit_transactions WHERE username = 'alice' AND transaction_type = 'usage'`).Scan(&usageCount); err != nil {
		t.Fatal(err)
	}
	if usageCount != 1 {
		t.Fatalf("expected one usage transaction, got %d", usageCount)
	}
}

func TestCreateCheckoutURL_ContainsSignedToken(t *testing.T) {
	withBillingSubscriptionEnv(t)
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	url, err := CreateCheckoutURL(cfg.Subscriptions, "subchk_url", subTestPlanID, "https://example.com/return")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(url, "/v1/start?token=") {
		t.Fatalf("unexpected checkout url: %s", url)
	}
}
