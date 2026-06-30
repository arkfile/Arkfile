package billing

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/models"
)

func TestProcessEntitlementCallback_ActivatedCreatesSubscription(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 2<<30)
	checkoutID := "subchk_activate"
	entRef := "ent_activate"
	seedPendingCheckout(t, db, checkoutID, "alice")

	eventID := newEventID()
	payload := testEntitlementPayload("entitlement.activated", eventID, checkoutID, entRef, "active")
	if err := ProcessEntitlementCallback(db, payload); err != nil {
		t.Fatalf("ProcessEntitlementCallback: %v", err)
	}

	sub, err := models.GetUserSubscriptionByEntitlementRef(db, entRef)
	if err != nil {
		t.Fatalf("GetUserSubscriptionByEntitlementRef: %v", err)
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

func TestProcessEntitlementCallback_Idempotent(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_idem"
	entRef := "ent_idem"
	seedPendingCheckout(t, db, checkoutID, "alice")

	eventID := newEventID()
	payload := testEntitlementPayload("entitlement.activated", eventID, checkoutID, entRef, "active")
	if err := ProcessEntitlementCallback(db, payload); err != nil {
		t.Fatal(err)
	}
	if err := ProcessEntitlementCallback(db, payload); err != nil {
		t.Fatalf("duplicate callback should be no-op: %v", err)
	}
	if countSubscriptionEvents(t, db, eventID) != 1 {
		t.Fatal("idempotent replay must not insert duplicate event")
	}
}

func TestProcessEntitlementCallback_PastDueSetsTimestamp(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_pastdue"
	entRef := "ent_pastdue"
	seedPendingCheckout(t, db, checkoutID, "alice")

	activate := testEntitlementPayload("entitlement.activated", newEventID(), checkoutID, entRef, "active")
	if err := ProcessEntitlementCallback(db, activate); err != nil {
		t.Fatal(err)
	}

	pastDue := testEntitlementPayload("entitlement.past_due", newEventID(), checkoutID, entRef, "past_due")
	if err := ProcessEntitlementCallback(db, pastDue); err != nil {
		t.Fatal(err)
	}

	sub, err := models.GetUserSubscriptionByEntitlementRef(db, entRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "past_due" || sub.PastDueSince == nil {
		t.Fatalf("expected past_due with timestamp, got %+v", sub)
	}
}

func TestProcessEntitlementCallback_RenewedClearsPastDue(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_renew"
	entRef := "ent_renew"
	seedPendingCheckout(t, db, checkoutID, "alice")

	if err := ProcessEntitlementCallback(db, testEntitlementPayload("entitlement.activated", newEventID(), checkoutID, entRef, "active")); err != nil {
		t.Fatal(err)
	}
	if err := ProcessEntitlementCallback(db, testEntitlementPayload("entitlement.past_due", newEventID(), checkoutID, entRef, "past_due")); err != nil {
		t.Fatal(err)
	}
	if err := ProcessEntitlementCallback(db, testEntitlementPayload("entitlement.renewed", newEventID(), checkoutID, entRef, "active")); err != nil {
		t.Fatal(err)
	}

	sub, err := models.GetUserSubscriptionByEntitlementRef(db, entRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "active" || sub.PastDueSince != nil {
		t.Fatalf("renewed subscription should clear past_due, got %+v", sub)
	}
}

func TestProcessEntitlementCallback_CanceledAndExpired(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_cancel"
	entRef := "ent_cancel"
	seedPendingCheckout(t, db, checkoutID, "alice")

	if err := ProcessEntitlementCallback(db, testEntitlementPayload("entitlement.activated", newEventID(), checkoutID, entRef, "active")); err != nil {
		t.Fatal(err)
	}
	if err := ProcessEntitlementCallback(db, testEntitlementPayload("entitlement.canceled", newEventID(), checkoutID, entRef, "canceled")); err != nil {
		t.Fatal(err)
	}
	sub, err := models.GetUserSubscriptionByEntitlementRef(db, entRef)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "canceled" || sub.CanceledAt == nil {
		t.Fatalf("expected canceled with timestamp, got %+v", sub)
	}

	if err := ProcessEntitlementCallback(db, testEntitlementPayload("entitlement.expired", newEventID(), checkoutID, entRef, "expired")); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM user_subscriptions WHERE entitlement_ref = ?`, entRef).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "expired" {
		t.Fatalf("expected expired status, got %q", status)
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
	entRef := "ent_bridge"
	seedPendingCheckout(t, db, checkoutID, "alice")
	if err := ProcessEntitlementCallback(db, testEntitlementPayload("entitlement.activated", newEventID(), checkoutID, entRef, "active")); err != nil {
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
