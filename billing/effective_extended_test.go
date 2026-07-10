package billing

import (
	"testing"
	"time"
)

func TestEffectiveBillingMode(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "free-user", 0)
	seedSubscriptionUser(t, db, "payg-user", 2<<30)
	seedSubscriptionUser(t, db, "sub-user", 2<<30)
	seedActiveGiftSubscription(t, db, "sub-user")

	if got := EffectiveBillingMode(db, "free-user"); got != BillingModeFree {
		t.Fatalf("free-user mode = %q, want free", got)
	}
	if got := EffectiveBillingMode(db, "payg-user"); got != BillingModePayg {
		t.Fatalf("payg-user mode = %q, want payg", got)
	}
	if got := EffectiveBillingMode(db, "sub-user"); got != BillingModeSubscribed {
		t.Fatalf("sub-user mode = %q, want subscribed", got)
	}
}

func TestShouldMeterAndTopUp(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 2<<30)
	seedSubscriptionUser(t, db, "bob", 2<<30)
	seedActiveGiftSubscription(t, db, "alice")

	if ShouldMeter(db, "alice") {
		t.Fatal("subscribed user should not be metered")
	}
	if !ShouldMeter(db, "bob") {
		t.Fatal("payg user should be metered")
	}
	if ShouldAllowTopUp(db, "alice") {
		t.Fatal("subscribed user should not allow top-up")
	}
	if !ShouldAllowTopUp(db, "bob") {
		t.Fatal("payg user should allow top-up")
	}
}

func TestShouldApplyPaygUploadCap(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	seedSubscriptionUser(t, db, "bob", 0)
	seedActiveGiftSubscription(t, db, "alice")

	if ShouldApplyPaygUploadCap(db, "alice") {
		t.Fatal("subscribed user should skip PAYG upload cap")
	}
	if !ShouldApplyPaygUploadCap(db, "bob") {
		t.Fatal("non-subscribed user should apply PAYG upload cap")
	}
}

func TestEffectiveFreeBaselineWithPlan(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	seedActiveGiftSubscription(t, db, "alice")

	baseline := EffectiveFreeBaseline(db, "alice")
	if baseline != subTestPlanGiB {
		t.Fatalf("effective free baseline = %d, want plan bytes %d", baseline, subTestPlanGiB)
	}
}

func TestSubscriptionUploadBlockedIntegration(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 0)
	checkoutID := "subchk_upload"
	entRef := "sub_upload"
	seedPendingCheckout(t, db, checkoutID, "alice")
	if err := ProcessSubscriptionBridgeCallback(db, testSubscriptionBridgePayload("subscription.activated", newEventID(), checkoutID, entRef, "active")); err != nil {
		t.Fatal(err)
	}
	if err := ProcessSubscriptionBridgeCallback(db, testSubscriptionBridgePayload("subscription.past_due", newEventID(), checkoutID, entRef, "past_due")); err != nil {
		t.Fatal(err)
	}

	blocked, err := SubscriptionUploadBlocked(db, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Fatal("past_due within grace should not block uploads yet")
	}

	old := time.Now().UTC().Add(-8 * 24 * time.Hour)
	if _, err := db.Exec(`UPDATE user_subscriptions SET past_due_since = ? WHERE subscription_ref = ?`, old, entRef); err != nil {
		t.Fatal(err)
	}
	blocked, err = SubscriptionUploadBlocked(db, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("past_due beyond grace should block uploads")
	}
}
