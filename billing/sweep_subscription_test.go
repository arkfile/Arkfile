package billing

import (
	"testing"
	"time"

	"github.com/arkfile/Arkfile/config"
)

func TestSweepAllUsers_SkipsSubscribedUser(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	seedSubscriptionUser(t, db, "alice", 2<<30)
	seedSubscriptionUser(t, db, "bob", 2<<30)
	seedActiveGiftSubscription(t, db, "alice")

	if _, err := db.Exec(`INSERT INTO user_credits (username, balance_usd_microcents) VALUES ('alice', 1000000), ('bob', 1000000)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO storage_usage_accumulator (username, unbilled_microcents, last_tick_at)
		VALUES ('alice', 5000, datetime('now')), ('bob', 7000, datetime('now'))`); err != nil {
		t.Fatal(err)
	}

	rate, err := ResolveRate(db, config.BillingConfig{CustomerPriceUSDPerTBPerMonth: "10.00"})
	if err != nil {
		t.Fatal(err)
	}

	summary, err := SweepAllUsers(db, rate, time.Now().UTC())
	if err != nil {
		t.Fatalf("SweepAllUsers: %v", err)
	}
	if summary.UsersSettled != 1 {
		t.Fatalf("expected 1 settled user, got %d", summary.UsersSettled)
	}
	if summary.TotalDrainedMicrocents != 7000 {
		t.Fatalf("expected 7000 drained microcents, got %d", summary.TotalDrainedMicrocents)
	}

	var aliceUnbilled int64
	if err := db.QueryRow(`SELECT unbilled_microcents FROM storage_usage_accumulator WHERE username = 'alice'`).Scan(&aliceUnbilled); err != nil {
		t.Fatal(err)
	}
	if aliceUnbilled != 5000 {
		t.Fatalf("alice accumulator should remain at 5000, got %d", aliceUnbilled)
	}

	var bobUnbilled int64
	err = db.QueryRow(`SELECT unbilled_microcents FROM storage_usage_accumulator WHERE username = 'bob'`).Scan(&bobUnbilled)
	if err == nil && bobUnbilled > 0 {
		t.Fatalf("bob accumulator should be drained, got %d", bobUnbilled)
	}
}
