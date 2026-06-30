package billing

import (
	"testing"
	"time"

	"github.com/arkfile/Arkfile/config"
)

func TestTickAllActiveUsers_SkipsSubscribedUser(t *testing.T) {
	withBillingSubscriptionEnv(t)
	db := openFullBillingSubscriptionTestDB(t)
	defer db.Close()

	seedSubscriptionPlan(t, db)
	freeBaseline := int64(1073741824)
	seedSubscriptionUser(t, db, "alice", freeBaseline+(10<<30))
	seedSubscriptionUser(t, db, "bob", freeBaseline+(10<<30))
	seedActiveGiftSubscription(t, db, "alice")

	rate, err := ResolveRate(db, config.BillingConfig{CustomerPriceUSDPerTBPerMonth: "10.00"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	count, errCount, err := TickAllActiveUsers(db, rate, time.Now().UTC(), cfg.Billing)
	if err != nil {
		t.Fatalf("TickAllActiveUsers: %v", err)
	}
	if errCount != 0 {
		t.Fatalf("unexpected tick errors: %d", errCount)
	}
	if count != 1 {
		t.Fatalf("expected 1 ticked user (bob only), got %d", count)
	}

	var aliceUnbilled int64
	err = db.QueryRow(`SELECT unbilled_microcents FROM storage_usage_accumulator WHERE username = 'alice'`).Scan(&aliceUnbilled)
	if err == nil && aliceUnbilled > 0 {
		t.Fatalf("alice accumulator should be empty, got %d", aliceUnbilled)
	}

	var bobUnbilled int64
	if err := db.QueryRow(`SELECT unbilled_microcents FROM storage_usage_accumulator WHERE username = 'bob'`).Scan(&bobUnbilled); err != nil {
		t.Fatalf("bob should have accumulator row: %v", err)
	}
	if bobUnbilled <= 0 {
		t.Fatalf("bob should have unbilled usage, got %d", bobUnbilled)
	}
}
