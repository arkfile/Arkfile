package billing

import (
	"database/sql"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/models"
)

func TestSubscriptionMeterPaused(t *testing.T) {
	now := time.Now().UTC()
	sub := &models.UserSubscription{Status: "active"}
	if !SubscriptionMeterPaused(sub) {
		t.Fatal("active should pause meter")
	}
	sub.Status = "canceled"
	sub.CurrentPeriodEnd = now.Add(24 * time.Hour)
	if !SubscriptionMeterPaused(sub) {
		t.Fatal("canceled in period should pause meter")
	}
	sub.CurrentPeriodEnd = now.Add(-time.Hour)
	if SubscriptionMeterPaused(sub) {
		t.Fatal("canceled after period should not pause meter")
	}
}

func TestSubscriptionBlocksTopUp(t *testing.T) {
	sub := &models.UserSubscription{Status: "active"}
	if !SubscriptionBlocksTopUp(sub) {
		t.Fatal("active should block top-up")
	}
	sub.Status = "expired"
	if SubscriptionBlocksTopUp(sub) {
		t.Fatal("expired should allow top-up")
	}
}

func TestSubscriptionBlocksUploadPastDueGrace(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour)
	sub := &models.UserSubscription{
		Status:       "past_due",
		PastDueSince: &old,
	}
	if !SubscriptionBlocksUpload(sub) {
		t.Fatal("past_due beyond grace should block upload")
	}
	recent := now.Add(-time.Hour)
	sub.PastDueSince = &recent
	if SubscriptionBlocksUpload(sub) {
		t.Fatal("past_due within grace should not block upload")
	}
}

func TestEffectiveStorageLimitWithPlan(t *testing.T) {
	db := openSubscriptionTestDB(t)
	defer db.Close()

	_, err := db.Exec(`INSERT INTO users (username, username_folded, storage_limit_bytes, is_approved, is_admin)
		VALUES ('alice', 'alice', 1073741824, 1, 0)`)
	if err != nil {
		t.Fatal(err)
	}
	planBytes := int64(250) << 30
	_, err = db.Exec(`INSERT INTO subscription_plans (plan_id, name, price_usd_cents, storage_limit_bytes)
		VALUES ('plan_test', '250 GB', 500, ?)`, planBytes)
	if err != nil {
		t.Fatal(err)
	}
	checkoutID := "subchk_test1"
	entRef := "sub_test1"
	_, err = db.Exec(`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status, subscription_ref)
		VALUES (?, 'alice', 'plan_test', 'completed', ?)`, checkoutID, entRef)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO user_subscriptions
		(username, plan_id, checkout_id, subscription_ref, status, source, current_period_start, current_period_end)
		VALUES ('alice', 'plan_test', ?, ?, 'active', 'gift', datetime('now'), datetime('now', '+30 days'))`,
		checkoutID, entRef)
	if err != nil {
		t.Fatal(err)
	}

	limit, err := EffectiveStorageLimit(db, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if limit != planBytes {
		t.Fatalf("expected plan limit %d, got %d", planBytes, limit)
	}
}

func openSubscriptionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		username_folded TEXT,
		storage_limit_bytes BIGINT NOT NULL,
		total_storage_bytes BIGINT NOT NULL DEFAULT 0,
		is_approved BOOLEAN NOT NULL DEFAULT 1,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		approved_by TEXT,
		approved_at DATETIME,
		deleted_at DATETIME
	);
	CREATE TABLE subscription_plans (
		plan_id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		price_usd_cents INTEGER NOT NULL,
		storage_limit_bytes BIGINT NOT NULL,
		sort_order INTEGER NOT NULL DEFAULT 0,
		is_active BOOLEAN NOT NULL DEFAULT 1,
		is_public BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_by TEXT
	);
	CREATE TABLE subscription_checkouts (
		checkout_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		plan_id TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		subscription_ref TEXT UNIQUE,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE user_subscriptions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		plan_id TEXT NOT NULL,
		checkout_id TEXT NOT NULL,
		subscription_ref TEXT UNIQUE NOT NULL,
		is_current BOOLEAN NOT NULL DEFAULT 1,
		status TEXT NOT NULL,
		source TEXT NOT NULL,
		state_version BIGINT NOT NULL DEFAULT 0,
		state_changed_at DATETIME,
		current_period_start DATETIME NOT NULL,
		current_period_end DATETIME NOT NULL,
		cancel_at_period_end BOOLEAN NOT NULL DEFAULT 0,
		canceled_at DATETIME,
		past_due_since DATETIME,
		gift_note TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return db
}
