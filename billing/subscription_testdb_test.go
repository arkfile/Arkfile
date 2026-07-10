package billing

import (
	"database/sql"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/subbridge"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

const (
	subTestSecret  = "test_subscription_bridge_pairing_root"
	subTestPlanID  = "plan_dev_250gb"
	subTestPlanGiB = int64(250) << 30
)

func withBillingSubscriptionEnv(t *testing.T) {
	t.Helper()
	logging.InitFallbackConsoleLogging()
	config.ResetConfigForTest()
	t.Setenv("JWT_SECRET", "test-jwt-secret")
	t.Setenv("STORAGE_PROVIDER_1", "generic-s3")
	t.Setenv("STORAGE_1_ENDPOINT", "http://localhost:9332")
	t.Setenv("STORAGE_1_ACCESS_KEY", "test")
	t.Setenv("STORAGE_1_SECRET_KEY", "test")
	t.Setenv("STORAGE_1_BUCKET", "test-bucket")
	t.Setenv("ARKFILE_SUBSCRIPTIONS_ENABLED", "true")
	t.Setenv("ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED", "true")
	t.Setenv("ARKFILE_SUBSCRIPTION_BRIDGE_URL", "http://127.0.0.1:8081")
	t.Setenv("ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT", subTestSecret)
	t.Setenv("ARKFILE_BILLING_ENABLED", "true")
	t.Setenv("ARKFILE_BILLING_PAYG_ENABLED", "true")
	t.Setenv("ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH", "10.00")
	if _, err := config.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
}

func openFullBillingSubscriptionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:arkfile-billing-sub-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		username_folded TEXT,
		storage_limit_bytes BIGINT NOT NULL DEFAULT 1073741824,
		total_storage_bytes BIGINT NOT NULL DEFAULT 0,
		is_approved BOOLEAN NOT NULL DEFAULT 1,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		approved_by TEXT,
		approved_at DATETIME,
		deleted_at DATETIME
	);
	CREATE TABLE user_credits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		balance_usd_microcents BIGINT NOT NULL DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
	);
	CREATE TABLE credit_transactions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		transaction_id TEXT UNIQUE DEFAULT NULL,
		username TEXT NOT NULL,
		amount_usd_microcents BIGINT NOT NULL,
		balance_after_usd_microcents BIGINT NOT NULL,
		transaction_type TEXT NOT NULL,
		reason TEXT,
		admin_username TEXT,
		metadata TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
	);
	CREATE TABLE storage_usage_accumulator (
		username TEXT PRIMARY KEY,
		unbilled_microcents BIGINT NOT NULL DEFAULT 0,
		last_tick_at DATETIME,
		last_billed_at DATETIME,
		FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
	);
	CREATE TABLE billing_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_by TEXT
	);
	CREATE TABLE subscription_plans (
		plan_id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		price_usd_cents INTEGER NOT NULL,
		storage_limit_bytes BIGINT NOT NULL,
		sort_order INTEGER NOT NULL DEFAULT 0,
		is_active INTEGER NOT NULL DEFAULT 1,
		is_public INTEGER NOT NULL DEFAULT 1,
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
		last_event_at DATETIME,
		current_period_start DATETIME NOT NULL,
		current_period_end DATETIME NOT NULL,
		cancel_at_period_end BOOLEAN NOT NULL DEFAULT 0,
		canceled_at DATETIME,
		past_due_since DATETIME,
		gift_note TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE subscription_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_id TEXT UNIQUE NOT NULL,
		event_type TEXT NOT NULL,
		subscription_ref TEXT,
		checkout_id TEXT,
		username TEXT,
		plan_id TEXT,
		state_version BIGINT NOT NULL DEFAULT 0,
		occurred_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'applied',
		admin_username TEXT,
		payload_hash TEXT NOT NULL,
		processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE UNIQUE INDEX idx_user_subscriptions_one_current
		ON user_subscriptions(username) WHERE is_current = 1;
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO billing_settings (key, value) VALUES ('customer_price_usd_per_tb_per_month', '10.00')`); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedSubscriptionUser(t *testing.T, db *sql.DB, username string, totalStorage int64) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO users (username, username_folded, total_storage_bytes, storage_limit_bytes, is_approved)
		 VALUES (?, ?, ?, 1073741824, 1)`,
		username, username, totalStorage,
	); err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
}

func seedSubscriptionPlan(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO subscription_plans (plan_id, name, price_usd_cents, storage_limit_bytes, is_active, is_public)
		 VALUES (?, '250 GB Dev', 500, ?, 1, 1)`,
		subTestPlanID, subTestPlanGiB,
	); err != nil {
		t.Fatal(err)
	}
}

func seedPendingCheckout(t *testing.T, db *sql.DB, checkoutID, username string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status) VALUES (?, ?, ?, 'pending')`,
		checkoutID, username, subTestPlanID,
	); err != nil {
		t.Fatal(err)
	}
}

func seedActiveGiftSubscription(t *testing.T, db *sql.DB, username string) {
	t.Helper()
	checkoutID := "subchk_gift_" + username
	entRef := "sub_gift_" + username
	seedPendingCheckout(t, db, checkoutID, username)
	if _, err := db.Exec(
		`UPDATE subscription_checkouts SET status = 'completed', subscription_ref = ? WHERE checkout_id = ?`,
		entRef, checkoutID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO user_subscriptions
		  (username, plan_id, checkout_id, subscription_ref, status, source, current_period_start, current_period_end)
		VALUES (?, ?, ?, ?, 'active', 'gift', datetime('now'), datetime('now', '+30 days'))`,
		username, subTestPlanID, checkoutID, entRef,
	); err != nil {
		t.Fatal(err)
	}
}

func testSubscriptionBridgePayload(eventType, eventID, checkoutID, entRef, status string) *subbridge.CallbackPayload {
	now := time.Now().UTC()
	return &subbridge.CallbackPayload{
		Protocol:           "subscription-bridge",
		Version:            1,
		EventID:            eventID,
		EventType:          eventType,
		CheckoutID:         checkoutID,
		SubscriptionRef:    entRef,
		PlanID:             subTestPlanID,
		StateVersion:       1,
		Status:             status,
		CurrentPeriodStart: now.Format(time.RFC3339),
		CurrentPeriodEnd:   now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		OccurredAt:         now.Format(time.RFC3339),
	}
}

func countSubscriptionEvents(t *testing.T, db *sql.DB, eventID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM subscription_events WHERE event_id = ?`, eventID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func newEventID() string {
	return "evt_" + uuid.New().String()
}
