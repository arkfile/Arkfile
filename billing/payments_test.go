package billing

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func openPaymentsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}
	schema := `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			username_folded TEXT UNIQUE NOT NULL,
			total_storage_bytes BIGINT NOT NULL DEFAULT 0,
			storage_limit_bytes BIGINT NOT NULL DEFAULT 1181116006,
			is_approved BOOLEAN NOT NULL DEFAULT 1,
			is_admin BOOLEAN NOT NULL DEFAULT 0
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
			transaction_type TEXT NOT NULL CHECK (transaction_type IN ('usage', 'gift', 'adjustment', 'payment')),
			reason TEXT,
			admin_username TEXT,
			metadata TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (username, username_folded) VALUES ('alice', 'alice')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return db
}

func TestProcessPayment_CreditsBalanceAndLedger(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()

	if _, err := db.Exec(`INSERT INTO user_credits (username, balance_usd_microcents) VALUES ('alice', -5000)`); err != nil {
		t.Fatalf("seed balance: %v", err)
	}

	tx, err := ProcessPayment(db, "alice", 1_000_000_000, "btcpay_prov_abc", "btcpay")
	if err != nil {
		t.Fatalf("ProcessPayment: %v", err)
	}
	if tx.AmountUSDMicrocents != 1_000_000_000 {
		t.Errorf("amount = %d, want 1000000000", tx.AmountUSDMicrocents)
	}
	if tx.BalanceAfterUSDMicrocents != 999_995_000 {
		t.Errorf("balance_after = %d, want 999995000", tx.BalanceAfterUSDMicrocents)
	}
	if tx.Reason == nil || *tx.Reason != "Payment top-up via btcpay" {
		t.Errorf("reason = %v, want Payment top-up via btcpay", tx.Reason)
	}
	if tx.TransactionType != "payment" {
		t.Errorf("transaction_type = %q, want payment", tx.TransactionType)
	}

	var txType string
	if err := db.QueryRow(`SELECT transaction_type FROM credit_transactions WHERE transaction_id = 'btcpay_prov_abc'`).Scan(&txType); err != nil {
		t.Fatalf("read transaction type: %v", err)
	}
	if txType != "payment" {
		t.Errorf("stored transaction_type = %q, want payment", txType)
	}

	var balance int64
	if err := db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = 'alice'`).Scan(&balance); err != nil {
		t.Fatalf("read balance: %v", err)
	}
	if balance != 999_995_000 {
		t.Errorf("stored balance = %d, want 999995000", balance)
	}

	var reason string
	if err := db.QueryRow(`SELECT reason FROM credit_transactions WHERE transaction_id = 'btcpay_prov_abc'`).Scan(&reason); err != nil {
		t.Fatalf("read transaction: %v", err)
	}
	if reason != "Payment top-up via btcpay" {
		t.Errorf("stored reason = %q", reason)
	}
}

func TestProcessPayment_CreatesUserCreditsWhenMissing(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()

	tx, err := ProcessPayment(db, "alice", 500_000_000, "btcpay_prov_new", "btcpay")
	if err != nil {
		t.Fatalf("ProcessPayment: %v", err)
	}
	if tx.BalanceAfterUSDMicrocents != 500_000_000 {
		t.Errorf("balance_after = %d, want 500000000", tx.BalanceAfterUSDMicrocents)
	}
}

func TestProcessPayment_RejectsDuplicateProviderTxID(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()

	if _, err := ProcessPayment(db, "alice", 100_000_000, "btcpay_dup", "btcpay"); err != nil {
		t.Fatalf("first ProcessPayment: %v", err)
	}
	_, err := ProcessPayment(db, "alice", 100_000_000, "btcpay_dup", "btcpay")
	if err == nil {
		t.Fatal("expected duplicate transaction_id error")
	}
	if !strings.Contains(err.Error(), "duplicate transaction_id") {
		t.Errorf("error = %q, want duplicate transaction_id mention", err)
	}
}

func TestProcessPayment_ValidationErrors(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()

	cases := []struct {
		name       string
		username   string
		amount     int64
		providerID string
		wantSubstr string
	}{
		{"empty username", "", 100, "prov", "empty target username"},
		{"zero amount", "alice", 0, "prov", "amount must be positive"},
		{"negative amount", "alice", -1, "prov", "amount must be positive"},
		{"empty provider id", "alice", 100, "", "provider transaction ID is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ProcessPayment(db, tc.username, tc.amount, tc.providerID, "btcpay")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q, want substring %q", err, tc.wantSubstr)
			}
		})
	}
}
