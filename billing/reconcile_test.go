package billing

import (
	"context"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/models"
)

type reconcileStatusProvider map[string]string

func (p reconcileStatusProvider) GetInvoiceStatus(_ context.Context, providerID string) (string, error) {
	return p[providerID], nil
}

func TestReconcilePaidInvoices_RepairsOrphans(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()

	if _, err := db.Exec(`
		CREATE TABLE payment_invoices (
			invoice_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			amount_usd_microcents BIGINT NOT NULL,
			status TEXT NOT NULL DEFAULT 'creating',
			provider TEXT NOT NULL,
			provider_invoice_id TEXT UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(username) REFERENCES users(username) ON DELETE RESTRICT,
			CHECK(status IN ('creating', 'pending', 'paid', 'expired', 'failed')),
			CHECK(provider IN ('btcpay'))
		);
	`); err != nil {
		t.Fatalf("create payment_invoices: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO payment_invoices
		  (invoice_id, username, amount_usd_microcents, status, provider, provider_invoice_id)
		VALUES ('inv_rec1', 'alice', 50000000, 'paid', 'btcpay', 'prov_rec1')
	`); err != nil {
		t.Fatalf("seed invoice: %v", err)
	}

	repaired, err := ReconcilePaidInvoices(db, "btcpay")
	if err != nil {
		t.Fatalf("ReconcilePaidInvoices: %v", err)
	}
	if repaired != 1 {
		t.Errorf("repaired = %d, want 1", repaired)
	}

	var txType string
	if err := db.QueryRow(`SELECT transaction_type FROM credit_transactions WHERE transaction_id = 'prov_rec1'`).Scan(&txType); err != nil {
		t.Fatalf("read credit: %v", err)
	}
	if txType != models.TransactionTypePayment {
		t.Errorf("transaction_type = %q, want payment", txType)
	}
}

func TestReconcilePendingInvoices_SettlesOnce(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE payment_invoices (
			invoice_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			amount_usd_microcents BIGINT NOT NULL,
			status TEXT NOT NULL,
			provider TEXT NOT NULL,
			provider_invoice_id TEXT UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO payment_invoices
		  (invoice_id, username, amount_usd_microcents, status, provider, provider_invoice_id)
		VALUES ('inv_pending', 'alice', 123000000, 'pending', 'btcpay', 'prov_pending');
	`); err != nil {
		t.Fatalf("create pending invoice: %v", err)
	}
	provider := reconcileStatusProvider{"prov_pending": "Settled"}
	report, err := ReconcilePendingInvoices(context.Background(), db, provider, "btcpay", 10, time.Second)
	if err != nil {
		t.Fatalf("ReconcilePendingInvoices: %v", err)
	}
	if report.Settled != 1 {
		t.Fatalf("settled = %d, want 1", report.Settled)
	}
	report, err = ReconcilePendingInvoices(context.Background(), db, provider, "btcpay", 10, time.Second)
	if err != nil {
		t.Fatalf("replay reconciliation: %v", err)
	}
	if report.Settled != 0 {
		t.Fatalf("replay settled = %d, want 0", report.Settled)
	}
	var balance, credits int64
	if err := db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = 'alice'`).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM credit_transactions WHERE transaction_id = 'prov_pending'`).Scan(&credits); err != nil {
		t.Fatal(err)
	}
	if balance != 123_000_000 || credits != 1 {
		t.Fatalf("balance=%d credits=%d, want 123000000 and 1", balance, credits)
	}
}
