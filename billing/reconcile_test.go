package billing

import (
	"testing"

	"github.com/84adam/Arkfile/models"
)

func TestReconcilePaidInvoices_RepairsOrphans(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()

	if _, err := db.Exec(`
		CREATE TABLE payment_invoices (
			invoice_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			amount_usd_microcents BIGINT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			provider TEXT NOT NULL,
			provider_invoice_id TEXT UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(username) REFERENCES users(username) ON DELETE RESTRICT,
			CHECK(status IN ('pending', 'paid', 'expired', 'failed')),
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
