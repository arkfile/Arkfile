package billing

import (
	"testing"

	"github.com/84adam/Arkfile/models"
)

func createPaymentInvoicesTable(t *testing.T, db interface{ Exec(string, ...interface{}) (interface{}, error) }) {
	t.Helper()
	// use *sql.DB via openPaymentsTestDB return type
}

func TestSettlePaymentInvoice_CreditsThenMarksPaid(t *testing.T) {
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
		VALUES ('inv_settle1', 'alice', 250000000, 'pending', 'btcpay', 'prov_settle1')
	`); err != nil {
		t.Fatalf("seed invoice: %v", err)
	}

	invoice := &models.PaymentInvoice{
		InvoiceID:           "inv_settle1",
		Username:            "alice",
		AmountUSDMicrocents: 250000000,
		Status:              "pending",
		Provider:            "btcpay",
		ProviderInvoiceID:   "prov_settle1",
	}

	tx, err := SettlePaymentInvoice(db, invoice, "btcpay")
	if err != nil {
		t.Fatalf("SettlePaymentInvoice: %v", err)
	}
	if tx == nil || tx.TransactionType != models.TransactionTypePayment {
		t.Fatalf("expected payment credit transaction, got %#v", tx)
	}

	var status string
	if err := db.QueryRow(`SELECT status FROM payment_invoices WHERE invoice_id = 'inv_settle1'`).Scan(&status); err != nil {
		t.Fatalf("read invoice status: %v", err)
	}
	if status != "paid" {
		t.Errorf("invoice status = %q, want paid", status)
	}
}

func TestSettlePaymentInvoice_RepairPaidWithoutCredit(t *testing.T) {
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
		VALUES ('inv_orphan1', 'alice', 100000000, 'paid', 'btcpay', 'prov_orphan1')
	`); err != nil {
		t.Fatalf("seed invoice: %v", err)
	}

	invoice := &models.PaymentInvoice{
		InvoiceID:           "inv_orphan1",
		Username:            "alice",
		AmountUSDMicrocents: 100000000,
		Status:              "paid",
		Provider:            "btcpay",
		ProviderInvoiceID:   "prov_orphan1",
	}

	if _, err := SettlePaymentInvoice(db, invoice, "btcpay"); err != nil {
		t.Fatalf("SettlePaymentInvoice repair: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM credit_transactions WHERE transaction_id = 'prov_orphan1'`).Scan(&count); err != nil {
		t.Fatalf("count credit: %v", err)
	}
	if count != 1 {
		t.Errorf("credit rows = %d, want 1", count)
	}
}
