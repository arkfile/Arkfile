package billing

import (
	"database/sql"
	"testing"

	"github.com/arkfile/Arkfile/models"
)

// createPaymentInvoicesTable creates payment_invoices with the current
// unified_schema.sql definition.
func createPaymentInvoicesTable(t *testing.T, db *sql.DB) {
	t.Helper()
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
			CHECK(status IN ('creating', 'pending', 'confirming', 'paid', 'expired', 'failed'))
		);
	`); err != nil {
		t.Fatalf("create payment_invoices: %v", err)
	}
}

func seedBillingInvoice(t *testing.T, db *sql.DB, invoiceID, status, providerID string, amount int64) *models.PaymentInvoice {
	t.Helper()
	invoice := &models.PaymentInvoice{
		InvoiceID:           invoiceID,
		Username:            "alice",
		AmountUSDMicrocents: amount,
		Status:              status,
		Provider:            "testprov",
		ProviderInvoiceID:   providerID,
	}
	if err := models.CreatePaymentInvoice(db, invoice); err != nil {
		t.Fatalf("seed invoice %s: %v", invoiceID, err)
	}
	return invoice
}

func invoiceStatus(t *testing.T, db *sql.DB, invoiceID string) string {
	t.Helper()
	var status string
	if err := db.QueryRow(`SELECT status FROM payment_invoices WHERE invoice_id = ?`, invoiceID).Scan(&status); err != nil {
		t.Fatalf("read invoice status: %v", err)
	}
	return status
}

func creditRowCount(t *testing.T, db *sql.DB, providerID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM credit_transactions WHERE transaction_id = ?`, providerID).Scan(&count); err != nil {
		t.Fatalf("count credit rows: %v", err)
	}
	return count
}

func TestSettlePaymentInvoice_CreditsThenMarksPaid(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)
	invoice := seedBillingInvoice(t, db, "inv_settle1", models.PaymentStatusPending, "prov_settle1", 250_000_000)

	tx, err := SettlePaymentInvoice(db, invoice, "testprov")
	if err != nil {
		t.Fatalf("SettlePaymentInvoice: %v", err)
	}
	if tx == nil || tx.TransactionType != models.TransactionTypePayment {
		t.Fatalf("expected payment credit transaction, got %#v", tx)
	}
	if got := invoiceStatus(t, db, "inv_settle1"); got != models.PaymentStatusPaid {
		t.Errorf("invoice status = %q, want paid", got)
	}
}

func TestSettlePaymentInvoice_SettlesConfirmingAndExpired(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)

	for _, status := range []string{models.PaymentStatusConfirming, models.PaymentStatusExpired, models.PaymentStatusFailed} {
		invoice := seedBillingInvoice(t, db, "inv_"+status, status, "prov_"+status, 100_000_000)
		if _, err := SettlePaymentInvoice(db, invoice, "testprov"); err != nil {
			t.Fatalf("SettlePaymentInvoice from %s: %v", status, err)
		}
		if got := invoiceStatus(t, db, invoice.InvoiceID); got != models.PaymentStatusPaid {
			t.Errorf("from %s: status = %q, want paid", status, got)
		}
		if got := creditRowCount(t, db, invoice.ProviderInvoiceID); got != 1 {
			t.Errorf("from %s: credit rows = %d, want 1", status, got)
		}
	}
}

func TestSettlePaymentInvoice_RejectsCreating(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)
	invoice := seedBillingInvoice(t, db, "inv_creating", models.PaymentStatusCreating, "prov_creating", 100_000_000)

	if _, err := SettlePaymentInvoice(db, invoice, "testprov"); err == nil {
		t.Fatal("expected error settling an invoice still in creating status")
	}
	if got := creditRowCount(t, db, "prov_creating"); got != 0 {
		t.Errorf("credit rows = %d, want 0", got)
	}
}

func TestSettlePaymentInvoice_RepairPaidWithoutCredit(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)
	invoice := seedBillingInvoice(t, db, "inv_orphan1", models.PaymentStatusPaid, "prov_orphan1", 100_000_000)

	if _, err := SettlePaymentInvoice(db, invoice, "testprov"); err != nil {
		t.Fatalf("SettlePaymentInvoice repair: %v", err)
	}
	if got := creditRowCount(t, db, "prov_orphan1"); got != 1 {
		t.Errorf("credit rows = %d, want 1", got)
	}
}
