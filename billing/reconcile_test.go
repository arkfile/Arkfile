package billing

import (
	"context"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/models"
)

type reconcileStatusProvider map[string]string

func (p reconcileStatusProvider) GetInvoiceStatus(_ context.Context, invoice *models.PaymentInvoice) (string, error) {
	return p[invoice.ProviderInvoiceID], nil
}

func TestReconcilePaidInvoices_RepairsOrphans(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)
	seedBillingInvoice(t, db, "inv_rec1", models.PaymentStatusPaid, "prov_rec1", 50_000_000)

	repaired, err := ReconcilePaidInvoices(db)
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
	createPaymentInvoicesTable(t, db)
	seedBillingInvoice(t, db, "inv_pending", models.PaymentStatusPending, "prov_pending", 123_000_000)

	provider := reconcileStatusProvider{"prov_pending": models.PaymentStatusPaid}
	report, err := ReconcilePendingInvoices(context.Background(), db, provider, "testprov", 10, time.Second)
	if err != nil {
		t.Fatalf("ReconcilePendingInvoices: %v", err)
	}
	if report.Settled != 1 {
		t.Fatalf("settled = %d, want 1", report.Settled)
	}
	report, err = ReconcilePendingInvoices(context.Background(), db, provider, "testprov", 10, time.Second)
	if err != nil {
		t.Fatalf("replay reconciliation: %v", err)
	}
	if report.Settled != 0 {
		t.Fatalf("replay settled = %d, want 0", report.Settled)
	}
	var balance int64
	if err := db.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = 'alice'`).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != 123_000_000 || creditRowCount(t, db, "prov_pending") != 1 {
		t.Fatalf("balance=%d credits=%d, want 123000000 and 1", balance, creditRowCount(t, db, "prov_pending"))
	}
}

func TestReconcilePendingInvoices_ConfirmingThenPaid(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)
	seedBillingInvoice(t, db, "inv_conf", models.PaymentStatusPending, "prov_conf", 500_000_000)

	provider := reconcileStatusProvider{"prov_conf": models.PaymentStatusConfirming}
	report, err := ReconcilePendingInvoices(context.Background(), db, provider, "testprov", 10, time.Second)
	if err != nil {
		t.Fatalf("reconcile confirming: %v", err)
	}
	if report.Updated != 1 || report.Settled != 0 {
		t.Fatalf("report = %+v, want updated=1 settled=0", report)
	}
	if got := invoiceStatus(t, db, "inv_conf"); got != models.PaymentStatusConfirming {
		t.Fatalf("status = %q, want confirming", got)
	}
	if got := creditRowCount(t, db, "prov_conf"); got != 0 {
		t.Fatalf("credit rows while confirming = %d, want 0", got)
	}

	provider["prov_conf"] = models.PaymentStatusPaid
	report, err = ReconcilePendingInvoices(context.Background(), db, provider, "testprov", 10, time.Second)
	if err != nil {
		t.Fatalf("reconcile paid: %v", err)
	}
	if report.Settled != 1 {
		t.Fatalf("report = %+v, want settled=1", report)
	}
	if got := creditRowCount(t, db, "prov_conf"); got != 1 {
		t.Fatalf("credit rows after paid = %d, want 1", got)
	}
}

func TestApplyProviderInvoiceStatus_NeverMovesBackward(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)

	confirming := seedBillingInvoice(t, db, "inv_back1", models.PaymentStatusConfirming, "prov_back1", 100_000_000)
	for _, status := range []string{models.PaymentStatusPending, models.PaymentStatusExpired} {
		got, err := ApplyProviderInvoiceStatus(db, confirming, status, "testprov")
		if err != nil {
			t.Fatalf("apply %s to confirming: %v", status, err)
		}
		if got != models.PaymentStatusConfirming {
			t.Errorf("apply %s to confirming: status = %q, want confirming", status, got)
		}
	}

	paid := seedBillingInvoice(t, db, "inv_back2", models.PaymentStatusPending, "prov_back2", 100_000_000)
	if _, err := ApplyProviderInvoiceStatus(db, paid, models.PaymentStatusPaid, "testprov"); err != nil {
		t.Fatalf("apply paid: %v", err)
	}
	for _, status := range []string{models.PaymentStatusPending, models.PaymentStatusConfirming, models.PaymentStatusExpired, models.PaymentStatusFailed} {
		got, err := ApplyProviderInvoiceStatus(db, paid, status, "testprov")
		if err != nil {
			t.Fatalf("apply %s to paid: %v", status, err)
		}
		if got != models.PaymentStatusPaid {
			t.Errorf("apply %s to paid: status = %q, want paid", status, got)
		}
	}
	if got := creditRowCount(t, db, "prov_back2"); got != 1 {
		t.Errorf("credit rows = %d, want 1", got)
	}
}

func TestApplyProviderInvoiceStatus_FailedAndExpired(t *testing.T) {
	db := openPaymentsTestDB(t)
	defer db.Close()
	createPaymentInvoicesTable(t, db)

	expiring := seedBillingInvoice(t, db, "inv_exp", models.PaymentStatusPending, "prov_exp", 100_000_000)
	if got, err := ApplyProviderInvoiceStatus(db, expiring, models.PaymentStatusExpired, "testprov"); err != nil || got != models.PaymentStatusExpired {
		t.Fatalf("pending to expired: got %q err %v", got, err)
	}
	failing := seedBillingInvoice(t, db, "inv_fail", models.PaymentStatusConfirming, "prov_fail", 100_000_000)
	if got, err := ApplyProviderInvoiceStatus(db, failing, models.PaymentStatusFailed, "testprov"); err != nil || got != models.PaymentStatusFailed {
		t.Fatalf("confirming to failed: got %q err %v", got, err)
	}
	if _, err := ApplyProviderInvoiceStatus(db, failing, "complete", "testprov"); err == nil {
		t.Fatal("expected error for a provider status that is not normalized")
	}
	if creditRowCount(t, db, "prov_exp")+creditRowCount(t, db, "prov_fail") != 0 {
		t.Fatal("expired or failed invoices must not be credited")
	}
}
