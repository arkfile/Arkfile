package billing

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/arkfile/Arkfile/models"
)

type InvoiceStatusProvider interface {
	GetInvoiceStatus(context.Context, string) (string, error)
}

type PendingReconcileReport struct {
	Checked int `json:"checked"`
	Settled int `json:"settled"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

// ReconcilePendingInvoices queries a bounded batch of associated pending
// invoices and settles only provider-authoritative Settled states.
func ReconcilePendingInvoices(ctx context.Context, db *sql.DB, provider InvoiceStatusProvider, paymentType string, batchSize int, requestTimeout time.Duration) (PendingReconcileReport, error) {
	var report PendingReconcileReport
	if provider == nil {
		return report, fmt.Errorf("billing.ReconcilePendingInvoices: provider is required")
	}
	if batchSize < 1 || batchSize > 100 {
		return report, fmt.Errorf("billing.ReconcilePendingInvoices: batch size must be between 1 and 100")
	}
	if requestTimeout <= 0 || requestTimeout > 30*time.Second {
		return report, fmt.Errorf("billing.ReconcilePendingInvoices: request timeout must be between 1ns and 30s")
	}
	invoices, err := models.ListPendingPaymentInvoices(db, paymentType, batchSize)
	if err != nil {
		return report, fmt.Errorf("billing.ReconcilePendingInvoices: list pending: %w", err)
	}
	for _, invoice := range invoices {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		report.Checked++
		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		status, statusErr := provider.GetInvoiceStatus(requestCtx, invoice.ProviderInvoiceID)
		cancel()
		if statusErr != nil {
			report.Errors++
			continue
		}
		if status != "Settled" {
			report.Skipped++
			continue
		}
		if _, err := SettlePaymentInvoice(db, invoice, paymentType); err != nil {
			if isDuplicateTransactionIDError(err) {
				report.Skipped++
				continue
			}
			report.Errors++
			continue
		}
		report.Settled++
	}
	return report, nil
}

// ReconcilePaidInvoices finds paid invoices missing a matching credit_transactions row
// and applies the ledger credit for each orphan.
func ReconcilePaidInvoices(db *sql.DB, paymentType string) (int, error) {
	invoices, err := models.ListPaidInvoicesWithoutCredit(db)
	if err != nil {
		return 0, fmt.Errorf("billing.ReconcilePaidInvoices: list orphans: %w", err)
	}

	repaired := 0
	for _, invoice := range invoices {
		_, err := ProcessPayment(db, invoice.Username, invoice.AmountUSDMicrocents, invoice.ProviderInvoiceID, paymentType)
		if err != nil {
			if isDuplicateTransactionIDError(err) {
				continue
			}
			return repaired, fmt.Errorf("billing.ReconcilePaidInvoices: invoice %s: %w", invoice.InvoiceID, err)
		}
		repaired++
	}
	return repaired, nil
}
