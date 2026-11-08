package billing

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/arkfile/Arkfile/models"
)

type InvoiceStatusProvider interface {
	GetInvoiceStatus(context.Context, *models.PaymentInvoice) (string, error)
}

type PendingReconcileReport struct {
	Checked int `json:"checked"`
	Settled int `json:"settled"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

// ApplyProviderInvoiceStatus records a normalized provider status on a local
// invoice and returns the resulting local status. Status only moves forward:
// pending to confirming, pending or confirming to expired or failed, and any
// unpaid status to paid. Only "paid" credits the user, via SettlePaymentInvoice.
func ApplyProviderInvoiceStatus(db *sql.DB, invoice *models.PaymentInvoice, status, paymentType string) (string, error) {
	switch status {
	case models.PaymentStatusPaid:
		if _, err := SettlePaymentInvoice(db, invoice, paymentType); err != nil {
			return invoice.Status, err
		}
		invoice.Status = models.PaymentStatusPaid
		return invoice.Status, nil
	case models.PaymentStatusConfirming:
		return advanceInvoiceStatus(db, invoice, []string{models.PaymentStatusPending}, status)
	case models.PaymentStatusExpired:
		return advanceInvoiceStatus(db, invoice, []string{models.PaymentStatusPending}, status)
	case models.PaymentStatusFailed:
		return advanceInvoiceStatus(db, invoice, []string{models.PaymentStatusPending, models.PaymentStatusConfirming}, status)
	case models.PaymentStatusPending:
		return invoice.Status, nil
	default:
		return invoice.Status, fmt.Errorf("billing.ApplyProviderInvoiceStatus: unknown provider status %q", status)
	}
}

func advanceInvoiceStatus(db *sql.DB, invoice *models.PaymentInvoice, from []string, to string) (string, error) {
	moved, err := models.AdvancePaymentInvoiceStatus(db, invoice.InvoiceID, from, to)
	if err != nil {
		return invoice.Status, fmt.Errorf("billing.ApplyProviderInvoiceStatus: %w", err)
	}
	if moved {
		invoice.Status = to
		return to, nil
	}
	latest, err := models.GetPaymentInvoice(db, invoice.InvoiceID)
	if err != nil {
		return invoice.Status, fmt.Errorf("billing.ApplyProviderInvoiceStatus: reload: %w", err)
	}
	invoice.Status = latest.Status
	return latest.Status, nil
}

// ReconcilePendingInvoices queries a bounded batch of open (pending or
// confirming) invoices and applies each provider status. Only a provider
// status of "paid" settles an invoice.
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
		status, statusErr := provider.GetInvoiceStatus(requestCtx, invoice)
		cancel()
		if statusErr != nil {
			report.Errors++
			continue
		}
		previous := invoice.Status
		result, err := ApplyProviderInvoiceStatus(db, invoice, status, paymentType)
		switch {
		case err != nil && isDuplicateTransactionIDError(err):
			report.Skipped++
		case err != nil:
			report.Errors++
		case result == previous:
			report.Skipped++
		case result == models.PaymentStatusPaid:
			report.Settled++
		default:
			report.Updated++
		}
	}
	return report, nil
}

// ReconcilePaidInvoices finds paid invoices missing a matching credit_transactions row
// and applies the ledger credit for each orphan.
func ReconcilePaidInvoices(db *sql.DB) (int, error) {
	invoices, err := models.ListPaidInvoicesWithoutCredit(db)
	if err != nil {
		return 0, fmt.Errorf("billing.ReconcilePaidInvoices: list orphans: %w", err)
	}

	repaired := 0
	for _, invoice := range invoices {
		_, err := ProcessPayment(db, invoice.Username, invoice.AmountUSDMicrocents, invoice.ProviderInvoiceID, invoice.Provider)
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
