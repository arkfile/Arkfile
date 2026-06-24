package billing

import (
	"database/sql"
	"fmt"

	"github.com/arkfile/Arkfile/models"
)

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
