package payments

import (
	"context"

	"github.com/arkfile/Arkfile/models"
)

type ProviderInvoice struct {
	ProviderInvoiceID string `json:"provider_invoice_id"`
	CheckoutURL       string `json:"checkout_url"`
}

// PaymentProvider creates one-time top-up invoices and reports their state.
// GetInvoiceStatus returns one of the models.PaymentStatus* values pending,
// confirming, paid, expired, or failed, after verifying that the provider
// invoice belongs to the given local invoice.
type PaymentProvider interface {
	Name() string
	CreateInvoice(ctx context.Context, invoiceID string, amountMicrocents int64) (*ProviderInvoice, error)
	GetInvoiceStatus(ctx context.Context, invoice *models.PaymentInvoice) (string, error)
	CheckoutURL(providerInvoiceID string) string
}
