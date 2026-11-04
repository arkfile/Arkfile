package payments

import "context"

type ProviderInvoice struct {
	ProviderInvoiceID string `json:"provider_invoice_id"`
	CheckoutURL       string `json:"checkout_url"`
}

// PaymentProvider is the seam for a future one-time top-up processor.
// GetInvoiceStatus returns a normalized status: paid, pending, expired, or failed.
type PaymentProvider interface {
	Name() string
	CreateInvoice(ctx context.Context, invoiceID string, amountMicrocents int64, redirectURL string) (*ProviderInvoice, error)
	GetInvoiceStatus(ctx context.Context, providerInvoiceID string) (string, error)
}
