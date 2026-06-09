package payments

import "context"

type ProviderInvoice struct {
	ProviderInvoiceID string `json:"provider_invoice_id"`
	CheckoutURL       string `json:"checkout_url"`
}

type PaymentProvider interface {
	CreateInvoice(ctx context.Context, invoiceID string, amountMicrocents int64, redirectURL string) (*ProviderInvoice, error)
}
