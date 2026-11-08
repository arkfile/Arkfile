package payments

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/money"
)

const (
	bitcartProviderName  = "bitcart"
	bitcartCurrency      = "USD"
	bitcartMaxBodyBytes  = 1 << 20
	bitcartClientTimeout = 20 * time.Second
)

// ErrBitcartInvoiceMismatch means the Bitcart invoice does not match the local
// invoice it is attached to. Such an invoice is never credited.
var ErrBitcartInvoiceMismatch = errors.New("bitcart invoice does not match local invoice")

// BitcartProvider talks to a Bitcart Merchants API. Invoices carry only the
// Arkfile invoice ID as order_id and the USD price; no username or other
// account data is sent to Bitcart.
type BitcartProvider struct {
	apiURL          string
	checkoutURL     string
	token           string
	storeID         string
	notificationURL string
	httpClient      *http.Client
}

func NewBitcartProvider(cfg config.PaymentsConfig, notificationURL string) (*BitcartProvider, error) {
	if cfg.BitcartAPIURL == "" || cfg.BitcartCheckoutURL == "" || cfg.BitcartAPIToken == "" || cfg.BitcartStoreID == "" {
		return nil, errors.New("bitcart provider requires API URL, checkout URL, API token, and store ID")
	}
	return &BitcartProvider{
		apiURL:          strings.TrimRight(cfg.BitcartAPIURL, "/"),
		checkoutURL:     strings.TrimRight(cfg.BitcartCheckoutURL, "/"),
		token:           cfg.BitcartAPIToken,
		storeID:         cfg.BitcartStoreID,
		notificationURL: notificationURL,
		httpClient: &http.Client{
			Timeout: bitcartClientTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (p *BitcartProvider) Name() string { return bitcartProviderName }

func (p *BitcartProvider) CheckoutURL(providerInvoiceID string) string {
	if providerInvoiceID == "" {
		return ""
	}
	return p.checkoutURL + "/i/" + url.PathEscape(providerInvoiceID)
}

type bitcartInvoice struct {
	ID       string          `json:"id"`
	Status   string          `json:"status"`
	OrderID  string          `json:"order_id"`
	StoreID  *string         `json:"store_id"`
	Price    json.RawMessage `json:"price"`
	Currency string          `json:"currency"`
}

func (p *BitcartProvider) CreateInvoice(ctx context.Context, invoiceID string, amountMicrocents int64) (*ProviderInvoice, error) {
	price, err := formatUSDPrice(amountMicrocents)
	if err != nil {
		return nil, err
	}
	body := map[string]string{
		"price":            price,
		"currency":         bitcartCurrency,
		"store_id":         p.storeID,
		"order_id":         invoiceID,
		"notification_url": p.notificationURL,
	}
	var created bitcartInvoice
	if err := p.do(ctx, http.MethodPost, "/invoices", body, &created); err != nil {
		return nil, fmt.Errorf("bitcart create invoice: %w", err)
	}
	if created.ID == "" {
		return nil, errors.New("bitcart create invoice: response has no invoice id")
	}
	if err := p.verify(&created, created.ID, invoiceID, amountMicrocents); err != nil {
		return nil, err
	}
	return &ProviderInvoice{ProviderInvoiceID: created.ID, CheckoutURL: p.CheckoutURL(created.ID)}, nil
}

func (p *BitcartProvider) GetInvoiceStatus(ctx context.Context, invoice *models.PaymentInvoice) (string, error) {
	if invoice == nil || invoice.ProviderInvoiceID == "" {
		return "", errors.New("bitcart invoice status: missing provider invoice id")
	}
	var remote bitcartInvoice
	if err := p.do(ctx, http.MethodGet, "/invoices/"+url.PathEscape(invoice.ProviderInvoiceID), nil, &remote); err != nil {
		return "", fmt.Errorf("bitcart invoice status: %w", err)
	}
	if err := p.verify(&remote, invoice.ProviderInvoiceID, invoice.InvoiceID, invoice.AmountUSDMicrocents); err != nil {
		return "", err
	}
	return mapBitcartStatus(remote.Status)
}

// verify checks that a Bitcart invoice is the one Arkfile created for the
// local invoice: same Bitcart id, order_id equal to the Arkfile invoice id,
// the configured store, and the USD price stored on the Arkfile invoice.
// The price compared is the fixed USD invoice amount, not a crypto amount.
func (p *BitcartProvider) verify(remote *bitcartInvoice, providerInvoiceID, invoiceID string, amountMicrocents int64) error {
	if remote.ID != providerInvoiceID {
		return fmt.Errorf("%w: invoice id", ErrBitcartInvoiceMismatch)
	}
	if remote.OrderID != invoiceID {
		return fmt.Errorf("%w: order_id", ErrBitcartInvoiceMismatch)
	}
	if remote.StoreID == nil || *remote.StoreID != p.storeID {
		return fmt.Errorf("%w: store_id", ErrBitcartInvoiceMismatch)
	}
	if !strings.EqualFold(remote.Currency, bitcartCurrency) {
		return fmt.Errorf("%w: currency", ErrBitcartInvoiceMismatch)
	}
	price, err := parseBitcartPrice(remote.Price)
	if err != nil || price != amountMicrocents {
		return fmt.Errorf("%w: price", ErrBitcartInvoiceMismatch)
	}
	return nil
}

// mapBitcartStatus converts a Bitcart invoice status to a local status.
// Bitcart "paid" and "unconfirmed" mean a transaction was seen but not
// confirmed; "confirmed" means fewer confirmations than the store requires.
// Only "complete" is treated as paid.
func mapBitcartStatus(status string) (string, error) {
	switch status {
	case "pending":
		return models.PaymentStatusPending, nil
	case "paid", "unconfirmed", "confirmed":
		return models.PaymentStatusConfirming, nil
	case "complete":
		return models.PaymentStatusPaid, nil
	case "expired":
		return models.PaymentStatusExpired, nil
	case "invalid", "refunded":
		return models.PaymentStatusFailed, nil
	default:
		return "", fmt.Errorf("bitcart invoice status: unknown status %q", status)
	}
}

func (p *BitcartProvider) do(ctx context.Context, method, path string, payload interface{}, out interface{}) error {
	var reqBody io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.apiURL+path, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, bitcartMaxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(data) > bitcartMaxBodyBytes {
		return errors.New("response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func formatUSDPrice(amountMicrocents int64) (string, error) {
	const microcentsPerCent = money.MicrocentsPerUSD / 100
	if amountMicrocents <= 0 || amountMicrocents%microcentsPerCent != 0 {
		return "", errors.New("top-up amount must be a positive whole number of cents")
	}
	cents := amountMicrocents / microcentsPerCent
	return fmt.Sprintf("%d.%02d", cents/100, cents%100), nil
}

func parseBitcartPrice(raw json.RawMessage) (int64, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" || value == "null" {
		return 0, errors.New("price missing")
	}
	if strings.HasPrefix(value, `"`) {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, err
		}
		value = s
	}
	return money.ParseUSDToMicrocents(value, 8, false)
}
