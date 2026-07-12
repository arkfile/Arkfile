package payments

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/models"
)

type BTCPayClient struct {
	BaseURL    string
	StoreID    string
	APIKey     string
	HTTPClient *http.Client
}

// DefaultInvoiceExpirationMinutes is passed to BTCPay on invoice creation so
// checkout remains open long enough for on-chain and external-tab flows.
const DefaultInvoiceExpirationMinutes = 60

func NewBTCPayClient(baseURL, storeID, apiKey string) *BTCPayClient {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &BTCPayClient{
		BaseURL:    baseURL,
		StoreID:    storeID,
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *BTCPayClient) CreateInvoice(ctx context.Context, invoiceID string, amountMicrocents int64, redirectURL string) (*ProviderInvoice, error) {
	amountUSD, err := formatTopUpUSD(amountMicrocents)
	if err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"amount":   amountUSD,
		"currency": "USD",
		"metadata": map[string]string{
			"invoice_id": invoiceID,
		},
		"checkout": map[string]interface{}{
			"speedPolicy":       "LowMediumSpeed",
			"redirectURL":       redirectURL,
			"expirationMinutes": DefaultInvoiceExpirationMinutes,
		},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/stores/%s/invoices", c.BaseURL, c.StoreID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("btcpay returned bad status: %d", resp.StatusCode)
	}

	var respData struct {
		ID           string `json:"id"`
		CheckoutLink string `json:"checkoutLink"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}
	if respData.ID == "" {
		return nil, fmt.Errorf("btcpay response omitted invoice ID")
	}
	if err := validateCheckoutURL(c.BaseURL, respData.CheckoutLink); err != nil {
		return nil, err
	}

	return &ProviderInvoice{
		ProviderInvoiceID: respData.ID,
		CheckoutURL:       respData.CheckoutLink,
	}, nil
}

func formatTopUpUSD(amountMicrocents int64) (string, error) {
	const microcentsPerCent = models.MicrocentsPerUSD / 100
	if amountMicrocents <= 0 {
		return "", fmt.Errorf("top-up amount must be positive")
	}
	if amountMicrocents%microcentsPerCent != 0 {
		return "", fmt.Errorf("top-up amount must have at most two decimal places")
	}
	dollars := amountMicrocents / models.MicrocentsPerUSD
	cents := (amountMicrocents % models.MicrocentsPerUSD) / microcentsPerCent
	return fmt.Sprintf("%d.%02d", dollars, cents), nil
}

func validateCheckoutURL(baseURL, checkoutLink string) error {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return fmt.Errorf("invalid configured BTCPay origin")
	}
	checkout, err := url.Parse(checkoutLink)
	if err != nil || checkout.Scheme == "" || checkout.Host == "" || checkout.User != nil {
		return fmt.Errorf("btcpay returned an invalid checkout link")
	}
	if !strings.EqualFold(base.Scheme, checkout.Scheme) || !strings.EqualFold(base.Host, checkout.Host) {
		return fmt.Errorf("btcpay checkout link origin does not match configured origin")
	}
	return nil
}

func (c *BTCPayClient) GetInvoiceStatus(ctx context.Context, providerInvoiceID string) (string, error) {
	if providerInvoiceID == "" {
		return "", fmt.Errorf("provider invoice ID is required")
	}
	url := fmt.Sprintf("%s/api/v1/stores/%s/invoices/%s", c.BaseURL, c.StoreID, providerInvoiceID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("btcpay returned status %d", resp.StatusCode)
	}

	var respData struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return "", err
	}
	return respData.Status, nil
}
