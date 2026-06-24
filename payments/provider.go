package payments

import (
	"errors"
	"fmt"

	"github.com/arkfile/Arkfile/config"
)

// NewProvider returns the configured payment provider implementation.
func NewProvider(cfg config.PaymentsConfig) (PaymentProvider, error) {
	if !cfg.Enabled {
		return nil, errors.New("payments integration is disabled")
	}
	if cfg.BTCPayServerURL == "" || cfg.BTCPayStoreID == "" || cfg.BTCPayAPIKey == "" {
		return nil, fmt.Errorf("BTCPay Server URL, store ID, and API key are required when payments are enabled")
	}
	return NewBTCPayClient(cfg.BTCPayServerURL, cfg.BTCPayStoreID, cfg.BTCPayAPIKey), nil
}
