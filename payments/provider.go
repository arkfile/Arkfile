package payments

import (
	"errors"

	"github.com/arkfile/Arkfile/config"
)

// NewProvider returns the configured payment provider implementation.
// No provider is built in. Enabling payments without one fails closed.
func NewProvider(cfg config.PaymentsConfig) (PaymentProvider, error) {
	if !cfg.Enabled {
		return nil, errors.New("payments integration is disabled")
	}
	return nil, errors.New("no payment provider is configured")
}
