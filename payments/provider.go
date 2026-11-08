package payments

import (
	"errors"
	"strings"

	"github.com/arkfile/Arkfile/config"
)

// BitcartNotificationPath is the Arkfile route that receives Bitcart invoice notifications.
const BitcartNotificationPath = "/api/webhooks/bitcart"

// NewProvider returns the configured payment provider. Bitcart is the only
// implementation; config validation guarantees its settings when enabled.
func NewProvider(cfg *config.Config) (PaymentProvider, error) {
	if cfg == nil || !cfg.Payments.Enabled {
		return nil, errors.New("payments integration is disabled")
	}
	notificationURL := strings.TrimRight(cfg.Server.BaseURL, "/") + BitcartNotificationPath
	return NewBitcartProvider(cfg.Payments, notificationURL)
}
