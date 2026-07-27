package handlers

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/logging"
)

// OobPaymentsHandler returns optional out-of-band payment destinations
// (PayNym / BIP47 payment code and Monero address) plus the instance admin
// contact when configured. These are display-only; Arkfile does not watch
// the chain or auto-credit. Operators verify payments externally and credit
// via arkfile-admin billing gift.
//
// GET /api/oob-payments (public)
func OobPaymentsHandler(c echo.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to load config for oob payments: %v", err)
		return JSONError(c, http.StatusServiceUnavailable, "Configuration unavailable")
	}

	paynym := strings.TrimSpace(cfg.OobPayments.PayNym)
	paymentCode := strings.TrimSpace(cfg.OobPayments.PayNymPaymentCode)
	monero := strings.TrimSpace(cfg.OobPayments.MoneroAddress)
	adminContact := strings.TrimSpace(cfg.Deployment.AdminContact)
	configured := cfg.OobPayments.Configured()

	return c.JSON(http.StatusOK, map[string]interface{}{
		"configured":           configured,
		"paynym":               paynym,
		"paynym_payment_code":  paymentCode,
		"monero_address":       monero,
		"admin_contact":        adminContact,
	})
}
