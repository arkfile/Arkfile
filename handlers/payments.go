package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/billing"
	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/payments"
)

type CreateInvoiceRequest struct {
	AmountUSD string `json:"amount_usd"`
	RequestID string `json:"request_id"`
}

func CreateInvoiceHandler(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to load config: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal configuration error")
	}

	if !billing.ShouldAllowTopUp(database.DB, username) {
		return echo.NewHTTPError(http.StatusConflict,
			"Top-ups are not available while you have an active subscription. Manage your plan from billing or use `arkfile-client subscription portal`.")
	}

	if !cfg.Payments.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "Payments integration is disabled")
	}

	var req CreateInvoiceRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	amountMicrocents, err := models.ParseUSDToMicrocents(req.AmountUSD, 2, false)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid amount format: %v", err))
	}

	minTopUpMicrocents, err := models.ParseUSDToMicrocents(cfg.Payments.MinTopUpUSD, 2, false)
	if err != nil {
		minTopUpMicrocents = 50000000 // default 0.50 USD
	}
	maxTopUpMicrocents, err := models.ParseUSDToMicrocents(cfg.Payments.MaxTopUpUSD, 2, false)
	if err != nil {
		maxTopUpMicrocents = 100000000000 // default 1000.00 USD
	}

	if amountMicrocents < minTopUpMicrocents || amountMicrocents > maxTopUpMicrocents {
		return echo.NewHTTPError(http.StatusBadRequest, "Amount is outside the configured top-up range")
	}

	provider, err := payments.NewProvider(cfg)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to initialize payment provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Payments provider is not configured")
	}

	requestUUID := uuid.New()
	if req.RequestID != "" {
		requestUUID, err = uuid.Parse(req.RequestID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "request_id must be a UUID")
		}
	}
	invoiceID := "inv_" + strings.ReplaceAll(requestUUID.String(), "-", "")

	invoice := &models.PaymentInvoice{
		InvoiceID:           invoiceID,
		Username:            username,
		AmountUSDMicrocents: amountMicrocents,
		Status:              models.PaymentStatusCreating,
		Provider:            provider.Name(),
	}
	if err := models.CreatePaymentInvoice(database.DB, invoice); err != nil {
		existing, getErr := models.GetPaymentInvoice(database.DB, invoiceID)
		if getErr == nil && existing.Username == username && existing.AmountUSDMicrocents == amountMicrocents {
			return echo.NewHTTPError(http.StatusConflict, "Payment request is already being processed")
		}
		logging.ErrorLogger.Printf("Payment invoice %s local creation failed: %v", invoiceID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to persist payment request")
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), 15*time.Second)
	defer cancel()
	provInv, err := provider.CreateInvoice(ctx, invoiceID, amountMicrocents)
	if err != nil {
		_ = models.UpdatePaymentInvoiceStatus(database.DB, invoiceID, models.PaymentStatusFailed)
		logging.ErrorLogger.Printf("Payment invoice %s provider creation failed: %v", invoiceID, err)
		return echo.NewHTTPError(http.StatusBadGateway, "Payment provider could not create the invoice")
	}
	var attachErr error
	for attempt := 0; attempt < 3; attempt++ {
		attachErr = models.AttachPaymentProviderInvoice(database.DB, invoiceID, provInv.ProviderInvoiceID)
		if attachErr == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(25 * time.Millisecond)
		}
	}
	if attachErr != nil {
		logging.ErrorLogger.Printf("Payment invoice %s provider association failed: %v", invoiceID, attachErr)
		return echo.NewHTTPError(http.StatusInternalServerError, "Payment invoice association is pending recovery")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"invoice_id":            invoiceID,
			"status":                models.PaymentStatusPending,
			"amount_usd_microcents": amountMicrocents,
			"checkout_url":          provInv.CheckoutURL,
			"provider":              provider.Name(),
		},
	})
}

// invoiceStatusResponse is the owner-facing invoice view. checkout_url is
// present only while the invoice is open.
type invoiceStatusResponse struct {
	*models.PaymentInvoice
	CheckoutURL string `json:"checkout_url,omitempty"`
}

func GetInvoiceStatusHandler(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	invoiceID := c.Param("invoice_id")
	if invoiceID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invoice ID is required")
	}

	invoice, err := models.GetPaymentInvoice(database.DB, invoiceID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invoice not found")
	}

	if invoice.Username != username {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	resp := invoiceStatusResponse{PaymentInvoice: invoice}
	if models.IsOpenPaymentStatus(invoice.Status) && invoice.ProviderInvoiceID != "" {
		if provider := configuredPaymentProvider(invoice.Provider); provider != nil {
			if paymentRefreshThrottle.allow(invoice.InvoiceID, time.Now()) {
				if err := refreshInvoiceFromProvider(c.Request().Context(), provider, invoice); err != nil {
					logging.ErrorLogger.Printf("Payment invoice %s status refresh failed: %v", invoice.InvoiceID, err)
				}
			}
			if models.IsOpenPaymentStatus(invoice.Status) {
				resp.CheckoutURL = provider.CheckoutURL(invoice.ProviderInvoiceID)
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// BitcartWebhookHandler receives Bitcart invoice notifications. The body is
// unsigned, so only the invoice id is read from it: the invoice must already
// be attached to a local invoice, and its status is fetched from Bitcart and
// verified before anything is recorded.
func BitcartWebhookHandler(c echo.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal configuration error")
	}
	if !cfg.Payments.Enabled {
		return echo.NewHTTPError(http.StatusNotFound, "Not found")
	}

	const maxNotificationBody = 4 << 10
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, maxNotificationBody+1))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read body")
	}
	if len(body) > maxNotificationBody {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Request body too large")
	}
	var notification struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &notification); err != nil || notification.ID == "" || len(notification.ID) > 128 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid notification")
	}

	ack := map[string]interface{}{"success": true}
	invoice, err := models.GetPaymentInvoiceByProviderID(database.DB, notification.ID)
	if err != nil {
		return c.JSON(http.StatusOK, ack)
	}
	provider, err := payments.NewProvider(cfg)
	if err != nil || invoice.Provider != provider.Name() {
		return c.JSON(http.StatusOK, ack)
	}
	if invoice.Status == models.PaymentStatusPaid {
		return c.JSON(http.StatusOK, ack)
	}
	if !paymentNotificationThrottle.allow(invoice.InvoiceID, time.Now()) {
		return c.JSON(http.StatusOK, ack)
	}
	if err := refreshInvoiceFromProvider(c.Request().Context(), provider, invoice); err != nil {
		logging.ErrorLogger.Printf("Payment invoice %s notification processing failed: %v", invoice.InvoiceID, err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to verify invoice with payment provider")
	}
	return c.JSON(http.StatusOK, ack)
}

// configuredPaymentProvider returns the live provider when payments are
// enabled and it matches providerName, or nil otherwise.
func configuredPaymentProvider(providerName string) payments.PaymentProvider {
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Payments.Enabled {
		return nil
	}
	provider, err := payments.NewProvider(cfg)
	if err != nil || provider.Name() != providerName {
		return nil
	}
	return provider
}

// refreshInvoiceFromProvider fetches and applies the provider status of one invoice.
func refreshInvoiceFromProvider(ctx context.Context, provider payments.PaymentProvider, invoice *models.PaymentInvoice) error {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status, err := provider.GetInvoiceStatus(reqCtx, invoice)
	if err != nil {
		return err
	}
	_, err = billing.ApplyProviderInvoiceStatus(database.DB, invoice, status, provider.Name())
	return err
}

// invoiceThrottle limits provider lookups per invoice so status polling and
// unauthenticated notifications cannot be used to flood the provider.
type invoiceThrottle struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[string]time.Time
}

var (
	paymentRefreshThrottle      = &invoiceThrottle{interval: 10 * time.Second, last: map[string]time.Time{}}
	paymentNotificationThrottle = &invoiceThrottle{interval: 2 * time.Second, last: map[string]time.Time{}}
)

func (t *invoiceThrottle) allow(invoiceID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if prev, ok := t.last[invoiceID]; ok && now.Sub(prev) < t.interval {
		return false
	}
	if len(t.last) > 10000 {
		for id, ts := range t.last {
			if now.Sub(ts) >= t.interval {
				delete(t.last, id)
			}
		}
	}
	t.last[invoiceID] = now
	return true
}

func AdminGetInvoiceHandler(c echo.Context) error {
	invoiceID := c.Param("invoice_id")
	if invoiceID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invoice ID is required")
	}

	invoice, err := models.GetPaymentInvoice(database.DB, invoiceID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invoice not found")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    invoice,
	})
}

func AdminListInvoicesHandler(c echo.Context) error {
	userFilter := c.QueryParam("user")
	statusFilter := c.QueryParam("status")

	invoices, err := models.ListPaymentInvoices(database.DB, userFilter, statusFilter)
	if err != nil {
		logging.ErrorLogger.Printf("Admin: failed to list invoices: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list invoices")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"invoices": invoices,
			"count":    len(invoices),
		},
	})
}

func AdminSyncInvoiceHandler(c echo.Context) error {
	invoiceID := c.Param("invoice_id")
	if invoiceID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invoice ID is required")
	}

	invoice, err := models.GetPaymentInvoice(database.DB, invoiceID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invoice not found")
	}

	if invoice.Status == "paid" {
		hasCredit, chkErr := models.CreditTransactionExistsForProviderID(database.DB, invoice.ProviderInvoiceID)
		if chkErr != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
		}
		if hasCredit {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"success": true,
				"data":    invoice,
				"message": "Invoice is already paid",
			})
		}
		if SettlePaymentInvoiceFunc == nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "SettlePaymentInvoiceFunc is not wired")
		}
		_, err = SettlePaymentInvoiceFunc(database.DB, invoice, invoice.Provider)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to credit user balance")
		}
		invoice.Status = "paid"
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    invoice,
			"message": "Invoice credit reconciled for paid invoice",
		})
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Admin sync: failed to load config: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal configuration error")
	}
	if !cfg.Payments.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "Payments integration is disabled")
	}

	provider, err := payments.NewProvider(cfg)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Payments provider is not configured")
	}
	if invoice.ProviderInvoiceID == "" || invoice.Provider != provider.Name() {
		return echo.NewHTTPError(http.StatusConflict, "Invoice is not attached to the configured payment provider")
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), 15*time.Second)
	defer cancel()
	remoteStatus, err := provider.GetInvoiceStatus(ctx, invoice)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, fmt.Sprintf("Failed to query payment provider: %v", err))
	}

	previous := invoice.Status
	result, err := billing.ApplyProviderInvoiceStatus(database.DB, invoice, remoteStatus, provider.Name())
	if err != nil {
		logging.ErrorLogger.Printf("Admin sync: invoice %s apply status failed: %v", invoice.InvoiceID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to apply provider status")
	}

	message := fmt.Sprintf("Invoice checked. Provider status is %s; local status is %s", remoteStatus, result)
	if result == models.PaymentStatusPaid && previous != models.PaymentStatusPaid {
		message = "Invoice successfully synchronized and settled"
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    invoice,
		"message": message,
	})
}

func AdminReconcilePaymentsHandler(c echo.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal configuration error")
	}
	if !cfg.Payments.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "Payments integration is disabled")
	}

	provider, err := payments.NewProvider(cfg)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Payments provider is not configured")
	}
	report, err := billing.ReconcilePendingInvoices(c.Request().Context(), database.DB, provider, provider.Name(), 50, 10*time.Second)
	if err != nil {
		logging.ErrorLogger.Printf("Admin pending payment reconciliation failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reconcile pending payment invoices")
	}
	repaired, err := billing.ReconcilePaidInvoices(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Admin paid payment reconciliation failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reconcile payment invoices")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"pending":        report,
			"repaired_count": repaired,
		},
		"message": "Payment reconciliation completed",
	})
}
