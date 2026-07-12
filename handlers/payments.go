package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	if !cfg.Payments.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "Payments integration is disabled")
	}

	if !billing.ShouldAllowTopUp(database.DB, username) {
		return echo.NewHTTPError(http.StatusConflict,
			"Top-ups are not available while you have an active subscription. Manage your plan from billing or use `arkfile-client subscription portal`.")
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

	provider, err := payments.NewProvider(cfg.Payments)
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
	redirectURL := fmt.Sprintf("%s/?success=true&invoice=%s", cfg.Server.BaseURL, invoiceID)

	invoice := &models.PaymentInvoice{
		InvoiceID:           invoiceID,
		Username:            username,
		AmountUSDMicrocents: amountMicrocents,
		Status:              "creating",
		Provider:            "btcpay",
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
	provInv, err := provider.CreateInvoice(ctx, invoiceID, amountMicrocents, redirectURL)
	if err != nil {
		_ = models.UpdatePaymentInvoiceStatus(database.DB, invoiceID, "failed")
		logging.ErrorLogger.Printf("Payment invoice %s provider creation failed", invoiceID)
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

	if err := ExtendAuthenticatedSession(c); err != nil {
		logging.InfoLogger.Printf("Payment invoice %s session extension skipped", invoiceID)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"invoice_id":   invoiceID,
			"checkout_url": provInv.CheckoutURL,
			"provider":     "btcpay",
		},
	})
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

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    invoice,
	})
}

func BTCPayWebhookHandler(c echo.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Webhook: failed to load config: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal configuration error")
	}

	if !cfg.Payments.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "Payments integration is disabled")
	}

	sigHeader := c.Request().Header.Get("BTCPay-Sig")
	if sigHeader == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing BTCPay-Sig header")
	}

	const maxWebhookBodyBytes = 64 << 10
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxWebhookBodyBytes)
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Webhook body is invalid or too large")
	}

	if !payments.VerifyBTCPaySignature(body, sigHeader, cfg.Payments.BTCPayWebhookSecret) {
		logging.ErrorLogger.Printf("Webhook signature verification failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid signature")
	}

	var payload struct {
		Type      string `json:"type"`
		InvoiceID string `json:"invoiceId"`
		StoreID   string `json:"storeId"`
		Metadata  struct {
			InvoiceID string `json:"invoice_id"`
		} `json:"metadata"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid JSON payload")
	}

	if payload.StoreID != "" && payload.StoreID != cfg.Payments.BTCPayStoreID {
		return echo.NewHTTPError(http.StatusForbidden, "Webhook store does not match")
	}
	if payload.Type != "InvoiceSettled" {
		return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "message": "Ignored event type"})
	}

	localInvoiceID := payload.Metadata.InvoiceID
	providerInvoiceID := payload.InvoiceID

	if localInvoiceID == "" && providerInvoiceID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Webhook invoice identifier is required")
	}

	var invoice *models.PaymentInvoice
	if localInvoiceID != "" {
		invoice, err = models.GetPaymentInvoice(database.DB, localInvoiceID)
		if err != nil {
			logging.ErrorLogger.Printf("Webhook local payment invoice was not found")
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Invoice association is not available yet")
		}
		if providerInvoiceID != "" {
			providerBound, providerErr := models.GetPaymentInvoiceByProviderID(database.DB, providerInvoiceID)
			if providerErr == nil && providerBound.InvoiceID != invoice.InvoiceID {
				logging.ErrorLogger.Printf("Webhook invoice %s has conflicting identifiers", invoice.InvoiceID)
				return echo.NewHTTPError(http.StatusConflict, "Webhook invoice identifiers conflict")
			}
			if providerErr != nil && providerErr != sql.ErrNoRows {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Invoice association is not available yet")
			}
			if invoice.ProviderInvoiceID == "" && invoice.Status == "creating" {
				if err := models.AttachPaymentProviderInvoice(database.DB, invoice.InvoiceID, providerInvoiceID); err != nil {
					return echo.NewHTTPError(http.StatusServiceUnavailable, "Invoice association is not available yet")
				}
				invoice.ProviderInvoiceID = providerInvoiceID
				invoice.Status = "pending"
			} else if invoice.ProviderInvoiceID != providerInvoiceID {
				logging.ErrorLogger.Printf("Webhook invoice %s has conflicting identifiers", invoice.InvoiceID)
				return echo.NewHTTPError(http.StatusConflict, "Webhook invoice identifiers conflict")
			}
		}
	} else {
		invoice, err = models.GetPaymentInvoiceByProviderID(database.DB, providerInvoiceID)
		if err != nil {
			logging.ErrorLogger.Printf("Webhook provider payment invoice was not found")
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Invoice association is not available yet")
		}
	}

	if invoice.Status == "paid" {
		hasCredit, chkErr := models.CreditTransactionExistsForProviderID(database.DB, invoice.ProviderInvoiceID)
		if chkErr != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
		}
		if hasCredit {
			return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "message": "Invoice already paid"})
		}
	}

	if SettlePaymentInvoiceFunc == nil {
		logging.ErrorLogger.Printf("Webhook CRITICAL: SettlePaymentInvoiceFunc is not wired")
		return echo.NewHTTPError(http.StatusInternalServerError, "System integration error")
	}

	_, err = SettlePaymentInvoiceFunc(database.DB, invoice, "btcpay")
	if err != nil {
		logging.ErrorLogger.Printf("Webhook failed to settle payment invoice %s: %v", invoice.InvoiceID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to credit payment balance")
	}

	logging.InfoLogger.Printf("Webhook settled payment invoice %s", invoice.InvoiceID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payment processed successfully",
	})
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
		_, err = SettlePaymentInvoiceFunc(database.DB, invoice, "btcpay")
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

	provider, err := payments.NewProvider(cfg.Payments)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Payments provider is not configured")
	}

	remoteStatus, err := provider.GetInvoiceStatus(context.Background(), invoice.ProviderInvoiceID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to query BTCPay Server: %v", err))
	}

	if remoteStatus == "Settled" {
		if SettlePaymentInvoiceFunc == nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "SettlePaymentInvoiceFunc is not wired")
		}
		_, err = SettlePaymentInvoiceFunc(database.DB, invoice, "btcpay")
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to credit user balance")
		}
		invoice.Status = "paid"
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    invoice,
			"message": "Invoice successfully synchronized and settled",
		})
	}

	if remoteStatus == "Expired" || remoteStatus == "Invalid" {
		status := "expired"
		if remoteStatus == "Invalid" {
			status = "failed"
		}
		if err := models.UpdatePaymentInvoiceStatus(database.DB, invoice.InvoiceID, status); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Database update error")
		}
		invoice.Status = status
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    invoice,
			"message": fmt.Sprintf("Invoice synced and updated to status: %s", status),
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    invoice,
		"message": fmt.Sprintf("Invoice checked. Current BTCPay state is %s", remoteStatus),
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

	provider, err := payments.NewProvider(cfg.Payments)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Payments provider is not configured")
	}
	report, err := billing.ReconcilePendingInvoices(c.Request().Context(), database.DB, provider, "btcpay", 50, 10*time.Second)
	if err != nil {
		logging.ErrorLogger.Printf("Admin pending payment reconciliation failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reconcile pending payment invoices")
	}
	repaired, err := billing.ReconcilePaidInvoices(database.DB, "btcpay")
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
