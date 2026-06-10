package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/billing"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/payments"
)

type CreateInvoiceRequest struct {
	AmountUSD string `json:"amount_usd"`
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

	var req CreateInvoiceRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	amountMicrocents, err := models.ParseCreditsFromUSD(req.AmountUSD)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid amount format: %v", err))
	}

	minTopUpMicrocents, err := models.ParseCreditsFromUSD(cfg.Payments.MinTopUpUSD)
	if err != nil {
		minTopUpMicrocents = 50000000 // default 0.50 USD
	}
	maxTopUpMicrocents, err := models.ParseCreditsFromUSD(cfg.Payments.MaxTopUpUSD)
	if err != nil {
		maxTopUpMicrocents = 100000000000 // default 1000.00 USD
	}

	if amountMicrocents < minTopUpMicrocents || amountMicrocents > maxTopUpMicrocents {
		minUSD := float64(minTopUpMicrocents) / float64(models.MicrocentsPerUSD)
		maxUSD := float64(maxTopUpMicrocents) / float64(models.MicrocentsPerUSD)
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Amount must be between $%.2f and $%.2f USD", minUSD, maxUSD))
	}

	provider, err := payments.NewProvider(cfg.Payments)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to initialize payment provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Payments provider is not configured")
	}

	invoiceID := "inv_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	redirectURL := fmt.Sprintf("%s/billing?success=true&invoice=%s", cfg.Server.BaseURL, invoiceID)

	provInv, err := provider.CreateInvoice(context.Background(), invoiceID, amountMicrocents, redirectURL)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create BTCPay invoice for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to initialize payment with BTCPay: %v", err))
	}

	invoice := &models.PaymentInvoice{
		InvoiceID:           invoiceID,
		Username:            username,
		AmountUSDMicrocents: amountMicrocents,
		Status:              "pending",
		Provider:            "btcpay",
		ProviderInvoiceID:   provInv.ProviderInvoiceID,
	}

	if err := models.CreatePaymentInvoice(database.DB, invoice); err != nil {
		logging.ErrorLogger.Printf("Failed to save payment invoice %s to DB: %v", invoiceID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to persist payment request")
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

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read request body")
	}

	if !payments.VerifyBTCPaySignature(body, sigHeader, cfg.Payments.BTCPayWebhookSecret) {
		logging.ErrorLogger.Printf("Webhook signature verification failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid signature")
	}

	var payload struct {
		Type      string `json:"type"`
		InvoiceID string `json:"invoiceId"`
		Metadata  struct {
			InvoiceID string `json:"invoice_id"`
		} `json:"metadata"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid JSON payload")
	}

	if payload.Type != "InvoiceSettled" && payload.Type != "InvoiceCompleted" {
		return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "message": "Ignored event type"})
	}

	localInvoiceID := payload.Metadata.InvoiceID
	providerInvoiceID := payload.InvoiceID

	var invoice *models.PaymentInvoice
	if localInvoiceID != "" {
		invoice, err = models.GetPaymentInvoice(database.DB, localInvoiceID)
	}
	if err != nil || invoice == nil {
		if providerInvoiceID != "" {
			invoice, err = models.GetPaymentInvoiceByProviderID(database.DB, providerInvoiceID)
		}
	}

	if err != nil || invoice == nil {
		logging.ErrorLogger.Printf("Webhook: no matching payment invoice found for local_id=%s, provider_id=%s: %v", localInvoiceID, providerInvoiceID, err)
		return echo.NewHTTPError(http.StatusNotFound, "No matching invoice found")
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
		logging.ErrorLogger.Printf("Webhook CRITICAL: failed to settle invoice %s for user %s: %v", invoice.InvoiceID, invoice.Username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to credit payment balance")
	}

	logging.InfoLogger.Printf("Webhook: successfully settled invoice %s for user %s (%d microcents)", invoice.InvoiceID, invoice.Username, invoice.AmountUSDMicrocents)

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

	repaired, err := billing.ReconcilePaidInvoices(database.DB, "btcpay")
	if err != nil {
		logging.ErrorLogger.Printf("Admin reconcile payments failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reconcile payment invoices")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"repaired_count": repaired,
		},
		"message": fmt.Sprintf("Reconciled %d paid invoice(s) missing ledger credits", repaired),
	})
}
