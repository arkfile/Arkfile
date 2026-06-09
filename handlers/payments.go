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

	invoiceID := "inv_" + strings.ReplaceAll(uuid.New().String(), "-", "")

	// Build the redirect URL
	redirectURL := fmt.Sprintf("%s/billing?success=true&invoice=%s", cfg.Server.BaseURL, invoiceID)

	client := payments.NewBTCPayClient(cfg.Payments.BTCPayServerURL, cfg.Payments.BTCPayStoreID, cfg.Payments.BTCPayAPIKey)
	provInv, err := client.CreateInvoice(context.Background(), invoiceID, amountMicrocents, redirectURL)
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

	// We only process InvoiceSettled and InvoiceCompleted webhook events
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
		return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "message": "Invoice already paid"})
	}

	// Update local status
	if err := models.UpdatePaymentInvoiceStatus(database.DB, invoice.InvoiceID, "paid"); err != nil {
		logging.ErrorLogger.Printf("Webhook: failed to update status for invoice %s: %v", invoice.InvoiceID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Database update error")
	}

	// Process the credit ledger payment settlement using the wired ProcessPaymentFunc seam
	if ProcessPaymentFunc == nil {
		logging.ErrorLogger.Printf("Webhook CRITICAL: ProcessPaymentFunc is not wired")
		return echo.NewHTTPError(http.StatusInternalServerError, "System integration error")
	}

	_, err = ProcessPaymentFunc(database.DB, invoice.Username, invoice.AmountUSDMicrocents, invoice.ProviderInvoiceID, "btcpay")
	if err != nil {
		logging.ErrorLogger.Printf("Webhook CRITICAL: failed to credit user %s for invoice %s: %v", invoice.Username, invoice.InvoiceID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to credit payment balance")
	}

	logging.InfoLogger.Printf("Webhook: successfully credited user %s with %d microcents for invoice %s", invoice.Username, invoice.AmountUSDMicrocents, invoice.InvoiceID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payment processed successfully",
	})
}

// Admin APIs (Storage Credits / Payments)

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
		"data":    invoices,
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
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    invoice,
			"message": "Invoice is already paid",
		})
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Admin sync: failed to load config: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal configuration error")
	}

	client := payments.NewBTCPayClient(cfg.Payments.BTCPayServerURL, cfg.Payments.BTCPayStoreID, cfg.Payments.BTCPayAPIKey)
	
	// Query BTCPay directly to get the current invoice state
	url := fmt.Sprintf("%s/api/v1/stores/%s/invoices/%s", client.BaseURL, client.StoreID, invoice.ProviderInvoiceID)
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to construct sync request")
	}
	req.Header.Set("Authorization", "token "+client.APIKey)

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to query BTCPay Server: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("BTCPay Server returned status %d", resp.StatusCode))
	}

	var respData struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to decode BTCPay response")
	}

	// BTCPay invoice states: New, Processing, Expired, Invalid, Settled
	if respData.Status == "Settled" {
		// Update status to paid and credit the user
		if err := models.UpdatePaymentInvoiceStatus(database.DB, invoice.InvoiceID, "paid"); err != nil {
			logging.ErrorLogger.Printf("Admin sync: failed to update status: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Database update error")
		}

		if ProcessPaymentFunc == nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "ProcessPaymentFunc is not wired")
		}

		_, err = ProcessPaymentFunc(database.DB, invoice.Username, invoice.AmountUSDMicrocents, invoice.ProviderInvoiceID, "btcpay")
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to credit user balance")
		}

		invoice.Status = "paid"
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    invoice,
			"message": "Invoice successfully synchronized and settled",
		})
	} else if respData.Status == "Expired" || respData.Status == "Invalid" {
		status := "expired"
		if respData.Status == "Invalid" {
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
		"message": fmt.Sprintf("Invoice checked. Current BTCPay state is %s", respData.Status),
	})
}
