package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
)

// GetUserCredits returns the current user's credit balance and transaction history
func GetUserCredits(c echo.Context) error {
	// Get authenticated username
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	// Get limit and offset for pagination
	limit := 20 // Default
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	offset := 0
	if offsetStr := c.QueryParam("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	// Get user credits summary
	summary, err := models.GetUserCreditsSummary(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get credits summary for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve credit information")
	}

	// Get full transaction history with pagination
	transactions, err := models.GetUserTransactions(database.DB, username, limit, offset)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get transactions for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve transaction history")
	}

	response := map[string]interface{}{
		"username":          username,
		"balance":           summary.Balance,
		"formatted_balance": summary.FormattedBalance,
		"transactions":      transactions,
		"pagination": map[string]interface{}{
			"limit":  limit,
			"offset": offset,
			"count":  len(transactions),
		},
	}

	return c.JSON(http.StatusOK, response)
}

// Admin Credit Management Endpoints

// AdminGetUserCredits retrieves credit information for a specific user (admin only)
func AdminGetUserCredits(c echo.Context) error {
	// Get authenticated admin username
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	// Check admin privileges
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify admin privileges")
	}
	if !adminUser.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target username from URL parameter
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	// Verify target user exists
	_, err = models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user")
	}

	// Get pagination parameters
	limit := 50 // Default for admin view
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 200 {
			limit = parsedLimit
		}
	}

	offset := 0
	if offsetStr := c.QueryParam("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	// Get target user's credits summary
	summary, err := models.GetUserCreditsSummary(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin failed to get credits summary for user %s: %v", targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve credit information")
	}

	// Get full transaction history with pagination
	transactions, err := models.GetUserTransactions(database.DB, targetUsername, limit, offset)
	if err != nil {
		logging.ErrorLogger.Printf("Admin failed to get transactions for user %s: %v", targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve transaction history")
	}

	// Log admin access
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "admin_view_user_credits",
			"target_username": targetUsername,
		},
	)

	response := map[string]interface{}{
		"target_username":   targetUsername,
		"balance":           summary.Balance,
		"formatted_balance": summary.FormattedBalance,
		"transactions":      transactions,
		"pagination": map[string]interface{}{
			"limit":  limit,
			"offset": offset,
			"count":  len(transactions),
		},
		"admin_info": map[string]interface{}{
			"viewed_by": adminUsername,
		},
	}

	return c.JSON(http.StatusOK, response)
}

// AdminAdjustCreditsRequest represents the request payload for admin credit adjustments
type AdminAdjustCreditsRequest struct {
	AmountUSD     string  `json:"amount_usd" validate:"required"`
	TransactionID *string `json:"transaction_id,omitempty"`
	Reason        string  `json:"reason" validate:"required"`
	Operation     string  `json:"operation" validate:"required"` // "add", "subtract", "set"
}

// AdminAdjustCredits allows admins to add, subtract, or set user credits (admin only)
func AdminAdjustCredits(c echo.Context) error {
	// Get authenticated admin username
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	// Check admin privileges
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify admin privileges")
	}
	if !adminUser.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target username from URL parameter
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	// Verify target user exists
	_, err = models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user")
	}

	// Parse request
	var req AdminAdjustCreditsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Validate operation
	if req.Operation != "add" && req.Operation != "subtract" && req.Operation != "set" {
		return echo.NewHTTPError(http.StatusBadRequest, "Operation must be 'add', 'subtract', or 'set'")
	}

	// Parse amount
	amountCents, err := models.ParseCreditsFromUSD(req.AmountUSD)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid amount format")
	}

	// Validate reason
	if req.Reason == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Reason is required for credit adjustments")
	}

	var transaction *models.CreditTransaction

	// Perform the requested operation
	switch req.Operation {
	case "add":
		transaction, err = models.AddCredits(
			database.DB, targetUsername, amountCents,
			models.TransactionTypeCredit, req.Reason,
			req.TransactionID, &adminUsername,
		)
	case "subtract":
		transaction, err = models.DebitCredits(
			database.DB, targetUsername, amountCents,
			models.TransactionTypeDebit, req.Reason,
			req.TransactionID, &adminUsername,
		)
	case "set":
		transaction, err = models.SetCredits(
			database.DB, targetUsername, amountCents,
			req.Reason, adminUsername,
		)
	}

	if err != nil {
		logging.ErrorLogger.Printf("Admin credit adjustment failed: admin=%s, target=%s, operation=%s, amount=%d, error=%v",
			adminUsername, targetUsername, req.Operation, amountCents, err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get updated balance for response
	updatedCredits, err := models.GetUserCredits(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get updated credits after adjustment: %v", err)
		// Don't fail the request, just log the error
	}

	response := map[string]interface{}{
		"success":         true,
		"target_username": targetUsername,
		"operation":       req.Operation,
		"amount_usd":      req.AmountUSD,
		"amount_cents":    amountCents,
		"transaction":     transaction,
		"admin_info": map[string]interface{}{
			"adjusted_by": adminUsername,
			"reason":      req.Reason,
		},
	}

	// Include updated balance if available
	if updatedCredits != nil {
		response["updated_balance"] = updatedCredits
		response["formatted_balance"] = models.FormatCreditsUSD(updatedCredits.BalanceUSDCents)
	}

	return c.JSON(http.StatusOK, response)
}

// AdminSetCreditsRequest represents the request payload for admin balance override
type AdminSetCreditsRequest struct {
	BalanceUSD    string  `json:"balance_usd" validate:"required"`
	TransactionID *string `json:"transaction_id,omitempty"`
	Reason        string  `json:"reason" validate:"required"`
}

// AdminSetCredits allows admins to set a user's balance to a specific amount (admin only)
func AdminSetCredits(c echo.Context) error {
	// Get authenticated admin username
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	// Check admin privileges
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify admin privileges")
	}
	if !adminUser.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target username from URL parameter
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	// Verify target user exists
	_, err = models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user")
	}

	// Parse request
	var req AdminSetCreditsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Parse balance
	balanceCents, err := models.ParseCreditsFromUSD(req.BalanceUSD)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid balance format")
	}

	// Validate reason
	if req.Reason == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Reason is required for balance adjustments")
	}

	// Set the balance
	transaction, err := models.SetCredits(
		database.DB, targetUsername, balanceCents,
		req.Reason, adminUsername,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Admin balance set failed: admin=%s, target=%s, balance=%d, error=%v",
			adminUsername, targetUsername, balanceCents, err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get updated balance for response
	updatedCredits, err := models.GetUserCredits(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get updated credits after balance set: %v", err)
		// Don't fail the request, just log the error
	}

	response := map[string]interface{}{
		"success":           true,
		"target_username":   targetUsername,
		"operation":         "set_balance",
		"new_balance_usd":   req.BalanceUSD,
		"new_balance_cents": balanceCents,
		"transaction":       transaction,
		"admin_info": map[string]interface{}{
			"adjusted_by": adminUsername,
			"reason":      req.Reason,
		},
	}

	// Include updated balance if available
	if updatedCredits != nil {
		response["updated_balance"] = updatedCredits
		response["formatted_balance"] = models.FormatCreditsUSD(updatedCredits.BalanceUSDCents)
	}

	return c.JSON(http.StatusOK, response)
}

// AdminGetAllCredits returns credit balances for all users (admin only)
func AdminGetAllCredits(c echo.Context) error {
	// Get authenticated admin username
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	// Check admin privileges
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify admin privileges")
	}
	if !adminUser.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get all user credits
	allCredits, err := models.GetAllUserCredits(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Admin failed to get all user credits: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve credit information")
	}

	// Format credits for display
	var formattedCredits []map[string]interface{}
	totalBalance := int64(0)

	for _, credit := range allCredits {
		totalBalance += credit.BalanceUSDCents
		formattedCredits = append(formattedCredits, map[string]interface{}{
			"username":          credit.Username,
			"balance_cents":     credit.BalanceUSDCents,
			"formatted_balance": models.FormatCreditsUSD(credit.BalanceUSDCents),
			"created_at":        credit.CreatedAt,
			"updated_at":        credit.UpdatedAt,
		})
	}

	// Log admin access
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":  "admin_view_all_credits",
			"user_count": len(allCredits),
		},
	)

	response := map[string]interface{}{
		"success": true,
		"users":   formattedCredits,
		"summary": map[string]interface{}{
			"total_users":             len(allCredits),
			"total_balance_cents":     totalBalance,
			"total_balance_formatted": models.FormatCreditsUSD(totalBalance),
		},
		"admin_info": map[string]interface{}{
			"viewed_by": adminUsername,
		},
	}

	return c.JSON(http.StatusOK, response)
}
