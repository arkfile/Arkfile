package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

// betaDisclaimer is the always-present disclaimer surfaced on every credits
// response and on the /billing page. Its presence is asserted by tests as a
// regression guard so it is never silently removed before the deployment
// transitions out of beta.
const betaDisclaimer = "Beta tester credit: balances reflect what you would owe in a paid deployment. No real charges occur during the beta."

// GetUserCredits returns the current user's signed microcent balance, the
// transaction history, and -- once the billing meter is wired in (Section D)
// -- the current_usage and credits_runway blocks. The beta_disclaimer field
// is always present.
func GetUserCredits(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	limit := paginationLimit(c, 20, 100)
	offset := paginationOffset(c)

	summary, err := models.GetUserCreditsSummary(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get credits summary for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve credit information")
	}

	transactions, err := models.GetUserTransactions(database.DB, username, limit, offset)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get transactions for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve transaction history")
	}

	currentUsage, creditsRunway := buildBillingProjection(database.DB, username, summary.Balance.BalanceUSDMicrocents)

	response := map[string]interface{}{
		"username":               username,
		"balance_usd_microcents": summary.Balance.BalanceUSDMicrocents,
		"formatted_balance":      summary.FormattedBalance,
		"current_usage":          currentUsage,
		"credits_runway":         creditsRunway,
		"beta_disclaimer":        betaDisclaimer,
		"transactions":           transactions,
		"pagination": map[string]interface{}{
			"limit":  limit,
			"offset": offset,
			"count":  len(transactions),
		},
	}

	return c.JSON(http.StatusOK, response)
}

// AdminGetUserCredits returns the credit information for a specific user.
// Requires admin privileges. Includes the current_usage and credits_runway
// blocks plus the always-present beta_disclaimer.
func AdminGetUserCredits(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify admin privileges")
	}
	if !adminUser.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	if _, err := models.GetUserByUsername(database.DB, targetUsername); err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user")
	}

	limit := paginationLimit(c, 50, 200)
	offset := paginationOffset(c)

	summary, err := models.GetUserCreditsSummary(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin failed to get credits summary for user %s: %v", targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve credit information")
	}

	transactions, err := models.GetUserTransactions(database.DB, targetUsername, limit, offset)
	if err != nil {
		logging.ErrorLogger.Printf("Admin failed to get transactions for user %s: %v", targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve transaction history")
	}

	currentUsage, creditsRunway := buildBillingProjection(database.DB, targetUsername, summary.Balance.BalanceUSDMicrocents)

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
		"target_username":        targetUsername,
		"balance_usd_microcents": summary.Balance.BalanceUSDMicrocents,
		"formatted_balance":      summary.FormattedBalance,
		"current_usage":          currentUsage,
		"credits_runway":         creditsRunway,
		"beta_disclaimer":        betaDisclaimer,
		"transactions":           transactions,
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

// AdminGetAllCredits returns the credit balances for every user, plus a
// per-user current_usage block and aggregate totals. Requires admin privileges.
// Negative balances are rendered with a leading "-".
func AdminGetAllCredits(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify admin privileges")
	}
	if !adminUser.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	allCredits, err := models.GetAllUserCredits(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Admin failed to get all user credits: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve credit information")
	}

	formattedCredits := make([]map[string]interface{}, 0, len(allCredits))
	totalBalance := int64(0)

	for _, credit := range allCredits {
		totalBalance += credit.BalanceUSDMicrocents
		// per-user current_usage (cheap: one users-row read + one rate read)
		currentUsage, _ := buildBillingProjection(database.DB, credit.Username, credit.BalanceUSDMicrocents)
		formattedCredits = append(formattedCredits, map[string]interface{}{
			"username":               credit.Username,
			"balance_usd_microcents": credit.BalanceUSDMicrocents,
			"formatted_balance":      models.FormatCreditsUSD(credit.BalanceUSDMicrocents),
			"current_usage":          currentUsage,
			"created_at":             credit.CreatedAt,
			"updated_at":             credit.UpdatedAt,
		})
	}

	overdrawnCount, err := models.CountOverdrawnUsers(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Admin failed to count overdrawn users: %v", err)
		// non-fatal: report -1 so the field's presence is preserved
		overdrawnCount = -1
	}

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
			"total_users":                  len(allCredits),
			"total_balance_usd_microcents": totalBalance,
			"total_balance_formatted":      models.FormatCreditsUSD(totalBalance),
			"users_currently_overdrawn":    overdrawnCount,
		},
		"beta_disclaimer": betaDisclaimer,
		"admin_info": map[string]interface{}{
			"viewed_by": adminUsername,
		},
	}

	return c.JSON(http.StatusOK, response)
}

// paginationLimit reads the `limit` query param, clamping into [1, max] with
// the given default when missing or invalid.
func paginationLimit(c echo.Context, defaultLimit, max int) int {
	if s := c.QueryParam("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= max {
			return n
		}
	}
	return defaultLimit
}

// paginationOffset reads the `offset` query param, returning 0 when missing
// or invalid.
func paginationOffset(c echo.Context) int {
	if s := c.QueryParam("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return n
		}
	}
	return 0
}
