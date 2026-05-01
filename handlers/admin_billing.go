package handlers

// Admin billing endpoints. The actual billing math (rate computation, tick,
// sweep, gift) lives in the billing/ package. These handlers are thin
// adapters that call into the function-pointer seams wired from main.go
// (see handlers/billing_projection.go for the seam definitions and §11.2 of
// docs/wip/storage-credits-v2.md for the architectural rationale).

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/models"
)

// AdminGetBillingPrice returns the current customer price and the derived
// internal rate. Read-only; safe for any admin to call.
//
// GET /api/admin/billing/price
func AdminGetBillingPrice(c echo.Context) error {
	if errResp := requireAdmin(c); errResp != nil {
		return errResp
	}

	rateMicrocentsPerGiBPerHour, customerPrice, available := resolveBillingRate(database.DB)
	resp := map[string]interface{}{
		"customer_price_usd_per_tb_per_month": customerPrice,
		"microcents_per_gib_per_hour":         rateMicrocentsPerGiBPerHour,
		"rate_human":                          formatRateHuman(customerPrice),
		"available":                           available,
		"resolved_at":                         time.Now().UTC().Format(time.RFC3339),
	}
	return JSONResponse(c, http.StatusOK, "Billing price retrieved", resp)
}

// AdminSetBillingPrice updates the customer price and atomically swaps the
// cached billing rate. The next tick observes the new rate.
//
// POST /api/admin/billing/set-price
// Body: { "customer_price_usd_per_tb_per_month": "19.99" }
func AdminSetBillingPrice(c echo.Context) error {
	adminUsername, errResp := requireAdminWithUsername(c)
	if errResp != nil {
		return errResp
	}

	if billingSetPriceFn == nil {
		return JSONError(c, http.StatusServiceUnavailable, "Billing not initialized")
	}

	var req struct {
		CustomerPriceUSDPerTBPerMonth string `json:"customer_price_usd_per_tb_per_month"`
	}
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request body")
	}
	priceStr := strings.TrimSpace(req.CustomerPriceUSDPerTBPerMonth)
	if priceStr == "" {
		return JSONError(c, http.StatusBadRequest, "customer_price_usd_per_tb_per_month is required")
	}

	// Capture previous rate for the response (so the operator sees both before/after).
	previousRate, previousPrice, _ := resolveBillingRate(database.DB)

	newRate, newPrice, err := billingSetPriceFn(database.DB, priceStr, adminUsername)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, fmt.Sprintf("Failed to set price: %v", err))
	}

	LogAdminAction(database.DB, adminUsername, "billing_set_price", "",
		fmt.Sprintf("price: %s -> %s (rate: %d -> %d microcents/GiB/hour)",
			previousPrice, newPrice, previousRate, newRate))

	return JSONResponse(c, http.StatusOK, "Billing price updated", map[string]interface{}{
		"previous_customer_price_usd_per_tb_per_month": previousPrice,
		"previous_microcents_per_gib_per_hour":         previousRate,
		"customer_price_usd_per_tb_per_month":          newPrice,
		"microcents_per_gib_per_hour":                  newRate,
		"rate_human":                                   formatRateHuman(newPrice),
		"updated_at":                                   time.Now().UTC().Format(time.RFC3339),
	})
}

// AdminGetBillingSweepSummary returns per-day aggregates of recent 'usage'
// transactions plus a point-in-time count of users currently in the negative.
// Used by the operator UI to spot trends.
//
// GET /api/admin/billing/sweep-summary?days=7
func AdminGetBillingSweepSummary(c echo.Context) error {
	if errResp := requireAdmin(c); errResp != nil {
		return errResp
	}

	days := 7
	if d := c.QueryParam("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	rows, err := database.DB.Query(`
		SELECT date(created_at) AS day,
		       COUNT(*) AS users_settled,
		       SUM(-amount_usd_microcents) AS total_drained_microcents
		FROM credit_transactions
		WHERE transaction_type = ?
		  AND created_at >= ?
		GROUP BY day
		ORDER BY day DESC`,
		models.TransactionTypeUsage, cutoff,
	)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to query sweep summary: %v", err))
	}
	defer rows.Close()

	type daySummary struct {
		Day                    string `json:"day"`
		UsersSettled           int    `json:"users_settled"`
		TotalDrainedMicrocents int64  `json:"total_drained_microcents"`
		TotalDrainedUSD        string `json:"total_drained_usd"`
	}
	out := []daySummary{}
	for rows.Next() {
		var d daySummary
		if scanErr := rows.Scan(&d.Day, &d.UsersSettled, &d.TotalDrainedMicrocents); scanErr != nil {
			return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to scan sweep summary: %v", scanErr))
		}
		d.TotalDrainedUSD = models.FormatCreditsUSD(d.TotalDrainedMicrocents)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to iterate sweep summary: %v", err))
	}

	negativeCount, _ := models.CountOverdrawnUsers(database.DB)

	return JSONResponse(c, http.StatusOK, "Sweep summary retrieved", map[string]interface{}{
		"days":                      days,
		"per_day":                   out,
		"users_currently_negative":  negativeCount,
		"users_currently_overdrawn": negativeCount, // duplicate alias for the CLI
	})
}

// AdminGetBillingOverdrawn lists every user with a negative balance.
//
// GET /api/admin/billing/overdrawn
func AdminGetBillingOverdrawn(c echo.Context) error {
	if errResp := requireAdmin(c); errResp != nil {
		return errResp
	}

	users, err := models.GetOverdrawnUsers(database.DB)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to list overdrawn users: %v", err))
	}

	type row struct {
		Username             string `json:"username"`
		BalanceUSDMicrocents int64  `json:"balance_usd_microcents"`
		FormattedBalance     string `json:"formatted_balance"`
		UpdatedAt            string `json:"updated_at"`
	}
	out := make([]row, 0, len(users))
	for _, u := range users {
		out = append(out, row{
			Username:             u.Username,
			BalanceUSDMicrocents: u.BalanceUSDMicrocents,
			FormattedBalance:     models.FormatCreditsUSD(u.BalanceUSDMicrocents),
			UpdatedAt:            u.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}

	return JSONResponse(c, http.StatusOK, "Overdrawn users retrieved", map[string]interface{}{
		"users":                     out,
		"users_currently_overdrawn": len(out),
	})
}

// AdminBillingGift adds positive microcent credit to a user's balance and
// writes a typed 'gift' transaction. Replaces the old POST /api/admin/credits
// endpoint (deleted in Section B+C); this is the only path for any admin-
// initiated positive balance adjustment.
//
// POST /api/admin/billing/gift
// Body: { "target_username": "...", "amount_usd": "5.00", "reason": "..." }
func AdminBillingGift(c echo.Context) error {
	adminUsername, errResp := requireAdminWithUsername(c)
	if errResp != nil {
		return errResp
	}

	if billingGiftFn == nil {
		return JSONError(c, http.StatusServiceUnavailable, "Billing not initialized")
	}

	var req struct {
		TargetUsername string `json:"target_username"`
		AmountUSD      string `json:"amount_usd"`
		Reason         string `json:"reason"`
	}
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request body")
	}
	req.TargetUsername = strings.TrimSpace(req.TargetUsername)
	req.AmountUSD = strings.TrimSpace(req.AmountUSD)
	req.Reason = strings.TrimSpace(req.Reason)

	if req.TargetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "target_username is required")
	}
	if req.AmountUSD == "" {
		return JSONError(c, http.StatusBadRequest, "amount_usd is required")
	}
	if req.Reason == "" {
		return JSONError(c, http.StatusBadRequest, "reason is required")
	}

	amountMicrocents, err := models.ParseCreditsFromUSD(req.AmountUSD)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, fmt.Sprintf("Invalid amount_usd: %v", err))
	}
	if amountMicrocents <= 0 {
		return JSONError(c, http.StatusBadRequest, "amount_usd must be positive")
	}

	// Verify the target user exists (early friendly error rather than a
	// foreign-key surprise from inside the gift transaction).
	if _, err := models.GetUserByUsername(database.DB, req.TargetUsername); err != nil {
		if err == sql.ErrNoRows {
			return JSONError(c, http.StatusNotFound, "Target user not found")
		}
		return JSONError(c, http.StatusInternalServerError, "Failed to look up target user")
	}

	tx, err := billingGiftFn(database.DB, req.TargetUsername, amountMicrocents, req.Reason, adminUsername)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to gift credits: %v", err))
	}

	LogAdminAction(database.DB, adminUsername, "billing_gift", req.TargetUsername,
		fmt.Sprintf("amount: %s, reason: %s", models.FormatCreditsUSD(amountMicrocents), req.Reason))

	return JSONResponse(c, http.StatusOK, "Credits gifted", map[string]interface{}{
		"transaction": map[string]interface{}{
			"id":                           tx.ID,
			"username":                     tx.Username,
			"amount_usd_microcents":        tx.AmountUSDMicrocents,
			"formatted_amount":             models.FormatCreditsUSD(tx.AmountUSDMicrocents),
			"balance_after_usd_microcents": tx.BalanceAfterUSDMicrocents,
			"formatted_balance_after":      models.FormatCreditsUSD(tx.BalanceAfterUSDMicrocents),
			"transaction_type":             tx.TransactionType,
			"reason":                       tx.Reason,
			"admin_username":               tx.AdminUsername,
			"created_at":                   tx.CreatedAt.UTC().Format(time.RFC3339),
		},
		"updated_balance_usd_microcents": tx.BalanceAfterUSDMicrocents,
		"formatted_updated_balance":      models.FormatCreditsUSD(tx.BalanceAfterUSDMicrocents),
	})
}

// AdminBillingTickNow forces an immediate tick (and optional sweep) of every
// active billable user. Intended for the e2e billing test in
// scripts/testing/e2e-test.sh; gated to ADMIN_DEV_TEST_API_ENABLED so it is
// physically not registered as a route in production-flavored deployments
// (see route_config.go for the gating).
//
// POST /api/admin/billing/tick-now
// Body: { "sweep": false }
func AdminBillingTickNow(c echo.Context) error {
	adminUsername, errResp := requireAdminWithUsername(c)
	if errResp != nil {
		return errResp
	}

	if billingTickNowFn == nil || billingSweepNowFn == nil {
		return JSONError(c, http.StatusServiceUnavailable, "Billing not initialized")
	}

	var req struct {
		Sweep bool `json:"sweep"`
	}
	if err := c.Bind(&req); err != nil {
		// Body is optional; keep req.Sweep at its zero value on bind error.
	}

	if err := billingTickNowFn(database.DB); err != nil {
		return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to tick: %v", err))
	}
	swept := false
	if req.Sweep {
		if err := billingSweepNowFn(database.DB); err != nil {
			return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Tick succeeded but sweep failed: %v", err))
		}
		swept = true
	}

	LogAdminAction(database.DB, adminUsername, "billing_tick_now", "",
		fmt.Sprintf("sweep: %t", req.Sweep))

	return JSONResponse(c, http.StatusOK, "Tick-now completed", map[string]interface{}{
		"ticked":    true,
		"swept":     swept,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// requireAdmin returns nil when the caller is a verified admin; otherwise
// returns the JSON error response that should be returned from the handler.
// Used by handlers that don't need the admin's username for logging.
func requireAdmin(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return JSONError(c, http.StatusUnauthorized, "Authentication required")
	}
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to get admin user")
	}
	if !adminUser.IsAdmin {
		return JSONError(c, http.StatusForbidden, "Admin privileges required")
	}
	return nil
}

// requireAdminWithUsername is the same as requireAdmin but also returns the
// admin's username for use in LogAdminAction.
func requireAdminWithUsername(c echo.Context) (string, error) {
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return "", JSONError(c, http.StatusUnauthorized, "Authentication required")
	}
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return "", JSONError(c, http.StatusInternalServerError, "Failed to get admin user")
	}
	if !adminUser.IsAdmin {
		return "", JSONError(c, http.StatusForbidden, "Admin privileges required")
	}
	return adminUsername, nil
}
