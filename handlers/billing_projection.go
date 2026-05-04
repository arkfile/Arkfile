package handlers

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/models"
)

// buildBillingProjection assembles the `current_usage` and `credits_runway`
// blocks returned by /api/credits and /api/admin/credits/:username. The
// projection is computed at request time from the user's current
// total_storage_bytes, the per-instance free baseline, and the live customer
// price (resolved by the billing package).
//
// Returns two map[string]interface{} blocks ready for JSON serialization.
//
// When the billing meter is disabled or the rate is not resolvable yet (for
// example, during the brief startup window before the scheduler
// populates billing_settings), the rate-dependent fields fall back to safe
// defaults (zero cost, nil runway) and the response remains structurally
// identical so frontend/tests do not branch on enabled/disabled.
func buildBillingProjection(db *sql.DB, username string, balanceMicrocents int64) (map[string]interface{}, map[string]interface{}) {
	totalStorageBytes := getUserTotalStorageBytes(db, username)
	freeBaseline := freeBaselineBytes()

	billable := totalStorageBytes - freeBaseline
	if billable < 0 {
		billable = 0
	}

	rateMicrocentsPerGiBPerHour, customerPrice, rateAvailable := resolveBillingRate(db)

	currentUsage := map[string]interface{}{
		"total_storage_bytes":              totalStorageBytes,
		"free_baseline_bytes":              freeBaseline,
		"billable_bytes":                   billable,
		"rate_microcents_per_gib_per_hour": rateMicrocentsPerGiBPerHour,
		"rate_human":                       formatRateHuman(customerPrice),
	}

	// Cost projection (per-month, assuming 30 days = 720 hours).
	if billable > 0 && rateAvailable {
		hourlyMicrocents := (billable * rateMicrocentsPerGiBPerHour) >> 30
		monthlyMicrocents := hourlyMicrocents * 720
		currentUsage["current_cost_per_month_microcents"] = monthlyMicrocents
		currentUsage["current_cost_per_month_usd_approx"] = "~" + models.FormatCreditsUSD(monthlyMicrocents)
	} else {
		currentUsage["current_cost_per_month_microcents"] = int64(0)
		if billable == 0 {
			currentUsage["current_cost_per_month_usd_approx"] = "~$0.0000"
		} else {
			// billing rate not yet available
			currentUsage["current_cost_per_month_usd_approx"] = "~$0.0000"
		}
	}

	// Runway projection.
	creditsRunway := buildCreditsRunway(balanceMicrocents, billable, rateMicrocentsPerGiBPerHour, rateAvailable)
	return currentUsage, creditsRunway
}

// buildCreditsRunway computes how long the user's positive balance will last
// at their current burn rate. Returns the negative-balance variant when
// `balanceMicrocents < 0`, the at-baseline variant when there is no billable
// usage, and the projection otherwise.
func buildCreditsRunway(balanceMicrocents, billableBytes, rateMicrocentsPerGiBPerHour int64, rateAvailable bool) map[string]interface{} {
	now := time.Now().UTC()

	if balanceMicrocents < 0 {
		return map[string]interface{}{
			"estimated_hours_remaining": int64(0),
			"note":                      "Balance is negative; charges continue to accumulate.",
			"computed_at":               now.Format(time.RFC3339),
		}
	}
	if billableBytes == 0 {
		return map[string]interface{}{
			"estimated_hours_remaining": nil,
			"note":                      "You are within the free baseline. No usage charges apply.",
			"computed_at":               now.Format(time.RFC3339),
		}
	}
	if !rateAvailable || rateMicrocentsPerGiBPerHour <= 0 {
		return map[string]interface{}{
			"estimated_hours_remaining": nil,
			"note":                      "Billing rate not yet resolved.",
			"computed_at":               now.Format(time.RFC3339),
		}
	}

	hourlyChargeMicrocents := (billableBytes * rateMicrocentsPerGiBPerHour) >> 30
	if hourlyChargeMicrocents <= 0 {
		// Below the per-tick truncation threshold: effectively free.
		return map[string]interface{}{
			"estimated_hours_remaining": nil,
			"note":                      "Hourly charge rounds to zero at current usage.",
			"computed_at":               now.Format(time.RFC3339),
		}
	}

	hoursRemaining := balanceMicrocents / hourlyChargeMicrocents
	runsOutAt := now.Add(time.Duration(hoursRemaining) * time.Hour)

	return map[string]interface{}{
		"estimated_hours_remaining":    hoursRemaining,
		"estimated_runs_out_at_approx": runsOutAt.Format(time.RFC3339),
		"computed_at":                  now.Format(time.RFC3339),
	}
}

// getUserTotalStorageBytes reads the user's currently-stored bytes. Returns
// 0 on any error (including "user not found"); callers display the response
// gracefully rather than failing.
func getUserTotalStorageBytes(db *sql.DB, username string) int64 {
	var f float64
	err := db.QueryRow(`SELECT total_storage_bytes FROM users WHERE username = ?`, username).Scan(&f)
	if err != nil {
		return 0
	}
	return int64(f)
}

// freeBaselineBytes returns the per-instance ARKFILE_FREE_STORAGE_BYTES.
// Defaults to 1181116006 (1.1 GiB) to match models.DefaultStorageLimit.
//
// This wrapper exists so Section D can swap in a typed config-driven version
// without revisiting handler call sites.
func freeBaselineBytes() int64 {
	return billingFreeBaselineBytes()
}

// resolveBillingRate is the seam between the handlers and the billing
// package. Section D replaces this with a real call to billing.ResolveRate.
// Until then the seam returns zeros (rateAvailable=false), which is exercised
// by the projection-builder paths above.
func resolveBillingRate(db *sql.DB) (rateMicrocentsPerGiBPerHour int64, customerPriceUSDPerTBPerMonth string, rateAvailable bool) {
	return billingResolveRate(db)
}

// formatRateHuman renders the customer price as "$10.00/TiB/month" or returns
// an empty string when no price is yet resolved.
func formatRateHuman(price string) string {
	if price == "" {
		return ""
	}
	return fmt.Sprintf("$%s/TiB/month", price)
}

// Default seams. Section D overrides these via the Set* functions below,
// which main.go calls during startup.

var (
	// billingFreeBaselineBytes returns the configured free baseline bytes.
	// Default before main.go wires it: matches the in-DB default storage limit.
	billingFreeBaselineBytes = func() int64 {
		return defaultFreeBaselineBytes
	}

	// billingResolveRate returns the live rate from billing_settings.
	// Default before main.go wires it: rate not yet available.
	billingResolveRate = func(db *sql.DB) (int64, string, bool) {
		return 0, "", false
	}

	// billingGiftFn calls billing.GiftCredits. Wired by main.go to avoid an
	// import cycle (handlers must not import billing directly because billing
	// imports models which... etc; the seam keeps the dependency arrow correct).
	billingGiftFn func(db *sql.DB, username string, amountUSDMicrocents int64, reason, adminUsername string) (*models.CreditTransaction, error)

	// billingSetPriceFn calls billing.SetCustomerPrice and returns the new
	// (microcents/GiB/hour, customer-price-string, error).
	billingSetPriceFn func(db *sql.DB, priceStr, updatedBy string) (int64, string, error)

	// billingTickNowFn forces an immediate tick of all active users
	// (dev/test API).
	billingTickNowFn func(db *sql.DB) error

	// billingSweepNowFn forces an immediate sweep of all accumulator rows
	// (dev/test API).
	billingSweepNowFn func(db *sql.DB) error
)

// defaultFreeBaselineBytes mirrors models.DefaultStorageLimit so the seam
// resolves to a sensible value before main.go wires BillingConfig.
const defaultFreeBaselineBytes int64 = 1181116006

// SetBillingProjectionSeams wires the projection helpers to the live billing
// package. Called once from main.go during startup.
func SetBillingProjectionSeams(
	freeBaseline func() int64,
	resolveRate func(db *sql.DB) (int64, string, bool),
) {
	if freeBaseline != nil {
		billingFreeBaselineBytes = freeBaseline
	}
	if resolveRate != nil {
		billingResolveRate = resolveRate
	}
}

// SetBillingGiftFunc wires the billing.GiftCredits call.
func SetBillingGiftFunc(fn func(db *sql.DB, username string, amountUSDMicrocents int64, reason, adminUsername string) (*models.CreditTransaction, error)) {
	billingGiftFn = fn
}

// SetBillingSetPriceFunc wires the billing.SetCustomerPrice call.
func SetBillingSetPriceFunc(fn func(db *sql.DB, priceStr, updatedBy string) (int64, string, error)) {
	billingSetPriceFn = fn
}

// SetBillingTickNowFunc wires the dev/test "tick now" call.
func SetBillingTickNowFunc(fn func(db *sql.DB) error) {
	billingTickNowFn = fn
}

// SetBillingSweepNowFunc wires the dev/test "sweep now" call.
func SetBillingSweepNowFunc(fn func(db *sql.DB) error) {
	billingSweepNowFn = fn
}

// silence the unused-import linter when database isn't yet used (it is
// referenced through the *sql.DB parameter; this assertion documents intent).
var _ = database.DB
