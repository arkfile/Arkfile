package handlers

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/arkfile/Arkfile/billing"
	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/models"
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
	freeBaseline := billing.EffectiveFreeBaseline(db, username)

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

	effectiveLimit, _ := billing.EffectiveStorageLimit(db, username)
	currentUsage["effective_storage_limit_bytes"] = effectiveLimit

	// Cost projection (per-month, assuming 30 days = 720 hours).
	if billable > 0 && rateAvailable && billing.ShouldMeter(db, username) {
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
	creditsRunway := buildCreditsRunway(balanceMicrocents, billable, rateMicrocentsPerGiBPerHour, rateAvailable && billing.ShouldMeter(db, username))
	return currentUsage, creditsRunway
}

func buildSubscriptionProjection(db *sql.DB, username string) (map[string]interface{}, string) {
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Subscriptions.Enabled {
		return nil, ""
	}

	mode := string(billing.EffectiveBillingMode(db, username))
	sub, _ := billing.GetActiveSubscription(db, username)
	user, uerr := models.GetUserByUsername(db, username)
	baseline := int64(models.DefaultStorageLimit)
	if uerr == nil {
		baseline = user.StorageLimitBytes
	}

	block := map[string]interface{}{
		"enabled": true,
	}
	if sub != nil {
		effectiveLimit, _ := billing.EffectiveStorageLimit(db, username)
		block["status"] = sub.Status
		block["plan_id"] = sub.PlanID
		block["plan_name"] = sub.PlanName
		block["price_usd"] = models.FormatPlanPriceUSD(sub.PlanPriceUSDCents)
		block["baseline_storage_bytes"] = baseline
		block["plan_storage_bytes"] = sub.PlanStorageBytes
		block["effective_storage_limit_bytes"] = effectiveLimit
		block["current_period_end"] = sub.CurrentPeriodEnd.UTC().Format(time.RFC3339)
		block["cancel_at_period_end"] = sub.CancelAtPeriodEnd
		block["source"] = sub.Source
	}
	return block, mode
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
// Defaults to 1073741824 (1 GiB) to match models.DefaultStorageLimit.
// The indirection keeps configuration wiring outside the handler package.
func freeBaselineBytes() int64 {
	return billingFreeBaselineBytes()
}

// resolveBillingRate is the configured seam between handlers and the billing
// package.
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

// Default seams are replaced through the Set* functions during startup.

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

	// ProcessPaymentFunc handles actual balance credit operations securely within a strict SQLite transaction bracket.
	ProcessPaymentFunc func(db *sql.DB, username string, amountUSDMicrocents int64, providerTxID string, paymentType string) (*models.CreditTransaction, error)

	// SettlePaymentInvoiceFunc credits the user and marks a payment invoice paid atomically.
	SettlePaymentInvoiceFunc func(db *sql.DB, invoice *models.PaymentInvoice, paymentType string) (*models.CreditTransaction, error)
)

// defaultFreeBaselineBytes mirrors models.DefaultStorageLimit so the seam
// resolves to a sensible value before main.go wires BillingConfig.
const defaultFreeBaselineBytes int64 = 1073741824

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

// SetProcessPaymentFunc wires the billing.ProcessPayment call.
func SetProcessPaymentFunc(fn func(db *sql.DB, username string, amountUSDMicrocents int64, providerTxID string, paymentType string) (*models.CreditTransaction, error)) {
	ProcessPaymentFunc = fn
}

// SetSettlePaymentInvoiceFunc wires the billing.SettlePaymentInvoice call.
func SetSettlePaymentInvoiceFunc(fn func(db *sql.DB, invoice *models.PaymentInvoice, paymentType string) (*models.CreditTransaction, error)) {
	SettlePaymentInvoiceFunc = fn
}

// silence the unused-import linter when database isn't yet used (it is
// referenced through the *sql.DB parameter; this assertion documents intent).
var _ = database.DB
