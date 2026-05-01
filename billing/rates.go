package billing

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

// Rate is the fully-resolved billing rate, ready for use by TickUser.
type Rate struct {
	// MicrocentsPerGiBPerHour is the canonical internal unit. All per-tick
	// math uses this directly.
	MicrocentsPerGiBPerHour int64

	// CustomerPriceUSDPerTBPerMonth is the dollars-and-cents string that the
	// operator set (e.g. "10.00", "19.99"). Used for human-readable display.
	CustomerPriceUSDPerTBPerMonth string

	// ResolvedAt is when this rate was last read from billing_settings.
	ResolvedAt time.Time
}

// FormatHumanReadable returns "$10.00/TiB/month".
func (r *Rate) FormatHumanReadable() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("$%s/TiB/month", r.CustomerPriceUSDPerTBPerMonth)
}

// BillingSettingsKeyCustomerPrice is the row key in billing_settings.
const BillingSettingsKeyCustomerPrice = "customer_price_usd_per_tb_per_month"

// HardcodedSafetyPriceUSDPerTBPerMonth is the last-resort fallback used when
// neither billing_settings nor the env var contain a parseable price. The
// meter logs ERROR and continues running so it never silently stops billing.
const HardcodedSafetyPriceUSDPerTBPerMonth = "10.00"

// cachedRate is the live rate atomically swapped by SetCachedRate and read by
// each tick. nil = "not yet resolved", caller falls back to ResolveRate.
var cachedRate atomic.Pointer[Rate]

// CachedRate returns the live cached rate, or nil if not yet resolved.
// Cheap; safe to call from hot paths.
func CachedRate() *Rate {
	return cachedRate.Load()
}

// SetCachedRate atomically swaps the cached rate. Called by ResolveRate after
// a successful read and by the admin set-price endpoint immediately on update.
func SetCachedRate(r *Rate) {
	cachedRate.Store(r)
}

// ResolveRate reads the customer price from billing_settings, parses it,
// computes the internal rate, caches the result, and returns it.
//
// Resolution order:
//  1. billing_settings row (authoritative).
//  2. cfg.Billing.CustomerPriceUSDPerTBPerMonth (env-var-derived seed).
//  3. HardcodedSafetyPriceUSDPerTBPerMonth ("10.00").
//
// Each fallback step logs an ERROR so silent degradation is visible.
func ResolveRate(db *sql.DB, cfg config.BillingConfig) (*Rate, error) {
	priceStr, err := readCustomerPriceFromDB(db)
	if err == nil && priceStr != "" {
		return finalizeRate(priceStr)
	}
	if err != nil && err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("billing: failed to read %s from billing_settings: %v",
			BillingSettingsKeyCustomerPrice, err)
	}

	// Fallback 1: env-var-derived seed.
	if cfg.CustomerPriceUSDPerTBPerMonth != "" {
		logging.ErrorLogger.Printf(
			"billing: billing_settings missing %s; falling back to ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH=%q",
			BillingSettingsKeyCustomerPrice, cfg.CustomerPriceUSDPerTBPerMonth)
		return finalizeRate(cfg.CustomerPriceUSDPerTBPerMonth)
	}

	// Fallback 2: hardcoded safety value.
	logging.ErrorLogger.Printf(
		"billing: no customer price configured anywhere; falling back to safety value %q",
		HardcodedSafetyPriceUSDPerTBPerMonth)
	return finalizeRate(HardcodedSafetyPriceUSDPerTBPerMonth)
}

// SeedCustomerPriceIfMissing inserts the env-derived customer price into
// billing_settings only if no row exists yet. Idempotent. Called once at
// startup. Returns the seeded (or already-present) price string.
func SeedCustomerPriceIfMissing(db *sql.DB, cfg config.BillingConfig) (string, error) {
	existing, err := readCustomerPriceFromDB(db)
	if err == nil && existing != "" {
		return existing, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("billing: failed to read existing customer price: %w", err)
	}

	price := cfg.CustomerPriceUSDPerTBPerMonth
	if price == "" {
		price = HardcodedSafetyPriceUSDPerTBPerMonth
	}

	// Validate before persisting.
	if _, perr := models.ParseCreditsFromUSD(price); perr != nil {
		return "", fmt.Errorf("billing: invalid seed price %q: %w", price, perr)
	}

	_, err = db.Exec(
		`INSERT INTO billing_settings (key, value, updated_at, updated_by)
		 VALUES (?, ?, CURRENT_TIMESTAMP, ?)`,
		BillingSettingsKeyCustomerPrice, price, "system-seed",
	)
	if err != nil {
		return "", fmt.Errorf("billing: failed to seed customer price: %w", err)
	}
	logging.InfoLogger.Printf("billing: seeded billing_settings.%s = %q", BillingSettingsKeyCustomerPrice, price)
	return price, nil
}

// SetCustomerPrice persists a new customer price to billing_settings, atomically
// updates the cached rate, and returns the resolved Rate. The atomic swap
// ensures the very next tick observes the new rate.
//
// Validates that priceStr parses as positive dollars-and-cents.
func SetCustomerPrice(db *sql.DB, priceStr, updatedBy string) (*Rate, error) {
	microcents, err := models.ParseCreditsFromUSD(priceStr)
	if err != nil {
		return nil, fmt.Errorf("invalid price string: %w", err)
	}
	if microcents <= 0 {
		return nil, errors.New("price must be greater than zero")
	}

	// Upsert: SQLite/rqlite "ON CONFLICT(key) DO UPDATE" pattern.
	_, err = db.Exec(`
		INSERT INTO billing_settings (key, value, updated_at, updated_by)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?)
		ON CONFLICT(key) DO UPDATE SET
		  value = excluded.value,
		  updated_at = CURRENT_TIMESTAMP,
		  updated_by = excluded.updated_by`,
		BillingSettingsKeyCustomerPrice, priceStr, updatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to persist customer price: %w", err)
	}

	rate, err := finalizeRate(priceStr)
	if err != nil {
		return nil, err
	}
	logging.InfoLogger.Printf("billing: set customer price to %q (%d microcents/GiB/hour) by %s",
		priceStr, rate.MicrocentsPerGiBPerHour, updatedBy)
	return rate, nil
}

// finalizeRate parses, converts, caches, and returns. Pure helper; never reads DB.
func finalizeRate(priceStr string) (*Rate, error) {
	rate, err := computeRate(priceStr)
	if err != nil {
		return nil, err
	}
	SetCachedRate(rate)
	return rate, nil
}

// computeRate converts a customer price string (USD per TiB per month) into
// the internal rate (microcents per GiB per hour).
//
// Math (floor-rounded so the derived rate never exceeds the operator's stated price):
//
//	microcents_per_TiB_per_month = price_microcents
//	microcents_per_GiB_per_hour  = floor(microcents_per_TiB_per_month / 1024 / 720)
//	                                                                 ^TiB->GiB ^days*hours
//
// Worked examples (binary GiB = 2^30, 30-day month = 720 hours):
//
//	$10.00 -> 1,000,000,000 microcents/TiB/month -> 1,356 microcents/GiB/hour
//	$19.99 -> 1,999,000,000                      -> 2,711
//	$20.00 -> 2,000,000,000                      -> 2,712
//	$24.99 -> 2,499,000,000                      -> 3,389
func computeRate(priceStr string) (*Rate, error) {
	priceStr = strings.TrimSpace(priceStr)
	if priceStr == "" {
		return nil, errors.New("price string is empty")
	}
	priceMicrocents, err := models.ParseCreditsFromUSD(priceStr)
	if err != nil {
		return nil, fmt.Errorf("invalid price %q: %w", priceStr, err)
	}
	if priceMicrocents <= 0 {
		return nil, fmt.Errorf("price must be positive, got %q (= %d microcents)", priceStr, priceMicrocents)
	}

	const hoursPerMonth = 24 * 30
	microcentsPerGiBPerHour := priceMicrocents / 1024 / hoursPerMonth

	return &Rate{
		MicrocentsPerGiBPerHour:       microcentsPerGiBPerHour,
		CustomerPriceUSDPerTBPerMonth: priceStr,
		ResolvedAt:                    time.Now().UTC(),
	}, nil
}

// readCustomerPriceFromDB returns the persisted customer price string, or
// (sql.ErrNoRows, "") if no row exists yet.
func readCustomerPriceFromDB(db *sql.DB) (string, error) {
	var v string
	err := db.QueryRow(
		`SELECT value FROM billing_settings WHERE key = ?`,
		BillingSettingsKeyCustomerPrice,
	).Scan(&v)
	if err != nil {
		return "", err
	}
	return v, nil
}

// ResetCachedRateForTest is a test-only helper. Production callers use
// SetCachedRate via SetCustomerPrice / ResolveRate.
func ResetCachedRateForTest() {
	cachedRate.Store(nil)
}
