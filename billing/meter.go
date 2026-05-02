package billing

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/logging"
)

// TickUser charges one user for one tick (one wall-clock hour). It reads the
// user's current total_storage_bytes, computes the billable bytes against
// freeBaselineBytes, calculates the per-tick charge in microcents, and upserts
// the storage_usage_accumulator row. Idempotent within a single transaction.
//
// When tick_charge_microcents == 0 (user at or below the free baseline), no
// row is written -- this keeps the DB completely free of below-baseline noise.
//
// Math:
//
//	billable_bytes        = max(0, total_storage_bytes - free_baseline_bytes)
//	tick_charge_microcents = (billable_bytes * rate_microcents_per_gib_per_hour) >> 30
//
// The right-shift is integer division by 2^30 (binary GiB), and truncates the
// fractional remainder. At the spec's representative rate of 1,356
// microcents/GiB/hour, the truncated fraction is < 1 microcent/hour per user,
// well below noise floor.
func TickUser(db *sql.DB, username string, rate *Rate, now time.Time, freeBaselineBytes int64) error {
	if rate == nil {
		return errors.New("billing.TickUser: nil rate")
	}
	if username == "" {
		return errors.New("billing.TickUser: empty username")
	}

	// Read total_storage_bytes outside the transaction; only the upsert needs
	// transactional guarantees, and a stale read is acceptable (a user uploads
	// at 12:30 and gets ticked at 13:00 for what is stored at 13:00).
	//
	// NOTE: rqlite returns BIGINT columns as JSON float64 (sometimes in
	// scientific notation) when values are large. Scan into float64 first,
	// then cast to int64 — the same pattern used elsewhere in this codebase
	// for rqlite float64 scanning.
	var totalStorageBytesF float64
	err := db.QueryRow(
		`SELECT total_storage_bytes FROM users WHERE username = ?`,
		username,
	).Scan(&totalStorageBytesF)
	totalStorageBytes := int64(totalStorageBytesF)
	if err != nil {
		return fmt.Errorf("billing.TickUser: read total_storage_bytes for %s: %w", username, err)
	}

	billable := totalStorageBytes - freeBaselineBytes
	if billable <= 0 {
		// Below the free baseline: no DB write, no audit trail noise.
		return nil
	}

	tickChargeMicrocents := (billable * rate.MicrocentsPerGiBPerHour) >> 30
	if tickChargeMicrocents <= 0 {
		// Tick charge truncated to zero (extremely small billable_bytes at low
		// rate). Skip the write so we don't pollute the accumulator with no-ops.
		return nil
	}

	// Upsert: one row per username; subsequent ticks accumulate the unbilled total.
	_, err = db.Exec(`
		INSERT INTO storage_usage_accumulator (username, unbilled_microcents, last_tick_at)
		VALUES (?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
		  unbilled_microcents = unbilled_microcents + excluded.unbilled_microcents,
		  last_tick_at = excluded.last_tick_at`,
		username, tickChargeMicrocents, now.UTC(),
	)
	if err != nil {
		return fmt.Errorf("billing.TickUser: upsert accumulator for %s: %w", username, err)
	}
	return nil
}

// TickAllActiveUsers ticks every billable user in one pass. Returns the count
// of users ticked successfully and the count that errored. Per-user errors are
// logged but do not abort the iteration so a single bad row doesn't block all
// other users from being billed.
//
// Filtering rules:
//   - is_approved = true (only approved users are billed).
//   - !is_admin OR cfg.IncludeAdmins (admins skipped by default to keep
//     beta-period usage data free of operator self-usage).
func TickAllActiveUsers(db *sql.DB, rate *Rate, now time.Time, cfg config.BillingConfig) (count int, errCount int, err error) {
	if rate == nil {
		return 0, 0, errors.New("billing.TickAllActiveUsers: nil rate")
	}

	query := `SELECT username FROM users WHERE is_approved = 1`
	if !cfg.IncludeAdmins {
		query += ` AND (is_admin = 0 OR is_admin IS NULL)`
	}

	rows, err := db.Query(query)
	if err != nil {
		return 0, 0, fmt.Errorf("billing.TickAllActiveUsers: list users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		if scanErr := rows.Scan(&username); scanErr != nil {
			logging.ErrorLogger.Printf("billing.TickAllActiveUsers: scan: %v", scanErr)
			errCount++
			continue
		}
		if tickErr := TickUser(db, username, rate, now, cfg.FreeBaselineBytes); tickErr != nil {
			logging.ErrorLogger.Printf("billing.TickAllActiveUsers: tick %s: %v", username, tickErr)
			errCount++
			continue
		}
		count++
	}
	if rerr := rows.Err(); rerr != nil {
		return count, errCount, fmt.Errorf("billing.TickAllActiveUsers: rows iteration: %w", rerr)
	}
	return count, errCount, nil
}
