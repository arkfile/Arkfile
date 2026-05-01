package billing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

// SweepAllUsers performs the daily settlement: drains every nonzero
// storage_usage_accumulator row into user_credits and writes one 'usage'
// transaction per user. Each user is processed in its own DB transaction,
// so a crash mid-iteration leaves already-settled users correct and the next
// sweep picks up the rest.
//
// The metadata field on each transaction row contains exactly the five fields
// in SettlementMetadata. It deliberately omits any per-day storage time-series
// to preserve the privacy invariant in §3.5 of the design doc.
//
// Returns the aggregate summary. UsersWithNegativeBalance is the point-in-time
// count of users whose balance ended up below zero after this sweep run.
func SweepAllUsers(db *sql.DB, rate *Rate, now time.Time) (SweepSummary, error) {
	if rate == nil {
		return SweepSummary{}, errors.New("billing.SweepAllUsers: nil rate")
	}

	rows, err := db.Query(`
		SELECT username, unbilled_microcents, last_tick_at, last_billed_at
		FROM storage_usage_accumulator
		WHERE unbilled_microcents > 0`)
	if err != nil {
		return SweepSummary{}, fmt.Errorf("billing.SweepAllUsers: list accumulator: %w", err)
	}

	type pending struct {
		username           string
		unbilledMicrocents int64
		lastTickAt         sql.NullString
		lastBilledAt       sql.NullString
	}

	var queue []pending
	for rows.Next() {
		var p pending
		if scanErr := rows.Scan(&p.username, &p.unbilledMicrocents, &p.lastTickAt, &p.lastBilledAt); scanErr != nil {
			rows.Close()
			return SweepSummary{}, fmt.Errorf("billing.SweepAllUsers: scan: %w", scanErr)
		}
		queue = append(queue, p)
	}
	if rerr := rows.Err(); rerr != nil {
		rows.Close()
		return SweepSummary{}, fmt.Errorf("billing.SweepAllUsers: rows: %w", rerr)
	}
	rows.Close()

	summary := SweepSummary{}
	for _, p := range queue {
		newBalance, settleErr := settleOneUser(db, rate, now, p.username, p.unbilledMicrocents, p.lastBilledAt)
		if settleErr != nil {
			logging.ErrorLogger.Printf("billing.SweepAllUsers: settle %s: %v", p.username, settleErr)
			continue
		}
		summary.UsersSettled++
		summary.TotalDrainedMicrocents += p.unbilledMicrocents
		if newBalance < 0 {
			summary.UsersWithNegativeBalance++
		}
	}

	return summary, nil
}

// settleOneUser runs the per-user transaction:
//
//  1. Read user_credits.balance_usd_microcents (create at 0 if missing).
//  2. new_balance = balance - unbilled_microcents (signed; may go negative).
//  3. Update user_credits.
//  4. Insert one credit_transactions row with type='usage'.
//  5. Zero the accumulator row; set last_billed_at = now.
//
// Returns the new balance after settlement.
func settleOneUser(db *sql.DB, rate *Rate, now time.Time, username string, drainedMicrocents int64, lastBilledAt sql.NullString) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Step 1: ensure a user_credits row exists (create at zero balance if not).
	var currentBalance int64
	err = tx.QueryRow(
		`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`,
		username,
	).Scan(&currentBalance)
	if err == sql.ErrNoRows {
		_, insErr := tx.Exec(
			`INSERT INTO user_credits (username, balance_usd_microcents, created_at, updated_at)
			 VALUES (?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			username,
		)
		if insErr != nil {
			return 0, fmt.Errorf("create user_credits row: %w", insErr)
		}
		currentBalance = 0
	} else if err != nil {
		return 0, fmt.Errorf("read user_credits: %w", err)
	}

	// Step 2 + 3: compute and persist the new (signed) balance.
	newBalance := currentBalance - drainedMicrocents
	_, err = tx.Exec(
		`UPDATE user_credits SET balance_usd_microcents = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE username = ?`,
		newBalance, username,
	)
	if err != nil {
		return 0, fmt.Errorf("update user_credits: %w", err)
	}

	// Step 4: write one 'usage' transaction with the privacy-preserving metadata.
	periodStart, periodEnd, ticksCount := computeSettlementPeriod(lastBilledAt, now)
	metaBytes, err := json.Marshal(SettlementMetadata{
		DrainedMicrocents:           drainedMicrocents,
		RateMicrocentsPerGiBPerHour: rate.MicrocentsPerGiBPerHour,
		PeriodStart:                 periodStart,
		PeriodEnd:                   periodEnd,
		TicksCount:                  ticksCount,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal metadata: %w", err)
	}

	reason := "Daily storage usage"
	_, err = tx.Exec(`
		INSERT INTO credit_transactions
		  (username, amount_usd_microcents, balance_after_usd_microcents,
		   transaction_type, reason, admin_username, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, NULL, ?, CURRENT_TIMESTAMP)`,
		username, -drainedMicrocents, newBalance, models.TransactionTypeUsage, reason, string(metaBytes),
	)
	if err != nil {
		return 0, fmt.Errorf("insert credit_transactions row: %w", err)
	}

	// Step 5: zero the accumulator and stamp last_billed_at.
	_, err = tx.Exec(
		`UPDATE storage_usage_accumulator
		 SET unbilled_microcents = 0, last_billed_at = ?
		 WHERE username = ?`,
		now.UTC(), username,
	)
	if err != nil {
		return 0, fmt.Errorf("reset accumulator: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}
	return newBalance, nil
}

// computeSettlementPeriod derives the period start/end and the implied tick
// count from the previous last_billed_at watermark. When this is the first
// sweep for the user (no last_billed_at), the period defaults to the last
// 24 hours.
//
// The 'ticks' count is informational only: in normal operation it is 24 (one
// tick per hour over a day); after a skipped sweep day it may be larger.
func computeSettlementPeriod(lastBilledAt sql.NullString, now time.Time) (start time.Time, end time.Time, ticks int) {
	end = now.UTC()
	if !lastBilledAt.Valid || lastBilledAt.String == "" {
		start = end.Add(-24 * time.Hour)
		ticks = 24
		return
	}
	if t, err := time.Parse("2006-01-02 15:04:05", lastBilledAt.String); err == nil {
		start = t.UTC()
	} else if t, err := time.Parse(time.RFC3339, lastBilledAt.String); err == nil {
		start = t.UTC()
	} else {
		// Unparseable: be conservative and use the 24h default rather than
		// guessing or zeroing. Logged at WARN by callers (the scheduler also
		// emits a > 25h skipped-sweep WARN that surfaces this kind of state).
		start = end.Add(-24 * time.Hour)
		ticks = 24
		return
	}
	elapsed := end.Sub(start)
	ticks = int(elapsed.Hours())
	if ticks < 1 {
		ticks = 1
	}
	return
}
