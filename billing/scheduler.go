package billing

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/logging"
)

// Scheduler is the wall-clock-aligned billing loop. One instance per process,
// started from main.go after DB and storage are up.
//
// Two cadences:
//   - Tick (every cfg.TickInterval, default 1h) -- charges every billable
//     user via TickAllActiveUsers and writes to storage_usage_accumulator.
//   - Sweep (once per day at cfg.SweepAtUTC, default 00:15 UTC) -- drains
//     accumulator into user_credits via SweepAllUsers.
//
// Wall-clock alignment: ticks fire at top-of-tick-interval (e.g. on the hour
// when TickInterval=1h). Sweeps fire at the configured HH:MM each UTC day.
// This means restart semantics are at-least-once: if a redeploy bridges a
// tick boundary, the next aligned tick fires immediately. The accumulator's
// `+= excluded.unbilled_microcents` correctly handles the brief overlap.
//
// nowFn is injectable for deterministic tests. Production callers use the
// default time.Now.
type Scheduler struct {
	db      *sql.DB
	cfg     config.BillingConfig
	nowFn   func() time.Time
	sleepFn func(time.Duration) // wraps time.Sleep so tests can fast-forward
}

// NewScheduler returns a configured Scheduler. nowFn defaults to time.Now;
// sleepFn defaults to time.Sleep. Tests inject both.
func NewScheduler(db *sql.DB, cfg config.BillingConfig) *Scheduler {
	return &Scheduler{
		db:      db,
		cfg:     cfg,
		nowFn:   time.Now,
		sleepFn: time.Sleep,
	}
}

// SetNowFn overrides the time source. Test-only.
func (s *Scheduler) SetNowFn(fn func() time.Time) {
	s.nowFn = fn
}

// SetSleepFn overrides the sleep function. Test-only.
func (s *Scheduler) SetSleepFn(fn func(time.Duration)) {
	s.sleepFn = fn
}

// Run blocks until ctx is cancelled. Returns ctx.Err() on shutdown, never nil.
//
// Behavior on startup:
//  1. Seed billing_settings if missing (idempotent).
//  2. Resolve the live rate.
//  3. Compute the next aligned tick boundary, sleep until then.
//  4. On each tick, run TickAllActiveUsers; if today's sweep boundary has
//     also been crossed, run SweepAllUsers.
//  5. Repeat until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) error {
	if !s.cfg.Enabled {
		logging.InfoLogger.Print("billing.Scheduler: disabled (cfg.Enabled=false); not starting")
		<-ctx.Done()
		return ctx.Err()
	}

	if _, err := SeedCustomerPriceIfMissing(s.db, s.cfg); err != nil {
		logging.ErrorLogger.Printf("billing.Scheduler: seed price failed: %v (continuing with fallback)", err)
	}

	rate, err := ResolveRate(s.db, s.cfg)
	if err != nil {
		return fmt.Errorf("billing.Scheduler: initial rate resolve: %w", err)
	}
	logging.InfoLogger.Printf("billing.Scheduler: starting with %s (%d microcents/GiB/hour); tick=%s, sweep=%s UTC, includeAdmins=%t, freeBaseline=%d bytes",
		rate.FormatHumanReadable(), rate.MicrocentsPerGiBPerHour,
		s.cfg.TickInterval, s.cfg.SweepAtUTC, s.cfg.IncludeAdmins, s.cfg.FreeBaselineBytes)

	// Track whether we have already run today's sweep, keyed by UTC date string.
	lastSweepDate := ""

	for {
		nextTick := nextTickBoundary(s.nowFn(), s.cfg.TickInterval)
		if !s.sleepUntil(ctx, nextTick) {
			return ctx.Err()
		}

		// Re-resolve the rate on each tick (cheap; reads cached rate first
		// via the atomic.Pointer; falls through to a DB read if the cache is
		// nil, which only happens between SetCustomerPrice swaps).
		if cached := CachedRate(); cached != nil {
			rate = cached
		} else {
			rate, err = ResolveRate(s.db, s.cfg)
			if err != nil {
				logging.ErrorLogger.Printf("billing.Scheduler: rate resolve failed: %v (skipping tick)", err)
				continue
			}
		}

		// Run the tick.
		now := s.nowFn().UTC()
		count, errCount, tickErr := TickAllActiveUsers(s.db, rate, now, s.cfg)
		if tickErr != nil {
			logging.ErrorLogger.Printf("billing.Scheduler: tick failed: %v", tickErr)
		} else {
			logging.InfoLogger.Printf("billing.Scheduler: tick at %s; %d users billed, %d errors",
				now.Format(time.RFC3339), count, errCount)
		}

		// If we've crossed today's sweep boundary and haven't yet swept today, sweep.
		todayDate := now.Format("2006-01-02")
		if shouldRunSweep(now, s.cfg.SweepAtUTC, lastSweepDate, todayDate) {
			summary, sweepErr := SweepAllUsers(s.db, rate, now)
			if sweepErr != nil {
				logging.ErrorLogger.Printf("billing.Scheduler: sweep failed: %v", sweepErr)
			} else {
				logging.InfoLogger.Printf("billing.Scheduler: sweep at %s; %d users settled, total drained = %d microcents, %d users now negative",
					now.Format(time.RFC3339), summary.UsersSettled, summary.TotalDrainedMicrocents, summary.UsersWithNegativeBalance)
			}
			lastSweepDate = todayDate

			// Skipped-sweep WARN: detect cases where the previous sweep was
			// more than 25h ago (operator-visible signal that a sweep day
			// was missed; the SweepAllUsers settlement metadata still
			// reflects the actual elapsed period accurately).
			if maxBilledAgo, ok := maxLastBilledAtAge(s.db, now); ok && maxBilledAgo > 25*time.Hour {
				logging.WarningLogger.Printf("billing.Scheduler: longest gap since last sweep was %s (>25h); a sweep window was skipped",
					maxBilledAgo.Round(time.Hour))
			}
		}
	}
}

// sleepUntil sleeps until target, returning false when ctx is cancelled first.
// The implementation polls at most once per second so cancel latency is bounded
// even when tests inject artificially long durations.
func (s *Scheduler) sleepUntil(ctx context.Context, target time.Time) bool {
	for {
		now := s.nowFn()
		if !now.Before(target) {
			return true
		}
		remaining := target.Sub(now)
		// Cap each sleep at 1s so ctx.Done is responsive.
		chunk := time.Second
		if remaining < chunk {
			chunk = remaining
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
		s.sleepFn(chunk)
	}
}

// nextTickBoundary returns the smallest time strictly after `now` that is
// aligned to a multiple of `interval` (relative to UTC midnight). For
// interval=1h, this is the next top-of-hour. For interval=1m (the test
// override), this is the next top-of-minute.
//
// Returns the next aligned moment; if `now` is exactly on a boundary, returns
// now + interval to guarantee we sleep at least one tick.
func nextTickBoundary(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		interval = time.Hour
	}
	utc := now.UTC()
	rounded := utc.Truncate(interval)
	next := rounded.Add(interval)
	if !next.After(utc) {
		next = next.Add(interval)
	}
	return next
}

// shouldRunSweep returns true when `now` has crossed today's sweep boundary
// and we have not yet run the sweep for `todayDate`.
//
// sweepAtUTC is parsed as "HH:MM"; on parse error returns false.
func shouldRunSweep(now time.Time, sweepAtUTC, lastSweepDate, todayDate string) bool {
	if lastSweepDate == todayDate {
		return false
	}
	hh, mm, ok := parseHHMM(sweepAtUTC)
	if !ok {
		return false
	}
	boundary := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, time.UTC)
	return !now.Before(boundary)
}

// parseHHMM parses "HH:MM" into (hour, minute). Returns ok=false on any
// parse failure.
func parseHHMM(s string) (hour, minute int, ok bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, false
	}
	h, err1 := atoiTwoDigit(s[0:2])
	m, err2 := atoiTwoDigit(s[3:5])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// atoiTwoDigit parses exactly two ASCII digits.
func atoiTwoDigit(s string) (int, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("expected 2 digits, got %d", len(s))
	}
	d1, d2 := int(s[0]-'0'), int(s[1]-'0')
	if d1 < 0 || d1 > 9 || d2 < 0 || d2 > 9 {
		return 0, fmt.Errorf("not digits: %q", s)
	}
	return d1*10 + d2, nil
}

// maxLastBilledAtAge returns the elapsed time since the oldest last_billed_at
// across all rows in storage_usage_accumulator, plus ok=true. Returns ok=false
// when the table is empty (nothing to gauge).
func maxLastBilledAtAge(db *sql.DB, now time.Time) (time.Duration, bool) {
	var s sql.NullString
	err := db.QueryRow(
		`SELECT MIN(last_billed_at) FROM storage_usage_accumulator WHERE last_billed_at IS NOT NULL`,
	).Scan(&s)
	if err != nil || !s.Valid || s.String == "" {
		return 0, false
	}
	t, err := time.Parse("2006-01-02 15:04:05", s.String)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s.String)
		if err != nil {
			return 0, false
		}
	}
	return now.UTC().Sub(t.UTC()), true
}
