// Package billing implements Arkfile's storage-usage meter and credits ledger.
//
// It is the single, definitive implementation of docs/wip/storage-credits-v2.md.
// All balances and amounts are denominated in microcents (1 USD = 100 cents =
// 100,000,000 microcents). Balances are signed: a user who overdraws their
// balance simply goes negative; there is no separate deficit column.
//
// Public surface:
//
//   - Rate, ResolveRate, SetCachedRate: rate resolution from billing_settings,
//     with an atomic.Pointer cache that admin set-price calls swap directly.
//   - TickUser, TickAllActiveUsers: per-hour metering. Writes the per-user
//     accumulator row only when there is a billable charge.
//   - SweepAllUsers: per-day settlement. Drains accumulator into user_credits
//     and writes one 'usage' transaction per user.
//   - Scheduler: wall-clock-aligned ticker loop wired into main.go. Injectable
//     time source for deterministic tests.
//   - GiftCredits: admin-initiated positive balance adjustment, written as
//     a typed 'gift' transaction so the audit log distinguishes operator
//     gifts from future paid top-ups.
//
// Privacy posture: the meter never logs per-tick activity; only the daily
// sweep writes audit rows. Settlement metadata deliberately excludes
// per-day storage time-series fields (see §3.5 of the design doc).
package billing

import (
	"time"
)

// SweepSummary is the aggregate result of one daily settlement run.
type SweepSummary struct {
	UsersSettled             int
	TotalDrainedMicrocents   int64
	UsersWithNegativeBalance int
}

// SettlementMetadata is the JSON structure stored in
// credit_transactions.metadata for a 'usage' row. It must contain ONLY these
// fields. Adding `avg_billable_bytes` or any per-day storage time-series
// field would be a privacy regression (§3.5 of the design doc).
type SettlementMetadata struct {
	DrainedMicrocents           int64     `json:"drained_microcents"`
	RateMicrocentsPerGiBPerHour int64     `json:"rate_microcents_per_gib_per_hour"`
	PeriodStart                 time.Time `json:"period_start"`
	PeriodEnd                   time.Time `json:"period_end"`
	TicksCount                  int       `json:"ticks_count"`
}
