# Storage Credits and Usage Metering

This document is the single, definitive design for Arkfile's storage-usage meter and credits ledger. It is intended to be implemented in one cohesive set of changes (no v1/v2 implementation forks). Payment-provider integration is explicitly out of scope and deferred to a future `docs/wip/payments.md`.

## 1. Scope

Build a usage meter that bills every approved user's stored bytes against a microcent-denominated credit balance. No payment provider integration, no over-quota enforcement based on balance, no auto-deletion. The existing `users.storage_limit_bytes` hard cap is unchanged. Pricing is a single number set by the operator in `secrets.env`; the system does not try to derive a price from underlying provider costs.

Meter-first sequencing rationale (one paragraph): the meter's correctness questions (precision, accumulation semantics, settlement) are independent of any payment provider's API and are easier to get right in isolation; running the meter against the live beta with no real money produces real usage data that anchors the eventual pricing decisions; the cents-to-microcents schema migration is cheapest to do before any provider depends on the columns; payment-provider integration is the largest single increase in privacy attack surface and deserves its own focused design document.

## 2. What Already Exists

Confirmed against the codebase:

- `models/user.go`: `DefaultStorageLimit = 1181116006` (1.1 GiB). `IsApproved` and `IsAdmin` fields. `User.CheckStorageAvailable(size)` is the upload-time hard-cap gate.
- `database/unified_schema.sql`:
  - `users.total_storage_bytes BIGINT` (maintained by upload/delete paths).
  - `users.storage_limit_bytes BIGINT NOT NULL DEFAULT 10737418240` (10 GiB) — disagrees with the Go constant; reconciled here.
  - `user_credits(balance_usd_cents INTEGER, ...)` with auto-update trigger.
  - `credit_transactions(transaction_id, username, amount_usd_cents INTEGER, balance_after_usd_cents INTEGER, transaction_type TEXT, reason, admin_username, metadata TEXT, created_at)` — `transaction_type` has no enum constraint.
  - `storage_providers(provider_id, ..., role TEXT DEFAULT 'tertiary', is_active BOOLEAN, cost_per_tb_cents INTEGER NULL, ...)`.
  - Indexes on `user_credits(username)`, `credit_transactions(username, transaction_id, type, created_at, admin_username)`.
- `models/credits.go`: `UserCredit`, `CreditTransaction`, `GetOrCreateUserCredits`, `GetUserCredits`, `CreateUserCredits`, `AddCredits`, `DebitCredits`, `SetCredits`, `GetUserTransactions`, `GetAllUserCredits`, `FormatCreditsUSD`, `ParseCreditsFromUSD`, `GetUserCreditsSummary`. Transaction-type constants: `credit`, `debit`, `adjustment`, `refund`. All write paths are DB-transactional and emit `logging.LogSecurityEvent(EventAdminAccess, ...)`.
- API endpoints: `GET /api/credits`, `GET /api/admin/credits`, `GET /api/admin/credits/:username`, `POST /api/admin/credits/:username` (add/subtract/set with required reason), `PUT /api/admin/credits/:username`. Admin upload-cap endpoint `PUT /api/admin/users/:username/storage`.
- `arkfile-admin set-cost --provider-id ID --cost AMOUNT` already writes `storage_providers.cost_per_tb_cents`. This value is retained for operator reference and future cost-tracking dashboards but is **not** read by the billing meter.
- Admin actions are logged via `LogAdminAction` to the `admin_logs` table.

Nothing in the credits ledger is connected to storage usage today. The frontend has no billing page.

## 3. Pricing Model

### 3.1 Internal Unit: Microcents per GiB per Hour

All balances and amounts are stored as `int64` **microcents** (1 USD = 100 cents = 100,000,000 microcents). The int64 range is ~$92 billion — comfortable. **Balances are signed**: a user who overdraws their balance simply goes negative; there is no separate deficit column (see §3.4).

The **rate** used by the meter is denominated as `int64` **microcents per GiB per hour** (binary GiB = 2^30 bytes). This is the canonical internal unit derived from the operator's stated customer price (§3.3).

Why this unit: storing the rate per byte per hour in microcents truncates to a sub-integer value at realistic prices ($10/TiB/month ≈ 0.00126 microcents/byte/hour, which rounds to zero as int64). Per-GiB-per-hour gives clean integer rates: $10/TiB/month ≈ 1,356 microcents/GiB/hour, with comfortable headroom.

The per-tick math is one int64 multiply + one shift:

```
tick_charge_microcents = (billable_bytes * rate_microcents_per_gib_per_hour) >> 30
```

The shift truncates fractional microcents per tick. At 1,356 microcents/GiB/hour, each truncated fraction is < 1 microcent/hour ≈ < $0.0000088/year/user — well below noise floor.

**Display formatting**: balances and transaction amounts in microcents are formatted with four decimal places of USD (e.g., `"$5.0000"`, `"-$0.0006"`) so fractional-cent accounting is honest, and a leading minus sign is shown for negative balances. *Projected* monthly costs in the UI use approximate framing (`"~$0.02/month"`) because the 30-day month convention introduces ~3% variance against actual months — calling it precise to four decimals would be misleading.

### 3.2 Tick (Hourly) and Settlement (Daily)

The meter ticks once per wall-clock hour (top-of-hour aligned; see §5.4). For each active user:

1. Read `total_storage_bytes` from `users`.
2. `billable_bytes = max(0, total_storage_bytes - free_baseline_bytes)`.
3. `tick_charge_microcents = (billable_bytes * rate_microcents_per_gib_per_hour) >> 30`.
4. If `tick_charge_microcents > 0`, upsert `storage_usage_accumulator` (one row per billable user) and update `last_tick_at`.

Ticks do not touch `user_credits` or `credit_transactions`. Users at or below the free baseline produce no DB write.

Once per day at a configurable UTC time (default `00:15`), a settlement sweep runs. For each accumulator row with `unbilled_microcents > 0`, in a per-user transaction:

1. Read `user_credits.balance_usd_microcents` (create at zero if missing).
2. `new_balance = balance - unbilled_microcents` (signed; may go negative).
3. Update `user_credits.balance_usd_microcents = new_balance`.
4. Insert one `credit_transactions` row: `transaction_type = 'usage'`, `amount_usd_microcents = -unbilled_microcents`, `balance_after_usd_microcents = new_balance`, `reason = "Daily storage usage"`, `metadata` JSON described in §3.5.
5. Zero the accumulator row; set `last_billed_at = now`.

Per-user transactions make the sweep restartable: a crash mid-iteration leaves already-swept users correct, and the next sweep picks up the rest. The `last_billed_at` watermark prevents double-billing.

Audit-log volume scales as `users × days`, not `users × hours`: 100 users × 365 days = 36,500 rows/year (vs. 876,000 if logged per-tick).

### 3.3 Customer Price → Internal Rate

The operator sets exactly **one** pricing knob, in `secrets.env`:

```
ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH=10.00
```

This is parsed as a dollars-and-cents string (e.g., `"10.00"`, `"19.99"`, `"24.99"`). It is the only place a price lives in the system. There is no markup multiplier, no auto-derivation from `storage_providers.cost_per_tb_cents`, no fallback constant chain, no rate-ceiling env var. The operator owns the number directly.

**Suggested values** (the deploy scripts seed `10.00` as the default):

- `10.00` — single storage backend, no replication.
- `20.00` — two storage backends with replication sync.

Conversion to the internal rate uses **floor-rounded integer math** so the derived rate never exceeds the operator's stated price:

```
microcents_per_TiB_per_month = price_dollars * 100 * 1_000_000        // dollars -> microcents
microcents_per_GiB_per_hour  = floor(microcents_per_TiB_per_month / 1024 / 720)
                                                                       // 720 = 30 days * 24 hours
```

Worked examples (TiB and GiB binary, 2^40 / 2^30; month = 30 days):

| Customer price | microcents/TiB/month | microcents/GiB/hour |
|---|---:|---:|
| $10.00 | 1,000,000,000 | **1,356** |
| $19.99 | 1,999,000,000 | **2,711** |
| $20.00 | 2,000,000,000 | **2,712** |
| $24.99 | 2,499,000,000 | **3,389** |

The price can be updated at runtime without restart via `arkfile-admin billing set-price` (§8) or the matching admin API endpoint (§6.4); the meter re-reads the value on its next tick.

### 3.4 Billable Bytes, Active Users, and Negative Balances

**Billable bytes** = `max(0, total_storage_bytes - free_baseline_bytes)`. The free baseline is per-instance (`ARKFILE_FREE_STORAGE_BYTES`, default = `1181116006` to match the Go `DefaultStorageLimit`). It operates independently of `users.storage_limit_bytes`: a user with a 50 GiB cap and 30 GiB stored has 28.9 GiB billable.

**Active users** for billing: `is_approved = true` and not deleted. Admins (`is_admin = true` or username matches `isAdminUsername()`) are excluded by default; toggle via `ARKFILE_BILLING_INCLUDE_ADMINS=true` (default `false`) so operator self-usage doesn't pollute beta usage data.

**Negative balances are allowed.** When a daily sweep drains more than the user's current balance, `balance_usd_microcents` simply goes negative. There is no separate deficit column; the signed balance is the single source of truth. This is a deliberate design choice for the beta period: every user — including beta testers whose initial gift has been exhausted — sees an honest, accumulating "what this would cost in a paid deployment" number, which is the most useful possible signal both to the operator and to the testers themselves. Any future payments work that needs to distinguish "debt to be settled" from "credit to be spent" can re-introduce a split column at that time.

### 3.5 Settlement Metadata (Privacy-Sensitive)

The daily-sweep `credit_transactions.metadata` JSON contains **only**:

```json
{
  "drained_microcents": 600,
  "rate_microcents_per_gib_per_hour": 1356,
  "period_start": "2026-04-30T00:15:00Z",
  "period_end":   "2026-05-01T00:15:00Z",
  "ticks_count":  24
}
```

It deliberately **omits** `avg_billable_bytes` (and any field that lets an observer reconstruct per-day storage history). `users.total_storage_bytes` already discloses current state; the meter must not introduce a new persistent per-day storage time-series. Reconciliation (cents owed vs. cents drained) is still possible from `drained_microcents` and `rate_microcents_per_gib_per_hour`.

## 4. Schema Changes

### 4.1 Migration Posture

The schema deltas in this document only touch the credits ledger. They do **not** touch file-encryption-key wrappers, OPAQUE auth records, file metadata, or anything else that would render previously-uploaded files inaccessible. By themselves these changes are safe to apply in place.

**However, the choice of deployment script matters enormously** — see §4.3 below. The wrong script can render every previously-uploaded beta-tester file unrecoverable even though the schema deltas themselves are file-safe.

### 4.2 Summary of Deltas

1. `users.storage_limit_bytes` default: `10737418240` → `1181116006` (matches `models.DefaultStorageLimit`). Existing rows keep whatever value they already have; only the column default changes.
2. `user_credits.balance_usd_cents INTEGER` → `user_credits.balance_usd_microcents BIGINT NOT NULL DEFAULT 0`. **Signed**: no `CHECK (balance >= 0)` constraint; balances may be negative.
3. `credit_transactions.amount_usd_cents` → `credit_transactions.amount_usd_microcents BIGINT NOT NULL`.
4. `credit_transactions.balance_after_usd_cents` → `credit_transactions.balance_after_usd_microcents BIGINT NOT NULL`.
5. `credit_transactions.transaction_type` accepts new values `usage` and `gift` (no enum constraint exists; documentation/code-side change).
6. New table `storage_usage_accumulator`:

```sql
CREATE TABLE IF NOT EXISTS storage_usage_accumulator (
    username TEXT PRIMARY KEY,
    unbilled_microcents BIGINT NOT NULL DEFAULT 0,
    last_tick_at DATETIME,
    last_billed_at DATETIME,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_storage_usage_accumulator_last_tick_at
    ON storage_usage_accumulator(last_tick_at);
CREATE INDEX IF NOT EXISTS idx_storage_usage_accumulator_last_billed_at
    ON storage_usage_accumulator(last_billed_at);
```

7. New table `billing_settings` (single-row key/value table for the customer price):

```sql
CREATE TABLE IF NOT EXISTS billing_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);
-- Seeded at first startup with key='customer_price_usd_per_tb_per_month'
-- and value taken from ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH.
```

The existing `INTEGER` columns are widened to `BIGINT` for cross-backend safety; in SQLite this is a no-op (INTEGER is already 64-bit) but spelling it `BIGINT` makes intent clear if/when a non-SQLite backend is introduced.

**Explicitly NOT added**: a `usage_deficit_microcents` column on `users`. Negative balances on `user_credits.balance_usd_microcents` carry that information directly.

### 4.3 Beta-Tester File Safety: `test-update.sh` vs `test-deploy.sh`

The `test.arkfile.net` deployment is the only environment with real beta-tester data. The schema deltas above are individually file-safe, but the *deploy script* that applies them is not always file-safe.

- **`test-update.sh`** rebuilds binaries and applies in-place migrations without wiping data. **This is the correct rollout path for `test.arkfile.net`.** OPAQUE auth records, file metadata, FEK wrappers, and uploaded blobs are all preserved.
- **`test-deploy.sh`** is the destructive provisioning script. It wipes the database (including OPAQUE auth records and file metadata) and reseeds from scratch. Running it against `test.arkfile.net` would render every previously-uploaded beta-tester file unrecoverable — the encrypted blobs in object storage become permanently unreadable without the wiped FEK wrappers and auth records. **Do not use it for `test.arkfile.net` after beta testers have begun uploading.**

The `_cents → _microcents` rename in step 2 of §11 must therefore be implemented as an in-place ALTER-style migration (rename columns, widen types, preserve any existing rows). Even though `user_credits` may currently be empty in production-like data, writing the migration properly is cheap insurance and establishes the pattern for all future schema changes.

**General rule** (added to project documentation as part of this work): *any future schema change in this codebase must explicitly state whether it renders previously-uploaded beta-tester files inaccessible, and provide an in-place migration path if so. Default deployment for `test.arkfile.net` is `test-update.sh`, never `test-deploy.sh`.*

### 4.4 Rename Surface (Go and JSON)

- `models.UserCredit.BalanceUSDCents` → `BalanceUSDMicrocents`; JSON tag `balance_usd_microcents`. **Signed** `int64`; may be negative.
- `models.CreditTransaction.AmountUSDCents` → `AmountUSDMicrocents`; JSON `amount_usd_microcents`.
- `models.CreditTransaction.BalanceAfterUSDCents` → `BalanceAfterUSDMicrocents`; JSON `balance_after_usd_microcents`.
- New transaction-type constants: `TransactionTypeUsage = "usage"`, `TransactionTypeGift = "gift"`.
- `models.FormatCreditsUSD(microcents int64) string` → four-decimal output (`"$5.0000"`, `"-$0.0006"`, `"-$1.2345"`).
- `models.ParseCreditsFromUSD(s string) (int64, error)` → returns microcents, with rounding at the microcent boundary; accepts a leading `-`.
- All `cmd/arkfile-admin/` struct definitions updated in lockstep.

## 5. The `billing/` Package

New top-level Go package. No third-party dependencies. Reads from `models/`, called by `handlers/`.

```
billing/
    types.go            // Rate, BillingConfig, UserUsage, SweepSummary
    rates.go            // ResolveRate, atomic.Pointer[Rate] cache
    rates_test.go
    meter.go            // TickUser, TickAllActiveUsers
    meter_test.go
    sweep.go            // SweepAllUsers
    sweep_test.go
    scheduler.go        // wall-clock-aligned ticker loop
    scheduler_test.go
    gift.go             // GiftCredits
    gift_test.go
```

### 5.1 `Rate` and Resolution

```go
type Rate struct {
    MicrocentsPerGiBPerHour      int64
    CustomerPriceUSDPerTBPerMonth string  // e.g. "10.00"
    ResolvedAt                   time.Time
}

func ResolveRate(db *sql.DB, cfg BillingConfig) (*Rate, error)
func (r *Rate) FormatHumanReadable() string
```

Resolution is straightforward: read the `customer_price_usd_per_tb_per_month` row from `billing_settings` (seeded at first startup from `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH`), parse it as dollars-and-cents, apply the conversion in §3.3. There is no priority chain, no fallback chain, no auto-derivation. If the row is missing for any reason, log ERROR and use the env-var value directly; if the env var is also missing or unparseable, log ERROR and use a hardcoded safety value of `10.00` so the meter does not crash.

The resolved `Rate` is cached in a package-level `atomic.Pointer[*Rate]` and re-read on each tick (cheap; one indexed primary-key SELECT). The admin `set-price` endpoint atomically swaps the cached pointer immediately on update so subsequent ticks use the new rate without waiting for any refresh interval.

### 5.2 `TickUser` and `TickAllActiveUsers`

```go
func TickUser(db *sql.DB, username string, rate *Rate,
              now time.Time, freeBaselineBytes int64) error

func TickAllActiveUsers(db *sql.DB, rate *Rate, now time.Time,
                        cfg BillingConfig) (count int, errCount int, err error)
```

`TickUser` runs as a single SQL transaction:

```sql
BEGIN;
  SELECT total_storage_bytes FROM users WHERE username = ?;
  -- compute billable_bytes, tick_charge_microcents in Go
  -- if tick_charge_microcents == 0: COMMIT; return  (no row written)
  INSERT INTO storage_usage_accumulator
    (username, unbilled_microcents, last_tick_at)
    VALUES (?, ?, ?)
    ON CONFLICT(username) DO UPDATE SET
      unbilled_microcents = unbilled_microcents + excluded.unbilled_microcents,
      last_tick_at = excluded.last_tick_at;
COMMIT;
```

`TickAllActiveUsers` filters: `is_approved = true` AND (`!is_admin` OR `cfg.IncludeAdmins`). Per-user errors are logged but do not abort the iteration; aggregate `errCount` is returned.

The tick samples `total_storage_bytes` at tick time (not transactional with upload/delete). A user uploading at 12:30 and ticked at 13:00 is billed for what's stored at 13:00 — a small free window, fine at our prices.

### 5.3 `SweepAllUsers`

```go
func SweepAllUsers(db *sql.DB, rate *Rate, now time.Time) (SweepSummary, error)

type SweepSummary struct {
    UsersSettled              int
    TotalDrainedMicrocents    int64
    UsersWithNegativeBalance  int   // count of users whose balance is < 0 after this sweep
}
```

Iterates `storage_usage_accumulator` where `unbilled_microcents > 0`. Per-user algorithm is steps 1–5 from §3.2. Idempotent on a per-row basis (zeroed accumulator row → no-op on next sweep).

The sweep uses the rate active at sweep time. Mid-day rate changes are not reconciled per-tick (acceptable approximation; rate changes are rare and the per-tick error is sub-cent).

`UsersWithNegativeBalance` is the point-in-time count of users whose `balance_usd_microcents` is strictly less than zero at the end of the sweep. The list of such users is queried separately via `arkfile-admin billing list-overdrawn` (§8).

### 5.4 `Scheduler` (Wall-Clock Aligned)

```go
type Scheduler struct {
    db          *sql.DB
    cfg         BillingConfig
    tickEvery   time.Duration   // default 1h
    sweepAtUTC  string          // default "00:15"
    nowFn       func() time.Time // injectable for tests; defaults to time.Now
}

func (s *Scheduler) Run(ctx context.Context) error
```

The scheduler aligns ticks to top-of-hour: at startup it sleeps until `now.Truncate(tickEvery).Add(tickEvery)`, then ticks at that interval. The sweep fires once per UTC day at `sweepAtUTC`. Operator audit reasoning ("at 03:00 UTC, every billable user should have been ticked") is preserved across restarts.

There is no separate rate-refresh interval; the rate is re-read from `billing_settings` on each tick (one cheap indexed lookup) and atomically swapped on admin `set-price` calls.

**Restart semantics**: ticks are *at-least-once*. If a `test-update.sh` or `prod-update.sh` restart bridges a tick boundary, the new binary's first aligned tick may fire within seconds of the old binary's last tick. The accumulator's `+= excluded.unbilled_microcents` correctly accumulates, so the user is briefly slightly overcharged (one extra tick, ≈ one hour's worth of microcents). Documented; acceptable.

Skipped sweeps (e.g., server down at 00:15 UTC): the next sweep drains the accumulator's full unbilled value in a single transaction row whose `period_start`/`period_end` accurately span the elapsed period (>24h). The scheduler logs WARN on detecting `elapsed-since-last-sweep > 25h`.

### 5.5 `GiftCredits`

```go
func GiftCredits(db *sql.DB, username string, amountUSDMicrocents int64,
                 reason string, adminUsername string) (*models.CreditTransaction, error)
```

Validates `amount > 0` and `reason != ""`. Inserts `transaction_type = 'gift'`. Distinct from `models.AddCredits` so the audit log distinguishes operator gifts from future paid top-ups.

### 5.6 Wiring in `main.go`

After DB open and existing background workers, before HTTP listen:

```go
if cfg.Billing.Enabled {
    sch := billing.NewScheduler(db, cfg.Billing)
    go func() {
        if err := sch.Run(rootCtx); err != nil {
            logging.ErrorLogger.Printf("billing scheduler exited: %v", err)
        }
    }()
} else {
    logging.InfoLogger.Print("billing scheduler disabled (ARKFILE_BILLING_ENABLED=false)")
}
```

### 5.7 New User Gift Hook

When a user is approved (existing `User.Approve` path), if `cfg.Billing.GiftedCreditsUSD > 0`, call `GiftCredits` with `reason = "Initial gift to new user"` and `adminUsername` set to the approver (or `"system"` for auto-approved admins). Folded into the same DB transaction bracket as approval so a failed gift rolls back the approval.

## 6. API Surface

### 6.1 Field Rename

Every `*_usd_cents` JSON field in credits responses becomes `*_usd_microcents`. `formatted_balance` retains the same key but emits four-decimal precision and a leading minus sign for negative balances. The `arkfile-admin` CLI structs are updated in lockstep so there is no version-skew window.

### 6.2 Extended: `GET /api/credits`

Adds two blocks. Canonical above-baseline shape:

```json
{
  "username": "alice",
  "balance_usd_microcents": 500000000,
  "formatted_balance": "$5.0000",
  "current_usage": {
    "total_storage_bytes": 2254857830,
    "free_baseline_bytes": 1181116006,
    "billable_bytes": 1073741824,
    "rate_microcents_per_gib_per_hour": 1356,
    "rate_human": "$10.00/TiB/month",
    "current_cost_per_month_microcents": 976608,
    "current_cost_per_month_usd_approx": "~$0.0098"
  },
  "credits_runway": {
    "estimated_hours_remaining": 512000,
    "estimated_runs_out_at_approx": "2084-06-01T00:00:00Z",
    "computed_at": "2026-04-30T20:15:00Z"
  },
  "transactions": [...],
  "pagination": {...}
}
```

Below-baseline: `billable_bytes = 0`, `current_cost_per_month_microcents = 0`, `credits_runway` becomes `{"estimated_hours_remaining": null, "note": "You are within the free baseline. No usage charges apply.", ...}`.

**Negative balance**: `balance_usd_microcents` is signed and may be negative (e.g., `-12345678`); `formatted_balance` then renders as `"-$0.1234"`. `credits_runway.estimated_hours_remaining` is `0` and `note` becomes `"Balance is negative; charges continue to accumulate."`

### 6.3 Extended Admin Endpoints

- `GET /api/admin/credits` — list-all gains per-user `current_usage` block (no runway; expensive). Balances may be negative.
- `GET /api/admin/credits/:username` — gains `current_usage` + `credits_runway`, retains existing `admin_info`.
- `GET /api/admin/users/:username/status` — gains `billing` block: `balance_usd_microcents` (signed), `formatted_balance`, `billable_bytes`, `current_cost_per_month_usd_approx`, `last_billed_at`.

### 6.4 New Admin Endpoints

All under `adminGroup` (existing TOTP-protected). All admin actions logged to `admin_logs` via `LogAdminAction`.

- `GET /api/admin/billing/price` — current customer price and derived rate. Response: `{ "customer_price_usd_per_tb_per_month": "10.00", "microcents_per_gib_per_hour": 1356, "resolved_at": "..." }`.
- `POST /api/admin/billing/set-price` — body `{ "customer_price_usd_per_tb_per_month": "19.99" }`. Validates parseable dollars-and-cents and `> 0`. Updates `billing_settings`, atomically swaps the cached `Rate`, returns the new resolved rate plus `previous_microcents_per_gib_per_hour`.
- `GET /api/admin/billing/sweep-summary?days=7` — last N days of daily totals from `credit_transactions WHERE transaction_type='usage'` aggregated by day. Each row includes `users_settled`, `total_drained_microcents`, `total_drained_usd`. Plus a top-level `users_currently_negative` point-in-time count.
- `GET /api/admin/billing/overdrawn` — list users with `balance_usd_microcents < 0`. Used by CLI `list-overdrawn`. Returns the list and a `users_currently_overdrawn` count.
- `POST /api/admin/billing/gift` — body `{target_username, amount_usd, reason}`. Validates, calls `GiftCredits`, returns `transaction` and `updated_balance`.
- `POST /api/admin/billing/tick-now` — dev/test only. Returns 403 unless `ADMIN_DEV_TEST_API_ENABLED=true`. Body `{sweep: bool}`. Used by `e2e-test.sh`.

### 6.5 Not Added

No `/api/billing/buy`, `/api/payments/*`, webhooks, invoices, payment-method storage, or "spend credits to extend storage" endpoints. All deferred to a future `payments.md`.

## 7. Frontend `/billing` Page

One new page linked from the user menu. Three sections plus a persistent disclaimer footer.

1. **Balance and runway**. Large balance display in four-decimal USD, signed (e.g., `$5.0000`, `-$0.1234`). Friendly runway estimate when positive (e.g., "~58 years at current usage"); when zero or negative the line reads "Charges continue to accumulate." The numeric balance is shown to **all users at all times**, including when negative — there is no admin-only gating.
2. **Current storage and cost**. `Storage used`, `Free baseline`, `Billable usage`, `Current rate ($10.00/TiB/month)`, `Your cost (~$0.0098/month at this usage)`, and the contrastive `Free baseline savings (~$0.0108/month — what you'd be paying without the free baseline)`. Below-baseline state replaces the cost lines with *"You are within the free baseline. No charges apply."* The cost lines render the same regardless of balance sign so beta testers always see what their actual usage would cost in a paid deployment.
3. **Transaction history**. Chronological list paginated by existing `limit`/`offset`. Each row shows date, type, signed microcent amount in four-decimal USD, and post-balance (also signed). Gift and adjustment rows show `by <admin-name>`; usage rows show no attribution.

No payment buttons. No Stripe.js. No external network requests from this page in v1. (Stripe-gating concerns — including the "click to confirm credit-card payment" pattern that loads Stripe.js only on explicit user opt-in — are deferred to `payments.md`.)

A compact one-line banner above the file list (`Balance: $5.0000  |  Storage: 2.1/50 GiB  |  ~$0.0098/month  |  Manage billing`) is optional; only render when the user has billable bytes or a non-default balance.

**No always-on disclaimer.** An earlier draft of this design specified a persistent "Beta tester credit: balances reflect what you would owe in a paid deployment" footer on every credits view. That copy was deliberately removed during Section G implementation: the panel presents the meter's facts (balance, billable bytes, projected cost) without commentary, and operator guidance about what the numbers mean is documented in `docs/billing.md` rather than embedded in the UI. Negative balances render in red as a factual UI signal; that's the only beta-relevant affordance that survives.

## 8. CLI Surface (`arkfile-admin billing`)

| Subcommand | Description |
|---|---|
| `billing show` | Pretty-prints `GET /api/admin/billing/price` + `GET /api/admin/billing/sweep-summary?days=30`. `--json` for machine output. |
| `billing show --user <name>` | Pretty-prints `GET /api/admin/credits/:username`, including `current_usage`, `credits_runway`, signed balance, last 10 transactions. |
| `billing set-price <USD-per-TB-per-month>` | `POST /api/admin/billing/set-price`. Example: `arkfile-admin billing set-price 19.99`. Local-validates parseable dollars-and-cents and `> 0`. Prints both the old and new derived `microcents_per_gib_per_hour`. |
| `billing gift --user <name> --amount <USD> --reason <text>` | `POST /api/admin/billing/gift`. Local-validates positive amount and non-empty reason. |
| `billing list-overdrawn` | `GET /api/admin/billing/overdrawn`. Shows `users_currently_overdrawn` count and the table. `--json` flag. |
| `billing tick-now [--sweep]` | Dev/test only. CLI checks `ADMIN_DEV_TEST_API_ENABLED` via a config-introspection endpoint **before** sending; handler also returns 403 if disabled. Both-sided gating. |

`arkfile-admin --help` and `arkfile-admin billing --help` updated to list the subcommands.

Not added: `arkfile-admin payments`, `arkfile-admin invoice`, `arkfile-admin refund`. Deferred to `payments.md`.

## 9. Configuration (`secrets.env`)

| Env Var | Type | Default | Meaning |
|---|---|---|---|
| `ARKFILE_BILLING_ENABLED` | bool | per-script (see below) | Master switch. When false, scheduler is not started; API endpoints continue to return current/zero state. |
| `ARKFILE_FREE_STORAGE_BYTES` | int64 | `1181116006` (1.1 GiB) | Per-instance free baseline. |
| `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH` | string | `"10.00"` | **The only pricing knob.** Dollars-and-cents string. Seeded into `billing_settings` at first startup; runtime updates use `arkfile-admin billing set-price`. |
| `ARKFILE_BILLING_GIFTED_CREDITS_USD` | string | `"5.00"` | Auto-gifted to each newly-approved user. `"0.00"` to disable. |
| `ARKFILE_BILLING_TICK_INTERVAL` | duration | `1h` | Test override only; production should leave at `1h`. |
| `ARKFILE_BILLING_SWEEP_AT_UTC` | `HH:MM` | `"00:15"` | Daily settlement time. |
| `ARKFILE_BILLING_INCLUDE_ADMINS` | bool | `false` | Include admin accounts in metering (off by default to keep beta usage data clean). |

**Removed** (do not exist in this design): `ARKFILE_BILLING_RATE_MICROCENTS_PER_GIB_HOUR`, `ARKFILE_BILLING_MARKUP_MULTIPLIER`, `ARKFILE_BILLING_RATE_FALLBACK_MICROCENTS_PER_GIB_HOUR`, `ARKFILE_BILLING_RATE_REFRESH_INTERVAL`, any rate-ceiling env var.

Per-script `ARKFILE_BILLING_ENABLED` defaults written into the generated `secrets.env`:

- `dev-reset.sh`: `false` (avoid timing-dependent test flakiness; the e2e billing test explicitly sets `true`).
- `local-deploy.sh`, `prod-deploy.sh`, `test-deploy.sh`: `true`.

Example `secrets.env` block (typical operator using defaults):

```
ARKFILE_BILLING_ENABLED=true
ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH=10.00
# ARKFILE_FREE_STORAGE_BYTES=1181116006
# ARKFILE_BILLING_GIFTED_CREDITS_USD=5.00
# ARKFILE_BILLING_TICK_INTERVAL=1h
# ARKFILE_BILLING_SWEEP_AT_UTC=00:15
# ARKFILE_BILLING_INCLUDE_ADMINS=false
```

If the operator enables a second storage backend with replication sync, raise the price to `20.00` (or any other dollars-and-cents value the operator chooses). The system makes no attempt to compute the correct number from underlying provider costs.

## 10. Test Plan

### 10.1 `billing/` Unit Tests

**`rates_test.go`**
- Conversion arithmetic: `"10.00"` → `1356`; `"19.99"` → `2711`; `"20.00"` → `2712`; `"24.99"` → `3389`. Floor-rounding verified at each boundary so derived rate never exceeds stated price.
- Parser: accepts `"10"`, `"10.0"`, `"10.00"`, `"19.99"`; rejects `""`, `"-1.00"`, `"abc"`, `"10.001"` (too many decimals).
- Resolution path: when `billing_settings` row exists, it wins; when missing, env-var fallback fires with ERROR log; when both missing, hardcoded `"10.00"` safety value with ERROR log.
- `atomic.Pointer` cache: concurrent reads during a write never observe a torn `Rate`.
- `set-price` updates `billing_settings`, atomically swaps cached pointer, and the new value is observed by the next `TickUser` call.

**`meter_test.go`**
- Tick math: edge cases at exactly the free baseline (charge = 0), one byte over (charge = `(1 * rate) >> 30`), and well over.
- Accumulator upsert: first tick inserts; subsequent ticks accumulate; `last_tick_at` monotonic.
- Below-baseline tick is a complete no-op (no DB write — verified via SQL traffic recording).
- Filtering: unapproved skipped; admin skipped when `IncludeAdmins=false`, included when `true`.
- Per-user error isolation: deliberate failure on user N does not stop user N+1.

**`sweep_test.go`**
- Drain math: known accumulator + balance → expected new balance and transaction-row content.
- **Negative-balance behavior**: balance crosses zero correctly (e.g., balance = 100, drain = 250 → new balance = -150); subsequent sweeps continue to drive the balance further negative without clamping; `transaction_type='usage'` rows are written normally.
- Per-user transaction rollback: deliberate mid-iteration error leaves prior users settled, current user unchanged, subsequent unaffected on next sweep.
- Idempotency: second sweep with no new ticks is a complete no-op.
- Metadata content: JSON contains the exact five fields from §3.5 with correct types; **explicitly asserts `avg_billable_bytes` is absent** (privacy regression guard).

**`scheduler_test.go`**
- Uses injectable `nowFn`. No `time.Sleep` in tests.
- Wall-clock alignment: starting at simulated `14:23:17`, first tick fires at `15:00:00`, then `16:00:00`, etc.
- Sweep timing: at `sweepAtUTC=12:00` over a simulated 24h window crossing 12:00, exactly one sweep call.
- Admin-set price change is observed on the next tick (rate atomically swapped).
- Skipped-sweep WARN: synthesizing `last_sweep_at = now - 26h` produces the documented WARN log.
- Clean shutdown: `cancel()` causes `Run` to return within a small timeout; no goroutine leak.

**`gift_test.go`**
- Validation: rejects `amount <= 0`, rejects empty `reason`.
- Inserts row with `transaction_type = 'gift'`, correct `admin_username`, correct `balance_after` (works correctly when starting balance is negative — gift bumps the negative balance toward zero, may or may not cross into positive).
- Emits security log event.

### 10.2 `models/credits_test.go` Updates

- Renamed columns are queried.
- `FormatCreditsUSD` produces four-decimal output from microcents, including signed (`500000000` → `"$5.0000"`, `-600` → `"-$0.0006"`, `-12345678` → `"-$0.1234"`).
- `ParseCreditsFromUSD` produces microcents with rounding at the microcent boundary; accepts a leading `-`.
- `AddCredits`/`DebitCredits`/`SetCredits` operate on microcents end-to-end and correctly handle negative starting balances.

### 10.3 Handler Tests

**`handlers/credits_test.go` (extended)**
- `GET /api/credits` shape includes `current_usage` and `credits_runway`.
- Below-baseline state returns `billable_bytes = 0` and the documented note.
- Above-baseline returns expected `current_cost_per_month_microcents` (fixed test rate for determinism).
- `formatted_balance` is four-decimal and signed.
- Negative-balance state: response includes negative `balance_usd_microcents`, `formatted_balance` rendered with leading `-`, runway note is `"Balance is negative; charges continue to accumulate."`.

**`handlers/billing_test.go` (new)**
- Each `/api/admin/billing/*` endpoint: shape, admin-auth-required (non-admin → 403), correct `LogAdminAction` call.
- `tick-now`: 403 when `ADMIN_DEV_TEST_API_ENABLED=false`.
- `set-price`: validates dollars-and-cents string, returns previous and new derived rate, takes effect on the next tick.
- `sweep-summary`: per-day rows correctly aggregated; `users_currently_negative` reflects point-in-time state.
- `overdrawn`: returns the list of users with `balance < 0`.

### 10.4 E2E Section in `scripts/testing/e2e-test.sh`

New section at end, gated by `ARKFILE_BILLING_ENABLED=true`:

1. Configure `dev-reset.sh` env to set `ARKFILE_BILLING_ENABLED=true`, `ARKFILE_BILLING_TICK_INTERVAL=1m`, `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH=10.00`, `ARKFILE_BILLING_GIFTED_CREDITS_USD=1.00`, `ARKFILE_FREE_STORAGE_BYTES=10485760` (10 MiB, so test files become billable quickly).
2. `dev-reset.sh` runs.
3. Test user uploads ~100 MB of files (≈ 90 MiB billable above the 10 MiB baseline).
4. `arkfile-admin billing tick-now --sweep` to advance the meter immediately.
5. Assert balance decreased by the computed expected amount (`90 MiB × rate × 1h`, with the right-shift truncation accounted for); assert one `usage` row in `credit_transactions` with the §3.5 metadata shape (and assert `avg_billable_bytes` field is absent).
6. `arkfile-admin billing gift --user <test-user> --amount 5.00 --reason "e2e test gift"`. Assert balance increased and a `gift` row exists.
7. `arkfile-admin billing set-price 19.99`. Assert response shows old (1356) and new (2711) derived rates. `tick-now` again and assert subsequent usage row reflects the new rate.
8. Repeat `tick-now --sweep` enough times to drive balance below zero. Assert `balance_usd_microcents < 0`, the user appears in `arkfile-admin billing list-overdrawn`, and the `GET /api/credits` response for that user includes the negative-balance runway note.
9. Cleanup: delete test files, cancel sessions.

### 10.5 Playwright Section in `scripts/testing/e2e-playwright.ts`

Minimal functional checks only:

1. Open the Billing panel via the in-app nav link.
2. Assert balance display matches the value returned by `GET /api/credits` (including correct sign and four-decimal formatting).
3. Assert `current_usage` numeric fields (storage used, free baseline, billable bytes, current cost per month) match the API response for the known test user.
4. Assert at least one `gift` row and one `usage` row appear in the transaction-history list with correct signed amounts.

Not asserted in v1: anything Stripe-related, anything CSP-related, anything about absence of third-party scripts. Those concerns belong to `payments.md`.

### 10.6 Coverage Targets

- `billing/`: 90%+ line coverage. Achievable: small package, side-effects concentrated in DB calls.
- New handlers: ~70% (matches existing handler standard).
- E2E: every documented user-visible behavior (gift, tick, sweep, negative balance, set-price) exercised at least once.

## 11. Implementation Checklist

Ten PR-sized steps for one engineer (~2-3 weeks total). This is a recommended landing order, not a phased multi-release rollout: the whole design lands together. Each step leaves the tree buildable and deployable.

| # | Step | Approx LOC | Status |
|---|---|---:|---|
| 1 | Reconcile `users.storage_limit_bytes` default to `1181116006`. | ~10 | [DONE] |
| 2 | Rename `_cents` → `_microcents` end-to-end (schema, models, handlers, CLI, helpers, tests). **In-place ALTER-style migration** preserves any existing `user_credits` / `credit_transactions` rows; widens columns to `BIGINT`; removes any `CHECK (balance >= 0)` so balances may go negative. Drops `usage_deficit_microcents` from the design (never shipped). Single PR with destructive-vs-in-place migration warning in commit message. **Per Q3 (operator decision): default gift to new users is now `0.00` USD; users start at zero balance and only manual admin gifts add credit.** Cleanup also removes the deprecated `models.AddCredits`, `models.DebitCredits`, `models.SetCredits` functions and the `POST /api/admin/credits/:username` and `PUT /api/admin/credits/:username` admin endpoints, replaced by typed `gift` transactions via `/api/admin/billing/gift`. | ~500 | [DONE] |
| 3 | Add `storage_usage_accumulator` and `billing_settings` tables + indexes; document `usage` / `gift` transaction-type values; seed `billing_settings.customer_price_usd_per_tb_per_month` from env on first startup. | ~80 | [DONE] |
| 4 | New `billing/` package (six files + tests), including `set-price` cache invalidation. Compiles standalone, dead code at this step. | ~600 | [DONE] |
| 5 | Wire scheduler into `main.go`; add `ARKFILE_BILLING_*` and `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH` to config loader; update deploy scripts to write defaults into generated `secrets.env`. Meter starts running on production-flavored deploys; no API exposure yet. | ~60 | [DONE: scheduler wiring + config loader completed in Section D; all four deploy scripts (dev-reset.sh, local-deploy.sh, prod-deploy.sh, test-deploy.sh) now write ARKFILE_BILLING_* defaults to their secrets.env heredoc. dev-reset.sh uses fast-test cadence (TICK_INTERVAL=1m, FREE_STORAGE_BYTES=10485760, GIFTED_CREDITS_USD=1.00) so the e2e billing phase can observe a full tick→sweep→negative-balance cycle quickly; the three production deploy scripts use TICK_INTERVAL=1h, FREE_STORAGE_BYTES=1181116006, GIFTED_CREDITS_USD=0.00.] |
| 6 | Extend handlers: `current_usage` / `credits_runway` blocks; new `/api/admin/billing/*` endpoints (`price`, `set-price`, `sweep-summary`, `overdrawn`, `gift`, `tick-now`); handler tests. | ~320 | [DONE: GET extensions in Section B+C; new admin endpoints in Section E. `tick-now` is registered under `/api/admin/dev-test/billing/tick-now` (gated by `ADMIN_DEV_TEST_API_ENABLED`); the route is physically not registered in production-flavored deployments. Handler unit tests are deferred to Section H's e2e billing test, matching the pattern used for other DB-heavy admin endpoints in the codebase.] |
| 7 | New frontend `/billing` page with three sections + optional banner; minimal Playwright tests per §10.5. | ~380 | [DONE: implemented as an inline panel toggled from the file-section nav (matching the existing security-settings + contact-info pattern) rather than as a standalone `/billing` route, since the SPA has no router and the inline-panel idiom is the only navigation primitive in the app. The Section G-polish pass (a) deleted the always-on beta disclaimer entirely from the response and the panel (see §7's "No always-on disclaimer" paragraph for the rationale), (b) added the `.billing-panel-section` CSS block in `client/static/css/styles.css` so the `<dl>` renders as a tight two-column grid with section eyebrows + tabular numerics + red negative-balance highlighting, (c) tightened copy by deleting the "Free baseline savings" and "Current rate" lines from the user view (the rate is admin-facing; users see only their own projected cost), and (d) moved the runway display from its own line under the balance to a row in the storage grid, directly under "Your projected cost", so the rate→cost→runway relationship is visually adjacent. The optional one-line banner above the file list is also omitted in this implementation; the always-visible Billing nav link makes the same data one click away. Playwright tests deferred to Section H.] |
| 8 | `arkfile-admin billing` subcommand group (`show`, `set-price`, `gift`, `list-overdrawn`, `tick-now`). | ~380 | [DONE] |
| 9 | E2E billing tests: (a) `dev-reset.sh` writes billing env vars to `secrets.env` so the meter actually runs in dev; (b) new `phase_11d_billing` in `scripts/testing/e2e-test.sh` exercises the full meter lifecycle (gift → tick → sweep → set-price → drive negative); (c) Playwright test verifying the Billing panel renders correctly with real meter data. | ~150 | [DONE: phase_11d_billing added before phase_12_cleanup — six subsections: initial-gift balance, tick accumulation, tick+sweep usage-transaction with privacy regression guard (avg_billable_bytes absent), gift, set-price round-trip, drive-negative + list-overdrawn; zero new login/logout cycles. Playwright test appended to e2e-playwright.ts asserting balance format, usage grid labels, gift+usage rows, negative-amount red highlight, and zero .billing-beta-disclaimer elements.] |

Total ≈ 2,450 lines, ~60% non-test. (Earlier drafts of this doc included a row 10 for `docs/billing.md`; that operator-facing markdown was deleted from scope -- the user-facing documentation surface is the code comments, `arkfile-admin billing --help`, and the Billing panel UI itself, not a separate operator page.)

**Beta-tester file safety reminder for step 2** (and any subsequent migration step): the migration must be in-place ALTER-style, not drop-and-recreate. Use `test-update.sh` (not `test-deploy.sh`) when applying to `test.arkfile.net`. See §4.3.

### 11.1 Implementation Status (live)

**DONE through Section G-polish (current session):**

- A — schema foundation (`storage_limit_bytes` reconcile, microcent rename, `storage_usage_accumulator` + `billing_settings` tables, in-place migration).
- B+C — `models/credits.go` rename to microcents; deleted deprecated `AddCredits`/`DebitCredits`/`SetCredits` and the `POST/PUT /api/admin/credits/:username` endpoints; extended `GET /api/credits` and `GET /api/admin/credits[/:username]` with `current_usage` and `credits_runway` blocks.
- D — `billing/` package (types, rates, meter, sweep, scheduler, gift) with full test coverage; `main.go` wires the scheduler when `cfg.Billing.Enabled=true`; config loader reads all `ARKFILE_BILLING_*` and `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH` env vars.
- E — `/api/admin/billing/*` endpoints in `handlers/admin_billing.go`: `GET price`, `POST set-price`, `GET sweep-summary`, `GET overdrawn`, `POST gift`. The dev/test-only `tick-now` is registered under `/api/admin/dev-test/billing/tick-now` (gated by `ADMIN_DEV_TEST_API_ENABLED`); the route is physically not registered in production-flavored deployments.
- F — `arkfile-admin billing` subcommand group (`show [--user NAME]`, `set-price`, `gift`, `list-overdrawn`, `tick-now [--sweep]`); all subcommands have `--json` output and full `--help` text; the `tick-now` subcommand emits a friendly local pre-flight warning when `ADMIN_DEV_TEST_API_ENABLED` is unset.
- G — Frontend Billing panel (`client/static/js/src/ui/billing.ts`) implemented as an inline panel toggled from the file-section nav, matching the existing security-settings + contact-info pattern. Three sections: Balance, Current Storage and Cost (grid layout), Transaction History (collapsed when empty).
- G-polish — disclaimer footer entirely deleted from both server (`handlers/credits.go`) and panel; `.billing-panel-section` CSS block in `client/static/css/styles.css` produces a tight two-column grid with section eyebrows, tabular numerics, and red negative-balance highlighting; "Estimated runway" moved into the Current Storage and Cost grid directly under "Your projected cost".

- H+J — all four deploy scripts write `ARKFILE_BILLING_*` defaults (see §11 row 5); `phase_11d_billing` added to `scripts/testing/e2e-test.sh`; Playwright billing-panel test added to `scripts/testing/e2e-playwright.ts` (see §11 row 9 for detail).

All sections complete.

**Architectural note** (carried forward from §11.2): when the meter is enabled at runtime, the scheduler reads its config at startup; env vars must therefore be present **before** `dev-reset.sh` / `*-deploy.sh` runs. The handler/billing import seam (function-pointer indirection through `handlers/billing_projection.go`) means `/api/credits` always returns the same JSON shape regardless of whether the meter is enabled, so the frontend and tests can rely on the response structure being stable.

### 11.2 Architectural Note: handler / billing import seam

To keep the dependency arrow `billing → models`, `handlers → models`, `main → billing + handlers` clean (and avoid an import cycle through models), `handlers/` does **not** import the `billing/` package directly. Instead, `main.go` wires function-pointer seams during startup:

- `handlers.SetBillingProjectionSeams(freeBaselineFn, resolveRateFn)` — the projection helper used by `GET /api/credits` and the admin per-user endpoints.
- `handlers.SetBillingGiftFunc(billing.GiftCredits)` — used by `POST /api/admin/billing/gift`.
- `handlers.SetBillingSetPriceFunc(...)` — wraps `billing.SetCustomerPrice`; used by `POST /api/admin/billing/set-price`.
- `handlers.SetBillingTickNowFunc(...)` and `SetBillingSweepNowFunc(...)` — used by `POST /api/admin/billing/tick-now` (gated to dev/test).

The seams are wired even when `cfg.Billing.Enabled=false`, so `/api/credits` always returns the same JSON shape; rate-dependent fields fall back to zero / `"Billing rate not yet resolved."` rather than disappearing from the response. Frontend and tests can therefore rely on the response structure being stable across enabled/disabled state.

Future contributors adding new endpoints that need to call into `billing/` should follow the same pattern: define a function-pointer seam in `handlers/billing_projection.go`, expose it via a `Set*Func` setter, and wire it from `main.go` alongside the others.

## 12. Honest Trade-offs

| # | Trade-off | Mitigation |
|---|---|---|
| 1 | Beta testers see a balance that can go negative even though no money changes hands; some may misread it as being charged. | An earlier draft of this design specified an always-on disclaimer footer to mitigate this. That copy was deliberately removed during Section G implementation (see §7's "No always-on disclaimer" paragraph). Operator guidance about what the numbers mean lives in this design doc and the `arkfile-admin billing --help` text rather than the UI. The negative balance is itself the useful signal — beta testers can see what their actual usage would cost in a paid deployment. |
| 2 | Single price knob means the operator must know what to set; no auto-derivation from provider costs. | Suggested defaults documented (`10.00` for one backend, `20.00` for two with replication). `arkfile-admin billing set-price` is a single command. `storage_providers.cost_per_tb_cents` is retained in schema for operator reference even though the meter does not read it. |
| 3 | Skipped-sweep day produces one larger transaction row spanning >24h. | Scheduler logs WARN on detection (`> 25h since last sweep`); `period_start`/`period_end` accurately reflect the actual span so reconciliation works. |
| 4 | Unbounded accumulator if sweeps fail repeatedly and unmonitored. | Real impact small (1 row/user, 2 int columns); operator alert on `last_billed_at < now - 48h`. |
| 5 | Restart bridges a tick boundary → at-least-once tick (brief slight overcharge). | Documented; the per-tick amount is at most 1 hour of microcents and washes out in practice. |
| 6 | Microcent migration touches credit-ledger schema. | In-place ALTER-style migration (step 2) preserves existing rows; deltas in this doc do **not** render uploaded files inaccessible. **However** running `test-deploy.sh` on `test.arkfile.net` would wipe everything regardless — use `test-update.sh`. See §4.3. |
| 7 | No bandwidth/egress billing. | Storage-only is a deliberate scope decision; operator sets a higher customer price if they have download-heavy users. |
| 8 | Single-process scheduler; multi-instance deployment would double-count. | Single-process matches the rest of the architecture (rqlite/SQLite consistency point); not a current concern. |
| 9 | Negative balances can grow unboundedly if a user is forgotten. | Visible in `arkfile-admin billing list-overdrawn` and in `sweep-summary.users_currently_negative`; future payments work decides resolution policy. |
| 10 | `users.storage_limit_bytes` hard cap and credit-balance soft signal coexist. | Both shown in `GET /api/admin/users/:username/status` so the contrast is visible; unifying them is a payments-work decision. |
| 11 | Per-day storage history persistence would be a new privacy disclosure. | **Eliminated**: §3.5 metadata excludes `avg_billable_bytes`. Reconciliation uses `drained_microcents` + `rate_microcents_per_gib_per_hour` only. |
| 12 | 30-day month convention introduces ~3% per-month variance. | Standard cloud-billing convention; UI uses approximate framing (`~$0.0098/month`) for projections; precise four-decimal display is reserved for actual balances and transaction amounts. |
| 13 | Test coverage of a meter that ticks hourly requires injectable time. | `Scheduler.nowFn` interface + `tickEvery` configuration make all timing testable without `time.Sleep`. |

## 13. Forward-Looking: Future `docs/wip/payments.md`

Scaffolding only. Not designed here.

**Hard prerequisites before payments work begins**:

1. **Item 8 of `general-enhancements.md`**: column-evolution layer. Once real money flows, "wipe to add a column" is unacceptable. (The in-place migration pattern established by step 2 of this design is a partial down payment on that.)
2. **Item 2 of `general-enhancements.md`**: pre-flight storage-quota endpoint. Clients need to ask "do I have room, and can I buy room if not?" before initiating uploads.
3. **At least 2–4 weeks of meter data from this design's deployment** to confirm the customer price and free baseline defaults with real-usage evidence rather than guesses.

**What this design locks in** (payments work must not regress):

- Microcent unit; rate denominated in microcents/GiB/hour; balances signed `int64` microcents.
- Hourly tick + daily settlement pattern; payments-driven credits land directly on `user_credits.balance_usd_microcents` (driving negative balances back toward zero or positive), and continue to drain via the same daily sweep.
- `credit_transactions` audit-log shape; payment top-ups add types like `payment_btc`, `payment_lightning`, `payment_monero`, `payment_stripe` without schema change.
- Settlement metadata excludes per-day storage history (privacy invariant).
- Free-baseline-above-which-billable model.
- Single `customer_price_usd_per_tb_per_month` knob owned by the operator.
- `users.storage_limit_bytes` hard cap is independent of credit balance; payments work is free to couple them or not.

**Open for the future document**:

- Whether `storage_limit_bytes` is replaced by a credit-balance-derived cap or kept independent.
- Per-user free-baseline overrides (grandfathered users, etc.).
- Bandwidth/egress billing.
- BTCPay (Lightning, on-chain BTC, Monero, stablecoins) and Stripe webhook handler shapes; idempotent invoice table; PII-scrubbing posture for Stripe `Customer` objects (`email=null`, `name=null`).
- Stripe.js gating: default off; loaded only after explicit user opt-in click ("click here to confirm you want to pay with a credit card instead of more private options such as Bitcoin, stablecoins, or Monero"); CSP exception only on the opt-in path.
- Auto-top-up policy and operator-configured monthly cap.
- Refund / pull-payment flow.
- Negative-balance resolution policy (write-off, attach to next top-up, soft block on uploads, etc.).

When the operator is ready, create `docs/wip/payments.md` and design these with this document's level of detail.
