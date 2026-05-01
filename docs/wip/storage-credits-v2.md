# Storage Credits and Usage Metering (v2 — streamlined)

This is a condensed, implementation-driving rewrite of `docs/wip/storage-credits.md`. It is intentionally definitive: design fixes that the v1 doc left as open questions or buried in a review-feedback appendix are folded in here as decisions. Where the v1 doc was wrong (notably the rate-units arithmetic), v2 corrects it.

## 1. Scope

Build a usage meter that bills every approved user's stored bytes against a microcent-denominated credit balance. No payment provider integration, no over-quota enforcement based on balance, no auto-deletion. The existing `users.storage_limit_bytes` hard cap is unchanged. Payment integration is a separate future document (`docs/wip/payments.md`).

Meter-first sequencing rationale (one paragraph): the meter's correctness questions (precision, accumulation semantics, rate changes) are independent of any provider's API and are easier to get right in isolation; running the meter against the live beta with no real money produces real usage data that anchors the eventual pricing decisions; the cents-to-microcents schema migration is cheapest to do before any provider depends on the columns; payment-provider integration is the largest single increase in privacy attack surface and deserves its own focused review.

## 2. What Already Exists

Confirmed against the codebase:

- `models/user.go`: `DefaultStorageLimit = 1181116006` (1.1 GiB). `IsApproved` and `IsAdmin` fields. `User.CheckStorageAvailable(size)` is the upload-time hard-cap gate.
- `database/unified_schema.sql`:
  - `users.total_storage_bytes BIGINT` (maintained by upload/delete paths).
  - `users.storage_limit_bytes BIGINT NOT NULL DEFAULT 10737418240` (10 GiB) — disagrees with the Go constant; reconciled in v2.
  - `user_credits(balance_usd_cents INTEGER, ...)` with auto-update trigger.
  - `credit_transactions(transaction_id, username, amount_usd_cents INTEGER, balance_after_usd_cents INTEGER, transaction_type TEXT, reason, admin_username, metadata TEXT, created_at)` — `transaction_type` has no enum constraint.
  - `storage_providers(provider_id, ..., role TEXT DEFAULT 'tertiary', is_active BOOLEAN, cost_per_tb_cents INTEGER NULL, ...)`.
  - Indexes on `user_credits(username)`, `credit_transactions(username, transaction_id, type, created_at, admin_username)`.
- `models/credits.go`: `UserCredit`, `CreditTransaction`, `GetOrCreateUserCredits`, `GetUserCredits`, `CreateUserCredits`, `AddCredits`, `DebitCredits`, `SetCredits`, `GetUserTransactions`, `GetAllUserCredits`, `FormatCreditsUSD`, `ParseCreditsFromUSD`, `GetUserCreditsSummary`. Transaction-type constants: `credit`, `debit`, `adjustment`, `refund`. All write paths are DB-transactional and emit `logging.LogSecurityEvent(EventAdminAccess, ...)`.
- API endpoints: `GET /api/credits`, `GET /api/admin/credits`, `GET /api/admin/credits/:username`, `POST /api/admin/credits/:username` (add/subtract/set with required reason), `PUT /api/admin/credits/:username`. Admin upload-cap endpoint `PUT /api/admin/users/:username/storage`.
- `arkfile-admin set-cost --provider-id ID --cost AMOUNT` already writes `storage_providers.cost_per_tb_cents`.
- Admin actions are logged via `LogAdminAction` to the `admin_logs` table.

Nothing in the credits ledger is connected to storage usage today. The frontend has no billing page.

## 3. Pricing Model

### 3.1 Internal Unit: Microcents per GiB per Hour

All balances and amounts are stored as `int64` **microcents** (1 USD = 100 cents = 100,000,000 microcents). The int64 range is ~$92 billion — comfortable.

The **rate** is denominated as `int64` **microcents per GiB per hour** (binary GiB = 2^30 bytes). This is the canonical internal unit.

Why this unit: storing the rate per byte per hour in microcents truncates to a sub-integer value at realistic prices ($20/TiB/month ≈ 0.00253 microcents/byte/hour, which rounds to zero as int64). Per-GiB-per-hour gives clean integer rates: $20/TiB/month ≈ 2,712 microcents/GiB/hour, with comfortable headroom.

The per-tick math is one int64 multiply + one shift:

```
tick_charge_microcents = (billable_bytes * rate_microcents_per_gib_per_hour) >> 30
```

The shift truncates fractional microcents per tick. At 2,712 microcents/GiB/hour, each truncated fraction is < 1 microcent/hour ≈ < $0.0000088/year/user — well below noise floor.

**Display formatting**: balances and transaction amounts in microcents are formatted with four decimal places of USD (e.g., `"$5.0000"`, `"-$0.0006"`) so fractional-cent accounting is honest. *Projected* monthly costs in the UI use approximate framing (`"~$0.02/month"`) because the 30-day month convention introduces ~3% variance against actual months — calling it precise to four decimals would be misleading.

### 3.2 Tick (Hourly) and Settlement (Daily)

The meter ticks once per wall-clock hour (top-of-hour aligned; see §5.4). For each active user:

1. Read `total_storage_bytes` from `users`.
2. `billable_bytes = max(0, total_storage_bytes - free_baseline_bytes)`.
3. `tick_charge_microcents = (billable_bytes * rate_microcents_per_gib_per_hour) >> 30`.
4. If `tick_charge_microcents > 0`, upsert `storage_usage_accumulator` (one row per billable user) and update `last_tick_at`.

Ticks do not touch `user_credits` or `credit_transactions`. Users at or below the free baseline produce no DB write.

Once per day at a configurable UTC time (default `00:15`), a settlement sweep runs. For each accumulator row with `unbilled_microcents > 0`, in a per-user transaction:

1. Read `user_credits.balance_usd_microcents` (create at zero if missing).
2. `new_balance = max(0, balance - unbilled)`; `deficit_added = max(0, unbilled - balance)`.
3. Update `user_credits.balance_usd_microcents = new_balance`.
4. If `deficit_added > 0`: `users.usage_deficit_microcents += deficit_added`; emit `balance_exhausted` log event.
5. Insert one `credit_transactions` row: `transaction_type = 'usage'`, `amount_usd_microcents = -drained`, `balance_after_usd_microcents = new_balance`, `reason = "Daily storage usage"`, `metadata` JSON described in §3.5.
6. Zero the accumulator row; set `last_billed_at = now`.

Per-user transactions make the sweep restartable: a crash mid-iteration leaves already-swept users correct, and the next sweep picks up the rest. The `last_billed_at` watermark prevents double-billing.

Audit-log volume scales as `users × days`, not `users × hours`: 100 users × 365 days = 36,500 rows/year (vs. 876,000 if logged per-tick).

### 3.3 Auto-Derived Sticker Rate

When `ARKFILE_BILLING_RATE_MICROCENTS_PER_GIB_HOUR` is unset, the rate is derived at startup and refreshed every `ARKFILE_BILLING_RATE_REFRESH_INTERVAL` (default 15m):

```
base_cost_per_tb_per_month_cents = SUM(
    cost_per_tb_cents
    FROM storage_providers
    WHERE is_active = true
      AND role IN ('primary', 'secondary', 'tertiary')
      AND cost_per_tb_cents IS NOT NULL
)
sticker_per_tb_per_month_microcents =
    base_cost_per_tb_per_month_cents * 1000 * markup_multiplier
sticker_per_gib_per_hour_microcents =
    sticker_per_tb_per_month_microcents / 1024 / 30 / 24
```

TiB and GiB are binary (2^40, 2^30). Months are conventionally 30 days × 24 hours = 720 hours.

Worked example: Wasabi $7.99 + Backblaze $6.00 = $13.99/TiB/month base × 1.43 markup = $20.0057/TiB/month sticker (rounded honestly, not to a fake clean $20.00) ≈ **2,713 microcents/GiB/hour**.

Resolution priority:

1. `ARKFILE_BILLING_RATE_MICROCENTS_PER_GIB_HOUR` set → use it. `Source = "env"`.
2. Else, `storage_providers` query above → derive. `Source = "auto-derived"`.
3. Else (no providers or all NULL costs) → use fallback constant `2712` (≈ $20/TiB/month). `Source = "fallback-default"`. Logged WARN.

Resolved rate is logged INFO at startup and on every refresh-induced change.

### 3.4 Billable Bytes and Active Users

**Billable bytes** = `max(0, total_storage_bytes - free_baseline_bytes)`. The free baseline is per-instance (`ARKFILE_FREE_STORAGE_BYTES`, default = `1181116006` to match the Go `DefaultStorageLimit`). It operates independently of `users.storage_limit_bytes`: a user with a 50 GiB cap and 30 GiB stored has 28.9 GiB billable.

**Active users** for billing: `is_approved = true` and not deleted. Admins (`is_admin = true` or username matches `isAdminUsername()`) are excluded by default; toggle via `ARKFILE_BILLING_INCLUDE_ADMINS=true` (default `false`) so operator self-usage doesn't pollute beta usage data.

### 3.5 Settlement Metadata (Privacy-Sensitive)

The daily-sweep `credit_transactions.metadata` JSON contains **only**:

```json
{
  "drained_microcents": 600,
  "rate_microcents_per_gib_per_hour": 2712,
  "period_start": "2026-04-30T00:15:00Z",
  "period_end":   "2026-05-01T00:15:00Z",
  "ticks_count":  24
}
```

It deliberately **omits** `avg_billable_bytes` (and any field that lets an observer reconstruct per-day storage history). `users.total_storage_bytes` already discloses current state; the meter must not introduce a new persistent per-day storage time-series. Reconciliation (cents owed vs. cents drained) is still possible from `drained_microcents` and `rate_microcents_per_gib_per_hour`.

## 4. Schema Changes

Migration strategy: wipe-and-redeploy. Greenfield, no production deployments, `dev-reset.sh`/`local-deploy.sh`/`prod-deploy.sh` accept full data wipe. **Hard prerequisite for any future payments work**: the column-evolution layer described in `docs/wip/general-enhancements.md` Item 8 must land before real money flows. Document this in the repo CHANGELOG when v2 is implemented.

### 4.1 Summary of Deltas

1. `users.storage_limit_bytes` default: `10737418240` → `1181116006` (matches `models.DefaultStorageLimit`).
2. `users.usage_deficit_microcents BIGINT NOT NULL DEFAULT 0` (new).
3. `user_credits.balance_usd_cents` → `user_credits.balance_usd_microcents BIGINT NOT NULL DEFAULT 0`.
4. `credit_transactions.amount_usd_cents` → `credit_transactions.amount_usd_microcents BIGINT NOT NULL`.
5. `credit_transactions.balance_after_usd_cents` → `credit_transactions.balance_after_usd_microcents BIGINT NOT NULL`.
6. `credit_transactions.transaction_type` accepts new values `usage` and `gift` (no enum constraint exists; documentation/code-side change).
7. New table `storage_usage_accumulator`:

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

The existing `INTEGER` columns are widened to `BIGINT` for cross-backend safety; in SQLite this is a no-op (INTEGER is already 64-bit) but spelling it `BIGINT` makes intent clear if/when a non-SQLite backend is introduced.

### 4.2 Rename Surface (Go and JSON)

- `models.UserCredit.BalanceUSDCents` → `BalanceUSDMicrocents`; JSON tag `balance_usd_microcents`.
- `models.CreditTransaction.AmountUSDCents` → `AmountUSDMicrocents`; JSON `amount_usd_microcents`.
- `models.CreditTransaction.BalanceAfterUSDCents` → `BalanceAfterUSDMicrocents`; JSON `balance_after_usd_microcents`.
- New transaction-type constants: `TransactionTypeUsage = "usage"`, `TransactionTypeGift = "gift"`.
- `models.FormatCreditsUSD(microcents int64) string` → four-decimal output (`"$5.0000"`, `"-$0.0006"`).
- `models.ParseCreditsFromUSD(s string) (int64, error)` → returns microcents, with rounding at the microcent boundary.
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
    ResolvedAt                   time.Time
    Source                       string   // "env" | "auto-derived" | "fallback-default"
    BaseCostPerTBPerMonthCents   int64    // 0 unless Source == "auto-derived"
    MarkupMultiplier             float64  // 1.0 unless Source == "auto-derived"
    ContributingProviders        []string // empty unless Source == "auto-derived"
}

func ResolveRate(db *sql.DB, cfg BillingConfig) (*Rate, error)
func (r *Rate) FormatHumanReadable() string
```

Cached in a package-level `atomic.Pointer[*Rate]`. Lock-free reads from the meter and from API handlers.

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
    UsersNewlyInDeficit       int    // newly clamped to zero in this sweep
    TotalDeficitAddedMicrocents int64
}
```

Iterates `storage_usage_accumulator` where `unbilled_microcents > 0`. Per-user algorithm is steps 1–6 from §3.2. Idempotent on a per-row basis (zeroed accumulator row → no-op on next sweep).

The sweep uses the rate active at sweep time. Mid-day rate changes are not reconciled per-tick in v2 (acceptable approximation; revisit if pricing volatility demands it).

`UsersNewlyInDeficit` counts users whose `usage_deficit_microcents` increased *during this sweep*, not the running total. The point-in-time count of users currently in any deficit is queried separately via `arkfile-admin billing list-deficits`.

### 5.4 `Scheduler` (Wall-Clock Aligned)

```go
type Scheduler struct {
    db               *sql.DB
    cfg              BillingConfig
    tickEvery        time.Duration   // default 1h
    sweepAtUTC       string          // default "00:15"
    rateRefreshEvery time.Duration   // default 15m
    nowFn            func() time.Time // injectable for tests; defaults to time.Now
}

func (s *Scheduler) Run(ctx context.Context) error
```

The scheduler aligns ticks to top-of-hour: at startup it sleeps until `now.Truncate(tickEvery).Add(tickEvery)`, then ticks at that interval. The sweep fires once per UTC day at `sweepAtUTC`. Operator audit reasoning ("at 03:00 UTC, every billable user should have been ticked") is preserved across restarts.

**Restart semantics**: ticks are *at-least-once*. If a `prod-update.sh` restart bridges a tick boundary, the new binary's first aligned tick may fire within seconds of the old binary's last tick. The accumulator's `+= excluded.unbilled_microcents` correctly accumulates, so the user is briefly slightly overcharged (one extra tick, ≈ one hour's worth of microcents). Documented; acceptable.

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

Every `*_usd_cents` JSON field in credits responses becomes `*_usd_microcents`. `formatted_balance` retains the same key but emits four-decimal precision. The `arkfile-admin` CLI structs are updated in lockstep so there is no version-skew window.

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
    "rate_microcents_per_gib_per_hour": 2712,
    "rate_human": "~$20.00/TiB/month",
    "current_cost_per_month_microcents": 1953216,
    "current_cost_per_month_usd_approx": "~$0.0195"
  },
  "credits_runway": {
    "estimated_hours_remaining": 256000,
    "estimated_runs_out_at_approx": "2055-02-03T00:00:00Z",
    "rate_source": "auto-derived",
    "computed_at": "2026-04-30T20:15:00Z"
  },
  "transactions": [...],
  "pagination": {...}
}
```

Below-baseline: `billable_bytes = 0`, `current_cost_per_month_microcents = 0`, `credits_runway` becomes `{"estimated_hours_remaining": null, "note": "You are within the free baseline. No usage charges apply.", ...}`.

Sanity-check the displayed runway: $5.0000 ÷ $0.0195/month ≈ 256 months ≈ 21 years.

### 6.3 Extended Admin Endpoints

- `GET /api/admin/credits` — list-all gains per-user `current_usage` block (no runway; expensive).
- `GET /api/admin/credits/:username` — gains `current_usage` + `credits_runway`, retains existing `admin_info`.
- `GET /api/admin/users/:username/status` — gains `billing` block: `balance_usd_microcents`, `formatted_balance`, `billable_bytes`, `current_cost_per_month_usd_approx`, `usage_deficit_microcents`, `last_billed_at`.

### 6.4 New Admin Endpoints

All under `adminGroup` (existing TOTP-protected). All admin actions logged to `admin_logs` via `LogAdminAction`.

- `GET /api/admin/billing/rate` — current resolved `Rate`. Fields `base_cost_*`, `markup_multiplier`, `contributing_providers` are present only when `source == "auto-derived"`. When `source == "fallback-default"`, an explanatory `note` is included.
- `POST /api/admin/billing/recompute-rate` — re-runs `ResolveRate`, atomically swaps the cached pointer, returns `{ "rate": {...}, "previous_rate_microcents_per_gib_per_hour": N }`. Response includes `"changed": true|false`.
- `GET /api/admin/billing/sweep-summary?days=7` — last N days of daily totals from `credit_transactions WHERE transaction_type='usage'` aggregated by day. Each row includes `users_settled`, `total_drained_microcents`, `total_drained_usd`, `users_newly_in_deficit_today`, `total_deficit_added_microcents`. Fields are explicitly named `..._today` / `_newly_` to prevent the misinterpretation that summing across days gives current-deficit population.
- `GET /api/admin/billing/deficits` — list users with `usage_deficit_microcents > 0`. Used by CLI `list-deficits`. Returns point-in-time `users_currently_in_deficit` count.
- `POST /api/admin/billing/gift` — body `{target_username, amount_usd, reason}`. Validates, calls `GiftCredits`, returns `transaction` and `updated_balance`.
- `POST /api/admin/billing/tick-now` — dev/test only. Returns 403 unless `ADMIN_DEV_TEST_API_ENABLED=true`. Body `{sweep: bool}`. Used by `e2e-test.sh`.

### 6.5 Not Added in v2

No `/api/billing/buy`, `/api/payments/*`, webhooks, invoices, payment-method storage, or "spend credits to extend storage" endpoints. All deferred.

## 7. Frontend `/billing` Page

One new page linked from the user menu. Three sections:

1. **Balance and runway**. Large balance display in four-decimal USD. Friendly runway estimate ("~21 years at current usage"). When balance is zero, the page does **not** display a numeric deficit to end users in v2; it shows: *"Beta preview: usage metering is active but no real charges occur. Continue using the service normally."* This avoids "what is this $0.0234 deficit?" support-ticket churn while still letting admins see the full deficit number via admin views.
2. **Current storage and cost**. `Storage used`, `Free baseline`, `Billable usage`, `Current rate (~$20.00/TiB/month)`, `Your cost (~$0.0195/month at this usage)`, and the contrastive `Free baseline savings (~$0.0216/month — what you'd be paying without the free baseline)`. Below-baseline state replaces the cost lines with *"You are within the free baseline. No charges apply."*
3. **Transaction history**. Chronological list paginated by existing `limit`/`offset`. Each row shows date, type, signed microcent amount in four-decimal USD, and post-balance. Gift and adjustment rows show `by <admin-name>`; usage rows show no attribution.

No payment buttons. No Stripe.js. No external network requests. The Playwright test (§9) asserts *no* `<script src="https://js.stripe.com/...">` and *no* requests to `js.stripe.com` exist on this page — regression guard for the privacy posture.

A compact one-line banner above the file list (`Balance: $5.0000  |  Storage: 2.1/50 GiB  |  ~$0.0195/month  |  Manage billing`) is optional; only render when the user has billable bytes or a non-default balance.

## 8. CLI Surface (`arkfile-admin billing`)

| Subcommand | Description |
|---|---|
| `billing show` | Pretty-prints `GET /api/admin/billing/rate` + `GET /api/admin/billing/sweep-summary?days=30`. `--json` for machine output. |
| `billing show --user <name>` | Pretty-prints `GET /api/admin/credits/:username`, including `current_usage`, `credits_runway`, `usage_deficit`, last 10 transactions. |
| `billing gift --user <name> --amount <USD> --reason <text>` | `POST /api/admin/billing/gift`. Local-validates positive amount and non-empty reason. |
| `billing recompute-rate` | `POST /api/admin/billing/recompute-rate`. If unchanged, prints "no change" and exits 0. |
| `billing list-deficits` | `GET /api/admin/billing/deficits`. Shows `users_currently_in_deficit` count and the table. `--json` flag. |
| `billing tick-now [--sweep]` | Dev/test only. CLI checks `ADMIN_DEV_TEST_API_ENABLED` via a config-introspection endpoint **before** sending; handler also returns 403 if disabled. Both-sided gating. |

`arkfile-admin --help` and `arkfile-admin billing --help` updated to list the subcommands.

Not added: `arkfile-admin payments`, `arkfile-admin invoice`, `arkfile-admin refund`. Deferred.

## 9. Configuration (`secrets.env`)

| Env Var | Type | Default | Meaning |
|---|---|---|---|
| `ARKFILE_BILLING_ENABLED` | bool | per-script (see below) | Master switch. When false, scheduler is not started; API endpoints continue to return current/zero state. |
| `ARKFILE_FREE_STORAGE_BYTES` | int64 | `1181116006` (1.1 GiB) | Per-instance free baseline. |
| `ARKFILE_BILLING_RATE_MICROCENTS_PER_GIB_HOUR` | int64 | unset | Explicit sticker rate. When set, overrides auto-derivation and markup. |
| `ARKFILE_BILLING_MARKUP_MULTIPLIER` | float | `1.43` | Multiplier on summed `cost_per_tb_cents` when auto-deriving. `1.0` = no markup. |
| `ARKFILE_BILLING_RATE_FALLBACK_MICROCENTS_PER_GIB_HOUR` | int64 | `2712` | Used when neither env-set nor providers-derivable. ≈ $20/TiB/month. |
| `ARKFILE_BILLING_GIFTED_CREDITS_USD` | string | `"5.00"` | Auto-gifted to each newly-approved user. `"0.00"` to disable. |
| `ARKFILE_BILLING_TICK_INTERVAL` | duration | `1h` | Test override only; production should leave at `1h`. |
| `ARKFILE_BILLING_SWEEP_AT_UTC` | `HH:MM` | `"00:15"` | Daily settlement time. |
| `ARKFILE_BILLING_RATE_REFRESH_INTERVAL` | duration | `15m` | How often to re-resolve the rate from `storage_providers`. |
| `ARKFILE_BILLING_INCLUDE_ADMINS` | bool | `false` | Include admin accounts in metering (off by default to keep beta usage data clean). |

Per-script `ARKFILE_BILLING_ENABLED` defaults written into the generated `secrets.env`:

- `dev-reset.sh`: `false` (avoid timing-dependent test flakiness; test that exercises the meter explicitly sets `true`).
- `local-deploy.sh`, `prod-deploy.sh`, `test-deploy.sh`: `true`.

Example `secrets.env` block (typical operator using all defaults):

```
ARKFILE_BILLING_ENABLED=true
# ARKFILE_FREE_STORAGE_BYTES=1181116006
# ARKFILE_BILLING_MARKUP_MULTIPLIER=1.43
# ARKFILE_BILLING_RATE_MICROCENTS_PER_GIB_HOUR=
# ARKFILE_BILLING_GIFTED_CREDITS_USD=5.00
# ARKFILE_BILLING_TICK_INTERVAL=1h
# ARKFILE_BILLING_SWEEP_AT_UTC=00:15
# ARKFILE_BILLING_RATE_REFRESH_INTERVAL=15m
# ARKFILE_BILLING_INCLUDE_ADMINS=false
```

## 10. Test Plan

### 10.1 `billing/` Unit Tests

**`rates_test.go`**
- Resolution-priority matrix: env wins over derivation; derivation wins over fallback; fallback fires only when neither.
- Auto-derivation arithmetic: known sums × known multipliers produce expected `MicrocentsPerGiBPerHour`; explicit tolerance for integer-divide truncation.
- Provider filtering: `is_active = false` excluded; non-{primary,secondary,tertiary} role excluded; NULL `cost_per_tb_cents` excluded; `cost_per_tb_cents = 0` *included* (zero is valid).
- `FormatHumanReadable` golden-string per `Source` value.
- `atomic.Pointer` cache: concurrent reads during a write never observe a torn `Rate`.

**`meter_test.go`**
- Tick math: edge cases at exactly the free baseline (charge = 0), one byte over (charge = `(1 * rate) >> 30`), and well over.
- Accumulator upsert: first tick inserts; subsequent ticks accumulate; `last_tick_at` monotonic.
- Below-baseline tick is a complete no-op (no DB write — verified via SQL traffic recording).
- Filtering: unapproved skipped; admin skipped when `IncludeAdmins=false`, included when `true`.
- Per-user error isolation: deliberate failure on user N does not stop user N+1.

**`sweep_test.go`**
- Drain math: known accumulator + balance → expected new balance, deficit, transaction-row content.
- Deficit clamping: balance never goes negative; `usage_deficit_microcents` increments; `balance_exhausted` log event emitted.
- Per-user transaction rollback: deliberate mid-iteration error leaves prior users settled, current user unchanged, subsequent unaffected on next sweep.
- Idempotency: second sweep with no new ticks is a complete no-op.
- Metadata content: JSON contains the exact five fields from §3.5 with correct types; **explicitly asserts `avg_billable_bytes` is absent** (privacy regression guard).

**`scheduler_test.go`**
- Uses injectable `nowFn`. No `time.Sleep` in tests.
- Wall-clock alignment: starting at simulated `14:23:17`, first tick fires at `15:00:00`, then `16:00:00`, etc.
- Sweep timing: at `sweepAtUTC=12:00` over a simulated 24h window crossing 12:00, exactly one sweep call.
- Rate refresh: at `rateRefreshEvery=5m`, rate is re-resolved on schedule independent of ticks; changed rate is logged INFO and atomically swapped.
- Skipped-sweep WARN: synthesizing `last_sweep_at = now - 26h` produces the documented WARN log.
- Clean shutdown: `cancel()` causes `Run` to return within a small timeout; no goroutine leak.

**`gift_test.go`**
- Validation: rejects `amount <= 0`, rejects empty `reason`.
- Inserts row with `transaction_type = 'gift'`, correct `admin_username`, correct `balance_after`.
- Emits security log event.

### 10.2 `models/credits_test.go` Updates

- Renamed columns are queried.
- `FormatCreditsUSD` produces four-decimal output from microcents (`500000000` → `"$5.0000"`, `-600` → `"-$0.0006"`).
- `ParseCreditsFromUSD` produces microcents with rounding at the microcent boundary.
- `AddCredits`/`DebitCredits`/`SetCredits` operate on microcents end-to-end.

### 10.3 Handler Tests

**`handlers/credits_test.go` (extended)**
- `GET /api/credits` shape includes `current_usage` and `credits_runway`.
- Below-baseline state returns `billable_bytes = 0` and the documented note.
- Above-baseline returns expected `current_cost_per_month_microcents` (fixed test rate for determinism).
- `formatted_balance` is four-decimal.

**`handlers/billing_test.go` (new)**
- Each `/api/admin/billing/*` endpoint: shape, admin-auth-required (non-admin → 403), correct `LogAdminAction` call.
- `tick-now`: 403 when `ADMIN_DEV_TEST_API_ENABLED=false`.
- `recompute-rate`: response includes `changed: true|false` correctly.
- `sweep-summary`: per-day rows are correctly aggregated and use the `_today`/`_newly_` field naming.

### 10.4 E2E Section in `scripts/testing/e2e-test.sh`

New section at end, gated by `ARKFILE_BILLING_ENABLED=true`:

1. Configure `dev-reset.sh` env to set `ARKFILE_BILLING_ENABLED=true`, `ARKFILE_BILLING_TICK_INTERVAL=1m`, `ARKFILE_BILLING_RATE_MICROCENTS_PER_GIB_HOUR=2712`, `ARKFILE_BILLING_GIFTED_CREDITS_USD=1.00`, `ARKFILE_FREE_STORAGE_BYTES=10485760` (10 MiB, so test files become billable quickly).
2. `dev-reset.sh` runs.
3. Test user uploads ~100 MB of files (≈ 90 MiB billable above the 10 MiB baseline).
4. `arkfile-admin billing tick-now --sweep` to advance the meter immediately.
5. Assert balance decreased by computed expected amount (`90 MiB × rate × 1h`, with the right-shift truncation accounted for); assert one `usage` row in `credit_transactions` with the §3.5 metadata shape (and assert `avg_billable_bytes` field is absent).
6. `arkfile-admin billing gift --user <test-user> --amount 5.00 --reason "e2e test gift"`. Assert balance increased and a `gift` row exists.
7. `arkfile-admin billing recompute-rate`. Assert response says `changed: false`.
8. Repeat `tick-now --sweep` enough times to drive balance to zero. Assert `users.usage_deficit_microcents` increments and the user appears in `arkfile-admin billing list-deficits`.
9. Cleanup: delete test files, cancel sessions.

### 10.5 Playwright Section in `scripts/testing/e2e-playwright.ts`

1. Navigate to `/billing`.
2. Assert balance display is four-decimal.
3. Assert `current_usage` block reflects known test-user state.
4. Assert transaction history lists gift and usage rows in chronological order.
5. **Assert no `<script src*="https://js.stripe.com">`** present.
6. **Assert zero requests to `js.stripe.com`** in the network log.
7. Assert deficit number is *not* shown to end users (only the "Beta preview" note appears for zero-balance state).

### 10.6 Coverage Targets

- `billing/`: 90%+ line coverage. Achievable: small package, side-effects concentrated in DB calls.
- New handlers: ~70% (matches existing handler standard).
- E2E: every documented user-visible behavior (gift, tick, sweep, deficit, recompute, rate refresh) exercised at least once.

## 11. Phase 1 Implementation Order

10 PR-sized steps. Each leaves the tree buildable and deployable.

| # | Step | Approx LOC |
|---|---|---|
| 1 | Reconcile `users.storage_limit_bytes` default to `1181116006`. | ~10 |
| 2 | Rename `_cents` → `_microcents` end-to-end (schema, models, handlers, CLI, helpers, tests). Drops + recreates `user_credits`; widens `credit_transactions` columns to BIGINT. Single PR with destructive-migration warning in commit message. | ~500 |
| 3 | Add `storage_usage_accumulator` table + indexes; `users.usage_deficit_microcents`; document `usage`/`gift` transaction-type values. | ~50 |
| 4 | New `billing/` package (six files + tests). Compiles standalone, dead code at this step. | ~600 |
| 5 | Wire scheduler into `main.go`; add `ARKFILE_BILLING_*` to config loader; update deploy scripts to write `ARKFILE_BILLING_ENABLED` into generated `secrets.env`. Meter starts running on production-flavored deploys; no API exposure yet. | ~50 |
| 6 | Extend handlers: `current_usage`/`credits_runway` blocks; new `/api/admin/billing/*` endpoints; handler tests. | ~300 |
| 7 | New frontend `/billing` page with three sections + optional banner; Playwright test (including the no-Stripe assertions). | ~400 |
| 8 | `arkfile-admin billing` subcommand group. | ~400 |
| 9 | E2E billing section in `scripts/testing/e2e-test.sh`. | ~100 |
| 10 | New `docs/billing.md` (operator-facing summary). Move `docs/wip/storage-credits.md` and `docs/wip/storage-credits-v2.md` to `docs/wip/archive/` once landed. | ~200 |

Total ≈ 2,600 lines, ~60% non-test. Two-to-three weeks for one engineer.

Cluster boundaries for batched merging:
- **A** = 1–3 (schema + rename, no behavioral change).
- **B** = 4–5 (meter starts running, invisible).
- **C** = 6–8 (observable, then administrable).
- **D** = 9–10 (test + docs).

A test/demo deployment after Cluster C lets the operator collect real usage data immediately and refine defaults (markup, gift size, free baseline) before Cluster D / before any payments work begins.

## 12. Honest Trade-offs

| # | Trade-off | Mitigation in v2 |
|---|---|---|
| 1 | Users see a balance and runway even though no money changes hands; some will read it as being charged. | Frontend renders an explicit "Beta preview — no real charges occur" banner; deficit number is admin-only in v2; gift size sized so runway is shown in years for typical users. |
| 2 | Auto-derived rate is only as fresh as `cost_per_tb_cents` maintenance. | Rate logged INFO at startup and on every change; `arkfile-admin billing show` displays `resolved_at` and contributing providers; `recompute-rate` admin escape hatch. |
| 3 | Skipped-sweep day produces one larger transaction row spanning >24h. | Scheduler logs WARN on detection (`> 25h since last sweep`); `period_start`/`period_end` accurately reflect the actual span so reconciliation works. |
| 4 | Unbounded accumulator if sweeps fail repeatedly and unmonitored. | Real impact small (1 row/user, 2 int columns); operator alert on `last_billed_at < now - 48h`. |
| 5 | Restart bridges a tick boundary → at-least-once tick (brief slight overcharge). | Documented; the per-tick amount is at most 1 hour of microcents and washes out in practice. |
| 6 | Microcent migration is destructive (drops `user_credits`). | Greenfield; current `user_credits` is effectively empty. **Hard prerequisite**: Item 8 (column-evolution) before payments work. |
| 7 | No bandwidth/egress billing. | Storage-only is a deliberate scope decision; operator sets a higher markup if they have download-heavy users. |
| 8 | Single-process scheduler; multi-instance deployment would double-count. | Single-process matches the rest of the architecture (rqlite/SQLite consistency point); not a current concern. |
| 9 | Deficit column is informational, not actionable in v2. | Listed in admin views and `list-deficits`; future payments work decides resolution policy. |
| 10 | `users.storage_limit_bytes` hard cap and credit-balance soft signal coexist. | Both shown in `GET /api/admin/users/:username/status` so the contrast is visible; unifying them is a payments-work decision. |
| 11 | Per-day storage history persistence would be a new privacy disclosure. | **Eliminated**: §3.5 metadata excludes `avg_billable_bytes`. Reconciliation uses `drained_microcents` + `rate_microcents_per_gib_per_hour` only. |
| 12 | 30-day month convention introduces ~3% per-month variance. | Standard cloud-billing convention; UI uses approximate framing (`~$0.02/month`) for projections; precise four-decimal display is reserved for actual balances and transaction amounts. |
| 13 | Test coverage of a meter that ticks hourly requires injectable time. | `Scheduler.nowFn` interface + `tickEvery`/`rateRefreshEvery` configuration make all timing testable without `time.Sleep`. |

## 13. Forward-Looking: Future `docs/wip/payments.md`

Scaffolding only. Not designed here.

**Hard prerequisites before payments work begins**:

1. **Item 8 of `general-enhancements.md`**: column-evolution layer. Once real money flows, "wipe to add a column" is unacceptable.
2. **Item 2 of `general-enhancements.md`**: pre-flight storage-quota endpoint. Clients need to ask "do I have room, and can I buy room if not?" before initiating uploads.
3. **At least 2–4 weeks of meter data from this work's deployment** to anchor pricing-default decisions (markup, free baseline, gift size) with evidence rather than guesses.

**What the meter built here locks in** (payments work must not regress):

- Microcent unit; rate denominated in microcents/GiB/hour; balances in microcents.
- Hourly tick + daily settlement pattern; payments-driven credits land directly on `user_credits.balance_usd_microcents`, then drain via the same daily sweep.
- `credit_transactions` audit-log shape; payment top-ups add types like `payment_btc`, `payment_lightning`, `payment_monero`, `payment_stripe` without schema change.
- Settlement metadata excludes per-day storage history (privacy invariant).
- Free-baseline-above-which-billable model.
- `users.storage_limit_bytes` hard cap is independent of credit balance in v2; payments work is free to couple them or not.

**Open for the future document**:

- Whether `storage_limit_bytes` is replaced by a credit-balance-derived cap or kept independent.
- Per-user free-baseline overrides (grandfathered users, etc.).
- Bandwidth/egress billing.
- BTCPay and Stripe webhook handler shapes; idempotent invoice table; PII-scrubbing posture for Stripe `Customer` objects (`email=null`, `name=null`).
- Stripe gating behind `STRIPE_ENABLED=false` default; dynamic ES-module import; CSP exception only when enabled.
- Auto-top-up policy and operator-configured monthly cap.
- Refund / pull-payment flow.
- Deficit resolution (write-off, attach to next top-up, soft block on uploads, etc.).

When the operator is ready, create `docs/wip/payments.md` and design these with this document's level of detail.
