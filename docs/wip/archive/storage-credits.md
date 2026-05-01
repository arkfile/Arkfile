# Storage Credits and Usage Metering

## Vision and Scope

Arkfile already enforces a per-user storage cap (`users.storage_limit_bytes`) and already has a USD-cents credit ledger (`user_credits` plus `credit_transactions`), but the two are not connected. An admin can change a quota and an admin can adjust a balance, and neither operation has any consequence for the other. There is no concept of price, no concept of usage-over-time, and no way for a user to see what their storage is costing or what they are getting for free.

This document describes a Phase 0/1 piece of work whose purpose is to close that gap with a usage meter and nothing else. After this work lands, every user has a credit balance denominated in microcents, an hourly meter that converts their current storage usage into a debit at a configurable rate, and a daily settlement that drains accumulated debits into the ledger as a single transaction row. The meter ticks for every user whether or not real money has ever changed hands. New users are gifted a starting balance so the math is visible from day one.

What this work deliberately does not do: it does not introduce any payment provider, any webhook, any invoice, any "buy storage" button, any over-quota enforcement, any auto-deletion of files, any change to the existing `users.storage_limit_bytes` hard cap. Those belong to a separate, later piece of work that will live in `docs/wip/payments.md` once it is ready to be designed in detail. This document references that future work only at the end, as forward-looking context.

The reasons to do the meter first and the payment integration later are operational and epistemic. Operationally, the meter is the harder thing to get right (precision, accumulation semantics, rate changes, edge cases) and is independent of any payment provider's API surface. Epistemically, running the meter in the live beta with no real money changing hands surfaces real usage data: how much the average beta user actually consumes, how much that would cost at various sticker prices, how often the meter ticks and what it costs in DB writes. That data informs the pricing decisions for the payment-integration work without forcing them up front.

The unit of internal accounting is the microcent: one millionth of a US cent, equivalently one hundred-millionth of a US dollar. All balances and rates are stored as int64 microcents. This is necessary because at realistic storage prices a single user's hourly debit is a small fraction of a cent, and storing balances in cents would truncate every charge to zero. Microcents give six decimal places of headroom inside the int64 range, which is enough to bill petabyte-years of storage without ever overflowing.

The free baseline (storage that does not get billed) defaults to the value already used everywhere else in the codebase: 1.1 GiB, the existing `models.DefaultStorageLimit`. The schema's existing `storage_limit_bytes` default of 10 GiB is wrong relative to the Go constant and is reconciled to 1.1 GiB as part of this work. A user who stays under the free baseline indefinitely sees their balance never debit. A user above the free baseline is billed only on the bytes above it.

## Why Now: Metering Before Payments

The temptation when adding a billing surface is to wire up a payment provider on day one and design the meter around it. Doing it in that order creates several problems that compound on each other.

The first problem is that payment-provider work is unforgiving. Webhooks have to be idempotent against replay, signature verification has to be strict, PII has to be deliberately not stored, and a single integration bug can result in either double-charging users or losing money. None of that should be done while also making decisions about how the meter should accumulate or how rates should be derived. Doing the meter first, in isolation, lets the precision and correctness questions for the meter be answered by themselves rather than tangled with provider-API ergonomics.

The second problem is that pricing decisions made up front are usually wrong. The default markup multiplier proposed in this document (1.43x over raw provider cost) is a guess. The default free baseline (1.1 GiB) is inherited from an older constant whose origin nobody remembers. The default new-user gift balance (proposed: $5) is a thumb-in-the-air number that should be confirmed against real beta usage data, not invented at design time. Running the meter for weeks against the live beta with no real money changing hands surfaces all of this. After a month of metering, the operator can look at actual numbers ("the median user is costing me $0.04/month at sticker price; the 95th-percentile user is costing me $0.31/month; one outlier is at $4.20/month") and choose final values for the payment work with evidence rather than vibes.

The third problem is that the existing schema and the existing handlers do not yet have the precision they need to support real billing. The current `user_credits.balance_usd_cents` column is a 64-bit integer in cents. At the realistic per-user-per-hour debit of ~0.066 cents, integer truncation eats every charge. Migrating to microcents has to happen before the meter is useful, and that migration is much less stressful when there is no payment provider depending on the existing column. Doing the cents-to-microcents migration as part of meter work, before any real money has been charged through the system, is the cheapest possible time to do it.

The fourth problem is privacy posture. Adding a payment provider is the largest single increase in attack surface and information leak the codebase will see, because every provider wants identifying information about the payer. AGENTS.md is unambiguous that the server should know nothing about visitors and never log PII. The meter has none of that surface: it operates entirely on data the server already has (`users.total_storage_bytes`, `storage_providers.cost_per_tb_cents`) and writes only aggregate per-user accounting rows. There is nothing PII-shaped in this work. Doing it first lets the privacy-sensitive work happen later in isolation, with its own review.

The fifth problem is that the meter is, on its own, a useful product feature. A privacy-first file vault that shows users "your storage is currently costing $0.020/month at our published rate; you are paying nothing because you are inside the free baseline plus a $5 starter gift; at this rate your gift gives you about 18 years of runway" is more honest about the economics of the service than one that hides the math. Even if the operator never turns on real payments, the meter improves the product. The existence of the meter also makes it easy to demonstrate to potential beta users what the eventual cost would be, which is useful for trust-building well before the operator is ready to take money.

The sequencing rule that follows from these reasons is: do the meter as a complete, shippable unit. Do not start payment-provider work until the meter has run against the beta for a meaningful amount of time and the resulting usage distribution has been examined. The meter is the prerequisite, not the placeholder.

## What Already Exists in the Codebase

The starting point for this work is much further along than a payment-system design document usually implies, because the credits-ledger half of the picture has already been built and shipped (without any user-visible billing connected to it). Inventorying what is in place keeps the design honest about what is actually new versus what is an extension of existing code.

The `users` table carries `total_storage_bytes` (an int64 that is the sum of finalized file padded sizes for that user) and `storage_limit_bytes` (an int64 hard cap that the upload path checks against via `User.CheckStorageAvailable`). The `models.DefaultStorageLimit` Go constant is currently `1181116006` bytes (1.1 GiB) and the schema's `storage_limit_bytes` column default is currently `10737418240` (10 GiB). Those two values disagree; the rest of the codebase appears to assume the Go constant. The reconciliation done in this work is to set both to 1.1 GiB.

The `user_credits` table already exists, with `balance_usd_cents` as an int64 plus `created_at` and `updated_at` columns and an automatic update trigger. The `credit_transactions` table is a full audit log with `transaction_id` (free-form external reference, the schema comment explicitly notes "Bitcoin, PayPal, etc."), `amount_usd_cents` (signed; negative for debits), `balance_after_usd_cents` (the balance after this transaction), `transaction_type` (currently `credit`, `debit`, `adjustment`, `refund`), `reason`, `admin_username`, and a free-form `metadata` TEXT field intended for JSON. Indexes exist on username, transaction_id, type, created_at, and admin_username. The model layer in `models/credits.go` provides `GetOrCreateUserCredits`, `GetUserCredits`, `CreateUserCredits`, `AddCredits`, `DebitCredits`, `SetCredits`, `GetUserTransactions`, `GetAllUserCredits`, plus formatting helpers `FormatCreditsUSD` and `ParseCreditsFromUSD`. All write paths are wrapped in DB transactions and emit security log events.

User-facing API: `GET /api/credits` returns the user's balance, formatted balance, transaction history, and pagination. Admin-facing API: `GET /api/admin/credits` lists all users' balances; `GET /api/admin/credits/:username` shows a specific user's balance and transactions; `POST /api/admin/credits/:username` performs `add`/`subtract`/`set` operations with a required reason; `PUT /api/admin/credits/:username` is a separate set-balance endpoint. None of these endpoints currently expose any usage-rate or runway information because there is no meter to derive it from.

The `storage_providers` table carries `cost_per_tb_cents` (`sql.NullInt64`) per provider, with a `role` column ('primary'/'secondary'/'tertiary'/...). The admin UI and `arkfile-admin set-cost --provider-id ID --cost AMOUNT` already exist for setting this. This is the field that the meter's auto-derivation logic reads to compute a default sticker rate when the operator has not set one explicitly in `secrets.env`. Active providers in roles primary/secondary/tertiary are summed; the result is the operator's monthly cost basis per terabyte for fully-replicated storage.

Quota enforcement happens in `handlers/uploads.go` (the upload session creation path), via `User.CheckStorageAvailable(size)` which compares `total_storage_bytes + size` against `storage_limit_bytes`. This work does not change that gate. It also does not change the existing `UpdateUserStorageLimit` admin endpoint at `PUT /api/admin/users/:username/storage`. The existing hard cap stays as-is; the meter operates alongside it.

Admin actions (including any modifications under this work) are logged to the existing `admin_logs` table via `LogAdminAction`. New admin operations introduced by this work (gifting credits, recomputing rates, etc.) use the same logging path.

The `arkfile-admin` CLI in `cmd/arkfile-admin/` already speaks the credits API for read operations and partially for adjustments. It will gain a small `billing` subcommand under this work for showing rates, gifting credits, and forcing rate recomputation.

The frontend has no billing page today; the credits API is unrendered. A minimal page is added under this work to display the user's balance, current usage rate, runway, and transaction history. No payment buttons are added; that surface waits for the future payments work.

Outside scope: the `models.DefaultStorageLimit` mismatch noted above is technically a pre-existing latent bug that this work happens to fix because the meter is sensitive to it. The fix is one line in the Go constant and one in the schema default; it is called out explicitly in the schema-changes section so reviewers can verify the intent.

## Pricing Model

### Unit of Account: the Microcent

All balances and rates are stored as `int64` values denominated in microcents. One microcent is one millionth of a US cent, equivalently one hundred-millionth of a US dollar:

    1 USD = 100 cents = 100,000 millicents = 100,000,000 microcents

The int64 range is approximately 9.22e18, which in microcents is about $92 billion -- vastly more than any conceivable balance. The resolution is $0.00000001, which is fine enough that the smallest plausible per-tick debit is still a comfortably-large integer.

This unit is necessary because of the magnitudes involved. At a sticker price of $20/TiB/month, the per-GiB-hour rate is about $0.0000274. Stored in cents, that rounds to zero; stored in millicents (1/1000 of a cent), it is 27 -- workable but with little headroom against future price changes or shorter tick intervals; stored in microcents, it is 27,400 -- comfortable integer math with no risk of truncation.

The choice to store the rate itself in microcents-per-byte-per-hour (rather than per-GiB-per-hour) at runtime keeps the per-user computation a single int64 multiplication: `charge_microcents = billable_bytes * rate_microcents_per_byte_per_hour`. Operators specify rates in human units (USD/TiB/month) in `secrets.env` and the system converts at startup.

User-facing display uses four decimal places of USD ("$5.0000") so the precision the meter operates at is visible. This is a deliberate signal that the system is doing fractional-cent accounting honestly. A formatting helper in `models/credits.go` will be extended (or replaced) to produce these strings from microcents.

### Tick Interval and Settlement: Hourly Meter, Daily Settlement

The meter ticks once per hour. Each tick performs, for each active user:

1. Read `total_storage_bytes` from `users` (already maintained by the upload/delete paths).
2. Compute `billable_bytes = max(0, total_storage_bytes - free_baseline_bytes)`.
3. Compute `tick_charge_microcents = billable_bytes * current_rate_microcents_per_byte_per_hour`.
4. Add `tick_charge_microcents` to that user's row in a new `storage_usage_accumulator` table; update `last_tick_at`.

Importantly, the tick does not touch `user_credits.balance_usd_microcents` and does not write a row to `credit_transactions`. It only updates the small accumulator table.

Once per day, at a configurable UTC time (default 00:15 UTC), a settlement sweep runs. For each user with a non-zero accumulator value:

1. Atomically: subtract `unbilled_microcents` from `user_credits.balance_usd_microcents`, zero out `unbilled_microcents`, set `last_billed_at = now`.
2. If the resulting balance would be negative, clamp to zero, store the deficit in a new `users.usage_deficit_microcents` column, and emit a "balance exhausted" log event. Do not take the balance negative. (The over-quota policy decision is deferred; for now, the meter only records the deficit and continues to tick. Upload behavior remains controlled by the existing `storage_limit_bytes` hard cap.)
3. Insert one row into `credit_transactions` with `transaction_type = 'usage'`, `amount_usd_microcents = -drained_amount`, `balance_after_usd_microcents = new_balance`, `reason = "Daily storage usage"`, `metadata = JSON encoding of {hours, avg_billable_bytes, rate_microcents_per_byte_per_hour, ticks_count, period_start, period_end}`.

This pattern keeps the audit log proportional to user-count-times-days rather than user-count-times-hours, which matters at scale. For 100 users over 1 year that is 36,500 rows instead of 876,000. The accumulator table itself is one row per user (PRIMARY KEY username), so its size is bounded by the user count.

Hourly granularity is the right tick interval for several reasons. It is fine enough that uploads and deletes within a day are reflected fairly (a user who uploads at 23:00 UTC and deletes at 01:00 UTC pays for two hours, not a full day). It is coarse enough that a single user's per-tick computation is trivial and the daily summary row is a meaningful aggregate. It is the standard for cloud-storage billing, so user expectations match. Sub-hour granularity (per-minute, per-second) would be possible with this design but adds nothing the user can perceive and increases the per-user microcent precision pressure.

### Auto-Derivation of the Sticker Rate

When the operator does not set `ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR` in `secrets.env`, the system derives it from the existing `storage_providers` table:

    base_cost_per_tb_per_month_cents = SUM(
      cost_per_tb_cents
      FROM storage_providers
      WHERE is_active = true
        AND role IN ('primary', 'secondary', 'tertiary')
        AND cost_per_tb_cents IS NOT NULL
    )
    sticker_per_tb_per_month_cents = base_cost_per_tb_per_month_cents
                                   * ARKFILE_BILLING_MARKUP_MULTIPLIER
    sticker_per_byte_per_hour_microcents = sticker_per_tb_per_month_cents
                                         * 1000          // cents -> microcents
                                         / 1099511627776 // bytes per TiB
                                         / 30            // days/month, conventional
                                         / 24            // hours/day

The "TiB" used here is binary (2^40 bytes), matching the rest of the codebase's use of binary units.

The default markup multiplier is **proposed at 1.43** -- chosen so that a Wasabi+Backblaze replicated configuration ($7.99 + $6.00 = $13.99/TiB/month base cost) produces a clean ~$20/TiB/month sticker price. Operators can override it. A markup of 1.0 (sticker = cost) is permitted and meaningful for non-profit deployments.

If no providers have `cost_per_tb_cents` set, or the table is empty (fresh dev instance), the system falls back to a documented constant of **2740 microcents/byte/hour** (equivalent to $20/TiB/month with TiB = 2^40 bytes). This is logged at WARN level on startup so operators know the fallback was used.

The resolved rate is logged at INFO on startup:

    billing: rate resolved to 2740 microcents/byte/hour
      (equivalent: $20.00/TiB/month sticker;
       derived from primary=$7.99 + secondary=$6.00 = $13.99/TiB/month base
       * markup 1.43;
       source: auto-derived from storage_providers)

A force-recompute admin operation re-reads `storage_providers` and updates the in-memory rate without restarting the server. This is needed because operators routinely change provider configurations after deploy.

### Billable-Bytes Definition: Above the Free Baseline

The meter charges only for bytes above the free baseline. A user storing 2.1 GiB with a 1.1 GiB baseline is billed for 1.0 GiB. A user storing 0.8 GiB is billed for nothing.

The free baseline is per-user, set in `secrets.env` as `ARKFILE_FREE_STORAGE_BYTES`, defaulting to `1181116006` (1.1 GiB). Operators can change it; future per-user overrides could be added if useful, but are not in this work.

The free baseline acts independently of the existing `users.storage_limit_bytes` hard cap. A user can have:

- `storage_limit_bytes = 50 GiB` (admin-granted cap)
- Free baseline = 1.1 GiB (instance default)
- `total_storage_bytes = 30 GiB` (current usage)

Their billable bytes are `30 - 1.1 = 28.9 GiB`. The cap of 50 GiB is unrelated to billing in this Phase 1 work; it remains a separate hard limit enforced at upload time. The decoupling is intentional: this work intentionally does not change the upload-gate semantics, so operators can ship the meter without changing user-facing upload behavior. Coupling them is a future-payments-work decision.

### What "Active" Means for the Meter

A user is active for billing purposes if they have an `is_approved = true` row in the `users` table and have not been revoked or deleted. The meter does not bill unapproved users (they cannot have stored bytes anyway because the upload path is blocked for them), and it does not bill admin accounts unless an operator-set flag enables that (`ARKFILE_BILLING_INCLUDE_ADMINS`, default `false`). Excluding admins by default keeps the operator's own usage from polluting per-user economic data during the metering-only phase.

## Schema Changes

This work introduces the smallest schema changes that are sufficient to support the meter, and explicitly defers any schema changes that would only be needed by the future payment-provider work.

### Migration Approach: Wipe-and-Redeploy

The Arkfile schema today is `CREATE TABLE IF NOT EXISTS`-only; there is no migration framework. Adding a column to an existing table silently no-ops, and changing a column type or default requires a full rebuild of the table. AGENTS.md explicitly notes that the project is greenfield, that there are no production deployments, and that "wipes are still acceptable for now."

The recommended approach for landing this work is therefore: ship the schema changes as additive `CREATE TABLE IF NOT EXISTS` rows for new tables and as one-line edits to existing `CREATE TABLE` definitions for column-name and column-default changes; instruct operators (currently just the test/demo deployment at `test.arkfile.net` and any local-deploy users) to run a destructive redeploy. The existing scripts already handle this: `dev-reset.sh` wipes by design, `local-deploy.sh` and `prod-deploy.sh` can be re-run after manual data wipe with the operator's understanding that all `user_credits` and `credit_transactions` rows will be lost. Beta users on the test instance will lose any credit balances they have today (which are zero in practice, since nothing currently writes to `user_credits` outside of the admin endpoints).

This is not a recommendation for the future. The strong recommendation is that **before any payment-provider work begins**, the column-evolution layer described in `docs/wip/general-enhancements.md` Item 8 should be implemented as a prerequisite. Once real money has flowed through the system, "wipe to add a column" stops being acceptable. The cost of writing the column-evolution layer is small (one day of work) and the value compounds across every future schema change. This document does not implement Item 8, but it explicitly flags it as the gating prerequisite for the next phase of work.

### Reconcile DefaultStorageLimit

A one-line correction to two locations:

- `models/user.go`: the `DefaultStorageLimit` constant is currently `1181116006` (1.1 GiB). Leave as-is.
- `database/unified_schema.sql`: change the `users.storage_limit_bytes` column default from `10737418240` (10 GiB) to `1181116006` (1.1 GiB), matching the Go constant. The `models.CreateUser` insert path already passes the Go constant explicitly so this default is rarely exercised, but the disagreement is a latent footgun and should be removed.

### Migrate `user_credits` to Microcents

The existing `user_credits.balance_usd_cents` column (BIGINT) is renamed and rescaled:

    -- Before:
    balance_usd_cents BIGINT NOT NULL DEFAULT 0

    -- After:
    balance_usd_microcents BIGINT NOT NULL DEFAULT 0

Because the schema-evolution layer is not yet present, this means the `user_credits` table is dropped and recreated on the next deploy. Existing rows are lost. Acceptable in the current beta state where the table is effectively empty.

The Go side: the `UserCredit` struct in `models/credits.go` renames `BalanceUSDCents` to `BalanceUSDMicrocents`. All callers (handlers, the formatting helper, the parsing helper) are updated.

### Migrate `credit_transactions` to Microcents

The same rename applies to the two amount-bearing columns:

    -- Before:
    amount_usd_cents INTEGER NOT NULL,
    balance_after_usd_cents INTEGER NOT NULL,

    -- After:
    amount_usd_microcents BIGINT NOT NULL,
    balance_after_usd_microcents BIGINT NOT NULL,

Note the type change from `INTEGER` to `BIGINT`: at microcent precision the `INTEGER` type (which in SQLite is 64-bit but in some backends is 32-bit) is not safe; explicit `BIGINT` makes intent clear.

The new transaction-type values added in this work:

- `usage` -- daily-usage debit row written by the settlement sweep. Negative `amount_usd_microcents`.
- `gift` -- credit added by an operator via the new admin gift command, distinct from `credit` (which is reserved for paid top-ups in the future payments work).

Existing values (`credit`, `debit`, `adjustment`, `refund`) remain valid and used as before.

### New Table: `storage_usage_accumulator`

A small table that holds per-user unbilled microcents between hourly ticks and the daily settlement sweep:

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

One row per user, created lazily on the user's first hourly tick. Foreign-key cascade ensures rows are removed when a user is deleted, so there is no orphan accumulation.

### New Column: `users.usage_deficit_microcents`

When the daily settlement would drain a user's balance below zero, the deficit is recorded but the balance is clamped to zero. The deficit is stored on the user row for future reconciliation:

    ALTER TABLE users ADD COLUMN usage_deficit_microcents BIGINT NOT NULL DEFAULT 0;

(Restated for the wipe-redeploy approach: this is folded into the `CREATE TABLE` for `users`.) The column is informational in this Phase 1; the future payments work will define what the operator can do with it (write off, attach to next top-up, etc.).

### New Indexes

Beyond the accumulator-table indexes above, the existing `idx_credit_transactions_type` index continues to serve well for the new `usage` and `gift` types. No additional indexes are needed for Phase 1.

### Summary of Schema Deltas

To make the diff easy to review, the full set of schema changes:

1. `users.storage_limit_bytes` default: `10737418240` -> `1181116006`.
2. `users.usage_deficit_microcents` BIGINT NOT NULL DEFAULT 0 (new).
3. `user_credits.balance_usd_cents` -> `user_credits.balance_usd_microcents` (rename + type-confirm BIGINT).
4. `credit_transactions.amount_usd_cents` -> `credit_transactions.amount_usd_microcents` (rename + type widen to BIGINT).
5. `credit_transactions.balance_after_usd_cents` -> `credit_transactions.balance_after_usd_microcents` (rename + type widen to BIGINT).
6. `credit_transactions.transaction_type` accepted values gain `usage` and `gift` (no enum constraint exists in the schema; this is a documentation/code-side change).
7. New table `storage_usage_accumulator` with two indexes.

The total churn is small. The user-visible churn (column renames in JSON responses) is addressed in the API section.

## The billing/ Package

This work introduces a new top-level Go package, `billing/`, that owns the meter end to end. It is deliberately a separate package from `models/` and `handlers/` because the meter has its own concerns (rate resolution, ticking, scheduling) that don't belong in either of those layers, and because it reads from `models/` (users, credits, storage_providers) but is read by `handlers/` (when handlers need the current rate or the per-user usage breakdown), so making it a peer package keeps the dependency graph clean.

### Package Layout

    billing/
        rates.go           // Rate resolution and caching
        rates_test.go
        meter.go           // Per-user hourly tick logic
        meter_test.go
        sweep.go           // Daily settlement sweep
        sweep_test.go
        scheduler.go       // The hourly+daily ticker that drives the meter
        scheduler_test.go
        gift.go            // Operator-initiated credit gifts
        gift_test.go
        types.go           // Shared types (Rate, UserUsage, BillingConfig, etc.)

Five small files plus tests. None depend on each other in a tight way; they share types via `types.go` and otherwise communicate through the database.

### `rates.go`: Rate Resolution and Caching

The rate-resolution layer takes the operator's configuration and the current `storage_providers` table and produces a single canonical `Rate` value:

    type Rate struct {
        MicrocentsPerBytePerHour int64
        ResolvedAt               time.Time
        Source                   string // "env", "auto-derived", "fallback-default"
        BaseCostPerTBPerMonthCents   int64    // 0 if Source != "auto-derived"
        MarkupMultiplier             float64  // 1.0 if Source != "auto-derived"
        ContributingProviders        []string // primary/secondary/tertiary IDs that summed
    }

The resolution function is `ResolveRate(db *sql.DB, cfg BillingConfig) (*Rate, error)`. It is called once at startup and again on demand via the `RecomputeRate` admin endpoint. The resolved rate is cached in a package-level `atomic.Pointer[Rate]` so reads from the meter and from API handlers are lock-free.

The resolution priority:

1. If `cfg.RateMicrocentsPerBytePerHour` is set (from `ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR` divided by `1024^3`), use it. `Source = "env"`.
2. Otherwise, query `storage_providers` for active rows in roles primary/secondary/tertiary, sum their `cost_per_tb_cents`, multiply by `cfg.MarkupMultiplier`, convert to microcents-per-byte-per-hour. `Source = "auto-derived"`.
3. Otherwise (no providers, or no providers with cost set), use the documented constant `2740` microcents/byte/hour. `Source = "fallback-default"`. Log at WARN.

A small helper `(*Rate).FormatHumanReadable() string` produces the multi-line log output shown in the Pricing Model section.

### `meter.go`: Per-User Hourly Tick

The per-user tick is a single function:

    func TickUser(db *sql.DB, username string, rate *Rate, now time.Time, freeBaselineBytes int64) error

It performs steps 1-4 from the Pricing Model section as a single SQL transaction:

    BEGIN;
      SELECT total_storage_bytes FROM users WHERE username = ?;
      -- compute billable_bytes and tick_charge_microcents in Go
      INSERT INTO storage_usage_accumulator (username, unbilled_microcents, last_tick_at)
        VALUES (?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
          unbilled_microcents = unbilled_microcents + excluded.unbilled_microcents,
          last_tick_at = excluded.last_tick_at;
    COMMIT;

For users with `billable_bytes = 0`, the tick is a no-op (no row written, no row updated). This keeps the accumulator table sparse: only billable users get rows.

The package also exposes `TickAllActiveUsers(db, rate, now, cfg) (count int, err error)` which iterates users (filtered by `is_approved = true` and the admin-include flag) and calls `TickUser` for each. Errors per user are logged but do not abort the whole tick; the function returns after attempting every user, with an aggregate error count.

The tick is intentionally not transactional with the upload/delete paths. It samples `total_storage_bytes` at tick time. A user who uploads at 12:30 and is metered at 13:00 gets billed for the bytes present at 13:00 -- effectively a 30-minute "free" window. This is fine at our price points and avoids the much higher complexity of per-event ledgering.

### `sweep.go`: Daily Settlement

The sweep function:

    func SweepAllUsers(db *sql.DB, rate *Rate, now time.Time) (summary SweepSummary, err error)

Iterates the `storage_usage_accumulator` table for rows with `unbilled_microcents > 0`. For each:

1. Open a SQL transaction.
2. Read `user_credits.balance_usd_microcents` (or create the row at zero if it doesn't exist).
3. Compute `new_balance = max(0, balance - unbilled)` and `deficit_added = max(0, unbilled - balance)`.
4. Update `user_credits.balance_usd_microcents = new_balance`.
5. If `deficit_added > 0`, increment `users.usage_deficit_microcents += deficit_added` and emit a "balance exhausted" log event.
6. Insert the daily-summary row into `credit_transactions` with type `usage`, the negative drained amount, `balance_after = new_balance`, the `metadata` JSON described in the Pricing Model section.
7. Update the accumulator row: `unbilled_microcents = 0`, `last_billed_at = now`.
8. Commit.

`SweepSummary` carries: total users settled, total microcents drained, count of users who hit deficit, total deficit microcents added. Used for the per-day operator log line and exposable via an admin API for monitoring.

The sweep is idempotent on a per-user basis via the per-row transaction: a partial sweep that crashes mid-iteration leaves users it has already swept correct, and the next sweep run picks up the rest. The `last_billed_at` column is the watermark that prevents double-billing.

The sweep does NOT recompute the rate. It uses the rate that was active at sweep time. The metadata includes the rate value so historical reconciliation is possible. (If the rate changed mid-day, the average billable bytes over the day are billed at the rate-at-sweep-time, which is a small approximation acceptable in Phase 1; a refined accumulator carrying per-tick rates is a possible future improvement.)

### `scheduler.go`: The Driver

A small `Scheduler` struct that owns two `time.Ticker`s and runs them inside a single goroutine governed by a `context.Context`:

    type Scheduler struct {
        db       *sql.DB
        cfg      BillingConfig
        tickEvery   time.Duration  // default 1h
        sweepAtUTC  time.Time      // default 00:15 UTC
        rateRefreshEvery time.Duration  // default 15m, in case providers changed
    }

    func (s *Scheduler) Run(ctx context.Context) error

The scheduler:

1. Resolves the initial rate, logs the resolved rate at INFO.
2. Enters a loop that:
   - Every `tickEvery`: calls `TickAllActiveUsers`, logs the count.
   - Every `rateRefreshEvery`: re-resolves the rate (cheap query); if it changed, logs the new rate at INFO and atomically swaps the cached pointer.
   - Once per day at `sweepAtUTC`: calls `SweepAllUsers`, logs the summary.
3. On `ctx.Done()`: returns cleanly.

The scheduler is NOT wall-clock-aligned. After a server restart the next tick happens at `now + tickEvery`, not at the top of the next hour. This is fine: the accumulator carries forward, and the small drift in tick boundaries is washed out at the daily sweep.

### `gift.go`: Operator-Initiated Gifts

A thin wrapper around `models.AddCredits` that records the transaction with `transaction_type = 'gift'` and a required `reason` string. Distinct from the existing admin "add credits" path so the audit log can distinguish "operator manually gifted credits" from "user paid and credits were added" (the latter is reserved for the future payments work).

    func GiftCredits(db *sql.DB, username string, amountUSDMicrocents int64,
                     reason string, adminUsername string) (*models.CreditTransaction, error)

Wired up to the new `arkfile-admin billing gift` subcommand and to a future admin-UI button. Validates that `amountUSDMicrocents > 0` and that `reason` is non-empty.

### `types.go`: Shared Types

`Rate` (above), `BillingConfig` (the resolved `ARKFILE_BILLING_*` env vars in struct form), `UserUsage` (the per-user breakdown returned by API handlers: billable bytes, current rate, runway estimate), `SweepSummary` (above).

### Where the Scheduler Is Started

In `main.go`, after the database is opened and after the existing background workers are started (the existing health-check goroutines, etc.), and before the HTTP server starts listening:

    if cfg.Billing.Enabled {
        scheduler := billing.NewScheduler(db, cfg.Billing)
        go func() {
            if err := scheduler.Run(rootCtx); err != nil {
                logging.ErrorLogger.Printf("billing scheduler exited: %v", err)
            }
        }()
    } else {
        logging.InfoLogger.Print("billing scheduler disabled (ARKFILE_BILLING_ENABLED=false)")
    }

The scheduler shares the existing root context so `Ctrl-C` cleanly cancels both the HTTP server and the meter.

### What the Package Does Not Do

It does not own:

- Any HTTP handler (those live in `handlers/`).
- Any database schema migration (those live in `database/`).
- Any payment-provider integration (deferred).
- Any frontend rendering (deferred to the credits page extension).

The package is self-contained, side-effect-confined to the database (plus log output), and depends only on the standard library, `database/sql`, the existing `models/` package, and the existing `logging/` package. No third-party dependencies are introduced by this work.

## API Surface Changes

The existing credits and admin endpoints gain enrichment fields, no existing field is removed, and a small set of new endpoints is added for the meter-specific data (the resolved rate, the daily sweep summary, and the rate-recompute action). The shape goal is "extend, don't break": clients that ignore unknown fields continue to work, and the `arkfile-admin` CLI gains the new fields incrementally.

### Field Rename: `_cents` -> `_microcents`

Every JSON field in credits responses that today is named `*_usd_cents` is renamed to `*_usd_microcents`. This is a breaking change in JSON shape but it is unavoidable and small in scope, since the credits API is currently unrendered in the frontend. Affected fields:

- `balance_usd_cents` -> `balance_usd_microcents` (in `UserCredit`).
- `amount_usd_cents` -> `amount_usd_microcents` (in `CreditTransaction`).
- `balance_after_usd_cents` -> `balance_after_usd_microcents` (in `CreditTransaction`).
- The `formatted_balance` field stays as a string but now formats from microcents with four decimal places (e.g., `"$5.0000"`).

The `arkfile-admin` CLI struct definitions in `cmd/arkfile-admin/main.go` and friends are updated in lockstep. CLI display formatting uses the same four-decimal helper.

### Extended: `GET /api/credits`

Adds a `current_usage` block and a `credits_runway` block:

    {
      "username": "alice",
      "balance_usd_microcents": 500000000,
      "formatted_balance": "$5.0000",
      "current_usage": {
        "total_storage_bytes": 2254857830,
        "free_baseline_bytes": 1181116006,
        "billable_bytes": 1073741824,
        "rate_microcents_per_byte_per_hour": 2740,
        "rate_human": "$20.00/TiB/month",
        "current_cost_per_month_microcents": 19660800,
        "current_cost_per_month_usd": "$0.0197",
        "free_baseline_savings_per_month_microcents": 21629440,
        "free_baseline_savings_per_month_usd": "$0.0216"
      },
      "credits_runway": {
        "estimated_hours_remaining": 25431,
        "estimated_runs_out_at": "2029-03-21T00:15:00Z",
        "rate_source": "auto-derived",
        "computed_at": "2026-04-30T20:15:00Z"
      },
      "transactions": [...],
      "pagination": {...}
    }

When the user is at or below the free baseline, `billable_bytes` is 0, `current_cost_per_month_*` is 0, and `credits_runway` becomes:

    "credits_runway": {
      "estimated_hours_remaining": null,
      "estimated_runs_out_at": null,
      "note": "You are within the free baseline. No usage charges apply.",
      "rate_source": "auto-derived",
      "computed_at": "2026-04-30T20:15:00Z"
    }

This is the user-facing equivalent of "you're costing me nothing right now, and your gift is intact." Important for the UX of the metering-only phase: most beta users will see this state most of the time.

### Extended: `GET /api/admin/credits` (list all)

The existing list-all admin endpoint adds the `current_usage` block per user (without the runway -- that's per-user expensive to compute and only useful in the detailed view). Lets the admin see the table view of "user, balance, current cost rate, billable bytes" at a glance.

### Extended: `GET /api/admin/credits/:username`

Adds the same `current_usage` and `credits_runway` blocks as the user-facing endpoint, plus an `admin_info` block already present.

### Extended: `GET /api/admin/users/:username/status`

Adds a `billing` block summarizing the user's billing position:

    "billing": {
      "balance_usd_microcents": 500000000,
      "formatted_balance": "$5.0000",
      "billable_bytes": 1073741824,
      "current_cost_per_month_usd": "$0.0197",
      "usage_deficit_microcents": 0,
      "last_billed_at": "2026-04-30T00:15:00Z"
    }

This is the admin's "do I need to gift this user more credits / talk to them about their usage" snapshot.

### New: `GET /api/admin/billing/rate`

Returns the currently-resolved rate and how it was derived. Useful for sanity-checking after a `storage_providers` change.

    GET /api/admin/billing/rate
    ->
    {
      "rate_microcents_per_byte_per_hour": 2740,
      "rate_human": "$20.00/TiB/month",
      "source": "auto-derived",
      "resolved_at": "2026-04-30T18:00:00Z",
      "base_cost_per_tb_per_month_cents": 1399,
      "markup_multiplier": 1.43,
      "contributing_providers": ["wasabi-us-central-1", "backblaze-b2"]
    }

When the rate source is `"env"`, the `base_cost_*`, `markup_multiplier`, and `contributing_providers` fields are omitted (because they don't apply). When the source is `"fallback-default"`, they are also omitted and a `note` field explains the fallback.

### New: `POST /api/admin/billing/recompute-rate`

Re-runs `ResolveRate` against the current `storage_providers` table and atomically swaps the in-memory cached rate. Returns the new resolved rate (same shape as the GET above). Logged to `admin_logs`.

    POST /api/admin/billing/recompute-rate
    ->
    {
      "success": true,
      "rate": { ... resolved Rate object ... },
      "previous_rate_microcents_per_byte_per_hour": 2500,
      "admin_info": { "recomputed_by": "admin-name" }
    }

This is the operator's escape hatch for "I just changed Wasabi's price; reflect it without restarting the server."

### New: `GET /api/admin/billing/sweep-summary?days=7`

Returns the most recent N days of daily-sweep summary data: total users settled, total drained microcents, total deficit added per day. Read directly from the `credit_transactions` table aggregating by day on `transaction_type = 'usage'`. Lets the admin produce trend charts without doing any per-row work.

    GET /api/admin/billing/sweep-summary?days=7
    ->
    {
      "days": 7,
      "summaries": [
        {
          "date": "2026-04-30",
          "users_settled": 47,
          "total_drained_microcents": 18250000,
          "total_drained_usd": "$0.1825",
          "users_in_deficit": 0,
          "total_deficit_added_microcents": 0
        },
        ... 6 more rows ...
      ]
    }

### New: `POST /api/admin/billing/gift` (per-user)

The dedicated gift endpoint, distinct from the existing `POST /api/admin/credits/:username` so the audit log clearly distinguishes gifts from generic credit adjustments. Body:

    POST /api/admin/billing/gift
    {
      "target_username": "alice",
      "amount_usd": "5.00",
      "reason": "Beta tester thank-you gift"
    }
    ->
    {
      "success": true,
      "target_username": "alice",
      "amount_usd": "5.00",
      "amount_microcents": 500000000,
      "transaction": { ... CreditTransaction object with type=gift ... },
      "updated_balance": { ... UserCredit object ... },
      "admin_info": { "gifted_by": "admin-name", "reason": "Beta tester..." }
    }

Validates `amount_usd > 0` and `reason` non-empty. Logs to `admin_logs` as action `gift_credits`.

### Routing and Authorization

All `/api/admin/billing/*` routes mount under the existing `adminGroup` in `handlers/route_config.go`, inheriting the existing TOTP-protected admin authentication. The `/api/credits` extension lives where it already does (TOTP-protected user group). No new authentication concepts are introduced.

### Backward Compatibility

The `_cents` -> `_microcents` rename is the only breaking JSON change. Everywhere else the new fields are additive: clients that don't know about `current_usage` or `credits_runway` continue to work and just don't display them. The `arkfile-admin` CLI tracks the rename in lockstep with the server (one PR, both directions), so there is no version-skew window where the CLI would break.

### What Is NOT Added in This Work

- No `/api/billing/buy` or `/api/payments/*` endpoints.
- No webhook receivers.
- No invoice creation.
- No "spend credits to extend storage" endpoint.
- No payment-method storage.

All of those are deferred to the future payments work.

## Frontend Surface Changes

The frontend addition for this work is intentionally minimal: a single new "Billing" page (or section, depending on how the existing nav is laid out) that renders the data already available from `GET /api/credits`. No payment buttons, no Stripe.js, no checkout flow. The page is meant to be self-explanatory to a non-technical user looking at it for the first time.

### New Page: `/billing` (or equivalent route)

Linked from the existing user menu (alongside settings/logout). The page has three sections, top to bottom:

#### Section 1: Balance and Runway

A large, friendly balance display:

    Your credit balance: $5.0000
    (Gifted by Arkfile on 2026-04-30)

    At your current usage rate, this lasts approximately 18 years.

When the user is at zero balance and has a deficit:

    Your credit balance: $0.0000
    Unbilled usage: $0.0234 (since 2026-08-15)

    Your credits ran out and additional usage is being recorded.
    No action is needed right now -- file uploads continue to work
    as long as you stay under your account's storage limit.

The "no action needed" framing matches the Phase 1 reality (no over-quota enforcement based on balance). It will change in the future payments work.

#### Section 2: Current Storage and Cost

A breakdown of the user's current usage:

    Storage used:    2.10 GiB of 50.0 GiB allowed
    Free baseline:   1.10 GiB (always free)
    Billable usage:  1.00 GiB

    Current rate:    $20.00/TiB/month
    Your cost:       $0.0197/month at this usage

    Free baseline savings:  $0.0216/month
    (You'd be paying this much extra without the free baseline.)

The free-baseline-savings line is a deliberate design choice: it makes the free 1.1 GiB feel like a tangible benefit, not just an abstract zero-debit zone. For most users in the metering-only phase this is the most informative line on the page (their billable usage is small, so their savings ratio is large).

When the user is below the free baseline:

    Storage used:    0.80 GiB of 50.0 GiB allowed
    Free baseline:   1.10 GiB (always free)
    Billable usage:  0.00 GiB

    You are within the free baseline. No charges apply.

#### Section 3: Transaction History

A simple chronological list of `credit_transactions` rows:

    2026-04-30  Gift                +$5.0000  ($5.0000)
                "Beta tester thank-you gift" by admin-name

    2026-05-01  Daily storage usage -$0.0006  ($4.9994)
                Avg 1.00 GiB billable, rate $20.00/TiB/month

    2026-05-02  Daily storage usage -$0.0006  ($4.9988)
                ...

Pagination using the existing `limit` and `offset` query parameters. Each row uses microcent precision in the display so the user sees the actual debit amounts. The "by admin-name" attribution is shown for `gift` and `adjustment` rows; usage rows have no attribution because they're system-generated.

#### Optional: A Compact Banner on the File-List Page

Above the existing file list, a one-line compact summary that matches the homepage banner pattern PayPerQ uses:

    Balance: $5.0000  |  Storage: 2.1/50 GiB  |  $0.0197/month  |  Manage billing

Only shown when the user has a non-zero billable usage or a non-default balance, to avoid clutter for users who never engage with the billing surface. Clicking "Manage billing" navigates to the new `/billing` page.

This is a small enhancement; if it adds visual noise it can be omitted entirely without losing functionality.

### What the Frontend Does NOT Add

- No payment-method form.
- No "Buy credits" button.
- No "Top up" flow.
- No saved-card management.
- No Stripe.js script tag, no Stripe Elements, no js.stripe.com requests of any kind.
- No external network requests at all beyond the existing Arkfile API.

This is consistent with the Phase 1 scope: the meter is observable but not actionable beyond what an admin can do via gifts. The user's only "action" if they want more credits is to contact the operator (in the beta phase, this is fine -- it's a small known set of users; in the public payments phase, they'll have buttons).

### Privacy and Loading-Behavior Notes

The billing page contains no PII -- everything it displays is derived from the user's existing account data and the global rate. No new analytics calls, no new third-party scripts, no fingerprinting. The page works under the same strict CSP as the rest of the frontend.

Decrypted-metadata posture (see `general-enhancements.md` items 5-7): the billing page does not interact with any of the user's encrypted-file metadata, so there is no incremental in-memory exposure of decrypted-plaintext material. The Account Key is not needed to render anything on this page.

### Implementation Mirroring Between Web and CLI

Per AGENTS.md's "one way to do things for a given client type" rule, the same data shape is consumed by the web frontend and by the `arkfile-admin billing show` CLI command. Both go through the documented JSON shape of `GET /api/credits` (or its admin variants). No frontend-specific server endpoints are introduced.

## CLI Surface Changes

The `arkfile-admin` CLI gets a new `billing` subcommand group. The existing `arkfile-admin set-cost` (which operates on `storage_providers.cost_per_tb_cents`) stays where it is and is referenced -- not duplicated -- from the new billing commands.

### New: `arkfile-admin billing show`

Pretty-prints the resolved rate and the global stats. Calls `GET /api/admin/billing/rate` and `GET /api/admin/billing/sweep-summary?days=30`.

    arkfile-admin billing show

    Resolved rate
      2740 microcents/byte/hour
      = $20.00/TiB/month sticker
      Source: auto-derived
      Base cost: $13.99/TiB/month (primary=wasabi-us-central-1 $7.99 + secondary=backblaze-b2 $6.00)
      Markup multiplier: 1.43x
      Resolved at: 2026-04-30 18:00:00 UTC

    30-day usage summary
      Total users settled:        47
      Total drained:              $5.4734
      Users in deficit:           0
      Total deficit accumulated:  $0.0000

      Daily averages:
        Per-user:      $0.0039/day  ($0.117/month)
        Total:         $0.182/day   ($5.47/month)

A `--json` flag produces machine-readable output in the same shape as the API response, for scripting.

### New: `arkfile-admin billing show --user <name>`

Shows a single user's billing position. Calls `GET /api/admin/credits/:username`.

    arkfile-admin billing show --user alice

    User: alice
      Balance:                $5.0000
      Storage:                2.10 GiB total (1.00 GiB billable above 1.10 GiB free baseline)
      Current rate:           $20.00/TiB/month
      Current cost:           $0.0197/month at this usage
      Estimated runway:       ~25,431 hours (~2.9 years) at current usage
      Last billed:            2026-04-30 00:15:00 UTC
      Usage deficit:          $0.0000

    Recent transactions (most recent 10):
      2026-04-30  Gift                +$5.0000  ($5.0000)
                  "Beta tester thank-you gift" by admin-name
      2026-05-01  Daily storage usage -$0.0006  ($4.9994)
      ...

### New: `arkfile-admin billing gift --user <name> --amount <USD> --reason <text>`

Sends `POST /api/admin/billing/gift`.

    arkfile-admin billing gift --user alice --amount 5.00 --reason "Beta tester thank-you"

    Success.
      Gifted:    $5.0000
      To user:   alice
      Reason:    Beta tester thank-you
      New balance: $10.0000
      Transaction ID: 482

Validates positive amount and non-empty reason locally before hitting the API.

### New: `arkfile-admin billing recompute-rate`

Sends `POST /api/admin/billing/recompute-rate`. Useful after `arkfile-admin set-cost --provider-id ... --cost ...`.

    arkfile-admin billing recompute-rate

    Recomputed rate
      Previous: 2500 microcents/byte/hour ($18.25/TiB/month)
      New:      2740 microcents/byte/hour ($20.00/TiB/month)
      Source:   auto-derived
      Base cost: $13.99/TiB/month (primary=wasabi-us-central-1 $7.99 + secondary=backblaze-b2 $6.00)
      Markup multiplier: 1.43x

If the rate did not actually change, the command says so and returns 0.

### New: `arkfile-admin billing list-deficits`

Lists all users with a non-zero `usage_deficit_microcents`. Useful for the operator to see who has run out of credits and is now accumulating unbilled usage.

    arkfile-admin billing list-deficits

    Users in deficit (3):
      USERNAME       BALANCE     DEFICIT     STORAGE       LAST BILLED
      bob            $0.0000     $0.0234     45.2 GiB     2026-08-15 00:15 UTC
      carol          $0.0000     $0.0089     12.1 GiB     2026-08-20 00:15 UTC
      dave           $0.0000     $0.0012     1.5 GiB      2026-08-22 00:15 UTC

A `--json` flag for scripting.

### New: `arkfile-admin billing tick-now` (dev/test only)

Forces an immediate meter tick (and optionally a sweep) without waiting for the scheduler. Only available when `ADMIN_DEV_TEST_API_ENABLED=true` (the existing dev/test gating). Used by `e2e-test.sh` to make billing observable in tests without waiting an hour.

    arkfile-admin billing tick-now [--sweep]

    Tick complete: 47 users metered.
    [Sweep complete: 47 users settled, $0.182 drained, 0 in deficit.]

When `ADMIN_DEV_TEST_API_ENABLED=false` this command returns an error explaining that the dev/test API is disabled, with no work performed.

### Help Text

The `arkfile-admin --help` output gains a `billing` line under the existing command list, and `arkfile-admin billing --help` lists the subcommands described above. Existing help text formatting is preserved.

### What the CLI Does NOT Add

- No `arkfile-admin payments` subcommand.
- No `arkfile-admin invoice` subcommand.
- No `arkfile-admin refund` subcommand.

All deferred to the future payments work.

## Configuration Reference

Every billing-related configuration value is read from `secrets.env` via the existing config-loading mechanism in `config/config.go`. All values are optional; sensible defaults are documented inline. Operators who want the meter to "just work" can set zero of these and accept defaults.

### Master Switch

`ARKFILE_BILLING_ENABLED` (boolean, default depends on deploy script):

- `dev-reset.sh`-generated `secrets.env`: **proposed default `false`**. Rationale: dev-reset wipes constantly, billing data is meaningless, and avoiding the meter keeps e2e tests free of timing-dependent flakiness. Override with `ARKFILE_BILLING_ENABLED=true` for tests that exercise the meter (the new e2e billing test does this).
- `local-deploy.sh`-generated `secrets.env`: **proposed default `true`**. Production-flavored deploy.
- `prod-deploy.sh`-generated `secrets.env`: **proposed default `true`**. Production deploy.
- `test-deploy.sh`-generated `secrets.env`: **proposed default `true`**. Matches what the test/demo `test.arkfile.net` deployment would want -- gives real beta usage data.

When `false`, the scheduler is not started, no ticks happen, no sweeps happen, no API endpoints related to billing are removed (they continue to return current state, just with stale or zero accumulator data). Useful for operators who want to deploy the code path but defer turning on the meter.

### Free Baseline

`ARKFILE_FREE_STORAGE_BYTES` (integer bytes, default `1181116006`):

The free-baseline storage size, in bytes. A user storing fewer bytes than this incurs no usage charge. Default matches the existing `models.DefaultStorageLimit` constant of 1.1 GiB. Operators can change it for their instance; common alternatives:

- Keep at 1.1 GiB (default; matches existing user expectations).
- Reduce to 100 MiB (`104857600`) for a more aggressive paid model.
- Increase to 5 GiB (`5368709120`) for a more generous free tier.

Per-user overrides are NOT supported in this Phase 1; the baseline is instance-wide. Future per-user overrides could be added if useful.

### Sticker Rate (Explicit)

`ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR` (integer, no default):

The explicit sticker rate in microcents per GiB per hour. When set, this overrides the auto-derivation and the markup multiplier; both are ignored. Useful for:

- Operators who want to set a specific price independent of provider costs.
- Operators running on infrastructure where `storage_providers.cost_per_tb_cents` is not maintained.
- Test environments where a fixed rate makes assertions easier.

If you want $20.00/TiB/month, the value to set is roughly:

    20.00 USD/TiB/month
    = 2000 cents/TiB/month
    = 2000 * 1000 microcents/TiB/month
    = 2,000,000 microcents/TiB/month
    / 1024 GiB/TiB
    / 30 days/month
    / 24 hours/day
    = ~2.71 microcents/GiB/hour

For the rate-per-byte-per-hour value used internally, divide that GiB-rate by `1024 * 1024 * 1024 = 1073741824`.

### Sticker Rate (Auto-Derived)

When `ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR` is unset, the rate is derived. Two values control the derivation:

`ARKFILE_BILLING_MARKUP_MULTIPLIER` (float, default `1.43`):

Multiplied against the sum of `storage_providers.cost_per_tb_cents` to produce the sticker price. Default of 1.43 turns a $14/TiB cost into a ~$20/TiB sticker. A multiplier of 1.0 means cost = sticker (no markup); higher multipliers reflect operator overhead, support, and profit margin. Operator's call.

`ARKFILE_BILLING_RATE_FALLBACK_MICROCENTS_PER_BYTE_HOUR` (integer, default `2740`):

The fallback rate used when no providers have `cost_per_tb_cents` set, or when the table is empty. Default of 2740 microcents/byte/hour equals $20/TiB/month at TiB=2^40. Operators rarely need to change this; it exists as a safety net.

### Gifted Starter Balance

`ARKFILE_BILLING_GIFTED_CREDITS_USD` (string, default `"5.00"`):

The amount of credits to gift to each newly-approved user, in USD. **Proposed default of $5.00** chosen to be:

- Big enough that the credits page shows years of runway at typical low usage (a powerful trust signal).
- Small enough that the operator's exposure for handing out gifts is bounded ($500 of gifts for the first 100 users, etc.).

Set to `"0.00"` for a deployment that wants no automatic gifts; operators can still gift via `arkfile-admin billing gift`. Set higher (`"10.00"`, `"25.00"`) for premium-tier deployments.

The gift is applied to the user's `user_credits` row at the time the user is approved (matching the existing approval flow's transaction-bracket). A row is added to `credit_transactions` with `transaction_type = 'gift'`, `reason = "Initial gift to new user"`, `admin_username` set to the approving admin's name (or "system" if approval was automatic for admin usernames).

### Tick and Sweep Timing

`ARKFILE_BILLING_TICK_INTERVAL` (Go duration, default `1h`):

How often the meter ticks. Production deployments should leave this at `1h`. For testing, can be set to `1m` or `10s` to make meter activity observable in short test runs.

`ARKFILE_BILLING_SWEEP_AT_UTC` (HH:MM string, default `"00:15"`):

The UTC time of day when the daily sweep runs. Default of `00:15` is "shortly after midnight" -- gives the previous day's usage time to fully accumulate (since the last tick at 23:00 UTC) before settlement. Operators in time zones where 00:15 UTC is an inconvenient time to monitor can shift it.

`ARKFILE_BILLING_RATE_REFRESH_INTERVAL` (Go duration, default `15m`):

How often the scheduler re-resolves the rate from `storage_providers`. Detects changes that operators make outside of the explicit `recompute-rate` admin command. Default of 15 minutes is a balance between freshness and DB-query frequency.

### Billing Includes Admins?

`ARKFILE_BILLING_INCLUDE_ADMINS` (boolean, default `false`):

When `false`, admin accounts are excluded from the meter -- they get neither hourly ticks nor daily-sweep transaction rows nor the gifted starter balance. When `true`, admins are billed exactly like regular users. Default of `false` keeps the operator's own files from polluting the per-user economic data being collected during the metering-only phase.

### Example `secrets.env` Block

For a typical operator using the defaults:

    # Storage billing -- all values optional, defaults documented in
    # docs/wip/storage-credits.md
    ARKFILE_BILLING_ENABLED=true
    # ARKFILE_FREE_STORAGE_BYTES=1181116006              # 1.1 GiB default
    # ARKFILE_BILLING_MARKUP_MULTIPLIER=1.43             # default
    # ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR=       # leave unset for auto-derivation
    # ARKFILE_BILLING_GIFTED_CREDITS_USD=5.00            # default
    # ARKFILE_BILLING_TICK_INTERVAL=1h                   # default
    # ARKFILE_BILLING_SWEEP_AT_UTC=00:15                 # default
    # ARKFILE_BILLING_RATE_REFRESH_INTERVAL=15m          # default
    # ARKFILE_BILLING_INCLUDE_ADMINS=false               # default

For a test deployment that wants a fixed rate and no gifts:

    ARKFILE_BILLING_ENABLED=true
    ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR=2740
    ARKFILE_BILLING_GIFTED_CREDITS_USD=0.00

For a deploy that wants the meter completely off:

    ARKFILE_BILLING_ENABLED=false

The deploy scripts (`local-deploy.sh`, `prod-deploy.sh`, `test-deploy.sh`, `dev-reset.sh`) are updated as part of this work to write the appropriate `ARKFILE_BILLING_ENABLED` line into the generated `secrets.env`. Other values default at server startup; operators only set them if they want to override.

### Open Question: Defaults Pending Operator Confirmation

The four defaults proposed in this section -- markup `1.43`, gifted balance `$5.00`, billing-enabled defaults per script, and the wipe-and-redeploy migration approach -- were proposed by the design author and have not yet been explicitly confirmed by the operator. They should be reviewed during PR review; this document calls them out so they don't slip through unnoticed.

## Honest Trade-offs and Risks

Per AGENTS.md "Honesty and Transparency" guidance, this section names every known weakness, sharp edge, and judgment call in the design. None of them are dealbreakers, but operators reviewing the design should see them spelled out.

### The Meter Is User-Visible Even Though Money Doesn't Change Hands

As soon as the credits page goes live, beta users will see a balance, a usage rate, and a runway estimate. Some non-trivial percentage of those users will read this as "I am being charged." The mitigations are:

- The gifted starter balance ($5.00 default) is sized so that runway is shown in years for typical users, making it visually obvious nothing is being lost.
- The "balance exhausted" state shows the explicit message "No action is needed right now -- file uploads continue to work as long as you stay under your account's storage limit."
- The deficit accumulates rather than blocking uploads, so even a user who somehow drives their balance to zero is not impeded.
- The frontend page header should explicitly say "Beta: this is a preview of the eventual paid storage system. No real charges occur." until the future payments work flips that flag.

There is no escape from "users will form opinions about the price they see." This is part of the value of running the meter early -- those opinions become data the operator can act on.

### Auto-Derived Rate Is Only as Good as `cost_per_tb_cents` Maintenance

If an operator forgets to update the Wasabi or Backblaze cost in `storage_providers` after a vendor price change, the sticker price silently lags reality. For the operator running at a small markup, this could mean billing below cost without realizing it. Mitigations:

- The resolved rate is logged at INFO on every server startup so an attentive operator notices changes.
- The `arkfile-admin billing show` command displays "rate resolved at" and "contributing providers" so an operator can quickly check.
- A future improvement (not in scope for this work but flagged): the admin UI for `storage_providers` should display "last cost update: N days ago" with a yellow indicator if N is large.

### The Daily Sweep Could Drift Forward If a Day Gets Skipped

If the server is down at 00:15 UTC on day N and comes back up at 02:00 UTC, the sweep for day N is missed. The accumulator continues to grow, and the next-day sweep at day N+1's 00:15 UTC drains 48 hours' worth of accumulated usage in a single transaction row labeled with the wrong period boundaries. Real-world impact:

- The total amount billed is correct (the meter has been ticking all along).
- The transaction row's `metadata.period_start` and `metadata.period_end` will span 48 hours, not 24.
- The user sees one larger debit on day N+1.

Mitigations: the scheduler logs a warning when it detects "elapsed since last sweep > 25 hours" and the metadata field includes accurate period boundaries so historical reconciliation works. A more elaborate fix (split into two summary rows) is possible but adds complexity for a low-frequency event; deferred.

### The Accumulator Carries Unbounded State If the Sweep Fails Repeatedly

If the daily sweep fails for any reason (DB error, OOM, etc.) and is not noticed, the accumulator grows without bound until manual intervention. Real-world impact: very small, since the accumulator table is one row per user with two integer columns. Even at 1M users, an unbounded accumulator is a few megabytes.

Mitigations: the operator should monitor the "users with `last_billed_at < now - 48h`" count via an admin alert. A future small enhancement (not in scope) would be a startup self-check that warns if any user has `last_tick_at - last_billed_at > 25 hours`.

### Tick Boundaries Are Not Wall-Clock Aligned

After a server restart, the next tick happens at `restart_time + 1h`, not at the top of the next wall-clock hour. So a server that restarts at 14:23:17 has ticks at 15:23:17, 16:23:17, etc., not at 15:00:00, 16:00:00. Real-world impact: none for billing accuracy (the accumulator carries forward), but it makes log timestamps slightly less predictable.

Mitigations: the operator can read the first tick log line to know the cadence. If wall-clock alignment is desired, it can be added to the scheduler in a future small enhancement.

### Microcent Migration Is Destructive in This Phase

Because Item 8 from `general-enhancements.md` is not implemented, the cents-to-microcents migration drops and recreates `user_credits` and the existing fields in `credit_transactions`. Any data in those tables today is lost. Real-world impact: minimal in current state (the tables are effectively empty in the test/demo deployment), but worth flagging to beta users in advance.

Mitigations: a one-line beta-user notice in the deploy announcement, and a documented `arkfile-admin billing show --user <name>` post-deploy that operators can run to confirm balances are reasonable for known users they may need to re-gift.

### No I/O / Bandwidth Billing

The meter only bills for stored bytes, not for bandwidth (uploads/downloads). For storage providers like Wasabi (no egress fees), this is fine. For Backblaze B2 (~$0.01/GiB egress over a small free allowance), heavy-download users undercount the operator's actual cost basis. Real-world impact:

- Users who upload-and-rarely-download cost the operator near the storage rate.
- Users who upload-and-download-frequently could cost the operator significantly more than the meter reports.

Mitigations: this is a design choice, not an oversight. Bandwidth metering is more complex (requires byte-counting in the download path, separate per-provider rate config, etc.) and is deferred. It is flagged here so operators considering download-heavy use cases know to set the markup multiplier higher to absorb the asymmetry.

### Scheduler Runs in a Single Process

If the operator deploys multiple Arkfile server instances behind a load balancer (for HA), all instances would run their own meter independently and double-count. The current Arkfile architecture is single-process by design (the SQLite/rqlite database is the consistency point), so this is not currently an issue. But if multi-instance deployment is ever introduced, the meter needs a leader-election or distributed-lock layer.

Mitigations: a one-line check at scheduler startup that fails fast if the operator has somehow misconfigured it for multi-instance use. For now, single-process is the assumption and is matched by the rest of the architecture.

### The Deficit Column Is Informational, Not Actionable

`users.usage_deficit_microcents` accumulates when balance hits zero, but in this Phase 1 nothing happens with it. The operator can see it via `arkfile-admin billing list-deficits` and choose to gift the user enough to clear it -- but there is no automatic clearing, no email to the user, no upload block. This is correct for the metering-only phase but worth being explicit about.

The future payments work will define what to do with deficits: write off to bad debt, attach to next top-up, treat as a soft over-quota signal that limits new uploads. This document does not pre-judge those choices.

### The Existing Hard Cap Stays in Place

`users.storage_limit_bytes` continues to enforce upload-time limits independent of the meter. A user with `storage_limit_bytes = 50 GiB` can upload up to 50 GiB regardless of their credit balance. This is the safe default for the metering-only phase: no change to existing user-facing upload behavior.

But it does mean the system has two notions of "limit" running side by side -- the hard cap (admin-controlled) and the soft cap implicit in the credit balance (meter-driven). Operators who confuse the two during admin operations could accidentally limit users in unexpected ways. The `GET /api/admin/users/:username/status` endpoint shows both, in the same `billing` block, so the contrast is visible.

The future payments work will need to make a decision about how to unify these two concepts. This document deliberately does not.

### Privacy Posture Has One Small New Surface

The meter writes per-user, per-day rows to `credit_transactions` with `metadata` JSON containing `avg_billable_bytes` for that day. This is per-user data the server already had (it's just `total_storage_bytes` minus the free baseline, sampled hourly), but persisting daily averages does create a long-term record of "how much storage user X had on day Y." A passive observer with database access learns:

- Each user's daily storage history.
- The shape of growth/shrinkage over time.

The server already knows this in real time via `users.total_storage_bytes`; the new persistence is just a multi-day historical record of it. This is not a new fundamental disclosure -- it is a longer-retained version of an existing one.

Mitigations: the daily summary metadata could omit `avg_billable_bytes` and only persist the drained-microcents amount, which would reduce the record to "user X paid $0.0006 on day Y" without disclosing the underlying byte count. The trade-off is that historical reconciliation becomes harder. Decision: keep `avg_billable_bytes` in metadata for now; revisit if/when privacy review surfaces it as a concern.

### The 30-Days-Per-Month Convention Is Imprecise

The rate calculation uses 30 days/month as a conventional simplification. Actual months are 28 to 31 days, so the per-hour rate is consistently a slight overcharge in 31-day months and a slight undercharge in 28-day months. Real-world impact: ~3% variance in either direction over a year.

Mitigations: this is the standard convention in cloud billing (AWS, GCP, Azure all do similar). Documented here so reviewers don't think it's a bug. A more precise calculation would multiply by the actual hours-in-month for the month being billed; not worth the complexity.

### Test Coverage Is Time-Sensitive

Unit-testing a scheduler that ticks every hour and sweeps every day requires either fast-forwarding time or making the intervals configurable. The design uses configurable intervals (good for tests) but unit-tests should use injectable clocks rather than wall time to be robust against CI flakiness.

Mitigations: the test plan section explicitly calls out injectable-clock testing patterns. The `billing/scheduler_test.go` file uses a `time.Now` interface that the test substitutes.

These trade-offs are all defensible for the metering-only phase. None of them block the work; they exist so that future readers (and the future-payments work) understand the boundaries.

## Test Plan

The meter is a piece of code that runs every hour against every active user and silently moves money around in a ledger. Test coverage matters more than usual because regressions can be quiet. The plan covers four layers: unit tests in `billing/`, model-layer tests for the rename-to-microcents migration, handler tests for the API surface, and a new e2e test section that exercises the full meter end to end.

### Unit Tests in `billing/`

`billing/rates_test.go`:

- Resolution priority test matrix: env-set value wins over derivation; auto-derivation fires when env is unset and providers exist; fallback fires when neither is available.
- Auto-derivation math: known inputs (sum of two providers' costs in cents, markup multiplier) produce the expected microcents-per-byte-per-hour value, with explicit tolerance assertions for the integer-math truncation.
- Provider filtering: rows with `is_active = false` are excluded; rows with role outside primary/secondary/tertiary are excluded; rows with NULL `cost_per_tb_cents` are excluded; rows with `cost_per_tb_cents = 0` are included (zero is a valid cost).
- `(*Rate).FormatHumanReadable()` produces the documented multi-line output for each `Source` value, with a golden-string comparison.
- Atomic-pointer cache test: concurrent reads while a write happens never observe a torn `Rate`.

`billing/meter_test.go`:

- Tick math: known `total_storage_bytes`, `free_baseline_bytes`, and `Rate` produce the expected `tick_charge_microcents`, with edge cases at exactly the free baseline (charge = 0), one byte over (charge = `rate * 1`), and well over.
- Accumulator update: first tick for a user inserts a row; subsequent ticks update the row in place; `last_tick_at` is monotonically updated.
- No-op for users below baseline: tick produces no DB write at all (verified by recording the SQL traffic).
- `TickAllActiveUsers` filters: unapproved users skipped; admin users skipped when `IncludeAdmins=false`; admin users included when `IncludeAdmins=true`.
- Per-user error isolation: one user's tick failing does not prevent the next user from being ticked; aggregate error count is correct.

`billing/sweep_test.go`:

- Drain math: known accumulator value and balance produce the expected new balance, deficit, and transaction-row content.
- Deficit clamping: when accumulator > balance, balance becomes 0 (not negative), deficit increments, log event is emitted.
- Idempotency: a sweep run twice in succession on the same data drains once and is a no-op the second time. (`unbilled_microcents = 0` after the first sweep means the second sweep finds nothing to drain.)
- Per-user transaction rollback: a deliberate DB error mid-sweep on user N leaves users 0..N-1 correctly settled and user N unchanged.
- Metadata content: the JSON in the `credit_transactions.metadata` field contains all the documented fields with the right types.

`billing/scheduler_test.go`:

- Uses an injectable clock (a small `Now func() time.Time` interface).
- Tick frequency: at `tickEvery=1m` over 10 simulated minutes, exactly 10 tick calls are recorded.
- Sweep frequency: at `sweepAtUTC=12:00` over a simulated 24h window crossing 12:00, exactly one sweep call is recorded.
- Rate refresh: at `rateRefreshEvery=5m`, the rate is re-resolved on schedule even without ticks; a changed rate is logged and the cached pointer swapped.
- Clean shutdown: `cancel()` causes `Run` to return within a small timeout; no goroutine leak.

`billing/gift_test.go`:

- Validates positive-amount and non-empty-reason precondition.
- Inserts the credit_transactions row with `transaction_type = 'gift'` and the right metadata.
- Logs the security event.
- Idempotency: not relevant (gift is not idempotent; calling twice gifts twice -- this is by design).

### Model-Layer Tests in `models/credits_test.go`

The existing `models/credits_test.go` (if present; if not, this work creates it) gains assertions on:

- The renamed columns (`balance_usd_microcents`, `amount_usd_microcents`, `balance_after_usd_microcents`) are the ones queried.
- `FormatCreditsUSD` (renamed if needed) produces four-decimal output from microcents.
- `ParseCreditsFromUSD` produces microcents from a USD string, with rounding at the microcent boundary.
- `AddCredits`/`DebitCredits`/`SetCredits` operate on microcents end to end.

### Handler Tests in `handlers/credits_test.go` and `handlers/billing_test.go`

`handlers/credits_test.go` (existing, extended):

- `GET /api/credits` response shape has the new `current_usage` and `credits_runway` blocks.
- A user at the free baseline returns `billable_bytes = 0` and the documented "you are within the free baseline" note.
- A user above the baseline returns the expected `current_cost_per_month_*` numbers (using a fixed test rate to make assertions deterministic).
- The `formatted_balance` is a four-decimal string.
- Pagination still works.

`handlers/billing_test.go` (new):

- `GET /api/admin/billing/rate` returns the cached rate object; admin auth required; non-admin returns 403.
- `POST /api/admin/billing/recompute-rate` re-resolves and returns the new rate; logs admin action.
- `GET /api/admin/billing/sweep-summary?days=7` returns the right number of summary rows aggregated from `credit_transactions`.
- `POST /api/admin/billing/gift` validates inputs and inserts the right transaction row; admin action logged.

### E2E Test Section in `scripts/testing/e2e-test.sh`

The existing `e2e-test.sh` already covers the full encrypt-upload-download-decrypt cycle. A new "billing meter" section is added near the end, gated by `ARKFILE_BILLING_ENABLED=true` in the dev-reset configuration:

1. Set `ARKFILE_BILLING_ENABLED=true`, `ARKFILE_BILLING_TICK_INTERVAL=1m`, `ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR=2740` (deterministic, no auto-derivation), `ARKFILE_BILLING_GIFTED_CREDITS_USD=1.00` (small enough to drain quickly).
2. `dev-reset.sh` runs to pick up the new config.
3. Test user uploads ~100 MB of test files (above the 1.1 GiB baseline by 0 bytes -- so we need to also reduce the baseline for this test, e.g., `ARKFILE_FREE_STORAGE_BYTES=10485760` for 10 MiB free baseline, leaving ~90 MiB billable).
4. Call `arkfile-admin billing tick-now --sweep` to force the meter to advance immediately.
5. Assert the user's balance has decreased by the expected amount (computed from the known `billable_bytes`, rate, and 1 hour). Assert a `usage` row was inserted into `credit_transactions` with the right metadata.
6. Call `arkfile-admin billing gift --user <test-user> --amount 5.00 --reason "e2e test gift"`. Assert the balance increased and a `gift` row was inserted.
7. Call `arkfile-admin billing recompute-rate`. Assert the rate is unchanged (no provider change happened) and the response says so.
8. Repeat tick-now several times to drive the balance to zero. Assert the deficit column is incremented and the user shows up in `arkfile-admin billing list-deficits`.
9. Cleanup: delete the test files, cancel any in-progress sessions.

This section is in the same shape as the existing `e2e-test.sh` sections (numbered phases, explicit assertions, cleanup). It runs in under a minute because of the small tick interval and small file sizes.

### Playwright Test Section in `scripts/testing/e2e-playwright.ts`

A small Playwright section that:

1. Navigates to the new `/billing` page.
2. Asserts the balance display shows four-decimal precision.
3. Asserts the "current usage" block shows the right billable-bytes value (from a known test-user state).
4. Asserts the "transaction history" section lists the gift and usage rows in chronological order.
5. Asserts there are NO `<script src="https://js.stripe.com/...">` tags in the page (privacy-posture regression check).
6. Asserts there are NO requests to `js.stripe.com` in the network log (CSP regression check).

The last two assertions are the explicit "no Stripe.js leaked into the meter-only page" tests called out in the Frontend section.

### Test Coverage Goals

- `billing/` package: 90%+ line coverage. Achievable because the package is small and side-effects are concentrated in DB calls.
- New handlers: same coverage standard as existing handlers (~70%).
- E2E meter section: every documented user-visible behavior (gift, tick, sweep, deficit, recompute) is exercised at least once.

### What the Tests Do NOT Cover

- Real-money behavior. All test invocations use the gift/usage path; no payment provider is invoked.
- Long-time-horizon behavior. Tests use minute-scale tick intervals; year-scale runway estimates are tested by computation, not by simulation.
- Multi-instance behavior. Single-process is the deployment assumption.

## Phase 1 Implementation Order

The work breaks into PR-sized steps that can be reviewed independently and that always leave the tree in a buildable, deployable state.

### Step 1: Reconcile `DefaultStorageLimit`

A one-line schema change plus a sanity-check unit test. Smallest possible change, lands first to clear out the latent bug before anything else touches the storage code. Independently shippable; no other Phase 1 work depends on this landing first but landing it first reduces noise in the later diffs.

### Step 2: Rename `_cents` -> `_microcents` Throughout

The cents-to-microcents migration:

- Schema changes (drop and recreate `user_credits`, alter `credit_transactions` columns).
- `models/credits.go` struct rename and method updates.
- `handlers/credits.go` JSON field rename and admin endpoint updates.
- `cmd/arkfile-admin/` struct rename and CLI display updates.
- All existing tests updated.
- Formatting helpers updated to four-decimal output.

This is destructive (drops `user_credits` data) and should land in a single PR with a clear commit-message warning. Operators know to re-deploy with a wipe.

After this step, the system is functionally identical to before, just with finer-grained internal precision and a renamed field. No new behavior. This is the largest single diff in the work but it is mechanical -- no design decisions, just a search-and-replace plus type widening.

### Step 3: New Schema Tables and Columns

`storage_usage_accumulator` table with indexes; `users.usage_deficit_microcents` column. New transaction types `usage` and `gift` are documented (no enum constraint to update). Smallest possible step; lands cleanly because nothing yet writes to these tables.

### Step 4: The `billing/` Package

The five core files (`rates.go`, `meter.go`, `sweep.go`, `scheduler.go`, `gift.go`, plus `types.go`) and their tests. Compiles and passes tests in isolation; no integration with `main.go` yet. The package is dead code at this step but reviewable on its own merits.

### Step 5: Wire the Scheduler Into `main.go`

The startup hook with the `cfg.Billing.Enabled` check, the goroutine spawn, the context cancellation. Configuration loading is updated to recognize all `ARKFILE_BILLING_*` env vars with documented defaults. Deploy scripts updated to write the appropriate `ARKFILE_BILLING_ENABLED` line into generated `secrets.env`.

After this step, the meter runs on production-flavored deploys. No user-visible change yet (the API hasn't been extended, so the data isn't surfaced).

### Step 6: Extend the API Surface

Handlers updated for the new `current_usage` and `credits_runway` blocks; new `/api/admin/billing/*` endpoints added. Handler tests added.

After this step, the meter is observable via API. Frontend still doesn't render it.

### Step 7: Frontend `/billing` Page

The new page. Three sections (balance, usage, transactions), the optional banner. Playwright test added. No Stripe-related code (those test assertions are the regression guard).

After this step, users see the meter on the new page. End of metering-only Phase 1 functionality.

### Step 8: `arkfile-admin billing` CLI

The new subcommand group. Each subcommand individually small. Help text updated.

After this step, operators can administer the meter from the CLI.

### Step 9: e2e Test Section

The new section in `e2e-test.sh`. Runs under `dev-reset.sh` with `ARKFILE_BILLING_ENABLED=true` and the small-interval test config.

### Step 10: Documentation Polish

A new `docs/billing.md` (separate from this WIP doc) summarizing the user-visible meter for inclusion in the operator-facing documentation. The WIP doc itself moves to `docs/wip/archive/storage-credits.md` once the work lands, per the existing pattern in `docs/wip/archive/`.

### Estimated Sizing

Approximate diff sizes per step (rough order of magnitude):

- Step 1: ~10 lines.
- Step 2: ~500 lines (mostly mechanical rename across many files).
- Step 3: ~50 lines of schema.
- Step 4: ~600 lines of Go (the meter itself plus tests).
- Step 5: ~50 lines (config + main.go + deploy scripts).
- Step 6: ~300 lines of handlers + tests.
- Step 7: ~400 lines of TypeScript + CSS + Playwright test.
- Step 8: ~400 lines of CLI.
- Step 9: ~100 lines of bash.
- Step 10: ~200 lines of markdown.

Total: about 2,600 lines of new/changed code, roughly 60% non-test. A reasonable two-to-three-week piece of work for one engineer, deliverable in 8-10 small PRs.

### Gating Between Steps

Each step is independently shippable but can be merged in clusters if PR overhead is too high. The natural cluster boundaries are:

- Cluster A: Steps 1-3 (schema + rename, no behavioral change).
- Cluster B: Steps 4-5 (the meter starts running, but is invisible).
- Cluster C: Steps 6-8 (the meter becomes observable, then administrable).
- Cluster D: Steps 9-10 (test coverage and docs).

A test/demo deployment after Cluster C lets the operator start collecting real usage data immediately, then iterate on defaults (markup, gift size, free baseline) based on what the meter reports. That feedback loop should run for at least a few weeks before any payment-provider work begins.

## Forward-Looking: Future docs/wip/payments.md

This section is scaffolding for a future document, not a design itself. It lists what is known about the eventual payments work so that the meter implementation does not accidentally foreclose options.

### What the Future Document Will Cover

A separate WIP document, tentatively at `docs/wip/payments.md`, will design the actual payment integration. The previous design discussion (see this conversation's history) settled several decisions that the future document should incorporate:

- Payment surface: BTC on-chain, BTC Lightning (via Boltz, no self-run LN node), Monero (via the BTCPay `btcpay-monero` plugin), USDT, USDC, USD/EUR via Stripe (cards, Apple/Google Pay, SEPA, ACH).
- Payment routing: BTCPay Server for everything except cards/USDC/SEPA/ACH; direct Stripe integration for those.
- Stripe gating: behind an operator-config flag (`STRIPE_ENABLED=false` by default) so privacy-maximalist deployments can ship BTCPay-only.
- Stripe loading behavior: dynamic ES module import, separate JS chunk, no `js.stripe.com` requests until the user explicitly clicks "pay with card." CSP gated behind the same flag.
- Stripe identity posture: `Customer` object created with `email=null`, `name=null`, `description=null`. PII fields scrubbed from webhook payloads before storing `raw_payload`. No `receipt_email`.
- Saved-card pattern: SetupIntent + PaymentIntent off-session for top-ups, modeled on PayPerQ's UI.
- Auto-top-up: opt-in, with operator-configurable hard monthly cap (proposed default $500/month).
- Idempotency: `payment_invoices` table with `UNIQUE(provider, provider_invoice_id)` so webhook replays cannot double-credit.
- Pricing surface: continuous-drain credits matching this work's microcent ledger, not separate prepaid entitlements. The meter built in this work IS the consumption side; the payments work just adds the top-up side.
- Free baseline policy: stays as-is (not changed by payments work).
- Over-quota policy when balance hits zero: soft block on uploads only, files preserved indefinitely, no auto-deletion ever in v1.
- Refund UX: admin-only in v1.
- USDT labeling: shared "stablecoins are visible to issuer and freezable" disclosure shown next to both USDT and USDC.

### Hard Prerequisites Before Payments Work Begins

Three items from this document and `docs/wip/general-enhancements.md` are flagged as gating prerequisites:

1. **Item 8 from `general-enhancements.md`**: the column-evolution layer. Once real money flows through the system, "wipe to add a column" stops being acceptable. This must land before the first payment provider integration.
2. **Item 2 from `general-enhancements.md`**: the pre-flight storage-quota endpoint. Clients need to ask "do I have room?" before initiating an upload, and "do I have room and can I buy room if not?" once payments exist. Worth implementing first as a small standalone change.
3. **At least 2-4 weeks of meter data from this work's deployment**, to inform pricing-default decisions with evidence rather than guesses.

### What the Meter Built in This Document Locks In

These design decisions made for the meter are durable and the payments work should build on them, not change them:

- The microcent unit. Payments add credits in microcents (denominated as USD on the wire but converted at the boundary), debits drain microcents.
- The hourly tick + daily settlement pattern. Payments-driven credit additions land on `user_credits.balance_usd_microcents` directly; the meter continues to drain from it daily.
- The `credit_transactions` audit log shape. Payment top-ups add new transaction types (e.g., `payment_btc`, `payment_lightning`, `payment_monero`, `payment_stripe`) that fit the existing schema without modification.
- The `transaction_id` field. Already designed for opaque external provider IDs ("Bitcoin, PayPal, etc.").
- The free-baseline-above-which-billable model. Payments don't change what is billable; they just make it possible to refill the credit balance.
- The decoupling of `users.storage_limit_bytes` from credit balance. Payments work might choose to couple them (over-quota soft block based on balance) or might not. This document does not pre-decide.

### What Is Left Open for the Future Document

Things this document does NOT pre-decide and that the future document should:

- Whether the existing `storage_limit_bytes` hard cap is replaced by a credit-balance-derived cap, or kept as an independent hard ceiling.
- Whether per-user free-baseline overrides should exist (e.g., grandfathered users get more free space).
- Whether bandwidth/egress should be billed in addition to storage.
- The exact shape of the BTCPay and Stripe webhook handlers.
- The exact set of payment-method strings exposed in the UI.
- The refund / pull-payment flow design.
- The auto-top-up implementation details.
- The deficit-column resolution policy (write off, attach to next top-up, soft block, etc.).

### Pointer

When the operator is ready to begin payments work, the next step is to create `docs/wip/payments.md` and design the items above with the same level of detail as this document. The conversation history that preceded this document captured many of those design decisions and should be referenced as input.

This document, `docs/wip/storage-credits.md`, is complete in itself: implementing it gives the operator a working storage-credits meter with no real-money integration. Whether and when to proceed with the payments work is an independent decision that this document does not force.

---

# ADDITIONAL NOTES AND INITIAL FEEDBACK FROM ANOTHER LLM

## Overall Assessment

**Logical, coherent, consistent: yes.** The doc is internally consistent, well-organized, and each section reinforces the others. The "metering before payments" sequencing argument in section 2 is genuinely persuasive (the four reasons -- correctness isolation, evidence-based pricing, schema migration window, privacy-surface isolation -- are all individually true).

**Feasible and doable: yes, with reservations on a few specific points.** The implementation order in Phase 1 is realistic, the diff sizes are honest (~2,600 lines including tests is the right ballpark), and the new `billing/` package layout cleanly avoids tangling with `models/` or `handlers/`. The 10 steps are correctly sized and could plausibly be done in 8-10 small PRs.

**AGENTS.md alignment: strong.** The doc explicitly addresses the "no PII," "privacy-first," "greenfield/wipe-acceptable," "one way to do things," and "honesty" guidance. The "Honest Trade-offs and Risks" section (12 named weaknesses, none hidden) is exactly the posture AGENTS.md asks for.

---

## What Works Particularly Well

1. **Microcent unit choice is correct.** The doc walks through the math: at $20/TiB/month, per-byte-per-hour in cents truncates to 0; in millicents it's 27 with no headroom; in microcents it's 27,400. This is the right precision floor.

2. **Hourly tick + daily settlement is the right decomposition.** Audit-log size scales with `users × days` not `users × hours`, and the per-user accumulator is bounded at one row per user. This is the standard cloud-billing pattern and the doc correctly justifies it.

3. **Auto-derivation from `storage_providers` is elegant.** Reuses `cost_per_tb_cents` infrastructure that already exists, with a clean override priority (env > derived > fallback constant) and a force-recompute escape hatch.

4. **Decoupling from the existing `storage_limit_bytes` hard cap is the right Phase 1 call.** Keeping the upload gate unchanged means this work cannot accidentally break user-facing upload behavior. The doc is admirably explicit that unifying the two notions of "limit" is deferred to the future payments work.

5. **The `_cents` -> `_microcents` rename is honestly flagged as breaking** with the mitigation that the credits API is currently unrendered and the test/demo deployment's tables are effectively empty.

6. **Privacy posture is taken seriously.** No new external network calls, no payment-provider surface, no Stripe.js. The Playwright regression assertions for "no js.stripe.com requests" are a thoughtful guardrail.

---

## Major Gaps and Confusing Items

These are real issues the doc does not adequately address. None are dealbreakers, but they should be resolved before implementation begins.

### 1. The `e2e-test.sh` script name is wrong throughout

AGENTS.md references `bash scripts/testing/e2e-test.sh` as the main test script. Looking at the actual repo, I see `scripts/testing/e2e-playwright.sh` and `scripts/testing/e2e-playwright.ts`, but no `e2e-test.sh` in the listing. The storage-credits doc treats `e2e-test.sh` as if it exists (Step 9, Test Plan section). This may simply be a script that lives elsewhere or is generated, but it's worth verifying before relying on it.

### 2. The unit conversion in the configuration section is wrong

Section "Sticker Rate (Explicit)" gives this worked example:

> 20.00 USD/TiB/month = 2000 cents/TiB/month = 2000 * 1000 microcents/TiB/month = 2,000,000 microcents/TiB/month / 1024 GiB/TiB / 30 / 24 = ~2.71 microcents/GiB/hour

Two problems:
- `2000 * 1000 = 2,000,000` is millicents/TiB/month, not microcents (microcent = 1/1,000,000 of a dollar = 1/10,000 of a cent, so 2000 cents = 20,000,000 microcents).
- The result "~2.71 microcents/GiB/hour" is therefore off by ~10x.

Cross-checking against the elsewhere-cited fallback `2740 microcents/byte/hour` (which the doc says equals $20/TiB/month):
- 2740 microcents/byte/hour × 1,099,511,627,776 bytes/TiB ≈ 3.013×10^15 microcents/TiB/hour
- × 720 hours/month ≈ 2.169×10^18 microcents/TiB/month
- ÷ 100,000,000 microcents/USD ≈ $21.69 billion/TiB/month -- clearly wrong.

Working it the other direction:
- $20/TiB/month = $20 × 100 × 1,000,000 = 2,000,000,000 microcents/TiB/month
- ÷ 720 hours/month = 2,777,778 microcents/TiB/hour
- ÷ 1,099,511,627,776 bytes/TiB ≈ 0.00253 microcents/byte/hour

So `2740 microcents/byte/hour` is not equivalent to $20/TiB/month -- it's off by roughly 6 orders of magnitude. Either the fallback constant is wrong, or the unit name is wrong (maybe it's meant to be "microcents per GiB per hour" -- in which case 2740 microcents/GiB/hour ≈ $20.06/TiB/month, which checks out).

**This is a significant precision/units bug in the design** that needs to be resolved before any code is written. My read is that the fallback constant should be either "2740 microcents per GiB per hour" or roughly "2.6 microcents per GiB per hour" or "0.0025 microcents per byte per hour" -- and the prose, the env var name (`ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR` vs the field `MicrocentsPerBytePerHour`), and the worked examples need to be reconciled to one canonical unit.

### 3. The env var name and the internal field disagree

`ARKFILE_BILLING_RATE_MICROCENTS_PER_GB_HOUR` (config) vs `Rate.MicrocentsPerBytePerHour` (Go struct). The doc says "divide by 1024^3 at startup" but doesn't show that conversion in `ResolveRate`. This needs to be explicit in the design (and tested), because GB vs GiB ambiguity in config (decimal 10^9 vs binary 2^30) is a classic source of off-by-7% bugs in storage code. The rest of the doc uses TiB = 2^40, so the env var should probably be `..._PER_GIB_PER_HOUR` to match.

### 4. The "30 days/month" convention has a worse problem than the doc admits

The doc admits ~3% variance month-to-month from the 30-day convention, and dismisses it as standard cloud-billing practice. But there's a sharper issue: the **scheduler ticks hourly indefinitely**, while the **rate is denominated in months**. If the operator sets `$20/TiB/month` literally, then over the course of a year the user is billed:

- 8,760 hours × per-hour-rate
- = 8,760 × ($20/720) = $243.33/TiB/year (if 720 hr/mo conversion)
- vs the "expected" $240/TiB/year ($20 × 12) -- 1.4% over

That is fine and the doc is right to dismiss it. But the **per-month transaction display** (e.g., "your cost: $0.0197/month") is computed by scaling the hourly rate × 720, which is consistently *under* what the user will actually be billed in 31-day months. Users may notice the ~3% discrepancy and report it as a bug. Worth having the UI display "approximately" or "~$0.02/month" rather than four-decimal precision on a quantity that's intrinsically only 3%-accurate.

### 5. The "balance exhausted but uploads continue" UX is confusing for Phase 1

Section "Frontend Surface Changes" specifies:

> Your credits ran out and additional usage is being recorded.
> No action is needed right now -- file uploads continue to work as long as you stay under your account's storage limit.

This is technically correct for Phase 1 but invites real user confusion: "If no action is needed and uploads work, what does the deficit number even mean?" The doc itself acknowledges this ("the deficit column is informational, not actionable") but the UX text doesn't successfully resolve it. In a beta context with a small known user set this is probably fine; in a wider rollout it would prompt support tickets. Consider whether the deficit display should be admin-only in Phase 1, with users just seeing "$0.0000 -- you are within the free baseline" or "currently in beta, no charges occur" until the payments work clarifies semantics.

### 6. Privacy concern: persistent per-day storage history is a new disclosure

The doc honestly flags this in trade-off section as "not a new fundamental disclosure -- just a longer-retained version of an existing one." But that framing understates it slightly:

- `users.total_storage_bytes` today is **current state only**. A passive observer with DB access at time T learns the user's storage at time T -- nothing about T-1, T-2, etc.
- The new `credit_transactions` rows with `metadata.avg_billable_bytes` create a **persistent, indexed time series** of every user's storage trajectory. A subpoena, breach, or rogue admin in year 5 learns the user's daily storage history for years 1-5.

For a privacy-first app this is a meaningful escalation in passive-disclosure surface, even if the data is "already known" in the moment. The doc's mitigation suggestion (omit `avg_billable_bytes` from metadata, keep only the drained amount) is the right one and I would push for adopting it as the default rather than deferring. The drained-microcents field alone is enough for billing reconciliation; reconstructing storage history from it is much harder. If historical reconciliation is needed, an operator-only opt-in could be added later.

This is the single most important AGENTS.md-aligned change I would suggest to the design.

### 7. Migration strategy explicitly relies on Item 8 not existing yet

The doc's wipe-and-redeploy migration is justified by greenfield posture, but the doc itself says "before any payment-provider work begins, Item 8 from `general-enhancements.md` should be implemented as a prerequisite." If the operator does not actually implement Item 8 before payments work, this whole document silently becomes a future migration headache. Worth a stronger word: this should be enforcement-gated, not advisory. Consider adding a check or at least a CHANGELOG note.

### 8. The scheduler's "not wall-clock-aligned" choice has a real downside in audit reasoning

The doc justifies non-wall-clock-aligned ticks with "log timestamps slightly less predictable." The bigger issue is that operator audit reasoning ("at 03:00 UTC, every user with X bytes should have been ticked") becomes harder. After several restarts the tick offset drifts and there's no single time-of-day the operator can predict. Wall-clock alignment is roughly 10 lines of `time.Sleep` to the next top-of-hour and is worth doing in v1; deferring it to "future enhancement" trades a small amount of code now for a recurring source of "why did X tick at 14:23 today" confusion later.

### 9. SweepSummary "users in deficit" is computed per-sweep, not cumulative

`SweepSummary` carries `count of users who hit deficit` -- the doc means "users newly clamped to zero in this sweep." The 30-day rollup endpoint (`/api/admin/billing/sweep-summary`) shows "users_in_deficit" per day. The risk is misinterpretation: a user who is in deficit on day 1 may also be in deficit on day 2-30, so summing the daily counts double-counts the same user 30 times. The endpoint result and the CLI need to clearly say "newly hit deficit on this day" vs "total currently in deficit" (which is queried separately via `arkfile-admin billing list-deficits`). Currently the doc is ambiguous.

### 10. Concurrent restart + tick race not addressed

If the operator runs `prod-update.sh` (the doc lists this as the post-code-change tool), the scheduler in the old binary stops, the new binary starts a new scheduler, and depending on timing a tick may fire twice within a few seconds (or not at all for the displaced hour). The accumulator's `ON CONFLICT DO UPDATE SET unbilled_microcents = ... + excluded.unbilled_microcents` correctly accumulates, so a double-tick double-charges the user briefly. Probably under-the-noise-floor in practice, but worth mentioning explicitly: the meter is "at least once" for ticks during restarts, not "exactly once."

### 11. `arkfile-admin billing tick-now` is dev/test only, but the design language is loose

The doc says "Only available when `ADMIN_DEV_TEST_API_ENABLED=true`." This is the right gating, but the doc doesn't specify *where* the gating is enforced -- handler-side or CLI-side or both. Should be both: handler returns 403 if dev/test API disabled, CLI checks before sending. Otherwise a misconfigured admin CLI hitting a production server could surprise everyone.

---

## Minor Items

- The doc at one point says "The default markup multiplier is **proposed at 1.43**" then in the example uses `(1.43 × $13.99 = $20.00)` -- actually `1.43 × 13.99 = 20.005`, which rounds to $20.01, not $20.00. Not a bug, just slightly imprecise.

- "Estimated runway: ~25,431 hours (~2.9 years)" -- 25,431 / 8760 ≈ 2.9 years checks out.

- The Section 1 example "lasts approximately 18 years" claim (gift $5 ÷ usage $0.0197/month ≈ 254 months ≈ 21 years) doesn't match precisely -- minor numeric inconsistency between the API example ($0.0197/month with $5 = 21yr) and the prose ("18 years").

- The doc references "PayPerQ" in passing (the optional banner pattern). Worth a brief footnote explaining what PayPerQ is, or removing the reference, to make the doc self-contained.

- The doc says in section "What Already Exists": `models/credits.go` includes `FormatCreditsUSD` and `ParseCreditsFromUSD`. I confirmed these exist. Good accuracy.

- The mention of "no enum constraint exists in the schema; this is a documentation/code-side change" for adding `usage` and `gift` transaction types is correct (I checked the schema; `transaction_type` is just `TEXT NOT NULL`).

---

## Recommendations Before Switching to Act Mode

In rough priority order:

1. **Resolve the units bug** (#2, #3): pick one canonical internal unit (microcents/byte/hour or microcents/GiB/hour), fix the worked examples, fix the env var name, and re-derive the fallback constant from first principles. This is the only thing in the doc that I think is actually *wrong* rather than just a judgment call.

2. **Make `avg_billable_bytes` exclusion the default** (#6): change the metadata-content design so daily-summary rows do not embed billable-bytes history. Reconciliation can be done from the accumulator + drained amount.

3. **Wall-clock-align the scheduler** (#8): trivial code, removes a recurring confusion source.

4. **Soften the "deficit but uploads work" UX** (#5): make the deficit display admin-only or wrap it in an explicit "Beta preview" banner.

5. **Verify `e2e-test.sh` exists** (#1) or correct the references.

6. **Disambiguate "users_in_deficit" semantics** (#9) in the API response and CLI output.

If you'd like, I can also: do a deeper dive into the `storage_providers` schema to confirm the `role` column accepts `'tertiary'` exactly as the doc claims; verify that the `is_approved`/admin filtering in `models/user.go` matches the meter's "active user" definition; or check that the existing admin handlers' authorization pattern matches what the new `/api/admin/billing/*` routes will inherit.

---