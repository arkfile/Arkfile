# Slice E — API / Authz / Admin / Billing

Author: in-depth security review per `docs/wip/idsrp.md` §8 (backend authz & object storage), §10 (API security), §14 (logging/telemetry hygiene), §22.3 (per-endpoint TOTP gating).
Plan reference: `docs/wip/review/00-plan.md` §4 Slice E.

## 0. Scope

### `idsrp.md` sections covered here
- §8 Backend Authorization & Object Storage — the admin / billing / misc surface only; file blob authz already covered in Slice C, share authz in Slice D.
- §10 API Security — admin / billing / misc endpoints registered in `handlers/route_config.go`.
- §14 Logging/Telemetry hygiene — admin, billing, credits, export, contact-info, health-monitoring code paths only.
- §22.3 TOTP-gated route verification at the API surface, with a mandatory `TOTP-gated?` column in §3.1.

### `idsrp.md` sections deferred to other slices
- §4 OPAQUE / TOTP / JWT internals → Slice A.
- §5 Argon2id / §6 file encryption / §16 key hierarchy → Slice B.
- §6 (cont.) chunked upload/download → Slice C.
- §7 sharing → Slice D.
- §3 (WASM, frontend), §12 (XSS), §13 (supply chain), §15 (deployment) → Slice F.

### Files actually read for this slice
- `handlers/route_config.go` (entire) — route registration ground truth.
- `handlers/middleware.go` (entire) — `AdminMiddleware`, `RequireApproved`, `RequireTOTP`, `RateLimitMiddleware`, `TimingProtectionMiddleware`, `TLSVersionCheck`, `PrivacyRequestLogger`.
- `handlers/admin.go` (entire 1429 LOC) — user management, system status, security events, file/share inspection.
- `handlers/admin_auth.go` (entire) — admin OPAQUE handshake (read for completeness; canonical analysis in Slice A).
- `handlers/admin_billing.go` (entire) — billing-price, gift, sweep-summary, overdrawn, tick-now (dev/test).
- `handlers/admin_storage.go` (entire 891 LOC) — multi-backend storage management, role swaps, copy/verify task submission.
- `handlers/admin_task_runner.go` (entire) — background copy/verify task lifecycle.
- `handlers/credits.go`, `handlers/billing_projection.go` — user/admin credit views and projection seams.
- `handlers/export.go` (entire) — `.arkbackup` export endpoint family.
- `handlers/contact_info.go` — user contact-info CRUD and admin read.
- `handlers/config.go` — public config endpoints (argon2/password/chunking/version).
- `handlers/rate_limiting.go` — share + auth rate-limit ladder and `share_access_attempts` table reuse.
- `handlers/flood_guard.go` — in-memory 401/404 flood detector wired globally in `main.go`.
- `handlers/handlers.go`, `handlers/response.go`, `handlers/error_pages.go` — small helpers.
- `billing/types.go`, `billing/rates.go`, `billing/meter.go`, `billing/sweep.go`, `billing/scheduler.go`, `billing/gift.go` — billing math, scheduler, ledger writes.
- `models/credits.go` — credits ledger model, `FormatCreditsUSD` / `ParseCreditsFromUSD`.
- `models/admin_task.go` — admin_tasks CRUD.
- `database/unified_schema.sql` (entire) — schema-level authz: FK / ON DELETE / UNIQUE / indices.
- `logging/security_events.go` — security event logger and sanitizer.
- `monitoring/health_endpoints.go` — `HealthMonitor`, public `/healthz` / `/readyz` registered from `main.go`.
- `main.go` (selected sections) — `/healthz`, `/readyz`, billing scheduler wiring, FloodGuard wiring, dev-admin auto-create.

### Out-of-scope for this slice (one-line each)
- TOTP middleware *internal* correctness (constant-time compare, time-step, lockout state, two-tier JWT model) — **Slice A** owns this.
- Admin OPAQUE handshake correctness — **Slice A**.
- Argon2id parameter trust on `/api/config/argon2` — covered in **Slice B** finding B-19.
- Frontend / CSP / dependency pinning / Caddy / systemd / build supply chain — **Slice F**.
- `_test.go` content review beyond presence/absence — testing-gap items go to §6.

---

## 1. Architecture & Data-Flow Summary (for this slice)

### 1.1 Route registration & middleware stack

`handlers/route_config.go` registers everything against one of three middleware contexts:

```
Echo (global)
 └── CSPMiddleware (main.go)                  : sets CSP, X-Frame-Options, etc. (Slice F)
 └── PrivacyRequestLogger (handlers)          : logs entityID + method + URI + status (no IP)
 └── FloodGuardMiddleware (handlers)          : in-memory 401/404 flood detector, GLOBAL
 └── public routes                            : /, /healthz, /readyz, /api/config/*, /api/version,
                                                /api/opaque/*, /api/admin/login/*, /api/bootstrap/*,
                                                /api/totp/* (with TOTPJWTMiddleware on /api/totp/* group),
                                                /api/refresh, /api/logout, /api/admin-contacts,
                                                /shared/:id, /api/public/shares/*, /api/files/:fileId/export

auth.Echo = Echo.Group("")
 │  + JWTMiddleware                           : verifies EdDSA JWT; rejects expired/invalid
 │  + TokenRevocationMiddleware               : per-jti revocation lookup
 │  + RequireApproved                         : user.is_approved OR user.is_admin
 │
 ├── /api/totp/status, /api/totp/reset        : full JWT only (no TOTP gate — by design, lets a user
 │                                              reset/check status after a partial state)
 └── totpProtectedGroup = auth.Echo.Group("")
     │ + RequireTOTP                          : user.totp_enabled == true
     │
     ├── /api/files/**                        : Slice C
     ├── /api/uploads/**                      : Slice C
     ├── /api/shares (authz endpoints)        : Slice D
     ├── /api/files/:fileId/envelope          : Slice D adjacent
     ├── /api/files/:fileId/export-token      : minted here, used on public ExportFile
     ├── /api/credits                         : THIS SLICE
     └── /api/revoke-token, /api/revoke-all   : THIS SLICE

pendingAllowedGroup = Echo.Group("")          : intentionally OMITS RequireApproved
 + JWTMiddleware
 + TokenRevocationMiddleware
 + RequireTOTP
 ├── /api/user/contact-info (GET/PUT/DELETE)

adminGroup = Echo.Group("/api/admin")
 + JWTMiddleware
 + AdminMiddleware                            : localhost-only + admin-flag + rate-limit + audit-log.
                                                NOTE: does NOT include RequireTOTP. See E-01.
 ├── /credits, /credits/:username
 ├── /users[/...]/*                           : approve, status, storage, revoke, delete, update, force-logout
 ├── /users/:u/files, /users/:u/shares
 ├── /users/:u/contact-info
 ├── /files/:fileId (DELETE), /files/:fileId/export, /shares/:shareId/revoke
 ├── /system/status, /system/health, /security/events
 ├── /storage/**                              : status, sync-status, copy-all/-user-files/-file,
 │                                              task/:taskId, cancel-task/:taskId,
 │                                              set-primary, set-secondary, set-tertiary, swap-providers,
 │                                              verify-storage, set-cost, verify-all,
 │                                              alerts/summary
 └── /billing/**                              : price (GET/SET), sweep-summary, overdrawn, gift

devTestAdminGroup = Echo.Group("/api/admin/dev-test")  : gated by ADMIN_DEV_TEST_API_ENABLED
 + JWTMiddleware + AdminMiddleware
 ├── /users/cleanup                           : wipe rows for one username across many tables
 ├── /totp/decrypt-check/:username            : reveals TOTP presence/decryptability
 └── /billing/tick-now                        : forces an immediate tick (and optional sweep)
```

### 1.2 Admin authz model

Three gates layered, in order, before any admin handler runs:

1. `AdminMiddleware` (handlers/middleware.go:559-629):
   1. **Localhost-only** by raw `c.RealIP()` check (`isLocalhostIP`).
   2. Composite EntityID (HMAC of IP + UA) used for rate limit + audit logging.
   3. Per-EntityID rate limit: 10 req/min keyed on `"/api/admin"` (NOT per route).
   4. JWT presence (`auth.GetUsernameFromToken(c) != ""`).
   5. DB lookup → `user.HasAdminPrivileges()`.
   6. Block `arkfile-dev-admin` in production (`utils.IsDevAdminAccount`).
   7. Audit log via `logging.LogSecurityEvent(EventAdminAccess, …)` with no IP.

2. Many admin handlers repeat their own admin check inline (`if !user.IsAdmin`) — defense-in-depth duplication that is mostly fine but inconsistent (see E-13).

3. `admin_billing.go` introduces local helpers `requireAdmin` / `requireAdminWithUsername` (lines 324-353) that only check `IsAdmin`, *not* localhost or dev-admin-in-production. They rely on `AdminMiddleware` for those checks. As long as the route is registered under `adminGroup`, this is safe today; **the helper is a footgun for any future caller** outside `adminGroup`.

### 1.3 Billing data flow

```
admin SetPrice ─┐
               ▼
       billing_settings (key='customer_price_usd_per_tb_per_month')
               │
               ▼
       billing.ResolveRate ──► atomic.Pointer[Rate] cache (SetCachedRate)
               │
               ▼
       Scheduler.Run (main.go startBillingScheduler)
               │
               ├─ every TickInterval (default 1h, aligned to UTC top-of-hour):
               │   └── billing.TickAllActiveUsers
               │       └── billing.TickUser (per user)
               │           billable = max(0, users.total_storage_bytes - cfg.FreeBaselineBytes)
               │           charge   = (billable * rate.MicrocentsPerGiBPerHour) >> 30     [int64 truncation]
               │           UPSERT storage_usage_accumulator (username PK)
               │             unbilled_microcents += charge
               │
               └─ once per day at cfg.SweepAtUTC (default 00:15 UTC):
                   └── billing.SweepAllUsers
                       └── settleOneUser (per user, in its own DB transaction):
                           read user_credits.balance  ── NOTE: read uses db, not tx (E-08)
                           new_balance = balance - drained
                           UPDATE user_credits
                           INSERT credit_transactions (type='usage', metadata=privacy-minimal JSON)
                           UPDATE storage_usage_accumulator SET unbilled=0, last_billed_at=now

admin GiftCredits ─► billing.GiftCredits (in single tx)
                     read user_credits via tx, add amount, write tx row (type='gift')

POST /api/admin/billing/tick-now (dev/test) ─► forces an immediate tick + optional sweep.
```

The handler-side projection (`/api/credits`, `/api/admin/credits[/...]`) recomputes the same math on the fly through `handlers/billing_projection.go` using the same cached rate and a separate read of `users.total_storage_bytes`.

---

## 2. Findings

Numbering is contiguous in this slice (`E-NN`). Severity per `idsrp.md` §18 with the §3 (Slice E goals) "blocker for payment-processor wiring" tag where appropriate. Every finding cites file:line.

### Finding E-01: Admin route group is not wired through `RequireTOTP`

- Severity: **Medium**
- Confidence: **High**
- Category: authorization / TOTP-enforcement
- Component: `handlers/route_config.go`, `handlers/middleware.go`, `handlers/admin_auth.go`
- Affected files/functions: `handlers/route_config.go:166-168`; `handlers/middleware.go:559-629` (`AdminMiddleware`); cross-ref `handlers/admin_auth.go:189-211` (`AdminOpaqueAuthFinalize`).
- Description: `adminGroup` is constructed as `Echo.Group("/api/admin")` with `auth.JWTMiddleware()` + `AdminMiddleware`. `AdminMiddleware` enforces localhost-only, rate limiting, audit logging, and `user.HasAdminPrivileges()` — but **does not** include `RequireTOTP` nor check any `totp_verified=true` claim on the JWT. By contrast, `totpProtectedGroup` for regular-user routes explicitly layers `RequireTOTP` on top of JWT (`route_config.go:95-96`).

  In practice today this is **partially mitigated** because `AdminOpaqueAuthFinalize` (`admin_auth.go:189-193`) refuses to issue any auth artifact unless the admin already has TOTP enabled, and it returns only a *temp* token from `auth.GenerateTemporaryTOTPToken`. Slice A is the authoritative review of that two-tier flow and whether a temp token is rejected by every protected route.
- Evidence:
  ```
  // handlers/route_config.go:166-168
  adminGroup := Echo.Group("/api/admin")
  adminGroup.Use(auth.JWTMiddleware()) // Add JWT middleware first
  adminGroup.Use(AdminMiddleware)      // Then admin middleware
  ```
  ```
  // handlers/middleware.go:559-629 — no RequireTOTP, no totp_verified claim check
  func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc { ... }
  ```
- Attack scenario:
  1. An attacker who has obtained an admin's *non-TOTP* JWT (e.g. via XSS, exfiltration of a refresh-token-derived JWT minted by a code path that skips TOTP, or via a future bug in the two-tier model audited in Slice A) can call every `/api/admin/**` endpoint from localhost.
  2. The chokepoint that `idsrp.md` §22.3 demands (every protected route must be TOTP-gated at the API surface) is enforced by the admin login *path*, not by the admin route *group*. Any future code change that mints a non-TOTP-verified JWT for an admin would silently expose the admin surface.
- Impact: defense-in-depth gap. With the current admin-login finalize logic and the Slice A audit, no exploit path is known today. Severity Medium and not High because the temp token issued by `AdminOpaqueAuthFinalize` is not a normal JWT; Slice A confirms whether it is rejected by `JWTMiddleware` here.
- Recommendation:
  1. Wrap `adminGroup` with `RequireTOTP` immediately, mirroring `totpProtectedGroup`. This adds one DB read per admin request (already paid by `AdminMiddleware`'s `GetUserByUsername`).
  2. Refactor `AdminMiddleware` to read user record once and pass it through context, so the extra TOTP check costs nothing.
  3. Add a per-route `TOTP-gated?` column to internal route docs and enforce in a CI test that parses `route_config.go`.
- Suggested tests:
  - Negative test: synthesize a JWT with `totp_verified=false` (or whatever the two-tier model emits) and confirm every `/api/admin/**` route returns 403.
  - Negative test: replay a temp token (`audience=arkfile-totp`) against `/api/admin/users` and confirm 401/403.
- Cross-refs: Slice A finding(s) on two-tier JWT model and temp-token acceptance.

---

### Finding E-02: SQL injection via interpolated `provider_id` in `AdminSyncStatus`

- Severity: **High**
- Confidence: **High**
- Category: authorization / injection
- Component: `handlers/admin_storage.go`
- Affected files/functions: `handlers/admin_storage.go:188-295` (`AdminSyncStatus`); specifically the `activeOn` / `notActiveOn` closures at `admin_storage.go:200-205` and the `database.DB.QueryRow(... + p + ...)` calls at `admin_storage.go:213-235`.
- Description: `AdminSyncStatus` builds SQL fragments by interpolating provider IDs into the query string via `fmt.Sprintf`:
  ```go
  activeOn := func(providerID string) string {
      return fmt.Sprintf("EXISTS (SELECT 1 FROM file_storage_locations fsl WHERE fsl.file_id = fm.file_id AND fsl.provider_id = '%s' AND fsl.status = 'active')", providerID)
  }
  ```
  These fragments are then concatenated into the WHERE clause and executed via `database.DB.QueryRow("SELECT COUNT(*) FROM file_metadata fm WHERE " + p + ...)`.

  The `providerID` value comes from `storage.Registry.PrimaryID()` / `SecondaryID()` / `TertiaryID()`, which in turn read the `provider_id` column from the `storage_providers` table. **`storage_providers.provider_id` is admin-controlled** — admin storage management endpoints (e.g. `AdminSetCost`, the migration paths that insert provider rows) accept `provider_id` from JSON body and write it to the table without sanitization beyond the empty check. An admin who can write provider rows can plant a malicious `provider_id` containing `' OR 1=1 --` etc.

  This is technically "admin-injects-into-admin-endpoint" so the privilege escalation is bounded — but it lets an admin produce arbitrary read/exec on the rqlite cluster from a counted endpoint, bypassing the schema-level controls and the audit trail.

- Evidence:
  ```
  // handlers/admin_storage.go:200-205
  activeOn := func(providerID string) string {
      return fmt.Sprintf("EXISTS (SELECT 1 FROM file_storage_locations fsl WHERE fsl.file_id = fm.file_id AND fsl.provider_id = '%s' AND fsl.status = 'active')", providerID)
  }
  notActiveOn := func(providerID string) string {
      return fmt.Sprintf("NOT EXISTS (SELECT 1 FROM file_storage_locations fsl WHERE fsl.file_id = fm.file_id AND fsl.provider_id = '%s' AND fsl.status = 'active')", providerID)
  }
  ```
  ```
  // handlers/admin_storage.go:213-216
  q := func(p, s, t string) int64 {
      var count int64
      database.DB.QueryRow("SELECT COUNT(*) FROM file_metadata fm WHERE " + p + " AND " + s + " AND " + t).Scan(&count)
      return count
  }
  ```
- Attack scenario:
  1. Admin (or anyone who has compromised one admin account) writes a `storage_providers` row with `provider_id = "x' OR 1=1 --"` via any insert path. (The codebase currently inserts providers via deploy scripts and `models/storage_provider.go`, not from an API; this is the bounded path.)
  2. Admin calls `GET /api/admin/storage/sync-status` and rqlite executes the injected SQL.
  3. Depending on rqlite's exact SQL grammar, the admin gets back rows revealing all `file_metadata`, or worse if multi-statement is enabled.
- Impact: bypass of the schema-level read pattern and corruption of the count-based dashboard. Limited to admin-from-admin today, but if a future endpoint accepts `provider_id` from a non-admin request (e.g. a guard against typos in the operator UI) the same SQL fragment becomes a generic SQLi sink.
- Recommendation:
  1. Replace string interpolation with parameterized queries. Build a single SELECT with placeholders:
     ```sql
     SELECT
       SUM(CASE WHEN EXISTS (SELECT 1 FROM file_storage_locations fsl WHERE fsl.file_id = fm.file_id AND fsl.provider_id = ? AND fsl.status='active') THEN 1 ELSE 0 END) AS on_primary,
       ...
     FROM file_metadata fm
     ```
     and pass `primaryID, secondaryID, tertiaryID` as arguments.
  2. Add a schema CHECK constraint or migration-time validator on `storage_providers.provider_id` that rejects anything outside `[a-zA-Z0-9_-]`.
  3. Adopt a linter rule banning `fmt.Sprintf` into SQL strings.
- Suggested tests:
  - Negative test: insert a provider with `provider_id = "x' AND 1=1 --"` and confirm `AdminSyncStatus` returns an error instead of running the injected SQL.
  - Code-pattern test: grep for `fmt.Sprintf` in `*.go` files containing `SELECT`/`WHERE` and fail CI on matches.

---

### Finding E-03: `settleOneUser` reads `user_credits.balance` outside the transaction; sweep + concurrent gift race

- Severity: **High** (transitions to Critical once a payment processor is wired)
- Confidence: **High**
- Category: design / billing-correctness / **blocker for payment-processor wiring**
- Component: `billing/sweep.go`
- Affected files/functions: `billing/sweep.go:91-171` (`settleOneUser`), specifically the read at `sweep.go:100-105`.
- Description: `settleOneUser` opens a transaction `tx` at line 92, then reads the current balance from `user_credits` at line 100-105 using **`db.QueryRow`** instead of `tx.QueryRow`. The subsequent UPDATE on `user_credits` (lines 122-126) uses `tx.Exec`. Between the unscoped read and the scoped write, another concurrent operation (a parallel sweep iteration on a different process replica, or a concurrent `billing.GiftCredits`) can change the balance, and the UPDATE will clobber the intervening change because it writes the absolute new value computed from a stale read.

  Even on a single rqlite leader, the read-outside-tx pattern means the new_balance written here is **not bound to a snapshot of the row being modified**. Under contention the visible balance will exhibit lost-update behavior: gift + sweep at the same wall-clock instant deletes the gift.

- Evidence:
  ```
  // billing/sweep.go:91-130 (excerpt)
  func settleOneUser(db *sql.DB, rate *Rate, now time.Time, username string, drainedMicrocents int64, lastBilledAt sql.NullString) (int64, error) {
      tx, err := db.Begin()
      if err != nil { return 0, fmt.Errorf("begin tx: %w", err) }
      defer tx.Rollback()

      // Step 1: ensure a user_credits row exists ...
      var currentBalanceF float64
      err = db.QueryRow(                                      // <-- READS OUTSIDE tx
          `SELECT balance_usd_microcents FROM user_credits WHERE username = ?`,
          username,
      ).Scan(&currentBalanceF)
      ...
      // Step 2 + 3: compute and persist the new (signed) balance.
      newBalance := currentBalance - drainedMicrocents
      _, err = tx.Exec(                                       // <-- writes inside tx
          `UPDATE user_credits SET balance_usd_microcents = ?, updated_at = CURRENT_TIMESTAMP
           WHERE username = ?`,
          newBalance, username,
      )
  ```
  Compare with `billing/gift.go:51-79` which correctly does `tx.QueryRow` + `tx.Exec`.
- Attack scenario:
  1. Admin runs `POST /api/admin/billing/gift target=alice amount=$5` at 00:14:59 UTC.
  2. Daily sweep fires at 00:15:00 UTC. `settleOneUser` for alice reads the balance from before the gift commits (read uses `db`, no snapshot).
  3. The sweep's UPDATE writes `pre_gift_balance − drained`. Alice loses the $5 gift.
  4. `credit_transactions` row for the gift exists (it was its own committed tx), but `user_credits.balance` no longer reflects it; the audit trail and the live balance diverge.
- Impact: Today this is a billing-correctness bug. Once paid top-ups exist (Stripe/crypto/ACH), the same race silently deletes paid balance and the gap becomes visible only to ledger-vs-balance reconciliation. Flag as **"blocker for payment-processor wiring"**.
- Recommendation:
  1. Change the read to `tx.QueryRow` so it shares the transaction's snapshot/locks with the UPDATE.
  2. Better: replace the read-modify-write with a single atomic UPDATE:
     ```sql
     UPDATE user_credits
        SET balance_usd_microcents = balance_usd_microcents - ?,
            updated_at = CURRENT_TIMESTAMP
      WHERE username = ?
     RETURNING balance_usd_microcents;
     ```
     rqlite supports RETURNING. Then write the `credit_transactions` row using the returned new balance.
  3. Add an integration test that interleaves a `GiftCredits` and a `settleOneUser` against the same user and asserts the final balance equals `initial - drained + gift`.
- Suggested tests:
  - Race test: spawn N goroutines, half calling `GiftCredits(alice, +5_000_000)` and half calling `settleOneUser(alice, drained=2_000_000)` simultaneously, verify final balance is deterministic given the inputs.
  - Property test: invariant `sum(credit_transactions.amount) == user_credits.balance` always holds.
- Cross-refs: E-04 (idempotency), E-21 (audit-trail cascade).

---

### Finding E-04: No idempotency key on `credit_transactions`; gift/usage rows can be duplicated under retry

- Severity: **Medium** (Critical once paid top-ups exist)
- Confidence: **High**
- Category: billing-correctness / **blocker for payment-processor wiring**
- Component: `models/credits.go`, `billing/gift.go`, `billing/sweep.go`, `database/unified_schema.sql`
- Affected files/functions:
  - `database/unified_schema.sql:357-369` (`credit_transactions` schema, `transaction_id` column exists but is NOT UNIQUE),
  - `billing/gift.go:81-91` (gift insert, no transaction_id),
  - `billing/sweep.go:145-154` (usage insert, no transaction_id).
- Description: The `credit_transactions` table reserves a `transaction_id TEXT` column for "External transaction ID, reserved for future payments work" (`unified_schema.sql:359`). However:
  1. The column has **no UNIQUE constraint**.
  2. Neither `GiftCredits` nor `settleOneUser` populates it.
  3. There is no application-side dedup before insert.

  Consequences today:
  - A retried admin `gift` call (e.g. operator clicks twice, or the LB retries on 5xx) will create two `gift` rows and double-credit the user.
  - The sweep's `settleOneUser` does not key on (username, day) so a process-level double-sweep (E-05) would produce two `usage` rows for the same day.

  Consequences once paid top-ups exist:
  - Stripe/crypto/ACH webhooks fire idempotency keys to avoid double-charging on retry. Without a UNIQUE `transaction_id` column, a webhook retry credits the user twice.

- Evidence:
  ```
  // database/unified_schema.sql:357-369
  CREATE TABLE IF NOT EXISTS credit_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      transaction_id TEXT,                              -- External transaction ID, reserved for future payments work
      username TEXT NOT NULL,
      amount_usd_microcents BIGINT NOT NULL,
      ...
  );
  ```
  (No `UNIQUE(transaction_id)`; no `CREATE UNIQUE INDEX` on transaction_id; only a non-unique index at `unified_schema.sql:546`.)
  ```
  // billing/gift.go:81-91 — no transaction_id passed
  res, err := tx.Exec(`
      INSERT INTO credit_transactions
        (username, amount_usd_microcents, balance_after_usd_microcents,
         transaction_type, reason, admin_username, created_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      username, amountUSDMicrocents, newBalance, models.TransactionTypeGift, reason, adminUsername,
  )
  ```
- Attack scenario:
  1. Operator runs `arkfile-admin billing gift alice 5.00 "loyalty bonus"`.
  2. Network blip; CLI retries the same request.
  3. Two `gift` rows are committed (each in its own `GiftCredits` transaction). Alice receives $10.
  4. Same pattern under payment-processor webhooks: Stripe sends `payment_intent.succeeded` twice (it does, by design). Two top-up rows; double credit.
- Impact: silent overpayment. Reconciliation between `credit_transactions` ledger and external processor records becomes ambiguous.
- Recommendation:
  1. Add `UNIQUE(transaction_id)` to `credit_transactions` and migrate existing rows to NULL (which is allowed under UNIQUE in SQLite).
  2. In `GiftCredits`, accept an `idempotency_key` parameter; require it from the admin API; pass through as `transaction_id`. Reject inserts where `transaction_id` already exists with a 409.
  3. In `settleOneUser`, derive a deterministic key like `"usage:" + username + ":" + date.Format("2006-01-02")` so a double-sweep collides on insert rather than producing two rows.
  4. Add a `CHECK(transaction_type IN ('usage','gift','adjustment', …paid_*))` constraint to lock down the type column.
- Suggested tests:
  - Duplicate-gift test: two parallel `POST /api/admin/billing/gift` with the same body; assert one succeeds and one returns 409.
  - Duplicate-sweep test: invoke `SweepAllUsers` twice in a row at the same instant (after seeding fresh accumulator); assert no duplicate `usage` row.
- Cross-refs: E-03 (race), E-05 (double-sweep), E-21 (audit-trail cascade).

---

### Finding E-05: Process-local `lastSweepDate` allows duplicate daily sweep across restarts

- Severity: **Medium** (Critical once paid top-ups exist)
- Confidence: **High**
- Category: billing-correctness / **blocker for payment-processor wiring**
- Component: `billing/scheduler.go`
- Affected files/functions: `billing/scheduler.go:87-138` (`Scheduler.Run`), `billing/scheduler.go:190-200` (`shouldRunSweep`).
- Description: `Scheduler.Run` tracks whether today's sweep has run via the local variable `lastSweepDate` (string of today's UTC date). On process restart, that variable resets to `""`, so the next tick that crosses today's sweep boundary will re-run the sweep even if a previous instance of the process already ran it earlier the same day.

  Today this is *mostly* benign because `SweepAllUsers` filters `WHERE unbilled_microcents > 0` (`sweep.go:34`). After the first sweep zeroes accumulators, the second sweep finds nothing for users with no ticks-since-first-sweep, so it is effectively a no-op for those users.

  But if any tick fires between the first sweep and the second (restart-triggered) sweep, those fresh accumulator values are settled as a *second* `usage` row for the same calendar day. Two `usage` rows per day was not the intended invariant.

- Evidence:
  ```
  // billing/scheduler.go:87
  lastSweepDate := ""
  ...
  // billing/scheduler.go:119-128
  todayDate := now.Format("2006-01-02")
  if shouldRunSweep(now, s.cfg.SweepAtUTC, lastSweepDate, todayDate) {
      summary, sweepErr := SweepAllUsers(s.db, rate, now)
      ...
      lastSweepDate = todayDate
      ...
  }
  ```
  `shouldRunSweep` only checks `lastSweepDate == todayDate` (`scheduler.go:191`); it never consults the DB for the actual most-recent sweep.
- Attack scenario:
  1. Sweep fires at 00:15 UTC and settles all users.
  2. Operator deploys an update at 01:00 UTC. Process restarts; `lastSweepDate = ""`.
  3. Next tick at 02:00 UTC. Between the first sweep and this restart, ticks have written fresh accumulator entries (one to two hours of usage). Scheduler now thinks the sweep hasn't run today and runs it again.
  4. A second `usage` row is inserted for every active user, charging them the 01:00-02:00 fractional hour as a full day's usage.
- Impact: small per-user financial gap today (one extra hour of usage settled as its own row); silent ledger anomaly. **Becomes Critical once paid top-ups exist** because operators reconciling against external processors will see a malformed ledger.
- Recommendation:
  1. Persist `last_sweep_at` in `billing_settings` (or a dedicated `billing_state` table) and consult it in `shouldRunSweep` so restart cannot resurrect a finished day.
  2. Combine with the per-row idempotency key from E-04 (`transaction_id = "usage:" + username + ":" + day`) so duplicate inserts collide regardless of scheduler state.
  3. Add a schema invariant test: "no two `usage` rows for the same `(username, date(created_at))`".
- Suggested tests:
  - Restart simulation: run a sweep, restart the scheduler (reset `lastSweepDate`), advance the clock by 1h, run a tick + sweep; assert at most one `usage` row exists for that day per user.
- Cross-refs: E-03, E-04, E-21.

---

### Finding E-06: `ParseCreditsFromUSD` accepts inputs that overflow int64 on multiplication

- Severity: **Medium**
- Confidence: **High**
- Category: billing-correctness / input-validation / **blocker for payment-processor wiring**
- Component: `models/credits.go`
- Affected files/functions: `models/credits.go:327-407` (`ParseCreditsFromUSD`), specifically line 402: `microcents := dollars*MicrocentsPerUSD + fractional*10_000`.
- Description: `ParseCreditsFromUSD` uses `fmt.Sscanf` with `%d` for the dollars part. `Sscanf` rejects values that exceed int64 max (`9_223_372_036_854_775_807`), so `"99999999999999999999.00"` returns an error. **But** values that fit in int64 yet overflow on the subsequent multiplication by `MicrocentsPerUSD = 100_000_000` are silently wrapped to negative numbers.

  The maximum safe dollar amount is `math.MaxInt64 / MicrocentsPerUSD = 92_233_720_368.547_758_07`, i.e. ~$92 billion. Any input larger than that produces an overflowed `microcents` value with no error.

  Today, `AdminBillingGift` (`handlers/admin_billing.go:200-272`) requires the admin to type the amount on the CLI, and the system is admin-only, so the practical exposure is low. **Once paid top-ups exist**, untrusted webhook payloads with attacker-controlled amounts hit this same parser.

- Evidence:
  ```
  // models/credits.go:395-407
  var fractional int64
  if padded != "" {
      _, err := fmt.Sscanf(padded, "%d", &fractional)
      if err != nil {
          return 0, fmt.Errorf("invalid fractional part: %w", err)
      }
  }

  // Each unit of `fractional` is 1/10_000 of a dollar = 10_000 microcents.
  microcents := dollars*MicrocentsPerUSD + fractional*10_000
  if negative {
      microcents = -microcents
  }
  return microcents, nil
  ```
  No overflow check after the multiplication or the addition.
- Attack scenario (post-payment-processor): Attacker submits an inflated value in a webhook payload that passes signature verification (e.g. via a processor misconfig); `ParseCreditsFromUSD` returns a negative `microcents` which `GiftCredits` rejects because `amountMicrocents <= 0` — but other paths (e.g. a refund path or a custom-currency convert path) may not have that guard.
- Impact: signed overflow silently produces negative or wrap-around values. Combined with any caller that skips the `<= 0` check, attacker-controlled balance manipulation.
- Recommendation:
  1. After computing `microcents = dollars*MicrocentsPerUSD + fractional*10_000`, check both:
     - `dollars > math.MaxInt64 / MicrocentsPerUSD` → error.
     - `microcents` did not overflow (use `math/bits.Mul64` for an explicit overflow detection).
  2. Cap accepted dollar amounts at a documented business maximum (e.g. $1B) and reject anything larger with a clear error.
  3. Add property tests covering boundary inputs: `MaxInt64 - 1`, `92_233_720_368.99`, `92_233_720_369.00`.
- Suggested tests:
  - `TestParseCreditsFromUSD_Overflow`: `ParseCreditsFromUSD("92233720369.00")` returns an error, not a negative value.
  - Fuzz test: random ASCII-digit strings up to 64 chars; assert either valid positive output or non-nil error.
- Cross-refs: E-07, E-04.

---

### Finding E-07: `billable * MicrocentsPerGiBPerHour` can overflow int64 in `TickUser`

- Severity: **Low** (Medium once free-baseline / storage-limit caps are removed)
- Confidence: **High**
- Category: billing-correctness
- Component: `billing/meter.go`, `handlers/billing_projection.go`
- Affected files/functions: `billing/meter.go:62` (`tickChargeMicrocents := (billable * rate.MicrocentsPerGiBPerHour) >> 30`); `handlers/billing_projection.go:46` (`hourlyMicrocents := (billable * rateMicrocentsPerGiBPerHour) >> 30`).
- Description: At the documented "representative rate" of 1,356 microcents/GiB/hour and a 64-bit signed `billable` (bytes), the multiplication `billable * rate` overflows int64 when `billable > 6.8e15 / 1356 ≈ 5_026_000 TB`. That's 5 EB, which is absurd for any single user.

  However, the formula is structurally fragile:
  1. There is no compile-time or runtime check that `billable` is bounded.
  2. The right-shift by 30 doesn't help — it only divides *after* the multiplication that may have already overflowed.
  3. If the rate is raised drastically (e.g. an operator typo: `$10000.00/TiB/month` instead of `$10.00`), the overflow ceiling drops by 1000×.

- Evidence:
  ```
  // billing/meter.go:56-63
  billable := totalStorageBytes - freeBaselineBytes
  if billable <= 0 { return nil }
  tickChargeMicrocents := (billable * rate.MicrocentsPerGiBPerHour) >> 30
  ```
- Attack scenario: not directly attacker-controllable today (storage usage is bounded by `users.storage_limit_bytes` and disk reality), but a misconfiguration in `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH` could push the rate into a range where realistic per-user storage triggers overflow.
- Impact: silent wrap-around to negative microcents written into the accumulator, which would later flip a user's balance positively when "drained" by the sweep.
- Recommendation:
  1. Use `math/bits.Mul64` for the multiplication, branch on overflow, and log + skip the tick (or settle at int64-max).
  2. Validate `MicrocentsPerGiBPerHour` against a sane maximum at `computeRate` time.
  3. Cap `total_storage_bytes` at the user's `storage_limit_bytes` before computing `billable`.
- Suggested tests:
  - Unit test with `billable = math.MaxInt64 / 2` and `rate = 4`; assert the function returns an error rather than a wrapped charge.
- Cross-refs: E-06.

---

### Finding E-08: `hoursPerMonth = 24 * 30 = 720` derives rates that are ~1.4% lower than the operator's stated USD-per-TB-per-month

- Severity: **Low**
- Confidence: **High**
- Category: design / billing accounting transparency
- Component: `billing/rates.go`
- Affected files/functions: `billing/rates.go:200-213` (`computeRate`), `billing/rates.go:182-184` (docstring).
- Description: `computeRate` divides the monthly customer price by `1024 * 720` to get microcents/GiB/hour. The "720" is documented as "30 days × 24 hours". Real average month length is ~730.5 hours, so a $10/TiB/month price is actually billed at $10 × (720 / 730.5) ≈ $9.86/TiB/month effective. The docstring acknowledges floor-rounding "so the derived rate never exceeds the operator's stated price" — but the chosen 720 systematically *under-bills* by ~1.4% which is a different invariant.

  Either choice is defensible; the issue is that the README and admin price endpoint surface the headline number ($10) without disclosing the 720-vs-730.5 mismatch. This is an honesty/transparency gap rather than a correctness bug.

- Evidence:
  ```
  // billing/rates.go:182-184
  // Math (floor-rounded so the derived rate never exceeds the operator's stated price):
  //   microcents_per_TiB_per_month = price_microcents
  //   microcents_per_GiB_per_hour  = floor(microcents_per_TiB_per_month / 1024 / 720)
  //                                                                 ^TiB->GiB ^days*hours
  ```
- Recommendation: document this explicitly in `docs/wip/storage-credits-v2.md` and in the admin price response. Alternative: switch to `730.5 * 2` half-hours / `730` rounded — pick one, document the trade-off.
- Suggested tests: golden-file test pinning the conversion for a representative table of prices, with a comment justifying the chosen denominator.

---

### Finding E-09: `AdminMiddleware` rate limit keys all admin routes under one bucket

- Severity: **Low**
- Confidence: **High**
- Category: rate-limiting / defense-in-depth
- Component: `handlers/middleware.go`
- Affected files/functions: `handlers/middleware.go:571-595`.
- Description: `AdminMiddleware` calls `DefaultRateLimitManager.CheckRateLimit(entityID, "/api/admin", 10, time.Minute)`. The endpoint key is a literal `"/api/admin"` for every admin route, so a single operator hitting `GET /api/admin/users` 5 times and `GET /api/admin/credits` 5 times will be rate-limited at the eleventh call regardless of which route.

  This is acceptable for protection against scanners but undersells the differentiated rate limits the per-route framework offers elsewhere (`LoginRateLimitMiddleware`, `TOTPRateLimitMiddleware`, etc.). It also makes operator UI tooling like the admin CLI's "list, then approve, then verify" workflows fragile against the global 10/min.

- Evidence:
  ```
  // handlers/middleware.go:571-580
  rateLimited, err := DefaultRateLimitManager.CheckRateLimit(
      entityID,
      "/api/admin",
      10, // 10 requests per minute
      time.Minute,
  )
  ```
- Recommendation: key the rate limit on `c.Request().URL.Path` (or on a normalized route prefix from `c.Path()`) rather than a constant.
- Suggested tests: send 20 alternating calls to two different admin routes; expect either both to be limited at 10 each (per-route) or all 20 to share a bucket — depending on which design you choose, but make the behavior explicit and tested.

---

### Finding E-10: `requireAdmin` / `requireAdminWithUsername` in `admin_billing.go` don't verify the request came through `AdminMiddleware`

- Severity: **Low**
- Confidence: **High**
- Category: design / authz-helpers
- Component: `handlers/admin_billing.go`
- Affected files/functions: `handlers/admin_billing.go:324-353`.
- Description: The local helpers `requireAdmin` and `requireAdminWithUsername` only check `auth.GetUsernameFromToken(c) != ""` and `user.IsAdmin == true`. They do not check localhost, do not check `IsDevAdminAccount`-in-production, and do not call `RequireTOTP`. They are safe today *because* every caller is registered under `adminGroup` which already runs `AdminMiddleware`. Any future caller that uses these helpers from a different group inherits a weaker admin check than the rest of the codebase.
- Evidence:
  ```
  // handlers/admin_billing.go:324-337
  func requireAdmin(c echo.Context) error {
      adminUsername := auth.GetUsernameFromToken(c)
      if adminUsername == "" {
          return JSONError(c, http.StatusUnauthorized, "Authentication required")
      }
      adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
      if err != nil { return JSONError(c, http.StatusInternalServerError, "Failed to get admin user") }
      if !adminUser.IsAdmin {
          return JSONError(c, http.StatusForbidden, "Admin privileges required")
      }
      return nil
  }
  ```
- Recommendation: either delete these helpers and rely on `AdminMiddleware` exclusively, or extend them to call `AdminMiddleware`'s checks (localhost, dev-admin-in-prod, rate limit, audit log) so they can be used outside `adminGroup` safely. Document the requirement at the function level.

---

### Finding E-11: `AdminCleanupTestUser` deletes the same `opaque_user_data` row twice via a typo'd cleanup list

- Severity: **Informational**
- Confidence: **High**
- Category: code hygiene / dev-test surface
- Component: `handlers/admin.go`
- Affected files/functions: `handlers/admin.go:139-140`.
- Description: The cleanup operations list in `AdminCleanupTestUser` includes `opaque_user_data` twice with identical SQL:
  ```
  {"opaque_user_data", "DELETE FROM opaque_user_data WHERE username = ?"},
  {"opaque_user_data", "DELETE FROM opaque_user_data WHERE username = ?"},
  ```
  This is harmless (the second DELETE is a no-op against an empty table) but the `tablesCleared` map key collision masks any future bug in this list. The endpoint is dev/test only so impact is low.
- Recommendation: delete one of the duplicate entries. Also delete the dead branch at `admin.go:153-158` that pretends to "handle tables that need different parameter patterns" but does nothing differently.

---

### Finding E-12: `AdminTOTPDecryptCheck` is admin-gated and dev-only, but its response can confirm TOTP-secret-decryptability for any user

- Severity: **Low**
- Confidence: **High**
- Category: privacy / debug-surface
- Component: `handlers/admin.go`
- Affected files/functions: `handlers/admin.go:206-271`, route registration at `handlers/route_config.go:239`.
- Description: `AdminTOTPDecryptCheck` returns `present` / `decryptable` / `enabled` / `setup_completed` for any user. It's gated by:
  1. `ADMIN_DEV_TEST_API_ENABLED=true` (registration time).
  2. `DEBUG_MODE=true` (handler-internal, line 208-211).
  3. `AdminMiddleware` (localhost + admin).

  All three are required, so production exposure is zero. The risk is operational: if any of those guards are misconfigured, the endpoint reveals which users have a working TOTP setup vs a broken one, which is enough to plan an attack.

- Recommendation: keep the three-guard model. Add a startup assertion that `ADMIN_DEV_TEST_API_ENABLED && !DEBUG_MODE` is rejected (it currently silently returns 404 from the handler, but the route is still registered).
- Cross-refs: Slice A on TOTP diagnostics.

---

### Finding E-13: Admin handlers inconsistently re-check `user.IsAdmin` after `AdminMiddleware`

- Severity: **Informational**
- Confidence: **High**
- Category: code hygiene / authz consistency
- Component: `handlers/admin.go`, `handlers/admin_billing.go`, `handlers/credits.go`
- Affected files/functions: many. Examples:
  - `handlers/admin.go:511-513` (`GetPendingUsers`),
  - `handlers/admin.go:533-535` (`DeleteUser`),
  - `handlers/admin.go:630-632` (`UpdateUser`),
  - `handlers/admin.go:862-864` (`UpdateUserStorageLimit`),
  - `handlers/credits.go:68-74` (`AdminGetUserCredits`),
  - `handlers/credits.go:145-151` (`AdminGetAllCredits`),
  vs. `handlers/admin_billing.go` which always uses `requireAdmin` and `handlers/admin_storage.go` which relies entirely on `AdminMiddleware`.
- Description: Defense-in-depth re-checks are fine, but the codebase mixes three styles:
  1. No re-check (storage handlers).
  2. Inline `if !user.IsAdmin` (admin.go, credits.go).
  3. Helper call `requireAdmin` (admin_billing.go).

  This makes it easy to forget a check when adding a new handler and easy to under-check when copy-pasting from the storage handlers.
- Recommendation: pick one style (the helper is cleanest) and migrate. Document in `handlers/admin.go` package doc that the helper is the *only* sanctioned inline check.

---

### Finding E-14: `AdminMiddleware` localhost gate trusts `c.RealIP()` which trusts forwarded headers

**STATUS: RESOLVED (2026-05-12)** as part of the F-01 fix. `AdminMiddleware` now calls `peerAddrIsLoopback(c)` instead of `parseIPAddress(c.RealIP())` + `isLocalhostIP(...)`; the helper reads `c.Request().RemoteAddr` and ignores `X-Forwarded-For` / `X-Real-IP` entirely. `main.go` additionally pins `e.IPExtractor = echo.ExtractIPDirect()`, and all four Caddyfile variants strip the spoofable headers and propagate the real client IP only in `X-Arkfile-Peer` (used by `publicClientIP` for EntityID/rate-limit binning, never for authz). Regression test `TestAdminMiddleware_RejectsForgedXFF` in `handlers/middleware_test.go` covers the gate. Full remediation record: `docs/wip/review/06-frontend-supply-ops.md` §F-01.

The original finding analysis (preserved below for the audit trail):

- Severity: **Medium**
- Confidence: **Medium**
- Category: authorization / deployment-dependent
- Component: `handlers/middleware.go`, dependent on Echo's `RealIP` configuration
- Affected files/functions: `handlers/middleware.go:561-566`.
- Description: `AdminMiddleware` does:
  ```
  clientIP := parseIPAddress(c.RealIP())
  if !isLocalhostIP(clientIP) {
      return echo.NewHTTPError(http.StatusForbidden, "Admin endpoints only available from localhost")
  }
  ```
  Echo's `c.RealIP()` walks `X-Forwarded-For` and `X-Real-IP` headers by default. If Arkfile is fronted by a reverse proxy that doesn't strip incoming `X-Forwarded-For` (Caddy by default *appends* rather than replaces — see Caddyfile review in Slice F), a client can send `X-Forwarded-For: 127.0.0.1` and the admin endpoint accepts the request.

  Whether this is exploitable depends on `Caddyfile.prod` and on whether `e.IPExtractor` is explicitly set to `echo.ExtractIPFromRealIPHeader` / `echo.ExtractIPDirect`. I did not read `main.go` for that line in this slice; if `e.IPExtractor` is unset (default), `c.RealIP()` *does* parse `X-Forwarded-For`.

- Evidence:
  ```
  // handlers/middleware.go:561-566
  clientIP := parseIPAddress(c.RealIP())
  if !isLocalhostIP(clientIP) {
      return echo.NewHTTPError(http.StatusForbidden, "Admin endpoints only available from localhost")
  }
  ```
- Attack scenario:
  1. Caddy reverse-proxies `arkfile.example.com` to the Go server on 127.0.0.1.
  2. Caddy appends `X-Forwarded-For: <real-client-ip>` to the request.
  3. An attacker sends `X-Forwarded-For: 127.0.0.1` from the public internet. Caddy appends the real IP, producing `X-Forwarded-For: 127.0.0.1, 1.2.3.4`.
  4. Echo's `c.RealIP()` returns `127.0.0.1` (the first entry). `isLocalhostIP` returns true.
  5. Attacker has bypassed the localhost gate — but still needs to defeat JWT + AdminMiddleware's admin-flag check, so this is not a complete bypass on its own.
- Impact: defense-in-depth loss. Combined with any future bug that lets a non-admin JWT through (or with a stolen admin JWT from XSS), the localhost gate provides no actual protection.
- Recommendation:
  1. Read the raw `c.Request().RemoteAddr` (after stripping the port) instead of `c.RealIP()` for the localhost check. `RemoteAddr` is the actual TCP peer.
  2. Alternatively, set `e.IPExtractor` to a custom function that trusts only the immediate proxy's address and validates trusted proxy IPs explicitly.
  3. Confirm Slice F covers Caddy's `X-Forwarded-For` posture.
- Suggested tests:
  - Black-box: from a non-loopback client, set `X-Forwarded-For: 127.0.0.1` and call `/api/admin/users`; confirm 403 not 401/200.
- Cross-refs: Slice F (Caddyfile review).

---

### Finding E-15: `LogAdminAction` writes plaintext `details` strings that can include sensitive operator inputs

- Severity: **Low**
- Confidence: **High**
- Category: logging hygiene / privacy
- Component: `handlers/admin.go`, `handlers/admin_billing.go`
- Affected files/functions: `handlers/admin.go:1421-1428` (`LogAdminAction`); call sites at `handlers/admin.go:710` (`UpdateUser` — `"Updated fields: isApproved: true, isAdmin: true, storageLimitBytes: …"`) and `handlers/admin_billing.go:78-80` (`billing_set_price` — `"price: 10.00 -> 19.99 (rate: 1356 -> 2711 microcents/GiB/hour)"`) and `handlers/admin_billing.go:254-255` (`billing_gift` — `"amount: $5.0000, reason: <operator-supplied string>"`).
- Description: `LogAdminAction` accepts arbitrary `details string` and inserts into `admin_logs.details`. Free-form operator input (e.g. a gift reason like `"PII: paid by alice@example.com"`) is persisted in cleartext, indefinitely (no documented retention).
- Recommendation:
  1. Document that `admin_logs.details` is operator-controlled cleartext.
  2. Add a retention/rotation policy similar to `security_events.CleanupOldEvents`.
  3. Add a startup warning when `admin_logs` row count exceeds a configurable threshold.
- Cross-refs: §3.5 of `storage-credits-v2.md` on settlement metadata privacy.

---

### Finding E-16: `/readyz` reveals internal dependency health to unauthenticated callers

- Severity: **Informational**
- Confidence: **High**
- Category: information disclosure / operational
- Component: `main.go`
- Affected files/functions: `main.go:39-65`.
- Description: `/readyz` is public (no auth), reachable from the open internet through Caddy. It returns:
  ```json
  {"rqlite": "ok", "storage": "ok", "status": "ready"}
  ```
  When unhealthy, it returns:
  ```json
  {"rqlite": "not ready: dial tcp 127.0.0.1:4001: connect: connection refused", ...}
  ```
  The error message can leak the rqlite port, hostname, and driver-specific error wording. This is standard k8s-probe behavior, but it's broadcast to every visitor.
- Recommendation:
  1. Strip error details for the public `/readyz` response (only "rqlite": "ok" | "not ready").
  2. Optionally bind `/readyz` and `/healthz` to a separate listener (different port) so they aren't reachable via the public ingress.
- Cross-refs: Slice F (Caddy ingress).

---

### Finding E-17: `AdminMiddleware` audit log lacks operation outcome (success/failure of the wrapped handler)

- Severity: **Informational**
- Confidence: **High**
- Category: logging / audit-trail completeness / **defense-in-depth for payment-processor wiring**
- Component: `handlers/middleware.go`
- Affected files/functions: `handlers/middleware.go:617-626`.
- Description: `AdminMiddleware` logs `EventAdminAccess` *before* calling `next(c)`. It records only `endpoint` + `method`. The post-handler outcome (status code, error) is never recorded by this middleware.

  Combined with the fact that many admin handlers do their own `LogSecurityEvent(EventAdminAccess, …)` calls (e.g. `admin.go:179-190` after a successful cleanup), the audit trail is inconsistent: some operations log twice, some log only the entry. There is no single source of truth for "admin action X happened and succeeded/failed at Y".

- Recommendation:
  1. Move the audit log to after `next(c)` in `AdminMiddleware` and include `res.Status` + `err.Error()`.
  2. Remove the per-handler `LogSecurityEvent(EventAdminAccess, …)` redundancy — the middleware logs the wrapped operation comprehensively.
  3. Required for payment-processor audit compliance (PCI / SOC 2): every privileged action needs a single, unambiguous outcome record.

---

### Finding E-18: `AdminGetContactInfo` decrypts and returns user contact info to the admin without warning

- Severity: **Informational**
- Confidence: **High**
- Category: privacy / design-disclosure
- Component: `handlers/contact_info.go`, `models/contact_info.go` (not read in detail)
- Affected files/functions: `handlers/contact_info.go:103-138` (`AdminGetContactInfo`).
- Description: The system intentionally encrypts user contact info at rest with a server-side key derived from the master key (per the schema comment at `unified_schema.sql:393-396`). This is server-knowable encryption, not E2EE — the server *can* decrypt and does so for admins via this endpoint. The encryption is a defense-in-depth measure against database snapshot exfiltration, not a confidentiality guarantee from the server operator.

  This is a documentation/expectation gap: the schema phrase "Only the admin can decrypt and read contact information" reads like an E2EE claim when in fact the server holds the key.

- Recommendation:
  1. Update `docs/AGENTS.md` and `docs/privacy.md` to clarify: "Contact info is encrypted at rest with a server-held key; admins can read it; the server operator can read it; this is not zero-knowledge."
  2. Audit-log every `AdminGetContactInfo` call (the current code only logs at `InfoLogger.Printf`, not via `LogSecurityEvent`).

---

### Finding E-19: Public `ExportFile` endpoint accepts any valid Arkfile JWT for any user's own file; no TOTP claim required

- Severity: **Medium**
- Confidence: **High**
- Category: authorization / TOTP-bypass-surface
- Component: `handlers/export.go`, `handlers/route_config.go`
- Affected files/functions: `handlers/route_config.go:147` (route on Echo not auth.Echo), `handlers/export.go:60-85` (`ExportFile`), `handlers/export.go:198-228` (`resolveExportAuthFromHeader`).
- Description: `/api/files/:fileId/export` is registered on the **public** Echo (not under `totpProtectedGroup`) because browser downloads use `?token=` query param to avoid Authorization header conflicts. The handler internally calls `resolveExportAuth` which has two paths:
  1. **Token path (`?token=...`)**: requires an export token minted by `CreateExportToken`, which IS under `totpProtectedGroup`. So this path is implicitly TOTP-gated at mint time.
  2. **Header path (`Authorization: Bearer <jwt>`)**: parses a normal Arkfile JWT via `auth.Claims` and accepts it. **No TOTP claim check, no route-level RequireTOTP**.

  The header path is intended for the CLI client which "sends standard Bearer token auth" (handler comment line 198). The CLI's JWT was issued after TOTP completion (Slice A confirms), so in practice this works. **But**: any code path that mints an Arkfile JWT without TOTP completion (e.g. a future bug, or the `auth.Echo` "TOTP setup is not yet done" temp-JWT if it ever shares the signing key) would let that JWT download any file the user owns.

  The same comment notes "the handler validates auth internally via resolveExportAuth() which checks either JWT or token" — but it does not verify TOTP status.

- Evidence:
  ```
  // handlers/route_config.go:144-147
  // File export download - registered on public router because browser downloads
  // use ?token= query param (no Authorization header). The handler validates
  // auth internally via resolveExportAuth() which checks either JWT or token.
  Echo.GET("/api/files/:fileId/export", ExportFile)
  ```
  ```
  // handlers/export.go:198-228
  func resolveExportAuthFromHeader(c echo.Context) (string, error) {
      authHeader := c.Request().Header.Get("Authorization")
      ...
      token, err := jwt.ParseWithClaims(tokenStr, &auth.Claims{}, func(t *jwt.Token) (interface{}, error) { ... })
      ...
      claims, ok := token.Claims.(*auth.Claims)
      if !ok || !token.Valid || claims.Username == "" {
          return "", echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
      }
      return claims.Username, nil
  }
  ```
- Attack scenario: depends entirely on Slice A's verdict on whether any non-TOTP-verified JWT can be minted. Today, the design appears to fail closed; this finding is defense-in-depth.
- Recommendation:
  1. After `resolveExportAuthFromHeader` returns a username, run `auth.IsUserTOTPEnabled` and require `totp_verified` claim or a DB check.
  2. Better: add a wrapper middleware specifically for routes that are public-by-router-but-auth-internal, and have it enforce both auth flavors AND TOTP gating.
- Cross-refs: E-01 (admin TOTP gating), Slice A (two-tier JWT model).

---

### Finding E-20: `AdminExportFile` lets any admin download any user's encrypted blob; design-level disclosure

- Severity: **Informational**
- Confidence: **High**
- Category: design / authz / privacy claim alignment
- Component: `handlers/export.go`
- Affected files/functions: `handlers/export.go:87-107` (`AdminExportFile`).
- Description: `AdminExportFile` streams any file's encrypted blob to any admin. Per `docs/AGENTS.md` privacy posture, this is a Critical-by-design capability: admins *cannot* decrypt the blob (no KEK on the server), but they can exfiltrate ciphertext + the encrypted FEK + the encrypted filename to attempt offline cracking later.

  Combined with Slice B finding B-19 (server-controlled Argon2id params), an admin can deliberately weaken params, then export blobs minted under the weakened regime and brute-force file passwords offline. This is the *expected* trust model for an Arkfile admin and is honestly disclosed in design docs.

- Recommendation: leave the capability in place but:
  1. Audit-log every `AdminExportFile` call into a tamper-evident table (separate from `admin_logs`).
  2. Surface a per-user UI banner: "Your admin can export your encrypted file blob; this does not let them decrypt it without your password."
  3. Cross-link this row from `docs/privacy.md`.
- Cross-refs: Slice B B-19, B-23 (admin-as-adversary).

---

### Finding E-21: `ON DELETE CASCADE` on `users(username)` wipes the entire financial audit trail for that user

- Severity: **High** (Critical once paid top-ups exist)
- Confidence: **High**
- Category: audit-trail integrity / schema / **blocker for payment-processor wiring**
- Component: `database/unified_schema.sql`
- Affected files/functions:
  - `database/unified_schema.sql:351` (`user_credits` FK ON DELETE CASCADE),
  - `database/unified_schema.sql:368` (`credit_transactions` FK ON DELETE CASCADE),
  - `database/unified_schema.sql:378` (`storage_usage_accumulator` FK ON DELETE CASCADE),
  - `database/unified_schema.sql:335` (`admin_logs.admin_username` FK ON DELETE CASCADE).
- Description: Deleting a user via `AdminDeleteUser` (or via direct row delete) cascades:
  - `user_credits` rows: gone.
  - `credit_transactions` rows: gone.
  - `storage_usage_accumulator`: gone.
  - `admin_logs` rows authored by that admin: gone.

  For a system that will hold real money via paid top-ups, this is a **financial audit-trail destruction primitive** triggerable by any admin (DeleteUser is admin-only).

  Today, `credit_transactions` rows are the only record of how a user's balance reached its final value. If a user is deleted, every gift, every usage settlement, and every (future) payment row vanishes.

- Evidence:
  ```
  -- database/unified_schema.sql:357-369
  CREATE TABLE IF NOT EXISTS credit_transactions (
      ...
      FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
  );
  ```
- Attack scenario (post-payment-processor): admin deletes a user whose paid top-up dispute is pending. Stripe asks for the transaction history. It no longer exists in the database. The dispute is lost; the operator pays the chargeback.
- Recommendation:
  1. Change `credit_transactions.username` FK to `ON DELETE SET NULL` and add a `deleted_user_marker TEXT` column with the username, so the row persists.
  2. Same for `admin_logs.admin_username`.
  3. Forbid `DELETE FROM users` directly; require a `users.deleted_at` soft-delete column.
  4. Add a database-level trigger that refuses to delete a user with non-zero `user_credits.balance` or any `credit_transactions` rows newer than N days.
- Cross-refs: E-03, E-04, E-05.

---

### Finding E-22: `credit_transactions.transaction_type` is not constrained to a CHECK list

- Severity: **Informational**
- Confidence: **High**
- Category: schema / data hygiene
- Component: `database/unified_schema.sql`
- Affected files/functions: `database/unified_schema.sql:363`.
- Description: The table accepts any TEXT for `transaction_type`. The code uses three constants (`usage`, `gift`, `adjustment`). A bug that inserts a typo (`"useage"`) would silently corrupt analytics.
- Recommendation: add `CHECK(transaction_type IN ('usage','gift','adjustment'))` and update when new types are added.
- Cross-refs: E-04.

---

### Finding E-23: `file_storage_locations.provider_id` has no `ON DELETE` rule

- Severity: **Low**
- Confidence: **High**
- Category: schema / referential integrity
- Component: `database/unified_schema.sql`
- Affected files/functions: `database/unified_schema.sql:439`.
- Description: `file_storage_locations.provider_id` references `storage_providers(provider_id)` with no `ON DELETE` specified. SQLite defaults to `NO ACTION`, which prevents deletion of a provider that has any locations referencing it. That's fine in normal operation but means a provider cannot be cleanly removed without first migrating all blobs off it.

  Combined with E-02 (SQL-injection-via-provider-id), if the provider_id column ever ends up with malformed rows (e.g. injected via a bug), they cannot be deleted without manual SQL.

- Recommendation: document the expected workflow ("decommission a provider only after `verify-all` confirms zero active locations"). Add an admin endpoint `DELETE /api/admin/storage/providers/:id` that performs the migrate-and-delete dance.

---

### Finding E-24: `share_access_attempts` table is reused as a polymorphic rate-limit store via synthetic share_ids

- Severity: **Low**
- Confidence: **High**
- Category: design / data-model clarity / rate-limit correctness
- Component: `handlers/rate_limiting.go`
- Affected files/functions:
  - `handlers/rate_limiting.go:495-543` (`getOrCreateAuthRateLimitEntry`),
  - `handlers/rate_limiting.go:545-600` (`recordAuthFailedAttempt`),
  - `handlers/rate_limiting.go:498-501` (the synthetic key construction `shareID := "auth_" + endpointType + "_" + entityID`).
- Description: To avoid a separate `auth_rate_limit_attempts` table, the auth rate-limit ladder reuses `share_access_attempts` with a synthetic `share_id` of the form `"auth_" + endpointType + "_" + entityID`. This means:
  1. The same row's `entity_id` and the synthetic `share_id`'s embedded entity_id are duplicates (`shareID` ends with the same value as `entityID`).
  2. The UNIQUE constraint `UNIQUE(share_id, entity_id)` is satisfied trivially because both halves come from the same source.
  3. The "share" cleanup queries that target `share_access_attempts` (e.g. for revoked shares) cannot distinguish between real share entries and auth-rate-limit entries.
  4. The scan at line 505-513 reads `share_id` into the variable named `entry.EndpointType` — a confusing aliasing.

  Functionally it works; semantically it's a footgun for future maintenance.

- Evidence:
  ```
  // handlers/rate_limiting.go:498-501
  // Use a different table/approach - we'll reuse share_access_attempts with endpoint_type as share_id
  shareID := "auth_" + endpointType + "_" + entityID
  ```
- Recommendation: introduce a dedicated `auth_rate_limit_attempts` table or — better — generalize `rate_limit_state` to cover this case (it already exists for the per-endpoint generic rate limiter). Migrating callers off `share_access_attempts` removes the cross-contamination risk.
- Cross-refs: Slice D D-10 (share rate-limit ladder) — that finding uses the same table for its intended purpose.

---

### Finding E-25: `OpaqueRegister*` paths do not call `recordAuthFailedAttempt`, so `RegisterRateLimitMiddleware` only blocks already-penalized entities

- Severity: **Medium**
- Confidence: **Medium**
- Category: rate-limiting / authentication
- Component: `handlers/rate_limiting.go`, `handlers/auth.go` (not read in this slice; referenced via routes)
- Affected files/functions: `handlers/rate_limiting.go:427-446` (`RegisterRateLimitMiddleware`), route registration at `handlers/route_config.go:62-63`.
- Description: `RegisterRateLimitMiddleware` checks `checkAuthRateLimit("register", entityID)` before forwarding the request. But the register handlers (`OpaqueRegisterResponse`, `OpaqueRegisterFinalize`) do not call `recordAuthFailedAttempt("register", entityID)` on failure (only `admin_auth.go` does this for admin login). So the failure-count column in `share_access_attempts` for `"auth_register_<entityID>"` never increments, the penalty ladder never escalates, and the middleware effectively only blocks entities that were *manually* marked penalized (which doesn't happen in this code path).

  The login path has the same structure; need to verify whether `OpaqueAuth*` handlers call `recordAuthFailedAttempt("login", ...)`. The fact that only `admin_auth.go` does so is a strong tell.

- Recommendation:
  1. Audit every auth endpoint handler in `handlers/auth.go` and add `recordAuthFailedAttempt(endpointType, entityID)` on every failure branch.
  2. Add a test that hits `/api/opaque/register/response` 20 times with bad input and asserts the 4th call returns 429.
- Cross-refs: Slice A on auth rate-limit coverage; this is the API-surface manifestation.

---

### Finding E-26: Public config endpoints (`/api/config/argon2`, etc.) are unrate-limited

- Severity: **Informational**
- Confidence: **High**
- Category: defense-in-depth / DoS surface
- Component: `handlers/route_config.go`, `handlers/config.go`
- Affected files/functions: `handlers/route_config.go:54-59`, `handlers/config.go` (entire).
- Description: `GET /api/config/argon2`, `/api/config/password-requirements`, `/api/config/chunking`, and `/api/version` are public and have no rate limit middleware. They return embedded JSON files of bounded size, so the DoS risk is small. They're also necessary for clients to bootstrap, so a per-IP limit would harm legitimate users.

  Slice B already covers the *content* of these endpoints under finding B-19 (server-controlled Argon2id params). The Slice E observation is purely that no rate limit is applied here, which is consistent with the design.

- Recommendation: optional — add a generous shared rate limit (e.g. 60/min per entity) just to dampen accidental client retry storms.

---

### Finding E-27: `AdminSecurityEvents` limit clamp uses `fmt.Sscanf` rather than strconv, silently coerces malformed input

- Severity: **Informational**
- Confidence: **High**
- Category: input parsing / consistency
- Component: `handlers/admin.go`
- Affected files/functions: `handlers/admin.go:1081-1091`.
- Description: The `limit` query param is parsed with `fmt.Sscanf(limitStr, "%d", &limit)`. If parsing fails, the code resets `limit = 100` rather than returning 400. This is consistent with the codebase's "tolerate bad input" stance for read-only admin endpoints, but it differs from the `paginationLimit` helper in `handlers/credits.go:213-220` which uses `strconv.Atoi`. Pick one parser and use it consistently. (No security impact.)
- Recommendation: replace with `strconv.Atoi` for consistency. Return 400 for malformed input on admin endpoints (admin tooling needs honest errors).

---

## 3. Tables

### 3.1 Endpoint Review Table — admin / billing / misc endpoints

Columns: `Method | Endpoint | Auth | Authz rule | TOTP-gated? | Rate-limited? | Sensitive inputs | Sensitive outputs | Notable issues | Suggested tests`.

`TOTP-gated?` reflects whether the route is wired through `RequireTOTP` or an equivalent route-level claim check **at the chokepoint** per `idsrp.md` §22.3. "**Indirect**" means the route is on a public router and the handler relies on internal token validation that implicitly required TOTP at mint time. "**No**" is a finding per §22.2/§22.3 unless explicitly documented as intentional.

| Method | Endpoint | Auth | Authz rule | TOTP-gated? | Rate-limited? | Sensitive inputs | Sensitive outputs | Notable issues | Suggested tests |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/healthz` | None | None | N/A | No | — | `{"status":"alive"}` | Trivial; reachable publicly | Unauth GET returns 200 |
| GET | `/readyz` | None | None | N/A | No | — | rqlite / storage health, may leak error wording | E-16 | Negative: assert errors don't include host/port |
| GET | `/api/config/argon2` | None | None | N/A | No (E-26) | — | Argon2 params JSON | Slice B B-19 | Public GET returns 200 |
| GET | `/api/config/password-requirements` | None | None | N/A | No | — | password reqs JSON | Slice B B-19 | — |
| GET | `/api/config/chunking` | None | None | N/A | No | — | chunk config JSON | Slice B | — |
| GET | `/api/version` | None | None | N/A | No | — | version string | Low risk | — |
| GET | `/api/admin-contacts` | None | None | N/A | No | — | admin contacts JSON | Public exposes admin usernames; intentional for support contact | Verify minimal disclosure |
| POST | `/api/refresh` | Refresh token | per-token | N/A | No | refresh token | new JWT | Slice A |
| POST | `/api/logout` | JWT | self | N/A | No | JWT | — | Slice A |
| GET | `/api/totp/status` | JWT (full) | self | N/A | No | — | TOTP status flags | Slice A |
| POST | `/api/totp/reset` | JWT (full) | self | N/A | No | — | reset confirmation | Slice A |
| POST | `/api/totp/setup` | TOTP-temp JWT | self | (entry point) | No | — | QR / URI | Slice A |
| POST | `/api/totp/verify` | TOTP-temp JWT | self | (entry point) | Yes (TOTP) | TOTP code | full JWT | Slice A |
| POST | `/api/totp/auth` | TOTP-temp JWT | self | (entry point) | Yes (TOTP) | TOTP code | full JWT | Slice A |
| POST | `/api/revoke-token` | JWT+TOTP | self | **Yes** | No | jti | — | OK |
| POST | `/api/revoke-all` | JWT+TOTP | self | **Yes** | No | — | — | OK |
| GET | `/api/credits` | JWT+TOTP | self | **Yes** | No | pagination | balance, transactions, runway | OK |
| GET | `/api/user/contact-info` | JWT (no Approved) +TOTP | self | **Yes** | No | — | contact info (decrypted) | OK |
| PUT | `/api/user/contact-info` | JWT (no Approved) +TOTP | self | **Yes** | No | contact info JSON | — | size-limit OK |
| DELETE | `/api/user/contact-info` | JWT (no Approved) +TOTP | self | **Yes** | No | — | — | OK |
| POST | `/api/files/:fileId/export-token` | JWT+TOTP | self-owns-file | **Yes** | No | fileId | short-lived JWT (60s) | OK |
| GET | `/api/files/:fileId/export` | JWT *or* export-token | (token-bound) or self-owns-file | **No (header path)** / Indirect (token path) | No | fileId, ?token= | **encrypted blob + metadata** | **E-19** | Negative: non-TOTP JWT should be rejected |
| POST | `/api/admin/login/response` | None (pre-auth) | None | (entry point) | Yes (login limiter) | username, credential | session-id, response | Slice A |
| POST | `/api/admin/login/finalize` | None (pre-auth) | None | (entry point — requires TOTP next) | Yes | session-id, authU | temp-token | Slice A |
| GET | `/api/admin/credits` | JWT+Admin | localhost+admin | **No (E-01)** | Yes (admin 10/min) | — | every user's balance | E-01, E-13 | Negative: non-TOTP JWT rejected |
| GET | `/api/admin/credits/:username` | JWT+Admin | localhost+admin | **No** | Yes | username | one user's full ledger | E-01 | — |
| GET | `/api/admin/users` | JWT+Admin | localhost+admin | **No** | Yes | — | all users + TOTP-enabled + file_count | E-01, E-12 (cross) | — |
| POST | `/api/admin/users/:u/approve` | JWT+Admin | localhost+admin | **No** | Yes | approved_by, storage_limit | — | E-01 | — |
| GET | `/api/admin/users/:u/status` | JWT+Admin | localhost+admin | **No** | Yes | username | TOTP/OPAQUE/tokens/billing | E-01 | — |
| PUT | `/api/admin/users/:u/storage` | JWT+Admin | localhost+admin | **No** | Yes | storage_limit_bytes | — | E-01 | bounds-check positive |
| POST | `/api/admin/users/:u/revoke` | JWT+Admin | localhost+admin | **No** | Yes | username | — | E-01; doesn't revoke JWTs (Slice A) | — |
| DELETE | `/api/admin/users/:u` | JWT+Admin | localhost+admin | **No** | Yes | username | — | **E-21 (cascade)**, E-01 | Negative: cannot delete if balance != 0 |
| PUT | `/api/admin/users/:u` | JWT+Admin | localhost+admin | **No** | Yes | is_approved, is_admin, storage_limit | — | E-01, E-15 (details log) | — |
| POST | `/api/admin/users/:u/force-logout` | JWT+Admin | localhost+admin | **No** | Yes | username | — | Slice A on JWT revocation | — |
| GET | `/api/admin/users/:u/files` | JWT+Admin | localhost+admin | **No** | Yes | username | file_id, storage_id, locations | E-01 | — |
| GET | `/api/admin/users/:u/shares` | JWT+Admin | localhost+admin | **No** | Yes | username | share_ids, access_count | E-01 | — |
| GET | `/api/admin/users/:u/contact-info` | JWT+Admin | localhost+admin | **No** | Yes | username | decrypted contact info | E-01, E-18 | audit-log every call |
| DELETE | `/api/admin/files/:fileId` | JWT+Admin | localhost+admin | **No** | Yes | fileId | — | E-01 | — |
| POST | `/api/admin/shares/:shareId/revoke` | JWT+Admin | localhost+admin | **No** | Yes | shareId | — | E-01; Slice D D-04 (reason leak) | — |
| GET | `/api/admin/files/:fileId/export` | JWT+Admin | localhost+admin | **No** | Yes | fileId | **encrypted blob of any user's file** | **E-20**, E-01 | Tamper-evident audit-log required |
| GET | `/api/admin/system/status` | JWT+Admin | localhost+admin | **No** | Yes | — | user counts, storage stats, TOTP counts | E-01 | — |
| GET | `/api/admin/system/health` | JWT+Admin | localhost+admin | **No** | Yes | — | DB / keys / storage / system details | E-01 | endpoint/bucket disclosed (admin OK) |
| GET | `/api/admin/security/events` | JWT+Admin | localhost+admin | **No** | Yes | type, severity, entity_id, limit | security events including usernames | E-01, E-27 | — |
| GET | `/api/admin/storage/status` | JWT+Admin | localhost+admin | **No** | Yes | — | provider IDs, costs, sizes | E-01 | — |
| GET | `/api/admin/storage/sync-status` | JWT+Admin | localhost+admin | **No** | Yes | — | per-provider sync stats | **E-02 (SQLi)**, E-01 | Negative: malformed provider_id |
| POST | `/api/admin/storage/copy-all` | JWT+Admin | localhost+admin | **No** | Yes | source_id, dest_id, verify, skip_existing | task_id | E-01 | — |
| POST | `/api/admin/storage/copy-user-files` | JWT+Admin | localhost+admin | **No** | Yes | username, source_id, dest_id | task_id | E-01 | — |
| POST | `/api/admin/storage/copy-file` | JWT+Admin | localhost+admin | **No** | Yes | file_id, source_id, dest_id | task_id | E-01 | — |
| GET | `/api/admin/storage/task/:taskId` | JWT+Admin | localhost+admin | **No** | Yes | task_id | task status + details | E-01; task IDs are UUIDs | — |
| POST | `/api/admin/storage/cancel-task/:taskId` | JWT+Admin | localhost+admin | **No** | Yes | task_id | — | E-01 | — |
| POST | `/api/admin/storage/set-primary` | JWT+Admin | localhost+admin | **No** | Yes | provider_id | role swap result | E-01 | — |
| POST | `/api/admin/storage/set-secondary` | JWT+Admin | localhost+admin | **No** | Yes | provider_id | — | E-01 | — |
| POST | `/api/admin/storage/set-tertiary` | JWT+Admin | localhost+admin | **No** | Yes | provider_id | — | E-01 | — |
| POST | `/api/admin/storage/swap-providers` | JWT+Admin | localhost+admin | **No** | Yes | — | swap result | E-01 | — |
| POST | `/api/admin/storage/verify-storage` | JWT+Admin | localhost+admin | **No** | Yes | provider_id (opt) | verification details | E-01 | — |
| POST | `/api/admin/storage/set-cost` | JWT+Admin | localhost+admin | **No** | Yes | provider_id, cost_per_tb_cents | — | E-01 | — |
| POST | `/api/admin/storage/verify-all` | JWT+Admin | localhost+admin | **No** | Yes | provider_id (opt), fix, concurrency | task_id | E-01 | — |
| GET | `/api/admin/alerts/summary` | JWT+Admin | localhost+admin | **No** | Yes | — | counts of failures/orphans/etc | E-01 | — |
| GET | `/api/admin/billing/price` | JWT+Admin | localhost+admin | **No** | Yes | — | current rate | E-01 | — |
| POST | `/api/admin/billing/set-price` | JWT+Admin | localhost+admin | **No** | Yes | customer_price_usd_per_tb_per_month | new rate | **E-01**, E-06 | Negative: overflow input |
| GET | `/api/admin/billing/sweep-summary` | JWT+Admin | localhost+admin | **No** | Yes | days | per-day usage aggregates | E-01 | — |
| GET | `/api/admin/billing/overdrawn` | JWT+Admin | localhost+admin | **No** | Yes | — | usernames in negative balance | E-01 | — |
| POST | `/api/admin/billing/gift` | JWT+Admin | localhost+admin | **No** | Yes | target_username, amount_usd, reason | transaction | **E-01**, **E-04**, E-06, E-15 | Duplicate-gift test |
| POST | `/api/admin/dev-test/users/cleanup` | JWT+Admin (dev-only) | localhost+admin+dev-flag | **No** | Yes | username, confirm | rows-cleared map | E-11 (duplicate cleanup row); production-disabled | — |
| GET | `/api/admin/dev-test/totp/decrypt-check/:u` | JWT+Admin (dev-only) | localhost+admin+dev-flag+DEBUG_MODE | **No** | Yes | username | TOTP diagnostic flags | E-12; triple-gated | — |
| POST | `/api/admin/dev-test/billing/tick-now` | JWT+Admin (dev-only) | localhost+admin+dev-flag | **No** | Yes | sweep | tick+sweep result | E-04, E-05 | — |

**Count summary**: 64 endpoints in this slice's scope. **51 of the 64** are on `adminGroup` and are therefore **not** route-level TOTP-gated; per E-01 this is the headline finding for the slice.

### 3.2 Billing operations table

Columns: `Operation | Inputs (untrusted?) | DB writes | Atomicity | Idempotent? | Authz | Audit log | Issues`.

| Operation | Inputs (untrusted?) | DB writes | Atomicity | Idempotent? | Authz | Audit log | Issues |
|---|---|---|---|---|---|---|---|
| `billing.TickUser` (per user, per hour) | username (system-supplied), rate, freeBaseline | INSERT/UPSERT `storage_usage_accumulator` | Single statement; rqlite-level | Yes (UPSERT `unbilled += charge`) | system | none | E-07 overflow; rate is server-controlled |
| `billing.SweepAllUsers` → `settleOneUser` (per user, daily) | username (system), drained_microcents, lastBilledAt | UPDATE `user_credits`; INSERT `credit_transactions`; UPDATE `storage_usage_accumulator` | Per-user tx; **but read outside tx (E-03)** | No (E-04 no key) | system | none on success; ErrorLogger on per-user failure | **E-03 race**, **E-04 no idempotency**, **E-05 restart double-run** |
| `billing.GiftCredits` (admin) | target_username, amount_microcents, reason, admin_username | INSERT-or-UPDATE `user_credits`; INSERT `credit_transactions` (type='gift') | One tx; reads + writes inside tx | No (E-04) | admin (via `AdminMiddleware` + `requireAdminWithUsername`) | `LogSecurityEvent(EventAdminAccess,…)` + `LogAdminAction` | E-04, **no idempotency key**, E-15 reason cleartext |
| `billing.SetCustomerPrice` (admin) | priceStr, updatedBy | UPSERT `billing_settings` (key=customer_price); cache swap via `SetCachedRate` | Single UPSERT + in-mem atomic.Pointer | Idempotent on same input | admin | `LogAdminAction("billing_set_price", …)` (E-15 details cleartext) | E-06 overflow on parse, E-08 720-vs-730.5 |
| `billing.SeedCustomerPriceIfMissing` (system startup) | priceStr from env or hardcoded fallback | INSERT into `billing_settings` only if missing | Single statement | Idempotent | system | InfoLogger | OK |
| `AdminBillingTickNow` (dev/test) | sweep bool | Forces immediate `TickAll` and optionally `SweepAllUsers` | Per-user; same issues as above | No | admin + dev-flag | `LogAdminAction("billing_tick_now", ...)` | Inherits E-03/E-04/E-05 |
| `models.GetUserCreditsSummary` | username | Read-only | n/a | n/a | self or admin | none | Lazy-creates a zero row via `GetOrCreateUserCredits` |

### 3.3 Schema integrity / authz invariants table

| Table | Critical FKs | ON DELETE | Effect | Issue |
|---|---|---|---|---|
| `user_credits` | username → users | CASCADE | wipes balance row | E-21 |
| `credit_transactions` | username → users | CASCADE | **wipes ledger** | **E-21** (Critical for payments) |
| `credit_transactions` | (transaction_id) | — | NOT UNIQUE | E-04 |
| `credit_transactions.transaction_type` | — | — | No CHECK constraint | E-22 |
| `storage_usage_accumulator` | username → users | CASCADE | wipes accumulator | E-21 |
| `admin_logs` | admin_username → users | CASCADE | **wipes admin audit trail** | **E-21** |
| `file_storage_locations` | provider_id → storage_providers | (no rule = NO ACTION) | cannot delete provider with locations | E-23 |
| `file_share_keys` | file_id → file_metadata | CASCADE | revoking the file revokes the share — intended |
| `storage_providers.provider_id` | — | — | No format check (must be sanitized) | **E-02** (combined with admin_storage.go interpolation) |

---

## 4. N/A items

Items the `idsrp.md` prompt asks about that do not exist in Arkfile's admin/billing surface (or are explicitly out-of-scope for this slice).

| Item from `idsrp.md` | Slice E status | Justification |
|---|---|---|
| Multi-tenant separation (§8) | N/A | Single tenant; `users.username` is the only authz dimension. |
| Folder hierarchy / nested folder ACL | N/A | Flat per-user file space. |
| SSRF on user-supplied URLs (§10) | N/A in this slice | No admin or billing endpoint accepts a URL for fetching. Confirmed by reading every endpoint in scope. |
| Archive extraction (§10) | N/A | Server never extracts archives; export streams raw encrypted blob. |
| Card / crypto / ACH / SEPA wiring | N/A *today* | No payment processor integrated yet. All payment-related findings (E-03, E-04, E-05, E-06, E-21) are tagged "blocker for payment-processor wiring" per `00-plan.md` Slice E goals. |
| Recipient public-key directory / PKI | N/A | Slice D; not relevant here. |
| CDN cache-poisoning for private content | Deferred to Slice F | Caddy / CDN posture. |
| TOTP middleware *implementation* details (constant-time, lockout state) | Deferred to Slice A | This slice only verifies route-level wiring (E-01). |
| Two-tier JWT model correctness (temp vs full token) | Deferred to Slice A | This slice only verifies route-level wiring. |
| Email verification / password reset flow | TBD — deferred to Slice A | None exists in this slice's scope; Arkfile's "lost password = lost files" posture means there is no reset by design. |
| Device enrollment / device management | N/A | Refresh tokens exist; no per-device UI. |
| systemd / Caddy / TLS / build supply chain | Deferred to Slice F |  |
| WASM artifact integrity / SRI | Deferred to Slice F |  |

---

## 5. Open Questions / blocked-on-developer

1. **Slice A cross-ref**: confirm definitively that no Arkfile JWT is ever minted with `aud=arkfile-prod` + `totp_verified=false` (or equivalent absent claim). If any path emits one (e.g. refresh after TOTP reset?), E-01 and E-19 escalate from Medium to High.
2. **Caddy `X-Forwarded-For` posture**: does `Caddyfile.prod` strip incoming `X-Forwarded-For` before forwarding to the Arkfile backend? If not, E-14 escalates from Medium to High. Slice F territory.
3. **Future paid-top-up design**: when payment processor integration is scoped, confirm the choice of `transaction_id` source (Stripe `pi_*` IDs, crypto txid, etc.) and add the UNIQUE constraint per E-04 *before* writing any paid rows.
4. **`AdminCleanupTestUser`'s duplicate `opaque_user_data` row (E-11)**: was this an intentional belt-and-suspenders for a CGO-side cache invalidation, or a copy-paste bug?
5. **Process-local `lastSweepDate` (E-05)**: is at-most-once daily sweep a documented invariant or an emergent property the team is relying on? The fix requires a small schema addition.
6. **`AdminGetContactInfo` audit log (E-18)**: should every admin read of a user's contact info land in `admin_logs`? Currently only `InfoLogger.Printf`.

---

## 6. Testing Gaps (to feed into Slice G)

Tests that this slice's findings demand and that are missing or thin in the present codebase. Prioritized.

1. **High-priority (correctness / billing)**:
   - Race test: `GiftCredits` interleaved with `settleOneUser` → final balance invariants (E-03).
   - Duplicate-gift test: identical `POST /api/admin/billing/gift` twice → 409 once UNIQUE constraint exists (E-04).
   - Duplicate-sweep test: `SweepAllUsers` twice after restart simulation → exactly one `usage` row per user per day (E-05).
   - Overflow tests: `ParseCreditsFromUSD("92233720369.00")` → error; `TickUser` with crafted `billable × rate` → no wrap-around (E-06, E-07).
   - Ledger invariant: `sum(credit_transactions.amount WHERE username = U) == user_credits.balance` always holds (E-03/E-04).

2. **High-priority (authz / TOTP gating)**:
   - For every `/api/admin/**` route, verify a non-TOTP-verified JWT is rejected — this is the per-route verification §22.3 demands (E-01).
   - SQL-injection probe: write a `storage_providers` row with `provider_id = "x' OR 1=1 --"` and call `GET /api/admin/storage/sync-status` → assert error (E-02).
   - Localhost-bypass probe: craft `X-Forwarded-For: 127.0.0.1` against `/api/admin/users` from a non-loopback client → assert 403 (E-14).
   - Export-header path: present a synthetic non-TOTP JWT to `GET /api/files/:fileId/export` (Bearer header) → assert 403 once E-19 is fixed.

3. **Medium-priority (auth rate-limit ladder)**:
   - 20 consecutive `POST /api/opaque/register/response` → expect 429 by attempt 4 once `recordAuthFailedAttempt` is wired into the register handlers (E-25).
   - Same for `/api/opaque/login/response` if not already covered in Slice A.

4. **Schema invariants** (would catch E-21 / E-22 / E-23 future regressions):
   - Assertion: deleting a user with a non-zero `user_credits.balance` is rejected.
   - Assertion: `credit_transactions` cannot contain a `transaction_type` outside the enum.
   - Assertion: `storage_providers.provider_id` matches `^[a-zA-Z0-9_-]+$`.

5. **Logging hygiene**:
   - Assert `admin_logs.details` for `update_user` does not include the user's storage limit if the design says it shouldn't (E-15 — clarify the policy first).
   - Assert `/readyz` error responses do not contain "rqlite" / driver-specific wording (E-16).

---

## 7. Hardening Recommendations (not vulnerabilities)

1. **Move all admin audit logging into `AdminMiddleware` post-handler** (E-17). Single source of truth; success/failure recorded together.
2. **Adopt a single `requireAdmin*` helper** (E-10, E-13) and migrate all admin handlers to it. Forbid inline `if !user.IsAdmin` via a linter rule.
3. **Add `UNIQUE(transaction_id)` to `credit_transactions`** even before payment-processor wiring (E-04). It is forward-compatible.
4. **Soft-delete users** via `deleted_at TIMESTAMP` rather than `DELETE FROM users` (E-21). Convert `DeleteUser` handler accordingly.
5. **Adopt a parameterized-SQL-only policy** (E-02). Add a `golangci-lint` rule banning `fmt.Sprintf` adjacent to SQL keywords.
6. **Document the metering math precisely**: 720 vs 730.5 hours per month (E-08); the floor-rounding intent; the truncation-floor of `>> 30`.
7. **Add Prometheus-style metrics for billing**: ticks-per-hour, sweeps-per-day, gifts-per-day, total drained. The current scheduler logs to ErrorLogger but does not expose counters.
8. **Move `/healthz` and `/readyz` to a separate listener** (E-16) for production deployments. Reduces unauthenticated dependency-fingerprint exposure.
9. **Tighten `/api/admin/users/:u/contact-info`** (E-18) to record every admin read in a tamper-evident table, separate from `admin_logs`.
10. **Add `auth_rate_limit_attempts` table** (E-24) to stop overloading `share_access_attempts`. Migration is straightforward.
11. **Confirm `OpaqueRegister*` and `OpaqueAuth*` handlers call `recordAuthFailedAttempt`** in every failure branch (E-25). Inherit the pattern from `admin_auth.go`.
12. **Constrain `storage_providers.provider_id` to a charset** at schema level. Prevents future E-02-style sinks.
13. **Establish a ledger-invariant background job**: nightly check that `sum(credit_transactions.amount) WHERE username=U` equals `user_credits.balance` for every user; alert on drift.
14. **Document the trust model for `AdminExportFile`** (E-20) in `docs/privacy.md` and add a UI banner. Honesty + transparency per `AGENTS.md`.

---

## End of Slice E
