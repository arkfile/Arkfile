# Subscription Plans and Dual-Model Billing

This document plans optional **subscription tiers** for Arkfile alongside the existing **pay-as-you-go (PAYG)** microcent meter, credits ledger, and BTCPay top-up flow. It is written for a greenfield implementation on top of the foundation already shipped in mid-2026: 1 GiB default storage (marketed as "1.0 GB Free"), auto-approval with admin override, registration throttling, PAYG negative-balance upload cap at −$10, runtime approval-policy toggle, and the billing/payments stack described in `docs/wip/storage-credits-v2.md` and `docs/wip/payments.md`.

The goal is not to codify margin math, competitor tables, or breakeven percentages in the codebase. Operators define a **plan catalog** (name, monthly price, storage limit). Users on an active subscription get that storage cap and **do not accrue PAYG usage charges** while subscribed. Users without a subscription remain on the existing free baseline + hourly meter + optional top-ups model. Private or gratis instances can disable billing, PAYG, subscriptions, and payments independently.

NOTE: This document and the production instance may mention or target "Stripe" support specifically (ideally as a plugin in BTCPayServer), but the infrastructure/code/functions should be general to support other payment processors equally well. E.g. Adyen, Mollie, Worldpay, CashApp/Square, etc.

## Relationship to existing billing and payments

Three commercial layers already exist and must coexist cleanly:

| Layer | Purpose today | Primary config |
|---|---|---|
| **Storage hard cap** | Upload blocked when `total_storage_bytes + padded_size > storage_limit_bytes` | Per-user `users.storage_limit_bytes` (default 1 GiB); admin `set-storage` |
| **PAYG meter** | Hourly microcent accumulation, daily settlement into `user_credits` | `ARKFILE_BILLING_ENABLED`, `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH`, `billing_settings` |
| **Top-ups** | One-time balance credit via BTCPay invoice | `ARKFILE_PAYMENTS_ENABLED`, BTCPay Greenfield + webhook |

Subscriptions add a fourth layer:

| Layer | Purpose (planned) | Config |
|---|---|---|
| **Subscription plan** | Flat monthly fee; raises storage limit; pauses PAYG meter while active | `ARKFILE_SUBSCRIPTIONS_ENABLED`, Payment processor credentials |

Important decouplings preserved from `docs/wip/payments.md`:

- Paying does **not** automatically raise storage unless the payment is a **subscription plan** (or an admin action).
- Hard storage cap and credit balance remain separate gates.
- Upload soft-block at negative PAYG balance applies only when PAYG metering is active for that user.

## Product model

### Free / PAYG (default)

Every new user gets immediate access (auto-approval when configured) with:

- `storage_limit_bytes` default **1 GiB** (`1073741824`), overridable per user via `arkfile-admin set-storage`.
- **Free baseline** for metering: 1 GiB (`ARKFILE_FREE_STORAGE_BYTES` / `Billing.FreeBaselineBytes`) — storage at or below this is not billable on PAYG.
- When PAYG is enabled: hourly tick, daily sweep, signed microcent balance, BTCPay top-ups, upload blocked at balance ≤ −$10 (configurable via `ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD`).
- Login and download remain available when upload-blocked for negative PAYG balance.

### Subscription

User selects a plan from the operator-defined catalog. While **active**:

- **`storage_limit_bytes` is set from the plan** (see precedence rules below).
- **PAYG metering is off** for that user — flat monthly fee covers storage up to the plan limit; no `usage` rows while subscribed.
- User is **not** subject to the PAYG negative-balance upload cap (there is no accumulating usage debt on PAYG while the meter is paused).

When subscription **ends** (cancel, expiry, failed payment after grace):

- Revert to free-tier defaults: 1 GiB storage limit (unless admin had set a higher manual cap — see precedence), PAYG meter on if instance PAYG enabled, free baseline 1 GiB.

### Operator pricing intent (marketing, not code)

Hosted offerings may tier from roughly **250 GB at the low end** to **20 TB at the high end**, with lower tiers priced at a higher effective $/TB and higher tiers approaching or even dropping below "fully allocated" infrastructure cost assumptions (~$15/TiB/month for dual-backend replication). Competitor research (Proton, MEGA, SpiderOak) informs positioning only; the codebase stores operator-editable plan rows, not margin tables.

Differentiators to emphasize in copy (not in schema): dual object-storage backends, export/portability, open source.

### v1 billing-mode decision (lock before schema)

**Recommended for v1:** subscription = **flat fee + storage limit + meter paused**. Do **not** implement per-plan microcent rates or "subscriber overage metering" in the first release.

**Deferred to v2:** plan-specific PAYG rate overrides, proration, annual billing, crypto recurring, automated purge on `past_due`.

## Instance toggles

Split the monolithic `ARKFILE_BILLING_ENABLED` concept into operator-visible modes:

| Variable | When true |
|---|---|
| `ARKFILE_BILLING_ENABLED` | Master switch: scheduler runs; billing APIs respond; projection in `/api/credits` |
| `ARKFILE_BILLING_PAYG_ENABLED` (new) | Hourly meter + daily sweep + PAYG negative upload cap |
| `ARKFILE_SUBSCRIPTIONS_ENABLED` (new) | Plan catalog, checkout, lifecycle webhooks, subscription UI |
| `ARKFILE_PAYMENTS_ENABLED` | BTCPay one-time top-ups (existing) |

Suggested defaults for **private / gratis** instances: all false. For **hosted PAYG-only**: billing + PAYG + payments on, subscriptions off. For **hosted with tiers**: all relevant flags on.

Startup validation: if subscriptions enabled, require provider credentials and webhook secret (see Payments integration). If only PAYG enabled, existing billing validation applies.

## Precedence rules

Document and implement consistently:

1. **`is_approved`** — unchanged; unapproved users blocked regardless of plan.
2. **Storage hard cap** — `CheckStorageAvailable` always uses effective limit:
   - Active subscription → plan `storage_limit_bytes`.
   - Else → `users.storage_limit_bytes` (default 1 GiB or admin `set-storage`).
   - **Admin override:** recommend `users.storage_limit_bytes = max(admin_value, plan_value)` while subscribed, and store `storage_limit_source` (`default`, `admin`, `plan`) to know what to revert to on cancel. Simpler v1 alternative: on subscribe, copy plan limit into `users.storage_limit_bytes`; on cancel, reset to `DefaultStorageLimit` unless admin flag `storage_limit_locked` set.
3. **PAYG meter** — skip `TickUser` when user has active subscription and instance subscriptions enabled.
4. **Free baseline in projection** — for subscribed users, treat effective free baseline as plan storage limit so `billable_bytes = 0` in UI while under cap.
5. **Upload gates** — hard cap always; PAYG 402 only when PAYG active and balance ≤ −cap; optional **`past_due` subscription blocks uploads** after grace (recommend: block uploads, allow download/delete).

## Database schema (planned)

Add to `database/unified_schema.sql` with migration helpers in `main.go` for existing DBs.

### `subscription_plans`

Operator catalog. Not seeded with fixed tiers in code — operator creates rows via admin API/CLI or seed script for their deployment.

```sql
CREATE TABLE IF NOT EXISTS subscription_plans (
    plan_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    price_usd_cents INTEGER NOT NULL,
    storage_limit_bytes BIGINT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    is_public BOOLEAN NOT NULL DEFAULT 1,
    provider_price_id TEXT UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);
```

Use integer USD cents in the catalog for human-friendly admin editing; convert consistently if the ledger ever records subscription charges.

### `user_subscriptions`

One logical active subscription per user; history via `subscription_events` or status transitions.

```sql
CREATE TABLE IF NOT EXISTS user_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'active', 'past_due', 'canceled', 'expired', 'trialing'
    )),
    current_period_start DATETIME NOT NULL,
    current_period_end DATETIME NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('payment-processor', 'manual')),
    provider_subscription_id TEXT UNIQUE,
    provider_customer_id TEXT,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT 0,
    canceled_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_username ON user_subscriptions(username);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_status ON user_subscriptions(status);
```

`provider = manual` for operator comp/grant without payment provider.

### `subscription_events`

Webhook idempotency and audit (mirror `payment_invoices` + webhook replay protection).

```sql
CREATE TABLE IF NOT EXISTS subscription_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    provider TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT,
    plan_id TEXT,
    payload_hash TEXT NOT NULL,
    processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Ledger interaction

**v1 recommendation:** subscription charges stay **out of** `user_credits` / `credit_transactions`. PAYG balance remains the microcent wallet for non-subscribers. Subscription payment history lives in provider dashboards + `subscription_events`. Optional later: `transaction_type = 'subscription'` for visibility in the billing panel.

## Backend: billing resolver

New package surface (e.g. `billing/subscription.go` or `models/subscriptions.go` + `billing/effective.go`):

| Function | Returns |
|---|---|
| `EffectiveBillingMode(username)` | `free`, `payg`, or `subscribed` |
| `EffectiveStorageLimit(username)` | Bytes for hard cap |
| `EffectiveFreeBaseline(username)` | Bytes for meter/projection |
| `ShouldMeter(username)` | Whether `TickUser` applies |
| `ShouldApplyPaygUploadCap(username)` | Whether 402 gate applies |

Wire into:

- `billing/meter.go` — `TickUser` / `TickAllActiveUsers`
- `handlers/billing_projection.go` — add `subscription` block to `/api/credits` and admin credits
- `handlers/uploads.go` — PAYG cap guard uses `ShouldApplyPaygUploadCap`
- `handlers/auth.go` or session bootstrap — optional exposure of plan in user profile if needed by frontend

Extend `buildBillingProjection` response shape:

```json
{
  "subscription": {
    "enabled": true,
    "status": "active",
    "plan_id": "plan_500gb",
    "plan_name": "500 GB",
    "price_usd": "9.00",
    "storage_limit_bytes": 536870912000,
    "current_period_end": "2026-07-26T00:00:00Z",
    "cancel_at_period_end": false
  },
  "billing_mode": "subscribed"
}
```

When subscriptions disabled globally, omit or null the block (same pattern as `payments` in `/api/credits`).

## Backend: HTTP API (planned)

### Public / user (authenticated unless noted)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/subscriptions/plans` | List public active plans |
| GET | `/api/subscriptions/me` | Current user subscription |
| POST | `/api/subscriptions/checkout` | Body: `{ "plan_id": "..." }` → checkout URL or session id |
| POST | `/api/subscriptions/portal` | Customer portal URL (manage/cancel/payment method) |

### Admin (`/api/admin/...`, existing admin MFA stack)

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/admin/subscriptions/plans` | List / create / update plans |
| GET | `/api/admin/subscriptions/users/:username` | Subscription detail + history |
| POST | `/api/admin/subscriptions/users/:username/assign` | Manual grant (`provider=manual`) |
| POST | `/api/admin/subscriptions/users/:username/cancel` | Force cancel |

### Webhooks

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/webhooks/<payment-provider?>` | Subscription lifecycle (signed) |

Register only when subscriptions enabled (same gating pattern as `ADMIN_DEV_TEST_API_ENABLED` and dev-test billing routes).

### Lifecycle handlers (idempotent)

| Event | Action |
|---|---|
| Checkout completed / subscription created | Set active, apply plan storage limit, record period dates |
| Invoice paid (renewal) | Extend `current_period_end` |
| Payment failed | `past_due`; optional upload block after grace |
| Canceled / subscription deleted | At period end: revert storage, re-enable PAYG meter |
| Plan changed (upgrade/downgrade) | Update limit; v1: apply immediately or at period end (pick one policy) |

Store `pre_subscription_storage_limit_bytes` on subscribe if revert logic needs it.

## Backend: payments integration

Current Arkfile ↔ BTCPay integration (`docs/wip/payments.md`) creates **one-time** invoices for balance top-ups. **Recurring subscriptions** need a different path.

### Recommended v1 path: Payment Processor Subscriptions API

- Arkfile calls Payment Processor Checkout / Billing with `processor_price_id` mapped from `subscription_plans`.
- Webhooks hit `POST /api/webhooks/<payment-processor?>` on the Arkfile server (not browser-exposed).
- Card data stays on payment processor hosted pages — **no Stripe.js in Arkfile** (same privacy posture as BTCPay iframe checkout).
- Operational alignment with `docs/wip/alma-pay-server.md`: Stripe account may live on the Alma Pay / BTCPay host, but Arkfile owns subscription state in SQLite/rqlite.

### Alternative (verify before building)

BTCPay Server Stripe plugin recurring support via Greenfield — only adopt if API surface supports create/manage/cancel subscriptions cleanly. Today’s code path only implements one-off `CreateInvoice`.

### Config (planned additions to `.env.example`)

```
ARKFILE_SUBSCRIPTIONS_ENABLED=false
ARKFILE_PAYMENT_PROCESSOR_SECRET_KEY=
ARKFILE_PAYMENT_PROCESSOR_WEBHOOK_SECRET=
ARKFILE_PAYMENT_PROCESSOR_PUBLISHABLE_KEY=   # optional; redirect checkout may not need it server-side
ARKFILE_SUBSCRIPTION_SUCCESS_URL= # default: /?subscription=success
ARKFILE_SUBSCRIPTION_CANCEL_URL=
```

Validate on startup when subscriptions enabled (mirror payments validation).

## arkfile-admin (planned)

New command group **`subscriptions`** (alongside `billing` and `payments`):

| Command | Purpose |
|---|---|
| `subscriptions list-plans [--json]` | Catalog |
| `subscriptions set-plan --plan-id ID --name NAME --price USD --storage LIMIT [--processor-price-id ID] [--active]` | Create/update plan |
| `subscriptions show --user USER [--json]` | User subscription status |
| `subscriptions assign --user USER --plan-id ID [--period-days N]` | Manual comp/grant |
| `subscriptions cancel --user USER [--immediate]` | Operator cancel |
| `subscriptions sync --user USER` | Poll provider vs local state |

Extend **`billing show --user`** and **`user-status`** to include subscription summary when enabled.

No user-facing purchase flow in admin CLI for v1 — users subscribe via the web UI.

## arkfile-client (planned)

Minimal surface for v1:

- Optional **`subscription status`** — prints plan, renewal date, storage limit from `/api/subscriptions/me`.
- No checkout in CLI unless power-user demand appears later.

PAYG **`billing`** subcommands remain unchanged for operators; end-user CLI billing is not required for subscriptions v1.

## TypeScript frontend (planned)

Extend `client/static/js/src/ui/billing.ts` and the billing panel markup.

### When subscriptions disabled

No UI change beyond current balance, usage projection, transaction history, and top-up modal.

### When subscriptions enabled

1. **Your plan** — plan name, price, renewal date, storage used/limit (from `/api/credits` + `/api/subscriptions/me`).
2. **Available plans** — cards from `GET /api/subscriptions/plans` (operator-defined ladder).
3. **Subscribe / Upgrade** — `POST /api/subscriptions/checkout` → redirect to Payment Processor Checkout (preferred) or embedded frame if CSP allows.
4. **Manage** — portal link from `POST /api/subscriptions/portal` (cancel, update card).
5. **PAYG section** — show balance, usage, and top-up only when `billing_mode === 'payg'`; collapse or hide when subscribed.

Return URL handling: mirror `resumePendingBillingCheckout` with `resumePendingSubscriptionCheckout` for `/?subscription=success&session_id=...`, session refresh, poll until active, strip query string.

CSP: if embedding checkout, add Payment Processor origin to `frame-src` (if different than BTCPayServer origin); redirect flow avoids this.

Playwright: mock plans + checkout APIs; assert billing panel shows plan storage; optional success-return flow test.

## Edge cases

| Scenario | Behavior |
|---|---|
| User over plan limit at downgrade/cancel | Block new uploads; allow download/delete/export |
| Admin `set-storage` while subscribed | Define precedence (see Precedence rules); document in admin CLI help |
| User with positive PAYG balance subscribes | Balance remains; meter paused; on cancel, meter resumes with existing balance |
| User `past_due` | Recommend upload block after grace; login + download allowed |
| Registration throttle / auto-approval | Unchanged; unrelated to subscriptions |
| Soft-deleted user | RESTRICT FK on subscriptions; handle cancel before delete |

## Testing (planned)

### Go unit tests

- Billing resolver: mode, limits, meter skip, PAYG cap skip when subscribed
- Webhook idempotency and state transitions
- Downgrade reverts storage limit
- `past_due` upload gate

### Shell e2e

New **`run_subscriptions`** group in `scripts/testing/e2e-test.sh` (after `run_payments`):

- Mock Payment Processor webhook server (parallel to `scripts/testing/btcpay-mock.go`)
- Subscribe test user → assert raised limit → assert upload allowed → cancel → assert revert
- Manual `subscriptions assign` path for environments without mock provider

### Playwright

Billing panel plans display; mocked checkout redirect; subscription success return URL.

## Build phases (recommended order)

1. **Schema + resolver + admin plan CRUD** — no payment provider; dogfood with `subscriptions assign`.
2. **Meter/storage integration** — wire `TickUser`, projection, upload gates; admin/CLI visibility.
3. **Frontend plans display** — read-only or manual-assign messaging.
4. **Payment processor checkout + webhooks** — subscribe, renew, cancel flows.
5. **E2e + Playwright + FAQ** — `docs/user-faq.md`, `.env.example`, deploy scripts.

## Documentation updates (when implemented)

| File | Change |
|---|---|
| `docs/wip/subscriptions.md` | Optional operator-focused detail spun out if this doc grows |
| `docs/wip/payments.md` | Cross-link: top-ups = PAYG; subscriptions = separate flow |
| `docs/user-faq.md` | Q&A prose: plans, cancel, what happens to files |
| `docs/api.md` | New endpoints |
| `docs/scripts-guide.md` | Admin CLI subscription commands |
| `.env.example` | New flags and Payment Processor vars |
| `scripts/dev-reset.sh`, deploy scripts | Sensible defaults per environment |

## Explicitly out of scope for v1

- Proration on mid-cycle plan changes
- Annual billing intervals
- Per-plan microcent rate overrides (subscriber "overage" metering)
- Margin / breakeven tables in code or config
- Crypto recurring subscriptions
- Automated storage purge on `past_due` (policy-only, like payments doc)
- Subscription purchase via `arkfile-client`
- Web admin UI (admin remains CLI-only by design)

## Status

**NOT STARTED.** Foundation prerequisites (1 GiB default, auto-approval, registration throttle, PAYG −$10 cap, billing meter, BTCPay top-ups, billing panel, `arkfile-admin billing` / `payments`) are implemented and e2e-verified as of June 2026. This document is the implementation plan for the next commercial layer.

## References

- `docs/wip/storage-credits-v2.md` — microcent meter, settlement, free baseline
- `docs/wip/payments.md` — BTCPay top-ups, 402 upload gate (PAYG)
- `docs/wip/alma-pay-server.md` — BTCPay/Stripe hosting on Alma Pay VPS
- `docs/wip/prod-prep/03-roadmap.md` — payments/billing sequencing note
- `handlers/billing_projection.go` — `/api/credits` projection
- `client/static/js/src/ui/billing.ts` — billing panel UI
- `cmd/arkfile-admin/billing_commands.go`, `payments_commands.go` — CLI patterns to mirror
