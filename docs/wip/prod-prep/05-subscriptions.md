# Subscription Plans and Entitlement Bridge Billing

Arkfile is a privacy-first file vault: usernames are pseudonymous, file data is client-side encrypted, and the server should learn as little as possible about who pays how. Subscription tiers add a fourth commercial layer on top of the existing storage cap, PAYG microcent meter, and BTCPay one-off top-ups already shipped for mid-2026 (1 GiB default marketed as "1.0 GB Free", auto-approval with admin override, registration throttling, PAYG negative-balance upload cap at −$10, and the billing/payments stack in `docs/wip/storage-credits-v2.md` and `docs/wip/payments.md`). Recurring card billing cannot be delegated to the BTCPay Stripe Payments plugin — that plugin adds fiat as a one-off payment method on BTCPay invoices, not pull-based monthly subscriptions. The chosen architecture keeps Arkfile free of payment-processor SDKs and native processor identifiers. Instead, a separate **Entitlement Bridge** service (planned at `billing.arkfile.net`) owns Stripe and any future processors (Adyen, Mollie, Worldpay, Square, etc.), converts processor lifecycle events into a single canonical entitlement protocol, and notifies Arkfile through one signed webhook. Arkfile stores only opaque `checkout_id` and `entitlement_ref` values plus local plan and status rows; usernames never leave the vault host in payment metadata. Operators define a plan catalog (name, display price, storage limit). Subscribed users get a raised effective storage cap and paused PAYG metering. Everyone else stays on the free baseline, hourly meter, and optional BTCPay top-ups. Private instances disable billing, PAYG, subscriptions, and payments independently.

## Relationship to existing billing and payments

Three commercial layers already exist in the codebase. Subscriptions add a fourth that must coexist without breaking the decouplings established in `docs/wip/payments.md`.

| Layer | Purpose today | Primary config |
|---|---|---|
| **Storage hard cap** | Upload blocked when usage exceeds effective limit | Per-user `users.storage_limit_bytes` (admin baseline, default 1 GiB); admin `set-storage` |
| **PAYG meter** | Hourly microcent accumulation, daily settlement into `user_credits` | `ARKFILE_BILLING_ENABLED`, `ARKFILE_BILLING_PAYG_ENABLED`, `billing_settings` |
| **Top-ups** | One-time balance credit via BTCPay invoice | `ARKFILE_PAYMENTS_ENABLED`, BTCPay Greenfield + webhook |
| **Subscription plan** | Flat monthly fee; raises effective storage cap; pauses PAYG meter while active | `ARKFILE_SUBSCRIPTIONS_ENABLED`, Entitlement Bridge URL + webhook secret |

Paying does **not** automatically raise storage unless the payment activates a **subscription plan** (or an admin runs `subscriptions assign`). Hard storage cap and credit balance remain separate gates. Upload soft-block at negative PAYG balance applies only when PAYG metering is active for that user.

## Three-host architecture

Commercial traffic splits across three hosts with narrow, explicit responsibilities. Arkfile never loads processor checkout scripts and never holds processor API keys for subscriptions.

```
┌─────────────────────────┐         ┌────────────────────────────┐         ┌──────────────┐
│  app.arkfile.net        │         │  billing.arkfile.net       │         │  Processors  │
│  (Arkfile)              │  HMAC   │  (Entitlement Bridge)      │  API    │  Stripe, …   │
│                         │◄───────►│                            │◄───────►│              │
│  username, files,       │         │  checkout_id join key      │         │              │
│  checkout_id,           │         │  entitlement_ref           │         │              │
│  entitlement_ref,       │         │  processor adapters        │         │              │
│  plan entitlement       │         │  cus_/sub_ etc. (bridge    │         │              │
│                         │         │  DB only, never in Arkfile)│         │              │
└─────────────────────────┘         └────────────────────────────┘         └──────────────┘

┌─────────────────────────┐
│  pay.arkfile.net        │   Unchanged: BTCPay one-off invoices for PAYG balance top-ups.
│  (BTCPay)               │   Metadata carries opaque `invoice_id` only (see `payments/btcpay.go`).
└─────────────────────────┘
```

| Host | Knows | Must not know |
|---|---|---|
| **Arkfile** | username, plan catalog, entitlement status, storage, meter state | Processor customer/subscription IDs, card data, processor webhooks |
| **Entitlement Bridge** | processor objects, checkout sessions, `checkout_id`, `entitlement_ref` | Usernames, file data, OPAQUE secrets |
| **BTCPay** | one-off invoice amounts, opaque `invoice_id` in metadata | Same as today; not used for recurring subscription lifecycle |

The BTCPay Stripe Payments plugin remains in scope **only** for fiat settlement on BTCPay top-up invoices. BTCPay native subscriptions (credit-balance or manual renewal) are not the v1 subscription backend. Recurring card pull billing lives entirely on the Entitlement Bridge.

## Privacy and identity correlation

Arkfile's privacy posture depends on minimizing what payment systems can correlate back to vault accounts.

**Opaque checkout linking.** When a user starts checkout, Arkfile creates a local `subscription_checkouts` row with a random `checkout_id` (`subchk_<uuid>`). Only that opaque ID crosses to the bridge and, through the bridge, into processor metadata. Usernames are never placed in bridge tokens, processor metadata, or callback payloads. This mirrors the existing top-up pattern where BTCPay invoice metadata carries only `invoice_id` while `payment_invoices.username` stays local.

**What Arkfile stores.** `checkout_id` and `entitlement_ref` (`ent_<uuid>`) are the only payment-side identifiers in the Arkfile database. No `cus_*`, `sub_*`, or processor price IDs.

**Residual exposure (document honestly).** Card subscribers opt into processor-side financial identity. Hosted checkout pages on the bridge or processor may invite the user to enter an email for receipts. Arkfile must not pre-fill email or real names into bridge start tokens. An operator with access to both Arkfile and bridge databases could manually join `checkout_id` to username; mitigate with separate VPS credentials, minimal staff access, and separate audit trails. Crypto PAYG top-ups via BTCPay remain the higher-privacy funding path. Card subscriptions are a user-opt-in convenience tier, not a zero-knowledge payment path. See persona notes in `docs/AGENTS.md` (cross-border records, self-hosted operator).

## Product model

### Free / PAYG (default)

Every new user gets immediate access (auto-approval when configured) with:

- **Admin baseline storage** default **1 GiB** (`1073741824`), overridable per user via `arkfile-admin set-storage`.
- **Free baseline for metering:** 1 GiB (`ARKFILE_FREE_STORAGE_BYTES` / `Billing.FreeBaselineBytes`) — storage at or below this is not billable on PAYG.
- When PAYG is enabled: hourly tick, daily sweep, signed microcent balance, BTCPay top-ups, upload blocked at balance ≤ −$10 (configurable via `ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD`).
- Login and download remain available when upload-blocked for negative PAYG balance.

### Subscription

User selects a plan from the operator-defined catalog. While entitlement status is **active** or **trialing**:

- **Effective storage cap** is the higher of admin baseline and plan limit (see Storage limit source of truth). `users.storage_limit_bytes` is not mutated.
- **PAYG metering is off** — flat monthly fee covers storage up to the plan limit; no new `usage` rows while subscribed.
- User is **not** subject to the PAYG negative-balance upload cap.

When entitlement **ends** (cancel, expiry, failed payment after grace):

- Effective cap reverts to admin baseline only. PAYG meter resumes if instance PAYG is enabled. Existing PAYG balance is unchanged.

### Operator pricing intent (marketing, not code)

Hosted offerings may tier from roughly **250 GB at the low end** to **20 TB at the high end**, with lower tiers priced at a higher effective $/TB and higher tiers approaching infrastructure cost assumptions (~$15/TiB/month for dual-backend replication). Competitor research (Proton, MEGA, SpiderOak) informs positioning only; the codebase stores operator-editable plan rows, not margin tables. Differentiators to emphasize in copy (not in schema): dual object-storage backends, export/portability, open source.

### v1 billing-mode decision (locked)

**v1:** subscription = **flat fee + storage limit + meter paused**. No per-plan microcent rates, no subscriber overage metering, no proration, no annual intervals, no crypto recurring subscriptions, no automated purge on `past_due`.

**Deferred:** plan-specific PAYG rate overrides, proration, annual billing, BTCPay-native subscriptions as an alternative backend, automated storage purge on `past_due` (policy-only, like `docs/wip/payments.md`).

## Storage limit source of truth

Storage limits confused operators when subscribe/cancel logic mutated `users.storage_limit_bytes` or stashed revert columns. v1 uses a single computed model that is easy to explain without reading Go.

**Admin baseline (`users.storage_limit_bytes`).** Set at registration (default 1 GiB) and changed only by `arkfile-admin set-storage`. Never modified by subscribe, cancel, or webhooks.

**Plan limit (`subscription_plans.storage_limit_bytes`).** Operator-defined entitlement for each catalog row.

**Effective upload cap (computed, never stored).**

```
if subscription status in (active, trialing):
    effective = max(users.storage_limit_bytes, plan.storage_limit_bytes)
else:
    effective = users.storage_limit_bytes
```

All upload gates call `EffectiveStorageLimit(username)`. `CheckStorageAvailable` uses the effective value, not the raw column alone.

**Operator mental model (three sentences).**

1. Every user has a **baseline storage cap** (default 1.0 GB Free). Change it with `arkfile-admin set-storage`.
2. If they have an **active paid plan**, their cap is the **higher of** baseline and plan size — visible in `arkfile-admin subscriptions show --user`.
3. **PAYG metering** runs only when they are not on an active plan; topping up balance (BTCPay) is separate from plan storage.

**Example CLI output shape for `subscriptions show --user`:**

```
User: alice
  Baseline storage (admin):     1.0 GB
  Entitlement:                  active (ent_a8f3… via bridge)
  Plan:                         500 GB ($9/mo) until 2026-07-26
  Effective upload cap:         500 GB
  Billing mode:                 subscribed (PAYG meter paused)
  PAYG balance:                 $3.42 (unchanged)
  Last checkout:                subchk_91c2… (completed)
```

## Precedence rules

Gates are evaluated in this order. Document and implement consistently.

1. **`is_approved`** — unchanged; unapproved users blocked regardless of plan.
2. **Storage hard cap** — `EffectiveStorageLimit` as defined above.
3. **Subscription `past_due`** — after operator-configured grace from bridge `entitlement.past_due` event: block uploads; login and download/delete/export remain allowed.
4. **PAYG meter** — skip `TickUser` when user has active or trialing subscription and instance subscriptions enabled.
5. **Free baseline in projection** — for subscribed users, treat effective free baseline as plan storage limit so `billable_bytes = 0` in UI while under cap.
6. **PAYG upload cap (402)** — apply only when `ShouldApplyPaygUploadCap` is true (PAYG active, not subscribed).

**Mid-period PAYG accumulator.** When a user subscribes while PAYG metering has unbilled microcents in `storage_usage_accumulator`, run a **final partial tick and sweep for that user** before pausing the meter. Fair to the operator; one-time transition cost for the user.

## Entitlement Bridge Protocol v1

The bridge and Arkfile communicate through one canonical protocol. Any processor adapter inside the bridge (Stripe v1, others later) must emit these events. Arkfile implements only this contract — not Stripe, Adyen, or Mollie webhooks directly.

### Outbound: user starts checkout (Arkfile → browser → bridge)

1. User `POST /api/subscriptions/checkout` with `{ "plan_id": "..." }`.
2. Arkfile inserts `subscription_checkouts` (`checkout_id`, `username`, `plan_id`, `status=pending`).
3. Arkfile returns `{ "checkout_url": "https://billing.arkfile.net/v1/start?token=..." }`.
4. Token is HMAC-signed by Arkfile (shared secret with bridge): `{ checkout_id, plan_id, exp, return_url }` — **no username**.
5. Bridge validates token, maps `plan_id` to processor SKU in bridge config, creates hosted checkout with processor metadata `{ "checkout_id": "<id>" }` only.
6. User completes payment on bridge/processor hosted pages. User may optionally enter email on those pages; Arkfile does not supply it.

### Inbound: entitlement lifecycle (bridge → Arkfile)

Single endpoint: `POST /api/webhooks/entitlements`

Header: `Entitlement-Bridge-Signature: t=<unix>,v1=<hmac_sha256_hex>` over raw body (timestamp + HMAC, replay window ~5 minutes).

```json
{
  "protocol": "entitlement-bridge",
  "version": 1,
  "event_id": "evt_uuid",
  "event_type": "entitlement.activated",
  "checkout_id": "subchk_...",
  "entitlement_ref": "ent_...",
  "plan_id": "plan_500gb",
  "status": "active",
  "current_period_start": "2026-06-26T00:00:00Z",
  "current_period_end": "2026-07-26T00:00:00Z",
  "cancel_at_period_end": false,
  "processor_family": "stripe",
  "occurred_at": "2026-06-26T12:00:00Z"
}
```

| `event_type` | Arkfile action |
|---|---|
| `entitlement.activated` | Link `entitlement_ref` to checkout row; upsert `user_subscriptions` with status `active` or `trialing` |
| `entitlement.renewed` | Extend `current_period_end` (and `current_period_start` if provided) |
| `entitlement.past_due` | Set status `past_due`; start grace timer for upload block |
| `entitlement.canceled` | Set `cancel_at_period_end` or immediate cancel per payload |
| `entitlement.expired` | Set status `expired`; meter resumes |
| `entitlement.plan_changed` | Update `plan_id` (v1: apply immediately) |

**Lookup:** prefer `entitlement_ref` when present; on first activation, fall back to `checkout_id` → local checkout row → username.

**Idempotency:** insert `subscription_events` keyed on `event_id`; duplicate events are no-ops.

`processor_family` (`stripe`, `adyen`, etc.) is an optional log label for operators. It is not a join key and not stored as a foreign identifier.

### Portal (manage / cancel / update payment method)

1. User `POST /api/subscriptions/portal` (authenticated).
2. Arkfile reads `entitlement_ref` from active subscription (never sends username to bridge).
3. Arkfile returns `{ "portal_url": "https://billing.arkfile.net/v1/portal?token=..." }` where token is HMAC-signed `{ entitlement_ref, exp, return_url }`.
4. Bridge creates processor portal session and redirects user.

### Sync (reconcile missed webhooks)

Arkfile scheduler or `arkfile-admin subscriptions sync --user` calls bridge:

`GET https://billing.arkfile.net/v1/entitlements/{entitlement_ref}` with HMAC auth.

Response uses the same field shape as callback payloads (without `event_id`). Arkfile reconciles local status and period dates. Bridge is source of truth for payment state; Arkfile is source of truth for storage and meter behavior.

## Multi-processor strategy

Processor diversity is isolated inside the Entitlement Bridge. Arkfile never imports processor SDKs for subscriptions and never stores processor-native IDs.

**Plan SKU mapping on the bridge.** Arkfile's `subscription_plans.plan_id` (e.g. `plan_500gb`) is the only commercial SKU in the vault database. Bridge configuration maps each `plan_id` to processor-specific offers:

```yaml
# bridge config (not in Arkfile repo)
plans:
  plan_500gb:
    stripe_price_id: price_...
  plan_1tb:
    mollie_product_id: ...
```

Adding Adyen or Square later means a new bridge adapter and config lines — zero Arkfile schema or API changes.

**v1 processor target:** Stripe Billing via bridge adapter. Other processors are documented as supported-by-bridge, not by Arkfile.

## Instance toggles

Split commercial modes so private and gratis instances can disable layers independently.

| Variable | When true |
|---|---|
| `ARKFILE_BILLING_ENABLED` | Master switch: scheduler runs; billing APIs respond; projection in `/api/credits` |
| `ARKFILE_BILLING_PAYG_ENABLED` (new) | Hourly meter + daily sweep + PAYG negative upload cap |
| `ARKFILE_SUBSCRIPTIONS_ENABLED` (new) | Plan catalog, checkout redirect, entitlement webhook, subscription UI |
| `ARKFILE_PAYMENTS_ENABLED` | BTCPay one-off top-ups (existing) |

Suggested defaults: **private / gratis** — all false. **Hosted PAYG-only** — billing + PAYG + payments on, subscriptions off. **Hosted with tiers** — all relevant flags on.

Startup validation when subscriptions enabled: require `ARKFILE_ENTITLEMENT_BRIDGE_URL` and `ARKFILE_ENTITLEMENT_BRIDGE_WEBHOOK_SECRET`. Do **not** require processor API keys on Arkfile.

## Configuration

### Arkfile (`.env.example`)

```
ARKFILE_SUBSCRIPTIONS_ENABLED=false
ARKFILE_ENTITLEMENT_BRIDGE_URL=https://billing.arkfile.net
ARKFILE_ENTITLEMENT_BRIDGE_WEBHOOK_SECRET=
ARKFILE_SUBSCRIPTION_RETURN_URL=          # default: app origin /?subscription=return
```

No Stripe, Adyen, Mollie, or Worldpay keys on the Arkfile host.

### Entitlement Bridge (separate VPS, out of Arkfile repo for v1)

Bridge holds processor credentials, plan SKU mapping, bridge database, and adapter code. Deployment follows the same isolation principles as `docs/wip/alma-pay-server.md` (dedicated unprivileged runtime user, Caddy TLS, rootless Podman). Full bridge service specification: `docs/wip/entitlement-bridge.md`. This document defines the Arkfile-side consumer contract only.

## Database schema (planned)

Add to `database/unified_schema.sql` with migration helpers in `main.go` for existing databases.

### `subscription_plans`

Operator catalog. Not seeded with fixed tiers in code — operator creates rows via admin CLI or seed script per deployment. Display price in USD cents for human-friendly editing; bridge owns processor price mapping.

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
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);
```

No `provider_price_id` or processor SKU columns on Arkfile.

### `subscription_checkouts`

Opaque checkout attempts. Parallel to `payment_invoices` for top-ups.

```sql
CREATE TABLE IF NOT EXISTS subscription_checkouts (
    checkout_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'completed', 'expired', 'canceled')),
    entitlement_ref TEXT UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_subscription_checkouts_username
    ON subscription_checkouts(username);
CREATE INDEX IF NOT EXISTS idx_subscription_checkouts_entitlement_ref
    ON subscription_checkouts(entitlement_ref);
```

### `user_subscriptions`

One logical active subscription per user; history via `subscription_events` and status transitions.

```sql
CREATE TABLE IF NOT EXISTS user_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    checkout_id TEXT NOT NULL,
    entitlement_ref TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'active', 'past_due', 'canceled', 'expired', 'trialing'
    )),
    source TEXT NOT NULL CHECK (source IN ('bridge', 'manual')),
    current_period_start DATETIME NOT NULL,
    current_period_end DATETIME NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT 0,
    canceled_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id) ON DELETE RESTRICT,
    FOREIGN KEY (checkout_id) REFERENCES subscription_checkouts(checkout_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_username ON user_subscriptions(username);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_status ON user_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_entitlement_ref ON user_subscriptions(entitlement_ref);
```

`source = manual` for operator comp/grant via `subscriptions assign` (synthetic `entitlement_ref` e.g. `ent_manual_<uuid>`, no bridge involved).

No `provider_customer_id`, `provider_subscription_id`, or processor columns.

### `subscription_events`

Webhook idempotency and audit (mirror `payment_invoices` + BTCPay webhook replay protection).

```sql
CREATE TABLE IF NOT EXISTS subscription_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    entitlement_ref TEXT,
    checkout_id TEXT,
    username TEXT,
    plan_id TEXT,
    payload_hash TEXT NOT NULL,
    processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Ledger interaction

Subscription charges stay **out of** `user_credits` / `credit_transactions` for v1. PAYG balance remains the microcent wallet for non-subscribers. Payment history lives in bridge/processor dashboards plus `subscription_events`. Optional later: `transaction_type = subscription` for billing panel visibility.

## Backend: billing resolver

Central resolver functions (e.g. `billing/subscription.go` + `billing/effective.go`):

| Function | Returns |
|---|---|
| `EffectiveBillingMode(username)` | `free`, `payg`, or `subscribed` |
| `EffectiveStorageLimit(username)` | Bytes for hard cap |
| `EffectiveFreeBaseline(username)` | Bytes for meter/projection |
| `ShouldMeter(username)` | Whether `TickUser` applies |
| `ShouldApplyPaygUploadCap(username)` | Whether 402 gate applies |

Wire into:

- `billing/meter.go` — `TickUser` / `TickAllActiveUsers`
- `handlers/billing_projection.go` — add `subscription` block to `/api/credits`
- `handlers/uploads.go` — storage cap and PAYG cap guards
- `billing/scheduler.go` — optional entitlement reconcile tick (daily or piggyback on sweep)

Extend `buildBillingProjection` response:

```json
{
  "subscription": {
    "enabled": true,
    "status": "active",
    "plan_id": "plan_500gb",
    "plan_name": "500 GB",
    "price_usd": "9.00",
    "baseline_storage_bytes": 1073741824,
    "plan_storage_bytes": 536870912000,
    "effective_storage_limit_bytes": 536870912000,
    "current_period_end": "2026-07-26T00:00:00Z",
    "cancel_at_period_end": false
  },
  "billing_mode": "subscribed"
}
```

When subscriptions disabled globally, omit or null the block (same pattern as `payments` in `/api/credits`). Do not expose raw `entitlement_ref` or `checkout_id` to the browser unless needed for return-URL polling; prefer status-only responses on public APIs.

## Backend: HTTP API (planned)

### Public / user (authenticated unless noted)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/subscriptions/plans` | List public active plans |
| GET | `/api/subscriptions/me` | Current user subscription + effective limits |
| POST | `/api/subscriptions/checkout` | Body: `{ "plan_id": "..." }` → bridge checkout URL |
| POST | `/api/subscriptions/portal` | Bridge portal URL for manage/cancel |

### Admin (`/api/admin/...`, existing admin MFA stack)

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/admin/subscriptions/plans` | List / create / update plans |
| GET | `/api/admin/subscriptions/users/:username` | Subscription detail + checkout history |
| POST | `/api/admin/subscriptions/users/:username/assign` | Manual grant (`source=manual`) |
| POST | `/api/admin/subscriptions/users/:username/cancel` | Force local cancel (bridge cancel is separate ops) |
| POST | `/api/admin/subscriptions/users/:username/sync` | Poll bridge for `entitlement_ref` |
| POST | `/api/admin/subscriptions/reconcile` | Bulk sync active entitlements nearing expiry |

### Webhooks

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/webhooks/entitlements` | Entitlement Bridge lifecycle (HMAC signed) |

Register only when subscriptions enabled. No per-processor webhook routes on Arkfile.

There is no public API to activate a subscription by username. All bridge activations resolve through `checkout_id` or `entitlement_ref` locally.

## Lifecycle and robustness

Webhook delivery is the primary path; reconcile is part of normal operations, not an emergency-only tool (same philosophy as `docs/wip/payments.md` for BTCPay).

| Source | When |
|---|---|
| Bridge webhook | Real-time entitlement changes |
| Scheduler reconcile | Daily: rows with `current_period_end` within window or past; call bridge GET |
| Admin sync/reconcile | Manual repair after bridge or network outage |

| Local status | Upload | Meter | Notes |
|---|---|---|---|
| `trialing`, `active` | Allowed to effective cap | Off | |
| `past_due` | Block after grace | Off until expired | Login/download OK |
| `canceled` (at period end) | Allowed until `current_period_end` | Off until end | |
| `expired`, `canceled` (immediate) | Baseline cap only | On if PAYG enabled | |

On subscribe transition to active: run partial PAYG sweep for that user, then pause meter.

## arkfile-admin (planned)

New command group **`subscriptions`** (alongside `billing` and `payments`):

| Command | Purpose |
|---|---|
| `subscriptions list-plans [--json]` | Catalog |
| `subscriptions set-plan --plan-id ID --name NAME --price USD --storage LIMIT [--active]` | Create/update plan |
| `subscriptions show --user USER [--json]` | Baseline, plan, effective cap, entitlement summary |
| `subscriptions assign --user USER --plan-id ID [--period-days N]` | Manual comp/grant |
| `subscriptions cancel --user USER [--immediate]` | Operator local cancel |
| `subscriptions sync --user USER` | Poll bridge by `entitlement_ref` |
| `subscriptions reconcile` | Bulk sync |

Extend **`billing show --user`** and **`user-status`** to include subscription summary when enabled.

No user-facing purchase flow in admin CLI — users subscribe via the web UI.

## arkfile-client (planned)

Minimal v1 surface:

- Optional **`subscription status`** — plan, renewal date, effective storage limit from `/api/subscriptions/me`.
- No checkout in CLI unless power-user demand appears later.

PAYG **`billing`** subcommands remain unchanged for operators.

## TypeScript frontend (planned)

Extend `client/static/js/src/ui/billing.ts` and billing panel markup.

### When subscriptions disabled

No change beyond current balance, usage projection, transaction history, and top-up modal.

### When subscriptions enabled

1. **Your plan** — plan name, price, renewal date, used/effective storage limit from `/api/credits`.
2. **Available plans** — cards from `GET /api/subscriptions/plans`.
3. **Subscribe / Upgrade** — `POST /api/subscriptions/checkout` → **redirect** to bridge URL (no processor scripts in Arkfile).
4. **Manage** — `POST /api/subscriptions/portal` → redirect to bridge portal.
5. **PAYG section** — balance, usage, top-up only when `billing_mode === 'payg'`; collapsed when subscribed.

Return URL: `resumePendingSubscriptionCheckout` for `/?subscription=return&checkout_id=...` — session refresh, poll `/api/subscriptions/me` until active, strip query string. Mirror `resumePendingBillingCheckout` in `billing.ts`.

Redirect-only checkout avoids adding bridge origin to CSP `frame-src`. BTCPay origin remains for top-up iframe only.

Playwright: mock plans and checkout APIs; assert effective storage in billing panel; optional return-URL flow.

## Edge cases

| Scenario | Behavior |
|---|---|
| User over plan limit at downgrade/cancel | Block new uploads; allow download/delete/export |
| Admin `set-storage` while subscribed | Effective cap = max(new baseline, plan); no mutation on subscribe/cancel |
| User with positive PAYG balance subscribes | Balance remains; partial sweep then meter paused |
| User `past_due` | Upload block after grace; login + download allowed |
| Registration throttle / auto-approval | Unchanged |
| Soft-deleted user | RESTRICT FK; cancel entitlement before delete |
| Bridge reachable but webhook missed | Reconcile/sync repairs local state |
| Manual assign | Synthetic `entitlement_ref`; no bridge call |

## Testing (planned)

### Go unit tests

- Billing resolver: mode, effective limits, meter skip, PAYG cap skip when subscribed
- Entitlement webhook signature verification and idempotency
- State transitions for each `event_type`
- `past_due` upload gate after grace
- Manual assign path

### Shell e2e

New **`run_subscriptions`** group in `scripts/testing/e2e-test.sh` (after `run_payments`):

- Mock Entitlement Bridge (`scripts/testing/entitlement-bridge-mock.go`, parallel to `btcpay-mock.go`)
- Checkout → signed webhook `entitlement.activated` → assert effective limit → upload OK
- `entitlement.expired` → revert to baseline cap
- Manual `subscriptions assign` without mock bridge

### Playwright

Billing panel plans display; mocked checkout redirect; subscription return URL polling.

## Build phases (recommended order)

1. **Schema + resolver + admin plan CRUD** — no bridge; dogfood with `subscriptions assign`.
2. **Meter/storage integration** — wire `TickUser`, projection, upload gates; admin/CLI breakdown output.
3. **Frontend plans display** — read-only or manual-assign messaging.
4. **Entitlement webhook + checkout redirect** — mock bridge in e2e.
5. **Entitlement Bridge VPS + Stripe adapter** — live `billing.arkfile.net` (separate repo/service).
6. **E2e + Playwright + FAQ** — `docs/user-faq.md`, `.env.example`, deploy scripts.

## Documentation updates (when implemented)

| File | Change |
|---|---|
| `docs/wip/entitlement-bridge.md` | Bridge service spec, deployment, processor adapters |
| `docs/wip/payments.md` | Cross-link: top-ups = BTCPay PAYG; subscriptions = Entitlement Bridge |
| `docs/user-faq.md` | Q&A prose: plans, cancel, what happens to files |
| `docs/api.md` | New endpoints |
| `docs/scripts-guide.md` | Admin CLI subscription commands |
| `.env.example` | Subscriptions + bridge vars (no processor keys) |
| `scripts/dev-reset.sh`, deploy scripts | Sensible defaults per environment |

## Explicitly out of scope for v1

- Processor SDKs or API keys on the Arkfile host
- Storing processor-native IDs (`cus_*`, `sub_*`, etc.) in Arkfile
- BTCPay Stripe plugin or BTCPay native subscriptions as the subscription backend
- Per-processor webhook routes on Arkfile (`/api/webhooks/stripe`, etc.)
- Proration, annual billing, subscriber overage metering
- Margin / breakeven tables in code or config
- Crypto recurring subscriptions
- Automated storage purge on `past_due`
- Subscription purchase via `arkfile-client`
- Web admin UI (admin remains CLI-only by design)
- Mutating `users.storage_limit_bytes` on subscribe/cancel

## Status

**NOT STARTED.** Foundation prerequisites (1 GiB default, auto-approval, registration throttle, PAYG −$10 cap, billing meter, BTCPay top-ups, billing panel, `arkfile-admin billing` / `payments`) are implemented and e2e-verified as of June 2026. This document is the implementation plan for the subscription and Entitlement Bridge layer.

## References

- `docs/AGENTS.md` — privacy-first design, personas, threat models
- `docs/wip/storage-credits-v2.md` — microcent meter, settlement, free baseline
- `docs/wip/payments.md` — BTCPay top-ups, opaque `invoice_id`, reconcile model
- `docs/wip/alma-pay-server.md` — BTCPay hosting on Alma/Podman (pay host)
- `docs/wip/entitlement-bridge.md` — bridge service spec, Stripe adapter, deployment
- `docs/wip/prod-prep/03-roadmap.md` — commercial layer sequencing
- `handlers/billing_projection.go` — `/api/credits` projection
- `client/static/js/src/ui/billing.ts` — billing panel UI
- `payments/btcpay.go` — opaque metadata pattern for top-ups
- `cmd/arkfile-admin/billing_commands.go`, `payments_commands.go` — CLI patterns to mirror
