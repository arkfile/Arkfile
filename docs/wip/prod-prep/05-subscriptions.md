# Subscription Plans and Subscription Bridge Billing

Arkfile is a privacy-first file vault: usernames are pseudonymous, file data is client-side encrypted, and the server should learn as little as possible about who pays how. Subscription tiers add a fourth commercial layer on top of the existing storage cap, PAYG microcent meter, and BTCPay one-off top-ups already shipped for mid-2026 (1 GiB default marketed as "1.0 GB Free", auto-approval with admin override, registration throttling, PAYG negative-balance upload cap at -$10, and the billing/payments stack in `docs/wip/storage-credits-v2.md` and `docs/wip/payments.md`). Recurring card billing cannot be delegated to the BTCPay Stripe Payments plugin — that plugin adds fiat as a one-off payment method on BTCPay invoices, not pull-based monthly subscriptions. The chosen architecture keeps Arkfile free of payment-processor SDKs and native processor identifiers. Instead, a separate **Subscription Bridge** service (planned at `billing.arkfile.net`) owns Stripe and any future processors (Adyen, Mollie, Worldpay, Worldline, Square, etc.), converts processor lifecycle events into the **Subscription Bridge Protocol v1**, and notifies Arkfile through one signed webhook. Arkfile stores only opaque `checkout_id` and `subscription_ref` values plus local plan and status rows; usernames never leave the vault host in payment metadata. Operators define a plan catalog (name, display price, storage limit). Subscribed users get a raised effective storage cap and paused PAYG metering. Everyone else stays on the free baseline, hourly meter, and optional BTCPay top-ups. Private or self-hosted instances may choose to disable billing, PAYG, subscriptions, and payments independently, if they so desire.

## Relationship to existing billing and payments

Three commercial layers already exist in the codebase. Subscriptions add a fourth that must coexist without breaking the decouplings established in `docs/wip/payments.md`.

| Layer | Purpose today | Primary config |
|---|---|---|
| **Storage hard cap** | Upload blocked when usage exceeds effective limit | Per-user `users.storage_limit_bytes` (admin baseline, default 1 GiB); admin `set-storage` |
| **PAYG meter** | Hourly microcent accumulation, daily settlement into `user_credits` | `ARKFILE_BILLING_ENABLED`, `ARKFILE_BILLING_PAYG_ENABLED`, `billing_settings` |
| **Top-ups** | One-time balance credit via BTCPay invoice | `ARKFILE_PAYMENTS_ENABLED`, BTCPay Greenfield + webhook |
| **Subscription plan** | Flat monthly fee; raises effective storage cap; pauses PAYG meter while active | `ARKFILE_SUBSCRIPTIONS_ENABLED`, Subscription Bridge URL + webhook secret |

Paying does **not** automatically raise storage unless the payment activates a **subscription plan** (paid via bridge checkout) or an operator runs **`subscriptions grant-gift-subscription`** (time-limited comp access, no processor). Hard storage cap and credit balance remain separate gates. Upload soft-block at negative PAYG balance applies only when PAYG metering is active for that user.

NOTE: During implementation, we should keep in mind we must maintain the ability of a user and the admin to agree to manually set a higher storage cap for a user who is willing and able to make one-time payments for the service and plans to keep a ~positive balance. E.g. user uses up the free 1 GB, contacts admin via contact info, requests storage cap increase to 10 GB, admin approves and directs user to make a PAYG payment, user balance stays positive for some time as they continue to add files; PAYG approach may continue like this indefinitely; users may always request a higher storage cap out of bounds (or separate from subscription plan system) as desired

## Three-host architecture

Commercial traffic splits across three hosts with narrow, explicit responsibilities. Arkfile never loads processor checkout scripts and never holds processor API keys for subscriptions.

```
┌─────────────────────────┐         ┌────────────────────────────┐         ┌──────────────┐
│  arkfile.net            │         │  billing.arkfile.net       │         │  Processors  │
│  (Arkfile app)          │  HMAC   │  (Subscription Bridge)      │  API    │  Stripe, …   │
│                         │◄───────►│                            │◄───────►│              │
│  username, files,       │         │  checkout_id join key      │         │              │
│  checkout_id,           │         │  subscription_ref           │         │              │
│  subscription_ref,       │         │  processor adapters        │         │              │
│  plan subscription       │         │  cus_/sub_ etc. (bridge    │         │              │
│                         │         │  DB only, never in Arkfile)│         │              │
└─────────────────────────┘         └────────────────────────────┘         └──────────────┘

┌─────────────────────────┐
│  pay.arkfile.net        │   Unchanged: BTCPay one-off invoices for PAYG balance top-ups.
│  (BTCPay)               │   Metadata carries opaque `invoice_id` only (see `payments/btcpay.go`).
└─────────────────────────┘
```

| Host | Knows | Must not know |
|---|---|---|
| **Arkfile** | username, plan catalog, subscription status, storage, meter state | Processor customer/subscription IDs, card data, processor webhooks |
| **Subscription Bridge** | processor objects, checkout sessions, `checkout_id`, `subscription_ref` | Usernames, file data, OPAQUE secrets |
| **BTCPay** | one-off invoice amounts, opaque `invoice_id` in metadata | Same as today; not used for recurring subscription lifecycle |

The BTCPay Stripe Payments plugin remains in scope **only** for fiat settlement on BTCPay top-up invoices. BTCPay native subscriptions (credit-balance or manual renewal) are not the v1 subscription backend. Recurring card pull billing lives entirely on the Subscription Bridge.

## Privacy and identity correlation

Arkfile's privacy posture depends on minimizing what payment systems can correlate back to vault accounts.

**Opaque checkout linking.** When a user starts checkout, Arkfile creates a local `subscription_checkouts` row with a random `checkout_id` (`subchk_<uuid>`). Only that opaque ID crosses to the bridge and, through the bridge, into processor metadata. Usernames are never placed in bridge tokens, processor metadata, or callback payloads. This mirrors the existing top-up pattern where BTCPay invoice metadata carries only `invoice_id` while `payment_invoices.username` stays local.

**What Arkfile stores.** `checkout_id` and `subscription_ref` (`sub_<uuid>`) are the only payment-side identifiers in the Arkfile database. No `cus_*`, `sub_*`, or processor price IDs.

**Residual exposure (document honestly).** Card subscribers opt into processor-side financial identity. Hosted checkout pages on the bridge or processor may invite the user to enter an email for receipts. Arkfile must not pre-fill email or real names into bridge start tokens. An operator with access to both Arkfile and bridge databases could manually join `checkout_id` to username; mitigate with separate VPS credentials, minimal staff access, and separate audit trails. Crypto PAYG top-ups via BTCPay remain the higher-privacy funding path. Card subscriptions are a user-opt-in convenience tier, not a zero-knowledge payment path. See persona notes in `docs/AGENTS.md` (cross-border records, self-hosted operator).

## Product model

### Free / PAYG (default)

Every new user gets immediate access (auto-approval when configured) with:

- **Admin baseline storage** default **1 GiB** (`1073741824`), overridable per user via `arkfile-admin set-storage`.
- **Free baseline for metering:** 1 GiB (`ARKFILE_FREE_STORAGE_BYTES` / `Billing.FreeBaselineBytes`) — storage at or below this is not billable on PAYG.
- When PAYG is enabled: hourly tick, daily sweep, signed microcent balance, BTCPay top-ups, upload blocked at balance ≤ −$10 (configurable via `ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD`).
- Login and download remain available when upload-blocked for negative PAYG balance.

### Subscription

User selects a plan from the operator-defined catalog. While subscription status is **active** or **trialing**:

- **Effective storage cap** is the higher of admin baseline and plan limit (see Storage limit source of truth). `users.storage_limit_bytes` is not mutated.
- **PAYG metering is off** — flat monthly fee covers storage up to the plan limit; no new `usage` rows while subscribed.
- User is **not** subject to the PAYG negative-balance upload cap.
- **BTCPay top-ups are not allowed** while subscribed (server, web UI, and `arkfile-client`).

When subscription **ends** (cancel, expiry, failed payment after grace):

- Effective cap reverts to admin baseline only. PAYG meter resumes if instance PAYG is enabled. Existing PAYG balance is unchanged.

### Operator pricing intent (marketing, not code)

Hosted offerings may tier from roughly **250 GB at the low end** to **20 TB at the high end**, with lower tiers priced at a higher effective $/TB and higher tiers approaching or even falling below infrastructure cost assumptions (~$15/TiB/month for dual-backend replication). Competitor research (Proton, MEGA, SpiderOak) informs positioning only; the codebase stores operator-editable plan rows, not margin tables. Differentiators to emphasize in copy (not in schema): dual object-storage backends, export/portability, fully open source backend and frontend, and secure file sharing capability.

### v1 billing-mode decision (locked)

**v1:** subscription = **flat fee + storage limit + meter paused**. No per-plan microcent rates, no subscriber overage metering, no proration, no annual intervals, no crypto recurring subscriptions, no automated purge on `past_due`.

**Deferred:** plan-specific PAYG rate overrides, proration, annual billing, BTCPay-native subscriptions as an alternative backend, automated storage purge on `past_due` (policy-only, like `docs/wip/payments.md`).

## How account billing works (operator guide)

This section is for billing staff, accounting, and sysadmins who need to understand behavior without reading application code. The tables below assume instance flags are on: billing, PAYG, subscriptions, and BTCPay top-ups.

Every account is in exactly one **billing mode** at a time (`billing_mode` on `/api/credits`: `free`, `payg`, or `subscribed`). Mode controls whether usage is metered by the hour, whether the user pays through a prepaid **balance**, or whether they are on a fixed **subscription plan**.

### Two payment channels (do not mix them on the ledger)

**Prepaid PAYG balance** lives in Arkfile (`user_credits`). Users add funds via BTCPay top-ups. Hourly usage accumulates and is deducted once per day (daily settlement). Subscription fees never post to this balance in v1.

**Subscription plan fees** are billed by the Subscription Bridge and card processor (`billing.arkfile.net`). Plan payments do not increase or decrease the PAYG balance. Receipt history for subscriptions is on the processor or bridge side, not in `credit_transactions`.

### Billing modes

| Billing mode (`billing_mode`) | Typical user | Storage paid via | Hourly usage charges | BTCPay top-up |
|---|---|---|---|---|
| **Free** | Within 1.0 GB Free tier | Included | No (usage at or below free baseline is not metered) | Allowed (optional; builds balance for later PAYG use) |
| **Pay-as-you-go (PAYG)** | Above free tier, no active plan | Prepaid balance | **Yes** (hourly meter, daily settlement) | **Allowed** |
| **Subscribed** | Active or trial plan | Flat monthly plan fee (bridge) | **No** (usage meter paused) | **Not allowed** |

While **Subscribed**, any existing PAYG balance remains on the account but is **frozen**: no new usage charges are applied and no new top-ups are accepted until the subscription ends.

### Worked example

Alice registers and receives 1.0 GB Free. She uploads 30 GB and tops up $20 via BTCPay. She is in **PAYG** mode: the hourly meter runs and daily settlement draws from her balance. She subscribes to a 500 GB monthly plan. The system runs a **final usage settlement** for any pending charges, then **pauses the meter**. Her $20 balance stays on file but is not spent while subscribed; **top-ups are blocked**. She manages renewal and payment method on the billing subdomain. When the plan expires or she cancels, she returns to **PAYG** (or **Free** if back within 1 GB): the meter resumes, top-ups work again, and her $20 balance is available for usage charges as before.

### Admin PAYG without subscription (unchanged)

Operators may still grant a higher **baseline storage cap** via `arkfile-admin set-storage` and direct a user to maintain a positive PAYG balance without any subscription plan. That path stays independent of the subscription catalog (see NOTE under Relationship to existing billing and payments).

### Gift subscriptions (operator-granted, no payment)

**Gift subscriptions** are time-limited plan subscriptions created only on Arkfile (`source = gift`). They use the same meter pause, effective storage cap, and top-up block rules as paid subscriptions while active, but **never touch the Subscription Bridge or a payment processor**.

| Action | Command / path |
|---|---|
| Grant comp / beta / influencer access | `arkfile-admin subscriptions grant-gift-subscription --user USER --plan-id ID [--days N] [--note "..."]` |
| End a gift early | `arkfile-admin subscriptions cancel-gift-subscription --user USER [--immediate]` |
| Inspect | `arkfile-admin subscriptions show --user USER` (shows `source: gift` vs `bridge`) |

**Duration (locked).** Default **30 days** when `--days` is omitted. Maximum **90 days** per grant (`--days` validated server-side; requests above 90 return **400**). Gifts do not auto-renew; when `current_period_end` passes, status becomes `expired` and PAYG resumes.

**One active subscription per user.** `grant-gift-subscription` is rejected (**409**) if the user already has an active or trialing subscription with `source = bridge` (or an active gift — extend by canceling the gift first or wait for expiry).

**No admin cancel for paid plans.** Arkfile admin **must not** expose a command that revokes local subscription for bridge-backed subscriptions without canceling at the processor. That pattern invites sysadmin misuse (vault access removed while Stripe keeps charging). Paid lifecycle changes happen only through:

1. **User self-service** — web billing panel or `arkfile-client subscription portal` (bridge → processor portal).
2. **Operator support** — cancel in the **Stripe dashboard** or bridge ops CLI (`bridge show-subscription`, processor dashboard); Arkfile picks up changes via subscription bridge webhooks or `subscriptions sync --user`.
3. **Verification** — `subscriptions show --user` and `subscriptions sync --user` after operator action.

There is no `arkfile-admin subscriptions cancel` for paid subscriptions.

## PAYG and metering gating matrix

When a user starts or stops a subscription plan, the behaviors in this table turn on or off together. Implementation uses one billing resolver; operators and support staff can use this table to answer “why is this user being charged?” or “why was top-up rejected?”

**Instance prerequisites:** `ARKFILE_BILLING_ENABLED` and `ARKFILE_BILLING_PAYG_ENABLED` must both be true for any PAYG metering or PAYG upload cap to apply. Per-user subscription state then further gates each row.

| Mechanism | Free (within free tier) | PAYG | Subscribed (active / trial) | Subscribed (past due, in grace) | After subscription ends |
|---|---|---|---|---|---|
| Hourly usage meter | Off (nothing to bill at/below baseline) | **On** | **Off** | **Off** | **On** if still above baseline |
| Daily settlement (balance debit) | Off | **On** | **Off** | **Off** | **On** |
| PAYG balance decreases from usage | No | Yes | **No** | **No** | Yes |
| BTCPay top-up | Allowed | Allowed | **Blocked** | **Blocked** | Allowed |
| Upload blocked at −$10 PAYG cap | No (not in PAYG debt mode) | Yes, if balance that low | **No** (cap not applied) | **No** | Yes, if PAYG and balance that low |
| Upload blocked for storage cap | Yes | Yes | Yes (effective plan cap) | Yes (subscription past-due rules after grace) | Yes (baseline cap) |

**When user subscribes:** Run **`FinalizePaygBeforeSubscribe(username)`** once — final hourly charge if needed, then settle any pending accumulator into the balance. Then turn the meter off.

**When user unsubscribes or plan expires:** Meter and daily settlement resume on the next scheduler cycle. Balance is unchanged.

**Daily settlement rule:** `SweepAllUsers` (and any per-user settle helper) must **skip users where `ShouldMeter(username)` is false**. A subscribed user must never receive a usage debit from settlement. If a subscribed user still has pending accumulator rows, treat as incomplete transition — repair via admin tools, not silent billing.

## Client parity (web app and arkfile-client)

Per `docs/AGENTS.md`, billing and subscriptions are an **important domain**: the browser billing panel and **`arkfile-client` must offer the same user-facing capabilities** and the same server-enforced rules (including top-up rejection while subscribed). Hosted checkout and portal flows open in the system browser from CLI; iframe embedding is web-only. Naming and behavior should mirror each other (e.g. web “Top Up Balance” ↔ `arkfile-client billing top-up`).

Implement web and CLI billing/subscription flows in the **same build phase**, not web-first with CLI deferred.

NOTE: As part of this subscriptions project, we must also make sure all required parity features are built out and verified working at least through unit/integration tests if not also through e2e tests for the billing side for arkfile-client. e.g. `arkfile-client billing top-up` must be built if missing or incomplete.

## Storage limit source of truth

Storage limits confused operators when subscribe/cancel logic mutated `users.storage_limit_bytes` or stashed revert columns. v1 uses a single computed model that is easy to explain without reading Go.

**Admin baseline (`users.storage_limit_bytes`).** Set at registration (default 1 GiB) and changed only by `arkfile-admin set-storage`. Never modified by subscribe, cancel, or webhooks.

**Plan limit (`subscription_plans.storage_limit_bytes`).** Operator-defined storage limit for each catalog row.

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
2. If they have an **active plan** (paid or gift), their cap is the **higher of** baseline and plan size — visible in `arkfile-admin subscriptions show --user`.
3. **PAYG metering** runs only when they are not on an active plan. **Top-ups (BTCPay) are only for PAYG/Free** — not while subscribed.

**Example CLI output shape for `subscriptions show --user` (paid):**

```
User: alice
  Baseline storage (admin):     1.0 GB
  Subscription:                 active (sub_a8f3… via bridge)
  Plan:                         500 GB ($9/mo) until 2026-07-26
  Effective upload cap:         500 GB
  Billing mode:                 subscribed (usage meter paused; top-ups disabled)
  PAYG balance:                 $3.42 (unchanged; frozen while subscribed)
  Last checkout:                subchk_91c2… (completed)
```

**Example (gift):**

```
User: bob
  Baseline storage (admin):     1.0 GB
  Subscription:                 active (sub_gift_c4… via gift)
  Plan:                         500 GB (gift, 22 days remaining)
  Effective upload cap:         500 GB
  Billing mode:                 subscribed (usage meter paused; top-ups disabled)
  Gift note:                    beta tester cohort A
```

## Precedence rules

Gates are evaluated in this order. Document and implement consistently.

1. **`is_approved`** — unchanged; unapproved users blocked regardless of plan.
2. **Storage hard cap** — `EffectiveStorageLimit` as defined above.
3. **Subscription `past_due`** — after operator-configured grace from bridge `subscription.past_due` event: block uploads; login and download/delete/export remain allowed.
4. **PAYG meter** — skip `TickUser` when user has active or trialing subscription and instance subscriptions enabled.
5. **Free baseline in projection** — for subscribed users, treat effective free baseline as plan storage limit so `billable_bytes = 0` in UI while under cap.
6. **PAYG upload cap (402)** — apply only when `ShouldApplyPaygUploadCap` is true (PAYG active, not subscribed).
7. **Top-ups** — reject `POST /api/billing/invoice` when subscription status is `active` or `trialing` (see Backend: HTTP API).

**Mid-period PAYG accumulator.** Covered by **When user subscribes** in the PAYG and metering gating matrix: `FinalizePaygBeforeSubscribe` runs a final partial tick and settlement before `ShouldMeter` becomes false.

## Subscription Bridge Protocol v1

The bridge and Arkfile communicate through one canonical, provider-neutral protocol. The complete v1 bridge includes Stripe and Adyen adapters. Arkfile implements only this contract — never provider webhooks directly.

### Outbound: user starts checkout (Arkfile → browser → bridge)

1. User `POST /api/subscriptions/checkout` with `{ "plan_id": "..." }`.
2. Arkfile inserts `subscription_checkouts` (`checkout_id`, `username`, `plan_id`, `status=pending`).
3. Arkfile returns `{ "checkout_url": "https://billing.arkfile.net/v1/start?token=..." }`.
4. Token is HMAC-signed with the HKDF-derived token key: `{ checkout_id, plan_id, return_url, iat, exp }` — **no username**. Its lifetime is at most 15 minutes. `plan_id` must be valid UTF-8, nonempty after Unicode whitespace trimming, and at most 128 UTF-8 bytes.
5. Bridge validates token, maps `plan_id` to processor SKU in bridge config, creates hosted checkout with processor metadata `{ "checkout_id": "<id>" }` only.
6. User completes payment on bridge/processor hosted pages. User may optionally enter email on those pages; Arkfile does not supply it.

### Inbound: subscription lifecycle (bridge → consumer app)

Single endpoint: `POST /api/webhooks/subscription-bridge`

Header: `Subscription-Bridge-Signature: t=<unix>,v1=<hmac_sha256_hex>` over raw body (timestamp + HMAC, replay window ~5 minutes).

```json
{
  "protocol": "subscription-bridge",
  "version": 1,
  "event_id": "evt_uuid",
  "event_type": "subscription.activated",
  "checkout_id": "subchk_...",
  "subscription_ref": "sub_...",
  "plan_id": "plan_500gb",
  "state_version": 1,
  "status": "active",
  "current_period_start": "2026-06-26T00:00:00Z",
  "current_period_end": "2026-07-26T00:00:00Z",
  "cancel_at_period_end": false,
  "state_changed_at": "2026-06-26T12:00:00Z"
}
```

| `event_type` | Arkfile action |
|---|---|
| `subscription.activated` | Run `FinalizePaygBeforeSubscribe`; link `subscription_ref`; upsert `user_subscriptions` with status `active` or `trialing` |
| `subscription.renewed` | Extend `current_period_end` (and `current_period_start` if provided) |
| `subscription.past_due` | Set status `past_due`; start grace timer for upload block |
| `subscription.canceled` | Set status `canceled` and `cancel_at_period_end=true`; access remains effective through `current_period_end` |
| `subscription.expired` | Set status `expired`; meter resumes |
| `subscription.plan_changed` | Update `plan_id` (v1: apply immediately) |

**Lookup:** prefer `subscription_ref` when present; on first activation, fall back to `checkout_id` → local checkout row → username.

**Idempotency and ordering:** JSON object key order is not canonical. Store the SHA-256 hash of the exact verified callback bytes, insert `subscription_events` keyed on `event_id`, reject reuse of an event ID with different bytes, and apply only a strictly newer `state_version`. Reconciliation snapshots use the same state transition path.

### Portal (manage / cancel / update payment method)

1. User `POST /api/subscriptions/portal` (authenticated).
2. Arkfile reads `subscription_ref` from active subscription (never sends username to bridge).
3. Arkfile returns `{ "portal_url": "https://billing.arkfile.net/v1/portal?token=..." }` where token is HMAC-signed `{ subscription_ref, return_url, iat, exp }`.
4. Bridge creates processor portal session and redirects user.

### Sync (reconcile missed webhooks)

Arkfile scheduler or `arkfile-admin subscriptions sync --user` calls bridge:

`GET https://billing.arkfile.net/v1/subscriptions/{subscription_ref}` with HMAC auth.

The response has the exact snapshot schema in `docs/wip/subscription-bridge.md`: the callback state fields without `event_id` and `event_type`. Arkfile strictly decodes it, retains the exact response bytes for its audit hash, and applies it through the same ordered state transition path as callbacks. Bridge is source of truth for payment state; Arkfile is source of truth for storage and meter behavior.

## Multi-processor strategy

Processor diversity is isolated inside the Subscription Bridge. Arkfile never imports processor SDKs for subscriptions and never stores processor-native IDs.

**Plan SKU mapping on the bridge.** Arkfile's `subscription_plans.plan_id` (e.g. `plan_500gb`) is the only commercial SKU in the vault database. Bridge configuration maps each `plan_id` to processor-specific offers:

```yaml
# bridge config (not in Arkfile repo)
plans:
  plan_500gb:
    stripe_price_id: price_...
  plan_1tb:
    processor: adyen
    # provider-specific offer data stays inside the bridge
```

Adding another processor later means a new bridge adapter and config lines — zero Arkfile schema or API changes.

**v1 processor targets:** complete Stripe and Adyen adapters. Stripe uses provider-managed subscriptions; Adyen uses the bridge scheduler and stored-payment-method flow. Both remain bridge concerns, not Arkfile concerns.

## Instance toggles

Split commercial modes so private and gratis instances can disable layers independently.

| Variable | When true |
|---|---|
| `ARKFILE_BILLING_ENABLED` | Master switch: scheduler runs; billing APIs respond; projection in `/api/credits` |
| `ARKFILE_BILLING_PAYG_ENABLED` (new) | Hourly meter + daily sweep + PAYG negative upload cap |
| `ARKFILE_SUBSCRIPTIONS_ENABLED` (new) | Plan catalog, gift subscriptions, subscription UI **and arkfile-client subscription commands** |
| `ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED` (new) | Paid checkout/portal, bridge callback, and reconcile integration |
| `ARKFILE_PAYMENTS_ENABLED` | BTCPay one-off top-ups (existing) |

Suggested defaults: **private / gratis** — all false. **Hosted PAYG-only** — billing + PAYG + payments on, subscriptions off. **Hosted with tiers** — all relevant flags on.

Gift-only mode requires no bridge URL or pairing root. When bridge integration is enabled, startup requires an HTTPS bridge URL (HTTP loopback is allowed for development), a normalized HTTPS return URL (or valid `BASE_URL` fallback), and `ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT` as exactly 64 lowercase hexadecimal characters representing 32 decoded bytes. Arkfile hex-decodes the root, then derives binary token, callback, and reconcile keys with HKDF-SHA256. Do **not** require processor API keys on Arkfile.

## Configuration

### Arkfile (`.env.example`)

```
ARKFILE_SUBSCRIPTIONS_ENABLED=false
ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED=false
ARKFILE_SUBSCRIPTION_BRIDGE_URL=https://billing.arkfile.net
ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT= # openssl rand -hex 32; same root on bridge
ARKFILE_SUBSCRIPTION_RETURN_URL=          # default: app origin /?subscription=return
ARKFILE_GIFT_SUBSCRIPTION_DEFAULT_DAYS=30   # grant-gift-subscription when --days omitted
ARKFILE_GIFT_SUBSCRIPTION_MAX_DAYS=90     # hard cap on --days / API days field
```

No Stripe, Adyen, Mollie, or Worldpay keys on the Arkfile host.

### Subscription Bridge (separate VPS, out of Arkfile repo for v1)

Bridge holds processor credentials, plan SKU mapping, bridge database, and adapter code. Deployment follows the same isolation principles as `docs/wip/alma-pay-server.md` (dedicated unprivileged runtime user, Caddy TLS, rootless Podman). Full bridge service specification: `docs/wip/subscription-bridge.md`. This document defines the Arkfile-side consumer contract only.

## Database schema (implemented)

Shipped in `database/unified_schema.sql` with migration helpers in `main.go`. Dev/e2e instances seed `plan_dev_250gb` (250 GiB, $5/mo display) when `ARKFILE_SUBSCRIPTION_SEED_DEV_PLAN=true` or in development mode (`scripts/dev-reset.sh`).

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
    subscription_ref TEXT UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_subscription_checkouts_username
    ON subscription_checkouts(username);
CREATE INDEX IF NOT EXISTS idx_subscription_checkouts_subscription_ref
    ON subscription_checkouts(subscription_ref);
```

### `user_subscriptions`

One logical active subscription per user; history via `subscription_events` and status transitions.

```sql
CREATE TABLE IF NOT EXISTS user_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    checkout_id TEXT NOT NULL,
    subscription_ref TEXT UNIQUE NOT NULL,
    is_current BOOLEAN NOT NULL DEFAULT 1,
    status TEXT NOT NULL CHECK (status IN (
        'active', 'past_due', 'canceled', 'expired', 'trialing'
    )),
    source TEXT NOT NULL CHECK (source IN ('bridge', 'gift')),
    state_version BIGINT NOT NULL DEFAULT 0,
    state_changed_at DATETIME,
    current_period_start DATETIME NOT NULL,
    current_period_end DATETIME NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT 0,
    canceled_at DATETIME,
    past_due_since DATETIME,
    gift_note TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id) ON DELETE RESTRICT,
    FOREIGN KEY (checkout_id) REFERENCES subscription_checkouts(checkout_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_username ON user_subscriptions(username);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_status ON user_subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_subscription_ref ON user_subscriptions(subscription_ref);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_subscriptions_one_current
    ON user_subscriptions(username) WHERE is_current = 1;
```

`source = gift` for operator grants via `grant-gift-subscription` only. Synthetic identifiers (no bridge):

- `subscription_ref`: `sub_gift_<uuid>`
- `checkout_id`: `subchk_gift_<uuid>` with a matching `subscription_checkouts` row (`status = completed`) to satisfy the FK

Gift rows set `current_period_end = current_period_start + N days` where **N defaults to 30** and **N ≤ 90**. `gift_note` is stored on `user_subscriptions`; the grant event stores the acting admin.

No `provider_customer_id`, `provider_subscription_id`, or processor columns on Arkfile.

### `subscription_events`

Webhook idempotency and audit (mirror `payment_invoices` + BTCPay webhook replay protection).

```sql
CREATE TABLE IF NOT EXISTS subscription_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    subscription_ref TEXT,
    checkout_id TEXT,
    username TEXT,
    plan_id TEXT,
    state_version BIGINT NOT NULL DEFAULT 0,
    state_changed_at DATETIME,
    disposition TEXT NOT NULL DEFAULT 'applied'
        CHECK(disposition IN ('applied', 'duplicate', 'ignored_stale')),
    admin_username TEXT,
    payload_hash TEXT NOT NULL,
    processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Ledger interaction

Subscription charges stay **out of** `user_credits` / `credit_transactions` for v1. PAYG balance remains the microcent wallet for non-subscribers. Payment history lives in bridge/processor dashboards plus `subscription_events`. Optional later: `transaction_type = subscription` for billing panel visibility.

## Backend: billing resolver (implemented)

Central resolver in `billing/effective.go` and `billing/subscription.go`:

| Function | Returns |
|---|---|
| `EffectiveBillingMode(username)` | `free`, `payg`, or `subscribed` |
| `EffectiveStorageLimit(username)` | Bytes for hard cap |
| `EffectiveFreeBaseline(username)` | Bytes for meter/projection |
| `ShouldMeter(username)` | Whether hourly tick and daily settlement apply |
| `ShouldApplyPaygUploadCap(username)` | Whether 402 gate applies |
| `ShouldAllowTopUp(username)` | Whether `POST /api/billing/invoice` is permitted |
| `FinalizePaygBeforeSubscribe(username)` | One-time tick + settle before meter off (subscribe / gift grant with meter pause) |

Wire into:

- `billing/meter.go` — `TickAllActiveUsers` skips users where `ShouldMeter` is false
- `billing/sweep.go` — `SweepAllUsers` skips non-metered users; export or add **`SettleUserAccumulator(username)`** for subscribe transition
- `handlers/payments.go` — reject invoice create when `ShouldAllowTopUp` is false
- `handlers/billing_projection.go` — add `subscription` block and `billing_mode` to `/api/credits`
- `handlers/uploads.go` — storage cap and PAYG cap guards
- `billing/scheduler.go` — optional subscription reconcile tick (daily or piggyback on sweep)
- Subscription bridge webhook handler — call `FinalizePaygBeforeSubscribe` on `subscription.activated`

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

`billing_mode` is the single client-facing field: `free`, `payg`, or `subscribed`. Same values in web UI, `arkfile-client`, and `/api/credits`. Matches `EffectiveBillingMode()` in the resolver.

When subscriptions disabled globally, omit or null the block (same pattern as `payments` in `/api/credits`). Do not expose raw `subscription_ref` or `checkout_id` to the browser unless needed for return-URL polling; prefer status-only responses on public APIs.

## Backend: HTTP API (implemented)

### Public / user (authenticated unless noted)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/subscriptions/plans` | List public active plans |
| GET | `/api/subscriptions/me` | Current user subscription + effective limits |
| POST | `/api/subscriptions/checkout` | Body: `{ "plan_id": "..." }` → bridge checkout URL |
| POST | `/api/subscriptions/portal` | Bridge portal URL for manage/cancel |
| POST | `/api/billing/invoice` | **Existing top-up path** — see Top-up rules below |

### Top-up rules (locked)

| Condition | Result |
|---|---|
| User subscription status `active` or `trialing` | **409 Conflict** — e.g. “Top-ups are not available while you have an active subscription. Manage your plan from billing or use `arkfile-client subscription portal`.” |
| Otherwise, payments enabled, amount valid | Unchanged BTCPay invoice flow (`docs/wip/payments.md`) |

Same rule in **`arkfile-client billing top-up`** (client-side pre-check from `/api/credits` plus server enforcement). Cross-link rejection behavior in `docs/wip/payments.md` when implemented.

### Admin (`/api/admin/...`, existing admin MFA stack)

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/admin/subscriptions/plans` | List / create / update plans |
| GET | `/api/admin/subscriptions/users/:username` | Subscription detail + checkout history |
| POST | `/api/admin/subscriptions/users/:username/grant-gift-subscription` | Body: `{ "plan_id", "days"?: 30 default, max 90, "note"?: "..." }` — `source=gift` only; **409** if user has active `source=bridge` subscription |
| POST | `/api/admin/subscriptions/users/:username/cancel-gift-subscription` | End gift early; **409** if active row is `source=bridge` (“use portal or processor dashboard for paid plans”) |
| POST | `/api/admin/subscriptions/users/:username/sync` | Poll bridge for `subscription_ref` (`source=bridge` only) |
| POST | `/api/admin/subscriptions/reconcile` | Bulk sync active bridge subscriptions nearing expiry |

### Webhooks

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/webhooks/subscription-bridge` | Subscription Bridge lifecycle (HMAC signed) |

Register only when subscriptions enabled. No per-processor webhook routes on Arkfile.

There is no public API to activate a subscription by username. All bridge activations resolve through `checkout_id` or `subscription_ref` locally.

## Lifecycle and robustness

Webhook delivery is the primary path; reconcile is part of normal operations, not an emergency-only tool (same philosophy as `docs/wip/payments.md` for BTCPay).

| Source | When |
|---|---|
| Bridge webhook | Real-time subscription changes (`source=bridge`) |
| Scheduler reconcile | Daily: **`source=bridge`** rows with `current_period_end` within window or past; call bridge GET |
| Scheduler gift expiry | Daily: **`source=gift`** rows past `current_period_end` → set `expired` locally (no bridge call) |
| Admin sync/reconcile | Manual repair after bridge or network outage (`source=bridge` only) |

| Local status | Upload | Meter | Top-up | Notes |
|---|---|---|---|---|
| `trialing`, `active` | Allowed to effective cap | Off | **Blocked** | |
| `past_due` | Block after grace | Off | **Blocked** | Login/download OK; not −$10 PAYG rule |
| `canceled` (at period end) | Allowed until `current_period_end` | Off until end | **Blocked** until period ends | |
| `expired`, `canceled` (immediate) | Baseline cap only | On if PAYG enabled | Allowed | |

On `subscription.activated`: `FinalizePaygBeforeSubscribe`, then meter off.

## arkfile-admin (implemented)

Command group **`subscriptions`** in `cmd/arkfile-admin/subscriptions_commands.go` (alongside `billing` and `payments`):

| Command | Purpose |
|---|---|
| `subscriptions list-plans [--json]` | Catalog |
| `subscriptions set-plan --plan-id ID --name NAME --price USD --storage LIMIT [--active]` | Create/update plan |
| `subscriptions show --user USER [--json]` | Baseline, plan, effective cap, subscription summary |
| `subscriptions grant-gift-subscription --user USER --plan-id ID [--days N] [--note NOTE]` | Gift grant; **default 30 days**, **max 90**; runs `FinalizePaygBeforeSubscribe` |
| `subscriptions cancel-gift-subscription --user USER [--immediate]` | End gift only; fails with clear error if `source=bridge` |
| `subscriptions sync --user USER` | Poll bridge by `subscription_ref` (paid subs only) |
| `subscriptions reconcile` | Bulk sync bridge-backed rows |

Extend **`billing show --user`** and **`user-status`** to include subscription summary when enabled.

No end-user subscription purchase in **`arkfile-admin`**. Operators grant **gifts** via CLI; users subscribe via **web app or `arkfile-client`**. Paid cancel is **portal or processor/bridge dashboard**, not Arkfile admin.

## arkfile-client (implemented)

End-user billing and subscriptions match the web billing panel (see **Client parity**). Command groups **`billing`** and **`subscription`** in `cmd/arkfile-client/` (same API surface as `billing.ts`). Response parsing normalizes flat `/api/credits` JSON and wrapped `{ success, data }` envelopes; HTTP errors surface Echo `message` text.

### `billing` (PAYG balance and top-ups)

| Command | Purpose |
|---|---|
| `billing show [--json]` | Balance, usage projection, `billing_mode`, transaction summary from `GET /api/credits` |
| `billing transactions [--json]` | Ledger rows (optional; may fold into `show`) |
| `billing top-up --amount USD [--open-browser] [--wait]` | Create BTCPay invoice; print or open checkout URL; optional poll until paid |
| `billing invoice status --id INV [--json]` | Poll local invoice status (parity with web return flow) |

**Top-up while subscribed:** command exits with clear error if `billing_mode` is `subscribed`; server returns 409 if invoked anyway.

### `subscription` (plans and Subscription Bridge checkout)

| Command | Purpose |
|---|---|
| `subscription status [--json] [--watch]` | Plan, renewal, effective storage cap, `billing_mode` from `/api/subscriptions/me` + credits |
| `subscription plans [--json]` | List public plans |
| `subscription subscribe --plan PLAN_ID [--open-browser] [--wait]` | `POST /api/subscriptions/checkout`; open or print bridge URL; optional poll until active |
| `subscription portal [--open-browser]` | `POST /api/subscriptions/portal`; open manage/cancel URL |

Hosted checkout and portal always use the **system browser** (or printed URL); no Stripe/BTCPay embed in terminal. **`--wait`** mirrors web polling after external payment.

### Parity checklist (web ↔ CLI)

| Web billing panel | arkfile-client |
|---|---|
| Balance, usage, transactions | `billing show` |
| Top Up Balance (PAYG only) | `billing top-up` |
| Return from BTCPay tab | `billing top-up --wait` / `billing invoice status` |
| Your plan / billing mode | `subscription status` |
| Plan cards | `subscription plans` |
| Subscribe | `subscription subscribe` |
| Manage plan | `subscription portal` |
| PAYG hidden when subscribed | No top-up command / server 409; `billing_mode` is `subscribed` |

Document new commands in `docs/scripts-guide.md` (user-facing `arkfile-client` section) — **CLI shipped; scripts-guide update still TODO.**

## TypeScript frontend (implemented on Arkfile host)

Extend `client/static/js/src/ui/billing.ts` and billing panel markup. Must stay in parity with `arkfile-client` (see **Client parity**). Plans list, subscribe redirect, portal redirect, `billing_mode` display, top-up hidden when subscribed, and `resumePendingSubscriptionCheckout` for return URLs are implemented.

### When subscriptions disabled

No change beyond current balance, usage projection, transaction history, and top-up modal.

### When subscriptions enabled

1. **Your plan** — plan name, price, renewal date, used/effective storage limit from `/api/credits`.
2. **Available plans** — cards from `GET /api/subscriptions/plans`.
3. **Subscribe / Upgrade** — `POST /api/subscriptions/checkout` → **redirect** to bridge URL (no processor scripts in Arkfile).
4. **Manage** — `POST /api/subscriptions/portal` → redirect to bridge portal.
5. **PAYG section** — balance, usage, top-up only when `billing_mode` is `free` or `payg`; hidden when `subscribed`.
6. **Top-up while subscribed** — button hidden; if API called, show server error message.

Return URL: `resumePendingSubscriptionCheckout` for `/?subscription=return&checkout_id=...` — session refresh, poll `/api/subscriptions/me` until active, strip query string. Mirror `resumePendingBillingCheckout` in `billing.ts`.

Redirect-only checkout avoids adding bridge origin to CSP `frame-src`. BTCPay origin remains for top-up iframe only.

Playwright: mock plans and checkout APIs; assert effective storage in billing panel; optional return-URL flow.

## Edge cases

| Scenario | Behavior |
|---|---|
| User over plan limit at downgrade/cancel | Block new uploads; allow download/delete/export |
| Admin `set-storage` while subscribed | Effective cap = max(new baseline, plan); no mutation on subscribe/cancel |
| User with positive PAYG balance subscribes | Balance remains frozen; `FinalizePaygBeforeSubscribe`; meter paused; top-ups blocked |
| User attempts top-up while subscribed | API **409**; web top-up hidden; `arkfile-client billing top-up` errors |
| User subscribes with pending usage in accumulator | Final tick + settle once, then meter off |
| User `past_due` | No PAYG metering; no top-ups; upload block after subscription grace (not −$10 rule) |
| Registration throttle / auto-approval | Unchanged |
| Soft-deleted user | RESTRICT FK; end gift via `cancel-gift-subscription` or wait for paid sub to end at processor before delete |
| Bridge reachable but webhook missed | Reconcile/sync repairs local state |
| Gift grant while user on paid plan | **409** — must cancel paid sub at processor first |
| Gift grant duration | Default 30 days; `--days` capped at 90 |
| Gift expiry | Scheduler or daily reconcile sets `expired` at `current_period_end`; meter resumes |
| `cancel-gift-subscription` on paid sub | **409** with message to use portal or Stripe/bridge |

Playwright: billing top-up modal is covered in `e2e-playwright.ts`; dedicated subscription plan cards and return-URL polling tests remain TODO.

## Testing

### Go unit and integration tests (done)

Implemented and passing in CI/dev:

- `billing/effective_test.go`, `billing/effective_extended_test.go` — mode, limits, `ShouldMeter`, `ShouldAllowTopUp`, PAYG cap skip when subscribed
- `billing/subscription_test.go`, `billing/subscription_testdb_test.go` — `FinalizePaygBeforeSubscribe`, subscription bridge callback state transitions (`activated`, `renewed`, `past_due`, `expired`, `plan_changed`), gift grant/cancel rules
- `billing/meter_subscription_test.go`, `billing/sweep_subscription_test.go` — meter and sweep skip for subscribed users
- `subbridge/hmac_test.go` — webhook signature verification and replay window
- `handlers/subscriptions_test.go`, `handlers/billing_projection_test.go` — user/admin HTTP handlers, `/api/credits` projection, top-up 409, `past_due` upload gate after grace
- `handlers/payments_test.go` — top-up 409 when subscribed (with subscription test helpers)
- `config/config_test.go` — subscription env validation
- `models/scan_test.go`, `models/subscription_plan_scan_test.go` — rqlite-safe boolean and BIGINT scan helpers for plan reads

### Shell e2e (done)

**`run_subscriptions`** group in `scripts/testing/e2e-test.sh` (after `run_payments`), using `scripts/testing/subscription-bridge-mock.go` on `:8081`. Verified as part of the full suite (**212 tests**, June 2026 dev-reset run):

- Mock Subscription Bridge start
- Dev plan `plan_dev_250gb` present (admin list-plans; exercises rqlite plan reads)
- Gift grant, credits projection (`billing_mode: subscribed`, 250 GiB effective cap), admin `subscriptions show`
- CLI: `billing show`, `subscription status`, `subscription plans` while subscribed
- Invoice API **409** and `arkfile-client billing top-up` rejected while gift subscribed
- `billing tick-now` does not add usage transactions while gift subscribed
- Gift cancel; credits not subscribed; BTCPay mock restarted for post-cancel top-up checks
- Invoice allowed and CLI top-up passes subscription gate after gift cancel
- Bridge checkout → mock `/v1/mock/activate` webhook → subscribed (`source: bridge`)
- Grant gift **409** and cancel-gift **409** while bridge subscription active
- Invoice/CLI top-up blocked while bridge subscribed
- Duplicate subscription bridge webhook idempotent (replay snapshot from mock `GET /v1/subscriptions/{ref}`)
- Mock `/v1/mock/expire` → not subscribed; invoice allowed again

Session reuse: `run_subscriptions` reuses the test-user session from `run_payments` when still valid (`ensure_user_session`), avoiding extra TOTP login cycles.

Foundation prerequisites remain e2e-verified in earlier groups: billing meter/sweep, PAYG negative cap, BTCPay top-ups, payments webhook idempotency.

### Playwright (partial)

- Done: billing top-up modal and BTCPay iframe (`e2e-playwright.ts`)
- TODO: subscription plan cards, mocked checkout redirect, return-URL polling, top-up hidden when subscribed

## Build phases (recommended order)

1. **Schema + resolver + admin plan CRUD** — **Done.** Unified schema, `billing/effective.go`, admin plan CRUD and gift commands, dev seed plan.
2. **Meter/storage/top-up integration** — **Done.** `ShouldMeter`, sweep skip, `ShouldAllowTopUp`, `FinalizePaygBeforeSubscribe`, upload gates, `/api/credits` projection; scheduler gift expiry and bridge reconcile hooks in `billing/scheduler.go`.
3. **Web billing panel + arkfile-client billing/subscription commands** — **Done.** `billing.ts` subscription UI; `cmd/arkfile-client/billing_commands.go` and `subscription_commands.go`.
4. **Subscription bridge consumer on Arkfile** — **Done on vault host.** Ordered transactional callbacks and snapshots, exact-field decoding, raw-byte audit hashes, gift atomicity, hex-decoded pairing root and HKDF-derived keys, authenticated reconcile, canonical fixture tests, user/admin APIs, mock bridge, and `run_subscriptions` e2e.
5. **Subscription Bridge service + Stripe and Adyen adapters** — **Not started.** Separate repository/deployment per `docs/wip/subscription-bridge.md`.
6. **Playwright subscription coverage + user/docs polish** — **Partial.** Playwright top-up exists; subscription-specific browser tests, `docs/user-faq.md`, `docs/api.md`, and `docs/scripts-guide.md` client billing section remain open.

## Documentation updates (when implemented)

| File | Change | Status |
|---|---|---|
| `docs/wip/subscription-bridge.md` | Bridge service spec, deployment, processor adapters | Spec exists; production deploy not done |
| `docs/wip/payments.md` | Cross-link: top-ups = BTCPay PAYG; top-up 409 when subscribed; subscriptions = Subscription Bridge | TODO |
| `docs/user-faq.md` | Q&A prose: plans, cancel (portal for paid; gifts are operator-only), PAYG vs subscription, top-ups while subscribed | TODO |
| `docs/api.md` | New endpoints; top-up 409 | TODO |
| `docs/scripts-guide.md` | Admin CLI subscription commands; **arkfile-client billing/subscription** | TODO |
| `.env.example` | Subscriptions + bridge vars (no processor keys) | Vars present (commented); review for prod defaults |
| `scripts/dev-reset.sh`, deploy scripts | Sensible defaults per environment | Dev/e2e use one test pairing root; production deploys remain bridge-disabled unless an admin supplies a generated root |

## Explicitly out of scope for v1

- Processor SDKs or API keys on the Arkfile host
- Storing processor-native IDs (`cus_*`, `sub_*`, etc.) in Arkfile
- BTCPay Stripe plugin or BTCPay native subscriptions as the subscription backend
- Per-processor webhook routes on Arkfile (`/api/webhooks/stripe`, etc.)
- Proration, annual billing, subscriber overage metering
- Margin / breakeven tables in code or config
- Crypto recurring subscriptions
- Automated storage purge on `past_due`
- Web admin UI (admin remains CLI-only by design)
- Mutating `users.storage_limit_bytes` on subscribe/cancel
- **`arkfile-admin` command that cancels or revokes bridge-backed subscriptions without processor cancel** (paid cancel = portal or Stripe/bridge dashboard only)

## Status

**Arkfile subscription layer: implemented; consumer hardening completed July 2026.** The vault host ships the full v1 consumer contract: ordered `state_version` callbacks and dedicated snapshots, event/state database transactions, exact verified-byte hashing, expired-row lookup, checkout/plan binding, concurrent replay protection, canonical `state_changed_at` persistence, atomic gift grants, disabled/gift-only semantics, consistent top-up policy, exact lowercase-hex root decoding with binary HKDF keys, bounded bridge HTTP, canonical protocol fixture tests, user/admin APIs and CLIs, billing UI, and a protocol-faithful dev mock. The existing full shell e2e baseline predates this hardening; focused Go coverage is the required verification for this change and `run_subscriptions` must be rerun before release.

**Still open for production:**

- **Subscription Bridge production service** (provider-neutral core, PostgreSQL, complete Stripe and Adyen adapters, Adyen scheduler/portal) — see `docs/wip/subscription-bridge.md`; Arkfile consumes it through the bridge URL and one HKDF pairing root.
- **Playwright** subscription-specific UI tests (plan cards, return URL, top-up hidden when subscribed).
- **User and operator docs:** `docs/user-faq.md`, `docs/api.md`, `docs/scripts-guide.md`, cross-links in `docs/wip/payments.md`.

**Foundation prerequisites** (1 GiB default marketed as 1.0 GB Free, auto-approval, registration throttle, PAYG −$10 cap, billing meter, BTCPay top-ups, billing panel PAYG, `arkfile-admin billing` / `payments`) were already implemented and remain e2e-verified in groups before `run_subscriptions`.

## References

- `docs/AGENTS.md` — privacy-first design, personas, threat models
- `docs/wip/storage-credits-v2.md` — microcent meter, settlement, free baseline
- `docs/wip/payments.md` — BTCPay top-ups, opaque `invoice_id`, reconcile model
- `docs/wip/alma-pay-server.md` — BTCPay hosting on Alma/Podman (pay host)
- `docs/wip/subscription-bridge.md` — bridge service spec, Stripe/Adyen adapters, deployment
- `docs/wip/prod-prep/03-roadmap.md` — commercial layer sequencing
- `handlers/billing_projection.go` — `/api/credits` projection
- `client/static/js/src/ui/billing.ts` — billing panel UI
- `payments/btcpay.go` — opaque metadata pattern for top-ups
- `cmd/arkfile-admin/billing_commands.go`, `payments_commands.go` — CLI patterns to mirror
- `cmd/arkfile-client/billing_commands.go`, `subscription_commands.go` — billing/subscription CLI
