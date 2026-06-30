# Entitlement Bridge Service

The Entitlement Bridge is a small, standalone payment-adjacent service that sits between Arkfile and recurring billing processors. Arkfile is a privacy-first file vault and must not hold processor API keys, processor-native identifiers (`cus_*`, `sub_*`), or processor webhook endpoints for subscriptions. The bridge runs on a separate VPS (planned hostname `billing.arkfile.net`), owns all processor integrations, and speaks to Arkfile through one canonical **Entitlement Bridge Protocol v1**. Its job is narrow: accept opaque checkout start tokens from Arkfile, host or redirect to processor checkout and customer-portal pages, verify processor webhooks, map processor lifecycle into entitlement events, and notify Arkfile with HMAC-signed callbacks keyed on `checkout_id` and `entitlement_ref` only. Usernames, file data, and vault credentials never enter the bridge database. Processor diversity (Stripe v1, Adyen, Mollie, Worldpay, Square, etc.) is handled inside the bridge through pluggable adapters; Arkfile configuration does not change when a new processor is added. This document specifies the bridge service itself. The Arkfile-side consumer contract, schema, resolver, and UI plan live in `docs/wip/prod-prep/05-subscriptions.md`. BTCPay on `pay.arkfile.net` remains unchanged and handles one-off PAYG balance top-ups only.

## Relationship to Arkfile and BTCPay

Three hosts cooperate with non-overlapping responsibilities. Confusing them leads to wrong integration assumptions (especially treating the BTCPay Stripe plugin as a subscription backend).

| Host | Role | Subscription involvement |
|---|---|---|
| **arkfile.net** (Arkfile app) | Vault, plan catalog, entitlement state, storage/meter gates | Creates `checkout_id`, stores `entitlement_ref`, receives entitlement webhooks |
| **billing.arkfile.net** (this service) | Processor adapters, checkout/portal sessions, entitlement notifications | Full subscription payment lifecycle |
| **pay.arkfile.net** (BTCPay) | Crypto/fiat one-off invoices for PAYG top-ups | None for subscriptions |

The bridge does not replace BTCPay and does not share a database with Arkfile. Plan display names and storage limits are defined in Arkfile's `subscription_plans` table; processor price SKUs are mapped in bridge configuration by `plan_id`.

## Threat model and design goals

The bridge VPS is single-purpose payment infrastructure, deployed with the same isolation instincts as `docs/wip/alma-pay-server.md`: dedicated unprivileged runtime user (`bridge` or similar, `/sbin/nologin`), rootless Podman or a single static binary under systemd, TLS terminated at Caddy on the host, application bound to loopback high port. Operator SSH uses a separate account; the runtime user owns data directories and secrets only.

**Goals.**

- Processor secrets never appear on the Arkfile host.
- Arkfile usernames never appear in processor metadata or bridge-to-processor APIs.
- Join keys are opaque: `checkout_id` (per attempt) and `entitlement_ref` (per ongoing entitlement).
- Webhook and callback verification is fail-closed (invalid signature → reject, no side effects).
- Idempotent event processing survives processor retries and bridge restarts.

**Accepted residual risk.** Card subscribers create processor-side financial identity. Hosted checkout may collect email for receipts. An operator with both database accesses can correlate `checkout_id` to username via Arkfile's `subscription_checkouts` table. Mitigate with separate credentials, minimal staff, and audit logging — not by pretending the join does not exist.

## Architecture

Public browsers reach `https://billing.example.com` on Caddy. Caddy reverse-proxies to the bridge process on `127.0.0.1:8081` (port is illustrative). Processors deliver webhooks to the bridge only. The bridge delivers entitlement events to Arkfile's `POST /api/webhooks/entitlements`. Arkfile may call back for sync via HMAC-authenticated GET. No browser traffic to Arkfile carries processor session IDs.

```
Browser ──► Caddy ──► Bridge ──► Processor API (Stripe, …)
                         │
                         ├──► Managed Postgres (e.g. DigitalOcean or Vultr; checkouts, entitlements, processor IDs)
                         │
                         └──► HMAC POST ──► Arkfile /api/webhooks/entitlements

Arkfile ──► signed start/portal tokens ──► Browser ──► Bridge /v1/start, /v1/portal
Arkfile ──► HMAC GET /v1/entitlements/{entitlement_ref} ──► Bridge (reconcile)
```

## Entitlement Bridge Protocol v1 (bridge perspective)

Protocol version 1 is the stable contract. Processor adapters translate native events into this shape; the **entitlement notifier** posts it to Arkfile. Field names and semantics must match `docs/wip/prod-prep/05-subscriptions.md` exactly so either document can be read independently.

### Start token (Arkfile → bridge, via browser redirect)

Arkfile signs a URL-safe token when the user calls `POST /api/subscriptions/checkout`. The bridge receives it on `GET /v1/start?token=...`.

**Payload (before signing):**

```json
{
  "checkout_id": "subchk_...",
  "plan_id": "plan_500gb",
  "return_url": "https://example.com/?subscription=return",
  "exp": 1710000000
}
```

**Rules.**

- HMAC-SHA256 with shared `BRIDGE_START_TOKEN_SECRET` (may equal webhook secret or be distinct).
- Reject expired tokens (`exp` more than ~15 minutes skew allowed).
- `checkout_id` and `plan_id` required; **no username field exists**.
- Bridge records a local checkout row if not already present (idempotent on `checkout_id`).
- Bridge resolves `plan_id` → processor SKU via config, creates hosted checkout session.
- Processor metadata MUST contain only `{ "checkout_id": "<id>" }` (and optionally `entitlement_ref` after first assignment — never username).

**Response:** HTTP 302 redirect to processor hosted checkout URL.

### Portal token (Arkfile → bridge, via browser redirect)

Arkfile signs when the user calls `POST /api/subscriptions/portal`.

**Payload:**

```json
{
  "entitlement_ref": "ent_...",
  "return_url": "https://example.com/",
  "exp": 1710000000
}
```

Bridge looks up local entitlement → processor customer/subscription, creates processor portal session, redirects browser. No username in token.

### Entitlement callback (bridge → Arkfile)

**Endpoint on Arkfile:** `POST /api/webhooks/entitlements`

**Header:** `Entitlement-Bridge-Signature: t=<unix>,v1=<hex>`

Signature base string: `<unix>.<raw_json_body>`. HMAC key: `BRIDGE_ARKFILE_WEBHOOK_SECRET` (same value as Arkfile's `ARKFILE_ENTITLEMENT_BRIDGE_WEBHOOK_SECRET`).

**Body:**

```json
{
  "protocol": "entitlement-bridge",
  "version": 1,
  "event_id": "evt_<uuid>",
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

| `event_type` | When bridge emits |
|---|---|
| `entitlement.activated` | First successful subscription or trial start |
| `entitlement.renewed` | Successful renewal (`invoice.paid` equivalent) |
| `entitlement.past_due` | Payment failed; subscription past_due in processor |
| `entitlement.canceled` | User or operator canceled (immediate or at period end) |
| `entitlement.expired` | Subscription ended; no longer entitled |
| `entitlement.plan_changed` | Plan SKU changed on existing entitlement |

**`status` values** sent to Arkfile: `active`, `trialing`, `past_due`, `canceled`, `expired` (align with Arkfile `user_subscriptions.status` CHECK constraint).

**Idempotency:** bridge generates stable `event_id` per logical transition; stores in `bridge_events` before POST; retries on Arkfile 5xx with backoff; Arkfile deduplicates on `event_id`.

### Entitlement query (Arkfile → bridge, server-to-server)

**Endpoint:** `GET /v1/entitlements/{entitlement_ref}`

**Auth:** `Authorization: Bridge-HMAC t=<unix>,v1=<hex>` over `GET\n/v1/entitlements/{entitlement_ref}\n<unix>` (or equivalent constant-time scheme).

**Response:** 200 with entitlement snapshot (same fields as callback body minus `event_id` / `event_type`). 404 if unknown ref.

Used by Arkfile reconcile scheduler and `arkfile-admin subscriptions sync`.

## HTTP routes (bridge service)

All public routes are behind Caddy TLS. Processor webhooks use separate path with processor-specific signature verification.

### Browser-facing

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/start` | Validate start token; create processor checkout; redirect |
| GET | `/v1/portal` | Validate portal token; create processor portal session; redirect |
| GET | `/health` | Liveness for monitoring |

Optional success/cancel landing pages on bridge domain if processor redirect requires absolute URLs; default return to Arkfile `return_url` from token.

### Processor webhooks (adapter-specific)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/webhooks/stripe` | Stripe Billing webhook (v1) |
| POST | `/v1/webhooks/adyen` | Future |
| POST | `/v1/webhooks/mollie` | Future |

Stripe endpoint verifies `Stripe-Signature` header. Other adapters verify their native headers. No processor webhook hits Arkfile.

### Server-to-server (Arkfile)

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/entitlements/{entitlement_ref}` | Reconcile snapshot |

Optional future: `POST /v1/entitlements/{entitlement_ref}/cancel` for operator-driven cancel initiated from Arkfile admin (v2). v1 cancel flows through processor portal only.

## Database schema (bridge)

The bridge uses **PostgreSQL**. State is small (checkouts, entitlements, event idempotency) but webhook retries, concurrent checkout sessions, and reconcile jobs benefit from a server database and provider-managed backups. Provision a managed Postgres instance—for example, **DigitalOcean Managed Databases for PostgreSQL** or **Vultr Managed Databases**—in the same region as the bridge app VPS when possible so latency stays low and private/VPC networking can be enabled. The bridge connects via `BRIDGE_DATABASE_URL` (or discrete `BRIDGE_DB_*` variables) over TLS. Schema migrations run at bridge startup or via a dedicated migrate step. Suggested tables:

### `bridge_checkouts`

One row per `checkout_id` received from Arkfile start token.

```sql
CREATE TABLE bridge_checkouts (
    checkout_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'completed', 'expired', 'canceled')),
    entitlement_ref TEXT,
    processor_family TEXT,
    processor_checkout_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### `bridge_entitlements`

Ongoing entitlement; processor IDs live here only.

```sql
CREATE TABLE bridge_entitlements (
    entitlement_ref TEXT PRIMARY KEY,
    checkout_id TEXT NOT NULL UNIQUE REFERENCES bridge_checkouts(checkout_id),
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL,
    processor_family TEXT NOT NULL,
    processor_customer_id TEXT,
    processor_subscription_id TEXT,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_bridge_entitlements_processor_sub
    ON bridge_entitlements(processor_subscription_id);
```

### `bridge_events`

Outbound entitlement notifications and processor webhook idempotency.

```sql
CREATE TABLE bridge_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    entitlement_ref TEXT,
    checkout_id TEXT,
    processor_event_id TEXT UNIQUE,
    payload_json TEXT NOT NULL,
    arkfile_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    arkfile_delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### `processor_webhook_log`

Optional raw audit of inbound processor payloads (redact PAN/card data at ingest if logged).

No `username` column anywhere.

## Managed PostgreSQL

Production bridge deployments target a **hosted managed Postgres** service, not a self-run database on the app VPS. DigitalOcean and Vultr both offer managed PostgreSQL suitable for this workload; use whichever matches where the bridge app VPS already lives.

**Colocation.** Create the managed database in the **same region** as the bridge app VPS (e.g. a DigitalOcean Droplet and DO managed Postgres both in `nyc3`, or Vultr compute and Vultr managed DB in the same location). Avoid cross-provider database links unless necessary—they add latency and often force traffic over the public internet.

**Sizing (v1).** Single-node Postgres at the smallest tier (typically 1 GB RAM class) is enough for early production. Bridge write volume is low. Scale up only if webhook replay or reconcile volume grows.

**Network hardening.**

- Prefer **private/VPC connectivity** (DigitalOcean VPC, Vultr VPC) so Postgres is not open to the world.
- If the managed product exposes a public host, restrict **trusted sources** to the bridge app VPS IP only.
- Require **TLS** (`sslmode=require` or stricter). Install the provider CA bundle if required.

**Credentials.** Dedicated database user (e.g. `bridge_app`) with least privilege on a `bridge` database only. Do not share Arkfile's database or BTCPay Postgres. Connection credentials live in bridge `.env` on the app VPS.

**Backups.** Use the provider's automated daily backups and point-in-time recovery when offered. Bridge data is payment-adjacent (processor IDs, checkout correlation) but contains no vault file content; treat backups as sensitive.

**Local dev / CI.** Ephemeral Postgres (e.g. Docker `postgres:18` in CI) is fine for tests. Production uses managed Postgres only—not SQLite.

## Processor adapter interface

Each adapter implements a common Go interface (or equivalent in the bridge implementation language):

| Method | Purpose |
|---|---|
| `CreateCheckout(ctx, planSKU, checkoutID, successURL, cancelURL)` | Returns redirect URL for hosted checkout |
| `CreatePortalSession(ctx, processorCustomerID, returnURL)` | Returns portal URL |
| `ParseWebhook(ctx, headers, body)` | Returns normalized internal events |
| `GetSubscription(ctx, processorSubscriptionID)` | Poll current state for reconcile |
| `Family()` | Returns `stripe`, `adyen`, etc. |

The **entitlement engine** maps normalized events → protocol v1 callbacks → POST Arkfile.

**Plan SKU config** (`config/plans.yaml` or env):

```yaml
default_processor: stripe

plans:
  plan_500gb:
    stripe_price_id: price_...
    display_name: "500 GB"   # bridge UI only; Arkfile owns user-facing copy
  plan_1tb:
    stripe_price_id: price_...
  plan_5tb:
    mollie_product_id: ...    # future second adapter
```

Arkfile `plan_id` strings must match keys here. Operator adds matching rows in Arkfile via `arkfile-admin subscriptions set-plan` and matching SKU lines in bridge config during deploy.

## Stripe adapter (v1)

Stripe Billing is the first adapter. Use Stripe Checkout in **subscription mode** with `line_items[].price` from config, or Billing Portal for management. Card data stays on Stripe hosted pages; bridge never touches PAN.

### Checkout session creation

- `mode: subscription`
- `metadata.checkout_id` = Arkfile opaque ID (only join key sent to Stripe)
- `subscription_data.metadata.checkout_id` = same
- `success_url` = Arkfile `return_url` from start token (with `?checkout_id=` appended if helpful)
- `cancel_url` = Arkfile app billing panel or generic cancel URL
- Do not set `client_reference_id` to username

On `checkout.session.completed`, bridge allocates `entitlement_ref` (`ent_<uuid>`), stores `processor_customer_id` and `processor_subscription_id`, emits `entitlement.activated`.

### Stripe webhook → entitlement mapping

| Stripe event | Bridge action |
|---|---|
| `checkout.session.completed` | Create entitlement; `entitlement.activated` |
| `customer.subscription.updated` | Map status; may emit `entitlement.canceled`, `entitlement.plan_changed`, or period updates |
| `customer.subscription.deleted` | `entitlement.expired` |
| `invoice.paid` | `entitlement.renewed` (update period end) |
| `invoice.payment_failed` | `entitlement.past_due` |

Verify webhook with `STRIPE_WEBHOOK_SECRET`. Store Stripe `event.id` in `processor_event_id` for idempotency.

### Customer portal

`billingPortal.sessions.create` with `customer` from `bridge_entitlements.processor_customer_id`, `return_url` from portal token.

## Multi-processor strategy

New processors add a webhook route, adapter implementation, and config stanza per `plan_id`. The entitlement engine and Arkfile contract are unchanged.

| Processor | Integration notes | v1 |
|---|---|---|
| **Stripe** | Checkout subscription mode + Billing Portal | Yes |
| **Adyen** | Recurring contract + hosted checkout | Future |
| **Mollie** | Subscriptions API | Future |
| **Worldpay** | Tokenization + scheduled payments | Future |
| **Square** | Subscriptions API | Future |

A plan may specify different processors per region in config (`default_processor` override by header or geo — future). v1 uses single default processor for all plans.

## Lifecycle and robustness

Webhook delivery is primary; reconcile is normal operations.

**Bridge-side retry.** After emitting an entitlement event, POST to Arkfile with exponential backoff until 2xx or manual intervention. Mark `arkfile_delivered` on success. Undelivered events surface in admin metrics / CLI.

**Bridge-side reconcile.** Periodic job (hourly): for each `bridge_entitlements` row in active/past_due, poll processor `GetSubscription`; if state diverges from last notified, emit corrective entitlement event.

**Arkfile-side reconcile.** Documented in `05-subscriptions.md`; calls `GET /v1/entitlements/{entitlement_ref}`. Bridge must return authoritative processor-derived snapshot.

**Clock skew.** Reject start/portal tokens and HMAC requests outside ±300 seconds unless configured otherwise.

**Startup.** Fail fast if webhook secrets, Arkfile callback URL, default processor credentials, or database connectivity are missing or migrations are pending.

## Configuration

Environment variables for the bridge service (`.env` on bridge VPS):

```
# Public URLs
BRIDGE_PUBLIC_URL=https://billing.arkfile.net
ARKFILE_WEBHOOK_URL=https://arkfile.net/api/webhooks/entitlements

# Shared secrets (must match Arkfile)
BRIDGE_ARKFILE_WEBHOOK_SECRET=
BRIDGE_START_TOKEN_SECRET=              # may equal webhook secret

# Stripe (v1)
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_PUBLISHABLE_KEY=                 # optional if fully redirect-based

# Server
BRIDGE_LISTEN=127.0.0.1:8081

# Database (managed PostgreSQL — e.g. DigitalOcean or Vultr)
BRIDGE_DATABASE_URL=postgres://bridge_app:PASSWORD@HOST:5432/bridge?sslmode=require
# Or discrete vars:
# BRIDGE_DB_HOST=
# BRIDGE_DB_PORT=5432
# BRIDGE_DB_NAME=bridge
# BRIDGE_DB_USER=bridge_app
# BRIDGE_DB_PASSWORD=
# BRIDGE_DB_SSLMODE=require

# Optional
BRIDGE_DEFAULT_SUCCESS_URL=
BRIDGE_DEFAULT_CANCEL_URL=
BRIDGE_LOG_LEVEL=info
```

Arkfile-side mirror (see `05-subscriptions.md`):

```
ARKFILE_ENTITLEMENT_BRIDGE_URL=https://billing.arkfile.net
ARKFILE_ENTITLEMENT_BRIDGE_WEBHOOK_SECRET=<same as BRIDGE_ARKFILE_WEBHOOK_SECRET>
```

Plan SKU mapping lives in `config/plans.yaml` mounted into the bridge container or read at startup. Startup must fail if the database is unreachable. `bridge health` should verify DB connectivity, not just HTTP liveness.

## Deployment

Target: small **app VPS** (1–2 vCPU, 1–2 GB RAM, 20–40 GB SSD) plus a **separate managed PostgreSQL** instance—for example on DigitalOcean or Vultr in the same region. No chain nodes; much lighter than BTCPay. Alma Linux 10 or Ubuntu LTS (latest), rootless Podman or a static binary, Caddy TLS on the app VPS, dedicated runtime user `bridge`. The app VPS may live on any provider; the managed database should be colocated in the same region or reachable over a private network when the provider supports it.

**Phase 1 — Host bootstrap (operator root).**

```bash
sudo groupadd -r bridge 2>/dev/null || true
sudo useradd -r -g bridge -d /var/lib/bridge -s /sbin/nologin -c "Entitlement Bridge runtime" bridge
sudo install -d -o bridge -g bridge -m 0750 /var/lib/bridge
sudo dnf -y install podman curl jq
sudo loginctl enable-linger bridge
```

**Phase 2 — Managed Postgres.** In the provider console (DigitalOcean or Vultr): create a PostgreSQL 18+ managed instance in the same region as the bridge app VPS. Create database `bridge` and user `bridge_app`. Enable VPC/private networking if available; use the private connection host in `BRIDGE_DATABASE_URL`. Enable automated backups. Restrict inbound to the app VPS IP if the endpoint is public.

**Phase 3 — Deploy artifact.** v1 may ship as a single Go binary in a minimal container image or directly under `bridge` user systemd unit. Bind `127.0.0.1:8081`. Mount `/var/lib/bridge` for secrets and config only—not database files. Run schema migrations before or during service start.

**Phase 4 — Caddy site block.**

```
billing.example.com {
    reverse_proxy 127.0.0.1:8081
}
```

**Phase 5 — Stripe dashboard.** Register webhook endpoint `https://billing.example.com/v1/webhooks/stripe` for required subscription events. Use live/test mode keys matching deployment.

**Phase 6 — Pair with Arkfile.** Set matching HMAC secrets on both hosts. Confirm Arkfile `ARKFILE_SUBSCRIPTIONS_ENABLED=true` only after end-to-end test on staging.

DNS: `billing.arkfile.net` (production), optional `billing-test.arkfile.net` for staging bridge paired with `test.arkfile.net`.

## Operations

Minimal operator surface on the bridge host (CLI or `curl` scripts). No relation to `arkfile-admin` — separate tooling.

| Command / action | Purpose |
|---|---|
| `bridge health` | Liveness + DB connectivity |
| `bridge show-checkout <checkout_id>` | Local checkout + entitlement mapping |
| `bridge show-entitlement <entitlement_ref>` | Status + processor IDs (operator eyes only) |
| `bridge replay-event <event_id>` | Re-POST undelivered callback to Arkfile |
| `bridge reconcile` | Poll all active entitlements against processor |
| `bridge list-undelivered` | Events where `arkfile_delivered=false` |

Payment refunds and chargebacks: v1 manual via processor dashboard; optional future `entitlement.expired` on chargeback webhook. Document policy in operator runbook; no automatic Arkfile file purge.

## Testing

**Unit tests.** Token verify/sign, HMAC callback formatting, Stripe webhook parsing, idempotency, plan SKU resolution.

**Integration tests.** Stripe test mode checkout → webhook → mock Arkfile receiver captures entitlement POST. Use ephemeral Postgres in CI (not SQLite) so SQL matches production.

**Cross-service e2e.** Arkfile `scripts/testing/e2e-test.sh` runs `entitlement-bridge-mock.go` (parallel to `btcpay-mock.go`) implementing `/v1/start`, `/v1/entitlements/{ref}`, and firing signed callbacks — no live Stripe or managed DB required in CI.

**Staging.** Real Stripe test mode + staging bridge VPS + `test.arkfile.net` before production keys.

## Build phases (bridge repo)

1. **Protocol types + HMAC helpers** — shared test vectors with Arkfile mock.
2. **Postgres schema migrations + checkout/start route** — redirect to stub URL.
3. **Stripe adapter + webhook handler** — test mode end-to-end.
4. **Entitlement notifier + retry** — POST to Arkfile mock.
5. **Portal route + GET entitlement sync.**
6. **Deploy scripts + Caddy + systemd** — staging VPS.
7. **Operator CLI + runbook.**

Bridge may live in a separate git repository (`arkfile-entitlement-bridge` or similar). v1 does not require merging into the main Arkfile monorepo.

## Explicitly out of scope for v1

- Username or email passed from Arkfile in tokens or metadata
- Arkfile storage of processor-native IDs
- BTCPay integration for subscriptions
- Proration, coupons, tax, multi-currency
- Multiple concurrent entitlements per checkout (one subscription per checkout)
- Automated chargeback → file purge
- Public self-signup of merchants (single-tenant operator bridge)

## Status

**NOT STARTED.** Protocol and schema specified here and in `docs/wip/prod-prep/05-subscriptions.md`. Arkfile consumer implementation not yet begun. Bridge service repository and deployment do not exist yet. Implement Arkfile phases 1–4 (schema, resolver, mock bridge e2e) before live Stripe staging.

## References

- `docs/wip/prod-prep/05-subscriptions.md` — Arkfile consumer, schema, resolver, UI, e2e plan
- `docs/wip/payments.md` — BTCPay top-ups; opaque `invoice_id` pattern to mirror
- `docs/wip/alma-pay-server.md` — VPS isolation and Caddy deployment patterns
- `docs/AGENTS.md` — privacy-first design and personas
- [Stripe Checkout subscription mode](https://docs.stripe.com/payments/checkout/subscriptions)
- [Stripe Billing webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)
