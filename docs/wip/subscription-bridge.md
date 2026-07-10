# Subscription Bridge — Standalone Service Specification (v1)

This document is the **normative build spec** for a small, reusable **Subscription Bridge** service. The bridge sits between a **consumer application** (any SaaS that sells recurring plan-based access) and **payment processors** (Stripe v1). The consumer holds user identity and business rules; the bridge holds processor API keys and maps processor subscription lifecycle into a single **Subscription Bridge Protocol v1**. Join keys are opaque: `checkout_id` (one checkout attempt) and `subscription_ref` (one ongoing paid subscription). **No consumer user identifiers** appear in the bridge database or processor metadata.

A reference consumer implementation exists in the Arkfile monorepo (`docs/wip/prod-prep/05-subscriptions.md`, package `subbridge/`). This spec is product-neutral so the bridge can ship as its own repository and serve multiple projects.

---

## 1. Problem statement

Recurring card billing requires processor SDKs, webhook endpoints, and native IDs (`cus_*`, `sub_*`, `price_*`). Many applications want subscriptions without importing that complexity into the main app database or deployment. The Subscription Bridge:

- Owns processor credentials and hosted checkout/portal pages.
- Stores processor-native IDs only in the bridge database.
- Notifies the consumer app via one HMAC-signed webhook contract.
- Exposes browser redirect entry points (`/v1/start`, `/v1/portal`) using signed tokens from the consumer.

The bridge is **not** a general billing platform: no one-off payments, no multi-tenant merchant signup, no proration/coupons/tax in v1.

---

## 2. Glossary

| Term | Meaning |
|---|---|
| **Consumer app** | Your main product (e.g. a file vault, API service). Holds usernames, plan catalog, feature gates. |
| **Subscription Bridge** | This service. Processor adapters + protocol notifier. |
| **Processor** | External recurring billing provider (Stripe v1). |
| **plan_id** | Opaque string defined by the consumer (`plan_500gb`). Bridge maps to processor SKU. |
| **checkout_id** | Opaque per-attempt ID from consumer (`subchk_<uuid>`). Only join key sent to processor metadata. |
| **subscription_ref** | Opaque ongoing subscription ID (`sub_<uuid>`). Stable across renewals. |
| **Start token** | HMAC-signed URL token for `/v1/start`. |
| **Portal token** | HMAC-signed URL token for `/v1/portal`. |
| **Callback** | HMAC-signed POST from bridge → consumer on lifecycle change. |

---

## 3. Architecture

```
Browser ──► TLS proxy ──► Subscription Bridge ──► Processor API
                              │
                              ├──► Postgres (checkouts, subscriptions, outbound events)
                              │
                              └──► HMAC POST ──► Consumer /api/webhooks/subscription-bridge

Consumer ──► signed tokens ──► Browser ──► Bridge /v1/start, /v1/portal
Consumer ──► HMAC GET ──► Bridge /v1/subscriptions/{subscription_ref}  (reconcile)
Processor ──► POST ──► Bridge /v1/webhooks/stripe  (never hits consumer)
```

**Responsibilities**

| Party | Knows | Must not know |
|---|---|---|
| Consumer | username, local plan catalog, subscription status, feature gates | Processor customer/subscription IDs, card data |
| Bridge | processor objects, checkout sessions, checkout_id, subscription_ref | Consumer usernames, application secrets beyond shared HMAC |
| Processor | card/bank instruments, customer email for receipts | Consumer usernames |

---

## 4. Threat model and design goals

**Goals**

- Processor secrets never on the consumer host.
- Consumer usernames never in processor metadata or bridge→processor APIs.
- Opaque join keys only: `checkout_id`, `subscription_ref`.
- Fail-closed HMAC on all bridge↔consumer traffic.
- Idempotent event processing (processor retries, bridge restarts).

**Residual risk**

Card subscribers have processor-side financial identity. An operator with access to both databases can correlate `checkout_id` → username via the consumer's `subscription_checkouts` table. Mitigate with separate credentials and minimal staff — do not pretend the join is impossible.

**Clock skew**

Reject tokens and HMAC requests outside ±300 seconds (configurable).

---

## 5. Subscription Bridge Protocol v1 (normative)

Protocol identifier: `"subscription-bridge"`, version `1`. Field names below are stable; consumer and bridge must match exactly.

### 5.1 Start token (consumer → bridge, via browser)

Consumer signs when user initiates checkout. Bridge receives `GET /v1/start?token=...`.

**Payload (JSON before signing):**

```json
{
  "checkout_id": "subchk_7f3a9c2e",
  "plan_id": "plan_500gb",
  "return_url": "https://app.example.com/?subscription=return",
  "exp": 1710000000
}
```

**Signing algorithm**

1. `body = JSON.Marshal(payload)` (compact, UTF-8).
2. `sig = HMAC-SHA256(secret, body)` → lowercase hex.
3. `token = base64url(body) + "." + hex(sig)` (RawURLEncoding, no padding).

**Validation**

- Verify HMAC with shared `BRIDGE_TOKEN_SECRET` (may equal webhook secret).
- Reject if `now > exp + 300s`.
- Require `checkout_id`, `plan_id`.
- **No username field** — must not exist in payload.
- Upsert `bridge_checkouts` row idempotently on `checkout_id`.
- Resolve `plan_id` → processor SKU; create hosted checkout session.
- Processor metadata: `{ "checkout_id": "<id>" }` only (never username).
- Response: HTTP 302 to processor hosted checkout URL.

**Test vector (secret = `test_subscription_bridge_secret`)**

Use the consumer `subbridge` package tests (`subbridge/hmac_test.go`) as the canonical cross-repo test vector source. CI in both repos must share the same secret and assert round-trip verify.

### 5.2 Portal token (consumer → bridge, via browser)

Consumer signs when user opens manage/cancel portal.

**Payload:**

```json
{
  "subscription_ref": "sub_a8f3c1d2",
  "return_url": "https://app.example.com/billing",
  "exp": 1710000000
}
```

Same signing as start token. Bridge looks up `subscription_ref` → processor customer, creates portal session, redirects browser.

### 5.3 Callback (bridge → consumer)

**Consumer endpoint (configurable):** `POST {CONSUMER_WEBHOOK_URL}`  
Default path in reference consumer: `/api/webhooks/subscription-bridge`

**Header:** `Subscription-Bridge-Signature: t=<unix>,v1=<hex>`

**Signature base string:** `<unix> + "." + raw_json_body`  
**HMAC key:** shared `BRIDGE_CONSUMER_WEBHOOK_SECRET` (consumer env: `ARKFILE_SUBSCRIPTION_BRIDGE_WEBHOOK_SECRET` in Arkfile).

**Body:**

```json
{
  "protocol": "subscription-bridge",
  "version": 1,
  "event_id": "evt_550e8400-e29b-41d4-a716-446655440000",
  "event_type": "subscription.activated",
  "checkout_id": "subchk_7f3a9c2e",
  "subscription_ref": "sub_a8f3c1d2",
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
| `subscription.activated` | First successful subscription or trial start |
| `subscription.renewed` | Successful renewal (`invoice.paid`) |
| `subscription.past_due` | Payment failed; processor status past_due |
| `subscription.canceled` | User/operator canceled (immediate or at period end) |
| `subscription.expired` | Subscription ended; no longer active |
| `subscription.plan_changed` | Plan SKU changed on existing subscription |
| `subscription.sync` | Reconcile-only (consumer may treat like state refresh) |

**`status` values:** `active`, `trialing`, `past_due`, `canceled`, `expired`

**Idempotency**

- Bridge generates stable `event_id` per logical transition; stores in `bridge_events` before POST.
- Retries on consumer 5xx with exponential backoff until 2xx or operator intervention.
- Consumer deduplicates on `event_id` (insert into `subscription_events` with UNIQUE).

**Webhook signature test**

```go
body := []byte(`{"protocol":"subscription-bridge","version":1,"event_id":"evt_1"}`)
header := SignWebhook("test_subscription_bridge_secret", body)
// header format: t=<unix>,v1=<hex>
```

### 5.4 Subscription snapshot (consumer → bridge, server-to-server)

**Endpoint:** `GET /v1/subscriptions/{subscription_ref}`

**Auth header:** `Authorization: Subscription-Bridge-HMAC t=<unix>,v1=<hex>`

**String to sign:** `GET\n/v1/subscriptions/{subscription_ref}\n<unix>`

**Response 200:** snapshot object (same fields as callback minus `event_id` / `event_type`).  
**Response 404:** unknown `subscription_ref`.

Used by consumer reconcile jobs and operator `sync` commands.

---

## 6. HTTP routes (bridge service)

### 6.1 Browser-facing

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/start` | Validate start token; create processor checkout; redirect |
| GET | `/v1/portal` | Validate portal token; create processor portal session; redirect |
| GET | `/health` | Liveness (+ DB ping in production) |

### 6.2 Processor webhooks

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/webhooks/stripe` | Stripe Billing webhook (v1) |

Verify native processor signature (`Stripe-Signature`). Store `event.id` in `processor_event_id` UNIQUE for idempotency.

### 6.3 Server-to-server (consumer)

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/subscriptions/{subscription_ref}` | Reconcile snapshot |

### 6.4 Dev/test only (optional mock helpers)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/mock/activate` | Test helper: `{checkout_id}` → fire `subscription.activated` |
| POST | `/v1/mock/expire` | Test helper: `{subscription_ref}` → fire `subscription.expired` |

Ship a separate `cmd/mock-bridge` or `scripts/subscription-bridge-mock.go` for consumer CI (see Arkfile `scripts/testing/subscription-bridge-mock.go`).

---

## 7. State machines

### 7.1 Checkout (`bridge_checkouts.status`)

```
pending ──(checkout.session.completed)──► completed
pending ──(timeout/abandon)────────────► expired
pending ──(user cancel)────────────────► canceled
```

### 7.2 Subscription (`bridge_subscriptions.status`)

```
(trial/)active ──(invoice.payment_failed)──► past_due
past_due ──(invoice.paid)──────────────────► active
active ──(cancel at period end)────────────► canceled (until period end)
any ──(subscription deleted)───────────────► expired
active ──(plan SKU change)─────────────────► active (emit plan_changed)
```

Each transition that affects consumer subscription state emits the corresponding callback `event_type`.

---

## 8. Database schema (PostgreSQL)

Use managed Postgres in production. Table prefix `sb_` is recommended for clarity.

```sql
CREATE TABLE sb_checkouts (
    checkout_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'expired', 'canceled')),
    subscription_ref TEXT,
    processor_family TEXT,
    processor_checkout_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sb_subscriptions (
    subscription_ref TEXT PRIMARY KEY,
    checkout_id TEXT NOT NULL UNIQUE REFERENCES sb_checkouts(checkout_id),
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
CREATE INDEX idx_sb_subscriptions_processor_sub ON sb_subscriptions(processor_subscription_id);

CREATE TABLE sb_outbound_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    subscription_ref TEXT,
    checkout_id TEXT,
    processor_event_id TEXT UNIQUE,
    payload_json TEXT NOT NULL,
    consumer_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    consumer_delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sb_processor_webhook_log (
    id BIGSERIAL PRIMARY KEY,
    processor_family TEXT NOT NULL,
    processor_event_id TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_json TEXT
);
```

**No `username` column anywhere.**

Run migrations at startup or via `bridge migrate`.

---

## 9. Processor adapter interface

Each adapter implements (Go interface suggested):

```go
type ProcessorAdapter interface {
    Family() string
    CreateCheckout(ctx, planSKU, checkoutID, successURL, cancelURL string) (redirectURL string, processorCheckoutID string, err error)
    CreatePortalSession(ctx, processorCustomerID, returnURL string) (portalURL string, err error)
    ParseWebhook(ctx, headers http.Header, body []byte) ([]NormalizedEvent, error)
    GetSubscription(ctx, processorSubscriptionID string) (*SubscriptionState, error)
}
```

The **subscription engine** maps `NormalizedEvent` → protocol v1 callbacks → POST consumer.

### 9.1 Plan SKU config (`config/plans.yaml`)

```yaml
default_processor: stripe

plans:
  plan_500gb:
    stripe_price_id: price_...
  plan_1tb:
    stripe_price_id: price_...
```

`plan_id` keys must match consumer catalog rows.

---

## 10. Stripe adapter (v1)

Use Stripe Checkout **subscription mode** and Billing Portal.

**Checkout session**

- `mode: subscription`
- `metadata.checkout_id` = opaque consumer checkout ID
- `subscription_data.metadata.checkout_id` = same
- `success_url` / `cancel_url` from start token `return_url` (+ optional `checkout_id` query param)
- Do **not** set `client_reference_id` to username

**Webhook mapping**

| Stripe event | Bridge action |
|---|---|
| `checkout.session.completed` | Allocate `subscription_ref` (`sub_<uuid>`); `subscription.activated` |
| `customer.subscription.updated` | Map status; may emit `subscription.canceled`, `subscription.plan_changed` |
| `customer.subscription.deleted` | `subscription.expired` |
| `invoice.paid` | `subscription.renewed` |
| `invoice.payment_failed` | `subscription.past_due` |

Verify with `STRIPE_WEBHOOK_SECRET`.

---

## 11. Configuration

```bash
# Public
BRIDGE_PUBLIC_URL=https://billing.example.com
CONSUMER_WEBHOOK_URL=https://app.example.com/api/webhooks/subscription-bridge

# Shared secrets (must match consumer)
BRIDGE_CONSUMER_WEBHOOK_SECRET=
BRIDGE_TOKEN_SECRET=                    # may equal webhook secret

# Stripe v1
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=

# Server
BRIDGE_LISTEN=127.0.0.1:8081

# Database
BRIDGE_DATABASE_URL=postgres://bridge_app:PASSWORD@HOST:5432/bridge?sslmode=require

# Optional
BRIDGE_LOG_LEVEL=info
```

**Consumer mirror (example Arkfile):**

```bash
ARKFILE_SUBSCRIPTIONS_ENABLED=true
ARKFILE_SUBSCRIPTION_BRIDGE_URL=https://billing.example.com
ARKFILE_SUBSCRIPTION_BRIDGE_WEBHOOK_SECRET=<same as BRIDGE_CONSUMER_WEBHOOK_SECRET>
```

Startup must **fail fast** if secrets, `CONSUMER_WEBHOOK_URL`, processor credentials, or database are missing.

---

## 12. Deployment

- Small app VPS (1–2 vCPU, 1–2 GB RAM) + managed Postgres in same region.
- TLS reverse proxy (Caddy/nginx) → bridge on loopback.
- Dedicated unprivileged runtime user; rootless container or static binary under systemd.
- Stripe dashboard: register `https://billing.example.com/v1/webhooks/stripe` for subscription events.

---

## 13. Operations CLI

| Command | Purpose |
|---|---|
| `bridge health` | Liveness + DB connectivity |
| `bridge show-checkout <checkout_id>` | Local checkout + subscription mapping |
| `bridge show-subscription <subscription_ref>` | Status + processor IDs (operator only) |
| `bridge replay-event <event_id>` | Re-POST undelivered callback |
| `bridge reconcile` | Poll active subscriptions against processor |
| `bridge list-undelivered` | Events where `consumer_delivered=false` |

Paid subscription cancel: processor dashboard or portal — not consumer admin CLI.

---

## 14. Testing requirements

**Unit tests**

- Start/portal token sign+verify (shared vectors with consumer `subbridge` package).
- Webhook HMAC sign+verify + replay window rejection.
- GET auth sign+verify.
- Stripe webhook parsing → normalized events.
- Idempotency on `event_id` and `processor_event_id`.

**Integration tests**

- Stripe test mode: checkout → webhook → mock consumer HTTP server captures POST.
- Ephemeral Postgres in CI (not SQLite).

**Cross-repo e2e**

Consumer app runs shell tests against `subscription-bridge-mock.go` (no live Stripe required). Mock implements `/v1/start`, `/v1/subscriptions/{ref}`, `/v1/mock/activate`, `/v1/mock/expire`.

---

## 15. Recommended repository layout

```
subscription-bridge/
├── SPEC.md                    # copy of this document
├── cmd/
│   ├── bridge/                # HTTP server main
│   └── bridge-cli/            # operator CLI
├── internal/
│   ├── protocol/              # types + validation
│   ├── hmac/                  # tokens + webhook + GET auth
│   ├── store/                 # postgres repositories
│   ├── engine/                # state machine + notifier
│   ├── notify/                # consumer webhook client + retry
│   └── adapters/
│       └── stripe/
├── migrations/
├── config/
│   └── plans.example.yaml
├── docker-compose.yml         # bridge + postgres for dev
├── Dockerfile
└── README.md
```

---

## 16. Build phases (bridge repo)

1. **Protocol types + HMAC helpers** — share test vectors with consumer `subbridge` package.
2. **Postgres migrations + `/v1/start` stub** — redirect to test URL.
3. **Stripe adapter + `/v1/webhooks/stripe`** — test mode end-to-end.
4. **Outbound notifier + retry** — POST to mock consumer.
5. **`/v1/portal` + GET `/v1/subscriptions/{ref}`**.
6. **Deploy artifacts** — systemd, Caddy, health checks.
7. **Operator CLI + runbook**.

---

## 17. Consumer integration checklist (any app)

1. Define local `subscription_plans` catalog with opaque `plan_id` strings.
2. On user checkout: create local `checkout_id`, sign start token, redirect browser to `{BRIDGE_URL}/v1/start?token=...`.
3. Implement `POST /api/webhooks/subscription-bridge` with HMAC verification.
4. On webhook `subscription.activated`: link `subscription_ref`, apply local subscription state.
5. Block conflicting commerce paths while subscribed (e.g. one-off top-ups → 409).
6. Portal: sign portal token with active `subscription_ref`; redirect to `/v1/portal`.
7. Reconcile: periodic GET `/v1/subscriptions/{subscription_ref}` for bridge-backed rows nearing period end.
8. Gift/comp subscriptions (no processor) stay entirely on consumer — never call bridge.

---

## 18. Explicitly out of scope for v1

- Username or email in tokens or processor metadata
- Consumer storage of processor-native IDs
- One-off payments (use a separate payment host)
- Proration, coupons, tax, multi-currency
- Multiple concurrent paid subscriptions per checkout
- Automated chargeback → access purge
- Public multi-merchant signup

---

## 19. Status

**Greenfield — bridge repository not yet created.** Arkfile consumer side is implemented: schema, `subbridge/` HMAC package, `POST /api/webhooks/subscription-bridge`, checkout/portal redirects, mock bridge for e2e, 26 subscription shell tests. Build this service in a **separate git repo** per sections 15–16; pair with Arkfile staging using Stripe test mode.

---

## 20. References

- Arkfile consumer contract: `docs/wip/prod-prep/05-subscriptions.md`
- Shared HMAC implementation: `subbridge/hmac.go`, `subbridge/hmac_test.go`
- Mock bridge for CI: `scripts/testing/subscription-bridge-mock.go`
- [Stripe Checkout subscriptions](https://docs.stripe.com/payments/checkout/subscriptions)
- [Stripe Billing webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)
