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
2. `sig = HMAC-SHA256(token_key, body)` → lowercase hex.
3. `token = base64url(body) + "." + hex(sig)` (RawURLEncoding, no padding).

**Validation**

- Verify HMAC with the HKDF-derived token key.
- Reject if `now > exp + 300s`.
- Require `checkout_id`, `plan_id`.
- **No username field** — must not exist in payload.
- Upsert `bridge_checkouts` row idempotently on `checkout_id`.
- Resolve `plan_id` → processor SKU; create hosted checkout session.
- Processor metadata: `{ "checkout_id": "<id>" }` only (never username).
- Response: HTTP 302 to processor hosted checkout URL.

**Pairing root and key derivation**

The consumer and bridge store one independently generated pairing root of at least 32 random bytes (64 lowercase hex characters recommended). They derive three 32-byte keys using HKDF-SHA256:

- salt: ASCII `subscription-bridge/v1`
- token key info: ASCII `consumer-to-bridge/token`
- callback key info: ASCII `bridge-to-consumer/callback`
- reconcile key info: ASCII `consumer-to-bridge/reconcile`

Keys are binary HKDF output, not hex text. Implementations must never use the pairing root directly as an HMAC key. Rotation uses a short two-root verification window, with all new signatures generated from the new root.

Golden vector for pairing root ASCII `0123456789abcdef0123456789abcdef`:

```text
token     d4c6d2a424e79004575dfb6eab85d0563a16d21ff3b8b24a67f7b61768cf0684
callback  82764734bee59c2e91e6c1e2a2adca2ba734282e9bf86f650108aec28c6f286f
reconcile 36bda83be5fd1fd170ae5bac3f6e79a12a299bb930653b8cf28e5d9122b28dbf
```

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
**HMAC key:** HKDF-derived callback key.

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
  "state_version": 4,
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
- Bridge increments `state_version` in the same database transaction as every consumer-visible state change. Versions begin at 1 and are strictly monotonic per `subscription_ref`.
- Retries on consumer 5xx with exponential backoff until 2xx or operator intervention.
- Consumer deduplicates on `event_id` (insert into `subscription_events` with UNIQUE).
- Consumer applies a callback only when `state_version` is greater than its stored version. It records lower/equal versions as `ignored_stale` and returns 2xx.

The notifier sends the stored immutable JSON bytes. Any 2xx marks delivery complete. Network failures, 408, 425, 429, and 5xx retry with full jitter over 1 minute, 5 minutes, 15 minutes, 1 hour, then a 6-hour cap. Other 4xx responses are dead-lettered because they indicate a protocol/configuration defect. Attempts continue until delivery or explicit operator abandonment; alert after 1 hour and again after 24 hours. Concurrent notifiers claim rows using leases and `FOR UPDATE SKIP LOCKED`.

`event_id`, `checkout_id`, and `subscription_ref` are opaque values with the `evt_`, `subchk_`, and `sub_` prefixes respectively. All callback fields are required except `processor_family`; timestamps are UTC RFC3339. The receiver must reject unknown event/status values, malformed identifiers, periods where end is not after start, and incompatible event/status pairs.

### 5.4 Subscription snapshot (consumer → bridge, server-to-server)

**Endpoint:** `GET /v1/subscriptions/{subscription_ref}`

**Auth header:** `Authorization: Subscription-Bridge-HMAC t=<unix>,v1=<hex>`

**String to sign:** `GET\n/v1/subscriptions/{subscription_ref}\n<unix>`

**Response 200:** snapshot object with all callback state fields, including `state_version`, but without `event_id` or `event_type`.
**Response 404:** unknown `subscription_ref`.

Used by consumer reconcile jobs and operator `sync` commands.

The reconcile request uses the HKDF-derived reconcile key. The bridge returns the same small 404 body for every unknown well-formed reference and performs no processor lookup in the request path. Exact wall-clock equality is not required; authenticated requests must avoid materially different response classes that expose internal processor state.

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
| POST | `/v1/webhooks/adyen` | Adyen Standard webhook (v1) |

Verify the processor-native signature before parsing: Stripe's `Stripe-Signature`, or Adyen's HMAC signature over the documented notification fields. Store the provider's stable event identity in `(processor_family, processor_event_id)` UNIQUE for idempotency. Acknowledge only after the normalized event and any outbound callback are durably committed.

### 6.3 Server-to-server (consumer)

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/subscriptions/{subscription_ref}` | Reconcile snapshot |

### 6.4 Dev/test only (optional mock helpers)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/mock/activate` | Test helper: `{checkout_id}` → fire `subscription.activated` |
| POST | `/v1/mock/expire` | Test helper: `{subscription_ref}` → fire `subscription.expired` |
| POST | `/v1/mock/replay` | Test helper: replay the stored callback for `{subscription_ref}` |

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
    processor_family TEXT NOT NULL CHECK (processor_family IN ('stripe', 'adyen')),
    processor_checkout_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sb_subscriptions (
    subscription_ref TEXT PRIMARY KEY,
    checkout_id TEXT NOT NULL UNIQUE REFERENCES sb_checkouts(checkout_id),
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'trialing', 'past_due', 'canceled', 'expired')),
    state_version BIGINT NOT NULL CHECK (state_version >= 1),
    processor_family TEXT NOT NULL CHECK (processor_family IN ('stripe', 'adyen')),
    processor_customer_id TEXT,
    processor_subscription_id TEXT,
    provider_payment_method_ref TEXT,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    past_due_since TIMESTAMPTZ,
    canceled_at TIMESTAMPTZ,
    next_charge_at TIMESTAMPTZ,
    scheduler_lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sb_subscriptions_processor_sub ON sb_subscriptions(processor_subscription_id);
CREATE INDEX idx_sb_subscriptions_due
    ON sb_subscriptions(next_charge_at)
    WHERE processor_family = 'adyen' AND status IN ('active', 'past_due');

CREATE TABLE sb_outbound_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    subscription_ref TEXT NOT NULL REFERENCES sb_subscriptions(subscription_ref),
    checkout_id TEXT NOT NULL REFERENCES sb_checkouts(checkout_id),
    state_version BIGINT NOT NULL,
    payload_json JSONB NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    last_error_class TEXT,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_sb_outbound_version
    ON sb_outbound_events(subscription_ref, state_version);
CREATE INDEX idx_sb_outbound_due
    ON sb_outbound_events(next_attempt_at) WHERE delivered_at IS NULL;

CREATE TABLE sb_processor_events (
    processor_family TEXT NOT NULL,
    processor_event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    payload_json JSONB NOT NULL,
    PRIMARY KEY (processor_family, processor_event_id)
);

CREATE TABLE sb_charge_attempts (
    attempt_id UUID PRIMARY KEY,
    subscription_ref TEXT NOT NULL REFERENCES sb_subscriptions(subscription_ref),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    attempt_number INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    processor_payment_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'authorized', 'refused', 'error', 'canceled')),
    refusal_reason_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    UNIQUE (subscription_ref, period_start, attempt_number)
);
```

**No `username` column anywhere.**

Provider references are sensitive operational data. Do not log them; encrypt `provider_payment_method_ref` at the application layer with a dedicated data-encryption key or a managed KMS envelope key. Run migrations through `bridge migrate`; production startup checks the schema version but does not silently migrate.

---

## 9. Processor adapter interface

Each adapter implements (Go interface suggested):

```go
type ProcessorAdapter interface {
    Family() string
    CreateCheckout(ctx context.Context, request CheckoutRequest) (CheckoutResult, error)
    CreatePortalSession(ctx, processorCustomerID, returnURL string) (portalURL string, err error)
    ParseWebhook(ctx context.Context, headers http.Header, body []byte) ([]NormalizedEvent, error)
    GetSubscription(ctx context.Context, subscription ProcessorSubscription) (*SubscriptionState, error)
    CancelSubscription(ctx context.Context, subscription ProcessorSubscription, atPeriodEnd bool) error
    ChargeRenewal(ctx context.Context, request RenewalRequest) (RenewalResult, error)
}
```

`ChargeRenewal` returns `ErrProviderManaged` for Stripe. `CreatePortalSession` uses Stripe Billing Portal for Stripe and the bridge-hosted portal for Adyen. The subscription engine is the only component allowed to map `NormalizedEvent` into state changes and protocol callbacks.

### 9.1 Plan SKU config (`config/plans.yaml`)

```yaml
default_processor: stripe

plans:
  plan_500gb:
    currency: USD
    amount_minor: 500
    interval: month
    stripe:
      price_id: price_...
    adyen:
      merchant_account: ExampleMerchant
      country_code: CH
  plan_1tb:
    currency: EUR
    amount_minor: 900
    interval: month
    stripe:
      price_id: price_...
    adyen:
      merchant_account: ExampleMerchantEU
      country_code: DE
```

`plan_id` keys must match consumer catalog rows. Amount and currency are immutable for an existing plan ID; changing either requires a new plan ID. Checkout processor selection is deterministic: an explicit configured plan processor, otherwise `default_processor`. It must not be chosen from user-controlled query parameters.

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
| `checkout.session.completed` | Link checkout, customer, and subscription IDs; fetch current subscription; never infer payment from checkout completion alone |
| `customer.subscription.created` | Fetch authoritative subscription; activate only for `active` or `trialing` |
| `customer.subscription.updated` | Fetch authoritative subscription; emit only a real status, period, cancellation, or price change |
| `customer.subscription.deleted` | `subscription.expired` |
| `invoice.paid` | For a later billing period, advance period and emit `subscription.renewed`; initial invoice may complete activation instead |
| `invoice.payment_failed` | `subscription.past_due` |

Map Stripe `trialing` → `trialing`, `active` → `active`, `past_due`/`unpaid`/`paused` → `past_due`, and `canceled`/`incomplete_expired` → `expired`. `incomplete` is not consumer-visible until it becomes active/trialing or expires. A scheduled cancellation remains `canceled` with access through `current_period_end`; deletion or period completion becomes `expired`.

Verify with `STRIPE_WEBHOOK_SECRET`. For every webhook, insert the Stripe event first, lock the subscription row, retrieve the latest Stripe subscription, and then compute a transition. This makes late Stripe delivery unable to regress state. The same transaction increments `state_version` and inserts the immutable outbound event. Price IDs not present in the configured reverse map are quarantined for operator action rather than sent to the consumer.

Use Stripe API idempotency keys derived from `checkout_id` for Checkout Session creation and from `event_id` for operator-initiated mutations. Retry network errors, 409, and 429/5xx according to Stripe guidance; do not retry deterministic 4xx responses.

---

## 11. Adyen adapter (v1)

Adyen v1 is a complete bridge-scheduled subscription implementation. The initial payment uses Adyen Checkout Sessions/Drop-in and stores a reusable payment method. Renewals use Adyen's recurring `/payments` flow; Adyen does not own the schedule.

**Initial checkout**

- Generate a bridge-only `shopperReference` (`sbr_<random>`), never a username, email, or consumer identifier.
- Set `reference=checkout_id`, `storePaymentMethod=true`, `shopperInteraction=Ecommerce`, and `recurringProcessingModel=Subscription`.
- Set amount/currency and `merchantAccount` only from the immutable plan configuration.
- Permit only HTTPS return URLs previously signed in the consumer token.
- Persist the resulting `storedPaymentMethodId`/recurring detail reference encrypted.
- Activate only after an authenticated `AUTHORISATION` success for the initial attempt and durable association with the checkout.

**Scheduled renewal**

For each due subscription, acquire a PostgreSQL lease with `FOR UPDATE SKIP LOCKED`, insert one `sb_charge_attempts` row, and call Adyen `/payments` with:

```text
shopperInteraction=ContAuth
recurringProcessingModel=Subscription
shopperReference=<bridge-generated value>
storedPaymentMethodId=<encrypted token after decryption>
reference=<stable charge-attempt id>
Idempotency-Key=<sb_charge_attempts.idempotency_key>
```

The period calendar is computed in UTC from the original activation day. Monthly anniversaries clamp to the last day of shorter months. The next period is not committed until authorization succeeds. One scheduler process may crash at any point without producing a second charge because the attempt row and Adyen idempotency key are stable.

**Adyen event mapping**

| Adyen notification/result | Bridge action |
|---|---|
| Initial `AUTHORISATION`, success | Persist token/linkage, allocate `subscription_ref`, emit `subscription.activated` |
| Renewal `AUTHORISATION`, success | Mark attempt authorized, advance period, emit `subscription.renewed` |
| Renewal `AUTHORISATION`, refused | Mark attempt refused, set first `past_due_since`, emit `subscription.past_due` |
| `CANCELLATION`/`CANCEL_OR_REFUND` for the active recurring payment contract | Reconcile; emit `subscription.canceled` or `subscription.expired` only when the bridge state actually changes |
| Chargeback/refund notifications | Record for operations; do not silently invent a protocol state transition in v1 |

Verify every Standard webhook notification item using Adyen HMAC before acknowledging it. Respond with the exact Adyen acceptance response only after committing the processor event. Derive a stable processor event ID from Adyen's `pspReference`, `eventCode`, `success`, and `originalReference` where no single event ID is supplied.

**Retries and dunning**

- Attempt 1 at `next_charge_at`; retry refused/transient renewals after 1 day, 3 days, and 5 days (configurable).
- A transport timeout remains `pending`; query Adyen by idempotency/reference or await webhook before retrying.
- Emit `subscription.past_due` once when entering that state. Successful recovery emits `subscription.renewed` and clears `past_due_since`.
- After the final failed attempt, remain `past_due` through the configured consumer grace period, then set `expired`, increment `state_version`, and emit `subscription.expired`.
- Never retry refusal codes classified as stolen, invalid, closed, or revoked payment method until the customer replaces the method.

**Bridge-hosted portal**

The signed `/v1/portal` route renders a bridge page that supports cancel-at-period-end, immediate cancel (operator-policy controlled), and payment-method replacement through Adyen Drop-in. CSRF protection and the short-lived portal token are mandatory. No processor identifier is exposed in HTML or URLs. Cancellation locks the subscription row, increments `state_version`, and emits `subscription.canceled`; the scheduler emits `subscription.expired` at period end.

---

## 12. Configuration

```bash
# Public
BRIDGE_PUBLIC_URL=https://billing.example.com
CONSUMER_WEBHOOK_URL=https://app.example.com/api/webhooks/subscription-bridge

# One consumer pairing root; derive directional keys with HKDF
BRIDGE_CONSUMER_PAIRING_ROOT=

# Provider selection and Stripe
BRIDGE_DEFAULT_PROCESSOR=stripe
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=

# Adyen
ADYEN_API_KEY=
ADYEN_HMAC_KEY=
ADYEN_LIVE_PREFIX=
ADYEN_ENVIRONMENT=test
ADYEN_DATA_ENCRYPTION_KEY=

# Server
BRIDGE_LISTEN=127.0.0.1:8081

# Database
BRIDGE_DATABASE_URL=postgres://bridge_app:PASSWORD@HOST:5432/bridge?sslmode=require

# Optional
BRIDGE_LOG_LEVEL=info
BRIDGE_SCHEDULER_ENABLED=true
BRIDGE_RENEWAL_RETRY_DELAYS=24h,72h,120h
```

**Consumer mirror (example Arkfile):**

```bash
ARKFILE_SUBSCRIPTIONS_ENABLED=true
ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED=true
ARKFILE_SUBSCRIPTION_BRIDGE_URL=https://billing.example.com
ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT=<same as BRIDGE_CONSUMER_PAIRING_ROOT>
```

Startup must fail fast if the pairing root, consumer URL, database, selected provider credentials, plan mappings, or encryption key for Adyen are missing. It must also reject HTTP public/consumer URLs except explicit loopback development URLs. Stripe-only deployments need no Adyen credentials; Adyen-only deployments need no Stripe credentials.

---

## 13. Deployment

- Small app VPS (1–2 vCPU, 1–2 GB RAM) + managed Postgres in same region.
- TLS reverse proxy (Caddy) → bridge on loopback.
- Dedicated unprivileged runtime user; rootless container or static binary under systemd.
- Stripe dashboard: register `https://billing.example.com/v1/webhooks/stripe` for subscription events.
- Adyen Customer Area: configure the Standard webhook at `https://billing.example.com/v1/webhooks/adyen`, enable HMAC, and restrict API credentials to required Checkout/recurring operations.
- If containers are used, ship a `Containerfile` and rootless Podman/Quadlet definitions. Native systemd deployment remains supported.

---

## 14. Operations CLI

| Command | Purpose |
|---|---|
| `bridge health` | Liveness + DB connectivity |
| `bridge show-checkout <checkout_id>` | Local checkout + subscription mapping |
| `bridge show-subscription <subscription_ref>` | Status + processor IDs (operator only) |
| `bridge replay-event <event_id>` | Re-POST undelivered callback |
| `bridge reconcile` | Poll active subscriptions against processor |
| `bridge list-undelivered` | Events where `consumer_delivered=false` |
| `bridge scheduler-status` | Due/leased Adyen renewals and oldest pending attempt |
| `bridge retry-charge <attempt_id>` | Retry an eligible Adyen attempt with the existing idempotency identity |

Paid subscription cancel: processor dashboard or portal — not consumer admin CLI.

---

## 15. Testing requirements

**Unit tests**

- HKDF golden vectors above; start/portal token, callback, and reconcile signatures must interoperate with the consumer `subbridge` package.
- Replay-window boundaries, malformed headers, invalid identifiers, unknown JSON fields, body limits, and URL validation.
- State transition matrix for every event/status pair and monotonic `state_version`.
- Stripe and Adyen fixtures for every mapping in sections 10–11, including duplicate and out-of-order provider events.
- Calendar-period tests for month ends and leap years.
- Scheduler crash tests before request, after request/before response, and after authorization/before commit.
- Idempotency on event ID, provider event identity, checkout ID, state version, and Adyen charge-attempt key.

**Integration tests**

- Stripe test mode: checkout → webhook → mock consumer HTTP server captures POST.
- Adyen test platform: initial checkout/tokenization → scheduled renewal → refusal → recovery → cancellation.
- Real PostgreSQL in CI (not SQLite), with at least two scheduler workers proving `SKIP LOCKED` leasing and one-charge behavior.
- Consumer endpoint returns 500 twice then 200: notifier delivers the identical event ID/body and stops after success.
- A rolled-back provider webhook transaction leaves no state version or outbound event.
- Reconcile returns exactly the latest committed state and version.

**Common adapter conformance suite**

Run the same black-box suite against Stripe and Adyen. Each adapter must create a checkout without consumer identity, activate once, renew once, enter and recover from past due, cancel, expire, reconcile, reject bad signatures, and remain idempotent under duplicate delivery. Provider-specific stubs may control time and results, but cannot bypass the production engine or store.

**Release acceptance**

- `go test ./...`, race-enabled unit tests, migrations on supported PostgreSQL versions, static analysis, and dependency vulnerability scans are green.
- No callback is sent before its database transaction commits.
- Killing either notifier or Adyen scheduler at every injected failure point produces no duplicate callback and no duplicate charge.
- Logs and HTTP responses contain no pairing root, derived key, payment-method reference, provider customer ID, or raw provider payload.
- Both provider conformance suites pass from a clean database.

**Cross-repo e2e**

Consumer app runs shell tests against `subscription-bridge-mock.go` (no live Stripe required). Mock implements `/v1/start`, authenticated `/v1/subscriptions/{ref}`, `/v1/mock/activate`, `/v1/mock/expire`, and `/v1/mock/replay`.

---

## 16. Recommended repository layout

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
│   ├── scheduler/             # Adyen recurring charge leasing/dunning
│   └── adapters/
│       ├── stripe/
│       └── adyen/
├── migrations/
├── config/
│   └── plans.example.yaml
├── Containerfile
├── quadlet/
│   └── subscription-bridge.container
└── README.md
```

---

## 17. Build phases (bridge repo)

1. **Protocol types + HMAC helpers** — share test vectors with consumer `subbridge` package.
2. **Postgres migrations + `/v1/start` stub** — redirect to test URL.
3. **Provider-neutral engine + outbound notifier** — version state transactionally and POST to a mock consumer with retries.
4. **Stripe adapter** — Checkout, Billing Portal, webhooks, reconcile, and conformance suite.
5. **Adyen adapter** — initial Checkout/tokenization, authenticated webhook, and reconcile.
6. **Adyen scheduler and hosted portal** — recurring charges, dunning, payment-method replacement, and cancellation.
7. **Common adapter conformance** — both providers pass identical lifecycle acceptance.
8. **Deploy artifacts** — systemd, Caddy, optional Podman/Quadlet, health checks.
9. **Operator CLI + backup/restore and incident runbooks**.

---

## 18. Consumer integration checklist (any app)

1. Define local `subscription_plans` catalog with opaque `plan_id` strings.
2. On user checkout: create local `checkout_id`, sign start token, redirect browser to `{BRIDGE_URL}/v1/start?token=...`.
3. Implement `POST /api/webhooks/subscription-bridge` with HMAC verification.
4. Validate the full callback, lock by opaque subscription/checkout, compare `state_version`, and atomically insert the event plus state change.
5. Block conflicting commerce paths while subscribed (e.g. one-off top-ups → 409).
6. Portal: sign portal token with active `subscription_ref`; redirect to `/v1/portal`.
7. Reconcile: periodic GET `/v1/subscriptions/{subscription_ref}` for bridge-backed rows nearing period end.
8. Gift/comp subscriptions (no processor) stay entirely on consumer — never call bridge.

---

## 19. Explicitly out of scope for v1

- Username or email in tokens or processor metadata
- Consumer storage of processor-native IDs
- One-off payments (use a separate payment host)
- Proration, coupons, tax calculation, currency conversion, or changing currency on an existing plan
- Multiple concurrent paid subscriptions per checkout
- Automated chargeback → access purge
- Public multi-merchant signup

---

## 20. Status

**Greenfield — bridge repository not yet created.** Arkfile's consumer implements ordered transactional callbacks, HKDF-derived protocol keys, checkout/portal redirects, reconcile authentication, and a protocol-faithful mock. Build the service in a separate git repository per sections 16–17. Stripe and Adyen are both required v1 adapters and must pass the common conformance suite before release.

---

## 21. References

- Arkfile consumer contract: `docs/wip/prod-prep/05-subscriptions.md`
- Shared HMAC implementation: `subbridge/hmac.go`, `subbridge/hmac_test.go`
- Mock bridge for CI: `scripts/testing/subscription-bridge-mock.go`
- [Stripe Checkout subscriptions](https://docs.stripe.com/payments/checkout/subscriptions)
- [Stripe Billing webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)
- [Adyen tokenization](https://docs.adyen.com/online-payments/tokenization/)
- [Adyen recurring payments](https://docs.adyen.com/online-payments/tokenization/make-recurring-payments/)
- [Adyen webhook HMAC verification](https://docs.adyen.com/development-resources/webhooks/verify-hmac-signatures/)
