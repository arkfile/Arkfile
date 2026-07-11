# Subscription Bridge — Standalone Service Specification (v1)

This document is the **normative build spec** for a small, reusable **Subscription Bridge** service. The bridge sits between exactly one **consumer application** per deployment (any SaaS that sells recurring plan-based access) and the required v1 payment processors, **Stripe and Adyen**. The consumer holds user identity and business rules; the bridge holds processor API keys and maps both processor lifecycles into **Subscription Bridge Protocol v1**. The only cross-system join identifiers are opaque `checkout_id` (one checkout attempt) and `subscription_ref` (one ongoing paid subscription). `plan_id` is a shared catalog key; `event_id` is an idempotency and audit identifier. **No consumer user identifiers** appear in the bridge database or processor metadata.

A reference consumer implementation exists in the Arkfile monorepo (`docs/wip/prod-prep/05-subscriptions.md`, package `subbridge/`). This spec is product-neutral so the bridge can be deployed separately for different products. A v1 deployment serves one consumer protocol namespace, one consumer webhook URL, and one pairing-root set. Multi-consumer and public multi-merchant operation are out of scope.

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
| **Processor** | Stripe or Adyen; both adapters are required for a complete v1 release. |
| **plan_id** | Shared immutable catalog key defined by the consumer (`plan_500gb`). Bridge maps it to trusted processor configuration. |
| **checkout_id** | Opaque per-attempt cross-system join ID from the consumer (`subchk_<uuid>`). Only join ID sent to processor metadata. |
| **subscription_ref** | Opaque ongoing cross-system join ID (`sub_<uuid>`). Stable across renewals. |
| **event_id** | Opaque identifier for one immutable callback; used for idempotency and audit, not identity joining. |
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
Processor ──► POST ──► Bridge /v1/webhooks/adyen   (never hits consumer)
```

**Responsibilities**

| Party | Knows | Must not know |
|---|---|---|
| Consumer | username, local plan catalog, subscription status, feature gates | Processor customer/subscription IDs, card data |
| Bridge | processor objects, checkout sessions, checkout_id, subscription_ref | Consumer usernames, application secrets beyond shared HMAC |
| Processor | card/bank instruments, customer email for receipts | Consumer usernames |

A deployment has exactly one consumer application. Its pairing-root set, callback URL, and protocol namespace must not be shared with another consumer. Separate products require separate bridge deployments in v1.

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

**Clock skew and token lifetime**

The default and maximum permitted clock-skew allowance is 300 seconds. Start and portal tokens contain integer Unix-second `iat` and `exp` fields. Require `exp > iat`, `exp - iat <= 900`, `iat <= now + 300`, and `now <= exp + 300`. Reject missing, non-integer, negative, or out-of-range timestamps. Callback and reconciliation signatures use the same 300-second request replay window, but a notifier retry creates a fresh signature header over the unchanged stored callback body.

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
  "return_url": "https://app.example.com/billing/return",
  "iat": 1767225600,
  "exp": 1767226500
}
```

**Signing algorithm**

1. `body = JSON.Marshal(payload)` (compact, UTF-8).
2. `sig = HMAC-SHA256(token_key, body)` → lowercase hex.
3. `token = base64url(body) + "." + hex(sig)` (RawURLEncoding, no padding).

**Validation**

- Verify HMAC with the HKDF-derived token key using constant-time comparison before acting on the payload.
- Require exactly `checkout_id`, `plan_id`, `return_url`, `iat`, and `exp`; reject unknown fields and enforce the lifetime rules in section 4.
- Require a normalized HTTPS `return_url`, except explicit loopback development URLs.
- **No username field** — it and every other consumer identity field must be rejected.
- Resolve `plan_id` and processor family from trusted configuration before accepting the checkout.
- For Adyen, generate the bridge-only processor shopper reference before the first checkout insert.
- In a short transaction, insert the first accepted `checkout_id` bound immutably to `plan_id`, normalized `return_url`, processor family, token/request fingerprint, stable provider idempotency key, and the Adyen shopper reference when applicable. The fingerprint is SHA-256 over the verified raw token payload bytes.
- An exact retry may return the existing live session or resume creation with the same provider idempotency key. Reuse with any different bound value returns HTTP 409. Completed, canceled, or expired checkout IDs are terminal and cannot be reused; the consumer must create a new ID.
- Call the provider outside the database transaction. Both Stripe and Adyen initial session creation use the stable checkout idempotency key. A timeout resumes the same creation operation; it must not allocate a second key or silently create an unrelated session.
- Processor metadata: `{ "checkout_id": "<id>" }` only (never username).
- Response: HTTP 302 to processor hosted checkout URL.

For checkout binding, normalize `return_url` by parsing it as an absolute URI, rejecting userinfo and fragments, lowercasing the scheme and DNS host, removing the HTTPS default port, and replacing an empty path with `/`. Preserve the parsed path and query ordering exactly; do not decode/re-encode application query values. Serialize that normalized URI and bind it to the checkout row. Invalid escapes, ambiguous authorities, and non-HTTPS non-loopback URLs fail closed.

**Pairing root and key derivation**

The consumer and bridge each configure the same pairing root as **exactly 64 lowercase hexadecimal characters representing exactly 32 bytes**. Reject uppercase characters, whitespace, non-hex characters, prefixes such as `0x`, and every other length. Hex-decode the configuration value before HKDF-SHA256. Implementations must never use the 64 ASCII configuration characters as input key material.

Derive three 32-byte keys using HKDF-SHA256:

- salt: ASCII `subscription-bridge/v1`
- token key info: ASCII `consumer-to-bridge/token`
- callback key info: ASCII `bridge-to-consumer/callback`
- reconcile key info: ASCII `consumer-to-bridge/reconcile`

Keys are binary HKDF output, not hex text. Implementations must never use the decoded pairing root directly as an HMAC key. Protocol v1 configures exactly one active pairing root and defines no overlapping two-root verification window. Rotation is a coordinated operational change that temporarily interrupts cross-service authentication until both sides use the new root; a future protocol version may define an explicit overlap mechanism.

Canonical derivation vector:

```text
configured root  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
decoded root     00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
salt             subscription-bridge/v1
token info       consumer-to-bridge/token
callback info    bridge-to-consumer/callback
reconcile info   consumer-to-bridge/reconcile
token key        1c3ffa613421f6a4958704b3090e9b970af7dd9107ce328cc9c5d33546701fa2
callback key     069dddf506c40199b88267dbc754808242339730f5cb042f3d72e4e19dbe946d
reconcile key    c090ac1d8b5c248d45c8ce7ca9f9b463b1f6ad4a2086061d53111214e24a433c
```

`fixtures/protocol-v1.json` is the canonical machine-readable fixture for this derivation and the signed protocol examples. The consumer repository mirrors that file and records the source bridge commit or release.

### 5.2 Portal token (consumer → bridge, via browser)

Consumer signs when user opens manage/cancel portal.

**Payload:**

```json
{
  "subscription_ref": "sub_a8f3c1d2",
  "return_url": "https://app.example.com/billing",
  "iat": 1767225600,
  "exp": 1767226500
}
```

Same signing, exact-field decoding, timestamp validation, and URL validation as the start token. Bridge looks up `subscription_ref` → processor customer, creates or resumes the appropriate portal session, and redirects the browser.

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
  "state_version": 1,
  "status": "active",
  "current_period_start": "2026-01-01T00:00:00Z",
  "current_period_end": "2026-02-01T00:00:00Z",
  "cancel_at_period_end": false,
  "state_changed_at": "2026-01-01T00:00:00Z"
}
```

| `event_type` | Meaning |
|---|---|
| `subscription.activated` | First successful subscription or trial start |
| `subscription.renewed` | Successful renewal or a provider-authoritative restoration to renewable `active` state |
| `subscription.past_due` | Payment failed; processor status past_due |
| `subscription.canceled` | Renewal disabled while the subscription remains effective through `current_period_end` |
| `subscription.expired` | Subscription ended; no longer active |
| `subscription.plan_changed` | Plan SKU changed on existing subscription |
| `subscription.sync` | Consumer-local audit event created when applying a snapshot; the bridge never emits it as a callback |

**`status` values:** `active`, `trialing`, `past_due`, `canceled`, `expired`.

`canceled` means non-renewing but still effective through `current_period_end`; it always has `cancel_at_period_end=true`. `expired` means no longer effective and always has `cancel_at_period_end=false`. Immediate cancellation transitions directly to `expired` and emits `subscription.expired`. Consumer entitlement during `past_due` is governed by the consumer's independently documented local grace policy; bridge dunning determines only whether billing recovery continues and when the canonical state transitions to `expired`.

Allowed bridge callback pairs are exact: `subscription.activated` with `active` or `trialing`; `subscription.renewed` with `active`; `subscription.past_due` with `past_due`; `subscription.canceled` with `canceled`; `subscription.expired` with `expired`; and `subscription.plan_changed` with `active`. `subscription.sync` is not a callback pair. Every other event/status combination fails closed.

**Idempotency**

- Bridge generates a stable `event_id` per logical transition and stores it in `sb_outbound_events` before POST.
- Bridge increments `state_version` in the same database transaction as every consumer-visible state change. Versions begin at 1 and are strictly monotonic per `subscription_ref`.
- Retries on consumer 5xx with exponential backoff until 2xx or operator intervention.
- Consumer deduplicates on `event_id` (insert into `subscription_events` with UNIQUE).
- Consumer applies a callback only when `state_version` is greater than its stored version. It records lower/equal versions as `ignored_stale` and returns 2xx.

The notifier sends the exact immutable bytes stored in `payload_body`; JSONB serialization is never authoritative. Any 2xx marks delivery complete. Network failures, 408, 425, 429, and 5xx retry with full jitter over 1 minute, 5 minutes, 15 minutes, 1 hour, then a 6-hour cap. Other 4xx responses transition to `dead_lettered` because they indicate a protocol/configuration defect. Attempts continue while state is `pending` until delivery or audited operator abandonment. Alert after 1 hour and again after 24 hours. Concurrent notifiers claim rows using leases and `FOR UPDATE SKIP LOCKED`.

`event_id`, `checkout_id`, and `subscription_ref` are opaque values with the `evt_`, `subchk_`, and `sub_` prefixes respectively. Each is at most 160 ASCII characters in total and has a non-empty suffix containing only letters, digits, `_`, or `-`. Every shown callback field is required; no other field is permitted. `processor_family` is intentionally absent because consumer behavior must be provider-neutral. Timestamps use second-precision UTC RFC3339 with `Z`; period end must be after period start. `state_changed_at` is the time at which the canonical state represented by `state_version` was committed, never callback-send or retrieval time. The receiver must reject unknown fields, unknown event/status values, malformed identifiers, unordered periods, and incompatible event/status pairs.

### 5.4 Subscription snapshot (consumer → bridge, server-to-server)

**Endpoint:** `GET /v1/subscriptions/{subscription_ref}`

**Auth header:** `Authorization: Subscription-Bridge-HMAC t=<unix>,v1=<hex>`

**String to sign:** `GET\n/v1/subscriptions/{subscription_ref}\n<unix>`

**Response 200:** the exact snapshot schema below. Every field is required and unknown fields are rejected:

```json
{
  "protocol": "subscription-bridge",
  "version": 1,
  "checkout_id": "subchk_7f3a9c2e",
  "subscription_ref": "sub_a8f3c1d2",
  "plan_id": "plan_500gb",
  "state_version": 1,
  "status": "active",
  "current_period_start": "2026-01-01T00:00:00Z",
  "current_period_end": "2026-02-01T00:00:00Z",
  "cancel_at_period_end": false,
  "state_changed_at": "2026-01-01T00:00:00Z"
}
```

The snapshot has a dedicated protocol type; it is not a callback with omitted fields. Its status, period, cancellation, identifier, and timestamp validation is identical to the corresponding callback fields. `state_changed_at` has the same canonical-commit meaning. The JSON response is protected by HTTPS and the authenticated request; v1 does not add an independent response signature. The exact 200 response body and metadata are in `fixtures/protocol-v1.json`.
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

Perform only the bounded parsing required by the provider's signature scheme, then verify the processor-native signature: Stripe's `Stripe-Signature`, or Adyen's HMAC signature over the documented notification fields. After verification, compute a SHA-256 hash of the raw body and discard it. Store the provider's stable event identity in `(processor_family, processor_event_id)` UNIQUE together with the hash, processing state, timestamps, and only the minimum normalized fields required for recovery and audit. Raw provider payloads are not retained by default.

An optional diagnostic quarantine must be explicitly enabled, separately access-controlled, encrypted with authenticated envelope encryption and key-version metadata, automatically deleted within a configured maximum of 7 days, and excluded from ordinary logs, metrics, errors, and CLI output. Acknowledge a webhook only after durable ingestion. State effects and any outbound callback must later commit atomically before the event is marked `processed`.

`normalized_fields` is a strict internal JSON object, not a raw-payload escape hatch. Omit inapplicable keys; do not store null placeholders, customer/profile objects, email, billing details, metadata maps, or arbitrary provider extensions. The exact v1 shapes are:

| `normalized_kind` | Other required keys | Optional bounded keys |
|---|---|---|
| `stripe.checkout_changed` | `checkout_id`, `processor_customer_id`, `processor_subscription_id`, `provider_occurred_at`, `authoritative_refresh_required=true` | none |
| `stripe.subscription_changed` | `processor_subscription_id`, `provider_occurred_at`, `authoritative_refresh_required=true` | `provider_price_id` |
| `adyen.initial_authorisation` | `checkout_id`, `processor_payment_id`, `provider_status`, `provider_occurred_at`, `success` | none |
| `adyen.renewal_authorisation` | `attempt_reference`, `processor_payment_id`, `provider_status`, `provider_occurred_at`, `success` | `refusal_code` only when unsuccessful |
| `adyen.contract_changed` | `processor_payment_id`, `provider_status`, `provider_occurred_at` | none |
| `adyen.operational_adjustment` | `processor_payment_id`, `provider_status`, `provider_occurred_at` | none |

No other key or normalized kind is permitted in v1. A stored-payment-method reference from a verified successful initial Adyen event goes only into the event's authenticated-encrypted sensitive fields and is moved or re-encrypted into the subscription in the state transaction.

`provider_event_type` is the provider-native bounded event label retained for audit and adapter fixture selection; `normalized_kind` is the closed provider-neutral processing taxonomy above. Engine transition code switches only on `normalized_kind` and its validated shape. `provider_occurred_at` is the provider-asserted event time normalized to second-precision UTC RFC3339. It is audit context, not a trustworthy ordering token, and must never override authoritative retrieval, fencing, local period monotonicity, or terminal-state guards.

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

### 7.1 Checkout (`sb_checkouts.status`)

```
creating ──(provider session accepted)────► pending
creating ──(timeout/ambiguous result)─────► creating (resume with the same key)
creating/pending ──(checkout deadline)────► expired
pending ──(normalized provider completion)──► completed
pending ──(provider expiry/abandonment)────► expired
pending ──(browser cancellation)───────────► canceled
```

At first acceptance, set `expires_at` to token `exp + 300s` as the maximum `creating` deadline. When the provider returns a live session, configure that provider session to expire at a bridge-selected bounded time and atomically replace `expires_at` with the same instant before redirecting. A sweeper expires `creating` or `pending` rows at that deadline under a row lock. Provider completion and expiry racing at the boundary serialize on the checkout row; an authenticated authoritative completion already accepted by the provider wins only if the provider reports it effective no later than the configured session expiry.

### 7.2 Subscription (`sb_subscriptions.status`)

```
trialing/active ──(normalized payment failure)──► past_due
past_due ──(authoritative paid state)──────────► active
trialing ──(trial completes successfully)──► active
active/trialing/past_due ──(cancel at period end)──► canceled (effective through period end)
canceled ──(authoritative cancellation reversal)──► active
active/trialing/past_due/canceled ──(immediate termination)──► expired
any ──(authoritative provider termination)────────► expired
active ──(normalized plan mapping change)─────────► active (emit plan_changed)
```

Each transition that affects consumer subscription state emits the corresponding callback `event_type`. Trial completion, past-due recovery, and authoritative reversal of a scheduled cancellation emit `subscription.renewed` with `active`. Reversing cancellation atomically cancels the pending expiry action. A canceled row retains its final non-null period and has a durable `expire` action due at `current_period_end`. Immediate cancellation never enters `canceled`; it transitions directly to `expired`.

Set `past_due_since` only on the first transition into `past_due`; leave it unchanged during repeated failures, clear it on recovery to `active`, and retain it when dunning terminates in `expired` for audit. Set `canceled_at=state_changed_at` when entering `canceled` or when an explicit immediate cancellation enters `expired`; clear it if a scheduled cancellation is authoritatively reversed. Provider termination unrelated to an explicit cancellation does not invent `canceled_at`.

### 7.3 Outbound delivery (`sb_outbound_events.delivery_state`)

```
pending ──(2xx)──────────────────────────► delivered
pending ──(deterministic other 4xx)──────► dead_lettered
pending ──(audited operator action)──────► abandoned
dead_lettered/abandoned ──(audited requeue)──► pending
```

Network failures, 408, 425, 429, and 5xx leave the event `pending` and schedule a later attempt. Terminal rows have `next_attempt_at=NULL` and no active lease. Requeue preserves `event_id`, `state_version`, and `payload_body`.

Notifier claims also use fencing: claiming a due event or reclaiming an expired lease sets a new random claim token, increments `fencing_token`, and commits before network delivery. Delivery, retry scheduling, dead-lettering, or abandonment conditionally matches the event ID, `pending` state, claim token, and fence. A stale notifier with zero affected rows discards its result. Network I/O never occurs inside the claim or completion transaction.

### 7.4 Scheduled actions and fencing

Every durable action has type `renew` or `expire`, a due time, stable unique `action_key`, status, claim token, monotonically increasing fencing token, and bounded lease. Canonical timestamps are second-precision UTC. Define:

```text
target = renew: target billing period start (the prior period end)
target = expire: effective time of the terminal transition
action_key = "act_" + lowercase_hex(
    SHA-256(UTF-8("subscription-bridge/v1/action\n"
                  + subscription_ref + "\n"
                  + action_type + "\n"
                  + target.UTC().Format(RFC3339)))
)
```

The unique `action_key` makes creation idempotent. One renewal action represents one target billing period and may own multiple sequential charge attempts during dunning; it is not replaced after each refusal. Before network work, a short preparation transaction locks a due pending renewal action and inserts exactly one `prepared` attempt for its next `attempt_number`, containing the complete immutable request. A later claim transaction atomically sets both the action and that attempt to `running`, sets the same new random claim token on both, increments the action's `fencing_token`, copies the resulting fence to the attempt, sets their leases, and commits. Reclaiming expired ownership increments the action fence again and copies the new value.

A renewal claim must join and conditionally verify `automatic_charging_blocked=false`; the same condition is rechecked at completion. A worker may complete, reschedule, or otherwise mutate an action or attempt only with a conditional update matching the action ID, `running` status, claim token, and fencing token it received on both rows. Zero affected rows means the worker lost ownership and must discard its result. This condition is mandatory even when a database row lock is also used.

An expiry action has no charge attempt. Its claim increments the action fence and completion conditionally matches the action ID, `running` state, claim token, and fence.

An active Adyen subscription has one renewal action for its next period. A canceled subscription has one expiry action whose target is `current_period_end`. Exhausted Adyen dunning creates one expiry action whose target is the configured billing-termination deadline. These are distinct transitions and therefore distinct keys when their target times differ. A subscription with `automatic_charging_blocked=true` cannot have a renewal action claimed or created.

For a new renewal action, `due_at=target_at`. Definitive retryable refusal changes only `due_at`; `target_at` and `action_key` remain the target billing period. For canceled expiry, `target_at=due_at=current_period_end`. For exhausted dunning, compute `target_at=due_at=final_refusal_at + BRIDGE_DUNNING_TERMINATION_DELAY`, normalized to whole seconds.

Scheduled-action state is exact:

```text
pending ──(fenced claim)────────────────────► running
running ──(success)─────────────────────────► completed
running ──(retryable definitive refusal)────► pending (same action, later due_at)
running ──(ambiguous result/expired lease)──► uncertain
uncertain ──(fenced resolution claim)───────► running
uncertain ──(resolution deadline)───────────► manual_review
pending/running ──(superseding transition)──► canceled
```

For `uncertain`, set `due_at` to the next bounded resolution attempt, never later than the joined charge attempt's `resolution_deadline`. Each inconclusive exact replay returns it to `uncertain` with a later `due_at`. `manual_review`, `completed`, and `canceled` are not automatically claimable.

### 7.5 Adyen renewal attempt

```
prepared ──(claimed with incremented fence)──► running
running ──(authorized)───────────────────────► authorized
running ──(definitive refusal)──────────────► refused
running ──(timeout/ambiguous transport)─────► uncertain
running ──(lease expires without proof of no send)──► uncertain
running ──(inconclusive exact replay)────────► uncertain
uncertain ──(fenced exact-replay claim)──────► running
uncertain ──(resolution deadline)───────────► manual_review
```

Only a definitive refusal permits the same renewal action to be rescheduled for a later dunning attempt with a new attempt identity and idempotency key. `uncertain` and `manual_review` never do. Entering `manual_review` atomically sets both the attempt and action to `manual_review`, sets `automatic_charging_blocked=true`, prevents all later automatic charging actions, and leaves the consumer-visible subscription `past_due`. Only an audited operator resolution may clear the block or cause a real consumer-visible transition.

---

## 8. Database schema (PostgreSQL)

Use managed Postgres in production. The following is the normative logical schema; migrations may factor repeated checks into domains or helper functions without weakening them.

```sql
CREATE DOMAIN sb_utc_second AS TIMESTAMPTZ
    CHECK (VALUE = date_trunc('second', VALUE));

CREATE TABLE sb_checkouts (
    checkout_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    normalized_return_url TEXT NOT NULL,
    processor_family TEXT NOT NULL CHECK (processor_family IN ('stripe', 'adyen')),
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    provider_idempotency_key TEXT NOT NULL UNIQUE,
    processor_shopper_reference TEXT,
    status TEXT NOT NULL CHECK (status IN ('creating', 'pending', 'completed', 'expired', 'canceled')),
    subscription_ref TEXT UNIQUE,
    processor_checkout_id TEXT,
    expires_at sb_utc_second NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((processor_family = 'adyen') = (processor_shopper_reference IS NOT NULL))
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
    processor_initial_payment_id TEXT,
    processor_shopper_reference TEXT,
    payment_method_ciphertext BYTEA,
    payment_method_nonce BYTEA,
    payment_method_key_version TEXT,
    current_period_start sb_utc_second NOT NULL,
    current_period_end sb_utc_second NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    state_changed_at sb_utc_second NOT NULL,
    past_due_since TIMESTAMPTZ,
    canceled_at sb_utc_second,
    automatic_charging_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    charging_block_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (current_period_end > current_period_start),
    CHECK ((status = 'canceled') = cancel_at_period_end),
    CHECK ((processor_family = 'adyen') = (processor_shopper_reference IS NOT NULL)),
    CHECK (NOT automatic_charging_blocked OR status = 'past_due'),
    CHECK ((automatic_charging_blocked AND charging_block_reason IS NOT NULL)
        OR (NOT automatic_charging_blocked AND charging_block_reason IS NULL)),
    CHECK ((payment_method_ciphertext IS NULL AND payment_method_nonce IS NULL
            AND payment_method_key_version IS NULL)
        OR (payment_method_ciphertext IS NOT NULL AND payment_method_nonce IS NOT NULL
            AND payment_method_key_version IS NOT NULL))
);
CREATE UNIQUE INDEX idx_sb_subscriptions_processor_sub
    ON sb_subscriptions(processor_family, processor_subscription_id)
    WHERE processor_subscription_id IS NOT NULL;
CREATE UNIQUE INDEX idx_sb_subscriptions_shopper_ref
    ON sb_subscriptions(processor_shopper_reference)
    WHERE processor_shopper_reference IS NOT NULL;
CREATE UNIQUE INDEX idx_sb_subscriptions_initial_payment
    ON sb_subscriptions(processor_family, processor_initial_payment_id)
    WHERE processor_initial_payment_id IS NOT NULL;

CREATE TABLE sb_outbound_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    subscription_ref TEXT NOT NULL REFERENCES sb_subscriptions(subscription_ref),
    checkout_id TEXT NOT NULL REFERENCES sb_checkouts(checkout_id),
    state_version BIGINT NOT NULL,
    payload_body BYTEA NOT NULL,
    payload_json JSONB,
    delivery_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (delivery_state IN ('pending', 'delivered', 'dead_lettered', 'abandoned')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    dead_lettered_at TIMESTAMPTZ,
    abandoned_at TIMESTAMPTZ,
    last_error_class TEXT,
    claim_token UUID,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
      (delivery_state = 'pending' AND next_attempt_at IS NOT NULL
       AND delivered_at IS NULL AND dead_lettered_at IS NULL AND abandoned_at IS NULL)
      OR (delivery_state = 'delivered' AND next_attempt_at IS NULL
          AND delivered_at IS NOT NULL
          AND dead_lettered_at IS NULL AND abandoned_at IS NULL)
      OR (delivery_state = 'dead_lettered' AND next_attempt_at IS NULL
          AND delivered_at IS NULL AND dead_lettered_at IS NOT NULL
          AND abandoned_at IS NULL)
      OR (delivery_state = 'abandoned' AND next_attempt_at IS NULL
          AND delivered_at IS NULL AND dead_lettered_at IS NULL
          AND abandoned_at IS NOT NULL)
    ),
    CHECK ((claim_token IS NULL) = (lease_until IS NULL)),
    CHECK (delivery_state = 'pending' OR (claim_token IS NULL AND lease_until IS NULL))
);
CREATE UNIQUE INDEX idx_sb_outbound_version
    ON sb_outbound_events(subscription_ref, state_version);
CREATE INDEX idx_sb_outbound_due
    ON sb_outbound_events(next_attempt_at)
    WHERE delivery_state = 'pending';

CREATE TABLE sb_processor_events (
    processor_family TEXT NOT NULL,
    processor_event_id TEXT NOT NULL,
    processing_action_id UUID NOT NULL UNIQUE,
    provider_event_type TEXT NOT NULL,
    payload_hash BYTEA NOT NULL CHECK (octet_length(payload_hash) = 32),
    normalized_fields JSONB NOT NULL,
    sensitive_ciphertext BYTEA,
    sensitive_nonce BYTEA,
    sensitive_key_version TEXT,
    processing_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (processing_state IN ('pending', 'running', 'processed', 'quarantined', 'manual_review')),
    subscription_ref TEXT REFERENCES sb_subscriptions(subscription_ref),
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    claim_token UUID,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    last_error_class TEXT,
    CHECK ((sensitive_ciphertext IS NULL AND sensitive_nonce IS NULL
            AND sensitive_key_version IS NULL)
        OR (sensitive_ciphertext IS NOT NULL AND sensitive_nonce IS NOT NULL
            AND sensitive_key_version IS NOT NULL)),
    CHECK ((processing_state = 'running' AND claim_token IS NOT NULL AND lease_until IS NOT NULL)
        OR (processing_state <> 'running' AND claim_token IS NULL AND lease_until IS NULL)),
    PRIMARY KEY (processor_family, processor_event_id)
);

CREATE TABLE sb_processing_leases (
    processing_key TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('idle', 'running')),
    active_action_id UUID UNIQUE REFERENCES sb_processor_events(processing_action_id),
    claim_token UUID,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
      (status = 'running' AND active_action_id IS NOT NULL
       AND claim_token IS NOT NULL AND lease_until IS NOT NULL)
      OR
      (status = 'idle' AND active_action_id IS NULL
       AND claim_token IS NULL AND lease_until IS NULL)
    )
);

CREATE TABLE sb_provider_event_quarantine (
    processor_family TEXT NOT NULL,
    processor_event_id TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_version TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at <= created_at + INTERVAL '7 days'),
    PRIMARY KEY (processor_family, processor_event_id),
    FOREIGN KEY (processor_family, processor_event_id)
        REFERENCES sb_processor_events(processor_family, processor_event_id)
        ON DELETE CASCADE
);

CREATE TABLE sb_operator_audit (
    audit_id UUID PRIMARY KEY,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sb_scheduled_actions (
    action_id UUID PRIMARY KEY,
    action_key TEXT NOT NULL UNIQUE,
    subscription_ref TEXT NOT NULL REFERENCES sb_subscriptions(subscription_ref),
    action_type TEXT NOT NULL CHECK (action_type IN ('renew', 'expire')),
    target_at sb_utc_second NOT NULL,
    due_at sb_utc_second NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'uncertain', 'completed',
                          'canceled', 'manual_review')),
    claim_token UUID,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    last_error_class TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((status = 'running' AND claim_token IS NOT NULL AND lease_until IS NOT NULL)
        OR (status <> 'running' AND claim_token IS NULL AND lease_until IS NULL))
);
CREATE INDEX idx_sb_scheduled_actions_due
    ON sb_scheduled_actions(due_at)
    WHERE status = 'pending';
CREATE INDEX idx_sb_scheduled_actions_uncertain
    ON sb_scheduled_actions(due_at)
    WHERE status = 'uncertain';

CREATE TABLE sb_charge_attempts (
    attempt_id UUID PRIMARY KEY,
    action_id UUID NOT NULL REFERENCES sb_scheduled_actions(action_id),
    subscription_ref TEXT NOT NULL REFERENCES sb_subscriptions(subscription_ref),
    period_start sb_utc_second NOT NULL,
    period_end sb_utc_second NOT NULL,
    attempt_number INTEGER NOT NULL,
    provider_endpoint TEXT NOT NULL,
    provider_api_version TEXT NOT NULL,
    merchant_account TEXT NOT NULL,
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    currency TEXT NOT NULL,
    attempt_reference TEXT NOT NULL UNIQUE,
    shopper_reference TEXT NOT NULL,
    shopper_interaction TEXT NOT NULL CHECK (shopper_interaction = 'ContAuth'),
    recurring_processing_model TEXT NOT NULL
        CHECK (recurring_processing_model = 'Subscription'),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    request_ciphertext BYTEA NOT NULL,
    request_nonce BYTEA NOT NULL,
    request_key_version TEXT NOT NULL,
    processor_payment_id TEXT,
    status TEXT NOT NULL
        CHECK (status IN ('prepared', 'running', 'uncertain', 'authorized',
                          'refused', 'manual_review', 'canceled')),
    claim_token UUID,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    first_submitted_at sb_utc_second,
    resolution_deadline sb_utc_second,
    refusal_reason_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at sb_utc_second,
    CHECK (period_end > period_start),
    CHECK (resolution_deadline <= first_submitted_at + INTERVAL '6 days'),
    CHECK ((status IN ('prepared', 'canceled')
            AND first_submitted_at IS NULL AND resolution_deadline IS NULL)
        OR (status NOT IN ('prepared', 'canceled')
            AND first_submitted_at IS NOT NULL AND resolution_deadline IS NOT NULL)),
    CHECK ((status = 'running' AND claim_token IS NOT NULL AND lease_until IS NOT NULL)
        OR (status <> 'running' AND claim_token IS NULL AND lease_until IS NULL)),
    UNIQUE (subscription_ref, period_start, attempt_number)
);
CREATE UNIQUE INDEX idx_sb_charge_attempts_processor_payment
    ON sb_charge_attempts(processor_payment_id)
    WHERE processor_payment_id IS NOT NULL;
```

**No `username` column anywhere.**

Provider references are sensitive operational data. Stored-payment-method references must never exist in plaintext at rest or logs. Encrypt them and exact replay request bodies with authenticated envelope encryption using a dedicated data-encryption key or managed KMS, a unique nonce, authenticated context binding the record identity and purpose, and persisted key-version metadata. Encryption keys and plaintext are never stored in these tables. Bridge-generated processor shopper references may be stored for Adyen operation but must not appear in ordinary logs, metrics, HTTP errors, or consumer-facing output.

`request_fingerprint` is SHA-256 over the normative canonical plaintext request representation defined in section 11, computed before encryption. It must never be computed over randomized ciphertext or loosely ordered JSON. Run migrations through `bridge migrate`; production startup checks the schema version but does not silently migrate.

Every timestamp that enters the consumer protocol or an action key uses `sb_utc_second`. Normalize trusted provider observations and local clocks to whole seconds by truncating fractional seconds before comparison and storage, and serialize them as UTC RFC3339 with `Z`. Operational receipt, lease, and audit timestamps may retain PostgreSQL's finer precision.

Every operator abandonment, requeue, manual attempt resolution, charging-block change, or other exceptional state override inserts an append-only `sb_operator_audit` row in the same transaction. Audit targets use bridge event, attempt, checkout, action, or subscription IDs—not provider-native identifiers. Audit metadata is bounded and must not contain secrets, raw provider payloads, payment-method references, or decrypted requests.

---

## 9. Processor adapter interface

Each adapter implements (Go interface suggested):

```go
type ProcessorAdapter interface {
    Family() string
    CreateCheckout(ctx context.Context, request CheckoutRequest) (CheckoutResult, error)
    CreatePortalSession(ctx context.Context, processorCustomerID, returnURL string) (portalURL string, err error)
    ParseWebhook(ctx context.Context, headers http.Header, body []byte) ([]NormalizedEvent, error)
    GetSubscription(ctx context.Context, subscription ProcessorSubscription) (*SubscriptionState, error)
    CancelSubscription(ctx context.Context, subscription ProcessorSubscription, atPeriodEnd bool) error
    ChargeRenewal(ctx context.Context, request RenewalRequest) (RenewalResult, error)
    ResolveRenewalAttempt(ctx context.Context, attempt RenewalAttempt) (RenewalResolution, error)
}
```

`ChargeRenewal` and `ResolveRenewalAttempt` return `ErrProviderManaged` for Stripe. For Adyen, `ResolveRenewalAttempt` may only replay the stored exact request to the persisted endpoint and API version using the same idempotency key, or correlate an authenticated webhook by the stable attempt reference. It must not claim a provider lookup capability that has not been verified against a specific supported Adyen API. `CreatePortalSession` uses Stripe Billing Portal for Stripe and the bridge-hosted portal for Adyen. The subscription engine is the only component allowed to map `NormalizedEvent` into state changes and protocol callbacks.

### 9.1 Plan SKU config (`config/plans.yaml`)

```yaml
default_processor: stripe

plans:
  plan_500gb:
    processor: stripe
    currency: USD
    amount_minor: 500
    interval: month
    stripe:
      price_id: price_...
    adyen:
      merchant_account: ExampleMerchant
      country_code: CH
  plan_1tb:
    processor: adyen
    currency: EUR
    amount_minor: 900
    interval: month
    stripe:
      price_id: price_...
    adyen:
      merchant_account: ExampleMerchantEU
      country_code: DE
```

`plan_id` keys must match consumer catalog rows. Amount and currency are immutable for an existing plan ID; changing either requires a new plan ID. Checkout processor selection is deterministic: the plan's optional `processor`, otherwise `default_processor`. Both selected providers must have a complete configuration and adapter. Provider selection must not come from user-controlled query parameters.

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

Map Stripe `trialing` → `trialing`, `active` → `active`, `past_due`/`unpaid`/`paused` → `past_due`, and `canceled`/`incomplete_expired` → `expired`. `incomplete` is not consumer-visible and remains only a checkout until it becomes active/trialing or terminates. A scheduled cancellation maps to bridge `canceled` with access through `current_period_end`; immediate cancellation, deletion, or period completion maps to `expired`.

Verify with `STRIPE_WEBHOOK_SECRET`. Processing uses the following sequence:

1. Verify the signature and durably ingest the minimal event record in a short transaction; discard the raw body.
2. Claim the event and a durable processing lease in a short transaction. Its `processing_key` is the `subscription_ref` when known, otherwise the `checkout_id`; this serializes all observations that can affect the same local aggregate. Every claim or expired-lease reclaim increments the lease's monotonically increasing fencing token, sets a new random claim token, and copies that token and resulting fence into the event while setting it to `running`.
3. Retrieve authoritative Stripe subscription state outside any database transaction or row lock.
4. In another short transaction, lock the local aggregate and conditionally verify the processing action ID, event `running` state, claim token, fencing token, and unexpired ownership in both the event and processing-lease rows. Zero matching rows means the observation is discarded.
5. Reject an observation that would regress a terminal state, committed period boundary, or local `state_version`. `provider_occurred_at` is never used as an ordering authority. Apply only a real canonical change. In the same transaction, increment `state_version` exactly once, set `state_changed_at` to the transaction time, insert the exact-byte outbox event, and mark the provider event processed.

The processing lease prevents ordinary concurrent retrieval; the fencing token prevents a worker whose lease expired during retrieval from committing after a newer claimant. Tests must cover two workers retrieving different Stripe states and completing in reverse order. Price IDs not present in the configured reverse map transition the event to `quarantined` for operator action rather than changing consumer state.

Use Stripe API idempotency keys derived from `checkout_id` for Checkout Session creation and from `event_id` for operator-initiated mutations. Retry network errors, 409, and 429/5xx according to Stripe guidance; do not retry deterministic 4xx responses.

---

## 11. Adyen adapter (v1)

Adyen v1 is a complete bridge-scheduled subscription implementation. The initial payment uses Adyen Checkout Sessions/Drop-in and stores a reusable payment method. Renewals use Adyen's recurring `/payments` flow; Adyen does not own the schedule.

**Initial checkout**

- Generate a bridge-only `shopperReference` (`sbr_<random>`), never a username, email, or consumer identifier.
- Set `reference=checkout_id`, `storePaymentMethod=true`, `shopperInteraction=Ecommerce`, and `recurringProcessingModel=Subscription`.
- Set amount/currency and `merchantAccount` only from the immutable plan configuration.
- Create the Adyen session with the checkout row's stable provider idempotency key. Exact `/v1/start` retries resume that operation; ambiguous transport results never allocate another key.
- Permit only HTTPS return URLs previously signed in the consumer token.
- Persist the resulting `storedPaymentMethodId`/recurring detail reference encrypted.
- Activate only after an authenticated `AUTHORISATION` success for the initial attempt and durable association with the checkout.

**Scheduled renewal**

For each due renewal action, first create its committed `prepared` `sb_charge_attempts` row, then claim the action and attempt with the scheduled-action fencing protocol before calling Adyen. The attempt persists the provider endpoint and API version, merchant account, amount minor units and currency, stable attempt reference, bridge-generated shopper reference, interaction and recurring-processing models, idempotency key, request fingerprint, and the encrypted exact request body. The first claim records `first_submitted_at` and the bounded resolution deadline.

The canonical plaintext request representation is UTF-8 JSON with exactly the following keys in this order, no insignificant whitespace, decimal `amount.value`, uppercase ISO currency, and JSON escaping as defined by RFC 8259:

```json
{"merchantAccount":"ExampleMerchant","amount":{"value":500,"currency":"USD"},"reference":"sba_550e8400-e29b-41d4-a716-446655440000","shopperReference":"sbr_7f3a9c2e","shopperInteraction":"ContAuth","recurringProcessingModel":"Subscription","storedPaymentMethodId":"<provider token>"}
```

No optional or provider-default field may be added during replay. Compute SHA-256 over these exact plaintext bytes before encryption. Encrypt those exact bytes using authenticated envelope encryption and store ciphertext, nonce, key version, and authenticated context binding `attempt_id`, provider family, endpoint, and API version. The stored-payment-method reference appears only inside this in-memory plaintext and encrypted body; it is never persisted separately in plaintext.

After committing the attempt and claim, call Adyen outside the transaction with:

```text
shopperInteraction=ContAuth
recurringProcessingModel=Subscription
shopperReference=<bridge-generated value>
storedPaymentMethodId=<encrypted token after decryption>
reference=<stable attempt reference>
Idempotency-Key=<sb_charge_attempts.idempotency_key>
```

The period calendar is computed in UTC from the original activation day. Monthly anniversaries clamp to the last day of shorter months. The next period is not committed until authorization succeeds. A worker may apply a result only when the attempt and scheduled action are both `running` and both action ID, claim token, and fencing token still match. Claims are committed before network I/O; no transaction or row lock remains open during the call.

**Recovery algorithm**

1. A definitive synchronous authorization or authenticated matching webhook stores the provider payment ID, transitions the attempt to `authorized`, sets whole-second `completed_at`, advances the period, completes the action, creates the next stable renewal action, and emits `subscription.renewed` in one transaction.
2. A definitive refusal transitions the attempt to `refused`, stores the provider payment ID when supplied, and sets `completed_at` to the whole-second local commit timestamp. It enters `past_due` once if necessary and either reschedules the same renewal action for its next configured dunning time or, after the final allowed refusal, completes it and creates one expiry action with `target_at=due_at=completed_at + BRIDGE_DUNNING_TERMINATION_DELAY`. This final attempt's `completed_at` is the normative `final_refusal_at` anchor.
3. A timeout, connection loss after transmission, malformed success response, other ambiguous transport result, or expired running lease without durable proof that no request was sent transitions the same attempt and action to `uncertain` and clears their ownership fields. It creates no new charge attempt, action, reference, or idempotency key.
4. Adyen documents idempotency keys as valid for a minimum of 7 days after first submission. A resolution worker claims the uncertain action and attempt together, increments the action fence, and may replay only the decrypted exact stored request to the same persisted regional endpoint/API version using the same key, or correlate an authenticated webhook using the stable attempt reference. The first claim, committed immediately before the intended first network submission, sets `first_submitted_at` and `resolution_deadline` no later than 6 days afterward. This conservatively starts the window even if the worker crashes before sending. A release must re-verify the provider guarantee and same-region requirement.
5. If no definitive result is established by the resolution deadline, atomically transition the attempt and action to `manual_review`, set the subscription's automatic-charging block, and stop all automatic charging. The visible state remains `past_due`.
6. An audited operator command may record external evidence and resolve the existing attempt. It must never silently allocate a new payment key. Clearing the charging block or causing `renewed`/`expired` requires an explicit durable resolution and real state transition.

This algorithm, stable identities, exact replay bytes, and fencing—not a claim of provider lookup by idempotency key or merchant reference—provide crash safety.

**Adyen event mapping**

| Adyen notification/result | Bridge action |
|---|---|
| Initial `AUTHORISATION`, success | Persist encrypted token/linkage and `processor_initial_payment_id`, copy the checkout shopper reference into the new subscription, allocate `subscription_ref`, emit `subscription.activated` |
| Renewal `AUTHORISATION`, success | Persist `processor_payment_id`, mark attempt authorized, advance period, emit `subscription.renewed` |
| Renewal `AUTHORISATION`, refused | Persist `processor_payment_id` when supplied, mark attempt refused, set first `past_due_since`, emit `subscription.past_due` |
| `CANCELLATION`/`CANCEL_OR_REFUND` for the active recurring payment contract | Reconcile; emit `subscription.canceled` or `subscription.expired` only when the bridge state actually changes |
| Chargeback/refund notifications | Record for operations; do not silently invent a protocol state transition in v1 |

Verify every Standard webhook notification item using Adyen HMAC before acknowledging it. Respond with the exact Adyen acceptance response only after committing the processor event. Derive a stable processor event ID from Adyen's `pspReference`, `eventCode`, `success`, and `originalReference` where no single event ID is supplied.

Resolve `adyen.contract_changed` only by a unique match of its `processor_payment_id`/original reference to `sb_subscriptions.processor_initial_payment_id` or `sb_charge_attempts.processor_payment_id`. If neither or more than one row matches, transition the processor event to `manual_review` without changing consumer-visible state. Never guess from customer data, shopper identity, amount, or timing.

**Retries and dunning**

- Attempt 1 is created when the target-period renewal action becomes due; after a definitive retryable refusal, reschedule that same action after 1 day, 3 days, and 5 days (configurable), creating a new sequential attempt only when it is claimed again.
- A transport timeout becomes `uncertain`; replay the exact request with the same idempotency key within the verified retention window or await a correlated authenticated webhook.
- Emit `subscription.past_due` once when entering that state. Successful recovery emits `subscription.renewed` and clears `past_due_since`.
- After the final definitive refusal, remain `past_due` until the bridge's configured billing-termination deadline, then execute the unique expiry action, set `expired`, increment `state_version`, and emit `subscription.expired`. This bridge dunning/termination delay is independent of any consumer-local access grace applied while status is `past_due`.
- Never retry refusal codes classified as stolen, invalid, closed, or revoked payment method until the customer replaces the method.

**Bridge-hosted portal**

The signed `/v1/portal` route renders a bridge page that supports cancel-at-period-end, immediate cancel (operator-policy controlled), and payment-method replacement through Adyen Drop-in. CSRF protection and the short-lived portal token are mandatory. No processor identifier is exposed in HTML or URLs. Cancel-at-period-end locks the subscription row, sets `canceled`, creates the unique expiry action, increments `state_version`, and emits `subscription.canceled` atomically. The expiry action emits `subscription.expired` at period end. Immediate cancellation transitions directly to `expired`.

---

## 12. Configuration

```bash
# Public
BRIDGE_PUBLIC_URL=https://billing.example.com
CONSUMER_WEBHOOK_URL=https://app.example.com/api/webhooks/subscription-bridge

# Exactly 64 lowercase hex characters; hex-decode before HKDF
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
BRIDGE_DUNNING_TERMINATION_DELAY=0s
BRIDGE_ADYEN_RESOLUTION_DEADLINE=144h
BRIDGE_PROVIDER_PAYLOAD_QUARANTINE_ENABLED=false
BRIDGE_PROVIDER_PAYLOAD_QUARANTINE_MAX_RETENTION=168h
```

**Consumer mirror (example Arkfile):**

```bash
ARKFILE_SUBSCRIPTIONS_ENABLED=true
ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED=true
ARKFILE_SUBSCRIPTION_BRIDGE_URL=https://billing.example.com
ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT=<same as BRIDGE_CONSUMER_PAIRING_ROOT>
```

Startup must fail fast if the pairing root is not exactly 64 lowercase hexadecimal characters or if the consumer URL, database, plan mappings, or credentials and encryption keys for every provider selected by the configured plans are missing. It must also reject HTTP public/consumer URLs except explicit loopback development URLs. A complete v1 build and release contains both adapters and passes both conformance suites; a deployment does not need credentials for a provider that no configured plan can select.

`BRIDGE_DUNNING_TERMINATION_DELAY` is the bridge's delay between the final definitive refusal and its canonical `expired` transition. It defaults to `0s`, may be configured from `0s` through `168h`, and is not consumer access grace. The Adyen resolution deadline defaults to and may not exceed 144 hours from the conservative first-claim timestamp, based on Adyen's documented minimum 7-day idempotency-key validity and a 24-hour safety margin. Startup rejects values outside these bounds. Diagnostic payload quarantine is off by default and its configured retention may not exceed 168 hours.

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
| `bridge reconcile` | Poll active subscriptions against processor |
| `bridge list-events [--state pending\|delivered\|dead_lettered\|abandoned]` | Status-aware callback delivery listing |
| `bridge requeue-event <event_id> --reason ...` | Audited requeue preserving the immutable event identity and body |
| `bridge abandon-event <event_id> --reason ...` | Audited terminal abandonment |
| `bridge scheduler-status` | Due/leased renewal and expiry actions plus uncertain/manual-review attempts |
| `bridge resolve-attempt <attempt_id> ...` | Audited resolution of an existing uncertain/manual-review attempt; never creates a new payment key |

Paid subscription cancel: processor dashboard or portal — not consumer admin CLI.

---

## 15. Testing requirements

**Unit tests**

- HKDF golden vectors above; start/portal token, callback, and reconcile signatures must interoperate with the consumer `subbridge` package.
- Replay-window boundaries, malformed headers, invalid identifiers, unknown JSON fields, body limits, and URL validation.
- Pairing-root acceptance for exactly 64 lowercase hex characters and rejection of wrong lengths, uppercase, whitespace, prefixes, and non-hex input.
- Start and portal token `iat`/`exp` boundaries, bounded future issue time, excessive lifetime, exact replay, checkout-property conflicts, and provider timeouts before and after request acceptance.
- State transition matrix for every event/status pair and monotonic `state_version`.
- Stripe and Adyen fixtures for every mapping in sections 10–11, including duplicate and out-of-order provider events.
- Calendar-period tests for month ends and leap years.
- Scheduler crash tests before request, after request/before response, and after authorization/before commit.
- Idempotency on event ID, provider event identity, checkout ID, state version, and Adyen charge-attempt key.
- Byte-identical callback retries after notifier restart; terminal delivery states and audited requeue/abandonment.
- Scheduled cancellation remains effective before period end, executes exactly one fenced expiry action, and then becomes ineffective.
- Fencing tests where an expired Stripe or scheduled-action worker completes after a newer claimant and is unable to commit.
- Adyen uncertain-attempt tests proving exact encrypted request replay with the original idempotency key, webhook correlation, resolution deadline, and automatic charging block.

**Integration tests**

- Stripe test mode: checkout → webhook → mock consumer HTTP server captures POST.
- Adyen test platform: initial checkout/tokenization → scheduled renewal → refusal → recovery → cancellation.
- Real PostgreSQL in CI (not SQLite), with at least two scheduler workers proving `SKIP LOCKED` leasing and one-charge behavior.
- Consumer endpoint returns 500 twice then 200: notifier delivers the identical event ID/body and stops after success.
- A rolled-back provider webhook transaction leaves no state version or outbound event.
- Reconcile returns exactly the latest committed state and version.
- Two Stripe workers retrieve different authoritative states and complete in reverse order; only the current fenced, non-regressing observation can commit.

**Common adapter conformance suite**

Run the same black-box suite against Stripe and Adyen. Each adapter must create a checkout without consumer identity, activate once, renew once, enter and recover from past due, cancel, expire, reconcile, reject bad signatures, and remain idempotent under duplicate delivery. Provider-specific fakes may control time and results, but cannot bypass the production engine or store.

**Release acceptance**

- `go test ./...`, race-enabled unit tests, migrations on supported PostgreSQL versions, static analysis, and dependency vulnerability scans are green.
- No callback is sent before its database transaction commits.
- Killing either notifier or Adyen scheduler at every injected failure point produces no duplicate callback and no duplicate charge.
- Logs and HTTP responses contain no pairing root, derived key, payment-method reference, provider customer ID, or raw provider payload.
- Both provider conformance suites pass from a clean database.
- `fixtures/protocol-v1.json` passes in this repository and its byte-identical mirrored copy passes in the consumer repository.

**Cross-repo e2e**

Consumer app runs shell tests against `subscription-bridge-mock.go` (no live Stripe required). Mock implements `/v1/start`, authenticated `/v1/subscriptions/{ref}`, `/v1/mock/activate`, `/v1/mock/expire`, and `/v1/mock/replay`.

---

## 16. Recommended repository layout

```
subscription-bridge/
├── SPEC.md                    # copy of this document
├── fixtures/
│   └── protocol-v1.json       # canonical cross-repository protocol fixture
├── cmd/
│   ├── bridge/                # HTTP server main
│   └── bridge-cli/            # operator CLI
├── internal/
│   ├── protocol/              # types + validation
│   ├── hmac/                  # tokens + webhook + GET auth
│   ├── store/                 # postgres repositories
│   ├── engine/                # state machine + notifier
│   ├── notify/                # consumer webhook client + retry
│   ├── scheduler/             # fenced renewal, expiry, dunning, and recovery actions
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
2. **Postgres migrations + idempotent `/v1/start` workflow** — exercise through a fake adapter, without a protocol stub.
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
- Multiple consumer applications or protocol namespaces in one bridge deployment

---

## 20. Status

**Greenfield — specification repository created; provider implementation has not begun.** Arkfile's consumer currently implements the earlier protocol draft and requires the atomic compatibility update described by the canonical fixture and this specification. Finalize and test the protocol, migrations, schemas, interfaces, state machines, and crash-recovery behavior before implementing either provider. Stripe and Adyen are both required v1 adapters and must pass the common conformance suite before release.

---

## 21. References

- Arkfile consumer contract: `docs/wip/prod-prep/05-subscriptions.md`
- Shared HMAC implementation: `subbridge/hmac.go`, `subbridge/hmac_test.go`
- Mock bridge for CI: `scripts/testing/subscription-bridge-mock.go`
- Canonical bridge fixture: `fixtures/protocol-v1.json`; Arkfile mirror: `subbridge/testdata/protocol-v1.json`
- [Stripe Checkout subscriptions](https://docs.stripe.com/payments/checkout/subscriptions)
- [Stripe Billing webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)
- [Adyen tokenization](https://docs.adyen.com/online-payments/tokenization/)
- [Adyen recurring payments](https://docs.adyen.com/online-payments/tokenization/make-recurring-payments/)
- [Adyen API idempotency](https://docs.adyen.com/development-resources/api-idempotency)
- [Adyen webhook HMAC verification](https://docs.adyen.com/development-resources/webhooks/verify-hmac-signatures/)

---

# protocol-v1.json

```
{
  "fixture": "subscription-bridge/protocol-v1",
  "fixture_version": 1,
  "pairing_root": {
    "configured_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "decoded_bytes_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "salt_ascii": "subscription-bridge/v1",
    "keys": {
      "token": {
        "info_ascii": "consumer-to-bridge/token",
        "derived_key_hex": "1c3ffa613421f6a4958704b3090e9b970af7dd9107ce328cc9c5d33546701fa2"
      },
      "callback": {
        "info_ascii": "bridge-to-consumer/callback",
        "derived_key_hex": "069dddf506c40199b88267dbc754808242339730f5cb042f3d72e4e19dbe946d"
      },
      "reconcile": {
        "info_ascii": "consumer-to-bridge/reconcile",
        "derived_key_hex": "c090ac1d8b5c248d45c8ce7ca9f9b463b1f6ad4a2086061d53111214e24a433c"
      }
    }
  },
  "start_token": {
    "payload_json_utf8": "{\"checkout_id\":\"subchk_7f3a9c2e\",\"plan_id\":\"plan_500gb\",\"return_url\":\"https://app.example.com/billing/return\",\"iat\":1767225600,\"exp\":1767226500}",
    "payload_base64url": "eyJjaGVja291dF9pZCI6InN1YmNoa183ZjNhOWMyZSIsInBsYW5faWQiOiJwbGFuXzUwMGdiIiwicmV0dXJuX3VybCI6Imh0dHBzOi8vYXBwLmV4YW1wbGUuY29tL2JpbGxpbmcvcmV0dXJuIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjE3NjcyMjY1MDB9",
    "signature_hex": "027b8e022a531a1fb51da0c21cb4c2495f3f1b616707b058e33e0fda48ef21e5",
    "token": "eyJjaGVja291dF9pZCI6InN1YmNoa183ZjNhOWMyZSIsInBsYW5faWQiOiJwbGFuXzUwMGdiIiwicmV0dXJuX3VybCI6Imh0dHBzOi8vYXBwLmV4YW1wbGUuY29tL2JpbGxpbmcvcmV0dXJuIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjE3NjcyMjY1MDB9.027b8e022a531a1fb51da0c21cb4c2495f3f1b616707b058e33e0fda48ef21e5"
  },
  "portal_token": {
    "payload_json_utf8": "{\"subscription_ref\":\"sub_a8f3c1d2\",\"return_url\":\"https://app.example.com/billing\",\"iat\":1767225600,\"exp\":1767226500}",
    "payload_base64url": "eyJzdWJzY3JpcHRpb25fcmVmIjoic3ViX2E4ZjNjMWQyIiwicmV0dXJuX3VybCI6Imh0dHBzOi8vYXBwLmV4YW1wbGUuY29tL2JpbGxpbmciLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6MTc2NzIyNjUwMH0",
    "signature_hex": "8a28b6bdd3fb8f5d9172e2d82e3d9971cbdef79611c9c6cdfddbf324f65e700b",
    "token": "eyJzdWJzY3JpcHRpb25fcmVmIjoic3ViX2E4ZjNjMWQyIiwicmV0dXJuX3VybCI6Imh0dHBzOi8vYXBwLmV4YW1wbGUuY29tL2JpbGxpbmciLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6MTc2NzIyNjUwMH0.8a28b6bdd3fb8f5d9172e2d82e3d9971cbdef79611c9c6cdfddbf324f65e700b"
  },
  "callback": {
    "body_json_utf8": "{\"protocol\":\"subscription-bridge\",\"version\":1,\"event_id\":\"evt_550e8400-e29b-41d4-a716-446655440000\",\"event_type\":\"subscription.activated\",\"checkout_id\":\"subchk_7f3a9c2e\",\"subscription_ref\":\"sub_a8f3c1d2\",\"plan_id\":\"plan_500gb\",\"state_version\":1,\"status\":\"active\",\"current_period_start\":\"2026-01-01T00:00:00Z\",\"current_period_end\":\"2026-02-01T00:00:00Z\",\"cancel_at_period_end\":false,\"state_changed_at\":\"2026-01-01T00:00:00Z\"}",
    "signature_timestamp": 1767225605,
    "signature_base_utf8": "1767225605.{\"protocol\":\"subscription-bridge\",\"version\":1,\"event_id\":\"evt_550e8400-e29b-41d4-a716-446655440000\",\"event_type\":\"subscription.activated\",\"checkout_id\":\"subchk_7f3a9c2e\",\"subscription_ref\":\"sub_a8f3c1d2\",\"plan_id\":\"plan_500gb\",\"state_version\":1,\"status\":\"active\",\"current_period_start\":\"2026-01-01T00:00:00Z\",\"current_period_end\":\"2026-02-01T00:00:00Z\",\"cancel_at_period_end\":false,\"state_changed_at\":\"2026-01-01T00:00:00Z\"}",
    "signature_hex": "9d6700ac9f9f8926d13b1cd5de608a1d2806bf987defe28d1667bfd88725be31",
    "signature_header": "t=1767225605,v1=9d6700ac9f9f8926d13b1cd5de608a1d2806bf987defe28d1667bfd88725be31"
  },
  "reconciliation_request": {
    "method": "GET",
    "path": "/v1/subscriptions/sub_a8f3c1d2",
    "signature_timestamp": 1767225605,
    "signature_base_utf8": "GET\n/v1/subscriptions/sub_a8f3c1d2\n1767225605",
    "signature_hex": "2432943b8b6253160b5676091c56a14a0ea7b2d178289a76d1598360bfb58475",
    "authorization_header": "Subscription-Bridge-HMAC t=1767225605,v1=2432943b8b6253160b5676091c56a14a0ea7b2d178289a76d1598360bfb58475"
  },
  "snapshot": {
    "response_status": 200,
    "content_type": "application/json",
    "response_is_independently_signed": false,
    "body_json_utf8": "{\"protocol\":\"subscription-bridge\",\"version\":1,\"checkout_id\":\"subchk_7f3a9c2e\",\"subscription_ref\":\"sub_a8f3c1d2\",\"plan_id\":\"plan_500gb\",\"state_version\":1,\"status\":\"active\",\"current_period_start\":\"2026-01-01T00:00:00Z\",\"current_period_end\":\"2026-02-01T00:00:00Z\",\"cancel_at_period_end\":false,\"state_changed_at\":\"2026-01-01T00:00:00Z\"}"
  }
}
```
