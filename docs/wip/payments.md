# Payments Integration (BTCPay Server)

This document describes how Arkfile adds self-service balance top-ups on top of the integer microcent-denominated storage-credits and usage-metering foundation. One USD is always 100,000,000 microcents. Payment processing is delegated to a self-hosted BTCPay Server instance, which handles the payment methods enabled by its operator. Arkfile never loads Stripe scripts in the browser and never parses Stripe webhooks directly; every paid top-up is represented locally as a BTCPay invoice and a corresponding ledger credit. Arkfile sends BTCPay only the USD amount and an opaque local invoice ID. It must never send usernames, email addresses, filenames, storage information, balances, wallet information, or other user PII.

The integration is implemented end-to-end with Go unit tests, shell-based e2e tests (`run_billing` and `run_payments` in `scripts/testing/e2e-test.sh`), and Playwright billing-panel tests including the top-up modal.

## Status

Settlement credits the user and marks the invoice `paid` atomically via `billing.SettlePaymentInvoice`. Ledger rows use `transaction_type = 'payment'`. CSP allows only the configured BTCPay origin in `frame-src` for embedded checkout. Admin `payments reconcile` discovers remotely settled pending invoices in bounded batches and also repairs paid invoices that lack matching ledger credits. Startup validation rejects unsafe payment origins and invalid amounts. External-tab checkout return is handled in the SPA through `resumePendingBillingCheckout` in `billing.ts`.

## Purpose and Architectural Alignment

The payments layer exists to let users top up their microcent balance without operator intervention. Rather than wiring multiple payment gateways into Arkfile, all provider complexity lives in BTCPay Server: address derivation, exchange rates, payment method selection, and settlement tracking. Arkfile's backend creates USD-denominated invoices through BTCPay's Greenfield API, records a local `payment_invoices` row, and credits the user's balance when BTCPay confirms settlement via a signed webhook.

This design builds on the storage-credits ledger and hourly billing meter described in the storage-credits design documents. Credit balance and hard storage caps remain decoupled: paying does not automatically raise a user's storage limit unless an operator configures that separately. The `payment_invoices` table provides an auditable record of initiated and completed top-ups distinct from the `credit_transactions` usage and gift rows written by the billing meter and admin tools.

## Core Assumptions and Decisions

The operator deploys and maintains a BTCPay Server instance. Arkfile communicates with it using the Greenfield API (`payments/btcpay.go`), creating invoices in USD that settle in whatever payment methods the store supports. Credit card payments, when offered, are rendered entirely on BTCPay's invoice page via the Stripe Payments plugin, which preserves Arkfile's Content Security Policy and avoids third-party payment scripts in our frontend. The CSP includes a `frame-src` directive for the configured BTCPay Server origin when payments are enabled.

Settlement is webhook-driven. BTCPay signs payloads with SHA256 HMAC using a shared secret; Arkfile verifies the exact raw body bytes with constant-time comparison, matches the event to a local invoice, and settles through `billing.SettlePaymentInvoice`, which credits the user and marks the invoice `paid` in one transaction. The provider invoice ID is stored as the `credit_transactions.transaction_id`, giving idempotent protection against duplicate credits on replay. `InvoiceSettled` is the only authoritative Greenfield settlement event. Other events, including `InvoiceCompleted`, are ignored.

Arkfile requests `LowMediumSpeed` for BTCPay invoice creation. This is the reference two-confirmation policy for on-chain settlement and Arkfile never requests `HighSpeed`. Lightning keeps its normal immediate finality; the on-chain speed policy does not add a confirmation delay to a completed Lightning payment.

For CLI users, the server returns a checkout URL when an invoice is created; the user completes payment in a browser. No client-side polling is required because the webhook applies the credit server-side once settlement is confirmed. Users who open checkout in an external tab are redirected back to `/?success=true&invoice=...`; the SPA opens the billing panel, polls invoice status, and strips the query string. Invoice creation also extends the browser session (refresh-token rotation) so checkout starts with a fresh JWT window.

## Quota Gating and Overdrawn Policy

When billing and PAYG are enabled, upload handlers soft-block users whose signed balance reaches the configured negative-balance magnitude by returning HTTP 402 Payment Required. Downloads and other read operations are unaffected; the account is not suspended. `ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD=10.00` means a positive configured magnitude of $10.00 and is stored as 1,000,000,000 microcents; negative configuration values, malformed decimals, excess precision, and overflow are rejected.

Hard storage limits remain independent of credit balance. The billing meter may allow negative balances during beta operation; production deployments with payments enabled are expected to enforce the upload soft-block so users cannot accumulate further storage charges without topping up.

A configurable grace period after which an operator may flag an overdrawn account for storage purge is described here as policy only. Automated deletion is not implemented; any purge must be an explicit administrative action logged in the admin audit trail.

## What Is Implemented

The `payment_invoices` table is defined in `database/unified_schema.sql` and managed through `models/payments.go`. The `payments` package defines a `PaymentProvider` interface (`CreateInvoice`, `GetInvoiceStatus`) in `payments/types.go`, implements it with `BTCPayClient` in `payments/btcpay.go`, verifies webhook signatures in `payments/webhooks.go`, and exposes `NewProvider(cfg)` in `payments/provider.go`. Handlers use the factory rather than constructing `BTCPayClient` directly.

HTTP handlers in `handlers/payments.go` expose user-facing invoice creation and status, the public BTCPay webhook receiver, and admin invoice inspection, sync, and reconcile. Routes are registered in `handlers/route_config.go`: `POST /api/billing/invoice` and `GET /api/billing/invoice/:invoice_id` (authenticated, TOTP-protected), `POST /api/webhooks/btcpay` (public, signature-verified), and admin routes `GET /api/admin/payments/invoice/:invoice_id`, `GET /api/admin/payments/invoices`, `POST /api/admin/payments/invoice/:invoice_id/sync`, and `POST /api/admin/payments/reconcile`. Settlement is wired through `SettlePaymentInvoiceFunc` in `handlers/billing_projection.go`, connected to `billing.SettlePaymentInvoice` at startup in `main.go`.

The billing panel in `client/static/js/src/ui/billing.ts` renders balance, usage projection, and transaction history from `GET /api/credits`. When payments are enabled, a "Top Up Balance" button opens a modal that posts to `/api/billing/invoice` and embeds the returned BTCPay checkout URL in an iframe. Payment rows display as type "Top-up" (`transaction_type = 'payment'`). No Stripe or other third-party payment scripts are loaded in the Arkfile frontend.

Administration is available through `arkfile-admin payments show`, `payments list`, `payments sync-invoice`, and `payments reconcile` (`cmd/arkfile-admin/payments_commands.go`). The sync command polls BTCPay for an invoice's remote state and settles locally only when BTCPay reports `Settled`, or repairs paid invoices missing ledger credits. Reconcile checks an oldest-first batch of at most 50 associated pending BTCPay invoices with a ten-second timeout per provider request, settles only `Settled` responses, continues past transient provider errors, and then repairs paid invoices without ledger credits. Re-running reconciliation or replaying a webhook cannot insert a second provider transaction.

Configuration is driven by environment variables in `config/config.go`. Payments default to disabled; when enabled, startup validates that BTCPay URL, store ID, API key, webhook secret, and `BASE_URL` are present and that min/max top-up amounts are positive with min less than max. Production BTCPay and Arkfile origins must be normalized public HTTPS origins without credentials, query, fragment, or path. HTTP is accepted only for loopback origins in explicitly identified development or test environments.

## Database Schema

Local payment state lives in `payment_invoices`:

```sql
CREATE TABLE IF NOT EXISTS payment_invoices (
    invoice_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    amount_usd_microcents BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'creating',
    provider TEXT NOT NULL,
    provider_invoice_id TEXT UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES users(username) ON DELETE RESTRICT,
    CHECK(status IN ('creating', 'pending', 'paid', 'expired', 'failed')),
    CHECK(provider IN ('btcpay'))
);
```

The RESTRICT foreign key ensures invoice records survive user soft-deletion for financial audit purposes. Indexes on `username` and `provider_invoice_id` support user lookups and webhook matching.

Paid top-ups write `credit_transactions` rows with `transaction_type = 'payment'`. Existing databases are migrated via `migrateCreditTransactionsPaymentType()` in `main.go`, which rebuilds `credit_transactions` when the CHECK constraint does not yet include `payment`.

## Backend Settlement Flow

The settlement sequence is: limit the body to 64 KiB, verify the webhook signature over the exact bytes, reject a present non-matching `storeId`, accept only `InvoiceSettled`, bind identifiers, and call `billing.SettlePaymentInvoice` to credit the user and mark the invoice `paid` atomically. Metadata lookup uses the opaque local `metadata.invoice_id`; provider-ID lookup is allowed when metadata is absent. When both identifiers are present they must identify the same row and stored provider invoice ID. During the `creating` transition, a valid signed webhook may attach the first provider ID to the matching local invoice. Conflicts are rejected without changing billing state. Unknown but valid invoices receive a retry-friendly non-success response because the local association may still be completing.

If an invoice is already `paid` but lacks a matching credit row (recovery path for historical bad state), `SettlePaymentInvoice` and `AdminSyncInvoiceHandler` apply only the ledger credit. `billing.ReconcilePaidInvoices` scans for all such orphans.

## HTTP API

`POST /api/billing/invoice` accepts `{"amount_usd": "20.00", "request_id": "<UUID>"}`. The frontend generates one opaque request UUID per opened top-up form and reuses it for retries; the server derives the local invoice ID from it, so a repeated request cannot create a second remote invoice. Top-ups must have at most two decimal places and remain within `ARKFILE_MIN_TOP_UP_USD` and `ARKFILE_MAX_TOP_UP_USD`; no floating-point value is used to parse, store, or format the amount. The handler durably inserts a `creating` row before contacting BTCPay and sends a Greenfield request containing currency `USD`, an exact two-decimal amount, metadata containing only `invoice_id`, `LowMediumSpeed`, a 60-minute expiration, and an Arkfile public-origin redirect. It then makes bounded attempts to attach the returned provider ID and transition to `pending`. Provider creation failure marks the local row failed. A signed webhook arriving during creation can complete the provider association after a database association failure; the opaque metadata also gives an operator a recovery key in BTCPay. The returned `checkoutLink` is rejected unless its origin exactly matches the configured BTCPay origin.

`GET /api/billing/invoice/:invoice_id` returns the local invoice record for the authenticated owner. `POST /api/webhooks/btcpay` is unauthenticated; it requires a valid `BTCPay-Sig` header and processes settlement events as described above.

Admin endpoints support invoice inspection, filtered listing (`?user=`, `?status=`), manual sync against BTCPay, pending-invoice discovery, and repair of paid invoices missing ledger credits. Checkout redirects and client claims are never settlement evidence.

## Frontend Integration

The billing panel follows the same inline-panel pattern as security settings and contact info. When payments are enabled, the top-up modal collects a USD amount, creates an invoice via the API, and replaces the form with a full-width iframe pointing at BTCPay's checkout page. BTCPay's invoice UI supports iframe embedding when the operator's BTCPay origin is allowed in CSP `frame-src`.

External-tab checkout returns to `/?success=true&invoice=...`. On load, `resumePendingBillingCheckout()` in `billing.ts` captures the invoice id (also stored in `sessionStorage` when the top-up modal creates an invoice), attempts a session refresh if needed, opens the billing panel, polls `GET /api/billing/invoice/:invoice_id` for up to about three minutes, and shows a message matched to the outcome (`paid`, still pending, or expired/failed). Tab visibility changes trigger a session refresh while the Arkfile tab is open.

## Administration

`arkfile-admin payments show <invoice_id>` displays a single invoice. `payments list [--user NAME] [--status STATUS]` lists invoices with optional filters. `payments sync-invoice <invoice_id>` queries BTCPay and reconciles local state, settling when the remote invoice is `Settled`, updating to `expired` or `failed` as appropriate, or repairing paid invoices missing credits. `payments reconcile` queries the bounded pending batch and then repairs paid invoices without matching ledger rows.

Manual refunds are deliberately not automated. Operators process refunds using `arkfile-admin billing gift` with a negative amount, keeping the financial API surface minimal.

## Configuration

Payments are controlled by these environment variables (also documented in `.env.example`):

```
ARKFILE_PAYMENTS_ENABLED=true
ARKFILE_BTCPAY_SERVER_URL=https://btcpay.example.com
ARKFILE_BTCPAY_STORE_ID=YourStoreIDHere
ARKFILE_BTCPAY_API_KEY=YourGreenfieldAPIKeyHere
ARKFILE_BTCPAY_WEBHOOK_SECRET=YourBTCPayWebhookSecretHere
ARKFILE_MIN_TOP_UP_USD=0.50
ARKFILE_MAX_TOP_UP_USD=1000.00
```

Defaults are `0.50` minimum and `1000.00` maximum top-up. When `ARKFILE_PAYMENTS_ENABLED=true`, startup rejects missing BTCPay credentials, a missing or unsafe `BASE_URL`, an unsafe BTCPay origin, excess amount precision, overflow, or invalid min/max configuration. The local mock uses an explicit loopback HTTP origin only in development and tests.

## Test Coverage

Go unit tests cover the BTCPay client (`payments/btcpay_test.go`), webhook signature verification (`payments/webhooks_test.go`), payment invoice model CRUD (`models/payments_test.go`), `billing.ProcessPayment` and `billing.SettlePaymentInvoice` ledger behavior (`billing/payments_test.go`, `billing/settle_test.go`, `billing/reconcile_test.go`), and handler-level flows including invoice creation, webhook settlement, signature rejection, idempotency, settlement failure leaving invoice pending, recovery of paid-without-credit invoices, invoice status ownership, admin sync, reconcile, payments config in `/api/credits`, and upload soft-blocking on negative balance (`handlers/payments_test.go`). Payments config loading and validation are tested in `config/config_test.go`.

Shell e2e tests run as `run_payments` in `scripts/testing/e2e-test.sh`, after `run_billing`. The payments phase starts a mock BTCPay server (`scripts/testing/btcpay-mock.go`), logs in the test user and confirms `GET /api/credits` exposes payments config, creates an invoice via `POST /api/billing/invoice` and verifies it appears in `arkfile-admin payments list`, sends a signed webhook to settle the invoice, confirms the invoice transitions to `paid` and the user ledger contains a "Payment top-up via btcpay" row with `transaction_type = 'payment'` (asserted with `jq` against `arkfile-admin billing show --user`, since admin CLI `--json` pretty-prints), and replays the webhook to confirm the response is idempotent and the balance is unchanged.

Playwright (`scripts/testing/e2e-playwright.ts`) runs after the shell e2e suite. One test opens the billing panel and verifies balance, usage grid, and transaction history (including gift and usage rows written by `run_billing`). A second test opens the top-up modal, mocks `POST /api/billing/invoice`, and confirms the checkout iframe embeds the returned URL. A third test navigates to `/?success=true&invoice=...` with a mocked paid invoice status and verifies the billing panel opens.

## Honest Trade-offs

Refunds are manual by design. An automated refund or chargeback API would expand the attack surface on a privacy-focused file vault; operators handle exceptions through existing admin billing tools.

Payment operational logs contain opaque local invoice IDs and sanitized failure categories only. They must not contain usernames, email addresses, API keys, webhook secrets, signed URLs, checkout URLs, provider credentials, raw webhook payloads, balances, amounts, transaction IDs, wallet information, filenames, or storage information. The authoritative username-to-invoice relationship remains only in the protected application database.

Webhook delivery is the primary settlement path. If a webhook is missed, an operator runs `payments sync-invoice` or bounded `payments reconcile`; both query BTCPay and require remote status `Settled`. The sync and reconcile tooling is part of the operational model, not an optional extra.

## Operational Notes

Subscription Bridge remains an independent consumer boundary for recurring subscriptions. Arkfile's one-time top-up path communicates only with BTCPay and does not gain Stripe credentials, Stripe webhooks, Boltz credentials, Monero RPC access, wallet access, or chain-daemon integration. AlmaPay deployment and payment infrastructure do not belong in Arkfile.

Secure unattended `arkfile-client` backup remains a separate client-authentication design. Do not pass account passwords, TOTP seeds, or TOTP codes through argv, environment variables, logs, or shell tracing. A narrow future implementation should read password and one-time MFA input from already-open file descriptors or systemd credential files, reject ambiguous simultaneous input sources, require restrictive file ownership and permissions, consume bounded single values, and erase buffers after use. Manual terminal entry must remain the default. The preferred long-term design is a revocable upload-only credential that cannot download, share, delete, manage the account, or access billing; that token and server authorization model requires a separate security review and must not be approximated by extending bearer session lifetime.

Automated unit and mock integration tests must never make real payments. Live BTC, Monero, Boltz, and Stripe acceptance tests are operator-run procedures requiring explicit authorization, isolated test accounts, production-equivalent configuration review, and real funds. Automated agents must not invoke them. Operators should first run the repository's non-destructive unit and static checks, then use the documented developer-controlled deployment and e2e workflow appropriate to their environment.

## Operator-Run Live Acceptance

A live AlmaPay-backed acceptance run is separate from Arkfile's automated suite. An authorized operator must verify the Arkfile and public BTCPay origins, store ID, webhook destination and secret, API-key scope, two-confirmation on-chain policy, Lightning behavior, and CSP before enabling payments. The operator then creates one explicitly authorized minimum-value invoice per enabled payment rail, confirms that BTCPay receives only the amount and opaque `invoice_id`, observes `InvoiceSettled`, verifies exactly one local ledger credit, replays the signed webhook, runs `arkfile-admin payments reconcile`, and confirms that neither replay changes the balance or ledger. BTC, Monero, Boltz, and Stripe steps spend real funds and must never be run by an automated agent. Arkfile must not receive or store AlmaPay wallet, RPC, Stripe, Boltz, or chain-daemon credentials during this procedure.
