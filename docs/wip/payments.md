# Payments Integration (BTCPay Server)

This document describes how Arkfile adds self-service balance top-ups on top of the microcent-denominated storage-credits and usage-metering foundation. Payment processing is delegated to a self-hosted BTCPay Server instance, which handles Bitcoin (on-chain and Lightning), Monero, and optionally credit cards through the BTCPay Server Stripe Payments plugin. Arkfile never loads Stripe scripts in the browser and never parses Stripe webhooks directly; every paid top-up is represented locally as a BTCPay invoice and a corresponding ledger credit. The design keeps the core application privacy-preserving: no user emails or real names are sent to BTCPay, and checkout happens either in an embedded iframe or via a checkout URL the user opens separately.

The integration is implemented end-to-end with Go unit tests, shell-based e2e tests (`phase_11d_billing` and `phase_11e_payments` in `scripts/testing/e2e-test.sh`), and Playwright billing-panel tests including the top-up modal.

## Purpose and Architectural Alignment

The payments layer exists to let users top up their microcent balance without operator intervention. Rather than wiring multiple payment gateways into Arkfile, all provider complexity lives in BTCPay Server: address derivation, exchange rates, payment method selection, and settlement tracking. Arkfile's backend creates USD-denominated invoices through BTCPay's Greenfield API, records a local `payment_invoices` row, and credits the user's balance when BTCPay confirms settlement via a signed webhook.

This design builds on the storage-credits ledger and hourly billing meter described in the storage-credits design documents. Credit balance and hard storage caps remain decoupled: paying does not automatically raise a user's storage limit unless an operator configures that separately. The `payment_invoices` table provides an auditable record of initiated and completed top-ups distinct from the `credit_transactions` usage and gift rows written by the billing meter and admin tools.

## Core Assumptions and Decisions

The operator deploys and maintains a BTCPay Server instance. Arkfile communicates with it using the Greenfield API (`payments/btcpay.go`), creating invoices in USD that settle in whatever payment methods the store supports. Credit card payments, when offered, are rendered entirely on BTCPay's invoice page via the Stripe Payments plugin, which preserves Arkfile's Content Security Policy and avoids third-party payment scripts in our frontend. The CSP includes a `frame-src` directive for the configured BTCPay Server origin when payments are enabled.

Settlement is webhook-driven. BTCPay signs payloads with SHA256 HMAC using a shared secret; Arkfile verifies the `BTCPay-Sig` header (`payments/webhooks.go`), matches the event to a local invoice, and settles through `billing.SettlePaymentInvoice`, which credits the user and marks the invoice `paid` in one transaction. The provider invoice ID is stored as the `credit_transactions.transaction_id`, giving idempotent protection against duplicate credits on replay. Webhook handlers accept `InvoiceSettled` and `InvoiceCompleted` events.

For CLI users, the server returns a checkout URL when an invoice is created; the user completes payment in a browser. No client-side polling is required because the webhook applies the credit server-side once settlement is confirmed. Users who open checkout in an external tab are redirected back to `/billing?success=true&invoice=...`; the SPA opens the billing panel, polls invoice status, and strips the query string.

## Quota Gating and Overdrawn Policy

When payments are enabled, upload handlers soft-block users with a negative credit balance by returning HTTP 402 Payment Required. Downloads and other read operations are unaffected; the account is not suspended. This gating is implemented in `handlers/uploads.go` and covered by unit tests.

Hard storage limits remain independent of credit balance. The billing meter may allow negative balances during beta operation; production deployments with payments enabled are expected to enforce the upload soft-block so users cannot accumulate further storage charges without topping up.

A configurable grace period after which an operator may flag an overdrawn account for storage purge is described here as policy only. Automated deletion is not implemented; any purge must be an explicit administrative action logged in the admin audit trail.

## What Is Implemented

The `payment_invoices` table is defined in `database/unified_schema.sql` and managed through `models/payments.go`. The `payments` package provides `BTCPayClient` for invoice creation and status polling, `VerifyBTCPaySignature` for webhook authentication, `NewProvider(cfg)` for construction, and a `PaymentProvider` interface in `types.go` that handlers consume through the factory.

HTTP handlers in `handlers/payments.go` expose user-facing invoice creation and status, the public BTCPay webhook receiver, admin invoice inspection/sync/reconcile. Routes are registered in `handlers/route_config.go`: `POST /api/billing/invoice` and `GET /api/billing/invoice/:invoice_id` (authenticated, TOTP-protected), `POST /api/webhooks/btcpay` (public, signature-verified), and admin routes `GET /api/admin/payments/invoice/:invoice_id`, `GET /api/admin/payments/invoices`, `POST /api/admin/payments/invoice/:invoice_id/sync`, and `POST /api/admin/payments/reconcile`. Settlement is wired through `SettlePaymentInvoiceFunc` in `handlers/billing_projection.go`, connected to `billing.SettlePaymentInvoice` at startup in `main.go`.

The billing panel in `client/static/js/src/ui/billing.ts` renders balance, usage projection, and transaction history from `GET /api/credits`. When payments are enabled, a "Top Up Balance" button opens a modal that posts to `/api/billing/invoice` and embeds the returned BTCPay checkout URL in an iframe. Payment rows display as type "Top-up" (`transaction_type = 'payment'`). No Stripe or other third-party payment scripts are loaded in the Arkfile frontend.

Administration is available through `arkfile-admin payments show`, `payments list`, `payments sync-invoice`, and `payments reconcile` (`cmd/arkfile-admin/payments_commands.go`). The sync command polls BTCPay for an invoice's remote state and settles locally when BTCPay reports `Settled`, or repairs paid invoices missing ledger credits. Reconcile scans all paid invoices without a matching `credit_transactions.transaction_id` and applies credits.

Configuration is driven by environment variables in `config/config.go`, seeded in `scripts/dev-reset.sh` for development. Payments default to disabled; when enabled, startup validates that BTCPay URL, store ID, API key, and webhook secret are present and that min/max top-up amounts are positive with min less than max.

## Database Schema

Local payment state lives in `payment_invoices`:

```sql
CREATE TABLE IF NOT EXISTS payment_invoices (
    invoice_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    amount_usd_microcents BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    provider TEXT NOT NULL,
    provider_invoice_id TEXT UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES users(username) ON DELETE RESTRICT,
    CHECK(status IN ('pending', 'paid', 'expired', 'failed')),
    CHECK(provider IN ('btcpay'))
);
```

The RESTRICT foreign key ensures invoice records survive user soft-deletion for financial audit purposes. Indexes on `username` and `provider_invoice_id` support user lookups and webhook matching.

Paid top-ups write `credit_transactions` rows with `transaction_type = 'payment'`. Existing databases are migrated via `migrateCreditTransactionsPaymentType()` in `main.go`, which rebuilds `credit_transactions` when the CHECK constraint does not yet include `payment`.

## Backend Settlement Flow

The settlement sequence is: verify the webhook signature, locate the local `payment_invoices` row (by metadata `invoice_id` or BTCPay `invoiceId`), call `billing.SettlePaymentInvoice` to credit the user and mark the invoice `paid` atomically. `SettlePaymentInvoice` runs inside a SQLite transaction for pending invoices: it inserts the `credit_transactions` row keyed by the provider invoice ID as `transaction_id`, updates the user balance, then marks the invoice `paid`. A duplicate `transaction_id` causes the insert to fail without marking the invoice paid, so webhook retries can succeed on the next attempt.

If an invoice is already `paid` but lacks a matching credit row (recovery path for historical bad state), `SettlePaymentInvoice` and `AdminSyncInvoiceHandler` apply only the ledger credit. `billing.ReconcilePaidInvoices` scans for all such orphans.

## HTTP API

`POST /api/billing/invoice` accepts `{"amount_usd": "20.00"}` (the `provider` field is not required; BTCPay is the only supported provider and is implied). The handler validates the amount against `ARKFILE_MIN_TOP_UP_USD` and `ARKFILE_MAX_TOP_UP_USD`, generates a local invoice ID (`inv_` prefix plus UUID), calls BTCPay to create the remote invoice with metadata linking back to the local ID, persists a `pending` row, and returns `invoice_id`, `checkout_url`, and `provider: "btcpay"`. A redirect URL of `/billing?success=true&invoice=...` is passed to BTCPay for external-tab checkout flows.

`GET /api/billing/invoice/:invoice_id` returns the local invoice record for the authenticated owner. `POST /api/webhooks/btcpay` is unauthenticated; it requires a valid `BTCPay-Sig` header and processes settlement events as described above.

Admin endpoints support invoice inspection, filtered listing (`?user=`, `?status=`), manual sync against BTCPay, and bulk reconcile of paid invoices missing ledger credits.

## Frontend Integration

The billing panel follows the same inline-panel pattern as security settings and contact info. When payments are enabled, the top-up modal collects a USD amount, creates an invoice via the API, and replaces the form with a full-width iframe pointing at BTCPay's checkout page. BTCPay's invoice UI supports iframe embedding when the operator's BTCPay origin is allowed in CSP `frame-src`.

External-tab checkout returns to `/billing?success=true&invoice=...`. On load, `handleBillingCheckoutReturn()` in `billing.ts` opens the billing panel, polls `GET /api/billing/invoice/:invoice_id` until status is `paid` or attempts are exhausted, shows a confirmation message, and strips the query string.

## Administration

`arkfile-admin payments show <invoice_id>` displays a single invoice. `payments list [--user NAME] [--status STATUS]` lists invoices with optional filters. `payments sync-invoice <invoice_id>` queries BTCPay and reconciles local state, settling when the remote invoice is `Settled`, updating to `expired`/`failed` as appropriate, or repairing paid invoices missing credits. `payments reconcile` scans all paid invoices without matching ledger rows and applies credits.

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

Defaults are `0.50` minimum and `1000.00` maximum top-up in code and `dev-reset.sh`. When `ARKFILE_PAYMENTS_ENABLED=true`, startup rejects missing BTCPay credentials or invalid min/max top-up configuration.

## Test Coverage

Go unit tests cover the BTCPay client (`payments/btcpay_test.go`), webhook signature verification (`payments/webhooks_test.go`), payment invoice model CRUD (`models/payments_test.go`), `billing.ProcessPayment` and `billing.SettlePaymentInvoice` ledger behavior (`billing/payments_test.go`, `billing/settle_test.go`, `billing/reconcile_test.go`), and handler-level flows including invoice creation, webhook settlement, signature rejection, idempotency, settlement failure leaving invoice pending, recovery of paid-without-credit invoices, invoice status ownership, admin sync, reconcile, payments config in `/api/credits`, and upload soft-blocking on negative balance (`handlers/payments_test.go`). Payments config loading and validation are tested in `config/config_test.go`.

End-to-end tests run as `phase_11e_payments` in `scripts/testing/e2e-test.sh`, after `phase_11d_billing`. The payments phase starts a mock BTCPay server (`scripts/testing/btcpay-mock.go`), creates an invoice via the API, verifies admin CLI listing, sends a signed webhook to settle the invoice, asserts the invoice becomes `paid` and the user ledger contains a row with `transaction_type = 'payment'`, and verifies duplicate webhook replay is idempotent.

Playwright (`scripts/testing/e2e-playwright.ts`) verifies the billing panel renders balance, usage grid, and transaction history, and tests the top-up modal invoice creation with a mocked API response and checkout iframe embedding.

## Honest Trade-offs

Refunds are manual by design. An automated refund or chargeback API would expand the attack surface on a privacy-focused file vault; operators handle exceptions through existing admin billing tools.

Because Arkfile does not send PII to BTCPay, BTCPay cannot send payment receipt emails on Arkfile's behalf unless configured independently on the BTCPay side. Users rely on transaction records in the Arkfile billing panel as their proof of payment.

Webhook delivery is the primary settlement path. If a webhook is missed, the user's balance is not credited until an operator runs `payments sync-invoice` for that invoice or `payments reconcile` repairs orphaned records. The sync and reconcile tooling is part of the operational model, not an optional extra.

## Operational Notes

Invoice creation calls BTCPay before persisting the local row. If the database insert fails after BTCPay succeeds, a remote orphan invoice may exist until an operator investigates. This is rare and does not affect webhook settlement once the local row exists.

After code changes, run `dev-reset.sh` followed by `e2e-test.sh` and `e2e-playwright.sh` to verify the full billing and payments path before enabling live payment traffic.
