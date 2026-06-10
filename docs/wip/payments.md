# Payments Integration (BTCPay Server)

This document describes how Arkfile adds self-service balance top-ups on top of the microcent-denominated storage-credits and usage-metering foundation. Payment processing is delegated to a self-hosted BTCPay Server instance, which handles Bitcoin (on-chain and Lightning), Monero, and optionally credit cards through the BTCPay Server Stripe Payments plugin. Arkfile never loads Stripe scripts in the browser and never parses Stripe webhooks directly; every paid top-up is represented locally as a BTCPay invoice and a corresponding ledger credit. The design keeps the core application privacy-preserving: no user emails or real names are sent to BTCPay, and checkout happens either in an embedded iframe or via a checkout URL the user opens separately.

Most of this integration is implemented and covered by Go unit tests, shell-based e2e tests (`phase_11d_billing` and `phase_11e_payments` in `scripts/testing/e2e-test.sh`), and a Playwright billing-panel test. A focused remediation pass remains before live financial traffic; that work is summarized at the end of this document.

## Purpose and Architectural Alignment

The payments layer exists to let users top up their microcent balance without operator intervention. Rather than wiring multiple payment gateways into Arkfile, all provider complexity lives in BTCPay Server: address derivation, exchange rates, payment method selection, and settlement tracking. Arkfile's backend creates USD-denominated invoices through BTCPay's Greenfield API, records a local `payment_invoices` row, and credits the user's balance when BTCPay confirms settlement via a signed webhook.

This design builds on the storage-credits ledger and hourly billing meter described in the storage-credits design documents. Credit balance and hard storage caps remain decoupled: paying does not automatically raise a user's storage limit unless an operator configures that separately. The `payment_invoices` table provides an auditable record of initiated and completed top-ups distinct from the `credit_transactions` usage and gift rows written by the billing meter and admin tools.

## Core Assumptions and Decisions

The operator deploys and maintains a BTCPay Server instance. Arkfile communicates with it using the Greenfield API (`payments/btcpay.go`), creating invoices in USD that settle in whatever payment methods the store supports. Credit card payments, when offered, are rendered entirely on BTCPay's invoice page via the Stripe Payments plugin, which preserves Arkfile's Content Security Policy and avoids third-party payment scripts in our frontend.

Settlement is webhook-driven. BTCPay signs payloads with SHA256 HMAC using a shared secret; Arkfile verifies the `BTCPay-Sig` header (`payments/webhooks.go`), matches the event to a local invoice, and credits the user through `billing.ProcessPayment`. The provider invoice ID is stored as the `credit_transactions.transaction_id`, giving idempotent protection against duplicate credits on replay. Webhook handlers accept `InvoiceSettled` and `InvoiceCompleted` events.

For CLI users, the server returns a checkout URL when an invoice is created; the user completes payment in a browser. No client-side polling is required because the webhook applies the credit server-side once settlement is confirmed.

## Quota Gating and Overdrawn Policy

When payments are enabled, upload handlers soft-block users with a negative credit balance by returning HTTP 402 Payment Required. Downloads and other read operations are unaffected; the account is not suspended. This gating is implemented in `handlers/uploads.go` and covered by unit tests.

Hard storage limits remain independent of credit balance. The billing meter may allow negative balances during beta operation; production deployments with payments enabled are expected to enforce the upload soft-block so users cannot accumulate further storage charges without topping up.

A configurable grace period after which an operator may flag an overdrawn account for storage purge is described here as policy only. Automated deletion is not implemented; any purge must be an explicit administrative action logged in the admin audit trail.

## What Is Implemented

The `payment_invoices` table is defined in `database/unified_schema.sql` and managed through `models/payments.go`. The `payments` package provides `BTCPayClient` for invoice creation, `VerifyBTCPaySignature` for webhook authentication, and a `PaymentProvider` interface in `types.go` that `BTCPayClient` satisfies structurally but that handlers do not yet consume uniformly.

HTTP handlers in `handlers/payments.go` expose user-facing invoice creation and status, the public BTCPay webhook receiver, and admin invoice inspection and sync. Routes are registered in `handlers/route_config.go`: `POST /api/billing/invoice` and `GET /api/billing/invoice/:invoice_id` (authenticated, TOTP-protected), `POST /api/webhooks/btcpay` (public, signature-verified), and admin routes `GET /api/admin/payments/invoice/:invoice_id`, `GET /api/admin/payments/invoices`, and `POST /api/admin/payments/invoice/:invoice_id/sync`. Settlement is wired through a `ProcessPaymentFunc` seam in `handlers/billing_projection.go`, connected to `billing.ProcessPayment` at startup in `main.go`.

The billing panel in `client/static/js/src/ui/billing.ts` renders balance, usage projection, and transaction history from `GET /api/credits`. When payments are enabled, a "Top Up Balance" button opens a modal that posts to `/api/billing/invoice` and embeds the returned BTCPay checkout URL in an iframe. No Stripe or other third-party payment scripts are loaded in the Arkfile frontend.

Administration is available through `arkfile-admin payments show`, `payments list`, and `payments sync-invoice` (`cmd/arkfile-admin/payments_commands.go`). The sync command polls BTCPay for an invoice's remote state and settles locally when BTCPay reports `Settled`.

Configuration is driven by environment variables in `config/config.go`, seeded in `scripts/dev-reset.sh` for development. Payments default to disabled; when enabled, BTCPay URL, store ID, API key, webhook secret, and min/max top-up amounts are read from env.

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

Paid top-ups are intended to write `credit_transactions` rows with `transaction_type = 'payment'`. The schema CHECK constraint currently allows only `usage`, `gift`, and `adjustment`; the running code incorrectly inserts `gift` for payment settlements. Adding `payment` to the constraint and fixing the insert are part of the remaining remediation work described below.

## Backend Settlement Flow

The intended settlement sequence is: verify the webhook signature, locate the local `payment_invoices` row (by metadata `invoice_id` or BTCPay `invoiceId`), credit the user's balance atomically via `billing.ProcessPayment`, then mark the invoice `paid`. `ProcessPayment` runs inside a SQLite transaction: it reads or creates the `user_credits` row, updates the balance, and inserts a `credit_transactions` row keyed by the provider invoice ID as `transaction_id`. A duplicate `transaction_id` causes the insert to fail, preventing double-credit on replay.

**Current deviation:** both the webhook handler and `AdminSyncInvoiceHandler` mark the invoice `paid` before calling `ProcessPayment`. If the credit step fails, the invoice is already `paid` and webhook retries return "Invoice already paid" without ever crediting the user. This must be corrected before production use, ideally by crediting first and marking paid only on success, or by wrapping both steps in a single transactional function such as `billing.SettlePaymentInvoice`.

**Current deviation:** `AdminSyncInvoiceHandler` performs raw BTCPay Greenfield HTTP and interprets BTCPay-specific status strings (`Settled`, `Expired`, `Invalid`) directly in the handler rather than through the `payments` package. The `PaymentProvider` interface covers `CreateInvoice` only; sync logic should move onto `BTCPayClient` (with a `GetInvoiceStatus` method or equivalent), and handlers should obtain the provider through a small factory such as `payments.NewProvider(cfg)` rather than calling `NewBTCPayClient` directly.

## HTTP API

`POST /api/billing/invoice` accepts `{"amount_usd": "20.00"}` (the `provider` field is not required; BTCPay is the only supported provider and is implied). The handler validates the amount against `ARKFILE_MIN_TOP_UP_USD` and `ARKFILE_MAX_TOP_UP_USD`, generates a local invoice ID (`inv_` prefix plus UUID), calls BTCPay to create the remote invoice with metadata linking back to the local ID, persists a `pending` row, and returns `invoice_id`, `checkout_url`, and `provider: "btcpay"`. A redirect URL of `/billing?success=true&invoice=...` is passed to BTCPay for external-tab checkout flows.

`GET /api/billing/invoice/:invoice_id` returns the local invoice record for the authenticated owner. `POST /api/webhooks/btcpay` is unauthenticated; it requires a valid `BTCPay-Sig` header and processes settlement events as described above.

Admin endpoints support invoice inspection, filtered listing (`?username=`, `?status=`), and manual sync against BTCPay for recovery when a webhook was missed.

## Frontend Integration

The billing panel follows the same inline-panel pattern as security settings and contact info. When payments are enabled, the top-up modal collects a USD amount, creates an invoice via the API, and replaces the form with a full-width iframe pointing at BTCPay's checkout page. BTCPay's invoice UI supports iframe embedding, so users can complete payment without leaving Arkfile in the common case.

The redirect URL passed to BTCPay for users who open checkout in a separate tab is not yet handled by the SPA: there is no `/billing` route or logic to read `?success=true&invoice=...` on load, open the billing panel, and confirm settlement. This is remaining work for the external-tab flow.

## Administration

`arkfile-admin payments show <invoice_id>` displays a single invoice. `payments list [--user NAME] [--status STATUS]` lists invoices with optional filters. `payments sync-invoice <invoice_id>` queries BTCPay and reconciles local state, settling when the remote invoice is `Settled` or updating to `expired`/`failed` as appropriate.

`payments reconcile`, which would scan for `paid` invoices lacking a matching `credit_transactions` row and repair them, is not yet implemented. This command is needed both for missed webhooks and as a recovery path for the settlement-order bug described above.

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

Defaults are `0.50` minimum and `1000.00` maximum top-up in code and `dev-reset.sh`. When `ARKFILE_PAYMENTS_ENABLED=true`, startup does not yet validate that BTCPay credentials are present; misconfiguration surfaces only when a user attempts to create an invoice.

## Test Coverage

Go unit tests cover the BTCPay client (`payments/btcpay_test.go`), webhook signature verification (`payments/webhooks_test.go`), payment invoice model CRUD (`models/payments_test.go`), `billing.ProcessPayment` ledger behavior (`billing/payments_test.go`), and handler-level flows including invoice creation, webhook settlement, signature rejection, idempotency on already-paid invoices, invoice status ownership, admin sync, payments config in `/api/credits`, and upload soft-blocking on negative balance (`handlers/payments_test.go`). Payments config loading is tested in `config/config_test.go`.

End-to-end tests run as `phase_11e_payments` in `scripts/testing/e2e-test.sh`, after `phase_11d_billing`. The payments phase starts a mock BTCPay server (`scripts/testing/btcpay-mock.go`), creates an invoice via the API, verifies admin CLI listing, sends a signed webhook to settle the invoice, and asserts the invoice becomes `paid` and the user ledger contains a row with reason `Payment top-up via btcpay`. Duplicate webhook replay is covered in Go unit tests but not yet in the e2e harness.

Playwright (`scripts/testing/e2e-playwright.ts`) verifies the billing panel renders balance, usage grid, and transaction history. The top-up modal and BTCPay iframe are not yet covered in Playwright. There are no TypeScript unit tests for `billing.ts`.

## Honest Trade-offs

Refunds are manual by design. An automated refund or chargeback API would expand the attack surface on a privacy-focused file vault; operators handle exceptions through existing admin billing tools.

Because Arkfile does not send PII to BTCPay, BTCPay cannot send payment receipt emails on Arkfile's behalf unless configured independently on the BTCPay side. Users rely on transaction records in the Arkfile billing panel as their proof of payment.

Webhook delivery is the primary settlement path. If a webhook is missed, the user's balance is not credited until an operator runs `payments sync-invoice` for that invoice or the not-yet-implemented `payments reconcile` command repairs orphaned records. The sync and reconcile tooling is therefore part of the operational model, not an optional extra.

## Remaining Work

The following items should be completed before enabling live payment traffic. They are ordered by severity.

Settlement order is the most urgent defect. The webhook handler and admin sync handler both mark invoices `paid` before `ProcessPayment` succeeds. A failed credit insert leaves the invoice in a state where retries are ignored. The fix is to credit first and mark paid only on success, or to combine both steps in a single transactional settlement function. The same change applies to both code paths. New tests should assert that a failed credit leaves the invoice `pending`, and that a recovery path works when the credit row already exists but the invoice is still `pending`.

The audit log must distinguish paid top-ups from admin gifts. `billing.ProcessPayment` currently inserts `transaction_type = 'gift'` because the schema CHECK constraint does not yet include `payment`. The constraint in `database/unified_schema.sql` must be extended, existing databases may need a table-rebuild migration in `runSchemaMigrations()`, test fixture schemas must be updated, and the insert and return value in `billing/payments.go` must use `payment`. Frontend display in `billing.ts` should treat `payment` as a top-up (not an admin gift). E2e and unit tests should assert the `payment` type explicitly.

The `PaymentProvider` interface must be wired through handlers rather than left as dead architecture. `BTCPayClient` already implements `CreateInvoice`; add invoice status polling to the client (moving the raw HTTP currently in `AdminSyncInvoiceHandler`), add `var _ PaymentProvider = (*BTCPayClient)(nil)` for compile-time enforcement, introduce `payments.NewProvider(cfg)` for construction, and have handlers depend on the interface. This is a small change that honors the decoupling goal of the `payments` package and keeps BTCPay-specific details out of handler code.

`payments reconcile` should be implemented as described in the Administration section: scan for `paid` invoices without a matching `credit_transactions.transaction_id`, call `ProcessPayment` for each orphan, and expose the operation as `POST /api/admin/payments/reconcile` and `arkfile-admin payments reconcile`. This is the safety net for missed webhooks and for any records affected by the settlement-order bug on test deployments.

Startup validation should reject `ARKFILE_PAYMENTS_ENABLED=true` when BTCPay URL, store ID, API key, or webhook secret are missing, and should verify that min and max top-up amounts parse as positive decimals with min less than max.

Post-checkout redirect handling should detect `?success=true&invoice=...` on page load, open the billing panel, show confirmation, and strip the query string. Optionally poll invoice status for users who completed payment in an external tab.

Test gaps to close: add duplicate webhook replay to `phase_11e_payments` in `e2e-test.sh`, add a Playwright test for the top-up modal and checkout iframe, and add settlement-order failure and recovery cases to `handlers/payments_test.go`.

After these remediations, run `dev-reset.sh` followed by `e2e-test.sh` and `e2e-playwright.sh` to verify the full billing and payments path.

