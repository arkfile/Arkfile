# Payments

Automated one-time top-ups are disabled. Arkfile keeps the generic invoice and credit-ledger seam so a payment provider can be added later. No processor client is built in. `ARKFILE_PAYMENTS_ENABLED` must stay false; startup rejects the flag while no provider exists.

Out-of-band PayNym / BIP47 and Monero credit stays in use. Those addresses are display-only. After the operator verifies a payment, `arkfile-admin billing gift` writes a `gift` ledger row. See `docs/wip/archive/oob-payments.md`.

Card subscriptions stay on the Subscription Bridge. Arkfile stores opaque `checkout_id` and `subscription_ref` values and accepts one signed webhook at `POST /api/webhooks/subscription-bridge`. See `docs/wip/prod-prep/05-subscriptions.md`.

## What remains

`payment_invoices` records `invoice_id`, username, amount in microcents, status (`creating`, `pending`, `paid`, `expired`, `failed`), `provider`, and `provider_invoice_id`. `models/payments.go` is the database access. `payments.PaymentProvider` exposes `Name`, `CreateInvoice`, and `GetInvoiceStatus`. `GetInvoiceStatus` is expected to return `paid`, `pending`, `expired`, or `failed`. `payments.NewProvider` returns an error until an implementation is added.

`credit_transactions.transaction_type = 'payment'` is the ledger row for a settled top-up. The provider invoice id is stored as `transaction_id` so a replay cannot credit twice. `billing.ProcessPayment` and `billing.SettlePaymentInvoice` perform that credit. `billing.ReconcilePendingInvoices` settles a pending row only when the provider reports `paid`.

Authenticated routes `POST /api/billing/invoice` and `GET /api/billing/invoice/:invoice_id` remain. Invoice creation returns 409 while the user has an active subscription, and 403 while payments are disabled. Admin `payments list`, `payments show`, `payments sync-invoice`, and `payments reconcile` remain. Sync and reconcile fail closed with no provider configured.

The browser shows Top Up Balance only when `GET /api/credits` includes a `payments` block, which happens only when payments are enabled. Checkout return handling in `billing.ts` is unchanged and waits for a future provider to issue a `checkout_url`.

One USD is 100,000,000 microcents. Top-up amounts use at most two decimal places and must fall between `ARKFILE_MIN_TOP_UP_USD` and `ARKFILE_MAX_TOP_UP_USD`.
