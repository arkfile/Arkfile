# Out-of-Band Crypto Top-Ups (PayNym and Monero)

Status: Implemented. Optional display-only payment destinations for manual PAYG credit. Not a replacement for AlmaPay/BTCPay or the Subscription Bridge; a straightforward interim and ongoing convenience rail.

## Purpose

Operators can publish a dedicated Bitcoin PayNym (and/or BIP47 payment code) and an optional Monero address. Users pay out of band, then contact the admin with their Arkfile username and transaction ID. The admin verifies the payment in Sparrow (or a Monero wallet) and credits the user with `arkfile-admin billing gift`. Arkfile does not watch the chain, create invoices for these rails, or auto-settle.

## Configuration

Set any combination of these environment variables (all optional; empty means the UI hides that method):

```
ADMIN_PAYNYM=+yourpaynym123
ADMIN_PAYNYM_PAYMENT_CODE=PM8T...
ADMIN_MONERO_ADDRESS=4...
```

Also set `ARKFILE_ADMIN_CONTACT` so users know where to send username + txid. Startup validates shape lightly: PayNym should start with `+`, payment codes with `PM8T`, Monero address length in a plausible range.

Use a Sparrow wallet dedicated to Arkfile receives. Do not reuse this payment code for Auth47 login identity.

## API

`GET /api/oob-payments` (public) returns:

```json
{
  "configured": true,
  "paynym": "+yourpaynym123",
  "paynym_payment_code": "PM8T...",
  "monero_address": "4...",
  "admin_contact": "ops@example.com"
}
```

When nothing is configured, `configured` is false and string fields are empty.

## Surfaces

Billing panel (logged-in web UI) shows a Manual Crypto Top-Up section when configured. `arkfile-client billing show` prints the same destinations and short steps (and includes them under `oob_payments` when using `--json`). FAQ entries describe the user flow.

## Operator credit procedure

1. User opens a BIP47 channel to the published PayNym (notification transaction), sends Bitcoin, and waits for confirmations; or sends XMR to the published Monero address.
2. User messages the admin contact with Arkfile username and payment txid.
3. Admin confirms the payment in Sparrow or their Monero wallet (amount, confirmations, destination).
4. Admin converts to USD using a documented rate rule (for example rate at first confirmation, round down).
5. Admin credits: `arkfile-admin billing gift --user NAME --amount USD --reason "PayNym top-up txid=..."` or `"XMR top-up txid=..."`.
6. Admin keeps a local list of credited txids. Gift has no idempotency key, so double-crediting the same txid is an ops failure mode.
7. Admin replies that credit was applied.

## Code map

| Piece | Location |
|-------|----------|
| Config | `config/config.go` (`OobPaymentsConfig`, env load, validation) |
| Handler | `handlers/oob_payments.go` |
| Route | `handlers/route_config.go` (`GET /api/oob-payments`) |
| Tests | `handlers/oob_payments_test.go` |
| Web UI | `client/static/js/src/ui/oob-payments.ts` (wired from `billing.ts`) |
| CSS | `client/static/css/styles.css` (`.billing-oob-*`) |
| CLI | `cmd/arkfile-client/billing_commands.go` |
| Admin gift help | `cmd/arkfile-admin/billing_commands.go` |
| Env sample | `.env.example` |
| Docs | `docs/api.md`, `docs/user-faq.md`, `client/static/faq.html`, this file |

## Explicit non-goals

No `payment_invoices` provider entry, no chain watcher, no FX service, no webhook, no automatic `payment` ledger type for these rails (manual credits use existing `gift`). Automated BTC/LN/card top-ups remain AlmaPay/BTCPay and Subscription Bridge.
