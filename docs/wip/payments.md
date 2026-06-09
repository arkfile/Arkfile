# Payments Integration and BTCPay Server Integration Plan

This document details the definitive design and implementation plan for adding payment-provider rails on top of Arkfile's microcent-denominated storage-credits and usage-metering foundation. It focuses on a unified integration with a self-hosted BTCPay Server instance to facilitate Bitcoin, Lightning, and Monero payments, while also supporting credit cards via the BTCPay Server Stripe Payments plugin. This approach keeps Arkfile's core codebase clean, secure, and privacy-preserving.

## Scope and Architectural Alignment

The goal of this design is to introduce automated, self-service payment flows that allow users to top up their microcent balances. Instead of integrating multiple independent payment gateways directly into Arkfile, we delegate all payment processing to a self-hosted BTCPay Server instance. This includes decentralized cryptocurrencies like Bitcoin (on-chain and Lightning) and Monero, as well as conventional credit cards via the BTCPay Server Stripe Payments extension.

This design assumes and builds upon the completed ledger schema and meter architecture specified in the storage credits design. In particular, it leverages the unique database constraints, soft-deletion structures, and the decoupled relationship between credit balance and storage hard caps.

## Core Assumptions and Decisions

We assume that the operator will deploy and maintain a self-hosted BTCPay Server instance. Arkfile's server backend will interact with this instance using BTCPay Server's Greenfield API to generate invoices denominated in USD, which are then settled in the user's chosen payment method. This delegates address derivation, exchange rate calculations, and payment tracking entirely to BTCPay Server, insulating Arkfile's backend from the operational complexity of managing blockchain nodes.

We have decided to use the Stripe Payments plugin for BTCPay Server to handle credit card payments. This plugin renders credit card payment options directly within the BTCPay Server invoice page. This decision eliminates the need for Arkfile's web frontend to load Stripe's proprietary scripts, preserving our strict Content Security Policy and shielding our users from direct third-party telemetry. It also means our backend database does not need custom Stripe webhook parsing logic or a separate invoice ledger; every payment is represented in Arkfile's system as a standard BTCPay Server invoice.

We have decided that a webhook-driven push model will serve as the primary settlement path. When a payment is settled, BTCPay Server will notify Arkfile via a cryptographic webhook. BTCPay Server signs these webhooks using a SHA256 HMAC of the payload, keyed by a secret shared with Arkfile during setup. When Arkfile receives this webhook, we verify the signature, locate the local invoice record, and perform a transactional update to credit the user's microcent balance while recording the BTCPay Server invoice ID in our unique transaction ledger.

For Go CLI users, the server will update their balance when the webhook resolves. When a CLI user requests a balance top-up, the server will return the raw BTCPay Server checkout web address in the terminal. The user can then open this link in their preferred browser to complete the payment. The CLI client does not need to perform active polling; the server automatically applies the credit to their account once the webhook is received and verified.

## Quota Gating and Overdrawn Policy

While the billing meter allows users to run negative balances during the beta, a production payment deployment enforces a soft-block on negative balances.

Upload Gating: The API upload handlers (including chunked upload endpoints) must check the user's credit balance. If the balance is negative, the server must return a 402 Payment Required HTTP status code and reject the upload. This is a soft-block; the account is not suspended, and download operations remain fully functional.

Hard Quota Decoupling: The hard limit on user storage is maintained independently of the credit balance. Paying does not dynamically increase the hard limit unless the operator configures specific tiers or the user explicitly buys a larger hard cap.

Active Grace and Cleanup: If an account remains in a negative-balance state for longer than a configurable grace period, the operator may choose to flag the account for storage purge. Automated deletion is strictly prohibited; the cleanup must be triggered by an administrative action logged in the admin logs table.

## Database Schema Changes

We introduce a single new table, `payment_invoices`, to manage the local state of payment requests before they are completed by the external payment processors. This ensures that we have a solid, auditable ledger of all initiated transactions.

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

CREATE INDEX IF NOT EXISTS idx_payment_invoices_username ON payment_invoices(username);
CREATE INDEX IF NOT EXISTS idx_payment_invoices_provider_invoice_id ON payment_invoices(provider_invoice_id);
```

The RESTRICT foreign key constraint guarantees that even if a user is soft-deleted, their invoice logs are retained in the database for financial compliance.

## The Go `payments` Package Architecture

We will add a new top-level Go package named `payments` to encapsulate all external provider interactions and keep handlers decoupled from third-party client details.

```
payments/
    types.go            // PaymentProvider interface, Invoice struct, Event struct
    btcpay.go           // BTCPay Server Greenfield client implementation
    webhooks.go         // Unified webhook validation and routing
```

### The `PaymentProvider` Interface

BTCPay Server will implement a common interface, allowing handlers to remain provider-agnostic:

```go
package payments

import (
	"context"
)

type ProviderInvoice struct {
	ProviderInvoiceID string
	CheckoutURL       string
}

type PaymentProvider interface {
	CreateInvoice(ctx context.Context, invoiceID string, amountMicrocents int64, redirectURL string) (*ProviderInvoice, error)
}
```

### BTCPay Greenfield Client (`btcpay.go`)

BTCPay Server Greenfield API is used directly via raw HTTP calls using Go's standard `net/http` package to avoid bloated third-party SDK dependencies.

Creating an invoice is done by sending a POST request to the store's invoices endpoint:

```go
package payments

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type BTCPayClient struct {
	BaseURL    string
	StoreID    string
	APIKey     string
	HTTPClient *http.Client
}

func (c *BTCPayClient) CreateInvoice(ctx context.Context, invoiceID string, amountMicrocents int64, redirectURL string) (*ProviderInvoice, error) {
	amountUSD := float64(amountMicrocents) / 100000000.0
	payload := map[string]interface{}{
		"amount":   fmt.Sprintf("%.2f", amountUSD),
		"currency": "USD",
		"metadata": map[string]string{
			"invoice_id": invoiceID,
		},
		"checkout": map[string]interface{}{
			"speedPolicy":    "HighSpeed",
			"redirectURL":    redirectURL,
		},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/stores/%s/invoices", c.BaseURL, c.StoreID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+c.APIKey)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("btcpay returned bad status: %d", resp.StatusCode)
	}
	var respData struct {
		ID          string `json:"id"`
		CheckoutLink string `json:"checkoutLink"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}
	return &ProviderInvoice{
		ProviderInvoiceID: respData.ID,
		CheckoutURL:       respData.CheckoutLink,
	}, nil
}
```

## Signature Verification and Webhook Routing

Webhook endpoint security is a critical risk area. We implement native cryptographic signature verification for all incoming payloads to eliminate replay attacks and tampering.

### BTCPay Webhook Signature Math

BTCPay Server signs webhooks using SHA256 HMAC of the raw request payload, using the webhook secret as the key. The value is sent as a hex-encoded string in the `BTCPay-Sig` header, prefixed with `sha256=`.

```go
package payments

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func VerifyBTCPaySignature(body []byte, sigHeader string, secret string) bool {
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	hexSig := sigHeader[7:]
	expectedSig, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	computedSig := mac.Sum(nil)
	return hmac.Equal(computedSig, expectedSig)
}
```

## Webhook Handler Event Processing and Payment Settlement

Webhook handlers must route verified payloads to settle local invoices. To preserve dependency boundaries, `main.go` will wire a settlement function seam to handlers during startup:

```go
var ProcessPaymentFunc func(db *sql.DB, username string, amountMicrocents int64, providerTxID string, paymentType string) (*models.CreditTransaction, error)

func SetProcessPaymentFunc(fn func(*sql.DB, string, int64, string, string) (*models.CreditTransaction, error)) {
	ProcessPaymentFunc = fn
}
```

### Transactional Credit Settlement Logic

The settlement routine in the `billing` package handles actual balance credit operations securely within a strict SQLite transaction bracket. It locks the `user_credits` record, inserts the transaction row ensuring uniqueness of the `transaction_id`, and adds the balance.

```go
package billing

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/models"
)

func ProcessPayment(db *sql.DB, username string, amountMicrocents int64, providerTxID string, paymentType string) (*models.CreditTransaction, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var currentBalance float64
	err = tx.QueryRow(`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`, username).Scan(&currentBalance)
	if err == sql.ErrNoRows {
		_, err = tx.Exec(`INSERT INTO user_credits (username, balance_usd_microcents) VALUES (?, 0)`, username)
		if err != nil {
			return nil, err
		}
		currentBalance = 0
	} else if err != nil {
		return nil, err
	}
	newBalance := int64(currentBalance) + amountMicrocents
	_, err = tx.Exec(`UPDATE user_credits SET balance_usd_microcents = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, newBalance, username)
	if err != nil {
		return nil, err
	}
	reason := fmt.Sprintf("Payment top-up via %s", paymentType)
	_, err = tx.Exec(`
		INSERT INTO credit_transactions (transaction_id, username, amount_usd_microcents, balance_after_usd_microcents, transaction_type, reason, created_at)
		VALUES (?, ?, ?, ?, 'payment', ?, CURRENT_TIMESTAMP)
	`, providerTxID, username, amountMicrocents, newBalance, reason)
	if err != nil {
		return nil, fmt.Errorf("failed to insert audit ledger (likely duplicate transaction): %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &models.CreditTransaction{
		Username:                  username,
		AmountUSDMicrocents:       amountMicrocents,
		BalanceAfterUSDMicrocents: newBalance,
		TransactionType:           "payment",
	}, nil
}
```

## HTTP API Surface

The API endpoints will be registered under the authenticated user route group, except for the public webhook receivers which must bypass OPAQUE authorization middleware.

### Create Invoice Endpoint

`POST /api/billing/invoice` (Authenticated)
Request Body:
```json
{
  "amount_usd": "20.00",
  "provider": "btcpay"
}
```

The handler will:
1. Validate that `amount_usd` parses to a decimal and fits within `ARKFILE_MIN_TOP_UP_USD` and `ARKFILE_MAX_TOP_UP_USD`.
2. Generate a cryptographically secure UUID as the local `invoice_id`.
3. Query the configured payment provider (`BTCPayClient`).
4. On provider success, write a `pending` row to `payment_invoices` recording the returned `provider_invoice_id`.
5. Return JSON:
```json
{
  "success": true,
  "data": {
    "invoice_id": "inv_8e4f16b2",
    "checkout_url": "https://btcpay.example.com/invoice?id=XyZ123",
    "provider": "btcpay"
  }
}
```

### Get Invoice Status Endpoint

`GET /api/billing/invoice/:invoice_id` (Authenticated)
Returns the local state of the invoice:
```json
{
  "success": true,
  "data": {
    "invoice_id": "inv_8e4f16b2",
    "status": "pending",
    "provider": "btcpay",
    "created_at": "2026-06-09T08:00:00Z"
  }
}
```

### Public Webhook Receiver

`POST /api/webhooks/btcpay` (Unauthenticated, public)
Checks the `BTCPay-Sig` header, reads the raw body, and calls `VerifyBTCPaySignature`. It decodes the JSON payload, checks for the `InvoiceSettled` event type, matches the metadata `invoice_id` against the local database, updates `payment_invoices.status = 'paid'`, and invokes `ProcessPayment`.

## Frontend Integration and BTCPay Modal Iframe

When a user selects "Top Up Balance" and clicks "Generate Invoice", the API returns the BTCPay `checkout_url`. The UI will load this URL inside an iframe directly within a modal. BTCPay Server's invoice UI is specifically optimized for iframe embed formats, offering a seamless payment flow without redirecting the user away from Arkfile.

For Go CLI users, the server will output the raw BTCPay Server checkout web address in the terminal. The user can then open this link in their preferred browser to complete the payment. No polling is required; the server automatically applies the credit to their account once the webhook is received and verified.

## CLI Surface (`arkfile-admin payments`)

A set of administration subcommands is added to assist operators with auditing and resolving out-of-sync events:

| Command | Action | Description |
|---|---|---|
| `payments show <invoice_id>` | `GET /api/admin/payments/:id` | Displays detailed database information for the specific invoice. |
| `payments list [--user NAME] [--status STATUS]` | `GET /api/admin/payments` | Lists local records with option to filter by user or invoice state. |
| `payments sync-invoice <invoice_id>` | `POST /api/admin/payments/:id/sync` | Actively polls BTCPay API for the invoice's true state and reconciles it. |
| `payments reconcile` | internal script | Scans the database for paid `payment_invoices` without corresponding `credit_transactions` and repairs them. |

## Configuration (`secrets.env`)

The operator configures the payment rails using these environment variables, which must be added to the production template:

```
ARKFILE_PAYMENTS_ENABLED=true
ARKFILE_BTCPAY_SERVER_URL=https://btcpay.example.com
ARKFILE_BTCPAY_STORE_ID=YourStoreIDHere
ARKFILE_BTCPAY_API_KEY=YourGreenfieldAPIKeyHere
ARKFILE_BTCPAY_WEBHOOK_SECRET=YourBTCPayWebhookSecretHere
ARKFILE_MIN_TOP_UP_USD=1.00
ARKFILE_MAX_TOP_UP_USD=500.00
```

## Test Plan

We require robust end-to-end and unit test coverage before allowing live financial traffic to process.

### Unit Tests

1. `btcpay_test.go`: Uses a local mock server mimicking the Greenfield API to assert that correct JSON payloads are generated and the returned `checkout_url` is parsed cleanly.
2. `webhooks_test.go`: Feeds mock payloads to the signature verification function, testing valid signatures, corrupted signatures, and tampered payloads.

### Integration and E2E Tests (`scripts/testing/e2e-test.sh`)

We add `phase_13_payments` to the testing harness (only when `ARKFILE_PAYMENTS_ENABLED=true`):
1. Spawn mock payment gateways inside the test server environment.
2. Create a test invoice via `POST /api/billing/invoice` and assert that a `pending` local record is written.
3. Emit a simulated, signed webhook payload to `/api/webhooks/btcpay` indicating the invoice was settled.
4. Assert that the local invoice transitions to `paid`, the user's microcent balance increases correspondingly, and exactly one `payment` type transaction is added to `credit_transactions`.
5. Submit a duplicate webhook payload and assert that the database UNIQUE constraint correctly triggers a rollback, preventing duplicate balance credits.

### Playwright Tests (`scripts/testing/e2e-playwright.ts`)

1. Open the Billing Panel and click the "Top Up Balance" button.
2. Enter an amount, click submit, and verify that the BTCPay iframe loads within the modal.

## Honest Trade-offs

1. Manual Refund Processing: We deliberately do not implement an automated refund/pull API. Refunds are processed manually by administrators using the `arkfile-admin billing gift` tool with negative values. This design choice minimizes complex financial attack vectors on our API backend.
2. Complete PII Scrubbing on BTCPay: Since we do not send user emails or real names to BTCPay Server's servers to safeguard privacy, BTCPay Server cannot automatically send payment receipt emails to customers unless configured on the BTCPay Server side directly. Users must rely on the transaction records shown in their local Arkfile Billing panel, which acts as their invoice proof.
3. Webhook Dependency: By relying on a webhook-driven push model as our primary settlement path, we assume that webhook delivery is reliable. If a webhook is missed, the user's balance will not be credited until the administrator manually runs the `payments sync-invoice` command or the automated reconciliation script runs.
