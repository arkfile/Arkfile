# Bitcart Setup for Bitcoin and Monero Top-Ups

This guide is for operators who want Arkfile users to buy storage credit with Bitcoin or Monero through a self-hosted [Bitcart](https://bitcart.ai) instance. Top-ups are off by default and nothing here is required to run Arkfile.

Throughout this guide, `pay.example.com` stands for the domain you give Bitcart and `files.example.com` stands for your Arkfile domain. Replace both with your own. The Bitcart steps below were checked against Bitcart 0.11. Menu names and defaults can change between Bitcart releases, so confirm them in the [Bitcart documentation](https://docs.bitcart.ai) for the version you install.

## How the pieces fit together

When a user asks for a top-up, Arkfile creates an invoice on your Bitcart store and sends the user to Bitcart's checkout page in a new tab. Arkfile sends Bitcart only the USD price, the store id, a notification URL, and a random Arkfile invoice id. It never sends a username or email. Bitcart watches the blockchain and, when the invoice is paid and confirmed, marks it `complete` and notifies Arkfile. Arkfile does not trust that notification. It fetches the invoice back from the Bitcart API, checks that every field matches what it created, and only then credits the user, exactly once. A background job repeats the lookup every minute, so a lost notification only delays the credit.

## 1. Install Bitcart on its own host

Run Bitcart on a separate server from Arkfile. Bitcart can link a payment to an Arkfile invoice id, and only the Arkfile server can link that invoice id to a username. Keeping them on different hosts means no single machine holds both halves. It also keeps Bitcart's Docker stack, wallets, and database out of the Arkfile host, whose deployment scripts do not manage them.

Follow Bitcart's Docker installation guide on the new host and point `pay.example.com` at it. Install only the coins you want to accept (for example BTC and XMR). Two settings matter at install time:

Start on a test network. For Bitcoin, set `BTC_NETWORK=testnet` before running the installer so you can test with coins that have no value. Check the Bitcart documentation for the equivalent setting for each other coin you enable. Note that Bitcart still uses live exchange rates on test networks.

Enable the standalone checkout page by adding `checkout` to `BITCART_ADDITIONAL_COMPONENTS`. With it, invoice pages are served at `https://pay.example.com/i/<invoice id>`. Without it, in Bitcart's default one-domain layout, they are served under the admin panel at `https://pay.example.com/admin/i/<invoice id>`. Either works with Arkfile, as long as step 6 matches.

## 2. Secure the Bitcart admin account and add wallets

Create the Bitcart admin account, then turn on two-factor authentication for it right away. This account controls the store settings that decide when Arkfile credits a payment.

Add your wallets as watch-only wallets: an extended public key (xpub, ypub or zpub) for Bitcoin, and for Monero the view-only wallet details that the Bitcart documentation lists for your version. A watch-only wallet lets Bitcart generate addresses and detect payments, but a compromise of the Bitcart host cannot spend the funds. Keep the spending keys offline.

If you set a "transaction speed" on a wallet, keep it at 1 or higher, or leave it unset. A wallet value overrides the store value from step 3.

## 3. Create the store and set its checkout settings

Create a store, set its default currency to USD, and attach the wallets. Arkfile prices every invoice in USD and rejects any invoice whose currency is not USD. Then open the store's checkout settings and set the following:

| Setting | Value | Why |
|---------|-------|-----|
| Transaction speed | 1 or more | The Bitcart default of 0 marks an invoice complete on an unconfirmed payment, which can be reversed. |
| Underpaid percentage | 0 | Any other value lets Bitcart mark a short payment complete, and Arkfile would credit the full invoice amount. |
| Require email | Off | Arkfile does not collect email addresses for top-ups. Leaving this on asks payers for one on the checkout page. |
| Allow anonymous invoice creation | Off | When on, anyone who learns the store id can create invoices on your store, and Bitcart does not check the API token on invoice creation. |
| Expiration | Your choice | Default is 15 minutes. A longer window, such as 60 minutes, helps users whose wallet is slow to broadcast. |

Arkfile enforces the confirmation rule on its own as well. It refuses to create an invoice when Bitcart offers an on-chain payment method that requires zero confirmations, and it refuses to credit a `complete` invoice unless the method that was paid required at least one confirmation or was Lightning. Lightning payments settle on their own network and Bitcart always completes them at zero confirmations.

## 4. Create the API token

Sign in to Bitcart as the store owner and create an API token with only the `invoice_management` permission. The token must belong to the account that owns the store. Do not grant wallet, store or server management permissions; Arkfile does not need them. Note the store id shown in the store's settings.

## 5. Check Bitcart from the Arkfile host

Before changing anything in Arkfile, confirm from the Arkfile server that Bitcart is reachable and behaves as expected. Run the following with your own values:

```bash
TOKEN='<api token>'
STORE='<store id>'

# Create a test invoice. This should return JSON with an "id".
curl -sS -X POST https://pay.example.com/api/invoices \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"price":"0.50","currency":"USD","store_id":"'"$STORE"'","order_id":"inv_manualcheck"}'

# The same request without the token should be refused with 403,
# which confirms anonymous invoice creation is off.
curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://pay.example.com/api/invoices \
  -H "Content-Type: application/json" \
  -d '{"price":"0.50","currency":"USD","store_id":"'"$STORE"'","order_id":"inv_manualcheck2"}'

# Read the invoice back. Check that "payments" lists your coins and that
# on-chain entries show "required_confirmations" of 1 or more.
curl -sS https://pay.example.com/api/invoices/<id from the first request>
```

If the first request returns 403 as well, the token is wrong, belongs to another user, or lacks `invoice_management`. If `payments` is empty, the store has no working wallet attached.

## 6. Find the checkout page prefix

Open `https://pay.example.com/i/<id>` in a browser. If it shows the test invoice, your checkout URL is `https://pay.example.com`. If it does not, open `https://pay.example.com/admin/i/<id>`; if that works, your checkout URL is `https://pay.example.com/admin`. Arkfile appends `/i/<invoice id>` to whatever you configure.

## 7. Configure Arkfile

Add these lines to `/opt/arkfile/etc/secrets.env` on the Arkfile server:

```bash
ARKFILE_PAYMENTS_ENABLED=true
ARKFILE_MIN_TOP_UP_USD=0.50
ARKFILE_MAX_TOP_UP_USD=1000.00
ARKFILE_BITCART_API_URL=https://pay.example.com/api
ARKFILE_BITCART_CHECKOUT_URL=https://pay.example.com
ARKFILE_BITCART_API_TOKEN=<api token>
ARKFILE_BITCART_STORE_ID=<store id>
```

Use the checkout URL you found in step 6. Both URLs must use HTTPS unless they point at loopback. An invalid or missing value stops the Arkfile service from starting, so check them carefully. The token stays in `secrets.env` and is never returned by any Arkfile endpoint.

Bitcart must be able to reach `https://files.example.com/api/webhooks/bitcart`. Arkfile sends that address with each invoice, so you do not configure it in Bitcart. If a firewall sits in front of Arkfile, allow inbound HTTPS from the Bitcart host.

## 8. Apply the change and run the provider check

Apply the configuration with the update script that matches your deployment: `sudo bash scripts/prod-update.sh` on a production server, `sudo bash scripts/test-update.sh` on a test server, or `sudo bash scripts/local-deploy.sh` for a local instance. These scripts keep your data, keys and `secrets.env`. The first start after upgrading migrates the `payment_invoices` table in place; existing invoices are kept.

On startup, Arkfile reads the store settings from Bitcart once and logs a warning or error for anything that needs attention. To run the same check on demand, sign in with `arkfile-admin login` on the Arkfile server itself (admin commands are accepted only from the local machine) and run:

```bash
arkfile-admin payments check
```

It checks that the token is accepted and that the store's transaction speed, underpaid percentage, email prompt and anonymous invoice creation settings match step 3. It exits with an error if a required setting is wrong. Some Bitcart versions do not report every setting; those show as warnings, so confirm them by hand in the Bitcart admin panel. Run the check again after you change Bitcart settings or upgrade Bitcart.

## 9. Test a top-up

Sign in to Arkfile as a regular user and buy the minimum top-up from the billing panel. Pay it from a test-network wallet. The invoice should move from pending to confirming when Bitcart sees the payment, then to paid once it confirms, and the balance should increase by the invoice amount. Repeat from the command line with `arkfile-client billing top-up --amount 0.50 --wait`.

Also let one invoice expire without paying it, and confirm it shows as expired with no credit. In the Bitcart logs, confirm that the notification to `/api/webhooks/bitcart` returned 200. As an admin, `arkfile-admin payments list` shows the stored state of every invoice.

## 10. Move to mainnet

When the test-network runs look right, reinstall or reconfigure Bitcart for mainnet, attach mainnet watch-only wallets to the store, re-apply the step 3 settings, create a new token if needed, update `secrets.env`, run the update script, and run `arkfile-admin payments check` again. Make one small real payment before announcing top-ups to users.

## Operating notes

Each user can hold at most five unpaid invoices at a time, because every invoice allocates fresh addresses in your wallets. A user at the limit is asked to pay or wait for an open invoice to expire. Paid, expired and failed invoices do not count.

Arkfile credits the USD amount of the invoice, not the amount actually sent. An overpayment is not credited beyond the invoice amount; refund the excess from your wallet if you choose to. An underpayment leaves the invoice unpaid until it expires, as long as the underpaid percentage is 0.

Refunding a payment in Bitcart does not remove credit that Arkfile already applied. If you refund a paid invoice, reduce the user's balance yourself through the admin credits endpoint (`POST /api/admin/credits/<username>`, see `docs/api.md`); `arkfile-admin` currently has no command that subtracts credit.

If you mark an invoice complete by hand in Bitcart, Arkfile credits it only when Bitcart recorded a payment on a method that required a confirmation. Arkfile refuses a manual completion with no recorded payment. To credit a payment Bitcart did not record, such as a late payment to an expired invoice's address, verify it on the blockchain and use `arkfile-admin billing gift --user <name> --amount <usd> --reason "<coin> txid=<id>"`.

The Arkfile reconciler runs every minute. It checks open invoices with Bitcart, least recently checked first. It also re-checks expired and failed invoices for 72 hours after creation, at most every 30 minutes, so a completion Bitcart records late is still credited. An open invoice that Bitcart can no longer report, for example after Bitcart was reinstalled, is closed locally 48 hours after creation. An invoice that never reached Bitcart is marked failed after 15 minutes. `arkfile-admin payments sync-invoice <invoice id>` forces a lookup of one invoice, and `arkfile-admin payments reconcile` credits any paid invoice missing its ledger entry.

Bitcart sends each notification once and does not sign it. That is safe because Arkfile treats a notification only as a prompt to look the invoice up. A forged notification can trigger at most a throttled lookup of an invoice that already exists.

The checkout page is served by Bitcart, so Bitcart sees the IP address and browser of whoever opens it, and the payment itself is visible on its blockchain. Users who want to keep that separate from their Arkfile session can open the payment page over Tor. Bitcart keeps its own records of invoices and payments; Arkfile stores only the invoice id, the owning user, the USD amount, the status and the Bitcart invoice id.

Keep Bitcart patched, back up its database and wallet configuration on their own schedule (Arkfile backups do not include them), and treat the Bitcart admin account and API token as sensitive. Someone with Bitcart admin access can change the confirmation settings or mark invoices complete. Arkfile's own checks limit the damage, but they cannot stop a Bitcart admin from crediting a payment that was recorded on a confirming method.
