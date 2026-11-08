package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/cli/format"
)

func handleBillingCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	if len(args) == 0 {
		printClientBillingUsage()
		return fmt.Errorf("billing requires a subcommand")
	}
	switch args[0] {
	case "show":
		return handleBillingShowCommand(client, config, args[1:])
	case "top-up":
		return handleBillingTopUpCommand(client, config, args[1:])
	case "invoice":
		if len(args) > 1 && args[1] == "status" {
			return handleBillingInvoiceStatusCommand(client, config, args[2:])
		}
		return fmt.Errorf("unknown billing subcommand: invoice (try: billing invoice status)")
	case "help", "--help", "-h":
		printClientBillingUsage()
		return nil
	default:
		printClientBillingUsage()
		return fmt.Errorf("unknown billing subcommand: %s", args[0])
	}
}

func printClientBillingUsage() {
	fmt.Print(`Usage: arkfile-client billing SUBCOMMAND [FLAGS]

SUBCOMMANDS:
    show [--json]                         Balance, usage, billing_mode from /api/credits;
                                          also prints optional PayNym/Monero OOB top-up info
    top-up --amount USD [--open-browser] [--wait] [--timeout 2h] [--poll-interval 15s]
                                          Create a Bitcoin/Monero payment invoice and print
                                          the payment page URL. --wait prints status changes
                                          (pending, confirming, paid) and exits 0 only when
                                          paid; expired or failed exits non-zero.
    invoice status --id INV [--json]      Show invoice status and, while open, the payment page

INVOICE STATUSES:
    pending      Waiting for payment
    confirming   Payment detected, waiting for network confirmation (not yet credited)
    paid         Payment confirmed, balance credited
    expired      Invoice expired before a payment was confirmed
    failed       Invoice failed or was refunded

`)
}

func handleBillingShowCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("billing show", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequestWithSession("GET", "/api/credits", nil, session)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		payload := map[string]interface{}{
			"credits": resp.Data,
		}
		if oob := fetchOobPaymentsPublic(client); oob != nil {
			payload["oob_payments"] = oob
		}
		return enc.Encode(payload)
	}
	printClientBillingShow(resp.Data)
	printClientOobPayments(fetchOobPaymentsPublic(client))
	return nil
}

func fetchOobPaymentsPublic(client *HTTPClient) map[string]interface{} {
	resp, err := client.makeRequest("GET", "/api/oob-payments", nil, "")
	if err != nil {
		return nil
	}
	if resp.Data == nil {
		return nil
	}
	configured, _ := resp.Data["configured"].(bool)
	if !configured {
		return nil
	}
	return resp.Data
}

func printClientOobPayments(data map[string]interface{}) {
	if data == nil {
		return
	}
	fmt.Printf("\nManual crypto top-up (out-of-band):\n")
	fmt.Printf("  Credit is applied manually after you contact the admin with your username and txid.\n")
	if paynym := stringField(data, "paynym"); paynym != "" {
		fmt.Printf("  PayNym:        %s\n", paynym)
	}
	if code := stringField(data, "paynym_payment_code"); code != "" {
		fmt.Printf("  Payment code:  %s\n", code)
	}
	if stringField(data, "paynym_payment_code") != "" || stringField(data, "paynym") != "" {
		fmt.Printf("  PayNym steps:  open a BIP47 channel (Sparrow/Ashigaru/etc.), pay, then message the admin with username + payment txid.\n")
	}
	if xmr := stringField(data, "monero_address"); xmr != "" {
		fmt.Printf("  Monero (XMR):  %s\n", xmr)
		fmt.Printf("  XMR steps:     send XMR, wait for confirmations, message the admin with username + txid.\n")
	}
	if contact := stringField(data, "admin_contact"); contact != "" {
		fmt.Printf("  Admin contact: %s\n", contact)
	}
}

func printClientBillingShow(data map[string]interface{}) {
	fmt.Printf("Balance: %s\n", stringField(data, "formatted_balance"))
	fmt.Printf("Billing mode: %s\n", stringField(data, "billing_mode"))

	if usage, ok := data["current_usage"].(map[string]interface{}); ok {
		fmt.Printf("\nCurrent storage and cost:\n")
		fmt.Printf("  Storage used:  %s\n", format.ClientBillingBytes(numberField(usage, "total_storage_bytes")))
		fmt.Printf("  Free baseline: %s\n", format.ClientBillingBytes(numberField(usage, "free_baseline_bytes")))
		fmt.Printf("  Billable:      %s\n", format.ClientBillingBytes(numberField(usage, "billable_bytes")))
		if limit := numberField(usage, "effective_storage_limit_bytes"); limit > 0 {
			fmt.Printf("  Upload cap:    %s\n", format.ClientBillingBytes(limit))
		}
		if rh := stringField(usage, "rate_human"); rh != "" {
			fmt.Printf("  Rate:          %s\n", rh)
		}
		if cost := stringField(usage, "current_cost_per_month_usd_approx"); cost != "" {
			fmt.Printf("  Projected cost: %s/month\n", cost)
		}
	}

	if cr, ok := data["credits_runway"].(map[string]interface{}); ok && cr != nil {
		billable := int64(0)
		if usage, ok := data["current_usage"].(map[string]interface{}); ok {
			billable = numberField(usage, "billable_bytes")
		}
		if note := stringField(cr, "note"); note != "" && billable == 0 {
			fmt.Printf("\n%s\n", note)
		} else if hours := numberField(cr, "estimated_hours_remaining"); hours > 0 && billable > 0 {
			fmt.Printf("\nEstimated runway: %d hours\n", hours)
			if endsAt := stringField(cr, "estimated_runs_out_at_approx"); endsAt != "" {
				fmt.Printf("  Estimated run-out: %s\n", endsAt)
			}
		} else if note := stringField(cr, "note"); note != "" {
			fmt.Printf("\nEstimated runway: %s\n", note)
		}
	}

	if txs, ok := data["transactions"].([]interface{}); ok && len(txs) > 0 {
		limit := len(txs)
		if limit > 10 {
			limit = 10
		}
		fmt.Printf("\nRecent transactions (latest %d):\n", limit)
		for i, t := range txs {
			if i >= 10 {
				break
			}
			tm, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			amount := stringField(tm, "formatted_amount")
			if amount == "" {
				amount = fmt.Sprintf("%d microcents", numberField(tm, "amount_usd_microcents"))
			}
			balAfter := stringField(tm, "formatted_balance_after")
			if balAfter == "" {
				balAfter = fmt.Sprintf("%d", numberField(tm, "balance_after_usd_microcents"))
			}
			fmt.Printf("  %s  %-10s  %12s  -> %12s  %s\n",
				stringField(tm, "created_at"),
				stringField(tm, "transaction_type"),
				amount,
				balAfter,
				stringField(tm, "reason"))
		}
	}
}

const (
	defaultInvoiceWaitTimeout  = 2 * time.Hour
	defaultInvoicePollInterval = 15 * time.Second
)

func handleBillingTopUpCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("billing top-up", flag.ExitOnError)
	amount := fs.String("amount", "", "Top-up amount in USD")
	openBrowser := fs.Bool("open-browser", false, "Open the payment page in a browser (https only)")
	wait := fs.Bool("wait", false, "Wait until the invoice is paid, expired, or failed")
	timeout := fs.Duration("timeout", defaultInvoiceWaitTimeout, "Maximum time to wait with --wait")
	pollInterval := fs.Duration("poll-interval", defaultInvoicePollInterval, "Status check interval with --wait")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *amount == "" {
		return fmt.Errorf("--amount is required")
	}
	if *pollInterval < time.Second {
		return fmt.Errorf("--poll-interval must be at least 1s")
	}
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	creditsResp, err := client.makeRequestWithSession("GET", "/api/credits", nil, session)
	if err != nil {
		return err
	}
	if stringField(creditsResp.Data, "billing_mode") == "subscribed" {
		return fmt.Errorf("top-ups are not available while you have an active subscription; use `arkfile-client subscription portal`")
	}
	resp, err := client.makeRequestWithSession("POST", "/api/billing/invoice", map[string]string{
		"amount_usd": *amount,
	}, session)
	if err != nil {
		return err
	}
	checkoutURL := stringField(resp.Data, "checkout_url")
	invoiceID := stringField(resp.Data, "invoice_id")
	fmt.Printf("Invoice: %s\n", invoiceID)
	fmt.Printf("Payment page: %s\n", checkoutURL)
	fmt.Printf("Open the payment page to pay with Bitcoin or Monero. Your balance is credited automatically once the payment is confirmed.\n")
	if *openBrowser && checkoutURL != "" {
		if err := checkBrowserCheckoutURL(checkoutURL); err != nil {
			fmt.Fprintf(os.Stderr, "Not opening browser: %v\n", err)
		} else {
			openBrowserURL(checkoutURL)
		}
	}
	if !*wait || invoiceID == "" {
		return nil
	}
	_, err = waitForInvoiceSettlement(client, session, invoiceID, invoiceWaitOptions{
		Timeout:  *timeout,
		Interval: *pollInterval,
		Out:      os.Stdout,
	})
	return err
}

type invoiceWaitOptions struct {
	Timeout  time.Duration
	Interval time.Duration
	Out      io.Writer
	Sleep    func(time.Duration)
	Now      func() time.Time
}

// invoiceStatusDescription is the user-facing explanation of a local invoice status.
func invoiceStatusDescription(status string) string {
	switch status {
	case "creating":
		return "Creating invoice"
	case "pending":
		return "Waiting for payment"
	case "confirming":
		return "Payment detected, waiting for network confirmation (not yet credited)"
	case "paid":
		return "Payment confirmed, balance credited"
	case "expired":
		return "Invoice expired before a payment was confirmed, no balance was credited"
	case "failed":
		return "Invoice failed or was refunded, no balance was credited"
	default:
		return status
	}
}

// waitForInvoiceSettlement polls the invoice until it reaches paid, expired, or
// failed. Prints each status change. Returns nil only when paid. Transient
// network and server errors are retried; an ended session or unknown invoice stops.
func waitForInvoiceSettlement(client *HTTPClient, session *AuthSession, invoiceID string, opts invoiceWaitOptions) (string, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultInvoiceWaitTimeout
	}
	if opts.Interval <= 0 {
		opts.Interval = defaultInvoicePollInterval
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Sleep == nil {
		opts.Sleep = time.Sleep
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	deadline := opts.Now().Add(opts.Timeout)
	lastStatus := ""
	for {
		resp, err := client.makeRequestWithSession("GET", "/api/billing/invoice/"+url.PathEscape(invoiceID), nil, session)
		switch {
		case err == nil:
			status := stringField(resp.Data, "status")
			if status != lastStatus {
				lastStatus = status
				fmt.Fprintf(opts.Out, "Status: %s -- %s\n", status, invoiceStatusDescription(status))
			}
			switch status {
			case "paid":
				return status, nil
			case "expired", "failed":
				return status, fmt.Errorf("invoice %s %s: no balance was credited", invoiceID, status)
			}
		case errors.Is(err, errAuthExpired):
			return lastStatus, fmt.Errorf("stopped waiting for invoice %s: %w", invoiceID, err)
		case strings.Contains(err.Error(), "HTTP 404"):
			return lastStatus, fmt.Errorf("invoice %s not found", invoiceID)
		default:
			logVerbose("Invoice status check failed, retrying: %v", err)
		}
		if !opts.Now().Before(deadline) {
			return lastStatus, fmt.Errorf("timed out after %s waiting for invoice %s (last status: %s); your balance is credited automatically if the payment confirms later. Check with: arkfile-client billing invoice status --id %s",
				opts.Timeout, invoiceID, lastStatus, invoiceID)
		}
		opts.Sleep(opts.Interval)
	}
}

// checkBrowserCheckoutURL permits https, and http only on loopback (local development).
func checkBrowserCheckoutURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid payment page URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return fmt.Errorf("payment page URL must use https")
}

func handleBillingInvoiceStatusCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("billing invoice status", flag.ExitOnError)
	id := fs.String("id", "", "Invoice ID")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequestWithSession("GET", "/api/billing/invoice/"+url.PathEscape(*id), nil, session)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}
	inv := resp.Data
	status := stringField(inv, "status")
	fmt.Printf("Invoice: %s\n", stringField(inv, "invoice_id"))
	fmt.Printf("Status:  %s -- %s\n", status, invoiceStatusDescription(status))
	if micro := numberField(inv, "amount_usd_microcents"); micro > 0 {
		fmt.Printf("Amount:  $%d.%02d USD\n", micro/100_000_000, (micro%100_000_000)/1_000_000)
	}
	if checkout := stringField(inv, "checkout_url"); checkout != "" {
		fmt.Printf("Payment page: %s\n", checkout)
	}
	return nil
}

func stringField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func numberField(m map[string]interface{}, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	default:
		return 0
	}
}

func formatClientBytes(n int64) string {
	return format.ClientBillingBytes(n)
}

func openBrowserURL(url string) {
	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("xdg-open", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		fmt.Println(url)
	}
}
