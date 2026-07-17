package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
    show [--json]                         Balance, usage, billing_mode from /api/credits
    top-up --amount USD [--open-browser] [--wait]
    invoice status --id INV [--json]

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
		return enc.Encode(resp.Data)
	}
	printClientBillingShow(resp.Data)
	return nil
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

func handleBillingTopUpCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("billing top-up", flag.ExitOnError)
	amount := fs.String("amount", "", "Top-up amount in USD")
	openBrowser := fs.Bool("open-browser", false, "Open checkout URL in browser")
	wait := fs.Bool("wait", false, "Poll until invoice is paid")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *amount == "" {
		return fmt.Errorf("--amount is required")
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
	fmt.Printf("Checkout URL: %s\n", checkoutURL)
	if *openBrowser && checkoutURL != "" {
		openBrowserURL(checkoutURL)
	}
	if *wait && invoiceID != "" {
		for i := 0; i < 60; i++ {
			time.Sleep(2 * time.Second)
			st, err := client.makeRequestWithSession("GET", "/api/billing/invoice/"+invoiceID, nil, session)
			if err != nil {
				continue
			}
			if stringField(st.Data, "status") == "paid" {
				fmt.Println("Payment confirmed.")
				return nil
			}
		}
		return fmt.Errorf("timed out waiting for payment")
	}
	return nil
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
	resp, err := client.makeRequestWithSession("GET", "/api/billing/invoice/"+*id, nil, session)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}
	inv := resp.Data
	fmt.Printf("Status: %s\n", stringField(inv, "status"))
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
