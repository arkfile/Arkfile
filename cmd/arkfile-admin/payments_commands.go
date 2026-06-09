package main

import (
	"flag"
	"fmt"
	"strings"
)

// handlePaymentsCommand is the top-level dispatcher for `arkfile-admin payments ...`.
func handlePaymentsCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	if len(args) == 0 {
		printPaymentsUsage()
		return fmt.Errorf("payments requires a subcommand")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "show":
		return handlePaymentsShowCommand(client, config, rest)
	case "list":
		return handlePaymentsListCommand(client, config, rest)
	case "sync-invoice":
		return handlePaymentsSyncInvoiceCommand(client, config, rest)
	case "help", "--help", "-h":
		printPaymentsUsage()
		return nil
	default:
		printPaymentsUsage()
		return fmt.Errorf("unknown payments subcommand: %s", sub)
	}
}

func printPaymentsUsage() {
	fmt.Print(`Usage: arkfile-admin payments SUBCOMMAND [FLAGS]

BTCPay Server / invoice payments admin operations.

SUBCOMMANDS:
    show <invoice_id>                     Show details for a specific payment invoice.
    list [--user NAME] [--status STATUS]  List payment invoices with optional filters.
    sync-invoice <invoice_id>             Sync local invoice state with BTCPay Server.

GLOBAL FLAGS:
    --json                                Emit machine-readable JSON instead of formatted text.
    --help                                Show subcommand-specific help.

EXAMPLES:
    arkfile-admin payments show inv_f359120ac9
    arkfile-admin payments list --status pending
    arkfile-admin payments sync-invoice inv_f359120ac9
`)
}

func handlePaymentsShowCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("payments show", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin payments show <invoice_id> [--json]

Show detailed database information for a specific payment invoice.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("invoice_id argument is required")
	}
	invoiceID := fs.Arg(0)

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("GET", "/api/admin/payments/invoice/"+invoiceID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to fetch payment invoice: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	invoice := resp.Data
	fmt.Printf("Payment Invoice Details:\n")
	fmt.Printf("  Invoice ID:        %s\n", safeString(invoice, "invoice_id"))
	fmt.Printf("  Username:          %s\n", safeString(invoice, "username"))
	fmt.Printf("  Amount Microcents: %d\n", safeInt64(invoice, "amount_usd_microcents"))
	fmt.Printf("  Status:            %s\n", safeString(invoice, "status"))
	fmt.Printf("  Provider:          %s\n", safeString(invoice, "provider"))
	fmt.Printf("  Provider ID:       %s\n", safeString(invoice, "provider_invoice_id"))
	fmt.Printf("  Created At:        %s\n", safeString(invoice, "created_at"))
	fmt.Printf("  Updated At:        %s\n", safeString(invoice, "updated_at"))
	return nil
}

func handlePaymentsListCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("payments list", flag.ExitOnError)
	user := fs.String("user", "", "Filter by username")
	status := fs.String("status", "", "Filter by status (pending, paid, expired, failed)")
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin payments list [--user NAME] [--status STATUS] [--json]

List payment invoices recorded in the system.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	url := "/api/admin/payments/invoices"
	var params []string
	if *user != "" {
		params = append(params, "user="+*user)
	}
	if *status != "" {
		params = append(params, "status="+*status)
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	resp, err := client.makeRequest("GET", url, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to list payment invoices: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	invoices, _ := resp.Data["data"].([]interface{})
	fmt.Printf("Payment Invoices Count: %d\n\n", len(invoices))
	if len(invoices) == 0 {
		return nil
	}

	fmt.Printf("%-20s  %-20s  %-15s  %-10s  %-25s\n", "INVOICE ID", "USERNAME", "AMOUNT (MICRO)", "STATUS", "CREATED AT")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	for _, inv := range invoices {
		im, ok := inv.(map[string]interface{})
		if !ok {
			continue
		}
		fmt.Printf("%-20s  %-20s  %-15d  %-10s  %-25s\n",
			safeString(im, "invoice_id"),
			safeString(im, "username"),
			safeInt64(im, "amount_usd_microcents"),
			safeString(im, "status"),
			safeString(im, "created_at"),
		)
	}
	return nil
}

func handlePaymentsSyncInvoiceCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("payments sync-invoice", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin payments sync-invoice <invoice_id> [--json]

Query BTCPay Server to synchronize the state of a pending invoice.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("invoice_id argument is required")
	}
	invoiceID := fs.Arg(0)

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("POST", "/api/admin/payments/invoice/"+invoiceID+"/sync", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	msg := resp.Message
	if msg == "" {
		msg = safeString(resp.Data, "message")
	}
	if msg == "" {
		msg = "Synchronized successfully"
	}

	invoice, _ := resp.Data["data"].(map[string]interface{})
	if invoice == nil {
		invoice = resp.Data
	}

	fmt.Printf("%s\n", msg)
	fmt.Printf("Current Local Invoice State:\n")
	fmt.Printf("  Invoice ID: %s\n", safeString(invoice, "invoice_id"))
	fmt.Printf("  Status:     %s\n", safeString(invoice, "status"))
	return nil
}
