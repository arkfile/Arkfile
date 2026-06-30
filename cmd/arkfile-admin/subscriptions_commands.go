package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"strings"
)

func handleSubscriptionsCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	if len(args) == 0 {
		printSubscriptionsUsage()
		return fmt.Errorf("subscriptions requires a subcommand")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list-plans":
		return handleSubscriptionsListPlansCommand(client, config, rest)
	case "set-plan":
		return handleSubscriptionsSetPlanCommand(client, config, rest)
	case "show":
		return handleSubscriptionsShowCommand(client, config, rest)
	case "grant-gift-subscription":
		return handleSubscriptionsGrantGiftCommand(client, config, rest)
	case "cancel-gift-subscription":
		return handleSubscriptionsCancelGiftCommand(client, config, rest)
	case "sync":
		return handleSubscriptionsSyncCommand(client, config, rest)
	case "reconcile":
		return handleSubscriptionsReconcileCommand(client, config, rest)
	case "help", "--help", "-h":
		printSubscriptionsUsage()
		return nil
	default:
		printSubscriptionsUsage()
		return fmt.Errorf("unknown subscriptions subcommand: %s", sub)
	}
}

func printSubscriptionsUsage() {
	fmt.Print(`Usage: arkfile-admin subscriptions SUBCOMMAND [FLAGS]

Subscription plan catalog and entitlement admin operations.

SUBCOMMANDS:
    list-plans [--json]                              List subscription plans
    set-plan --plan-id ID --name NAME --price USD --storage LIMIT [--active]
    show --user USER [--json]                        Show user subscription summary
    grant-gift-subscription --user USER --plan-id ID [--days N] [--note NOTE]
    cancel-gift-subscription --user USER [--immediate]
    sync --user USER                                 Poll bridge for paid subscription
    reconcile [--json]                               Bulk sync bridge entitlements + expire gifts

GLOBAL FLAGS:
    --json                                           Machine-readable JSON output
`)
}

func handleSubscriptionsListPlansCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("subscriptions list-plans", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequest("GET", "/api/admin/subscriptions/plans", nil, session.AccessToken)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp.Data)
	}
	plans, _ := resp.Data["plans"].([]interface{})
	for _, p := range plans {
		m, _ := p.(map[string]interface{})
		fmt.Printf("%s  %s  $%.2f  %s  active=%v public=%v\n",
			safeString(m, "plan_id"), safeString(m, "name"),
			float64(safeInt64(m, "price_usd_cents"))/100.0,
			formatBytes(safeInt64(m, "storage_limit_bytes")),
			safeBool(m, "is_active"), safeBool(m, "is_public"))
	}
	return nil
}

func handleSubscriptionsSetPlanCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("subscriptions set-plan", flag.ExitOnError)
	planID := fs.String("plan-id", "", "Plan ID")
	name := fs.String("name", "", "Display name")
	price := fs.String("price", "", "Price in USD (e.g. 5.00)")
	storage := fs.String("storage", "", "Storage limit (e.g. 250GB)")
	active := fs.Bool("active", true, "Plan is active")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planID == "" || *name == "" || *price == "" || *storage == "" {
		return fmt.Errorf("--plan-id, --name, --price, and --storage are required")
	}
	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"plan_id":        *planID,
		"name":           *name,
		"price_usd":      *price,
		"storage_limit":  *storage,
		"is_active":      *active,
		"is_public":      true,
	}
	resp, err := client.makeRequest("POST", "/api/admin/subscriptions/plans", payload, session.AccessToken)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp.Data)
	}
	fmt.Printf("Saved plan %s\n", *planID)
	return nil
}

func handleSubscriptionsShowCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("subscriptions show", flag.ExitOnError)
	user := fs.String("user", "", "Username")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return fmt.Errorf("--user is required")
	}
	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequest("GET", "/api/admin/subscriptions/users/"+*user, nil, session.AccessToken)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp.Data)
	}
	data := resp.Data
	fmt.Printf("User: %s\n", safeString(data, "username"))
	fmt.Printf("  Baseline storage (admin):     %s\n", formatBytes(safeInt64(data, "baseline_storage_bytes")))
	fmt.Printf("  Effective upload cap:         %s\n", formatBytes(safeInt64(data, "effective_storage_limit_bytes")))
	fmt.Printf("  Billing mode:                 %s\n", safeString(data, "billing_mode"))
	if sub, ok := data["subscription"].(map[string]interface{}); ok && sub != nil {
		fmt.Printf("  Entitlement:                  %s (%s via %s)\n",
			safeString(sub, "status"), safeString(sub, "entitlement_ref"), safeString(sub, "source"))
		fmt.Printf("  Plan:                         %s\n", safeString(sub, "plan_name"))
	}
	return nil
}

func handleSubscriptionsGrantGiftCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("subscriptions grant-gift-subscription", flag.ExitOnError)
	user := fs.String("user", "", "Username")
	planID := fs.String("plan-id", "", "Plan ID")
	days := fs.Int("days", 0, "Gift duration in days (default from server)")
	note := fs.String("note", "", "Operator note")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" || *planID == "" {
		return fmt.Errorf("--user and --plan-id are required")
	}
	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{"plan_id": *planID, "note": *note}
	if *days > 0 {
		payload["days"] = *days
	}
	resp, err := client.makeRequest("POST", "/api/admin/subscriptions/users/"+*user+"/grant-gift-subscription", payload, session.AccessToken)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp.Data)
	}
	fmt.Printf("Gift subscription granted for %s\n", *user)
	return nil
}

func handleSubscriptionsCancelGiftCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("subscriptions cancel-gift-subscription", flag.ExitOnError)
	user := fs.String("user", "", "Username")
	immediate := fs.Bool("immediate", false, "End gift immediately")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return fmt.Errorf("--user is required")
	}
	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}
	path := "/api/admin/subscriptions/users/" + *user + "/cancel-gift-subscription"
	if *immediate {
		path += "?immediate=true"
	}
	_, err = client.makeRequest("POST", path, nil, session.AccessToken)
	if err != nil {
		return err
	}
	fmt.Printf("Gift subscription canceled for %s\n", *user)
	return nil
}

func handleSubscriptionsSyncCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("subscriptions sync", flag.ExitOnError)
	user := fs.String("user", "", "Username")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return fmt.Errorf("--user is required")
	}
	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequest("POST", "/api/admin/subscriptions/users/"+*user+"/sync", nil, session.AccessToken)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp.Data)
	}
	fmt.Printf("Synced subscription for %s\n", *user)
	return nil
}

func handleSubscriptionsReconcileCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("subscriptions reconcile", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequest("POST", "/api/admin/subscriptions/reconcile", nil, session.AccessToken)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp.Data)
	}
	fmt.Printf("Reconcile complete: %+v\n", resp.Data)
	return nil
}

func safeBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t == "true" || t == "1"
	default:
		return false
	}
}

func formatBytes(n int64) string {
	if n >= 1<<40 {
		return fmt.Sprintf("%.1f TB", float64(n)/(1<<40))
	}
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	}
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d B", n)
}

func safeInt64FromAny(v interface{}) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	default:
		return 0
	}
}
