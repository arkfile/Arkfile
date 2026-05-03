package main

// Billing subcommand group for arkfile-admin. The top-level command
// `arkfile-admin billing` dispatches to one of:
//
//   show              - GET /api/admin/billing/price + GET /api/admin/billing/sweep-summary
//   show --user NAME  - GET /api/admin/credits/:username
//   set-price PRICE   - POST /api/admin/billing/set-price
//   gift              - POST /api/admin/billing/gift
//   list-overdrawn    - GET /api/admin/billing/overdrawn
//   tick-now [--sweep] - POST /api/admin/dev-test/billing/tick-now (dev/test only)
//
// Each subcommand local-validates inputs (parseable dollars-and-cents,
// non-empty reason, etc.) before sending. All output is human-readable by
// default; pass --json for machine-readable JSON.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// handleBillingCommand is the top-level dispatcher for `arkfile-admin billing ...`.
// It peels off the subcommand and forwards the remainder.
func handleBillingCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	if len(args) == 0 {
		printBillingUsage()
		return fmt.Errorf("billing requires a subcommand")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "show":
		return handleBillingShowCommand(client, config, rest)
	case "set-price":
		return handleBillingSetPriceCommand(client, config, rest)
	case "gift":
		return handleBillingGiftCommand(client, config, rest)
	case "list-overdrawn":
		return handleBillingListOverdrawnCommand(client, config, rest)
	case "tick-now":
		return handleBillingTickNowCommand(client, config, rest)
	case "help", "--help", "-h":
		printBillingUsage()
		return nil
	default:
		printBillingUsage()
		return fmt.Errorf("unknown billing subcommand: %s", sub)
	}
}

func printBillingUsage() {
	fmt.Print(`Usage: arkfile-admin billing SUBCOMMAND [FLAGS]

Storage credits / usage metering admin operations.

SUBCOMMANDS:
    show                     Show current price and last 30 days of sweep activity.
    show --user NAME         Show one user's balance, current usage, and runway.
    set-price USD-per-TB-mo  Update the customer price (e.g. "19.99").
    gift                     Add positive credit to a user's balance.
    list-overdrawn           List users whose balance is below zero.
    tick-now [--sweep]       Force an immediate tick (dev/test only).

GLOBAL FLAGS:
    --json                   Emit machine-readable JSON instead of formatted text.
    --help                   Show subcommand-specific help.

EXAMPLES:
    arkfile-admin billing show
    arkfile-admin billing show --user alice
    arkfile-admin billing set-price 19.99
    arkfile-admin billing gift --user alice --amount 5.00 --reason "beta tester"
    arkfile-admin billing list-overdrawn --json
    arkfile-admin billing tick-now --sweep
`)
}

// handleBillingShowCommand calls /api/admin/billing/price and (when no
// --user flag is provided) /api/admin/billing/sweep-summary; with --user it
// instead calls /api/admin/credits/:username.
func handleBillingShowCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("billing show", flag.ExitOnError)
	user := fs.String("user", "", "Show credits for one specific user (optional)")
	days := fs.Int("days", 30, "Number of days to include in sweep summary (1-365)")
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin billing show [--user NAME] [--days N] [--json]

Without --user: prints the current customer price + derived rate, plus a
per-day summary of recent storage-usage sweep activity.

With --user: prints one user's balance, current usage block, runway, and
recent transactions.

FLAGS:
    --user NAME    Show details for one user instead of the global price summary.
    --days N       Days to include in the sweep summary (default 30, max 365).
    --json         Emit machine-readable JSON.
    --help         Show this help message.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *days < 1 || *days > 365 {
		return fmt.Errorf("--days must be between 1 and 365")
	}

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	if *user != "" {
		return showOneUser(client, session.AccessToken, *user, *jsonOut)
	}

	// Global view: price + sweep summary.
	priceResp, err := client.makeRequest("GET", "/api/admin/billing/price", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to fetch billing price: %w", err)
	}
	sweepResp, err := client.makeRequest("GET", fmt.Sprintf("/api/admin/billing/sweep-summary?days=%d", *days), nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to fetch sweep summary: %w", err)
	}

	if *jsonOut {
		out := map[string]interface{}{
			"price":         priceResp.Data,
			"sweep_summary": sweepResp.Data,
		}
		return printJSON(out)
	}

	printPriceSummary(priceResp.Data)
	fmt.Println()
	printSweepSummary(sweepResp.Data, *days)
	return nil
}

func showOneUser(client *HTTPClient, token, username string, jsonOut bool) error {
	resp, err := client.makeRequest("GET", "/api/admin/credits/"+username, nil, token)
	if err != nil {
		return fmt.Errorf("failed to fetch user credits: %w", err)
	}
	if jsonOut {
		return printJSON(resp.Data)
	}
	printUserCredits(username, resp.Data)
	return nil
}

// handleBillingSetPriceCommand updates the customer price.
func handleBillingSetPriceCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("billing set-price", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin billing set-price USD-per-TB-per-month [--json]

Update the customer price. Accepts a dollars-and-cents string.

EXAMPLES:
    arkfile-admin billing set-price 10.00
    arkfile-admin billing set-price 19.99

FLAGS:
    --json    Emit machine-readable JSON.
    --help    Show this help message.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("set-price requires a price argument (e.g. \"19.99\")")
	}
	priceStr := strings.TrimSpace(fs.Arg(0))

	// Local pre-flight validation: positive parseable dollars-and-cents.
	if !looksLikeDollarsAndCents(priceStr) {
		return fmt.Errorf("invalid price %q (expected dollars-and-cents, e.g. \"19.99\")", priceStr)
	}

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"customer_price_usd_per_tb_per_month": priceStr,
	}
	resp, err := client.makeRequest("POST", "/api/admin/billing/set-price", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("set-price failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	prevRate := safeInt64(resp.Data, "previous_microcents_per_gib_per_hour")
	newRate := safeInt64(resp.Data, "microcents_per_gib_per_hour")
	prevPrice := safeString(resp.Data, "previous_customer_price_usd_per_tb_per_month")
	newPrice := safeString(resp.Data, "customer_price_usd_per_tb_per_month")
	rateHuman := safeString(resp.Data, "rate_human")

	fmt.Printf("Billing price updated.\n")
	fmt.Printf("  Previous: %s/TiB/month  (%d microcents/GiB/hour)\n", emptyOrValue(prevPrice, "-"), prevRate)
	fmt.Printf("  Current:  %s            (%d microcents/GiB/hour)\n", emptyOrValue(rateHuman, newPrice+"/TiB/month"), newRate)
	fmt.Printf("\nThe new rate will be observed on the next tick.\n")
	return nil
}

// handleBillingGiftCommand adds positive credit to a user's balance.
func handleBillingGiftCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("billing gift", flag.ExitOnError)
	user := fs.String("user", "", "Target username (required)")
	amount := fs.String("amount", "", "Amount in USD (e.g. \"5.00\") (required)")
	reason := fs.String("reason", "", "Reason for the gift (required)")
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin billing gift --user NAME --amount USD --reason "..." [--json]

Add positive credit to a user's balance. Records the gift as a typed
'gift' transaction in the audit log.

FLAGS:
    --user NAME      Target username (required).
    --amount USD     Amount in USD (e.g. "5.00") (required, must be positive).
    --reason TEXT    Reason for the gift (required, recorded in audit log).
    --json           Emit machine-readable JSON.
    --help           Show this help message.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	*user = strings.TrimSpace(*user)
	*amount = strings.TrimSpace(*amount)
	*reason = strings.TrimSpace(*reason)
	if *user == "" {
		return fmt.Errorf("--user is required")
	}
	if *amount == "" {
		return fmt.Errorf("--amount is required")
	}
	if *reason == "" {
		return fmt.Errorf("--reason is required")
	}
	if !looksLikeDollarsAndCents(*amount) {
		return fmt.Errorf("invalid --amount %q (expected dollars-and-cents, e.g. \"5.00\")", *amount)
	}

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"target_username": *user,
		"amount_usd":      *amount,
		"reason":          *reason,
	}
	resp, err := client.makeRequest("POST", "/api/admin/billing/gift", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("gift failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	updatedBalance := safeString(resp.Data, "formatted_updated_balance")
	if updatedBalance == "" {
		// fall back to int microcents if the formatter field isn't present
		updatedBalance = fmt.Sprintf("%d microcents", safeInt64(resp.Data, "updated_balance_usd_microcents"))
	}
	fmt.Printf("Gifted %s to %s.\n", *amount, *user)
	fmt.Printf("  Reason:        %s\n", *reason)
	fmt.Printf("  New balance:   %s\n", updatedBalance)
	if txMap, ok := resp.Data["transaction"].(map[string]interface{}); ok {
		fmt.Printf("  Transaction ID: %d\n", safeInt64(txMap, "id"))
	}
	return nil
}

// handleBillingListOverdrawnCommand lists every user with a negative balance.
func handleBillingListOverdrawnCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("billing list-overdrawn", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin billing list-overdrawn [--json]

List every user whose credit balance is below zero.

FLAGS:
    --json    Emit machine-readable JSON.
    --help    Show this help message.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("GET", "/api/admin/billing/overdrawn", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("list-overdrawn failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	count := int(safeFloat64(resp.Data, "users_currently_overdrawn"))
	fmt.Printf("Users currently overdrawn: %d\n\n", count)
	if count == 0 {
		return nil
	}
	users, _ := resp.Data["users"].([]interface{})
	if len(users) == 0 {
		return nil
	}
	fmt.Printf("%-30s  %-15s  %-25s\n", "USERNAME", "BALANCE", "LAST UPDATED")
	fmt.Printf("%-30s  %-15s  %-25s\n", strings.Repeat("-", 30), strings.Repeat("-", 15), strings.Repeat("-", 25))
	for _, u := range users {
		um, ok := u.(map[string]interface{})
		if !ok {
			continue
		}
		fmt.Printf("%-30s  %-15s  %-25s\n",
			safeString(um, "username"),
			safeString(um, "formatted_balance"),
			safeString(um, "updated_at"))
	}
	return nil
}

// handleBillingTickNowCommand forces an immediate meter tick. Dev/test only.
//
// The CLI checks ADMIN_DEV_TEST_API_ENABLED locally before sending so that
// when the env var is unset we print a friendly error rather than getting
// a server-side 404 from a route that simply does not exist in production.
func handleBillingTickNowCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("billing tick-now", flag.ExitOnError)
	sweep := fs.Bool("sweep", false, "Also run the daily settlement sweep immediately after ticking")
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin billing tick-now [--sweep] [--json]

Force an immediate meter tick. Dev/test only -- this endpoint exists only
when ADMIN_DEV_TEST_API_ENABLED=true on the server. Used by the e2e
billing test to advance the meter without waiting for the hourly cadence.

FLAGS:
    --sweep   Also run the daily settlement sweep right after ticking
              (drains the accumulator into user_credits and writes one
              'usage' transaction per user with nonzero accumulator).
    --json    Emit machine-readable JSON.
    --help    Show this help message.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Local pre-flight: dev-test API endpoint must be enabled both server-side
	// AND be acknowledged by the operator's local environment. We can't fully
	// check the server-side flag without an introspection endpoint, but we
	// can warn early if the operator's local env doesn't have it set, since
	// that strongly suggests the server doesn't either (they're typically
	// configured together in secrets.env).
	if v := strings.ToLower(os.Getenv("ADMIN_DEV_TEST_API_ENABLED")); v != "true" && v != "1" && v != "yes" {
		fmt.Fprintln(os.Stderr,
			"Warning: ADMIN_DEV_TEST_API_ENABLED is not set in your local environment.")
		fmt.Fprintln(os.Stderr,
			"         tick-now is a dev/test endpoint and is only registered when the")
		fmt.Fprintln(os.Stderr,
			"         server also has ADMIN_DEV_TEST_API_ENABLED=true. If you get a 404,")
		fmt.Fprintln(os.Stderr,
			"         the server has billing tick-now disabled (production-safe default).")
		fmt.Fprintln(os.Stderr, "")
	}

	session, err := requireBillingSession(config)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{"sweep": *sweep}
	resp, err := client.makeRequest("POST", "/api/admin/dev-test/billing/tick-now", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("tick-now failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	fmt.Printf("Tick completed at %s\n", safeString(resp.Data, "timestamp"))
	if safeBool(resp.Data, "swept") {
		fmt.Printf("Sweep also completed.\n")
	}
	return nil
}

// requireBillingSession loads the admin session and verifies it's not expired.
// Returns a friendly error otherwise. Used by every billing subcommand.
func requireBillingSession(config *AdminConfig) (*AdminSession, error) {
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("admin session expired, please login again")
	}
	return session, nil
}

// looksLikeDollarsAndCents is a friendly local pre-check. The server still
// validates rigorously via models.ParseCreditsFromUSD; this just catches
// obvious typos before they cost a round-trip.
//
// Accepts: "10", "10.0", "10.00", "10.0001", with optional leading "$" / "+".
// Rejects negatives (gift/set-price both require positive values).
func looksLikeDollarsAndCents(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimPrefix(s, "+")
	if s == "" || s == "." {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return false
	}
	if _, err := strconv.ParseUint(parts[0], 10, 64); err != nil {
		return false
	}
	if len(parts) == 2 {
		if len(parts[1]) > 4 || len(parts[1]) == 0 {
			return false
		}
		if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
			return false
		}
	}
	return true
}

// emptyOrValue returns fallback when v is empty, otherwise v. Used by the
// formatted output paths to render gracefully when the server omits a field.
func emptyOrValue(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// printJSON pretty-prints v to stdout.
func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printPriceSummary renders a `billing show` price block.
func printPriceSummary(d map[string]interface{}) {
	available := safeBool(d, "available")
	customerPrice := safeString(d, "customer_price_usd_per_tb_per_month")
	rate := safeInt64(d, "microcents_per_gib_per_hour")
	rateHuman := safeString(d, "rate_human")

	fmt.Println("Current price:")
	if !available {
		fmt.Println("  (rate not yet resolved -- billing may be disabled or pending startup seed)")
		return
	}
	fmt.Printf("  Customer price:  %s\n", emptyOrValue(rateHuman, customerPrice+"/TiB/month"))
	fmt.Printf("  Internal rate:   %d microcents/GiB/hour\n", rate)
	fmt.Printf("  Resolved at:     %s\n", safeString(d, "resolved_at"))
}

// printSweepSummary renders the per-day sweep activity table.
func printSweepSummary(d map[string]interface{}, days int) {
	negativeCount := int(safeFloat64(d, "users_currently_negative"))
	fmt.Printf("Sweep summary (last %d days):\n", days)
	fmt.Printf("  Users currently with negative balance: %d\n\n", negativeCount)

	perDay, _ := d["per_day"].([]interface{})
	if len(perDay) == 0 {
		fmt.Println("  No sweep activity in this window.")
		return
	}
	fmt.Printf("  %-12s  %-15s  %-15s\n", "DAY", "USERS SETTLED", "TOTAL DRAINED")
	fmt.Printf("  %-12s  %-15s  %-15s\n", strings.Repeat("-", 12), strings.Repeat("-", 15), strings.Repeat("-", 15))
	for _, row := range perDay {
		rm, ok := row.(map[string]interface{})
		if !ok {
			continue
		}
		fmt.Printf("  %-12s  %-15d  %-15s\n",
			safeString(rm, "day"),
			safeInt64(rm, "users_settled"),
			safeString(rm, "total_drained_usd"))
	}
}

// printUserCredits renders the per-user credits view (`billing show --user NAME`).
func printUserCredits(username string, d map[string]interface{}) {
	balance := safeString(d, "formatted_balance")
	if balance == "" {
		balance = fmt.Sprintf("%d microcents", safeInt64(d, "balance_usd_microcents"))
	}
	fmt.Printf("Credits for %s:\n", username)
	fmt.Printf("  Balance: %s\n", balance)

	if cu, ok := d["current_usage"].(map[string]interface{}); ok && cu != nil {
		fmt.Printf("\nCurrent usage:\n")
		fmt.Printf("  Total stored:    %d bytes\n", safeInt64(cu, "total_storage_bytes"))
		fmt.Printf("  Free baseline:   %d bytes\n", safeInt64(cu, "free_baseline_bytes"))
		fmt.Printf("  Billable:        %d bytes\n", safeInt64(cu, "billable_bytes"))
		if rh := safeString(cu, "rate_human"); rh != "" {
			fmt.Printf("  Rate:            %s\n", rh)
		}
		if cost := safeString(cu, "current_cost_per_month_usd_approx"); cost != "" {
			fmt.Printf("  Projected cost:  %s\n", cost)
		}
	}

	if cr, ok := d["credits_runway"].(map[string]interface{}); ok && cr != nil {
		fmt.Printf("\nRunway:\n")
		if note := safeString(cr, "note"); note != "" {
			fmt.Printf("  %s\n", note)
		} else {
			fmt.Printf("  Hours remaining:    %d\n", safeInt64(cr, "estimated_hours_remaining"))
			if endsAt := safeString(cr, "estimated_runs_out_at_approx"); endsAt != "" {
				fmt.Printf("  Estimated run-out:  %s\n", endsAt)
			}
		}
	}

	if txs, ok := d["transactions"].([]interface{}); ok && len(txs) > 0 {
		fmt.Printf("\nRecent transactions (latest %d):\n", min(len(txs), 10))
		for i, t := range txs {
			if i >= 10 {
				break
			}
			tm, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			amount := safeString(tm, "formatted_amount")
			if amount == "" {
				amount = fmt.Sprintf("%d microcents", safeInt64(tm, "amount_usd_microcents"))
			}
			balAfter := safeString(tm, "formatted_balance_after")
			if balAfter == "" {
				balAfter = fmt.Sprintf("%d", safeInt64(tm, "balance_after_usd_microcents"))
			}
			fmt.Printf("  %s  %-10s  %12s  -> %12s  %s\n",
				safeString(tm, "created_at"),
				safeString(tm, "transaction_type"),
				amount,
				balAfter,
				safeString(tm, "reason"))
		}
	}
}
