package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func handleSubscriptionCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	if len(args) == 0 {
		printClientSubscriptionUsage()
		return fmt.Errorf("subscription requires a subcommand")
	}
	switch args[0] {
	case "status":
		return handleSubscriptionStatusCommand(client, config, args[1:])
	case "plans":
		return handleSubscriptionPlansCommand(client, config, args[1:])
	case "subscribe":
		return handleSubscriptionSubscribeCommand(client, config, args[1:])
	case "portal":
		return handleSubscriptionPortalCommand(client, config, args[1:])
	case "help", "--help", "-h":
		printClientSubscriptionUsage()
		return nil
	default:
		printClientSubscriptionUsage()
		return fmt.Errorf("unknown subscription subcommand: %s", args[0])
	}
}

func printClientSubscriptionUsage() {
	fmt.Print(`Usage: arkfile-client subscription SUBCOMMAND [FLAGS]

SUBCOMMANDS:
    status [--json] [--watch]
    plans [--json]
    subscribe --plan PLAN_ID [--open-browser] [--wait]
    portal [--open-browser]

`)
}

func handleSubscriptionStatusCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("subscription status", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	watch := fs.Bool("watch", false, "Poll until subscribed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	render := func() error {
		meResp, err := client.makeRequestWithSession("GET", "/api/subscriptions/me", nil, session)
		if err != nil {
			return err
		}
		creditsResp, err := client.makeRequestWithSession("GET", "/api/credits", nil, session)
		if err != nil {
			return err
		}
		if *jsonOut {
			out := map[string]interface{}{
				"subscription": meResp.Data["data"],
				"credits":        creditsResp.Data,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		data, _ := meResp.Data["data"].(map[string]interface{})
		fmt.Printf("Billing mode: %s\n", stringField(data, "billing_mode"))
		if sub, ok := data["subscription"].(map[string]interface{}); ok {
			fmt.Printf("Plan: %s (%s) until %s\n",
				stringField(sub, "plan_name"), stringField(sub, "status"), stringField(sub, "current_period_end"))
			fmt.Printf("Effective cap: %s\n", formatClientBytes(numberField(data, "effective_storage_limit_bytes")))
		} else {
			fmt.Println("No active subscription.")
		}
		return nil
	}
	if !*watch {
		return render()
	}
	for i := 0; i < 60; i++ {
		if err := render(); err != nil {
			return err
		}
		meResp, _ := client.makeRequestWithSession("GET", "/api/subscriptions/me", nil, session)
		data, _ := meResp.Data["data"].(map[string]interface{})
		if sub, ok := data["subscription"].(map[string]interface{}); ok {
			st := stringField(sub, "status")
			if st == "active" || st == "trialing" {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for active subscription")
}

func handleSubscriptionPlansCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("subscription plans", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequestWithSession("GET", "/api/subscriptions/plans", nil, session)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}
	plans, _ := resp.Data["plans"].([]interface{})
	for _, p := range plans {
		m, _ := p.(map[string]interface{})
		fmt.Printf("%s  %s  $%.2f/mo  %s\n",
			stringField(m, "plan_id"), stringField(m, "name"),
			float64(numberField(m, "price_usd_cents"))/100.0,
			formatClientBytes(numberField(m, "storage_limit_bytes")))
	}
	return nil
}

func handleSubscriptionSubscribeCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("subscription subscribe", flag.ExitOnError)
	plan := fs.String("plan", "", "Plan ID")
	openBrowser := fs.Bool("open-browser", false, "Open checkout in browser")
	wait := fs.Bool("wait", false, "Poll until subscription active")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *plan == "" {
		return fmt.Errorf("--plan is required")
	}
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequestWithSession("POST", "/api/subscriptions/checkout", map[string]string{
		"plan_id": *plan,
	}, session)
	if err != nil {
		return err
	}
	inner, _ := resp.Data["data"].(map[string]interface{})
	url := stringField(inner, "checkout_url")
	fmt.Printf("Checkout URL: %s\n", url)
	if *openBrowser && url != "" {
		openBrowserURL(url)
	}
	if *wait {
		return handleSubscriptionStatusCommand(client, config, []string{"--watch"})
	}
	return nil
}

func handleSubscriptionPortalCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("subscription portal", flag.ExitOnError)
	openBrowser := fs.Bool("open-browser", false, "Open portal in browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	resp, err := client.makeRequestWithSession("POST", "/api/subscriptions/portal", nil, session)
	if err != nil {
		return err
	}
	inner, _ := resp.Data["data"].(map[string]interface{})
	url := stringField(inner, "portal_url")
	fmt.Printf("Portal URL: %s\n", url)
	if (*openBrowser || strings.TrimSpace(url) != "") && url != "" {
		if *openBrowser {
			openBrowserURL(url)
		}
	}
	return nil
}
