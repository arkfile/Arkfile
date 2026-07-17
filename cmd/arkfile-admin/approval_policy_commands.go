package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// handleSetApprovalPolicyCommand calls POST /api/admin/system/approval-policy to
// flip the instance-wide auto-approval policy live (no server restart needed).
// require_approval=true  => new registrations require explicit admin approval.
// require_approval=false => new registrations are auto-approved at registration
// time with approved_by="system". The value is persisted in system_settings and
// survives restarts.
func handleSetApprovalPolicyCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("set-approval-policy", flag.ExitOnError)
	requireApproval := fs.String("require-approval", "", "Auto-approval policy: 'true' (new users require admin approval) or 'false' (new users auto-approved) (required)")
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin set-approval-policy --require-approval true|false [--json]

Set the instance-wide auto-approval policy for new registrations. Takes effect
immediately without a server restart and is persisted in system_settings so it
survives restarts. This does not change the approval status of existing users;
use 'approve-user'/'unapprove-user' for per-account control.

FLAGS:
    --require-approval true|false   true: new users require admin approval.
                                    false: new users are auto-approved at
                                    registration time (approved_by="system").
    --json                          Emit machine-readable JSON.
    --help                          Show this help message.

EXAMPLES:
    arkfile-admin set-approval-policy --require-approval false
    arkfile-admin set-approval-policy --require-approval true --json
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	val := strings.ToLower(strings.TrimSpace(*requireApproval))
	var enabled bool
	switch val {
	case "true", "1", "yes":
		enabled = true
	case "false", "0", "no":
		enabled = false
	default:
		return fmt.Errorf("--require-approval must be 'true' or 'false'")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{"require_approval": enabled}
	resp, err := client.makeRequest("POST", "/api/admin/system/approval-policy", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("set-approval-policy failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	fmt.Printf("Approval policy updated: require_approval=%t\n", enabled)
	fmt.Println("New registrations are now " + approvalPolicyDescription(enabled) + ".")
	return nil
}

// handleGetApprovalPolicyCommand calls GET /api/admin/system/approval-policy.
func handleGetApprovalPolicyCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("get-approval-policy", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin get-approval-policy [--json]

Print the current instance-wide auto-approval policy and its source
("system_settings" if an admin has set it, otherwise "env" reflecting the
REQUIRE_APPROVAL startup default).

FLAGS:
    --json   Emit machine-readable JSON.
    --help   Show this help message.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("GET", "/api/admin/system/approval-policy", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("get-approval-policy failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	enabled := safeBool(resp.Data, "require_approval")
	source := safeString(resp.Data, "source")
	fmt.Printf("require_approval = %t\n", enabled)
	fmt.Printf("source           = %s\n", source)
	fmt.Println("New registrations are " + approvalPolicyDescription(enabled) + ".")
	return nil
}

func approvalPolicyDescription(requireApproval bool) string {
	if requireApproval {
		return "pending admin approval (require_approval=true)"
	}
	return "auto-approved at registration time (require_approval=false)"
}

// handleResetRegistrationThrottleCommand calls the dev/test-only endpoint
// POST /api/admin/dev-test/registration-throttle/reset to clear the
// registration_attempts table. Used by the e2e throttle-interaction test to
// start from a known state and to avoid leaving the test host's entityID in a
// multi-hour cooldown that would block manual testing afterward.
func handleResetRegistrationThrottleCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("reset-registration-throttle", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON instead of formatted text")
	fs.Usage = func() {
		fmt.Print(`Usage: arkfile-admin reset-registration-throttle [--json]

Clear the registration_attempts table (dev/test only). This endpoint exists
only when ADMIN_DEV_TEST_API_ENABLED=true on the server. Used by the e2e
throttle-interaction test to reset the per-entityID registration counter so the
test can run from a known state and does not leave the host in a cooldown.

FLAGS:
    --json   Emit machine-readable JSON.
    --help   Show this help message.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if v := strings.ToLower(os.Getenv("ADMIN_DEV_TEST_API_ENABLED")); v != "true" && v != "1" && v != "yes" {
		fmt.Fprintln(os.Stderr,
			"Warning: ADMIN_DEV_TEST_API_ENABLED is not set in your local environment.")
		fmt.Fprintln(os.Stderr,
			"         reset-registration-throttle is a dev/test endpoint and is only registered")
		fmt.Fprintln(os.Stderr,
			"         when the server has ADMIN_DEV_TEST_API_ENABLED=true. If you get a 404, the")
		fmt.Fprintln(os.Stderr,
			"         server has it disabled (production-safe default).")
		fmt.Fprintln(os.Stderr, "")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("POST", "/api/admin/dev-test/registration-throttle/reset", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("reset-registration-throttle failed: %w", err)
	}

	if *jsonOut {
		return printJSON(resp.Data)
	}

	fmt.Printf("Registration throttle reset (deleted %v rows).\n", resp.Data["deleted"])
	return nil
}
