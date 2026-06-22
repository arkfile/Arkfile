package main

import (
	"flag"
	"fmt"
	"time"
)

// handleFlagUserReregistrationCommand flags one account, or all accounts, for a
// one-time OPAQUE re-registration. This is the operator side of a routine OPAQUE
// credential rotation: affected users keep their files, shares, MFA enrollment,
// and settings, and re-bind their OPAQUE record to the current server keys on
// their next sign-in. Sessions are revoked so the change takes effect at once.
func handleFlagUserReregistrationCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("flag-user-reregistration", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to flag for re-registration (omit with --all)")
	allFlag := fs.Bool("all", false, "Flag every active account (full-deployment OPAQUE key rotation)")
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage:
    arkfile-admin flag-user-reregistration --username USER --confirm
    arkfile-admin flag-user-reregistration --all --confirm

Flag account(s) for a one-time OPAQUE re-registration. On their next login the
affected user(s) transparently re-register their OPAQUE record against the
current server keys. Files, shares, MFA enrollment, and settings are preserved.
Outstanding sessions are revoked so the rotation takes effect immediately.

Use --all when rotating the OPAQUE server keys for the entire deployment.

FLAGS:
    --username USER     Username to flag (required unless --all)
    --all               Flag every active account
    --confirm           Required confirmation for this operation
    --help              Show this help message

EXAMPLES:
    arkfile-admin flag-user-reregistration --username alice12345 --confirm
    arkfile-admin flag-user-reregistration --all --confirm
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *allFlag && *usernameFlag != "" {
		return fmt.Errorf("--username and --all are mutually exclusive")
	}
	if !*allFlag && *usernameFlag == "" {
		return fmt.Errorf("either --username or --all is required")
	}
	if !*confirm {
		return fmt.Errorf("--confirm is required for this operation")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	payload := map[string]interface{}{"confirm": true}

	if *allFlag {
		resp, err := client.makeRequest("POST", "/api/admin/users/flag-reregistration-all", payload, session.AccessToken)
		if err != nil {
			return fmt.Errorf("flag-all re-registration failed: %w", err)
		}
		flagged, _ := resp.Data["users_flagged"].(float64)
		revokeFailures, _ := resp.Data["revoke_failures"].(float64)
		fmt.Printf("Flagged %d account(s) for OPAQUE re-registration.\n", int(flagged))
		if revokeFailures > 0 {
			fmt.Printf("WARNING: failed to revoke sessions for %d account(s); run force-logout manually for those users.\n", int(revokeFailures))
		}
		fmt.Println("Each user will transparently re-register on next login; files, shares, MFA, and settings are preserved.")
		return nil
	}

	resp, err := client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/flag-reregistration", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("flag re-registration failed: %w", err)
	}
	forceLogout, _ := resp.Data["force_logout"].(bool)
	fmt.Printf("User %s flagged for OPAQUE re-registration.\n", *usernameFlag)
	if forceLogout {
		fmt.Printf("User %s has been force-logged out (all tokens revoked).\n", *usernameFlag)
	}
	fmt.Println("On next login the user transparently re-registers; files, shares, MFA, and settings are preserved.")
	return nil
}
