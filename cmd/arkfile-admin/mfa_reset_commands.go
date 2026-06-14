package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func handleResetUserMFACommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("reset-user-mfa", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username whose MFA will be fully reset (required)")
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt (required)")
	acknowledgeNoContact := fs.Bool("acknowledge-no-contact-info", false,
		"Acknowledge resetting MFA when the user has no contact info on file")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin reset-user-mfa --username USER --confirm [--acknowledge-no-contact-info]

Clear all MFA credentials and backup codes for a user, force-logout all sessions,
and leave the account in requires_mfa_setup state. Use only after verifying the
requester's identity out-of-band (ideally against saved contact info).

This is a last-resort recovery for total MFA lockout. Users who still have backup
codes should use self-service recovery first.

FLAGS:
    --username USER                     Username to reset (required)
    --confirm                           Required confirmation for this operation
    --acknowledge-no-contact-info       Required when the user has no contact info on file
    --help                              Show this help message

EXAMPLES:
    arkfile-admin reset-user-mfa --username alice12345 --confirm
    arkfile-admin reset-user-mfa --username bob.123.ABC --confirm --acknowledge-no-contact-info
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("--username is required")
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

	contactResp, err := client.makeRequest("GET", "/api/admin/users/"+*usernameFlag+"/contact-info", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to load contact info before MFA reset: %w", err)
	}

	hasContactInfo, _ := contactResp.Data["has_contact_info"].(bool)
	if hasContactInfo {
		fmt.Printf("Contact information on file for %s:\n", *usernameFlag)
		if contactInfoRaw, ok := contactResp.Data["contact_info"]; ok {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(contactInfoRaw)
		}
	} else {
		fmt.Printf("WARNING: No contact information on file for %s.\n", *usernameFlag)
		if !*acknowledgeNoContact {
			return fmt.Errorf("user has no contact info on file; re-run with --acknowledge-no-contact-info after out-of-band identity verification")
		}
		fmt.Println("Proceeding with --acknowledge-no-contact-info.")
	}

	payload := map[string]interface{}{"confirm": true}
	resp, err := client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/reset-mfa", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("MFA reset failed: %w", err)
	}

	alreadyReset, _ := resp.Data["already_reset"].(bool)
	if alreadyReset {
		fmt.Printf("User %s has no MFA enrollment to reset\n", *usernameFlag)
		return nil
	}

	forceLogout, _ := resp.Data["force_logout"].(bool)
	fmt.Printf("MFA reset completed for %s\n", *usernameFlag)
	if forceLogout {
		fmt.Printf("User %s has been force-logged out (all tokens revoked)\n", *usernameFlag)
	}
	fmt.Println("Instruct the user to log in with their password and complete MFA setup again.")
	return nil
}
