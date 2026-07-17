package main

import (
	"flag"
	"fmt"
)

func handleRotateOpaqueKeysCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	if len(args) == 0 {
		printRotateOpaqueKeysUsage()
		return fmt.Errorf("a subcommand is required: rotate or replace-keys")
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "rotate":
		return handleRotateOpaqueKeysRotate(client, config, rest)
	case "replace-keys":
		return handleRotateOpaqueKeysReplaceKeys(client, config, rest)
	case "--help", "-h", "help":
		printRotateOpaqueKeysUsage()
		return nil
	default:
		printRotateOpaqueKeysUsage()
		return fmt.Errorf("unknown subcommand: %s", sub)
	}
}

func printRotateOpaqueKeysUsage() {
	fmt.Print(`Usage: arkfile-admin rotate-opaque-keys <rotate|replace-keys> [flags]

Rotate the OPAQUE server private key and OPRF seed for the whole deployment.
Each user's opaque_user_data record is bound to the server keys present at
registration, so rotation requires every account to re-register on next login.
Files, shares, MFA, and settings are preserved.

ORDER IS LOAD-BEARING. Replacing server keys before flagging accounts causes
users to see a generic authentication failure instead of the guided
re-registration prompt. Always prefer the atomic "rotate" subcommand.

SUBCOMMANDS:
    rotate                  Flag all accounts AND replace server keys (recommended)
    replace-keys            Replace keys only (requires flag-user-reregistration --all first)

FLAGS:
    --confirm               Required confirmation for the operation
    --help                  Show this help message

EXAMPLES:
    arkfile-admin rotate-opaque-keys rotate --confirm
    arkfile-admin flag-user-reregistration --all --confirm
    arkfile-admin rotate-opaque-keys replace-keys --confirm
`)
}

func handleRotateOpaqueKeysRotate(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-opaque-keys rotate", flag.ExitOnError)
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt (required)")
	fs.Usage = printRotateOpaqueKeysUsage
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf("--confirm is required for this operation")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("POST", "/api/admin/system/rotate-opaque-keys", map[string]interface{}{"confirm": true}, session.AccessToken)
	if err != nil {
		return fmt.Errorf("OPAQUE key rotation request failed: %w", err)
	}

	flagged, _ := resp.Data["users_flagged"].(float64)
	revokeFailures, _ := resp.Data["revoke_failures"].(float64)
	privFP, _ := resp.Data["private_key_fingerprint"].(string)
	seedFP, _ := resp.Data["oprf_seed_fingerprint"].(string)

	fmt.Printf("OPAQUE server keys rotated. Flagged %d account(s) for re-registration.\n", int(flagged))
	if privFP != "" && seedFP != "" {
		fmt.Printf("New key fingerprints (sha256 prefix): private=%s oprf_seed=%s\n", privFP, seedFP)
	}
	if revokeFailures > 0 {
		fmt.Printf("WARNING: failed to revoke sessions for %d account(s); run force-logout manually.\n", int(revokeFailures))
	}
	fmt.Println("Each user will re-register on next login; files, shares, MFA, and settings are preserved.")
	return nil
}

func handleRotateOpaqueKeysReplaceKeys(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-opaque-keys replace-keys", flag.ExitOnError)
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt (required)")
	fs.Usage = printRotateOpaqueKeysUsage
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf("--confirm is required for this operation")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("POST", "/api/admin/system/replace-opaque-keys", map[string]interface{}{"confirm": true}, session.AccessToken)
	if err != nil {
		return fmt.Errorf("OPAQUE key replacement request failed: %w", err)
	}

	privFP, _ := resp.Data["private_key_fingerprint"].(string)
	seedFP, _ := resp.Data["oprf_seed_fingerprint"].(string)
	fmt.Println("OPAQUE server keys replaced.")
	if privFP != "" && seedFP != "" {
		fmt.Printf("New key fingerprints (sha256 prefix): private=%s oprf_seed=%s\n", privFP, seedFP)
	}
	fmt.Println("Accounts must already have been flagged with flag-user-reregistration --all.")
	return nil
}
