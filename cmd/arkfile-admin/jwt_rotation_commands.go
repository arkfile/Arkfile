package main

import (
	"flag"
	"fmt"
	"time"
)

func handleRotateJWTKeysCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	if len(args) == 0 {
		printRotateJWTKeysUsage()
		return fmt.Errorf("a subcommand is required: rotate or retire")
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "rotate":
		return handleRotateJWTKeysRotate(client, config, rest)
	case "retire":
		return handleRotateJWTKeysRetire(client, config, rest)
	case "--help", "-h", "help":
		printRotateJWTKeysUsage()
		return nil
	default:
		printRotateJWTKeysUsage()
		return fmt.Errorf("unknown subcommand: %s", sub)
	}
}

func printRotateJWTKeysUsage() {
	fmt.Print(`Usage: arkfile-admin rotate-jwt-keys <rotate|retire> [flags]

Rotate the server's JWT signing keys with a verification overlap. Rotation is
online and zero-downtime: a new active key version is generated for both the
temp and full tiers, and the previous version stays in the verification set so
already-issued tokens keep working until they expire.

SUBCOMMANDS:
    rotate                  Generate a new active signing version for both tiers
    retire --version N      Remove a superseded version after the overlap window

FLAGS:
    --confirm               Required confirmation for the operation
    --version N             (retire) The superseded version number to delete
    --help                  Show this help message

EXAMPLES:
    arkfile-admin rotate-jwt-keys rotate --confirm
    arkfile-admin rotate-jwt-keys retire --version 1 --confirm
`)
}

func handleRotateJWTKeysRotate(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-jwt-keys rotate", flag.ExitOnError)
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt (required)")
	fs.Usage = printRotateJWTKeysUsage
	if err := fs.Parse(args); err != nil {
		return err
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

	resp, err := client.makeRequest("POST", "/api/admin/system/rotate-jwt-keys", map[string]interface{}{}, session.AccessToken)
	if err != nil {
		return fmt.Errorf("JWT key rotation request failed: %w", err)
	}

	tempVersion, _ := resp.Data["temp_version"].(float64)
	fullVersion, _ := resp.Data["full_version"].(float64)
	fmt.Printf("JWT signing keys rotated. Active versions are now temp=v%d, full=v%d.\n", int(tempVersion), int(fullVersion))
	fmt.Println("The previous versions remain valid for verification until their tokens expire.")
	fmt.Println("After the access-token lifetime has elapsed you may retire the old version:")
	fmt.Printf("    arkfile-admin rotate-jwt-keys retire --version %d --confirm\n", int(fullVersion)-1)
	return nil
}

func handleRotateJWTKeysRetire(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-jwt-keys retire", flag.ExitOnError)
	version := fs.Int("version", 0, "Superseded version number to retire (required)")
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt (required)")
	fs.Usage = printRotateJWTKeysUsage
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version <= 0 {
		return fmt.Errorf("--version must be a positive integer")
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

	payload := map[string]interface{}{"version": *version}
	if _, err := client.makeRequest("POST", "/api/admin/system/retire-jwt-key-version", payload, session.AccessToken); err != nil {
		return fmt.Errorf("JWT key retirement request failed: %w", err)
	}

	fmt.Printf("Retired JWT signing key version v%d from both tiers.\n", *version)
	return nil
}
