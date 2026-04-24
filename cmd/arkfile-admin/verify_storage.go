package main

import (
	"encoding/json"
	"flag"
	"fmt"
)

// handleVerifyStorageCommand triggers a storage round-trip verification via the
// Arkfile server's admin API. Requires an active admin session.
//
// The server performs: upload 1 MB test object -> download -> SHA-256 verify -> delete
// using its already-initialized S3 connection. No local file access needed.
// If --provider-id is specified, verifies that specific provider; otherwise defaults
// to the primary provider.
func handleVerifyStorageCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("verify-storage", flag.ExitOnError)

	providerID := fs.String("provider-id", "", "Provider ID to verify (defaults to primary)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin verify-storage [--provider-id PROVIDER_ID]

Verify S3 storage connectivity via the Arkfile server admin API.
The server performs a full round-trip test:
  1. Upload a 1 MB test object
  2. Download the object back
  3. Verify the SHA-256 hash matches
  4. Delete the test object

Requires an active admin session (run 'arkfile-admin login' first).

FLAGS:
    --provider-id ID    Provider ID to verify (defaults to primary if omitted)
    --help              Show this help message

EXAMPLES:
    arkfile-admin verify-storage
    arkfile-admin verify-storage --provider-id wasabi-us-central-1
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load admin session
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login' first): %w", err)
	}

	if *providerID != "" {
		fmt.Printf("Requesting storage verification for provider: %s\n", *providerID)
	} else {
		fmt.Println("Requesting storage verification from server...")
	}

	// Build request payload
	var payload interface{}
	if *providerID != "" {
		payload = map[string]string{"provider_id": *providerID}
	}

	resp, err := client.makeRequest("POST", "/api/admin/storage/verify-storage", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("storage verification request failed: %w", err)
	}

	// Extract and display the verification result
	data := resp.Data
	if data == nil {
		return fmt.Errorf("no verification data in server response")
	}

	provider, _ := data["provider"].(string)
	duration, _ := data["duration"].(string)
	verified, _ := data["verified"].(bool)
	uploadOK, _ := data["upload_ok"].(bool)
	downloadOK, _ := data["download_ok"].(bool)
	hashMatchOK, _ := data["hash_match_ok"].(bool)
	deleteOK, _ := data["delete_ok"].(bool)
	verifyError, _ := data["error"].(string)

	fmt.Printf("Storage provider: %s\n", provider)

	if uploadOK {
		fmt.Println("[OK] Upload successful")
	} else {
		fmt.Println("[X] Upload failed")
	}
	if downloadOK {
		fmt.Println("[OK] Download successful")
	}
	if hashMatchOK {
		fmt.Println("[OK] Hash verified")
	}
	if deleteOK {
		fmt.Println("[OK] Test object deleted")
	}

	if verified {
		fmt.Printf("\nSUCCESS! Storage verification complete.\n")
		fmt.Printf("  Provider: %s\n", provider)
		fmt.Printf("  Duration: %s\n", duration)
		fmt.Printf("  Round-trip: upload -> download -> verify hash -> delete\n")
		fmt.Printf("  All checks passed.\n")
		return nil
	}

	if verifyError != "" {
		return fmt.Errorf("verification failed: %s", verifyError)
	}

	// Dump full response for debugging
	respJSON, _ := json.MarshalIndent(data, "", "  ")
	return fmt.Errorf("verification failed (details: %s)", string(respJSON))
}
