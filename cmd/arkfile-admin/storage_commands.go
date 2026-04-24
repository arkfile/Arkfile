package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// handleStorageStatusCommand shows configured providers, file counts, and sync status
func handleStorageStatusCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("storage-status", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin storage-status [--json]

Show configured storage providers, file counts, sync status, and costs.

FLAGS:
    --json    Output as JSON
    --help    Show this help message

EXAMPLES:
    arkfile-admin storage-status
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	resp, err := client.makeRequest("GET", "/api/admin/storage/status", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get storage status: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	providersRaw, ok := resp.Data["providers"].([]interface{})
	if ok && len(providersRaw) > 0 {
		for i, p := range providersRaw {
			pm := p.(map[string]interface{})
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("Provider %d:\n", i+1)
			fmt.Printf("  ID:         %s\n", safeString(pm, "provider_id"))
			fmt.Printf("  Type:       %s\n", safeString(pm, "provider_type"))
			fmt.Printf("  Bucket:     %s\n", safeString(pm, "bucket_name"))
			fmt.Printf("  Region:     %s\n", safeString(pm, "region"))
			fmt.Printf("  Role:       %s\n", safeString(pm, "role"))
			active := "yes"
			if !safeBool(pm, "is_active") {
				active = "no"
			}
			fmt.Printf("  Active:     %s\n", active)
			fmt.Printf("  Files:      %d\n", safeInt64(pm, "total_objects"))
			fmt.Printf("  Size:       %s\n", formatFileSize(safeInt64(pm, "total_size_bytes")))

			cost := "--"
			if pm["cost_per_tb_cents"] != nil {
				costCents := safeInt64(pm, "cost_per_tb_cents")
				if costCents > 0 {
					cost = fmt.Sprintf("$%.2f/TB/month", float64(costCents)/100.0)
				}
			}
			fmt.Printf("  Cost:       %s\n", cost)

			verified := "--"
			if v := safeString(pm, "last_verified_at"); v != "" {
				if len(v) >= 10 {
					verified = v[:10]
				}
			}
			fmt.Printf("  Verified:   %s\n", verified)
		}
	} else {
		fmt.Println("  (no providers configured)")
	}

	replEnabled := safeBool(resp.Data, "replication_enabled")
	totalFiles := safeInt64(resp.Data, "total_files")
	fullyReplicated := safeInt64(resp.Data, "fully_replicated")
	gaps := safeInt64(resp.Data, "partially_replicated")

	replStr := "disabled"
	if replEnabled {
		replStr = "enabled"
	}

	fmt.Printf("\nReplication: %s\n", replStr)
	fmt.Printf("Total files: %d | Fully replicated: %d | Gaps: %d\n", totalFiles, fullyReplicated, gaps)

	return nil
}

// handleStorageSyncStatusCommand shows detailed sync information
func handleStorageSyncStatusCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("storage-sync-status", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin storage-sync-status [--json]

Show detailed breakdown of file locations and replication gaps.

FLAGS:
    --json    Output as JSON
    --help    Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	resp, err := client.makeRequest("GET", "/api/admin/storage/sync-status", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get sync status: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	fmt.Println("Storage Sync Status")
	fmt.Println()
	fmt.Printf("  Total files:        %d\n", safeInt64(resp.Data, "total_files"))
	fmt.Printf("  On primary only:    %d\n", safeInt64(resp.Data, "on_primary_only"))
	fmt.Printf("  On secondary only:  %d\n", safeInt64(resp.Data, "on_secondary_only"))

	if failedRaw, ok := resp.Data["failed_locations"].([]interface{}); ok && len(failedRaw) > 0 {
		fmt.Printf("\n  Failed locations (%d):\n", len(failedRaw))
		for _, f := range failedRaw {
			fm := f.(map[string]interface{})
			fmt.Printf("    file: %s  provider: %s  owner: %s\n",
				safeString(fm, "file_id"), safeString(fm, "provider_id"), safeString(fm, "owner_username"))
		}
	}

	if orphanedRaw, ok := resp.Data["orphaned_blobs"].([]interface{}); ok && len(orphanedRaw) > 0 {
		fmt.Printf("\n  Orphaned blobs (%d):\n", len(orphanedRaw))
		for _, o := range orphanedRaw {
			om := o.(map[string]interface{})
			fmt.Printf("    file: %s  provider: %s\n",
				safeString(om, "file_id"), safeString(om, "provider_id"))
		}
	}

	return nil
}

// handleCopyAllCommand copies all files from one provider to another
func handleCopyAllCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("copy-all", flag.ExitOnError)
	from := fs.String("from", "", "Source provider ID (required)")
	to := fs.String("to", "", "Destination provider ID (required)")
	verify := fs.Bool("verify", false, "Verify SHA-256 hash during copy")
	skipExisting := fs.Bool("skip-existing", true, "Skip files already on destination")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin copy-all --from PROVIDER --to PROVIDER [FLAGS]

Copy all files from one storage provider to another.

FLAGS:
    --from PROVIDER       Source provider ID (required)
    --to PROVIDER         Destination provider ID (required)
    --verify              Verify SHA-256 hash during copy (default: false)
    --skip-existing       Skip files already on destination (default: true)
    --help                Show this help message

EXAMPLES:
    arkfile-admin copy-all --from seaweedfs-local --to wasabi-us-central-1 --verify --skip-existing
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		return fmt.Errorf("--from and --to are required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	payload := map[string]interface{}{
		"source_provider_id":      *from,
		"destination_provider_id": *to,
		"verify":                  *verify,
		"skip_existing":           *skipExisting,
	}

	resp, err := client.makeRequest("POST", "/api/admin/storage/copy-all", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("copy-all failed: %w", err)
	}

	taskID := safeString(resp.Data, "task_id")
	fmt.Printf("Copy task queued: %s\n", taskID)
	fmt.Printf("Use 'arkfile-admin task-status --task-id %s' to check progress.\n", taskID)
	return nil
}

// handleCopyUserFilesCommand copies all files for a user between providers
func handleCopyUserFilesCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("copy-user-files", flag.ExitOnError)
	username := fs.String("username", "", "Username (required)")
	from := fs.String("from", "", "Source provider ID (required)")
	to := fs.String("to", "", "Destination provider ID (required)")
	verify := fs.Bool("verify", false, "Verify SHA-256 hash during copy")
	skipExisting := fs.Bool("skip-existing", true, "Skip files already on destination")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin copy-user-files --username USER --from PROVIDER --to PROVIDER [FLAGS]

Copy all files for a specific user from one provider to another.

FLAGS:
    --username USER       Target user (required)
    --from PROVIDER       Source provider ID (required)
    --to PROVIDER         Destination provider ID (required)
    --verify              Verify SHA-256 hash during copy (default: false)
    --skip-existing       Skip files already on destination (default: true)
    --help                Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *from == "" || *to == "" {
		return fmt.Errorf("--username, --from, and --to are required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	payload := map[string]interface{}{
		"username":                *username,
		"source_provider_id":      *from,
		"destination_provider_id": *to,
		"verify":                  *verify,
		"skip_existing":           *skipExisting,
	}

	resp, err := client.makeRequest("POST", "/api/admin/storage/copy-user-files", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("copy-user-files failed: %w", err)
	}

	taskID := safeString(resp.Data, "task_id")
	fmt.Printf("Copy task queued: %s\n", taskID)
	fmt.Printf("Use 'arkfile-admin task-status --task-id %s' to check progress.\n", taskID)
	return nil
}

// handleCopyFileCommand copies a single file between providers
func handleCopyFileCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("copy-file", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to copy (required)")
	from := fs.String("from", "", "Source provider ID (required)")
	to := fs.String("to", "", "Destination provider ID (required)")
	verify := fs.Bool("verify", false, "Verify SHA-256 hash during copy")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin copy-file --file-id ID --from PROVIDER --to PROVIDER [FLAGS]

Copy a single file from one storage provider to another.

FLAGS:
    --file-id ID          File ID to copy (required)
    --from PROVIDER       Source provider ID (required)
    --to PROVIDER         Destination provider ID (required)
    --verify              Verify SHA-256 hash during copy (default: false)
    --help                Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fileID == "" || *from == "" || *to == "" {
		return fmt.Errorf("--file-id, --from, and --to are required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	payload := map[string]interface{}{
		"file_id":                 *fileID,
		"source_provider_id":      *from,
		"destination_provider_id": *to,
		"verify":                  *verify,
	}

	resp, err := client.makeRequest("POST", "/api/admin/storage/copy-file", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("copy-file failed: %w", err)
	}

	taskID := safeString(resp.Data, "task_id")
	fmt.Printf("Copy task queued: %s\n", taskID)
	fmt.Printf("Use 'arkfile-admin task-status --task-id %s' to check progress.\n", taskID)
	return nil
}

// handleTaskStatusCommand checks status of a background task
func handleTaskStatusCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("task-status", flag.ExitOnError)
	taskID := fs.String("task-id", "", "Task ID to check (required)")
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin task-status --task-id ID [--json]

Check the status of a background storage task.

FLAGS:
    --task-id ID    Task ID to check (required)
    --json          Output as JSON
    --help          Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *taskID == "" {
		return fmt.Errorf("--task-id is required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	resp, err := client.makeRequest("GET", "/api/admin/storage/task/"+*taskID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get task status: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	status := safeString(resp.Data, "status")
	taskType := safeString(resp.Data, "task_type")
	current := safeInt64(resp.Data, "progress_current")
	total := safeInt64(resp.Data, "progress_total")

	fmt.Printf("Task: %s\n", *taskID)
	fmt.Printf("Type: %s\n", taskType)
	fmt.Printf("Status: %s\n", status)

	if total > 0 {
		pct := float64(current) / float64(total) * 100
		fmt.Printf("Progress: %d/%d (%.1f%%)\n", current, total, pct)
	}

	if details, ok := resp.Data["details"].(map[string]interface{}); ok {
		copied := safeInt64(details, "files_copied")
		skipped := safeInt64(details, "files_skipped")
		failed := safeInt64(details, "files_failed")
		bytesCopied := safeInt64(details, "bytes_copied")
		fmt.Printf("  Copied: %d | Skipped: %d | Failed: %d\n", copied, skipped, failed)
		if bytesCopied > 0 {
			fmt.Printf("  Bytes copied: %s\n", formatFileSize(bytesCopied))
		}
		// Show current file transfer progress for large files
		curFileBytes := safeInt64(details, "current_file_bytes")
		curFileSize := safeInt64(details, "current_file_size")
		if status == "running" && curFileSize > 0 && curFileBytes < curFileSize {
			pctFile := float64(curFileBytes) / float64(curFileSize) * 100
			fmt.Printf("  Current file: %s / %s (%.1f%%)\n",
				formatFileSize(curFileBytes), formatFileSize(curFileSize), pctFile)
		}
	}

	if errMsg := safeString(resp.Data, "error_message"); errMsg != "" {
		fmt.Printf("Error: %s\n", errMsg)
	}

	return nil
}

// handleCancelTaskCommand cancels a running task
func handleCancelTaskCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("cancel-task", flag.ExitOnError)
	taskID := fs.String("task-id", "", "Task ID to cancel (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin cancel-task --task-id ID

Cancel a running background storage task.

FLAGS:
    --task-id ID    Task ID to cancel (required)
    --help          Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *taskID == "" {
		return fmt.Errorf("--task-id is required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	_, err = client.makeRequest("POST", "/api/admin/storage/cancel-task/"+*taskID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("cancel-task failed: %w", err)
	}

	fmt.Printf("Task cancellation requested: %s\n", *taskID)
	return nil
}

// handleSetPrimaryCommand promotes a provider to primary
func handleSetPrimaryCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("set-primary", flag.ExitOnError)
	providerID := fs.String("provider-id", "", "Provider ID to promote (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin set-primary --provider-id ID

Promote a secondary provider to primary. New uploads will go to this provider.

FLAGS:
    --provider-id ID    Provider to promote (must be secondary)
    --help              Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *providerID == "" {
		return fmt.Errorf("--provider-id is required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	payload := map[string]interface{}{"provider_id": *providerID}
	resp, err := client.makeRequest("POST", "/api/admin/storage/set-primary", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("set-primary failed: %w", err)
	}

	fmt.Println(safeString(resp.Data, "message"))
	return nil
}

// handleSetSecondaryCommand sets a provider as secondary
func handleSetSecondaryCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("set-secondary", flag.ExitOnError)
	providerID := fs.String("provider-id", "", "Provider ID to set as secondary (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin set-secondary --provider-id ID

Promote or demote a provider to secondary (auto-replication target).

FLAGS:
    --provider-id ID    Provider to set as secondary
    --help              Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *providerID == "" {
		return fmt.Errorf("--provider-id is required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	payload := map[string]interface{}{"provider_id": *providerID}
	resp, err := client.makeRequest("POST", "/api/admin/storage/set-secondary", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("set-secondary failed: %w", err)
	}

	fmt.Println(safeString(resp.Data, "message"))
	return nil
}

// handleSetTertiaryCommand sets a provider as tertiary
func handleSetTertiaryCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("set-tertiary", flag.ExitOnError)
	providerID := fs.String("provider-id", "", "Provider ID to demote to tertiary (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin set-tertiary --provider-id ID

Demote a secondary provider to tertiary (manual-only copy target).

FLAGS:
    --provider-id ID    Provider to demote (must be secondary)
    --help              Show this help message
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *providerID == "" {
		return fmt.Errorf("--provider-id is required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	payload := map[string]interface{}{"provider_id": *providerID}
	resp, err := client.makeRequest("POST", "/api/admin/storage/set-tertiary", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("set-tertiary failed: %w", err)
	}

	fmt.Println(safeString(resp.Data, "message"))
	return nil
}

// handleSwapProvidersCommand swaps primary and secondary providers
func handleSwapProvidersCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	resp, err := client.makeRequest("POST", "/api/admin/storage/swap-providers", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("swap-providers failed: %w", err)
	}

	fmt.Println(safeString(resp.Data, "message"))
	return nil
}

// handleSetCostCommand sets monthly cost per TB for a provider
func handleSetCostCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("set-cost", flag.ExitOnError)
	providerID := fs.String("provider-id", "", "Provider ID (required)")
	cost := fs.Float64("cost", 0, "Monthly cost per TB in dollars (e.g. 7.99)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin set-cost --provider-id ID --cost AMOUNT

Set monthly cost per TB for a storage provider (for cost tracking).

FLAGS:
    --provider-id ID    Provider to set cost for (required)
    --cost AMOUNT       Monthly cost per TB in dollars (e.g. 7.99)
    --help              Show this help message

EXAMPLES:
    arkfile-admin set-cost --provider-id wasabi-us-central-1 --cost 7.99
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *providerID == "" {
		return fmt.Errorf("--provider-id is required")
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	// Convert dollars to cents
	costCents := int64(*cost * 100)

	payload := map[string]interface{}{
		"provider_id":       *providerID,
		"cost_per_tb_cents": costCents,
	}

	_, err = client.makeRequest("POST", "/api/admin/storage/set-cost", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("set-cost failed: %w", err)
	}

	fmt.Printf("Cost updated for %s: $%.2f/TB/month\n", *providerID, *cost)
	return nil
}

// displayLoginAlerts checks for storage alerts after login and displays them if present
func displayLoginAlerts(client *HTTPClient, accessToken string) {
	resp, err := client.makeRequest("GET", "/api/admin/alerts/summary", nil, accessToken)
	if err != nil {
		return // silently skip if alerts endpoint fails
	}

	hasAlerts := safeBool(resp.Data, "has_alerts")
	if !hasAlerts {
		return
	}

	message := safeString(resp.Data, "message")
	if message != "" {
		fmt.Printf("\n[!] Storage alerts:\n")
		// Split message parts by comma and display each as a bullet
		parts := strings.Split(message, ".")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				fmt.Printf("  - %s\n", part)
			}
		}
	}
}

// handleVerifyAllCommand performs HEAD-based verification of all file locations.
func handleVerifyAllCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("verify-all", flag.ExitOnError)
	providerID := fs.String("provider-id", "", "Only verify files on this provider (default: all providers)")
	fix := fs.Bool("fix", false, "Mark missing files as 'missing' in DB (default: dry-run)")
	concurrency := fs.Int("concurrency", 10, "Parallel HEAD requests")
	watch := fs.Bool("watch", false, "Poll task status until complete")
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin verify-all [FLAGS]

Verify all file locations via HEAD requests against S3 providers.
Detects missing or size-mismatched blobs without downloading any data.

FLAGS:
    --provider-id ID    Only verify files on this provider (default: all providers)
    --fix               Mark missing files as "missing" in DB (default: dry-run)
    --concurrency N     Parallel HEAD requests (default: 10)
    --watch             Poll task status until complete
    --json              Output as JSON
    --help              Show this help message

EXAMPLES:
    arkfile-admin verify-all
    arkfile-admin verify-all --provider-id wasabi-us-central-1 --fix
    arkfile-admin verify-all --concurrency 20 --watch
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	// Submit verify-all task
	payload := map[string]interface{}{
		"fix":         *fix,
		"concurrency": *concurrency,
	}
	if *providerID != "" {
		payload["provider_id"] = *providerID
	}

	resp, err := client.makeRequest("POST", "/api/admin/storage/verify-all", payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to start verify-all task: %w", err)
	}

	taskID := safeString(resp.Data, "task_id")
	if taskID == "" {
		return fmt.Errorf("no task_id in response")
	}

	fmt.Printf("Verify-all task started: %s\n", taskID)

	if !*watch {
		fmt.Printf("Use 'arkfile-admin task-status --task-id %s --watch' to monitor progress.\n", taskID)
		return nil
	}

	// Watch mode: poll until complete
	for {
		time.Sleep(3 * time.Second)

		taskResp, err := client.makeRequest("GET", "/api/admin/storage/task/"+taskID, nil, session.AccessToken)
		if err != nil {
			fmt.Printf("  (poll error: %v)\n", err)
			continue
		}

		status := safeString(taskResp.Data, "status")
		current := safeInt64(taskResp.Data, "progress_current")
		total := safeInt64(taskResp.Data, "progress_total")

		if *jsonOutput && (status == "completed" || status == "failed" || status == "canceled") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(taskResp.Data)
		}

		pct := float64(0)
		if total > 0 {
			pct = float64(current) / float64(total) * 100
		}

		// Extract details for progress display
		verifiedOK := int64(0)
		missing := int64(0)
		sizeMismatch := int64(0)
		errors := int64(0)
		if detailsRaw, ok := taskResp.Data["details"].(map[string]interface{}); ok {
			verifiedOK = safeInt64(detailsRaw, "verified_ok")
			missing = safeInt64(detailsRaw, "missing")
			sizeMismatch = safeInt64(detailsRaw, "size_mismatch")
			errors = safeInt64(detailsRaw, "errors")
		}

		fmt.Printf("\r  Status: %s | Progress: %d/%d (%.1f%%) | OK: %d | Missing: %d | Size mismatch: %d | Errors: %d",
			status, current, total, pct, verifiedOK, missing, sizeMismatch, errors)

		if status == "completed" || status == "failed" || status == "canceled" {
			fmt.Println()
			if status == "completed" {
				fmt.Printf("\nVerification complete.\n")
				fmt.Printf("  OK: %d\n", verifiedOK)
				fmt.Printf("  Missing: %d\n", missing)
				fmt.Printf("  Size mismatch: %d\n", sizeMismatch)
				fmt.Printf("  Errors: %d\n", errors)
				if missing > 0 || sizeMismatch > 0 {
					if *fix {
						fmt.Printf("\n  %d locations updated to status 'missing'.\n", missing+sizeMismatch)
						fmt.Printf("  Run 'copy-all --skip-existing' to re-copy missing files.\n")
					} else {
						fmt.Printf("\n  [!] %d issues found. Run with --fix to mark missing files.\n", missing+sizeMismatch)
					}
				}
			} else {
				fmt.Printf("\nTask %s: %s\n", taskID, status)
			}
			return nil
		}
	}
}
