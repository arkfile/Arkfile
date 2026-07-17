package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func handleExportFileCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("export-file", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to export (required)")
	outputPath := fs.String("output", "", "Output file path (default: <file-id>.arkbackup)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin export-file --file-id FILE_ID [--output PATH]

Export a user's encrypted file as a .arkbackup bundle for disaster recovery.
The admin can export any user's file, but cannot decrypt it without the user's password.

FLAGS:
    --file-id ID        File ID to export (required)
    --output PATH       Output file path (default: <file-id>.arkbackup)
    --help             Show this help message

EXAMPLES:
    arkfile-admin export-file --file-id abc-123-def
    arkfile-admin export-file --file-id abc-123-def --output backup.arkbackup
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" {
		return fmt.Errorf("--file-id is required")
	}

	if *outputPath == "" {
		*outputPath = *fileID + ".arkbackup"
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	logVerbose("Exporting file %s as .arkbackup bundle (admin export)...", *fileID)

	// Make raw HTTP request (binary response, not JSON)
	url := fmt.Sprintf("%s/api/admin/files/%s/export", client.baseURL, *fileID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create export request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("export failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	// Stream response to output file
	outFile, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	written, err := io.Copy(outFile, resp.Body)
	outFile.Close()
	if err != nil {
		os.Remove(*outputPath)
		return fmt.Errorf("failed to write export bundle: %w", err)
	}

	fmt.Printf("Exported %s to %s (%d bytes)\n", *fileID, *outputPath, written)
	fmt.Printf("Note: This bundle is encrypted and can only be decrypted by the file owner.\n")
	return nil
}

// handleSystemStatusCommand shows system status and metrics

func handleListFilesCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("list-files", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to list files for (required)")
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin list-files --username USER [--json]

List all files owned by a specific user.

FLAGS:
    --username USER     Username to list files for (required)
    --json              Output as JSON
    --help              Show this help message

EXAMPLES:
    arkfile-admin list-files --username alice12345
    arkfile-admin list-files --username alice12345 --json
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("--username is required")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("GET", "/api/admin/users/"+*usernameFlag+"/files", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to list files: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	count := safeFloat64(resp.Data, "count")
	fmt.Printf("Files for user %s (%d total):\n\n", *usernameFlag, int(count))

	filesRaw, ok := resp.Data["files"].([]interface{})
	if !ok || len(filesRaw) == 0 {
		fmt.Println("  (no files)")
		return nil
	}

	sep := strings.Repeat("-", 80)
	for i, f := range filesRaw {
		fm := f.(map[string]interface{})
		fileID := safeString(fm, "file_id")
		storageID := safeString(fm, "storage_id")
		sizeBytes := safeInt64(fm, "size_bytes")
		chunkCount := safeInt64(fm, "chunk_count")
		uploadDate := safeString(fm, "upload_date")
		passwordType := safeString(fm, "password_type")

		// Parse storage locations from API response
		var locationStrs []string
		if locsRaw, ok := fm["locations"].([]interface{}); ok {
			for _, loc := range locsRaw {
				if s, ok := loc.(string); ok && s != "" {
					locationStrs = append(locationStrs, s)
				}
			}
		}
		locationsDisplay := "(none)"
		if len(locationStrs) > 0 {
			locationsDisplay = strings.Join(locationStrs, ", ")
		}

		fmt.Println(sep)
		fmt.Printf("File %d of %d\n", i+1, len(filesRaw))
		fmt.Printf("  File ID:      %s\n", fileID)
		fmt.Printf("  Storage ID:   %s\n", storageID)
		fmt.Printf("  Size:         %s\n", formatFileSize(sizeBytes))
		fmt.Printf("  Chunks:       %d\n", chunkCount)
		fmt.Printf("  Type:         %s\n", passwordType)
		fmt.Printf("  Uploaded:     %s\n", uploadDate)
		fmt.Printf("  Locations:    %s\n", locationsDisplay)
	}

	return nil
}

// handleListSharesCommand lists shares owned by a specific user
func handleListSharesCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("list-shares", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to list shares for (required)")
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin list-shares --username USER [--json]

List all shares owned by a specific user.

FLAGS:
    --username USER     Username to list shares for (required)
    --json              Output as JSON
    --help              Show this help message

EXAMPLES:
    arkfile-admin list-shares --username alice12345
    arkfile-admin list-shares --username alice12345 --json
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("--username is required")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("GET", "/api/admin/users/"+*usernameFlag+"/shares", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to list shares: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	count := safeFloat64(resp.Data, "count")
	fmt.Printf("Shares for user %s (%d total):\n\n", *usernameFlag, int(count))

	sharesRaw, ok := resp.Data["shares"].([]interface{})
	if !ok || len(sharesRaw) == 0 {
		fmt.Println("  (no shares)")
		return nil
	}

	sep := strings.Repeat("-", 80)
	for i, s := range sharesRaw {
		sm := s.(map[string]interface{})
		shareID := safeString(sm, "share_id")
		fileID := safeString(sm, "file_id")
		accessCount := safeInt64(sm, "access_count")
		isRevoked := safeBool(sm, "is_revoked")
		createdAt := safeString(sm, "created_at")

		revokedStr := "No"
		if isRevoked {
			revokedStr = "Yes"
		}

		fmt.Println(sep)
		fmt.Printf("Share %d of %d\n", i+1, len(sharesRaw))
		fmt.Printf("  Share ID:   %s\n", shareID)
		fmt.Printf("  File ID:    %s\n", fileID)
		fmt.Printf("  Accesses:   %d\n", accessCount)
		fmt.Printf("  Revoked:    %s\n", revokedStr)
		fmt.Printf("  Created:    %s\n", createdAt)
	}

	return nil
}

// handleDeleteFileCommand deletes a specific file by ID
func handleDeleteFileCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("delete-file", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to delete (required)")
	confirm := fs.Bool("confirm", false, "Confirm deletion without interactive prompt (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin delete-file --file-id ID --confirm

Delete a specific file from storage and database. This also removes associated shares.
This operation is IRREVERSIBLE.

FLAGS:
    --file-id ID        File ID to delete (required)
    --confirm           Required flag to confirm this destructive operation
    --help              Show this help message

EXAMPLES:
    arkfile-admin delete-file --file-id abc-123-def --confirm
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" {
		return fmt.Errorf("--file-id is required")
	}
	if !*confirm {
		return fmt.Errorf("--confirm flag is required for this destructive operation")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("DELETE", "/api/admin/files/"+*fileID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("delete file failed: %w", err)
	}

	owner := safeString(resp.Data, "owner")
	fmt.Printf("File %s deleted successfully (owner: %s)\n", *fileID, owner)
	return nil
}

// handleRevokeShareCommand revokes a specific share by ID
func handleRevokeShareCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("revoke-share", flag.ExitOnError)
	shareID := fs.String("share-id", "", "Share ID to revoke (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin revoke-share --share-id ID

Revoke a specific share, making it inaccessible to anonymous recipients.

FLAGS:
    --share-id ID       Share ID to revoke (required)
    --help              Show this help message

EXAMPLES:
    arkfile-admin revoke-share --share-id abc123def456
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *shareID == "" {
		return fmt.Errorf("--share-id is required")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("POST", "/api/admin/shares/"+*shareID+"/revoke", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("revoke share failed: %w", err)
	}

	owner := safeString(resp.Data, "owner")
	fmt.Printf("Share %s revoked successfully (owner: %s)\n", *shareID, owner)
	return nil
}

// handleSecurityEventsCommand views recent security events
func handleSecurityEventsCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("security-events", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	limit := fs.Int("limit", 50, "Number of events to display (max 500)")
	filterType := fs.String("type", "", "Filter by event type (e.g. share_not_found, opaque_login_failure)")
	filterSeverity := fs.String("severity", "", "Filter by severity (INFO, WARNING, CRITICAL)")
	filterEntityID := fs.String("entity-id", "", "Filter by entity ID (16-char hex)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin security-events [FLAGS]

View recent security events (login attempts, rate limits, share enumeration, admin actions, etc.)

FLAGS:
    --json              Output as JSON
    --limit N           Number of events to display (default: 50, max: 500)
    --type TYPE         Filter by event type
    --severity LEVEL    Filter by severity (INFO, WARNING, CRITICAL)
    --entity-id ID      Filter by entity ID (16-char hex, from HMAC)
    --help              Show this help message

EVENT TYPES:
    opaque_login_success    Successful OPAQUE+TOTP login
    opaque_login_failure    Failed OPAQUE authentication
    share_not_found         Share ID 404 (potential enumeration)
    share_enumeration       Share ID enumeration detected (progressive penalty applied)
    invalid_download_token  Invalid download token on share chunk
    rate_limit_violation    Rate limit triggered
    suspicious_pattern      Unauthorized flood detected (10-19 bad requests in 10min window)
    endpoint_abuse          Severe abuse: share enumeration (32+ unique 404s) or
                            unauthorized flood (40+ bad requests in 10min window)
    unauthorized_access     TOTP bypass attempt
    admin_access            Admin API action
    key_health_check        Key health monitoring event

    Flood guard events (suspicious_pattern, endpoint_abuse) include
    detection_type:"unauthorized_flood" in the details JSON field.

EXAMPLES:
    arkfile-admin security-events
    arkfile-admin security-events --severity WARNING
    arkfile-admin security-events --type share_not_found --limit 100
    arkfile-admin security-events --entity-id a1b2c3d4e5f67890
    arkfile-admin security-events --json --type opaque_login_failure
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Build query parameters for filtering
	endpoint := fmt.Sprintf("/api/admin/security/events?limit=%d", *limit)
	if *filterType != "" {
		endpoint += "&type=" + *filterType
	}
	if *filterSeverity != "" {
		endpoint += "&severity=" + *filterSeverity
	}
	if *filterEntityID != "" {
		endpoint += "&entity_id=" + *filterEntityID
	}

	resp, err := client.makeRequest("GET", endpoint, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get security events: %w", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Data)
	}

	eventsRaw, ok := resp.Data["events"].([]interface{})
	if !ok || len(eventsRaw) == 0 {
		fmt.Println("No security events found")
		return nil
	}

	count := len(eventsRaw)

	// Show active filters
	filters := []string{}
	if *filterType != "" {
		filters = append(filters, "type="+*filterType)
	}
	if *filterSeverity != "" {
		filters = append(filters, "severity="+*filterSeverity)
	}
	if *filterEntityID != "" {
		filters = append(filters, "entity="+*filterEntityID)
	}

	if len(filters) > 0 {
		fmt.Printf("Security Events (%d results, filters: %s):\n\n", count, strings.Join(filters, ", "))
	} else {
		fmt.Printf("Security Events (%d results):\n\n", count)
	}

	for i := 0; i < count; i++ {
		event, ok := eventsRaw[i].(map[string]interface{})
		if !ok {
			continue
		}
		eventType := safeString(event, "event_type")
		severity := safeString(event, "severity")
		timestamp := safeString(event, "timestamp")
		entityID := safeString(event, "entity_id")
		username := safeString(event, "username")

		// Format timestamp (truncate to seconds)
		if len(timestamp) > 19 {
			timestamp = timestamp[:19]
		}

		// Severity indicator
		severityTag := ""
		switch severity {
		case "CRITICAL":
			severityTag = "[!!]"
		case "WARNING":
			severityTag = "[!] "
		default:
			severityTag = "    "
		}

		// Build event line
		fmt.Printf("  %s [%s] %-28s", severityTag, timestamp, eventType)

		if entityID != "" {
			fmt.Printf("  entity:%s", entityID)
		}
		if username != "" {
			fmt.Printf("  user:%s", username)
		}

		// Show details inline (compact)
		if details, ok := event["details"].(map[string]interface{}); ok && len(details) > 0 {
			detailParts := []string{}
			for k, v := range details {
				detailParts = append(detailParts, fmt.Sprintf("%s=%v", k, v))
			}
			if len(detailParts) > 0 {
				fmt.Printf("  {%s}", strings.Join(detailParts, ", "))
			}
		}

		fmt.Println()
	}

	return nil
}
