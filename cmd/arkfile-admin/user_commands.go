package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// handleListUsersCommand lists all users with detailed information
func handleListUsersCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("list-users", flag.ExitOnError)
	var (
		detailed     = fs.Bool("detailed", false, "Show detailed user information")
		includeAdmin = fs.Bool("include-admin", false, "Include admin users in listing")
		pendingOnly  = fs.Bool("pending", false, "Show only pending approval users")
		limit        = fs.Int("limit", 50, "Maximum number of users to list")
		offset       = fs.Int("offset", 0, "Offset for pagination")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin list-users [FLAGS]

List all users with administrative information.

FLAGS:
    --detailed          Show detailed user information
    --include-admin     Include admin users in listing
    --pending           Show only users pending approval
    --limit INT         Maximum number of users to list (default: 50)
    --offset INT        Offset for pagination (default: 0)
    --help             Show this help message

EXAMPLES:
    arkfile-admin list-users
    arkfile-admin list-users --detailed
    arkfile-admin list-users --pending
    arkfile-admin list-users --limit 10 --offset 20
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Build query parameters
	params := fmt.Sprintf("?limit=%d&offset=%d", *limit, *offset)
	if *includeAdmin {
		params += "&include_admin=true"
	}
	if *pendingOnly {
		params += "&pending_only=true"
	}

	// Request user list
	resp, err := client.makeRequest("GET", "/api/admin/users"+params, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	// Parse user list
	usersData, ok := resp.Data["users"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid user list response")
	}

	if len(usersData) == 0 {
		if *pendingOnly {
			fmt.Println("No users pending approval")
		} else {
			fmt.Println("No users found")
		}
		return nil
	}

	fmt.Printf("Users (%d total):\n\n", len(usersData))

	if *detailed {
		for i, userData := range usersData {
			userMap := userData.(map[string]interface{})
			fmt.Printf("%d. %s\n", i+1, userMap["username"])
			fmt.Printf("   Status: %s\n", statusStr(userMap))
			fmt.Printf("   Admin: %v\n", safeBool(userMap, "is_admin"))
			fmt.Printf("   TOTP: %v\n", safeBool(userMap, "totp_enabled"))
			fmt.Printf("   Files: %d\n", safeInt64(userMap, "file_count"))
			fmt.Printf("   Storage: %s / %s (%.1f%%)\n",
				formatFileSize(safeInt64(userMap, "total_storage_bytes")),
				formatFileSize(safeInt64(userMap, "storage_limit_bytes")),
				safeFloat64(userMap, "usage_percent"))
			fmt.Printf("   Registered: %s\n", safeString(userMap, "registration_date"))
			if login := safeString(userMap, "last_login"); login != "" {
				fmt.Printf("   Last Login: %s\n", login)
			}
			fmt.Println()
		}
	} else {
		for i, userData := range usersData {
			userMap := userData.(map[string]interface{})
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("USERNAME: %s\n", userMap["username"])
			fmt.Printf("  %-10s %-6s %-5s %-6s %-12s %-7s %s\n",
				"STATUS", "ADMIN", "TOTP", "FILES", "STORAGE", "USAGE", "REGISTERED")

			status := statusStr(userMap)
			adminStr := boolYesNo(safeBool(userMap, "is_admin"))
			totpStr := boolYesNo(safeBool(userMap, "totp_enabled"))
			fileCount := safeInt64(userMap, "file_count")
			storageReadable := safeString(userMap, "total_storage_readable")
			if storageReadable == "" {
				storageReadable = formatFileSize(safeInt64(userMap, "total_storage_bytes"))
			}
			usagePercent := safeFloat64(userMap, "usage_percent")
			regDate := safeString(userMap, "registration_date")

			fmt.Printf("  %-10s %-6s %-5s %-6d %-12s %-7s %s\n",
				status, adminStr, totpStr,
				fileCount, storageReadable, fmt.Sprintf("%.1f%%", usagePercent), regDate)
		}
	}

	fmt.Printf("\nShowing %d users (offset: %d)\n", len(usersData), *offset)

	return nil
}

// handleApproveUserCommand approves a pending user account
func handleApproveUserCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("approve-user", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", "", "Username to approve (required)")
		storageLimit = fs.String("storage", "", "Storage limit override (default: keep current, examples: 1GB, 500MB, 10GB)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin approve-user [FLAGS]

Approve a pending user account. Optionally set a custom storage limit.

FLAGS:
    --username USER     Username to approve (required)
    --storage LIMIT     Storage limit override (optional, default: keep current limit)
    --help             Show this help message

EXAMPLES:
    arkfile-admin approve-user --username alice12345
    arkfile-admin approve-user --username bob.123.ABC --storage 10GB
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Build approve request
	approveReq := map[string]interface{}{
		"approved_by": session.Username,
	}

	// Only include storage_limit_bytes if explicitly specified
	if *storageLimit != "" {
		limitBytes, err := parseStorageLimit(*storageLimit)
		if err != nil {
			return fmt.Errorf("invalid storage limit: %w", err)
		}
		approveReq["storage_limit_bytes"] = limitBytes
	}

	_, err = client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/approve", approveReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("user approval failed: %w", err)
	}

	fmt.Printf("User %s approved successfully\n", *usernameFlag)
	if *storageLimit != "" {
		limitBytes, _ := parseStorageLimit(*storageLimit)
		fmt.Printf("Storage limit set to: %s\n", formatFileSize(limitBytes))
	} else {
		fmt.Printf("Storage limit: default (1.1 GB)\n")
	}

	return nil
}

// handleUnapproveUserCommand revokes a user's approval and immediately terminates all active sessions.
// This is the correct way to prevent a previously-approved user from continuing to use the site:
// setting is_approved=false alone does not invalidate JWTs that are already in flight.
func handleUnapproveUserCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("unapprove-user", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to unapprove (required)")
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin unapprove-user --username USER [--confirm]

Revoke a user's approval status and force-logout all active sessions.
The user will be unable to perform any authenticated actions immediately.
Use 'approve-user' to re-approve the account later if needed.

FLAGS:
    --username USER     Username to unapprove (required)
    --confirm           Confirm without interactive prompt
    --help              Show this help message

EXAMPLES:
    arkfile-admin unapprove-user --username alice12345
    arkfile-admin unapprove-user --username alice12345 --confirm
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

	if !*confirm {
		fmt.Printf("Unapprove user '%s' and terminate all active sessions? (yes/no): ", *usernameFlag)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if r := strings.TrimSpace(strings.ToLower(response)); r != "yes" && r != "y" {
			fmt.Println("Unapprove cancelled")
			return nil
		}
	}

	// Step 1: Revoke approval and terminate sessions in one server call.
	_, err = client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/revoke", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to unapprove user: %w", err)
	}
	fmt.Printf("User %s approval revoked\n", *usernameFlag)
	fmt.Printf("User %s sessions terminated (all tokens revoked)\n", *usernameFlag)
	return nil
}

// handleRevokeUserCommand revokes user access and terminates all active sessions.
func handleRevokeUserCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("revoke-user", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", "", "Username to revoke (required)")
		confirm      = fs.Bool("confirm", false, "Confirm revocation without prompt")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin revoke-user [FLAGS]

Revoke user access and disable account. All active sessions are terminated immediately.

FLAGS:
    --username USER     Username to revoke (required)
    --confirm           Confirm revocation without interactive prompt
    --help             Show this help message

EXAMPLES:
    arkfile-admin revoke-user --username alice12345
    arkfile-admin revoke-user --username bob.123.ABC --confirm
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Confirm revocation if not already confirmed
	if !*confirm {
		fmt.Printf("Are you sure you want to revoke access for user '%s'? (yes/no): ", *usernameFlag)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))

		if response != "yes" && response != "y" {
			fmt.Println("User revocation cancelled")
			return nil
		}
	}

	// Revoke user (unapprove and terminate sessions via canonical endpoint).
	_, err = client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/revoke", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("user revocation failed: %w", err)
	}
	fmt.Printf("User %s access revoked successfully\n", *usernameFlag)
	fmt.Printf("User %s sessions terminated (all tokens revoked)\n", *usernameFlag)
	return nil
}

// handleUserStatusCommand gets the status of a specific user
func handleUserStatusCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("user-status", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", "", "Username to check status for (required)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin user-status [FLAGS]

Get the status and details of a specific user account.

FLAGS:
    --username USER     Username to check (required)
    --help             Show this help message

EXAMPLES:
    arkfile-admin user-status --username alice12345
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Get user status
	resp, err := client.makeRequest("GET", "/api/admin/users/"+*usernameFlag+"/status", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get user status: %w", err)
	}

	// Display user status from nested response structure
	data := resp.Data

	// Top-level fields
	exists := false
	if v, ok := data["exists"].(bool); ok {
		exists = v
	}

	fmt.Printf("User Status: %s\n", *usernameFlag)
	fmt.Println("--------------------------")

	if !exists {
		fmt.Printf("Exists:          No\n")
		return nil
	}

	// Parse nested "user" object
	username := *usernameFlag
	isAdmin := false
	isApproved := false
	createdAt := ""
	if userObj, ok := data["user"].(map[string]interface{}); ok {
		if v, ok := userObj["username"].(string); ok {
			username = v
		}
		if v, ok := userObj["is_admin"].(bool); ok {
			isAdmin = v
		}
		if v, ok := userObj["is_approved"].(bool); ok {
			isApproved = v
		}
		if v, ok := userObj["created_at"].(string); ok {
			createdAt = v
		}
	}

	// Format created_at for display
	createdFormatted := createdAt
	if createdAt != "" {
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			createdFormatted = t.Format("2006-01-02 15:04:05")
		} else if t, err := time.Parse("2006-01-02T15:04:05Z", createdAt); err == nil {
			createdFormatted = t.Format("2006-01-02 15:04:05")
		}
	}

	fmt.Printf("Username:        %s\n", username)
	fmt.Printf("Exists:          Yes\n")
	fmt.Printf("Admin:           %s\n", boolYesNo(isAdmin))
	fmt.Printf("Approved:        %s\n", boolYesNo(isApproved))
	if createdFormatted != "" {
		fmt.Printf("Created:         %s\n", createdFormatted)
	}

	// Parse nested "totp" object
	if totpObj, ok := data["totp"].(map[string]interface{}); ok {
		fmt.Printf("\nTOTP Status\n")
		fmt.Println("--------------------------")
		present, _ := totpObj["present"].(bool)
		decryptable, _ := totpObj["decryptable"].(bool)
		enabled, _ := totpObj["enabled"].(bool)
		setupCompleted, _ := totpObj["setup_completed"].(bool)
		fmt.Printf("Present:         %s\n", boolYesNo(present))
		fmt.Printf("Decryptable:     %s\n", boolYesNo(decryptable))
		fmt.Printf("Enabled:         %s\n", boolYesNo(enabled))
		fmt.Printf("Setup Completed: %s\n", boolYesNo(setupCompleted))
	}

	// Parse nested "opaque" object
	if opaqueObj, ok := data["opaque"].(map[string]interface{}); ok {
		fmt.Printf("\nOPAQUE Status\n")
		fmt.Println("--------------------------")
		hasAccount, _ := opaqueObj["has_account"].(bool)
		fmt.Printf("Has Account:     %s\n", boolYesNo(hasAccount))
	}

	// Parse nested "tokens" object
	if tokensObj, ok := data["tokens"].(map[string]interface{}); ok {
		fmt.Printf("\nTokens\n")
		fmt.Println("--------------------------")
		activeRefresh := int(0)
		if v, ok := tokensObj["active_refresh_tokens"].(float64); ok {
			activeRefresh = int(v)
		}
		revoked := int(0)
		if v, ok := tokensObj["revoked_tokens"].(float64); ok {
			revoked = int(v)
		}
		fmt.Printf("Active Refresh:  %d\n", activeRefresh)
		fmt.Printf("Revoked:         %d\n", revoked)
	}

	return nil
}

// handleUserContactInfoCommand views a user's contact information
func handleUserContactInfoCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("user-contact-info", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to view contact info for (required)")
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin user-contact-info --username USER [--json]

View a user's contact information (decrypted server-side).

FLAGS:
    --username USER     Username to view contact info for (required)
    --json              Output as JSON
    --help             Show this help message

EXAMPLES:
    arkfile-admin user-contact-info --username alice12345
    arkfile-admin user-contact-info --username alice12345 --json
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

	resp, err := client.makeRequest("GET", "/api/admin/users/"+*usernameFlag+"/contact-info", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get contact info: %w", err)
	}

	hasInfo, _ := resp.Data["has_contact_info"].(bool)
	if !hasInfo {
		fmt.Printf("No contact information set for %s\n", *usernameFlag)
		return nil
	}

	contactInfoRaw, ok := resp.Data["contact_info"]
	if !ok {
		return fmt.Errorf("invalid response: missing contact_info")
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(contactInfoRaw)
	}

	// Re-marshal and unmarshal for typed access
	infoJSON, err := json.Marshal(contactInfoRaw)
	if err != nil {
		return fmt.Errorf("failed to parse contact info: %w", err)
	}

	var info struct {
		DisplayName string `json:"display_name"`
		Contacts    []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
			Label string `json:"label,omitempty"`
		} `json:"contacts"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(infoJSON, &info); err != nil {
		return fmt.Errorf("failed to parse contact info: %w", err)
	}

	fmt.Printf("Contact Information for %s\n", *usernameFlag)
	fmt.Println("--------------------------")
	fmt.Printf("  Display Name: %s\n", info.DisplayName)

	if len(info.Contacts) > 0 {
		fmt.Println("  Contacts:")
		for i, c := range info.Contacts {
			label := c.Type
			if c.Type == "other" && c.Label != "" {
				label = c.Label
			}
			fmt.Printf("    [%d] %s: %s\n", i+1, label, c.Value)
		}
	} else {
		fmt.Println("  Contacts: (none)")
	}

	if info.Notes != "" {
		fmt.Printf("  Notes: %s\n", info.Notes)
	}

	return nil
}

// handleSetStorageCommand sets user storage limits
func handleSetStorageCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("set-storage", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", "", "Username to modify (required)")
		storageLimit = fs.String("limit", "", "New storage limit (required, examples: 1GB, 500MB, 10GB)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin set-storage [FLAGS]

Set or modify user storage limits.

FLAGS:
    --username USER     Username to modify (required)
    --limit LIMIT       New storage limit (required, examples: 1GB, 500MB, 10GB)
    --help             Show this help message

EXAMPLES:
    arkfile-admin set-storage --username alice12345 --limit 10GB
    arkfile-admin set-storage --username bob.123.ABC --limit 500MB
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}
	if *storageLimit == "" {
		return fmt.Errorf("storage limit is required")
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Parse storage limit
	limitBytes, err := parseStorageLimit(*storageLimit)
	if err != nil {
		return fmt.Errorf("invalid storage limit: %w", err)
	}

	// Set storage limit
	storageReq := map[string]interface{}{
		"storage_limit_bytes": limitBytes,
	}

	_, err = client.makeRequest("PUT", "/api/admin/users/"+*usernameFlag+"/storage", storageReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("storage limit update failed: %w", err)
	}

	fmt.Printf("Storage limit updated for user %s\n", *usernameFlag)
	fmt.Printf("New limit: %s\n", formatFileSize(limitBytes))

	return nil
}

// handleExportFileCommand exports a user's encrypted file as a .arkbackup bundle.
// Uses the admin export endpoint which can export any user's file.
// The admin CANNOT decrypt the bundle (they don't know the user's password).

// handleUpdateUserCommand updates user properties (admin, approved, storage)
func handleUpdateUserCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("update-user", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to update (required)")
	isApproved := fs.String("is-approved", "", "Set approved status (true/false)")
	isAdmin := fs.String("is-admin", "", "Set admin status (true/false)")
	storageLimit := fs.String("storage-limit", "", "Set storage limit (e.g. 5GB, 500MB)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin update-user --username USER [FLAGS]

Update user properties. At least one property flag must be provided.

FLAGS:
    --username USER         Username to update (required)
    --is-approved BOOL      Set approved status (true/false)
    --is-admin BOOL         Set admin status (true/false)
    --storage-limit LIMIT   Set storage limit (e.g. 5GB, 500MB)
    --help                  Show this help message

EXAMPLES:
    arkfile-admin update-user --username alice12345 --is-admin true
    arkfile-admin update-user --username alice12345 --is-approved false
    arkfile-admin update-user --username alice12345 --storage-limit 10GB
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("--username is required")
	}

	if *isApproved == "" && *isAdmin == "" && *storageLimit == "" {
		return fmt.Errorf("at least one of --is-approved, --is-admin, or --storage-limit is required")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	payload := make(map[string]interface{})
	if *isApproved != "" {
		b := strings.ToLower(*isApproved) == "true"
		payload["is_approved"] = b
	}
	if *isAdmin != "" {
		b := strings.ToLower(*isAdmin) == "true"
		payload["is_admin"] = b
	}
	if *storageLimit != "" {
		limitBytes, err := parseStorageLimit(*storageLimit)
		if err != nil {
			return fmt.Errorf("invalid storage limit: %w", err)
		}
		payload["storage_limit_bytes"] = limitBytes
	}

	_, err = client.makeRequest("PUT", "/api/admin/users/"+*usernameFlag, payload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("update user failed: %w", err)
	}

	fmt.Printf("User %s updated successfully\n", *usernameFlag)
	return nil
}

// handleDeleteUserCommand deletes a user and all associated data
func handleDeleteUserCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("delete-user", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to delete (required)")
	confirm := fs.Bool("confirm", false, "Confirm deletion without interactive prompt (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin delete-user --username USER --confirm

Permanently delete a user and all associated data (files, shares, metadata).
This operation is IRREVERSIBLE.

FLAGS:
    --username USER     Username to delete (required)
    --confirm           Required flag to confirm this destructive operation
    --help              Show this help message

EXAMPLES:
    arkfile-admin delete-user --username alice12345 --confirm
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("--username is required")
	}
	if !*confirm {
		return fmt.Errorf("--confirm flag is required for this destructive operation")
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	_, err = client.makeRequest("DELETE", "/api/admin/users/"+*usernameFlag, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("delete user failed: %w", err)
	}

	fmt.Printf("User %s deleted successfully (all files, shares, and metadata removed)\n", *usernameFlag)
	return nil
}

// handleForceLogoutCommand forces a user logout by revoking all their tokens
func handleForceLogoutCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("force-logout", flag.ExitOnError)
	usernameFlag := fs.String("username", "", "Username to force-logout (required)")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin force-logout --username USER

Force-logout a user by revoking all their JWT and refresh tokens.
Use for incident response when a session may be compromised.

FLAGS:
    --username USER     Username to force-logout (required)
    --help              Show this help message

EXAMPLES:
    arkfile-admin force-logout --username alice12345
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

	_, err = client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/force-logout", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("force logout failed: %w", err)
	}

	fmt.Printf("User %s has been force-logged out (all tokens revoked)\n", *usernameFlag)
	return nil
}

// handleListFilesCommand lists files owned by a specific user
