// arkfile-admin - Local system maintenance and monitoring tool
// This tool provides local administrative functions for system operations without network access

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

const (
	Version = "1.0.0-static"
	Usage   = `arkfile-admin - Hybrid network/local admin tool for arkfile server management

USAGE:
    arkfile-admin [global options] command [command options] [arguments...]

NETWORK COMMANDS (Admin API - localhost only):
    login             Admin login via OPAQUE+TOTP authentication
    logout            Clear admin session
    list-users        List all users (dev-test env only)
    approve-user      Approve user account (dev-test env only)
    set-storage       Set user storage limit (via credits API)

LOCAL COMMANDS (Direct system access - server endpoints not yet available):
    backup            Create system backup (local implementation)
    restore           Restore from backup (local implementation)
    monitor           Performance monitoring (local implementation)
    audit             Security audit (local implementation)
    key-rotation      Rotate cryptographic keys (local implementation)
    health-check      System health check (local implementation)
    system-status     System status overview (local implementation)
    version           Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL for network commands (default: https://localhost:4443)
    --base-dir DIR      Installation directory for local commands (default: /opt/arkfile)
    --config FILE       Configuration file path
    --username USER     Admin username for authentication
    --verbose, -v       Verbose output
    --help, -h          Show help

EXAMPLES:
    # Network-based admin operations:
    arkfile-admin login --username admin
    arkfile-admin list-users
    arkfile-admin approve-user --username alice
    
    # Local system operations:
    arkfile-admin backup --output backup.tar.gz
    arkfile-admin health-check --detailed
    arkfile-admin key-rotation --type jwt
`
)

var verbose bool

// AdminConfig holds configuration for the admin client
type AdminConfig struct {
	ServerURL     string `json:"server_url"`
	Username      string `json:"username"`
	TLSInsecure   bool   `json:"tls_insecure"`
	TLSMinVersion uint16 `json:"tls_min_version"`
	TokenFile     string `json:"token_file"`
	ConfigFile    string `json:"config_file"`
}

// AdminSession holds admin authentication session data
type AdminSession struct {
	Username       string    `json:"username"`
	AccessToken    string    `json:"access_token"`
	RefreshToken   string    `json:"refresh_token"`
	ExpiresAt      time.Time `json:"expires_at"`
	OPAQUEExport   string    `json:"opaque_export"`
	ServerURL      string    `json:"server_url"`
	SessionCreated time.Time `json:"session_created"`
	IsAdmin        bool      `json:"is_admin"`
}

// HTTPClient wraps http.Client with additional functionality
type HTTPClient struct {
	client  *http.Client
	baseURL string
	verbose bool
}

// Response represents a generic API response
type Response struct {
	Success      bool                   `json:"success"`
	Message      string                 `json:"message"`
	Data         map[string]interface{} `json:"data"`
	Error        string                 `json:"error"`
	TempToken    string                 `json:"temp_token"`
	SessionKey   string                 `json:"session_key"`
	RequiresTOTP bool                   `json:"requires_totp"`
	Token        string                 `json:"token"`
	RefreshToken string                 `json:"refresh_token"`
	ExpiresAt    time.Time              `json:"expires_at"`
	OPAQUEExport string                 `json:"opaque_export"`
}

// User represents user information
type User struct {
	Username          string    `json:"username"`
	IsAdmin           bool      `json:"is_admin"`
	IsApproved        bool      `json:"is_approved"`
	StorageLimitBytes int64     `json:"storage_limit_bytes"`
	TotalStorageBytes int64     `json:"total_storage_bytes"`
	CreatedAt         time.Time `json:"created_at"`
	LastLoginAt       time.Time `json:"last_login_at"`
	TOTPEnabled       bool      `json:"totp_enabled"`
}

func main() {
	// Global flags
	var (
		serverURL   = flag.String("server-url", "https://localhost:4443", "Server URL")
		configFile  = flag.String("config", "", "Configuration file path")
		tlsInsecure = flag.Bool("tls-insecure", false, "Skip TLS certificate verification (localhost only)")
		username    = flag.String("username", "", "Admin username for authentication")
		verboseFlag = flag.Bool("verbose", false, "Verbose output")
		vFlag       = flag.Bool("v", false, "Verbose output (short)")
		helpFlag    = flag.Bool("help", false, "Show help information")
		hFlag       = flag.Bool("h", false, "Show help information (short)")
		versionFlag = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	verbose = *verboseFlag || *vFlag

	if *versionFlag {
		printVersion()
		return
	}

	if *helpFlag || *hFlag || flag.NArg() == 0 {
		printUsage()
		return
	}

	// Load configuration
	config := &AdminConfig{
		ServerURL:   *serverURL,
		Username:    *username,
		TLSInsecure: *tlsInsecure,
		ConfigFile:  *configFile,
		TokenFile:   getAdminSessionFilePath(),
	}

	// Force TLS 1.3 only for maximum security
	config.TLSMinVersion = tls.VersionTLS13

	// Load config file if specified
	if *configFile != "" {
		if err := loadConfigFile(config, *configFile); err != nil {
			logError("Failed to load config file: %v", err)
			os.Exit(1)
		}
	}

	// Create HTTP client
	client := newHTTPClient(config.ServerURL, config.TLSInsecure, config.TLSMinVersion, verbose)

	// Parse command
	command := flag.Arg(0)
	args := flag.Args()[1:]

	// Execute command - route to network or local implementation
	switch command {
	// Network-based commands (use admin API)
	case "login":
		if err := handleLoginCommand(client, config, args); err != nil {
			logError("Login failed: %v", err)
			os.Exit(1)
		}
	case "logout":
		if err := handleLogoutCommand(config, args); err != nil {
			logError("Logout failed: %v", err)
			os.Exit(1)
		}
	case "list-users":
		fmt.Printf("Dev-test environment only - using network implementation\n")
		if err := handleListUsersCommand(client, config, args); err != nil {
			logError("List users failed: %v", err)
			os.Exit(1)
		}
	case "approve-user":
		fmt.Printf("Dev-test environment only - using network implementation\n")
		if err := handleApproveUserCommand(client, config, args); err != nil {
			logError("Approve user failed: %v", err)
			os.Exit(1)
		}
	case "set-storage":
		if err := handleSetStorageCommand(client, config, args); err != nil {
			logError("Set storage failed: %v", err)
			os.Exit(1)
		}

	// Network-based system monitoring commands
	case "system-status":
		if err := handleSystemStatusCommand(client, config, args); err != nil {
			logError("System status failed: %v", err)
			os.Exit(1)
		}
	case "health-check":
		if err := handleHealthCheckCommand(client, config, args); err != nil {
			logError("Health check failed: %v", err)
			os.Exit(1)
		}

	// Local commands (server endpoints not yet available)
	case "backup":
		fmt.Printf("Using local implementation - server endpoint not yet available\n")
		if err := handleBackupCommand(config, args); err != nil {
			logError("Backup failed: %v", err)
			os.Exit(1)
		}
	case "restore":
		fmt.Printf("Using local implementation - server endpoint not yet available\n")
		if err := handleRestoreCommand(config, args); err != nil {
			logError("Restore failed: %v", err)
			os.Exit(1)
		}
	case "monitor":
		fmt.Printf("Using local implementation - server endpoint not yet available\n")
		if err := handleMonitorCommand(config, args); err != nil {
			logError("Monitor failed: %v", err)
			os.Exit(1)
		}
	case "audit":
		fmt.Printf("Using local implementation - server endpoint not yet available\n")
		if err := handleAuditCommand(config, args); err != nil {
			logError("Audit failed: %v", err)
			os.Exit(1)
		}
	case "key-rotation":
		fmt.Printf("Using local implementation - server endpoint not yet available\n")
		if err := handleKeyRotationCommand(client, config, args); err != nil {
			logError("Key rotation failed: %v", err)
			os.Exit(1)
		}

	// Legacy commands that were removed from network - keeping for compatibility
	case "revoke-user":
		fmt.Printf("Command deprecated - use network API when available\n")
		if err := handleRevokeUserCommand(client, config, args); err != nil {
			logError("Revoke user failed: %v", err)
			os.Exit(1)
		}

	case "version":
		printVersion()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

// newHTTPClient creates a new HTTP client with appropriate TLS configuration
func newHTTPClient(baseURL string, tlsInsecure bool, tlsMinVersion uint16, verbose bool) *HTTPClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsInsecure,
			MinVersion:         tlsMinVersion,
		},
	}

	return &HTTPClient{
		client:  &http.Client{Transport: tr, Timeout: 30 * time.Second},
		baseURL: strings.TrimSuffix(baseURL, "/"),
		verbose: verbose,
	}
}

// makeRequest makes an HTTP request with proper error handling
func (c *HTTPClient) makeRequest(method, endpoint string, payload interface{}, token string) (*Response, error) {
	url := c.baseURL + endpoint

	var body io.Reader
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if c.verbose {
		logVerbose("Making %s request to %s", method, url)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if c.verbose {
		logVerbose("Response status: %d", resp.StatusCode)
		logVerbose("Response body: %s", string(responseData))
	}

	var apiResp Response
	if err := json.Unmarshal(responseData, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return &apiResp, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiResp.Error)
	}

	return &apiResp, nil
}

// handleLoginCommand processes admin login command
func handleLoginCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", config.Username, "Admin username for login")
		saveSession  = fs.Bool("save-session", true, "Save session for future use")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin login [FLAGS]

Authenticate as administrator using OPAQUE protocol.

FLAGS:
    --username USER     Admin username for authentication (required)
    --save-session      Save session for future use (default: true)
    --help             Show this help message

EXAMPLES:
    arkfile-admin login --username admin
    arkfile-admin login --username root --save-session=false
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("admin username is required")
	}

	// Get password securely
	fmt.Printf("Enter admin password for %s: ", *usernameFlag)
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Perform OPAQUE login with admin verification
	logVerbose("Starting OPAQUE authentication for admin user: %s", *usernameFlag)

	loginReq := map[string]string{
		"username": *usernameFlag,
		"password": string(password),
	}

	loginResp, err := client.makeRequest("POST", "/api/admin/login", loginReq, "")
	if err != nil {
		return fmt.Errorf("admin login failed: %w", err)
	}

	// Handle TOTP requirement
	if loginResp.RequiresTOTP {
		fmt.Print("Enter TOTP code: ")
		reader := bufio.NewReader(os.Stdin)
		totpCode, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read TOTP code: %w", err)
		}
		totpCode = strings.TrimSpace(totpCode)

		totpReq := map[string]interface{}{
			"code":        totpCode,
			"session_key": loginResp.SessionKey,
			"is_backup":   false,
		}

		totpResp, err := client.makeRequest("POST", "/api/totp/auth", totpReq, loginResp.TempToken)
		if err != nil {
			return fmt.Errorf("TOTP authentication failed: %w", err)
		}

		// Update response with final tokens
		loginResp.Token = totpResp.Token
		loginResp.RefreshToken = totpResp.RefreshToken
		loginResp.ExpiresAt = totpResp.ExpiresAt
		loginResp.OPAQUEExport = totpResp.OPAQUEExport
	}

	// Create admin session
	session := &AdminSession{
		Username:       *usernameFlag,
		AccessToken:    loginResp.Token,
		RefreshToken:   loginResp.RefreshToken,
		ExpiresAt:      loginResp.ExpiresAt,
		OPAQUEExport:   loginResp.OPAQUEExport,
		ServerURL:      config.ServerURL,
		SessionCreated: time.Now(),
		IsAdmin:        true,
	}

	// Save session if requested
	if *saveSession {
		if err := saveAdminSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save admin session: %v", err)
		} else {
			logVerbose("Admin session saved to: %s", config.TokenFile)
		}
	}

	fmt.Printf("Admin login successful for user: %s\n", *usernameFlag)
	fmt.Printf("Session expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Administrative privileges active\n")

	return nil
}

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
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
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

	fmt.Printf("Users (%d found):\n\n", len(usersData))

	if *detailed {
		for i, userData := range usersData {
			userMap := userData.(map[string]interface{})
			fmt.Printf("%d. %s\n", i+1, userMap["username"])
			fmt.Printf("   Admin: %v\n", userMap["is_admin"])
			fmt.Printf("   Approved: %v\n", userMap["is_approved"])
			fmt.Printf("   TOTP: %v\n", userMap["totp_enabled"])
			fmt.Printf("   Storage: %s / %s\n",
				formatFileSize(int64(userMap["total_storage_bytes"].(float64))),
				formatFileSize(int64(userMap["storage_limit_bytes"].(float64))))
			fmt.Printf("   Created: %s\n", userMap["created_at"])
			if userMap["last_login_at"] != nil {
				fmt.Printf("   Last Login: %s\n", userMap["last_login_at"])
			}
			fmt.Println()
		}
	} else {
		fmt.Printf("%-3s %-20s %-8s %-8s %-6s %-15s %s\n",
			"#", "Username", "Admin", "Approved", "TOTP", "Storage", "Created")
		fmt.Println(strings.Repeat("-", 80))

		for i, userData := range usersData {
			userMap := userData.(map[string]interface{})
			adminStr := "No"
			if userMap["is_admin"].(bool) {
				adminStr = "Yes"
			}
			approvedStr := "No"
			if userMap["is_approved"].(bool) {
				approvedStr = "Yes"
			}
			totpStr := "No"
			if userMap["totp_enabled"].(bool) {
				totpStr = "Yes"
			}
			storageUsed := formatFileSize(int64(userMap["total_storage_bytes"].(float64)))

			fmt.Printf("%-3d %-20s %-8s %-8s %-6s %-15s %s\n",
				i+1, userMap["username"], adminStr, approvedStr, totpStr,
				storageUsed, userMap["created_at"])
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
		storageLimit = fs.String("storage", "5GB", "Storage limit for the user")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin approve-user [FLAGS]

Approve a pending user account and set storage limits.

FLAGS:
    --username USER     Username to approve (required)
    --storage LIMIT     Storage limit (default: 5GB, examples: 1GB, 500MB, 10GB)
    --help             Show this help message

EXAMPLES:
    arkfile-admin approve-user --username alice
    arkfile-admin approve-user --username bob --storage 10GB
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	// Load admin session
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	// Parse storage limit
	limitBytes, err := parseStorageLimit(*storageLimit)
	if err != nil {
		return fmt.Errorf("invalid storage limit: %w", err)
	}

	// Approve user
	approveReq := map[string]interface{}{
		"storage_limit_bytes": limitBytes,
	}

	_, err = client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/approve", approveReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("user approval failed: %w", err)
	}

	fmt.Printf("User %s approved successfully\n", *usernameFlag)
	fmt.Printf("Storage limit set to: %s\n", formatFileSize(limitBytes))

	return nil
}

// handleRevokeUserCommand revokes user access
func handleRevokeUserCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("revoke-user", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", "", "Username to revoke (required)")
		confirm      = fs.Bool("confirm", false, "Confirm revocation without prompt")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin revoke-user [FLAGS]

Revoke user access and disable account.

FLAGS:
    --username USER     Username to revoke (required)
    --confirm           Confirm revocation without interactive prompt
    --help             Show this help message

EXAMPLES:
    arkfile-admin revoke-user --username alice
    arkfile-admin revoke-user --username bob --confirm
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	// Load admin session
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
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

	// Revoke user
	_, err = client.makeRequest("POST", "/api/admin/users/"+*usernameFlag+"/revoke", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("user revocation failed: %w", err)
	}

	fmt.Printf("User %s access revoked successfully\n", *usernameFlag)

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
    arkfile-admin set-storage --username alice --limit 10GB
    arkfile-admin set-storage --username bob --limit 500MB
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
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
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

// handleSystemStatusCommand shows system status and metrics
func handleSystemStatusCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("system-status", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin system-status

Show system status, metrics, and health information.

EXAMPLES:
    arkfile-admin system-status
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load admin session
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	// Get system status
	resp, err := client.makeRequest("GET", "/api/admin/system/status", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get system status: %w", err)
	}

	// Display system status
	status := resp.Data
	fmt.Printf("System Status\n")
	fmt.Printf("================\n\n")

	if uptime, ok := status["uptime"].(string); ok {
		fmt.Printf("Uptime: %s\n", uptime)
	}
	if version, ok := status["version"].(string); ok {
		fmt.Printf("Version: %s\n", version)
	}
	if goVersion, ok := status["go_version"].(string); ok {
		fmt.Printf("Go Version: %s\n", goVersion)
	}

	fmt.Printf("\nStorage Statistics\n")
	fmt.Printf("====================\n")
	if storage, ok := status["storage"].(map[string]interface{}); ok {
		if totalFiles, ok := storage["total_files"].(float64); ok {
			fmt.Printf("Total Files: %.0f\n", totalFiles)
		}
		if totalSize, ok := storage["total_size_bytes"].(float64); ok {
			fmt.Printf("Total Size: %s\n", formatFileSize(int64(totalSize)))
		}
		if avgFileSize, ok := storage["average_file_size_bytes"].(float64); ok {
			fmt.Printf("Average File Size: %s\n", formatFileSize(int64(avgFileSize)))
		}
	}

	fmt.Printf("\nUser Statistics\n")
	fmt.Printf("=================\n")
	if users, ok := status["users"].(map[string]interface{}); ok {
		if totalUsers, ok := users["total_users"].(float64); ok {
			fmt.Printf("Total Users: %.0f\n", totalUsers)
		}
		if activeUsers, ok := users["active_users"].(float64); ok {
			fmt.Printf("Active Users: %.0f\n", activeUsers)
		}
		if adminUsers, ok := users["admin_users"].(float64); ok {
			fmt.Printf("Admin Users: %.0f\n", adminUsers)
		}
		if pendingUsers, ok := users["pending_approval"].(float64); ok {
			fmt.Printf("Pending Approval: %.0f\n", pendingUsers)
		}
	}

	fmt.Printf("\nSecurity Status\n")
	fmt.Printf("=================\n")
	if security, ok := status["security"].(map[string]interface{}); ok {
		if totpUsers, ok := security["totp_enabled_users"].(float64); ok {
			fmt.Printf("TOTP Enabled Users: %.0f\n", totpUsers)
		}
		if lastKeyRotation, ok := security["last_key_rotation"].(string); ok {
			fmt.Printf("Last Key Rotation: %s\n", lastKeyRotation)
		}
	}

	return nil
}

// handleKeyRotationCommand handles key rotation operations
func handleKeyRotationCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("key-rotation", flag.ExitOnError)
	var (
		keyType = fs.String("type", "", "Key type to rotate: jwt, opaque, totp (required)")
		force   = fs.Bool("force", false, "Force rotation without confirmation")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin key-rotation [FLAGS]

Perform cryptographic key rotation operations.

FLAGS:
    --type TYPE         Key type to rotate: jwt, opaque, totp (required)
    --force            Force rotation without confirmation prompt
    --help             Show this help message

EXAMPLES:
    arkfile-admin key-rotation --type jwt
    arkfile-admin key-rotation --type opaque --force
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyType == "" {
		return fmt.Errorf("key type is required (jwt, opaque, totp)")
	}

	if *keyType != "jwt" && *keyType != "opaque" && *keyType != "totp" {
		return fmt.Errorf("invalid key type: %s (must be jwt, opaque, or totp)", *keyType)
	}

	// Load admin session
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	// Confirm rotation if not forced
	if !*force {
		fmt.Printf("Warning: Key rotation will invalidate existing sessions and may require user re-authentication.\n")
		fmt.Printf("Are you sure you want to rotate %s keys? (yes/no): ", *keyType)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))

		if response != "yes" && response != "y" {
			fmt.Println("Key rotation cancelled")
			return nil
		}
	}

	// Perform key rotation
	rotationReq := map[string]interface{}{
		"key_type": *keyType,
	}

	resp, err := client.makeRequest("POST", "/api/admin/system/rotate-keys", rotationReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}

	fmt.Printf("%s key rotation completed successfully\n", strings.ToUpper(*keyType))
	if message, ok := resp.Data["message"].(string); ok {
		fmt.Printf("Details: %s\n", message)
	}

	return nil
}

// handleHealthCheckCommand performs comprehensive system health check
func handleHealthCheckCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("health-check", flag.ExitOnError)
	var (
		detailed = fs.Bool("detailed", false, "Show detailed health information")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin health-check [FLAGS]

Perform comprehensive system health check.

FLAGS:
    --detailed          Show detailed health information
    --help             Show this help message

EXAMPLES:
    arkfile-admin health-check
    arkfile-admin health-check --detailed
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load admin session
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in as admin (use 'arkfile-admin login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("admin session expired, please login again")
	}

	// Perform health check
	params := ""
	if *detailed {
		params = "?detailed=true"
	}

	resp, err := client.makeRequest("GET", "/api/admin/system/health"+params, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	// Display health results
	health := resp.Data
	fmt.Printf("System Health Check\n")
	fmt.Printf("=====================\n\n")

	if overall, ok := health["overall_status"].(string); ok {
		statusIcon := "OK"
		if overall != "healthy" {
			statusIcon = "[X]"
		}
		fmt.Printf("Overall Status: %s %s\n\n", statusIcon, strings.ToUpper(overall))
	}

	// Display component health
	if components, ok := health["components"].(map[string]interface{}); ok {
		fmt.Printf("Component Health:\n")
		fmt.Printf("-----------------\n")

		for component, status := range components {
			statusMap := status.(map[string]interface{})
			statusStr := statusMap["status"].(string)
			statusIcon := "OK"
			if statusStr != "healthy" {
				statusIcon = "[X]"
			}

			fmt.Printf("%-15s %s %s", component+":", statusIcon, statusStr)

			if *detailed {
				if message, ok := statusMap["message"].(string); ok && message != "" {
					fmt.Printf(" - %s", message)
				}
			}
			fmt.Println()
		}
	}

	return nil
}

// handleLogoutCommand processes admin logout command
func handleLogoutCommand(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin logout

Clear the saved admin session and logout.

EXAMPLES:
    arkfile-admin logout
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Remove admin session file
	if err := os.Remove(config.TokenFile); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove admin session file: %w", err)
		}
	}

	fmt.Printf("Admin logout successful\n")
	return nil
}

// Helper functions

func printVersion() {
	fmt.Printf("arkfile-admin version %s\n", Version)
	fmt.Printf("Administrative tool for arkfile server management\n")
}

func printUsage() {
	fmt.Print(Usage)
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Printf("[VERBOSE] "+format+"\n", args...)
	}
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

func getAdminSessionFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".arkfile-admin-session.json"
	}
	return filepath.Join(homeDir, ".arkfile-admin-session.json")
}

func saveAdminSession(session *AdminSession, filePath string) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

func loadAdminSession(filePath string) (*AdminSession, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var session AdminSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func loadConfigFile(config *AdminConfig, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, config)
}

func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	if exp >= len(units) {
		return fmt.Sprintf("%d B", bytes)
	}

	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

func parseStorageLimit(limit string) (int64, error) {
	limit = strings.ToUpper(strings.TrimSpace(limit))

	// Extract numeric part and unit
	var value float64
	var unit string

	if strings.HasSuffix(limit, "GB") {
		unit = "GB"
		if _, err := fmt.Sscanf(limit, "%fGB", &value); err != nil {
			return 0, fmt.Errorf("invalid GB format: %s", limit)
		}
	} else if strings.HasSuffix(limit, "MB") {
		unit = "MB"
		if _, err := fmt.Sscanf(limit, "%fMB", &value); err != nil {
			return 0, fmt.Errorf("invalid MB format: %s", limit)
		}
	} else if strings.HasSuffix(limit, "KB") {
		unit = "KB"
		if _, err := fmt.Sscanf(limit, "%fKB", &value); err != nil {
			return 0, fmt.Errorf("invalid KB format: %s", limit)
		}
	} else if strings.HasSuffix(limit, "B") {
		unit = "B"
		if _, err := fmt.Sscanf(limit, "%fB", &value); err != nil {
			return 0, fmt.Errorf("invalid B format: %s", limit)
		}
	} else {
		return 0, fmt.Errorf("invalid storage limit format: %s (use GB, MB, KB, or B)", limit)
	}

	if value < 0 {
		return 0, fmt.Errorf("storage limit cannot be negative")
	}

	// Convert to bytes
	var bytes int64
	switch unit {
	case "GB":
		bytes = int64(value * 1024 * 1024 * 1024)
	case "MB":
		bytes = int64(value * 1024 * 1024)
	case "KB":
		bytes = int64(value * 1024)
	case "B":
		bytes = int64(value)
	}

	return bytes, nil
}

// Local command handlers (using local file system access)

// handleBackupCommand creates a system backup
func handleBackupCommand(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	var (
		output  = fs.String("output", "arkfile-backup.tar.gz", "Output backup file")
		baseDir = fs.String("base-dir", "/opt/arkfile", "Installation base directory")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin backup [FLAGS]

Create a system backup including configuration, keys, and data.

FLAGS:
    --output FILE       Output backup file (default: arkfile-backup.tar.gz)
    --base-dir DIR      Installation base directory (default: /opt/arkfile)
    --help             Show this help message

EXAMPLES:
    arkfile-admin backup --output backup-$(date +%%Y%%m%%d).tar.gz
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("Creating system backup...\n")
	fmt.Printf("Output file: %s\n", *output)
	fmt.Printf("Base directory: %s\n", *baseDir)

	// TODO: Implement actual backup logic
	fmt.Printf("Backup functionality requires server endpoint implementation\n")
	fmt.Printf("Would backup: config files, keys, database, user data\n")

	return fmt.Errorf("backup endpoint not yet implemented on server")
}

// handleRestoreCommand restores from a system backup
func handleRestoreCommand(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	var (
		input   = fs.String("input", "", "Input backup file (required)")
		baseDir = fs.String("base-dir", "/opt/arkfile", "Installation base directory")
		force   = fs.Bool("force", false, "Force restore without confirmation")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin restore [FLAGS]

Restore system from backup file.

FLAGS:
    --input FILE        Input backup file (required)
    --base-dir DIR      Installation base directory (default: /opt/arkfile)
    --force            Force restore without confirmation
    --help             Show this help message

EXAMPLES:
    arkfile-admin restore --input backup-20240814.tar.gz
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *input == "" {
		return fmt.Errorf("input backup file is required")
	}

	fmt.Printf("Restoring from backup...\n")
	fmt.Printf("Input file: %s\n", *input)
	fmt.Printf("Base directory: %s\n", *baseDir)
	fmt.Printf("Force mode: %v\n", *force)

	// TODO: Implement actual restore logic
	fmt.Printf("Restore functionality requires server endpoint implementation\n")
	fmt.Printf("Would restore: config files, keys, database, user data\n")

	return fmt.Errorf("restore endpoint not yet implemented on server")
}

// handleMonitorCommand performs performance monitoring
func handleMonitorCommand(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	var (
		duration = fs.Duration("duration", 60*time.Second, "Monitoring duration")
		interval = fs.Duration("interval", 5*time.Second, "Sampling interval")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin monitor [FLAGS]

Perform real-time performance monitoring.

FLAGS:
    --duration DURATION Monitoring duration (default: 60s)
    --interval DURATION Sampling interval (default: 5s)
    --help             Show this help message

EXAMPLES:
    arkfile-admin monitor --duration 5m --interval 10s
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("Starting performance monitoring...\n")
	fmt.Printf("Duration: %s\n", *duration)
	fmt.Printf("Interval: %s\n", *interval)

	// TODO: Implement actual monitoring logic
	fmt.Printf("Monitoring functionality requires server endpoint implementation\n")
	fmt.Printf("Would monitor: CPU, memory, disk I/O, network, database performance\n")

	return fmt.Errorf("monitoring endpoint not yet implemented on server")
}

// handleAuditCommand performs security audit
func handleAuditCommand(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	var (
		detailed = fs.Bool("detailed", false, "Show detailed audit information")
		output   = fs.String("output", "", "Save audit report to file")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin audit [FLAGS]

Perform comprehensive security audit.

FLAGS:
    --detailed          Show detailed audit information
    --output FILE       Save audit report to file
    --help             Show this help message

EXAMPLES:
    arkfile-admin audit --detailed --output audit-report.txt
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("🔍 Performing security audit...\n")
	fmt.Printf("Detailed mode: %v\n", *detailed)
	if *output != "" {
		fmt.Printf("Output file: %s\n", *output)
	}

	// TODO: Implement actual audit logic
	fmt.Printf("Audit functionality requires server endpoint implementation\n")
	fmt.Printf("Would audit: file permissions, key security, user access, configuration\n")

	return fmt.Errorf("audit endpoint not yet implemented on server")
}

// readPassword reads a password from stdin without echoing using terminal controls
func readPassword() (string, error) {
	fmt.Print("")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println() // Add newline after password input
	return string(bytePassword), nil
}
