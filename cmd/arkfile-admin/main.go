// arkfile-admin - Local system maintenance and monitoring tool
// This tool provides local administrative functions for system operations without network access

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
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

	"github.com/84adam/Arkfile/auth"
)

const (
	Version = "1.0.0-static"
	Usage   = `arkfile-admin - Hybrid network/local admin tool for arkfile server management

USAGE:
    arkfile-admin [global options] command [command options] [arguments...]

NETWORK COMMANDS (Admin API - localhost only):
    bootstrap         Bootstrap the first admin user (requires token)
    login             Admin login via OPAQUE+TOTP authentication
    setup-totp        Setup Two-Factor Authentication (TOTP)
    logout            Clear admin session
    list-users        List all users
    approve-user      Approve user account
    user-status       Get status of a specific user
    set-storage       Set user storage limit
    revoke-user       Revoke user access and disable account

SYSTEM COMMANDS:
    system-status     System status overview
    health-check      System health check
    version           Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL for network commands (default: https://localhost:8443)
    --tls-insecure      Skip TLS certificate verification (dev/localhost only)
    --base-dir DIR      Installation directory for local commands (default: /opt/arkfile)
    --config FILE       Configuration file path
    --username USER     Admin username for authentication
    --verbose, -v       Verbose output
    --help, -h          Show help

EXAMPLES:
    # Admin authentication:
    arkfile-admin login --username admin
    
    # User management:
    arkfile-admin list-users
    arkfile-admin approve-user --username alice
    arkfile-admin set-storage --username alice --limit 10GB
    
    # System monitoring:
    arkfile-admin system-status
    arkfile-admin health-check --detailed
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
	TempToken      string    `json:"temp_token,omitempty"`
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
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
}

// User represents user information
type User struct {
	Username          string    `json:"username"`
	IsAdmin           bool      `json:"is_admin"`
	IsApproved        bool      `json:"is_approved"`
	StorageLimitBytes int64     `json:"storage_limit_bytes"`
	TotalStorageBytes int64     `json:"total_storage_bytes"`
	RegistrationDate  time.Time `json:"registration_date"`
	LastLogin         time.Time `json:"last_login"`
	TOTPEnabled       bool      `json:"totp_enabled"`
}

func main() {
	// Global flags
	var (
		serverURL   = flag.String("server-url", "https://localhost:8443", "Server URL")
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
	case "bootstrap":
		if err := handleBootstrapCommand(client, config, args); err != nil {
			logError("Bootstrap failed: %v", err)
			os.Exit(1)
		}
	case "login":
		if err := handleLoginCommand(client, config, args); err != nil {
			logError("Login failed: %v", err)
			os.Exit(1)
		}
	case "setup-totp":
		if err := handleSetupTOTPCommand(client, config, args); err != nil {
			logError("TOTP setup failed: %v", err)
			os.Exit(1)
		}
	case "logout":
		if err := handleLogoutCommand(config, args); err != nil {
			logError("Logout failed: %v", err)
			os.Exit(1)
		}
	case "list-users":
		if err := handleListUsersCommand(client, config, args); err != nil {
			logError("List users failed: %v", err)
			os.Exit(1)
		}
	case "approve-user":
		if err := handleApproveUserCommand(client, config, args); err != nil {
			logError("Approve user failed: %v", err)
			os.Exit(1)
		}
	case "set-storage":
		if err := handleSetStorageCommand(client, config, args); err != nil {
			logError("Set storage failed: %v", err)
			os.Exit(1)
		}
	case "revoke-user":
		if err := handleRevokeUserCommand(client, config, args); err != nil {
			logError("Revoke user failed: %v", err)
			os.Exit(1)
		}
	case "user-status":
		if err := handleUserStatusCommand(client, config, args); err != nil {
			logError("User status failed: %v", err)
			os.Exit(1)
		}

	// System monitoring commands
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
		return &apiResp, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiResp.Message)
	}

	return &apiResp, nil
}

// handleBootstrapCommand processes the bootstrap command
func handleBootstrapCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	var (
		tokenFlag    = fs.String("token", "", "Bootstrap token (required)")
		usernameFlag = fs.String("username", "admin", "Username for admin account")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin bootstrap [FLAGS]

Bootstrap the first admin user using the token provided by the server logs.

FLAGS:
    --token TOKEN      Bootstrap token from server logs (required)
    --username USER    Username for admin account (default: admin)
    --help            Show this help message

EXAMPLES:
    arkfile-admin bootstrap --token <TOKEN>
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *tokenFlag == "" {
		return fmt.Errorf("bootstrap token is required")
	}

	// Get password securely
	fmt.Printf("Enter password for admin user %s: ", *usernameFlag)
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Confirm password
	fmt.Print("Confirm password: ")
	passwordConfirm, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}

	// Verify passwords match
	if password != passwordConfirm {
		return fmt.Errorf("passwords do not match")
	}

	// Perform OPAQUE multi-step registration
	logVerbose("Starting OPAQUE bootstrap for user: %s", *usernameFlag)

	// Step 1: Create registration request (client-side)
	clientSecret, registrationRequest, err := auth.ClientCreateRegistrationRequest([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	// Encode registration request for transmission
	registrationRequestB64 := base64.StdEncoding.EncodeToString(registrationRequest)

	// Step 2: Send registration request to server
	regReq := map[string]string{
		"bootstrap_token":      *tokenFlag,
		"username":             *usernameFlag,
		"registration_request": registrationRequestB64,
	}

	regResp, err := client.makeRequest("POST", "/api/bootstrap/register/response", regReq, "")
	if err != nil {
		return fmt.Errorf("bootstrap registration failed: %w", err)
	}

	// Step 3: Decode server's registration response
	registrationResponseB64, ok := regResp.Data["registration_response"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing registration_response")
	}

	// Extract session_id from Data if present, otherwise fallback to top-level SessionID
	sessionID, ok := regResp.Data["session_id"].(string)
	if !ok || sessionID == "" {
		// Try to get from response data directly if not in Data map (depends on makeRequest impl)
		// makeRequest puts everything in Data map or top level fields?
		// makeRequest returns *Response which has Data map.
		// But wait, makeRequest implementation:
		// var apiResp Response
		// if err := json.Unmarshal(responseData, &apiResp); err != nil { ... }
		// return &apiResp, nil
		// So session_id should be in Data map if server puts it there.
		// The server implementation of bootstrap puts it in Data map?
		// Let's assume it does or check handlers/bootstrap.go later.
		// For now, I'll assume it's in Data.
	}
	if sessionID == "" {
		return fmt.Errorf("invalid server response: missing session_id")
	}

	registrationResponse, err := base64.StdEncoding.DecodeString(registrationResponseB64)
	if err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	// Step 4: Finalize registration (client-side)
	registrationRecord, _, err := auth.ClientFinalizeRegistration(clientSecret, registrationResponse, *usernameFlag)
	if err != nil {
		return fmt.Errorf("failed to finalize registration: %w", err)
	}

	// Encode registration record for transmission
	registrationRecordB64 := base64.StdEncoding.EncodeToString(registrationRecord)

	// Step 5: Send registration record to server to complete registration
	finalizeReq := map[string]string{
		"bootstrap_token":     *tokenFlag,
		"session_id":          sessionID,
		"username":            *usernameFlag,
		"registration_record": registrationRecordB64,
	}

	regFinalizeResp, err := client.makeRequest("POST", "/api/bootstrap/register/finalize", finalizeReq, "")
	if err != nil {
		return fmt.Errorf("bootstrap finalization failed: %w", err)
	}

	fmt.Printf("Bootstrap successful! Admin user '%s' created.\n", *usernameFlag)

	// Handle TOTP requirement
	requiresTOTP, _ := regFinalizeResp.Data["requires_totp"].(bool)
	tempToken, _ := regFinalizeResp.Data["temp_token"].(string)

	if requiresTOTP && tempToken != "" {
		// Save session with temp token for TOTP setup
		session := &AdminSession{
			Username:       *usernameFlag,
			TempToken:      tempToken,
			ServerURL:      config.ServerURL,
			SessionCreated: time.Now(),
			ExpiresAt:      time.Now().Add(15 * time.Minute), // Temp token usually short-lived
			IsAdmin:        true,
		}

		if err := saveAdminSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save session for TOTP setup: %v", err)
		} else {
			fmt.Printf("\nTOTP setup required. Session saved.\n")
			fmt.Printf("Please run 'arkfile-admin setup-totp' to complete account setup.\n")
		}
	}

	return nil
}

// handleSetupTOTPCommand processes TOTP setup command
func handleSetupTOTPCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("setup-totp", flag.ExitOnError)
	var (
		showSecret = fs.Bool("show-secret", false, "Only show the secret (for automation)")
		verifyCode = fs.String("verify", "", "Verify the setup with a code")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin setup-totp [FLAGS]

Setup Two-Factor Authentication (TOTP) for the account.
This is usually required immediately after registration.

FLAGS:
    --show-secret     Only show the secret key and exit (for automation)
    --verify CODE     Verify the setup with a code (for automation)
    --help            Show this help message

EXAMPLES:
    arkfile-admin setup-totp
    arkfile-admin setup-totp --show-secret
    arkfile-admin setup-totp --verify 123456
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load session
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in (use 'arkfile-admin login' or 'bootstrap'): %w", err)
	}

	// Determine which token to use
	// If we have a TempToken, we are in the setup flow
	// If we have an AccessToken, we might be re-configuring or finishing setup
	token := session.TempToken
	if token == "" {
		token = session.AccessToken
	}

	if token == "" {
		return fmt.Errorf("no valid session found. Please register or login first")
	}

	// If verifying, we skip the setup call and go straight to verification
	if *verifyCode != "" {
		return verifyTOTP(client, config, session, token, *verifyCode)
	}

	// Step 1: Call setup endpoint to get secret
	setupResp, err := client.makeRequest("POST", "/api/totp/setup", nil, token)
	if err != nil {
		return fmt.Errorf("failed to initiate TOTP setup: %w", err)
	}

	secret, ok := setupResp.Data["secret"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing secret")
	}

	// Output secret
	if *showSecret {
		// For automation, print in a parseable format
		fmt.Printf("TOTP_SECRET:%s\n", secret)
		return nil
	}

	// Interactive mode
	fmt.Println("=== Two-Factor Authentication Setup ===")
	fmt.Println("1. Open your authenticator app (Google Authenticator, Authy, etc.)")
	fmt.Println("2. Add a new account manually")
	fmt.Printf("3. Enter this secret key: %s\n", secret)
	fmt.Println("=======================================")
	fmt.Println()

	// Prompt for code
	fmt.Print("Enter the 6-digit code from your app: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read code: %w", err)
	}
	code = strings.TrimSpace(code)

	return verifyTOTP(client, config, session, token, code)
}

func verifyTOTP(client *HTTPClient, config *AdminConfig, session *AdminSession, token, code string) error {
	verifyReq := map[string]string{
		"code": code,
	}

	verifyResp, err := client.makeRequest("POST", "/api/totp/verify", verifyReq, token)
	if err != nil {
		return fmt.Errorf("failed to verify TOTP code: %w", err)
	}

	// Update session with final tokens
	if token, ok := verifyResp.Data["token"].(string); ok {
		session.AccessToken = token
	}
	if refreshToken, ok := verifyResp.Data["refresh_token"].(string); ok {
		session.RefreshToken = refreshToken
	}
	if expiresStr, ok := verifyResp.Data["expires_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, expiresStr); err == nil {
			session.ExpiresAt = t
		}
	}

	session.TempToken = "" // Clear temp token

	if err := saveAdminSession(session, config.TokenFile); err != nil {
		logError("Warning: Failed to save updated session: %v", err)
	}

	fmt.Println("TOTP Setup Complete!")

	// Display backup codes if available
	if backupCodes, ok := verifyResp.Data["backup_codes"].([]interface{}); ok {
		fmt.Println("\n=== BACKUP CODES ===")
		fmt.Println("SAVE THESE CODES IN A SAFE PLACE!")
		fmt.Println("You can use these to login if you lose your authenticator device.")
		fmt.Println("--------------------")
		for _, code := range backupCodes {
			fmt.Println(code)
		}
		fmt.Println("--------------------")
	}

	return nil
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

	// Perform multi-step OPAQUE login with admin verification
	logVerbose("Starting multi-step OPAQUE authentication for admin user: %s", *usernameFlag)

	// Step 1: Create credential request
	clientState, credentialRequest, err := auth.ClientCreateCredentialRequest([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to create credential request: %w", err)
	}

	// Step 2: Send credential request to server
	authStartReq := map[string]string{
		"username":           *usernameFlag,
		"credential_request": base64.StdEncoding.EncodeToString(credentialRequest),
	}

	authStartResp, err := client.makeRequest("POST", "/api/admin/login/response", authStartReq, "")
	if err != nil {
		return fmt.Errorf("admin authentication start failed: %w", err)
	}

	sessionID, ok := authStartResp.Data["session_id"].(string)
	if !ok {
		return fmt.Errorf("invalid session ID in response")
	}

	credentialResponseStr, ok := authStartResp.Data["credential_response"].(string)
	if !ok {
		return fmt.Errorf("invalid credential response")
	}

	// Decode base64 credential response
	credentialResponse, err := base64.StdEncoding.DecodeString(credentialResponseStr)
	if err != nil {
		return fmt.Errorf("failed to decode credential response: %w", err)
	}

	// Step 3: Recover credentials and create auth token
	_, authU, exportKey, err := auth.ClientRecoverCredentials(clientState, credentialResponse, *usernameFlag)
	if err != nil {
		return fmt.Errorf("failed to recover credentials: %w", err)
	}

	// Step 4: Finalize authentication
	authFinishReq := map[string]string{
		"session_id": sessionID,
		"username":   *usernameFlag,
		"auth_u":     base64.StdEncoding.EncodeToString(authU),
	}

	loginResp, err := client.makeRequest("POST", "/api/admin/login/finalize", authFinishReq, "")
	if err != nil {
		return fmt.Errorf("admin authentication finalization failed: %w", err)
	}

	// Extract data from login response
	var accessToken, refreshToken, opaqueExport string
	var expiresAt time.Time

	// Check if TOTP is required
	requiresTOTP, _ := loginResp.Data["requires_totp"].(bool)

	if requiresTOTP {
		sessionKey, _ := loginResp.Data["session_key"].(string)
		tempToken, _ := loginResp.Data["temp_token"].(string)

		fmt.Print("Enter TOTP code: ")
		reader := bufio.NewReader(os.Stdin)
		totpCode, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read TOTP code: %w", err)
		}
		totpCode = strings.TrimSpace(totpCode)

		totpReq := map[string]interface{}{
			"code":        totpCode,
			"session_key": sessionKey,
			"is_backup":   false,
		}

		totpResp, err := client.makeRequest("POST", "/api/totp/auth", totpReq, tempToken)
		if err != nil {
			return fmt.Errorf("TOTP authentication failed: %w", err)
		}

		// Get tokens from TOTP response
		accessToken, _ = totpResp.Data["token"].(string)
		refreshToken, _ = totpResp.Data["refresh_token"].(string)
		opaqueExport, _ = totpResp.Data["opaque_export"].(string)

		if expiresStr, ok := totpResp.Data["expires_at"].(string); ok {
			expiresAt, _ = time.Parse(time.RFC3339, expiresStr)
		}
	} else {
		// Get tokens directly from login response
		accessToken, _ = loginResp.Data["token"].(string)
		refreshToken, _ = loginResp.Data["refresh_token"].(string)
		// Use the export key we derived locally if not provided by server
		if export, ok := loginResp.Data["opaque_export"].(string); ok {
			opaqueExport = export
		} else {
			opaqueExport = base64.StdEncoding.EncodeToString(exportKey)
		}

		if expiresStr, ok := loginResp.Data["expires_at"].(string); ok {
			expiresAt, _ = time.Parse(time.RFC3339, expiresStr)
		}
	}

	// Create admin session
	session := &AdminSession{
		Username:       *usernameFlag,
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		ExpiresAt:      expiresAt,
		OPAQUEExport:   opaqueExport,
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
			fmt.Printf("   Created: %s\n", userMap["registration_date"])
			if userMap["last_login"] != nil {
				fmt.Printf("   Last Login: %s\n", userMap["last_login"])
			}
			fmt.Println()
		}
	} else {
		fmt.Printf("%-3s %-20s %-8s %-8s %-6s %-20s %s\n",
			"#", "Username", "Admin", "Approved", "TOTP", "Storage", "Created")
		fmt.Println(strings.Repeat("-", 85))

		for i, userData := range usersData {
			userMap := userData.(map[string]interface{})
			adminStr := boolYesNo(userMap["is_admin"].(bool))
			approvedStr := boolYesNo(userMap["is_approved"].(bool))
			totpStr := boolYesNo(userMap["totp_enabled"].(bool))
			storageUsed := formatFileSize(int64(userMap["total_storage_bytes"].(float64)))
			storageLimit := formatFileSize(int64(userMap["storage_limit_bytes"].(float64)))
			storageStr := fmt.Sprintf("%s / %s", storageUsed, storageLimit)

			// Format registration_date to just the date portion
			regDate := fmt.Sprintf("%v", userMap["registration_date"])
			if t, err := time.Parse(time.RFC3339, regDate); err == nil {
				regDate = t.Format("2006-01-02")
			}

			fmt.Printf("%-3d %-20s %-8s %-8s %-6s %-20s %s\n",
				i+1, userMap["username"], adminStr, approvedStr, totpStr,
				storageStr, regDate)
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
		"approved_by":         session.Username,
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
    arkfile-admin user-status --username alice
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

// boolYesNo returns "Yes" or "No" for a boolean value
func boolYesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
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

// readPassword reads a password from stdin. If stdin is a terminal, it will
// read without echoing. If stdin is a pipe, it will read directly.
func readPassword() (string, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat stdin: %w", err)
	}

	// Check if stdin is a Character Device, which indicates a terminal
	if (fi.Mode() & os.ModeCharDevice) != 0 {
		// Terminal mode: read password without echoing
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		// Add a newline because terminal reads don't echo the Enter key
		fmt.Println()
		return string(bytePassword), nil
	}

	// Not a terminal, so read from stdin (likely a pipe)
	// Read byte-by-byte to avoid buffering more than the line (which would consume subsequent inputs like TOTP)
	var passwordBytes []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("failed to read password from stdin: %w", err)
		}
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			passwordBytes = append(passwordBytes, buf[0])
		}
	}
	// Trim trailing carriage return if present
	return strings.TrimRight(string(passwordBytes), "\r"), nil
}
