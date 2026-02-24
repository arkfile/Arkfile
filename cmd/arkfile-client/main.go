// arkfile-client - file vault management and sharing client with OPAQUE authentication
// This tool provides authenticated server communication for file operations
// NOTE: This client does NOT perform any encryption/decryption operations
// All crypto operations must be done with the cryptocli tool

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/crypto"
	"golang.org/x/term"
)

const (
	Version = "2.0.0-static"
	Usage   = `arkfile-client - File vault management and sharing client with OPAQUE authentication

USAGE:
    arkfile-client [global options] command [command options] [arguments...]

COMMANDS:
    register      Register a new account with arkfile server
    setup-totp    Setup Two-Factor Authentication (TOTP)
    login         Authenticate with arkfile server
    upload        Upload pre-encrypted file to server
    download      Download encrypted file from server  
    share         Manage file shares (create, list, delete)
    download-share Download a shared file
    list-files    List available files (encrypted metadata)
    get-file-metadata  Get metadata for a specific file (includes encrypted_fek)
    logout        Logout and clear session
    agent         Manage the agent (start, stop, status)
    version       Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL (default: https://localhost:8443)
    --config FILE       Configuration file path
    --tls-insecure      Skip TLS certificate verification (localhost only)
    --username USER     Username for authentication
    --verbose, -v       Verbose output
    --help, -h          Show help

IMPORTANT:
    This client does NOT perform encryption/decryption.
    Use 'cryptocli' for all cryptographic operations.

WORKFLOW:
    1. Register: arkfile-client register --username alice
    2. Encrypt file: cryptocli encrypt-password --file doc.pdf --username alice
    3. Upload: arkfile-client upload --file doc.pdf.enc --metadata metadata.json
    4. Download: arkfile-client download --file-id xyz --output encrypted.dat
    5. Decrypt: cryptocli decrypt-password --file encrypted.dat --username alice

SHARE WORKFLOW:
    1. Get FEK: cryptocli decrypt-fek --encrypted-fek "..." --username alice
    2. Create Share Envelope: cryptocli create-share-envelope --fek "..." --share-id "..." --file-id "..."
    3. Create Share: arkfile-client share create --file-id xyz --encrypted-envelope "..." --salt "..."
    4. Download Share: arkfile-client download-share --share-id abc --output shared.enc
    5. Decrypt Share Envelope: cryptocli decrypt-share-envelope --encrypted-envelope "..." --salt "..." --share-id "..." --file-id "..."
    6. Decrypt File: cryptocli decrypt-file-key --file ... --fek <DECRYPTED_FEK_HEX>

EXAMPLES:
    arkfile-client register --username alice
    arkfile-client login --username alice
    arkfile-client upload --file document.pdf.enc --metadata metadata.json
    arkfile-client download --file-id abc123 --output downloaded.enc
    arkfile-client list-files --json
    arkfile-client share create --file-id 123 --encrypted-envelope "..." --salt "..."
    arkfile-client download-share --share-id 456 --output shared.enc
`
)

var verbose bool

// ClientConfig holds configuration for the client
type ClientConfig struct {
	ServerURL     string `json:"server_url"`
	Username      string `json:"username"`
	TLSInsecure   bool   `json:"tls_insecure"`
	TLSMinVersion uint16 `json:"tls_min_version"`
	TokenFile     string `json:"token_file"`
	ConfigFile    string `json:"config_file"`
}

// AuthSession holds authentication session data
type AuthSession struct {
	Username       string    `json:"username"`
	AccessToken    string    `json:"access_token"`
	RefreshToken   string    `json:"refresh_token"`
	TempToken      string    `json:"temp_token,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	ServerURL      string    `json:"server_url"`
	SessionCreated time.Time `json:"session_created"`
}

// HTTPClient wraps http.Client with additional functionality
type HTTPClient struct {
	client  *http.Client
	baseURL string
	verbose bool
}

// Response represents a generic API response
type Response struct {
	Success             bool                   `json:"success"`
	Message             string                 `json:"message"`
	Data                map[string]interface{} `json:"data"`
	Error               string                 `json:"error"`
	TempToken           string                 `json:"temp_token"`
	SessionKey          string                 `json:"session_key"`
	RequiresTOTP        bool                   `json:"requires_totp"`
	Token               string                 `json:"token"`
	RefreshToken        string                 `json:"refresh_token"`
	ExpiresAt           time.Time              `json:"expires_at"`
	SessionID           string                 `json:"session_id"`
	FileID              string                 `json:"file_id"`
	StorageID           string                 `json:"storage_id"`
	EncryptedFileSHA256 string                 `json:"encrypted_file_sha256"`
}

// UploadMetadata represents pre-encrypted metadata for upload
type UploadMetadata struct {
	EncryptedFilename  string `json:"encrypted_filename"`
	FilenameNonce      string `json:"filename_nonce"`
	EncryptedSHA256sum string `json:"encrypted_sha256sum"`
	SHA256sumNonce     string `json:"sha256sum_nonce"`
	EncryptedFEK       string `json:"encrypted_fek"`
	PasswordType       string `json:"password_type"`
	PasswordHint       string `json:"password_hint"`
}

var globalAgent *Agent

func main() {
	// Global flags
	var (
		serverURL   = flag.String("server-url", "https://localhost:8443", "Server URL")
		configFile  = flag.String("config", "", "Configuration file path")
		tlsInsecure = flag.Bool("tls-insecure", false, "Skip TLS certificate verification (localhost only)")
		username    = flag.String("username", "", "Username for authentication")
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
	config := &ClientConfig{
		ServerURL:   *serverURL,
		Username:    *username,
		TLSInsecure: *tlsInsecure,
		ConfigFile:  *configFile,
		TokenFile:   getSessionFilePath(),
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

	// Auto-start agent for most commands (except agent management commands)
	if command != "agent" && command != "version" && command != "" {
		if err := ensureAgentRunning(); err != nil {
			logVerbose("Warning: Failed to start agent: %v", err)
		}
	}

	// Execute command
	switch command {
	case "register":
		if err := handleRegisterCommand(client, config, args); err != nil {
			logError("Registration failed: %v", err)
			os.Exit(1)
		}
	case "setup-totp":
		if err := handleSetupTOTPCommand(client, config, args); err != nil {
			logError("TOTP setup failed: %v", err)
			os.Exit(1)
		}
	case "login":
		if err := handleLoginCommand(client, config, args); err != nil {
			logError("Login failed: %v", err)
			os.Exit(1)
		}
	case "upload":
		if err := handleUploadCommand(client, config, args); err != nil {
			logError("Upload failed: %v", err)
			os.Exit(1)
		}
	case "download":
		if err := handleDownloadCommand(client, config, args); err != nil {
			logError("Download failed: %v", err)
			os.Exit(1)
		}
	case "share":
		if err := handleShareCommand(client, config, args); err != nil {
			logError("Share command failed: %v", err)
			os.Exit(1)
		}
	case "download-share":
		if err := handleDownloadShareCommand(client, config, args); err != nil {
			logError("Download share failed: %v", err)
			os.Exit(1)
		}
	case "list-files":
		if err := handleListFilesCommand(client, config, args); err != nil {
			logError("List files failed: %v", err)
			os.Exit(1)
		}
	case "get-file-metadata":
		if err := handleGetFileMetadataCommand(client, config, args); err != nil {
			logError("Get file metadata failed: %v", err)
			os.Exit(1)
		}
	case "logout":
		if err := handleLogoutCommand(config, args); err != nil {
			logError("Logout failed: %v", err)
			os.Exit(1)
		}
	case "agent":
		if err := handleAgentCommand(args); err != nil {
			logError("Agent command failed: %v", err)
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
func (c *HTTPClient) makeRequest(method, endpoint string, payload interface{}, token string, headers ...string) (*Response, error) {
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
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
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

	// Extract fields from Data map if present (server wraps data in "data" field)
	if apiResp.Data != nil {
		if val, ok := apiResp.Data["requires_totp"].(bool); ok {
			apiResp.RequiresTOTP = val
		}
		if val, ok := apiResp.Data["temp_token"].(string); ok {
			apiResp.TempToken = val
		}
		if val, ok := apiResp.Data["token"].(string); ok {
			apiResp.Token = val
		}
		if val, ok := apiResp.Data["refresh_token"].(string); ok {
			apiResp.RefreshToken = val
		}
		if val, ok := apiResp.Data["session_id"].(string); ok {
			apiResp.SessionID = val
		}
		if val, ok := apiResp.Data["file_id"].(string); ok {
			apiResp.FileID = val
		}
		if val, ok := apiResp.Data["storage_id"].(string); ok {
			apiResp.StorageID = val
		}
		if val, ok := apiResp.Data["encrypted_file_sha256"].(string); ok {
			apiResp.EncryptedFileSHA256 = val
		}

		// Handle expiration time
		if val, ok := apiResp.Data["expires_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				apiResp.ExpiresAt = t
			} else if t, err := time.Parse(time.RFC3339Nano, val); err == nil {
				apiResp.ExpiresAt = t
			}
		}
	}

	if resp.StatusCode >= 400 {
		return &apiResp, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiResp.Error)
	}

	return &apiResp, nil
}

// handleRegisterCommand processes registration command
func handleRegisterCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", config.Username, "Username for registration")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client register [FLAGS]

Register a new account with arkfile server using OPAQUE protocol.

FLAGS:
    --username USER    Username for registration (required)
    --help            Show this help message

EXAMPLES:
    arkfile-client register --username alice
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	// Get password securely
	password, err := readPassword(fmt.Sprintf("Enter password for new user %s: ", *usernameFlag))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Confirm password
	passwordConfirm, err := readPassword("Confirm password: ")
	if err != nil {
		// Clear first password
		for i := range password {
			password[i] = 0
		}
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}

	// Verify passwords match
	if !bytes.Equal(password, passwordConfirm) {
		// Clear both passwords
		for i := range password {
			password[i] = 0
		}
		for i := range passwordConfirm {
			passwordConfirm[i] = 0
		}
		return fmt.Errorf("passwords do not match")
	}

	// Clear confirmation password (no longer needed)
	for i := range passwordConfirm {
		passwordConfirm[i] = 0
	}

	// Perform OPAQUE multi-step registration
	logVerbose("Starting OPAQUE registration for user: %s", *usernameFlag)

	// Step 1: Create registration request (client-side)
	clientSecret, registrationRequest, err := auth.ClientCreateRegistrationRequest(password)
	if err != nil {
		// Securely clear password
		for i := range password {
			password[i] = 0
		}
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	// Securely clear the password from memory after creating registration request
	for i := range password {
		password[i] = 0
	}

	// Encode registration request for transmission
	registrationRequestB64 := base64.StdEncoding.EncodeToString(registrationRequest)

	// Step 2: Send registration request to server
	regReq := map[string]string{
		"username":             *usernameFlag,
		"registration_request": registrationRequestB64,
	}

	regResp, err := client.makeRequest("POST", "/api/opaque/register/response", regReq, "")
	if err != nil {
		return fmt.Errorf("OPAQUE registration failed: %w", err)
	}

	// Step 3: Decode server's registration response
	registrationResponseB64, ok := regResp.Data["registration_response"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing registration_response")
	}

	// Extract session_id from Data if present, otherwise fallback to top-level SessionID
	sessionID, ok := regResp.Data["session_id"].(string)
	if !ok || sessionID == "" {
		sessionID = regResp.SessionID
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
		"session_id":          sessionID,
		"username":            *usernameFlag,
		"registration_record": registrationRecordB64,
	}

	regFinalizeResp, err := client.makeRequest("POST", "/api/opaque/register/finalize", finalizeReq, "")
	if err != nil {
		return fmt.Errorf("OPAQUE registration finalization failed: %w", err)
	}

	fmt.Printf("Registration successful for user: %s\n", *usernameFlag)

	// Handle TOTP requirement
	if regFinalizeResp.RequiresTOTP && regFinalizeResp.TempToken != "" {
		// Save session with temp token for TOTP setup
		session := &AuthSession{
			Username:       *usernameFlag,
			TempToken:      regFinalizeResp.TempToken,
			ServerURL:      config.ServerURL,
			SessionCreated: time.Now(),
			ExpiresAt:      time.Now().Add(15 * time.Minute), // Temp token usually short-lived
		}

		if err := saveAuthSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save session for TOTP setup: %v", err)
		} else {
			fmt.Printf("\nTOTP setup required. Session saved.\n")
			fmt.Printf("Please run 'arkfile-client setup-totp' to complete account setup.\n")
		}
	} else {
		fmt.Printf("\nPlease login manually with: arkfile-client login --username %s\n", *usernameFlag)
	}

	return nil
}

// handleSetupTOTPCommand processes TOTP setup command
func handleSetupTOTPCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("setup-totp", flag.ExitOnError)
	var (
		showSecret = fs.Bool("show-secret", false, "Only show the secret (for automation)")
		verifyCode = fs.String("verify", "", "Verify the setup with a code")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client setup-totp [FLAGS]

Setup Two-Factor Authentication (TOTP) for the account.
This is usually required immediately after registration.

FLAGS:
    --show-secret     Only show the secret key and exit (for automation)
    --verify CODE     Verify the setup with a code (for automation)
    --help            Show this help message

EXAMPLES:
    arkfile-client setup-totp
    arkfile-client setup-totp --show-secret
    arkfile-client setup-totp --verify 123456
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in (use 'arkfile-client login' or 'register'): %w", err)
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

func verifyTOTP(client *HTTPClient, config *ClientConfig, session *AuthSession, token, code string) error {
	verifyReq := map[string]string{
		"code": code,
	}

	verifyResp, err := client.makeRequest("POST", "/api/totp/verify", verifyReq, token)
	if err != nil {
		return fmt.Errorf("failed to verify TOTP code: %w", err)
	}

	// Update session with final tokens
	if verifyResp.Token != "" {
		session.AccessToken = verifyResp.Token
		session.RefreshToken = verifyResp.RefreshToken
		session.ExpiresAt = verifyResp.ExpiresAt
		session.TempToken = "" // Clear temp token
	}

	if err := saveAuthSession(session, config.TokenFile); err != nil {
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

// handleLoginCommand processes login command
func handleLoginCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	var (
		usernameFlag   = fs.String("username", config.Username, "Username for login")
		saveSession    = fs.Bool("save-session", true, "Save session for future use")
		totpCode       = fs.String("totp-code", "", "TOTP code for non-interactive login")
		nonInteractive = fs.Bool("non-interactive", false, "Don't prompt for input")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client login [FLAGS]

Authenticate with arkfile server using OPAQUE protocol.

FLAGS:
    --username USER       Username for authentication (required)
    --totp-code CODE      TOTP code for non-interactive login
    --non-interactive     Don't prompt for input (for automated scripts)
    --save-session        Save session for future use (default: true)
    --help               Show this help message

EXAMPLES:
    arkfile-client login --username alice
    arkfile-client login --username bob --save-session=false
    arkfile-client login --username alice --totp-code 123456 --non-interactive
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	// Get password securely
	password, err := readPassword(fmt.Sprintf("Enter password for %s: ", *usernameFlag))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Perform OPAQUE multi-step authentication
	logVerbose("Starting OPAQUE authentication for user: %s", *usernameFlag)

	// Step 1: Create credential request (client-side)
	clientSecret, credentialRequest, err := auth.ClientCreateCredentialRequest(password)
	if err != nil {
		// Securely clear password
		for i := range password {
			password[i] = 0
		}
		return fmt.Errorf("failed to create credential request: %w", err)
	}

	// Securely clear the password from memory after creating credential request
	for i := range password {
		password[i] = 0
	}

	// Encode credential request for transmission
	credentialRequestB64 := base64.StdEncoding.EncodeToString(credentialRequest)

	// Step 2: Send credential request to server
	authReq := map[string]string{
		"username":           *usernameFlag,
		"credential_request": credentialRequestB64,
	}

	authResp, err := client.makeRequest("POST", "/api/opaque/login/response", authReq, "")
	if err != nil {
		return fmt.Errorf("OPAQUE authentication failed: %w", err)
	}

	// Step 3: Decode server's credential response
	credentialResponseB64, ok := authResp.Data["credential_response"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing credential_response")
	}

	// Extract session_id from Data if present, otherwise fallback to top-level SessionID
	sessionID, ok := authResp.Data["session_id"].(string)
	if !ok || sessionID == "" {
		sessionID = authResp.SessionID
	}
	if sessionID == "" {
		return fmt.Errorf("invalid server response: missing session_id")
	}

	credentialResponse, err := base64.StdEncoding.DecodeString(credentialResponseB64)
	if err != nil {
		return fmt.Errorf("failed to decode credential response: %w", err)
	}

	// Step 4: Recover credentials and generate authU (client-side)
	accountKey, authU, _, err := auth.ClientRecoverCredentials(clientSecret, credentialResponse, *usernameFlag)
	if err != nil {
		return fmt.Errorf("failed to recover credentials: %w", err)
	}

	// Encode authU for transmission
	authUB64 := base64.StdEncoding.EncodeToString(authU)

	// Step 5: Send authU to server to finalize authentication
	finalizeReq := map[string]string{
		"session_id": sessionID,
		"username":   *usernameFlag,
		"auth_u":     authUB64,
	}

	loginResp, err := client.makeRequest("POST", "/api/opaque/login/finalize", finalizeReq, "")
	if err != nil {
		return fmt.Errorf("OPAQUE authentication finalization failed: %w", err)
	}

	// Handle TOTP requirement
	if loginResp.RequiresTOTP {
		var userTotpCode string

		// Check if TOTP code was provided via command line
		if *totpCode != "" {
			userTotpCode = *totpCode
			logVerbose("Using provided TOTP code for non-interactive authentication")
		} else {
			// Check if non-interactive mode is enabled
			if *nonInteractive {
				return fmt.Errorf("non-interactive mode enabled but no TOTP code provided (--totp-code required)")
			}

			// Interactive mode: prompt user
			fmt.Print("Enter TOTP code: ")
			reader := bufio.NewReader(os.Stdin)
			totpInput, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read TOTP code: %w", err)
			}
			userTotpCode = strings.TrimSpace(totpInput)
		}

		totpReq := map[string]interface{}{
			"code":       userTotpCode,
			"sessionKey": loginResp.SessionKey,
			"isBackup":   false,
		}

		totpResp, err := client.makeRequest("POST", "/api/totp/auth", totpReq, loginResp.TempToken)
		if err != nil {
			return fmt.Errorf("TOTP authentication failed: %w", err)
		}

		// Update response with final tokens
		loginResp.Token = totpResp.Token
		loginResp.RefreshToken = totpResp.RefreshToken
		loginResp.ExpiresAt = totpResp.ExpiresAt
	}

	// Create session
	session := &AuthSession{
		Username:       *usernameFlag,
		AccessToken:    loginResp.Token,
		RefreshToken:   loginResp.RefreshToken,
		ExpiresAt:      loginResp.ExpiresAt,
		ServerURL:      config.ServerURL,
		SessionCreated: time.Now(),
	}

	// Save session if requested
	if *saveSession {
		if err := saveAuthSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save session: %v", err)
		} else {
			logVerbose("Session saved to: %s", config.TokenFile)
		}
	}

	// Store AccountKey in agent for future use
	agentClient, err := NewAgentClient()
	if err != nil {
		logVerbose("Warning: Failed to create agent client: %v", err)
	} else {
		if err := agentClient.StoreAccountKey(accountKey); err != nil {
			logVerbose("Warning: Failed to store account key in agent: %v", err)
		} else {
			logVerbose("Account key stored in agent successfully")
		}
	}

	// Securely clear accountKey from memory after storing in agent
	defer func() {
		for i := range accountKey {
			accountKey[i] = 0
		}
	}()

	fmt.Printf("Login successful for user: %s\n", *usernameFlag)
	fmt.Printf("Session expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))

	return nil
}

// handleUploadCommand processes upload command for pre-encrypted files
func handleUploadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	var (
		filePath     = fs.String("file", "", "Pre-encrypted file to upload (required)")
		metadataFile = fs.String("metadata", "", "JSON file with encrypted metadata (required)")
		chunkSize    = fs.Int("chunk-size", int(crypto.PlaintextChunkSize()), "Chunk size in bytes")
		showProgress = fs.Bool("progress", true, "Show upload progress")
		// Raw metadata flags for when not using a metadata file
		encFilename = fs.String("encrypted-filename", "", "Base64 encrypted filename")
		encSha256   = fs.String("encrypted-sha256", "", "Base64 encrypted SHA256")
		encFek      = fs.String("encrypted-fek", "", "Base64 encrypted FEK")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client upload [FLAGS]

Upload a pre-encrypted file to the arkfile server.
The file must already be encrypted using cryptocli.

FLAGS:
    --file FILE             Pre-encrypted file to upload (required)
    --metadata FILE         JSON file with encrypted metadata (recommended)
    OR provide metadata directly:
    --encrypted-filename    Base64 encrypted filename
    --encrypted-sha256      Base64 encrypted SHA256
    --encrypted-fek         Base64 encrypted FEK
    --password-type TYPE    Password type: account/custom/share (default: account)
    
    --chunk-size SIZE       Chunk size in bytes (default: from chunking-params.json)
    --progress             Show upload progress (default: true)
    --help                 Show this help message

WORKFLOW:
    1. Encrypt file: cryptocli encrypt-password --file doc.pdf --username alice
    2. Encrypt metadata: cryptocli encrypt-metadata --filename "doc.pdf" --sha256sum "..." --username alice
    3. Upload: arkfile-client upload --file doc.pdf.enc --metadata metadata.json

EXAMPLES:
    arkfile-client upload --file document.pdf.enc --metadata metadata.json
    arkfile-client upload --file data.enc --encrypted-filename "..." --encrypted-sha256 "..." --encrypted-fek "..."
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required")
	}

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in (use 'arkfile-client login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("session expired, please login again")
	}

	// Read encrypted file
	encryptedData, err := os.ReadFile(*filePath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	logVerbose("Uploading pre-encrypted file: %s (%d bytes)", *filePath, len(encryptedData))

	// Load or construct metadata
	var metadata UploadMetadata
	if *metadataFile != "" {
		// Load metadata from JSON file
		metadataData, err := os.ReadFile(*metadataFile)
		if err != nil {
			return fmt.Errorf("failed to read metadata file: %w", err)
		}
		if err := json.Unmarshal(metadataData, &metadata); err != nil {
			return fmt.Errorf("failed to parse metadata JSON: %w", err)
		}
	} else if *encFilename != "" && *encSha256 != "" && *encFek != "" {
		// Use provided metadata flags - nonces must be provided separately
		// The client no longer attempts to extract nonces from encrypted data
		return fmt.Errorf("direct metadata flags are deprecated. Please use a JSON metadata file or provide separate nonce parameters")
	} else {
		return fmt.Errorf("metadata JSON file is required (use --metadata)")
	}

	// Initialize chunked upload
	totalChunks := (len(encryptedData) + *chunkSize - 1) / *chunkSize

	uploadReq := map[string]interface{}{
		"encrypted_filename":  metadata.EncryptedFilename,
		"filename_nonce":      metadata.FilenameNonce,
		"encrypted_sha256sum": metadata.EncryptedSHA256sum,
		"sha256sum_nonce":     metadata.SHA256sumNonce,
		"encrypted_fek":       metadata.EncryptedFEK,
		"total_size":          len(encryptedData),
		"chunk_size":          *chunkSize,
		"password_hint":       metadata.PasswordHint,
		"password_type":       metadata.PasswordType,
	}

	uploadResp, err := client.makeRequest("POST", "/api/uploads/init", uploadReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("upload initialization failed: %w", err)
	}

	sessionID := uploadResp.SessionID
	fileID := uploadResp.FileID

	logVerbose("Upload session initialized: %s", sessionID)
	logVerbose("File ID: %s", fileID)

	// Upload chunks
	if *showProgress {
		fmt.Printf("Uploading encrypted file (%s) in %d chunks...\n", formatFileSize(int64(len(encryptedData))), totalChunks)
	}

	for chunkIndex := 0; chunkIndex < totalChunks; chunkIndex++ {
		start := chunkIndex * *chunkSize
		end := start + *chunkSize
		if end > len(encryptedData) {
			end = len(encryptedData)
		}

		chunkData := encryptedData[start:end]
		chunkHash := sha256.Sum256(chunkData)
		chunkHashStr := fmt.Sprintf("%x", chunkHash)

		uploadURL := fmt.Sprintf("%s/api/uploads/%s/chunks/%d", client.baseURL, sessionID, chunkIndex)

		req, err := http.NewRequest("POST", uploadURL, bytes.NewBuffer(chunkData))
		if err != nil {
			return fmt.Errorf("chunk %d: failed to create request: %w", chunkIndex, err)
		}

		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
		req.Header.Set("X-Chunk-Hash", chunkHashStr)
		req.ContentLength = int64(len(chunkData))

		if client.verbose {
			logVerbose("Uploading chunk %d to %s", chunkIndex, uploadURL)
		}

		resp, err := client.client.Do(req)
		if err != nil {
			return fmt.Errorf("chunk %d upload failed: %w", chunkIndex, err)
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("chunk %d upload failed: status %d, body: %s", chunkIndex, resp.StatusCode, string(bodyBytes))
		}
		resp.Body.Close()

		if *showProgress {
			progress := float64(chunkIndex+1) / float64(totalChunks) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d chunks)", progress, chunkIndex+1, totalChunks)
		}
	}

	if *showProgress {
		fmt.Println() // Add newline after progress
	}

	// Finalize upload - no body needed since session ID is in the URL
	finalizeURL := fmt.Sprintf("/api/uploads/%s/complete", sessionID)
	finalizeResp, err := client.makeRequest("POST", finalizeURL, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("upload finalization failed: %w", err)
	}

	fmt.Printf("Upload completed successfully\n")
	fmt.Printf("File ID: %s\n", fileID)
	fmt.Printf("Storage ID: %s\n", finalizeResp.StorageID)
	fmt.Printf("Server-side Encrypted SHA256: %s\n", finalizeResp.EncryptedFileSHA256)
	fmt.Printf("Encrypted file size: %s\n", formatFileSize(int64(len(encryptedData))))

	return nil
}

// ChunkDownloadMetadata represents the metadata response for chunked downloads
type ChunkDownloadMetadata struct {
	FileID         string `json:"file_id"`
	SizeBytes      int64  `json:"size_bytes"`
	ChunkCount     int64  `json:"chunk_count"`
	ChunkSizeBytes int64  `json:"chunk_size_bytes"`
}

// handleDownloadCommand processes download command using chunked download API
func handleDownloadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	var (
		fileID       = fs.String("file-id", "", "File ID to download (required)")
		outputPath   = fs.String("output", "", "Output file path for the encrypted data (required)")
		showProgress = fs.Bool("progress", true, "Show download progress")
		resume       = fs.Bool("resume", false, "Resume interrupted download if partial file exists")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client download [FLAGS]

Downloads an encrypted file from the server using chunked download.
The downloaded file will still be encrypted - use cryptocli to decrypt it.

FLAGS:
    --file-id ID        File ID to download (required)
    --output PATH       Output file path for the encrypted data (required)
    --progress          Show download progress (default: true)
    --resume            Resume interrupted download if partial file exists
    --help             Show this help message

WORKFLOW:
    1. Download: arkfile-client download --file-id "..." --output encrypted.dat
    2. Decrypt: cryptocli decrypt-password --file encrypted.dat --username alice

EXAMPLES:
    arkfile-client download --file-id "abc123..." --output downloaded.enc
    arkfile-client download --file-id "def456..." --output file.enc --resume
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" {
		return fmt.Errorf("file-id must be specified")
	}
	if *outputPath == "" {
		return fmt.Errorf("output must be specified")
	}

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in (use 'arkfile-client login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("session expired, please login again")
	}

	logVerbose("Starting chunked download for file: %s", *fileID)

	// STEP 1: Get chunk metadata from the unified /meta endpoint
	metadataURL := fmt.Sprintf("/api/files/%s/meta", *fileID)
	logVerbose("Fetching chunk metadata from: %s", metadataURL)

	metadataReq, err := http.NewRequest("GET", client.baseURL+metadataURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create metadata request: %w", err)
	}
	metadataReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

	metadataResp, err := client.client.Do(metadataReq)
	if err != nil {
		return fmt.Errorf("metadata request failed: %w", err)
	}
	defer metadataResp.Body.Close()

	metaRawBytes, err := io.ReadAll(metadataResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read metadata response: %w", err)
	}

	if metadataResp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata request failed with status %d: %s", metadataResp.StatusCode, string(metaRawBytes))
	}

	var chunkMeta ChunkDownloadMetadata
	if err := json.Unmarshal(metaRawBytes, &chunkMeta); err != nil {
		return fmt.Errorf("failed to parse chunk metadata: %w", err)
	}

	logVerbose("File size: %d bytes, Chunks: %d, Chunk size: %d bytes",
		chunkMeta.SizeBytes, chunkMeta.ChunkCount, chunkMeta.ChunkSizeBytes)

	// STEP 2: Determine starting chunk for resume
	var startChunk int64 = 0
	var existingSize int64 = 0

	if *resume {
		if info, err := os.Stat(*outputPath); err == nil {
			existingSize = info.Size()
			// Calculate which chunk to resume from
			startChunk = existingSize / chunkMeta.ChunkSizeBytes
			// Verify the existing file aligns with chunk boundaries
			if existingSize%chunkMeta.ChunkSizeBytes != 0 {
				// Truncate to last complete chunk
				startChunk = existingSize / chunkMeta.ChunkSizeBytes
				existingSize = startChunk * chunkMeta.ChunkSizeBytes
				logVerbose("Truncating partial chunk, resuming from chunk %d", startChunk)
			}
			if startChunk > 0 {
				logVerbose("Resuming download from chunk %d (existing: %d bytes)", startChunk, existingSize)
			}
		}
	}

	// STEP 3: Open/create output file
	var outFile *os.File
	if *resume && existingSize > 0 {
		// Truncate to last complete chunk and append
		outFile, err = os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		if err := outFile.Truncate(existingSize); err != nil {
			outFile.Close()
			return fmt.Errorf("failed to truncate file for resume: %w", err)
		}
		if _, err := outFile.Seek(existingSize, 0); err != nil {
			outFile.Close()
			return fmt.Errorf("failed to seek to resume position: %w", err)
		}
	} else {
		outFile, err = os.Create(*outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		startChunk = 0
		existingSize = 0
	}
	defer outFile.Close()

	// STEP 4: Download chunks
	if *showProgress {
		if startChunk > 0 {
			fmt.Printf("Resuming download of encrypted file (%s) from chunk %d/%d...\n",
				formatFileSize(chunkMeta.SizeBytes), startChunk+1, chunkMeta.ChunkCount)
		} else {
			fmt.Printf("Downloading encrypted file (%s) in %d chunks...\n",
				formatFileSize(chunkMeta.SizeBytes), chunkMeta.ChunkCount)
		}
	}

	totalBytesDownloaded := existingSize

	for chunkIndex := startChunk; chunkIndex < chunkMeta.ChunkCount; chunkIndex++ {
		chunkURL := fmt.Sprintf("/api/files/%s/chunks/%d", *fileID, chunkIndex)

		chunkReq, err := http.NewRequest("GET", client.baseURL+chunkURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create chunk %d request: %w", chunkIndex, err)
		}
		chunkReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

		chunkResp, err := client.client.Do(chunkReq)
		if err != nil {
			return fmt.Errorf("chunk %d download failed: %w", chunkIndex, err)
		}

		if chunkResp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(chunkResp.Body)
			chunkResp.Body.Close()
			return fmt.Errorf("chunk %d download failed with status %d: %s", chunkIndex, chunkResp.StatusCode, string(bodyBytes))
		}

		// Write chunk to file
		written, err := io.Copy(outFile, chunkResp.Body)
		chunkResp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to write chunk %d: %w", chunkIndex, err)
		}

		totalBytesDownloaded += written

		if *showProgress {
			progress := float64(chunkIndex+1) / float64(chunkMeta.ChunkCount) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d chunks, %s/%s)",
				progress,
				chunkIndex+1, chunkMeta.ChunkCount,
				formatFileSize(totalBytesDownloaded),
				formatFileSize(chunkMeta.SizeBytes))
		}
	}

	if *showProgress {
		fmt.Println() // Newline after progress
	}

	logVerbose("Successfully downloaded %d bytes to %s", totalBytesDownloaded, *outputPath)

	// STEP 5: Save file metadata for decryption (reuse response from STEP 1)
	metaPath := *outputPath + ".metadata.json"
	if err := os.WriteFile(metaPath, metaRawBytes, 0644); err != nil {
		fmt.Printf("Warning: Failed to save metadata file: %v\n", err)
	} else {
		fmt.Printf("Metadata saved to: %s\n", metaPath)
	}

	fmt.Printf("Encrypted file downloaded successfully\n")
	fmt.Printf("File ID: %s\n", *fileID)
	fmt.Printf("Saved to: %s\n", *outputPath)
	fmt.Printf("Size: %s\n", formatFileSize(totalBytesDownloaded))
	fmt.Printf("\nUse 'cryptocli decrypt-password' to decrypt the file.\n")

	return nil
}

// ServerFileListResponse represents the server's file list response format
type ServerFileListResponse struct {
	Files   []ServerFileInfo `json:"files"`
	Storage interface{}      `json:"storage"`
}

// ServerFileInfo represents file metadata from server response
type ServerFileInfo struct {
	FileID            string `json:"file_id"`
	StorageID         string `json:"storage_id"`
	PasswordHint      string `json:"password_hint"`
	PasswordType      string `json:"password_type"`
	FilenameNonce     string `json:"filename_nonce"`
	EncryptedFilename string `json:"encrypted_filename"`
	SHA256Nonce       string `json:"sha256sum_nonce"`
	EncryptedSHA256   string `json:"encrypted_sha256sum"`
	EncryptedFEK      string `json:"encrypted_fek"`
	SizeBytes         int64  `json:"size_bytes"`
	SizeReadable      string `json:"size_readable"`
	UploadDate        string `json:"upload_date"`
}

// handleShareCommand processes share management commands
func handleShareCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("subcommand required: create, list, delete, revoke")
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "create":
		return handleShareCreate(client, config, subArgs)
	case "list":
		return handleShareList(client, config, subArgs)
	case "delete":
		return handleShareDelete(client, config, subArgs)
	case "revoke":
		return handleShareRevoke(client, config, subArgs)
	default:
		return fmt.Errorf("unknown subcommand: %s", subcommand)
	}
}

func handleShareCreate(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share create", flag.ExitOnError)
	var (
		shareID           = fs.String("share-id", "", "Client-generated share ID (required)")
		fileID            = fs.String("file-id", "", "File ID to share (required)")
		encryptedEnvelope = fs.String("encrypted-envelope", "", "Base64 encrypted envelope (required)")
		salt              = fs.String("salt", "", "Base64 salt (required)")
		downloadTokenHash = fs.String("download-token-hash", "", "Base64 SHA256 hash of download token (required)")
		expiresAt         = fs.String("expires-at", "", "Expiration time (RFC3339)")
		maxDownloads      = fs.Int("max-downloads", 0, "Maximum number of downloads (0 for unlimited)")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *shareID == "" || *fileID == "" || *encryptedEnvelope == "" || *salt == "" || *downloadTokenHash == "" {
		return fmt.Errorf("share-id, file-id, encrypted-envelope, salt, and download-token-hash are required")
	}

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	req := map[string]interface{}{
		"share_id":            *shareID,
		"file_id":             *fileID,
		"encrypted_envelope":  *encryptedEnvelope,
		"salt":                *salt,
		"download_token_hash": *downloadTokenHash,
	}

	if *expiresAt != "" {
		req["expires_at"] = *expiresAt
	}
	if *maxDownloads > 0 {
		req["max_downloads"] = *maxDownloads
	}

	resp, err := client.makeRequest("POST", "/api/shares", req, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to create share: %w", err)
	}

	// Response fields may be at top level or in Data map
	respShareID, _ := resp.Data["share_id"].(string)
	shareURL, _ := resp.Data["share_url"].(string)

	// If not in Data, the response struct fields are directly in the JSON
	// The makeRequest function doesn't parse ShareResponse, so we use the input share_id
	if respShareID == "" {
		respShareID = *shareID // Use the client-provided share_id
	}

	fmt.Printf("Share created successfully\n")
	fmt.Printf("Share ID: %s\n", respShareID)
	fmt.Printf("Share URL: %s\n", shareURL)

	return nil
}

func handleShareList(client *HTTPClient, config *ClientConfig, args []string) error {
	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	resp, err := client.makeRequest("GET", "/api/shares", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to list shares: %w", err)
	}

	shares, ok := resp.Data["shares"].([]interface{})
	if !ok {
		fmt.Println("No shares found")
		return nil
	}

	fmt.Printf("Found %d shares:\n\n", len(shares))
	for _, s := range shares {
		share := s.(map[string]interface{})
		fmt.Printf("ID: %s\n", share["share_id"])
		fmt.Printf("File ID: %s\n", share["file_id"])
		fmt.Printf("Created: %s\n", share["created_at"])
		if exp, ok := share["expires_at"].(string); ok && exp != "" {
			fmt.Printf("Expires: %s\n", exp)
		}
		if max, ok := share["max_downloads"].(float64); ok && max > 0 {
			count := 0.0
			if c, ok := share["download_count"].(float64); ok {
				count = c
			}
			fmt.Printf("Downloads: %.0f/%.0f\n", count, max)
		}
		fmt.Println("---")
	}

	return nil
}

func handleShareDelete(client *HTTPClient, config *ClientConfig, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("share ID required")
	}
	shareID := args[0]

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	_, err = client.makeRequest("DELETE", "/api/shares/"+shareID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to delete share: %w", err)
	}

	fmt.Printf("Share %s deleted successfully\n", shareID)
	return nil
}

func handleShareRevoke(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share revoke", flag.ExitOnError)
	var (
		reason = fs.String("reason", "owner_revoked", "Revocation reason")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("share ID required")
	}
	shareID := fs.Arg(0)

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	req := map[string]interface{}{
		"reason": *reason,
	}

	_, err = client.makeRequest("POST", "/api/shares/"+shareID+"/revoke", req, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to revoke share: %w", err)
	}

	fmt.Printf("Share %s revoked successfully (reason: %s)\n", shareID, *reason)
	return nil
}

func handleDownloadShareCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("download-share", flag.ExitOnError)
	var (
		shareID       = fs.String("share-id", "", "Share ID to download (required)")
		outputPath    = fs.String("output", "", "Output file path (required)")
		downloadToken = fs.String("download-token", "", "Download token (base64, required)")
		showProgress  = fs.Bool("progress", true, "Show download progress")
		resume        = fs.Bool("resume", false, "Resume interrupted download if partial file exists")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client download-share [FLAGS]

Downloads a shared encrypted file using chunked download.
The downloaded file will still be encrypted - use cryptocli to decrypt it.

FLAGS:
    --share-id ID           Share ID to download (required)
    --output PATH           Output file path (required)
    --download-token TOKEN  Download token from share envelope decryption (required)
    --progress              Show download progress (default: true)
    --resume                Resume interrupted download if partial file exists
    --help                  Show this help message

WORKFLOW:
    1. Get share envelope: arkfile-client share get-envelope --share-id "..."
    2. Decrypt envelope: cryptocli decrypt-share-envelope --encrypted-envelope "..." --salt "..."
    3. Download: arkfile-client download-share --share-id "..." --download-token "..." --output shared.enc
    4. Decrypt: cryptocli decrypt-file-key --file shared.enc --fek <FEK_FROM_ENVELOPE>

EXAMPLES:
    arkfile-client download-share --share-id "abc123..." --download-token "..." --output shared.enc
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *shareID == "" || *outputPath == "" || *downloadToken == "" {
		return fmt.Errorf("share-id, output, and download-token are required")
	}

	logVerbose("Starting chunked download for share: %s", *shareID)

	// STEP 1: Get chunk metadata for the share (public endpoint - no auth required)
	metadataURL := fmt.Sprintf("/api/public/shares/%s/metadata", *shareID)
	logVerbose("Fetching share chunk metadata from: %s", metadataURL)

	metadataReq, err := http.NewRequest("GET", client.baseURL+metadataURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create metadata request: %w", err)
	}

	metadataResp, err := client.client.Do(metadataReq)
	if err != nil {
		return fmt.Errorf("metadata request failed: %w", err)
	}
	defer metadataResp.Body.Close()

	if metadataResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(metadataResp.Body)
		return fmt.Errorf("metadata request failed with status %d: %s", metadataResp.StatusCode, string(bodyBytes))
	}

	var chunkMeta ChunkDownloadMetadata
	if err := json.NewDecoder(metadataResp.Body).Decode(&chunkMeta); err != nil {
		return fmt.Errorf("failed to parse chunk metadata: %w", err)
	}

	logVerbose("File size: %d bytes, Chunks: %d, Chunk size: %d bytes",
		chunkMeta.SizeBytes, chunkMeta.ChunkCount, chunkMeta.ChunkSizeBytes)

	// STEP 2: Determine starting chunk for resume
	var startChunk int64 = 0
	var existingSize int64 = 0

	if *resume {
		if info, err := os.Stat(*outputPath); err == nil {
			existingSize = info.Size()
			startChunk = existingSize / chunkMeta.ChunkSizeBytes
			if existingSize%chunkMeta.ChunkSizeBytes != 0 {
				startChunk = existingSize / chunkMeta.ChunkSizeBytes
				existingSize = startChunk * chunkMeta.ChunkSizeBytes
				logVerbose("Truncating partial chunk, resuming from chunk %d", startChunk)
			}
			if startChunk > 0 {
				logVerbose("Resuming download from chunk %d (existing: %d bytes)", startChunk, existingSize)
			}
		}
	}

	// STEP 3: Open/create output file
	var outFile *os.File
	if *resume && existingSize > 0 {
		outFile, err = os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		if err := outFile.Truncate(existingSize); err != nil {
			outFile.Close()
			return fmt.Errorf("failed to truncate file for resume: %w", err)
		}
		if _, err := outFile.Seek(existingSize, 0); err != nil {
			outFile.Close()
			return fmt.Errorf("failed to seek to resume position: %w", err)
		}
	} else {
		outFile, err = os.Create(*outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		startChunk = 0
		existingSize = 0
	}
	defer outFile.Close()

	// STEP 4: Download chunks
	if *showProgress {
		if startChunk > 0 {
			fmt.Printf("Resuming download of shared file (%s) from chunk %d/%d...\n",
				formatFileSize(chunkMeta.SizeBytes), startChunk+1, chunkMeta.ChunkCount)
		} else {
			fmt.Printf("Downloading shared file (%s) in %d chunks...\n",
				formatFileSize(chunkMeta.SizeBytes), chunkMeta.ChunkCount)
		}
	}

	totalBytesDownloaded := existingSize

	for chunkIndex := startChunk; chunkIndex < chunkMeta.ChunkCount; chunkIndex++ {
		chunkURL := fmt.Sprintf("/api/public/shares/%s/chunks/%d", *shareID, chunkIndex)

		chunkReq, err := http.NewRequest("GET", client.baseURL+chunkURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create chunk %d request: %w", chunkIndex, err)
		}
		chunkReq.Header.Set("X-Download-Token", *downloadToken)

		chunkResp, err := client.client.Do(chunkReq)
		if err != nil {
			return fmt.Errorf("chunk %d download failed: %w", chunkIndex, err)
		}

		if chunkResp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(chunkResp.Body)
			chunkResp.Body.Close()
			return fmt.Errorf("chunk %d download failed with status %d: %s", chunkIndex, chunkResp.StatusCode, string(bodyBytes))
		}

		written, err := io.Copy(outFile, chunkResp.Body)
		chunkResp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to write chunk %d: %w", chunkIndex, err)
		}

		totalBytesDownloaded += written

		if *showProgress {
			progress := float64(chunkIndex+1) / float64(chunkMeta.ChunkCount) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d chunks, %s/%s)",
				progress,
				chunkIndex+1, chunkMeta.ChunkCount,
				formatFileSize(totalBytesDownloaded),
				formatFileSize(chunkMeta.SizeBytes))
		}
	}

	if *showProgress {
		fmt.Println()
	}

	logVerbose("Successfully downloaded %d bytes to %s", totalBytesDownloaded, *outputPath)

	fmt.Printf("Shared file downloaded successfully\n")
	fmt.Printf("Share ID: %s\n", *shareID)
	fmt.Printf("Saved to: %s\n", *outputPath)
	fmt.Printf("Size: %s\n", formatFileSize(totalBytesDownloaded))
	fmt.Printf("\nUse 'cryptocli decrypt-file-key' with the FEK from the share envelope to decrypt.\n")

	return nil
}

// handleListFilesCommand processes list-files command
func handleListFilesCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("list-files", flag.ExitOnError)
	var (
		limit  = fs.Int("limit", 50, "Maximum number of files to list")
		offset = fs.Int("offset", 0, "Offset for pagination")
		asJSON = fs.Bool("json", false, "Output file list as raw JSON")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client list-files [FLAGS]

List encrypted file metadata from the server.
Metadata decryption must be handled separately by the 'cryptocli' tool.

FLAGS:
    --limit INT         Maximum number of files to list (default: 50)
    --offset INT        Offset for pagination (default: 0)
    --json              Output file list as raw JSON
    --help             Show this help message

WORKFLOW:
    1. List: arkfile-client list-files --json > files.json
    2. Decrypt metadata: cryptocli decrypt-metadata --encrypted-filename "..." --encrypted-sha256sum "..." --username alice

EXAMPLES:
    arkfile-client list-files
    arkfile-client list-files --json
    arkfile-client list-files --limit 10 --json | jq .
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in (use 'arkfile-client login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("session expired, please login again")
	}

	// Request file list with direct HTTP handling to avoid response wrapper issues
	endpoint := fmt.Sprintf("/api/files?limit=%d&offset=%d", *limit, *offset)

	// Make direct HTTP request to get raw response
	url := client.baseURL + endpoint
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	if client.verbose {
		logVerbose("Making GET request to %s", url)
	}

	httpResp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	responseData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if client.verbose {
		logVerbose("Response status: %d", httpResp.StatusCode)
		logVerbose("Raw response body: %s", string(responseData))
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("server returned status %d: %s", httpResp.StatusCode, string(responseData))
	}

	// If --json flag is set, output the raw JSON and exit
	if *asJSON {
		// Output the raw JSON directly without re-formatting to preserve encoding
		fmt.Println(string(responseData))
		return nil
	}

	// Otherwise, parse and print a human-readable summary
	var serverResponse ServerFileListResponse
	if err := json.Unmarshal(responseData, &serverResponse); err != nil {
		return fmt.Errorf("failed to parse server response: %w", err)
	}

	if client.verbose {
		logVerbose("Parsed %d files from server response", len(serverResponse.Files))
	}

	if len(serverResponse.Files) == 0 {
		fmt.Println("No files found")
		return nil
	}

	fmt.Printf("Found %d file(s) for user %s:\n\n", len(serverResponse.Files), session.Username)
	fmt.Println("File ID                                 Size       Upload Date")
	fmt.Println("------------------------------------  ---------- --------------------------")

	for _, serverFile := range serverResponse.Files {
		fmt.Printf("%-36s  %-10s %s\n", serverFile.FileID, serverFile.SizeReadable, serverFile.UploadDate)
	}

	fmt.Printf("\nNote: Metadata is encrypted. Use 'cryptocli decrypt-metadata' to decrypt filenames.\n")
	fmt.Printf("Use --json flag to get raw metadata for decryption.\n")

	return nil
}

// handleGetFileMetadataCommand fetches metadata for a specific file
func handleGetFileMetadataCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("get-file-metadata", flag.ExitOnError)
	var (
		fileID = fs.String("file-id", "", "File ID to get metadata for (required)")
		asJSON = fs.Bool("json", false, "Output as raw JSON")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client get-file-metadata [FLAGS]

Get encrypted metadata for a specific file, including encrypted_fek.
This is useful for share creation workflows.

FLAGS:
    --file-id ID    File ID to get metadata for (required)
    --json          Output as raw JSON
    --help          Show this help message

EXAMPLES:
    arkfile-client get-file-metadata --file-id "abc123..."
    arkfile-client get-file-metadata --file-id "abc123..." --json
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" {
		return fmt.Errorf("file-id is required")
	}

	// Load session
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in (use 'arkfile-client login'): %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("session expired, please login again")
	}

	// Fetch file metadata
	endpoint := fmt.Sprintf("/api/files/%s/meta", *fileID)
	url := client.baseURL + endpoint

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	if client.verbose {
		logVerbose("Making GET request to %s", url)
	}

	httpResp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	responseData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if client.verbose {
		logVerbose("Response status: %d", httpResp.StatusCode)
		logVerbose("Raw response body: %s", string(responseData))
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("server returned status %d: %s", httpResp.StatusCode, string(responseData))
	}

	// If --json flag is set, output the raw JSON
	if *asJSON {
		fmt.Println(string(responseData))
		return nil
	}

	// Parse and display human-readable output
	var fileMeta ServerFileInfo
	if err := json.Unmarshal(responseData, &fileMeta); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("File Metadata for: %s\n", *fileID)
	fmt.Println("----------------------------------------")
	fmt.Printf("File ID:           %s\n", fileMeta.FileID)
	fmt.Printf("Storage ID:        %s\n", fileMeta.StorageID)
	fmt.Printf("Size:              %s (%d bytes)\n", fileMeta.SizeReadable, fileMeta.SizeBytes)
	fmt.Printf("Upload Date:       %s\n", fileMeta.UploadDate)
	fmt.Printf("Password Type:     %s\n", fileMeta.PasswordType)
	fmt.Printf("Password Hint:     %s\n", fileMeta.PasswordHint)
	fmt.Println("----------------------------------------")
	fmt.Printf("Encrypted FEK:     %s\n", fileMeta.EncryptedFEK)
	fmt.Printf("Encrypted Filename: %s\n", fileMeta.EncryptedFilename)
	fmt.Printf("Filename Nonce:    %s\n", fileMeta.FilenameNonce)
	fmt.Printf("Encrypted SHA256:  %s\n", fileMeta.EncryptedSHA256)
	fmt.Printf("SHA256 Nonce:      %s\n", fileMeta.SHA256Nonce)

	return nil
}

// handleLogoutCommand processes logout command
func handleLogoutCommand(config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client logout

Clear the saved session and logout.

EXAMPLES:
    arkfile-client logout
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Clear AccountKey from agent
	agentClient, err := NewAgentClient()
	if err != nil {
		logVerbose("Warning: Failed to create agent client: %v", err)
	} else {
		if err := agentClient.Clear(); err != nil {
			logVerbose("Warning: Failed to clear agent: %v", err)
		} else {
			logVerbose("Account key cleared from agent")
		}
	}

	// Remove session file
	if err := os.Remove(config.TokenFile); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove session file: %w", err)
		}
	}

	fmt.Printf("Logged out successfully\n")
	return nil
}

// Helper functions

func printVersion() {
	fmt.Printf("arkfile-client version %s\n", Version)
	fmt.Printf("File vault management and sharing client (crypto operations via cryptocli)\n")
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

func getSessionFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".arkfile-session.json"
	}
	return filepath.Join(homeDir, ".arkfile-session.json")
}

func saveAuthSession(session *AuthSession, filePath string) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

func loadAuthSession(filePath string) (*AuthSession, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var session AuthSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func loadConfigFile(config *ClientConfig, filePath string) error {
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

// readPassword reads a password from stdin. If stdin is a terminal, it will
// print the provided prompt and read without echoing. If stdin is a pipe, it will
// read directly. The caller is responsible for securely clearing the returned byte slice.
func readPassword(prompt string) ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat stdin: %w", err)
	}

	// Check if stdin is a Character Device, which indicates a terminal
	if (fi.Mode() & os.ModeCharDevice) != 0 {
		if prompt != "" {
			fmt.Print(prompt)
		}
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		// Add a newline because terminal reads don't echo the Enter key
		fmt.Println()
		return bytePassword, nil
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
			return nil, fmt.Errorf("failed to read password from stdin: %w", err)
		}
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			passwordBytes = append(passwordBytes, buf[0])
		}
	}
	// Trim trailing carriage return if present
	return bytes.TrimRight(passwordBytes, "\r"), nil
}

// ensureAgentRunning starts the agent if it's not already running
func ensureAgentRunning() error {
	// Try to ping existing agent
	client, err := NewAgentClient()
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	if err := client.Ping(); err == nil {
		// Agent is already running
		logVerbose("Agent is already running")
		return nil
	}

	// Agent not running, start it
	logVerbose("Starting agent...")
	agent, err := NewAgent()
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	if err := agent.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	globalAgent = agent
	logVerbose("Agent started successfully at: %s", agent.GetSocketPath())

	return nil
}

// handleAgentCommand processes agent management commands
func handleAgentCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("subcommand required: start, stop, status")
	}

	subcommand := args[0]

	switch subcommand {
	case "start":
		return handleAgentStart()
	case "stop":
		return handleAgentStop()
	case "status":
		return handleAgentStatus()
	default:
		return fmt.Errorf("unknown subcommand: %s", subcommand)
	}
}

func handleAgentStart() error {
	// Check if already running
	client, err := NewAgentClient()
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	if err := client.Ping(); err == nil {
		fmt.Println("Agent is already running")
		return nil
	}

	// Start agent
	agent, err := NewAgent()
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	if err := agent.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	globalAgent = agent
	fmt.Printf("Agent started successfully\n")
	fmt.Printf("Socket: %s\n", agent.GetSocketPath())

	// Keep agent running
	fmt.Println("Agent is running. Press Ctrl+C to stop.")
	select {}
}

func handleAgentStop() error {
	client, err := NewAgentClient()
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	// Try to clear and stop via client
	if err := client.Clear(); err != nil {
		logVerbose("Warning: Failed to clear agent: %v", err)
	}

	// If we have a global agent, stop it
	if globalAgent != nil {
		if err := globalAgent.Stop(); err != nil {
			return fmt.Errorf("failed to stop agent: %w", err)
		}
		globalAgent = nil
	}

	fmt.Println("Agent stopped successfully")
	return nil
}

func handleAgentStatus() error {
	client, err := NewAgentClient()
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	if err := client.Ping(); err != nil {
		fmt.Println("Agent Status: NOT RUNNING")
		return nil
	}

	fmt.Println("Agent Status: RUNNING")
	fmt.Printf("Socket: %s\n", client.socketPath)
	return nil
}
