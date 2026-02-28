// arkfile-client - unified file vault management CLI with streaming crypto
// Handles both cryptographic operations and server communication in one tool.

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

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/crypto"
	"golang.org/x/term"
)

const Version = "3.0.0"

const Usage = `arkfile-client - Unified file vault CLI with streaming encryption

USAGE:
    arkfile-client [global options] command [command options]

COMMANDS:
    register          Register a new account
    setup-totp        Setup Two-Factor Authentication (TOTP)
    generate-totp     Generate a TOTP code from a base32 secret (for scripting)
    login             Authenticate with arkfile server
    upload            Encrypt and upload a file (streaming, per-chunk AES-GCM)
    download          Download and decrypt a file (streaming, per-chunk AES-GCM)
    list-files        List files with auto-decrypted filenames
    share             Manage file shares (create, list, delete, revoke)
    share download    Download a shared file (no auth required)
    generate-test-file Generate a test file for upload testing
    logout            Logout and clear session
    agent             Manage the agent (start, stop, status)
    version           Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL (default: https://localhost:8443)
    --tls-insecure      Skip TLS certificate verification (localhost only)
    --username USER     Username for authentication
    --timeout SECS      HTTP request timeout in seconds (default: 120, min: 10, max: 600)
    --verbose, -v       Verbose output
    --help, -h          Show help

EXAMPLES:
    arkfile-client register --username alice
    arkfile-client login --username alice
    arkfile-client upload --file document.pdf --username alice
    arkfile-client upload --file document.pdf --username alice --password-type custom
    arkfile-client upload --file document.pdf --username alice --force
    arkfile-client download --file-id abc123 --output document.pdf --username alice
    arkfile-client list-files
    arkfile-client list-files --json
    arkfile-client list-files --raw
    arkfile-client share create --file-id abc123
    arkfile-client share list
    arkfile-client share download --share-id xyz --output file.pdf
    arkfile-client generate-test-file --filename test.bin --size 104857600
    arkfile-client agent start
    arkfile-client logout
`

var verbose bool

// ClientConfig holds configuration for the client
type ClientConfig struct {
	ServerURL   string `json:"server_url"`
	Username    string `json:"username"`
	TLSInsecure bool   `json:"tls_insecure"`
	TokenFile   string `json:"token_file"`
	ConfigFile  string `json:"config_file"`
	TimeoutSecs int    `json:"timeout_secs"`
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
	ChunkCount        int64  `json:"chunk_count"`
	ChunkSizeBytes    int64  `json:"chunk_size_bytes"`
}

// ServerFileListResponse represents the server's file list response format
type ServerFileListResponse struct {
	Files   []ServerFileInfo `json:"files"`
	Storage interface{}      `json:"storage"`
}

var globalAgent *Agent

func main() {
	var (
		serverURL   = flag.String("server-url", "https://localhost:8443", "Server URL")
		configFile  = flag.String("config", "", "Configuration file path")
		tlsInsecure = flag.Bool("tls-insecure", false, "Skip TLS certificate verification (localhost only)")
		username    = flag.String("username", "", "Username for authentication")
		timeoutSecs = flag.Int("timeout", 120, "HTTP request timeout in seconds (min: 10, max: 600)")
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

	// Clamp timeout to valid range
	if *timeoutSecs < 10 {
		*timeoutSecs = 10
	}
	if *timeoutSecs > 600 {
		*timeoutSecs = 600
	}

	config := &ClientConfig{
		ServerURL:   *serverURL,
		Username:    *username,
		TLSInsecure: *tlsInsecure,
		ConfigFile:  *configFile,
		TokenFile:   getSessionFilePath(),
		TimeoutSecs: *timeoutSecs,
	}

	if *configFile != "" {
		if err := loadConfigFile(config, *configFile); err != nil {
			logError("Failed to load config file: %v", err)
			os.Exit(1)
		}
	}

	client := newHTTPClient(config.ServerURL, config.TLSInsecure, config.TimeoutSecs, verbose)

	command := flag.Arg(0)
	args := flag.Args()[1:]

	// Auto-start agent for most commands
	if command != "agent" && command != "version" && command != "" {
		if err := ensureAgentRunning(); err != nil {
			logVerbose("Warning: Failed to start agent: %v", err)
		}
	}

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
	case "list-files":
		if err := handleListFilesCommand(client, config, args); err != nil {
			logError("List files failed: %v", err)
			os.Exit(1)
		}
	case "share":
		if err := handleShareCommand(client, config, args); err != nil {
			logError("Share command failed: %v", err)
			os.Exit(1)
		}
	case "generate-totp":
		if err := handleGenerateTOTPCommand(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "generate-test-file":
		if err := handleGenerateTestFileCommand(args); err != nil {
			logError("Generate test file failed: %v", err)
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

// newHTTPClient creates a new HTTP client with TLS 1.3 and configurable timeout
func newHTTPClient(baseURL string, tlsInsecure bool, timeoutSecs int, verbose bool) *HTTPClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsInsecure,
			MinVersion:         tls.VersionTLS13,
		},
	}

	return &HTTPClient{
		client:  &http.Client{Transport: tr, Timeout: time.Duration(timeoutSecs) * time.Second},
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

	// Extract fields from Data map if present
	if apiResp.Data != nil {
		if val, ok := apiResp.Data["requires_totp"].(bool); ok {
			apiResp.RequiresTOTP = val
		}
		if val, ok := apiResp.Data["temp_token"].(string); ok {
			apiResp.TempToken = val
		}
		if val, ok := apiResp.Data["session_key"].(string); ok {
			apiResp.SessionKey = val
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

// decodeJSONResponse decodes a raw http.Response body into a target struct
func decodeJSONResponse(resp *http.Response, target interface{}) error {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	return json.Unmarshal(data, target)
}

// requireSession loads and validates the current auth session.
// Returns a clear error message if not logged in.
func requireSession(config *ClientConfig) (*AuthSession, error) {
	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("not logged in. Please run: arkfile-client login --username <user>")
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired. Please run: arkfile-client login --username <user>")
	}
	return session, nil
}

// requireAccountKey gets the account key from the agent.
// Returns a clear error if agent is not running or key is not set.
func requireAccountKey() ([]byte, error) {
	agentClient, err := NewAgentClient()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to agent: %w", err)
	}

	accountKey, err := agentClient.GetAccountKey()
	if err != nil {
		return nil, fmt.Errorf("account key not found in agent. Please run: arkfile-client login --username <user>")
	}

	return accountKey, nil
}

// ============================================================
// AUTH COMMANDS
// ============================================================

func handleRegisterCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	usernameFlag := fs.String("username", config.Username, "Username for registration")

	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client register --username USER\n\nRegister a new account.\n")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	password, err := readPasswordWithStrengthCheck(
		fmt.Sprintf("Enter password for new user %s: ", *usernameFlag),
		"account",
	)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	passwordConfirm, err := readPassword("Confirm password: ")
	if err != nil {
		clearBytes(password)
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}

	if !bytes.Equal(password, passwordConfirm) {
		clearBytes(password)
		clearBytes(passwordConfirm)
		return fmt.Errorf("passwords do not match")
	}
	clearBytes(passwordConfirm)

	logVerbose("Starting OPAQUE registration for user: %s", *usernameFlag)

	clientSecret, registrationRequest, err := auth.ClientCreateRegistrationRequest(password)
	if err != nil {
		clearBytes(password)
		return fmt.Errorf("failed to create registration request: %w", err)
	}
	clearBytes(password)

	regResp, err := client.makeRequest("POST", "/api/opaque/register/response", map[string]string{
		"username":             *usernameFlag,
		"registration_request": encodeBase64(registrationRequest),
	}, "")
	if err != nil {
		return fmt.Errorf("OPAQUE registration failed: %w", err)
	}

	registrationResponseB64, ok := regResp.Data["registration_response"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing registration_response")
	}

	sessionID, ok := regResp.Data["session_id"].(string)
	if !ok || sessionID == "" {
		sessionID = regResp.SessionID
	}
	if sessionID == "" {
		return fmt.Errorf("invalid server response: missing session_id")
	}

	registrationResponse, err := decodeBase64(registrationResponseB64)
	if err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	registrationRecord, _, err := auth.ClientFinalizeRegistration(clientSecret, registrationResponse, *usernameFlag)
	if err != nil {
		return fmt.Errorf("failed to finalize registration: %w", err)
	}

	regFinalizeResp, err := client.makeRequest("POST", "/api/opaque/register/finalize", map[string]string{
		"session_id":          sessionID,
		"username":            *usernameFlag,
		"registration_record": encodeBase64(registrationRecord),
	}, "")
	if err != nil {
		return fmt.Errorf("OPAQUE registration finalization failed: %w", err)
	}

	fmt.Printf("Registration successful for user: %s\n", *usernameFlag)

	if regFinalizeResp.RequiresTOTP && regFinalizeResp.TempToken != "" {
		session := &AuthSession{
			Username:       *usernameFlag,
			TempToken:      regFinalizeResp.TempToken,
			ServerURL:      config.ServerURL,
			SessionCreated: time.Now(),
			ExpiresAt:      time.Now().Add(15 * time.Minute),
		}
		if err := saveAuthSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save session for TOTP setup: %v", err)
		} else {
			fmt.Printf("\nTOTP setup required. Please run: arkfile-client setup-totp\n")
		}
	} else {
		fmt.Printf("\nPlease login with: arkfile-client login --username %s\n", *usernameFlag)
	}

	return nil
}

func handleSetupTOTPCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("setup-totp", flag.ExitOnError)
	showSecret := fs.Bool("show-secret", false, "Only show the secret (for automation)")
	verifyCode := fs.String("verify", "", "Verify the setup with a code")

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in (use 'arkfile-client login' or 'register'): %w", err)
	}

	token := session.TempToken
	if token == "" {
		token = session.AccessToken
	}
	if token == "" {
		return fmt.Errorf("no valid session found. Please register or login first")
	}

	if *verifyCode != "" {
		return verifyTOTP(client, config, session, token, *verifyCode)
	}

	setupResp, err := client.makeRequest("POST", "/api/totp/setup", nil, token)
	if err != nil {
		return fmt.Errorf("failed to initiate TOTP setup: %w", err)
	}

	secret, ok := setupResp.Data["secret"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing secret")
	}

	if *showSecret {
		fmt.Printf("TOTP_SECRET:%s\n", secret)
		return nil
	}

	fmt.Println("=== Two-Factor Authentication Setup ===")
	fmt.Println("1. Open your authenticator app")
	fmt.Println("2. Add a new account manually")
	fmt.Printf("3. Enter this secret key: %s\n", secret)
	fmt.Println("=======================================")

	fmt.Print("Enter the 6-digit code from your app: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read code: %w", err)
	}

	return verifyTOTP(client, config, session, token, strings.TrimSpace(code))
}

func verifyTOTP(client *HTTPClient, config *ClientConfig, session *AuthSession, token, code string) error {
	verifyResp, err := client.makeRequest("POST", "/api/totp/verify", map[string]string{"code": code}, token)
	if err != nil {
		return fmt.Errorf("failed to verify TOTP code: %w", err)
	}

	if verifyResp.Token != "" {
		session.AccessToken = verifyResp.Token
		session.RefreshToken = verifyResp.RefreshToken
		session.ExpiresAt = verifyResp.ExpiresAt
		session.TempToken = ""
	}

	if err := saveAuthSession(session, config.TokenFile); err != nil {
		logError("Warning: Failed to save updated session: %v", err)
	}

	fmt.Println("TOTP Setup Complete!")

	if backupCodes, ok := verifyResp.Data["backup_codes"].([]interface{}); ok {
		fmt.Println("\n=== BACKUP CODES ===")
		fmt.Println("SAVE THESE CODES IN A SAFE PLACE!")
		fmt.Println("--------------------")
		for _, c := range backupCodes {
			fmt.Println(c)
		}
		fmt.Println("--------------------")
	}

	return nil
}

func handleLoginCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	usernameFlag := fs.String("username", config.Username, "Username")
	saveSession := fs.Bool("save-session", true, "Save session for future use")
	totpCode := fs.String("totp-code", "", "TOTP code for non-interactive login")
	totpSecret := fs.String("totp-secret", "", "TOTP secret — CLI generates the code internally (for scripted/test use)")
	nonInteractive := fs.Bool("non-interactive", false, "Don't prompt for input")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("username is required")
	}

	password, err := readPassword(fmt.Sprintf("Enter password for %s: ", *usernameFlag))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	logVerbose("Starting OPAQUE authentication for user: %s", *usernameFlag)

	clientSecret, credentialRequest, err := auth.ClientCreateCredentialRequest(password)
	if err != nil {
		clearBytes(password)
		return fmt.Errorf("failed to create credential request: %w", err)
	}
	clearBytes(password)

	authResp, err := client.makeRequest("POST", "/api/opaque/login/response", map[string]string{
		"username":           *usernameFlag,
		"credential_request": encodeBase64(credentialRequest),
	}, "")
	if err != nil {
		return fmt.Errorf("OPAQUE authentication failed: %w", err)
	}

	credentialResponseB64, ok := authResp.Data["credential_response"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing credential_response")
	}

	sessionID, ok := authResp.Data["session_id"].(string)
	if !ok || sessionID == "" {
		sessionID = authResp.SessionID
	}
	if sessionID == "" {
		return fmt.Errorf("invalid server response: missing session_id")
	}

	credentialResponse, err := decodeBase64(credentialResponseB64)
	if err != nil {
		return fmt.Errorf("failed to decode credential response: %w", err)
	}

	accountKey, authU, _, err := auth.ClientRecoverCredentials(clientSecret, credentialResponse, *usernameFlag)
	if err != nil {
		return fmt.Errorf("failed to recover credentials: %w", err)
	}

	loginResp, err := client.makeRequest("POST", "/api/opaque/login/finalize", map[string]string{
		"session_id": sessionID,
		"username":   *usernameFlag,
		"auth_u":     encodeBase64(authU),
	}, "")
	if err != nil {
		clearBytes(accountKey)
		return fmt.Errorf("OPAQUE authentication finalization failed: %w", err)
	}

	// Handle TOTP
	if loginResp.RequiresTOTP {
		var userTotpCode string
		if *totpCode != "" {
			// Explicit code provided
			userTotpCode = *totpCode
		} else if *totpSecret != "" {
			// Secret provided — generate code internally (waits for clean TOTP window)
			code, err := generateTOTPCode(*totpSecret)
			if err != nil {
				clearBytes(accountKey)
				return fmt.Errorf("failed to generate TOTP code from secret: %w", err)
			}
			userTotpCode = code
			logVerbose("Generated TOTP code from secret")
		} else if *nonInteractive {
			clearBytes(accountKey)
			return fmt.Errorf("non-interactive mode: --totp-code or --totp-secret required")
		} else {
			fmt.Print("Enter TOTP code: ")
			reader := bufio.NewReader(os.Stdin)
			totpInput, err := reader.ReadString('\n')
			if err != nil {
				clearBytes(accountKey)
				return fmt.Errorf("failed to read TOTP code: %w", err)
			}
			userTotpCode = strings.TrimSpace(totpInput)
		}

		totpResp, err := client.makeRequest("POST", "/api/totp/auth", map[string]interface{}{
			"code":       userTotpCode,
			"sessionKey": loginResp.SessionKey,
			"isBackup":   false,
		}, loginResp.TempToken)
		if err != nil {
			clearBytes(accountKey)
			return fmt.Errorf("TOTP authentication failed: %w", err)
		}

		loginResp.Token = totpResp.Token
		loginResp.RefreshToken = totpResp.RefreshToken
		loginResp.ExpiresAt = totpResp.ExpiresAt
	}

	session := &AuthSession{
		Username:       *usernameFlag,
		AccessToken:    loginResp.Token,
		RefreshToken:   loginResp.RefreshToken,
		ExpiresAt:      loginResp.ExpiresAt,
		ServerURL:      config.ServerURL,
		SessionCreated: time.Now(),
	}

	if *saveSession {
		if err := saveAuthSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save session: %v", err)
		}
	}

	// Store account key in agent
	agentClient, err := NewAgentClient()
	if err != nil {
		logVerbose("Warning: Failed to create agent client: %v", err)
	} else {
		if err := agentClient.StoreAccountKey(accountKey); err != nil {
			logVerbose("Warning: Failed to store account key in agent: %v", err)
		} else {
			logVerbose("Account key stored in agent")
		}

		// Populate digest cache from existing files
		if err := populateDigestCache(client, session, accountKey, agentClient); err != nil {
			logVerbose("Warning: Failed to populate digest cache: %v", err)
		}
	}

	defer clearBytes(accountKey)

	fmt.Printf("Login successful for user: %s\n", *usernameFlag)
	fmt.Printf("Session expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))

	return nil
}

// populateDigestCache fetches the file list and populates the agent's digest cache
func populateDigestCache(client *HTTPClient, session *AuthSession, accountKey []byte, agentClient *AgentClient) error {
	req, err := http.NewRequest("GET", client.baseURL+"/api/files?limit=1000&offset=0", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var fileList ServerFileListResponse
	if err := decodeJSONResponse(resp, &fileList); err != nil {
		return err
	}

	cache := make(map[string]string, len(fileList.Files))
	for _, f := range fileList.Files {
		if f.EncryptedSHA256 == "" || f.SHA256Nonce == "" {
			continue
		}
		sha256hex, err := decryptMetadataField(f.EncryptedSHA256, f.SHA256Nonce, accountKey)
		if err != nil {
			logVerbose("Warning: failed to decrypt sha256 for file %s: %v", f.FileID, err)
			continue
		}
		cache[f.FileID] = sha256hex
	}

	if err := agentClient.StoreDigestCache(cache); err != nil {
		return fmt.Errorf("failed to store digest cache: %w", err)
	}

	logVerbose("Digest cache populated with %d entries", len(cache))
	return nil
}

func handleLogoutCommand(config *ClientConfig, args []string) error {
	agentClient, err := NewAgentClient()
	if err != nil {
		logVerbose("Warning: Failed to create agent client: %v", err)
	} else {
		if err := agentClient.Clear(); err != nil {
			logVerbose("Warning: Failed to clear agent: %v", err)
		}
	}

	if err := os.Remove(config.TokenFile); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove session file: %w", err)
		}
	}

	fmt.Println("Logged out successfully")
	return nil
}

// ============================================================
// AGENT COMMANDS
// ============================================================

func handleAgentCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("subcommand required: start, stop, status")
	}

	switch args[0] {
	case "start":
		return handleAgentStart()
	case "stop":
		return handleAgentStop()
	case "status":
		return handleAgentStatus()
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func handleAgentStart() error {
	client, err := NewAgentClient()
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	if err := client.Ping(); err == nil {
		fmt.Println("Agent is already running")
		return nil
	}

	agent, err := NewAgent()
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	if err := agent.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	globalAgent = agent
	fmt.Printf("Agent started\nSocket: %s\n", agent.GetSocketPath())
	fmt.Println("Agent is running. Press Ctrl+C to stop.")
	select {}
}

func handleAgentStop() error {
	client, err := NewAgentClient()
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	if err := client.Clear(); err != nil {
		logVerbose("Warning: Failed to clear agent: %v", err)
	}

	if globalAgent != nil {
		if err := globalAgent.Stop(); err != nil {
			return fmt.Errorf("failed to stop agent: %w", err)
		}
		globalAgent = nil
	}

	fmt.Println("Agent stopped")
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

// ============================================================
// HELPER FUNCTIONS
// ============================================================

func printVersion() {
	fmt.Printf("arkfile-client version %s\n", Version)
	fmt.Printf("Unified file vault CLI with streaming per-chunk AES-GCM encryption\n")
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

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
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

// encodeBase64 encodes bytes to base64 string (used for API transmission)
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes a base64 string to bytes
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// readPassword reads a password securely from terminal (no echo) or stdin
func readPassword(prompt string) ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat stdin: %w", err)
	}

	if (fi.Mode() & os.ModeCharDevice) != 0 {
		if prompt != "" {
			fmt.Print(prompt)
		}
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		fmt.Println()
		return bytePassword, nil
	}

	// Not a terminal: read from stdin byte-by-byte
	var passwordBytes []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			passwordBytes = append(passwordBytes, buf[0])
		}
	}
	return bytes.TrimRight(passwordBytes, "\r"), nil
}

// readPasswordWithStrengthCheck prompts for password, validates strength, loops until valid
func readPasswordWithStrengthCheck(prompt, context string) ([]byte, error) {
	for {
		password, err := readPassword(prompt)
		if err != nil {
			return nil, err
		}

		var result *crypto.PasswordValidationResult
		switch context {
		case "account":
			result = crypto.ValidateAccountPassword(string(password))
		case "custom":
			result = crypto.ValidateCustomPassword(string(password))
		case "share":
			result = crypto.ValidateSharePassword(string(password))
		default:
			result = crypto.ValidateAccountPassword(string(password))
		}

		// Display strength feedback
		scoreLabels := []string{"VERY WEAK", "WEAK", "FAIR", "STRONG", "VERY STRONG"}
		label := scoreLabels[0]
		if result.StrengthScore >= 0 && result.StrengthScore < len(scoreLabels) {
			label = scoreLabels[result.StrengthScore]
		}
		fmt.Printf("Password strength: %s (score %d/4)\n", label, result.StrengthScore)

		if result.Requirements.Length.Met {
			fmt.Printf("  [OK] %s\n", result.Requirements.Length.Message)
		} else {
			fmt.Printf("  [X] %s\n", result.Requirements.Length.Message)
		}
		if result.Requirements.Uppercase.Met {
			fmt.Printf("  [OK] %s\n", result.Requirements.Uppercase.Message)
		} else {
			fmt.Printf("  [X] %s\n", result.Requirements.Uppercase.Message)
		}
		if result.Requirements.Lowercase.Met {
			fmt.Printf("  [OK] %s\n", result.Requirements.Lowercase.Message)
		} else {
			fmt.Printf("  [X] %s\n", result.Requirements.Lowercase.Message)
		}
		if result.Requirements.Number.Met {
			fmt.Printf("  [OK] %s\n", result.Requirements.Number.Message)
		} else {
			fmt.Printf("  [X] %s\n", result.Requirements.Number.Message)
		}
		if result.Requirements.Special.Met {
			fmt.Printf("  [OK] %s\n", result.Requirements.Special.Message)
		} else {
			fmt.Printf("  [X] %s\n", result.Requirements.Special.Message)
		}
		for _, suggestion := range result.Suggestions {
			fmt.Printf("  [i] %s\n", suggestion)
		}

		if result.MeetsRequirement {
			return password, nil
		}

		fmt.Println()
		fmt.Println("Password does not meet requirements. Please try again.")
		clearBytes(password)
	}
}

func ensureAgentRunning() error {
	agentClient, err := NewAgentClient()
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	if err := agentClient.Ping(); err == nil {
		logVerbose("Agent is already running")
		return nil
	}

	logVerbose("Starting agent...")
	agent, err := NewAgent()
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	if err := agent.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	globalAgent = agent
	logVerbose("Agent started at: %s", agent.GetSocketPath())
	return nil
}
