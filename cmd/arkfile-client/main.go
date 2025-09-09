// arkfile-client - Secure file sharing client with OPAQUE authentication
// This tool provides authenticated server communication for file operations

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

	"crypto/sha256"

	"golang.org/x/term"

	"github.com/84adam/Arkfile/crypto"
)

const (
	Version = "1.0.0-static"
	Usage   = `arkfile-client - Secure file sharing client with OPAQUE authentication

USAGE:
    arkfile-client [global options] command [command options] [arguments...]

COMMANDS:
    login         Authenticate with arkfile server
    upload        Upload file to server
    download      Download file from server  
    list-files    List available files
    create-share  Create anonymous share link
    logout        Logout and clear session
    version       Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL (default: https://localhost:4443)
    --config FILE       Configuration file path
    --tls-insecure      Skip TLS certificate verification (localhost only)
    --username USER     Username for authentication
    --verbose, -v       Verbose output
    --help, -h          Show help

EXAMPLES:
    arkfile-client login --username alice
    arkfile-client upload --file document.pdf
    arkfile-client download --file document.pdf --output ./downloads/
    arkfile-client --server-url https://files.example.com login --username alice
    arkfile-client create-share --file document.pdf --password sharepass123
    arkfile-client list-files
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
	SessionID           string                 `json:"sessionId"`
	FileID              string                 `json:"fileId"`
	StorageID           string                 `json:"storageId"` // For verification
	EncryptedFileSHA256 string                 `json:"encryptedFileSHA256"`
}

// FileInfo represents file metadata
type FileInfo struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	FileSize    int64     `json:"file_size"`
	ContentType string    `json:"content_type"`
	CreatedAt   time.Time `json:"created_at"`
	DownloadURL string    `json:"download_url"`
}

func main() {
	// Global flags
	var (
		serverURL   = flag.String("server-url", "https://localhost:4443", "Server URL")
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

	// Execute command
	switch command {
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
	case "create-share":
		if err := handleCreateShareCommand(client, config, args); err != nil {
			logError("Create share failed: %v", err)
			os.Exit(1)
		}
	case "logout":
		if err := handleLogoutCommand(config, args); err != nil {
			logError("Logout failed: %v", err)
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

	if resp.StatusCode >= 400 {
		return &apiResp, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiResp.Error)
	}

	return &apiResp, nil
}

// handleLoginCommand processes login command
func handleLoginCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	var (
		usernameFlag = fs.String("username", config.Username, "Username for login")
		saveSession  = fs.Bool("save-session", true, "Save session for future use")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client login [FLAGS]

Authenticate with arkfile server using OPAQUE protocol.

FLAGS:
    --username USER     Username for authentication (required)
    --save-session      Save session for future use (default: true)
    --help             Show this help message

EXAMPLES:
    arkfile-client login --username alice
    arkfile-client login --username bob --save-session=false
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

	// Perform OPAQUE login
	logVerbose("Starting OPAQUE authentication for user: %s", *usernameFlag)

	loginReq := map[string]string{
		"username": *usernameFlag,
		"password": string(password), // OPAQUE login still expects string password
	}
	// Securely clear the password from memory after it's used for loginReq
	for i := range password {
		password[i] = 0
	}

	loginResp, err := client.makeRequest("POST", "/api/opaque/login", loginReq, "")
	if err != nil {
		return fmt.Errorf("OPAQUE login failed: %w", err)
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

	fmt.Printf("✅ Login successful for user: %s\n", *usernameFlag)
	fmt.Printf("Session expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))

	return nil
}

// handleUploadCommand processes upload command
func handleUploadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	var (
		filePath     = fs.String("file", "", "File to upload (required)")
		filename     = fs.String("name", "", "Custom filename (optional)")
		chunkSize    = fs.Int("chunk-size", 16*1024*1024, "Chunk size in bytes")
		showProgress = fs.Bool("progress", true, "Show upload progress")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client upload [FLAGS]

Upload a file to the arkfile server with password-based encryption.

FLAGS:
    --file FILE         File to upload (required)
    --name NAME         Custom filename (optional, uses original if not specified)
    --chunk-size SIZE   Chunk size in bytes (default: 1048576 = 1MB)
    --progress          Show upload progress (default: true)
    --help             Show this help message

EXAMPLES:
    arkfile-client upload --file document.pdf
    arkfile-client upload --file video.mp4 --name "my-video.mp4"
    arkfile-client upload --file large.dat --chunk-size 2097152
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

	// Read file
	fileData, err := os.ReadFile(*filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Determine filename
	uploadFilename := *filename
	if uploadFilename == "" {
		uploadFilename = filepath.Base(*filePath)
	}

	logVerbose("Uploading file: %s (%d bytes)", uploadFilename, len(fileData))

	// Get password for FEK encryption
	logVerbose("Reading password for FEK encryption...")
	password, err := readPassword("Enter password to encrypt File Encryption Key (FEK): ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Generate File Encryption Key (FEK)
	fek, err := crypto.GenerateAESKey()
	if err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Encrypt file
	encryptedFile, err := crypto.EncryptGCM(fileData, fek)
	if err != nil {
		return fmt.Errorf("file encryption failed: %w", err)
	}

	// Encrypt FEK with password using Argon2ID
	encryptedFEK, err := crypto.EncryptFEKWithPassword(fek, password, session.Username, "account")
	if err != nil {
		return fmt.Errorf("FEK encryption failed: %w", err)
	}

	// Securely clear the password from memory
	for i := range password {
		password[i] = 0
	}

	// Calculate original file hash
	hash := sha256.Sum256(fileData)
	fileHash := fmt.Sprintf("%x", hash)

	// Encrypt metadata with the FEK
	encryptedFilename, err := crypto.EncryptGCM([]byte(uploadFilename), fek)
	if err != nil {
		return fmt.Errorf("filename encryption failed: %w", err)
	}

	encryptedHash, err := crypto.EncryptGCM([]byte(fileHash), fek)
	if err != nil {
		return fmt.Errorf("file hash encryption failed: %w", err)
	}

	// Create envelope for password-based encryption type
	envelope := crypto.CreatePasswordEnvelope("account")

	// Initialize chunked upload with the new, secure payload
	totalChunks := (len(encryptedFile) + *chunkSize - 1) / *chunkSize

	uploadReq := map[string]interface{}{
		"encryptedFilename":  base64.StdEncoding.EncodeToString(encryptedFilename),
		"filenameNonce":      base64.StdEncoding.EncodeToString(encryptedFilename[:12]), // GCM nonce is the first 12 bytes
		"encryptedSha256sum": base64.StdEncoding.EncodeToString(encryptedHash),
		"sha256sumNonce":     base64.StdEncoding.EncodeToString(encryptedHash[:12]), // GCM nonce is the first 12 bytes
		"encryptedFek":       base64.StdEncoding.EncodeToString(encryptedFEK),
		"totalSize":          len(fileData),
		"chunkSize":          *chunkSize,
		"passwordHint":       "", // Not implemented in this client version
		"passwordType":       "account",
		"envelopeData":       base64.StdEncoding.EncodeToString(envelope),
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
	fmt.Printf("Uploading %s (%s) in %d chunks...\n", uploadFilename, formatFileSize(int64(len(fileData))), totalChunks)

	for chunkIndex := 0; chunkIndex < totalChunks; chunkIndex++ {
		start := chunkIndex * *chunkSize
		end := start + *chunkSize
		if end > len(encryptedFile) {
			end = len(encryptedFile)
		}

		chunkData := encryptedFile[start:end]
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
			resp.Body.Close() // Ensure body is closed
			return fmt.Errorf("chunk %d upload failed: status %d, body: %s", chunkIndex, resp.StatusCode, string(bodyBytes))
		}
		resp.Body.Close() // Ensure body is closed on success too

		if *showProgress {
			progress := float64(chunkIndex+1) / float64(totalChunks) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d chunks)", progress, chunkIndex+1, totalChunks)
		}
	}

	if *showProgress {
		fmt.Println() // Add newline after progress
	}

	// Finalize upload
	finalizeReq := map[string]interface{}{
		"session_id": sessionID,
	}

	finalizeURL := fmt.Sprintf("/api/uploads/%s/complete", sessionID)
	finalizeResp, err := client.makeRequest("POST", finalizeURL, finalizeReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("upload finalization failed: %w", err)
	}

	fmt.Printf("✅ Upload completed successfully\n")
	fmt.Printf("File ID: %s\n", fileID)
	fmt.Printf("Storage ID: %s\n", finalizeResp.StorageID)
	fmt.Printf("Server-side Encrypted SHA256: %s\n", finalizeResp.EncryptedFileSHA256)
	fmt.Printf("Original size: %s\n", formatFileSize(int64(len(fileData))))
	fmt.Printf("Encrypted size: %s\n", formatFileSize(int64(len(encryptedFile))))

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
	PasswordHint      string `json:"passwordHint"`
	PasswordType      string `json:"passwordType"`
	FilenameNonce     string `json:"filenameNonce"`
	EncryptedFilename string `json:"encryptedFilename"`
	SHA256Nonce       string `json:"sha256sumNonce"`
	EncryptedSHA256   string `json:"encryptedSha256sum"`
	SizeBytes         int64  `json:"size_bytes"`
	SizeReadable      string `json:"size_readable"`
	UploadDate        string `json:"uploadDate"`
}

// handleListFilesCommand processes list-files command
func handleListFilesCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("list-files", flag.ExitOnError)
	var (
		detailed = fs.Bool("detailed", false, "Show detailed file information")
		decrypt  = fs.Bool("decrypt", true, "Decrypt filename and SHA256 metadata")
		limit    = fs.Int("limit", 50, "Maximum number of files to list")
		offset   = fs.Int("offset", 0, "Offset for pagination")
		showRaw  = fs.Bool("raw", false, "Show raw encrypted metadata (for debugging)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client list-files [FLAGS]

List files uploaded by the authenticated user with metadata decryption.

FLAGS:
    --detailed          Show detailed file information
    --decrypt           Decrypt filename and SHA256 metadata (default: true)
    --raw              Show raw encrypted metadata (for debugging)
    --limit INT         Maximum number of files to list (default: 50)
    --offset INT        Offset for pagination (default: 0)
    --help             Show this help message

EXAMPLES:
    arkfile-client list-files
    arkfile-client list-files --detailed
    arkfile-client list-files --limit 10 --offset 20
    arkfile-client list-files --raw --no-decrypt
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

	// Parse the response directly as ServerFileListResponse
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

	fmt.Printf("Files for user %s:\n\n", session.Username)

	// Get password for metadata decryption if needed
	var password string
	if *decrypt && !*showRaw {
		passwordBytes, err := readPassword("Enter password to decrypt file metadata: ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = string(passwordBytes)
		// Securely clear password bytes
		for i := range passwordBytes {
			passwordBytes[i] = 0
		}
		if password == "" {
			logError("Warning: Empty password, showing encrypted metadata")
			*decrypt = false
		}
	}

	// Display files
	if *detailed {
		for i, serverFile := range serverResponse.Files {
			fmt.Printf("%d. ", i+1)

			if *showRaw {
				fmt.Printf("[ENCRYPTED] %s\n", serverFile.EncryptedFilename)
				fmt.Printf("   File ID: %s\n", serverFile.FileID)
				fmt.Printf("   Storage ID: %s\n", serverFile.StorageID)
				fmt.Printf("   Password Type: %s\n", serverFile.PasswordType)
				fmt.Printf("   Password Hint: %s\n", serverFile.PasswordHint)
				fmt.Printf("   Filename Nonce: %s\n", serverFile.FilenameNonce)
				fmt.Printf("   Encrypted Filename: %s\n", serverFile.EncryptedFilename)
				fmt.Printf("   SHA256 Nonce: %s\n", serverFile.SHA256Nonce)
				fmt.Printf("   Encrypted SHA256: %s\n", serverFile.EncryptedSHA256)
			} else if *decrypt && password != "" {
				// Decrypt metadata
				filename, sha256sum, err := decryptFileMetadata(serverFile, password, session.Username)
				if err != nil {
					logError("Failed to decrypt metadata for file %s: %v", serverFile.FileID, err)
					fmt.Printf("[DECRYPT FAILED] %s\n", serverFile.FileID)
				} else {
					fmt.Printf("%s\n", filename)
					fmt.Printf("   SHA256: %s\n", sha256sum)
				}
				fmt.Printf("   File ID: %s\n", serverFile.FileID)
				fmt.Printf("   Storage ID: %s\n", serverFile.StorageID)
				fmt.Printf("   Password Type: %s\n", serverFile.PasswordType)
			} else {
				fmt.Printf("[ENCRYPTED] %s\n", serverFile.FileID)
				fmt.Printf("   File ID: %s\n", serverFile.FileID)
				fmt.Printf("   Storage ID: %s\n", serverFile.StorageID)
				fmt.Printf("   Password Type: %s\n", serverFile.PasswordType)
			}

			fmt.Printf("   Size: %s (%d bytes)\n", serverFile.SizeReadable, serverFile.SizeBytes)
			fmt.Printf("   Upload Date: %s\n", serverFile.UploadDate)
			fmt.Println()
		}
	} else {
		for i, serverFile := range serverResponse.Files {
			displayName := serverFile.FileID // Default to file ID

			if *showRaw {
				displayName = fmt.Sprintf("[ENCRYPTED] %s", serverFile.EncryptedFilename)
			} else if *decrypt && password != "" {
				// Decrypt filename only
				filename, _, err := decryptFileMetadata(serverFile, password, session.Username)
				if err != nil {
					logError("Failed to decrypt filename for file %s: %v", serverFile.FileID, err)
					displayName = fmt.Sprintf("[DECRYPT FAILED] %s", serverFile.FileID)
				} else {
					displayName = filename
				}
			} else {
				displayName = fmt.Sprintf("[ENCRYPTED] %s", serverFile.FileID)
			}

			fmt.Printf("%3d. %-40s %10s  %s\n", i+1, displayName, serverFile.SizeReadable, serverFile.UploadDate)
		}
	}

	fmt.Printf("\nShowing %d files (offset: %d)\n", len(serverResponse.Files), *offset)

	return nil
}

// decryptFileMetadata decrypts filename and SHA256 from server file metadata
func decryptFileMetadata(serverFile ServerFileInfo, password, username string) (string, string, error) {
	// Decode base64 encoded metadata
	encryptedFilename, err := base64.StdEncoding.DecodeString(serverFile.EncryptedFilename)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode encrypted filename: %w", err)
	}

	encryptedSHA256, err := base64.StdEncoding.DecodeString(serverFile.EncryptedSHA256)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode encrypted SHA256: %w", err)
	}

	// Use shared crypto function to decrypt metadata
	// Note: The encrypted data already contains nonces from EncryptGCM, so pass nil for nonce parameters
	filename, sha256sum, err := crypto.DecryptFileMetadata(
		nil, encryptedFilename,
		nil, encryptedSHA256,
		password, username,
	)
	if err != nil {
		return "", "", fmt.Errorf("metadata decryption failed: %w", err)
	}

	return filename, sha256sum, nil
}

// handleDownloadCommand processes download command
func handleDownloadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	var (
		fileID       = fs.String("file-id", "", "File ID to download")
		filename     = fs.String("file", "", "Filename to download (alternative to file-id)")
		outputPath   = fs.String("output", "", "Output file path (optional)")
		outputDir    = fs.String("output-dir", ".", "Output directory (default: current)")
		showProgress = fs.Bool("progress", true, "Show download progress")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client download [FLAGS]

Download a file from the arkfile server with password-based decryption.

FLAGS:
    --file-id ID        File ID to download (from list-files)
    --file FILENAME     Filename to download (alternative to file-id)
    --output PATH       Output file path (optional, uses original filename if not specified)
    --output-dir DIR    Output directory (default: current directory)
    --progress          Show download progress (default: true)
    --help             Show this help message

EXAMPLES:
    arkfile-client download --file-id abc123def456
    arkfile-client download --file document.pdf
    arkfile-client download --file-id abc123 --output ~/Downloads/my-doc.pdf
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" && *filename == "" {
		return fmt.Errorf("either file-id or file must be specified")
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

	// Find file by name if needed
	targetFileID := *fileID
	if targetFileID == "" {
		// List files and find by name
		resp, err := client.makeRequest("GET", "/api/files", nil, session.AccessToken)
		if err != nil {
			return fmt.Errorf("failed to list files: %w", err)
		}

		filesData := resp.Data["files"].([]interface{})
		found := false
		for _, fileData := range filesData {
			fileMap := fileData.(map[string]interface{})
			if fileMap["filename"].(string) == *filename {
				targetFileID = fileMap["id"].(string)
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("file not found: %s", *filename)
		}
	}

	// Get file metadata and encrypted data directly from server
	resp, err := client.makeRequest("GET", "/api/download/"+targetFileID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get file metadata: %w", err)
	}

	// Check if the response has the expected structure
	if resp.Data == nil {
		return fmt.Errorf("server returned empty response data")
	}

	fileDataInterface, exists := resp.Data["file"]
	if !exists {
		return fmt.Errorf("server response missing 'file' field")
	}

	fileData, ok := fileDataInterface.(map[string]interface{})
	if !ok {
		return fmt.Errorf("server response 'file' field has unexpected type: %T", fileDataInterface)
	}

	// Extract file size
	fileSizeInterface, exists := fileData["file_size"]
	if !exists {
		return fmt.Errorf("server response missing 'file_size' field")
	}
	fileSize := int64(fileSizeInterface.(float64))

	// Extract encrypted file data directly from response
	encryptedDataInterface, exists := fileData["data"]
	if !exists {
		return fmt.Errorf("server response missing 'data' field")
	}
	encryptedDataString, ok := encryptedDataInterface.(string)
	if !ok {
		return fmt.Errorf("server response 'data' field has unexpected type: %T", encryptedDataInterface)
	}
	encryptedData := []byte(encryptedDataString)

	logVerbose("Retrieved encrypted file data: %d bytes", len(encryptedData))

	// We'll decrypt the filename after getting the FEK to determine output path
	if *showProgress {
		fmt.Printf("Processing encrypted file (%s)...\n", formatFileSize(fileSize))
	}

	// Get encrypted FEK from metadata
	encryptedFEKInterface, exists := fileData["encrypted_fek"]
	if !exists {
		return fmt.Errorf("server response missing 'encrypted_fek' field")
	}
	encryptedFEKBase64, ok := encryptedFEKInterface.(string)
	if !ok {
		return fmt.Errorf("server response 'encrypted_fek' field has unexpected type: %T", encryptedFEKInterface)
	}
	encryptedFEK, err := base64.StdEncoding.DecodeString(encryptedFEKBase64)
	if err != nil {
		return fmt.Errorf("invalid encrypted FEK: %w", err)
	}

	// Get password to decrypt FEK
	password, err := readPassword("Enter password to decrypt File Encryption Key (FEK): ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Decrypt FEK with password using Argon2ID
	fek, _, err := crypto.DecryptFEKWithPassword(encryptedFEK, password, session.Username)
	if err != nil {
		return fmt.Errorf("FEK decryption failed: %w", err)
	}

	// Decrypt file
	plaintext, err := crypto.DecryptGCM(encryptedData, fek)
	if err != nil {
		return fmt.Errorf("file decryption failed: %w", err)
	}

	// Decrypt filename to determine the original filename for output
	var originalFilename string
	if filenameNonceInterface, exists := fileData["filenameNonce"]; exists {
		if filenameNonceBase64, ok := filenameNonceInterface.(string); ok {
			if encryptedFilenameInterface, exists := fileData["encryptedFilename"]; exists {
				if encryptedFilenameBase64, ok := encryptedFilenameInterface.(string); ok {
					_, err := base64.StdEncoding.DecodeString(filenameNonceBase64)
					if err == nil {
						encryptedFilename, err := base64.StdEncoding.DecodeString(encryptedFilenameBase64)
						if err == nil {
							decryptedFilename, _, err := crypto.DecryptFileMetadata(
								nil, encryptedFilename,
								nil, nil, // We don't need SHA256 for download
								string(password), session.Username,
							)
							if err == nil {
								originalFilename = decryptedFilename
							}
						}
					}
				}
			}
		}
	}

	// Fallback to file ID if filename decryption failed
	if originalFilename == "" {
		originalFilename = targetFileID + ".decrypted"
		logVerbose("Warning: Could not decrypt filename, using fallback: %s", originalFilename)
	}

	// Securely clear the password from memory
	for i := range password {
		password[i] = 0
	}

	// Determine output path
	finalOutputPath := *outputPath
	if finalOutputPath == "" {
		finalOutputPath = filepath.Join(*outputDir, originalFilename)
	}

	// Write file
	if err := os.WriteFile(finalOutputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("✅ Download completed successfully\n")
	fmt.Printf("File saved to: %s\n", finalOutputPath)
	fmt.Printf("Original filename: %s\n", originalFilename)
	fmt.Printf("Size: %s\n", formatFileSize(int64(len(plaintext))))

	return nil
}

// handleCreateShareCommand processes create-share command
func handleCreateShareCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("create-share", flag.ExitOnError)
	var (
		fileID        = fs.String("file-id", "", "File ID to share")
		filename      = fs.String("file", "", "Filename to share (alternative to file-id)")
		password      = fs.String("password", "", "Share password (optional, will prompt if not provided)")
		expiresInDays = fs.Int("expires", 30, "Expiration in days")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client create-share [FLAGS]

Create an anonymous share link for a file.

FLAGS:
    --file-id ID        File ID to share (from list-files)
    --file FILENAME     Filename to share (alternative to file-id)
    --password PASS     Share password (optional, will prompt if not provided)
    --expires DAYS      Expiration in days (default: 30)
    --help             Show this help message

EXAMPLES:
    arkfile-client create-share --file-id abc123def456
    arkfile-client create-share --file document.pdf --password mypass123
    arkfile-client create-share --file-id abc123 --expires 7
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" && *filename == "" {
		return fmt.Errorf("either file-id or file must be specified")
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

	// Find file by name if needed
	targetFileID := *fileID
	if targetFileID == "" {
		// List files and find by name
		resp, err := client.makeRequest("GET", "/api/files", nil, session.AccessToken)
		if err != nil {
			return fmt.Errorf("failed to list files: %w", err)
		}

		filesData := resp.Data["files"].([]interface{})
		found := false
		for _, fileData := range filesData {
			fileMap := fileData.(map[string]interface{})
			if fileMap["filename"].(string) == *filename {
				targetFileID = fileMap["id"].(string)
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("file not found: %s", *filename)
		}
	}

	// Get share password
	sharePassword := *password
	if sharePassword == "" {
		fmt.Print("Enter share password: ")
		reader := bufio.NewReader(os.Stdin)
		passwordInput, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		sharePassword = strings.TrimSpace(passwordInput)
	}

	if sharePassword == "" {
		return fmt.Errorf("share password is required")
	}

	// Create share
	createShareReq := map[string]interface{}{
		"password":        sharePassword,
		"expires_in_days": *expiresInDays,
	}

	shareResp, err := client.makeRequest("POST", "/api/files/"+targetFileID+"/share", createShareReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("share creation failed: %w", err)
	}

	shareID := shareResp.Data["share_id"].(string)
	shareURL := shareResp.Data["share_url"].(string)
	expiresAt := shareResp.Data["expires_at"].(string)

	fmt.Printf("✅ Share created successfully\n")
	fmt.Printf("Share ID: %s\n", shareID)
	fmt.Printf("Share URL: %s\n", shareURL)
	fmt.Printf("Expires: %s\n", expiresAt)
	fmt.Printf("\nShare this URL with others to allow anonymous access.\n")
	fmt.Printf("They will need the password: %s\n", sharePassword)

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

	// Remove session file
	if err := os.Remove(config.TokenFile); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove session file: %w", err)
		}
	}

	fmt.Printf("✅ Logged out successfully\n")
	return nil
}

// Helper functions

func printVersion() {
	fmt.Printf("arkfile-client version %s\n", Version)
	fmt.Printf("Static binary with OPAQUE authentication\n")
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

func getContentType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".mp4":
		return "video/mp4"
	case ".mp3":
		return "audio/mpeg"
	case ".zip":
		return "application/zip"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
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

func downloadFile(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
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
	bytePassword, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read password from stdin: %w", err)
	}
	// Trim trailing newline characters which are common in piped input
	return bytes.TrimRight(bytePassword, "\r\n"), nil
}
