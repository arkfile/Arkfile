// arkfile-client - Secure file sharing client with OPAQUE authentication
// This tool provides authenticated server communication for file operations
// NOTE: This client does NOT perform any encryption/decryption operations
// All crypto operations must be done with the cryptocli tool

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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
	Version = "2.0.0-static"
	Usage   = `arkfile-client - Secure file sharing client with OPAQUE authentication

USAGE:
    arkfile-client [global options] command [command options] [arguments...]

COMMANDS:
    login         Authenticate with arkfile server
    upload        Upload pre-encrypted file to server
    download      Download encrypted file from server  
    list-files    List available files (encrypted metadata)
    logout        Logout and clear session
    version       Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL (default: https://localhost:4443)
    --config FILE       Configuration file path
    --tls-insecure      Skip TLS certificate verification (localhost only)
    --username USER     Username for authentication
    --verbose, -v       Verbose output
    --help, -h          Show help

IMPORTANT:
    This client does NOT perform encryption/decryption.
    Use 'cryptocli' for all cryptographic operations.

WORKFLOW:
    1. Encrypt file: cryptocli encrypt-password --file doc.pdf --username alice
    2. Upload: arkfile-client upload --file doc.pdf.enc --metadata metadata.json
    3. Download: arkfile-client download --file-id xyz --output encrypted.dat
    4. Decrypt: cryptocli decrypt-password --file encrypted.dat --username alice

EXAMPLES:
    arkfile-client login --username alice
    arkfile-client upload --file document.pdf.enc --metadata metadata.json
    arkfile-client download --file-id abc123 --output downloaded.enc
    arkfile-client list-files --json
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
	TempToken           string                 `json:"tempToken"`
	SessionKey          string                 `json:"sessionKey"`
	RequiresTOTP        bool                   `json:"requiresTOTP"`
	Token               string                 `json:"token"`
	RefreshToken        string                 `json:"refreshToken"`
	ExpiresAt           time.Time              `json:"expiresAt"`
	SessionID           string                 `json:"sessionId"`
	FileID              string                 `json:"fileId"`
	StorageID           string                 `json:"storageId"`
	EncryptedFileSHA256 string                 `json:"encryptedFileSHA256"`
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
		"password": string(password),
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
			"code":       totpCode,
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

	fmt.Printf("✅ Login successful for user: %s\n", *usernameFlag)
	fmt.Printf("Session expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))

	return nil
}

// handleUploadCommand processes upload command for pre-encrypted files
func handleUploadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	var (
		filePath     = fs.String("file", "", "Pre-encrypted file to upload (required)")
		metadataFile = fs.String("metadata", "", "JSON file with encrypted metadata (required)")
		chunkSize    = fs.Int("chunk-size", 16*1024*1024, "Chunk size in bytes")
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
    
    --chunk-size SIZE       Chunk size in bytes (default: 16777216 = 16MB)
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
		"totalSize":           len(encryptedData),
		"chunkSize":           *chunkSize,
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

	fmt.Printf("✅ Upload completed successfully\n")
	fmt.Printf("File ID: %s\n", fileID)
	fmt.Printf("Storage ID: %s\n", finalizeResp.StorageID)
	fmt.Printf("Server-side Encrypted SHA256: %s\n", finalizeResp.EncryptedFileSHA256)
	fmt.Printf("Encrypted file size: %s\n", formatFileSize(int64(len(encryptedData))))

	return nil
}

// handleDownloadCommand processes download command
func handleDownloadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	var (
		fileID     = fs.String("file-id", "", "File ID to download (required)")
		outputPath = fs.String("output", "", "Output file path (required)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client download [FLAGS]

Downloads an encrypted file from the server.
The downloaded file will still be encrypted - use cryptocli to decrypt it.

FLAGS:
    --file-id ID        File ID to download (required)
    --output PATH       Output file path for the encrypted data (required)
    --help             Show this help message

WORKFLOW:
    1. Download: arkfile-client download --file-id "..." --output encrypted.dat
    2. Decrypt: cryptocli decrypt-password --file encrypted.dat --username alice

EXAMPLES:
    arkfile-client download --file-id "abc123..." --output downloaded.enc
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

	// Perform a direct HTTP GET to handle the file download stream
	downloadURL := client.baseURL + "/api/download/" + *fileID
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	if client.verbose {
		logVerbose("Making GET request to %s", downloadURL)
	}

	httpResp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("server returned status %d: %s", httpResp.StatusCode, string(bodyBytes))
	}

	// Create the output file
	outFile, err := os.Create(*outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Stream the download directly to the file
	bytesWritten, err := io.Copy(outFile, httpResp.Body)
	if err != nil {
		return fmt.Errorf("failed to write downloaded data to file: %w", err)
	}

	logVerbose("Wrote %d bytes to %s", bytesWritten, *outputPath)

	fmt.Printf("✅ Encrypted file downloaded successfully\n")
	fmt.Printf("Saved to: %s\n", *outputPath)
	fmt.Printf("Size: %s\n", formatFileSize(bytesWritten))
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
	fmt.Printf("Secure file sharing client (crypto operations via cryptocli)\n")
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
	bytePassword, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read password from stdin: %w", err)
	}
	// Trim trailing newline characters which are common in piped input
	return bytes.TrimRight(bytePassword, "\r\n"), nil
}
