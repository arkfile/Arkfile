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

	"golang.org/x/term"

	"github.com/84adam/arkfile/crypto"
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
	OPAQUEExport   string    `json:"opaque_export"`
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
	fmt.Printf("Enter password for %s: ", *usernameFlag)
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Perform OPAQUE login
	logVerbose("Starting OPAQUE authentication for user: %s", *usernameFlag)

	loginReq := map[string]string{
		"username": *usernameFlag,
		"password": string(password),
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
		loginResp.OPAQUEExport = totpResp.OPAQUEExport
	}

	// Create session
	session := &AuthSession{
		Username:       *usernameFlag,
		AccessToken:    loginResp.Token,
		RefreshToken:   loginResp.RefreshToken,
		ExpiresAt:      loginResp.ExpiresAt,
		OPAQUEExport:   loginResp.OPAQUEExport,
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
	if session.OPAQUEExport != "" {
		fmt.Printf("OPAQUE export key available for cryptocli integration\n")
	}

	return nil
}

// handleUploadCommand processes upload command
func handleUploadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	var (
		filePath     = fs.String("file", "", "File to upload (required)")
		filename     = fs.String("name", "", "Custom filename (optional)")
		chunkSize    = fs.Int("chunk-size", 1024*1024, "Chunk size in bytes")
		showProgress = fs.Bool("progress", true, "Show upload progress")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client upload [FLAGS]

Upload a file to the arkfile server with encryption.

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

	// Encrypt FEK with session key derived from OPAQUE export
	opaqueExportBytes := []byte(session.OPAQUEExport)

	// Validate and derive session key using unified crypto functions
	if err := crypto.ValidateOPAQUEExportKey(opaqueExportBytes); err != nil {
		return fmt.Errorf("invalid OPAQUE export key: %w", err)
	}

	sessionKey, err := crypto.DeriveSessionKey(opaqueExportBytes, crypto.SessionKeyContext)
	if err != nil {
		return fmt.Errorf("session key derivation failed: %w", err)
	}

	encryptedFEK, err := crypto.EncryptGCM(fek, sessionKey)
	if err != nil {
		return fmt.Errorf("FEK encryption failed: %w", err)
	}

	// Initialize chunked upload
	totalChunks := (len(encryptedFile) + *chunkSize - 1) / *chunkSize

	uploadReq := map[string]interface{}{
		"filename":      uploadFilename,
		"file_size":     len(encryptedFile),
		"content_type":  getContentType(uploadFilename),
		"encrypted_fek": base64.StdEncoding.EncodeToString(encryptedFEK),
		"total_chunks":  totalChunks,
	}

	uploadResp, err := client.makeRequest("POST", "/api/upload/init", uploadReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("upload initialization failed: %w", err)
	}

	sessionID := uploadResp.Data["session_id"].(string)
	fileID := uploadResp.Data["file_id"].(string)

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

		chunkReq := map[string]interface{}{
			"session_id":  sessionID,
			"chunk_index": chunkIndex,
			"chunk_data":  base64.StdEncoding.EncodeToString(chunkData),
			"chunk_size":  len(chunkData),
		}

		_, err := client.makeRequest("POST", "/api/upload/chunk", chunkReq, session.AccessToken)
		if err != nil {
			return fmt.Errorf("chunk %d upload failed: %w", chunkIndex, err)
		}

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

	_, err = client.makeRequest("POST", "/api/upload/finalize", finalizeReq, session.AccessToken)
	if err != nil {
		return fmt.Errorf("upload finalization failed: %w", err)
	}

	fmt.Printf("✅ Upload completed successfully\n")
	fmt.Printf("File ID: %s\n", fileID)
	fmt.Printf("Original size: %s\n", formatFileSize(int64(len(fileData))))
	fmt.Printf("Encrypted size: %s\n", formatFileSize(int64(len(encryptedFile))))

	return nil
}

// handleListFilesCommand processes list-files command
func handleListFilesCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("list-files", flag.ExitOnError)
	var (
		detailed = fs.Bool("detailed", false, "Show detailed file information")
		limit    = fs.Int("limit", 50, "Maximum number of files to list")
		offset   = fs.Int("offset", 0, "Offset for pagination")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-client list-files [FLAGS]

List files uploaded by the authenticated user.

FLAGS:
    --detailed          Show detailed file information
    --limit INT         Maximum number of files to list (default: 50)
    --offset INT        Offset for pagination (default: 0)
    --help             Show this help message

EXAMPLES:
    arkfile-client list-files
    arkfile-client list-files --detailed
    arkfile-client list-files --limit 10 --offset 20
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

	// Request file list
	endpoint := fmt.Sprintf("/api/files?limit=%d&offset=%d", *limit, *offset)
	resp, err := client.makeRequest("GET", endpoint, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to list files: %w", err)
	}

	// Parse file list
	filesData, ok := resp.Data["files"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid file list response")
	}

	if len(filesData) == 0 {
		fmt.Println("No files found")
		return nil
	}

	fmt.Printf("Files for user %s:\n\n", session.Username)

	if *detailed {
		for i, fileData := range filesData {
			fileMap := fileData.(map[string]interface{})
			fmt.Printf("%d. %s\n", i+1, fileMap["filename"])
			fmt.Printf("   ID: %s\n", fileMap["id"])
			fmt.Printf("   Size: %s\n", formatFileSize(int64(fileMap["file_size"].(float64))))
			fmt.Printf("   Type: %s\n", fileMap["content_type"])
			fmt.Printf("   Created: %s\n", fileMap["created_at"])
			fmt.Println()
		}
	} else {
		for i, fileData := range filesData {
			fileMap := fileData.(map[string]interface{})
			size := formatFileSize(int64(fileMap["file_size"].(float64)))
			fmt.Printf("%3d. %-30s %10s  %s\n", i+1, fileMap["filename"], size, fileMap["created_at"])
		}
	}

	fmt.Printf("\nShowing %d files (offset: %d)\n", len(filesData), *offset)

	return nil
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

Download a file from the arkfile server.

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

	// Get file metadata and download URL
	resp, err := client.makeRequest("GET", "/api/files/"+targetFileID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get file metadata: %w", err)
	}

	fileData := resp.Data["file"].(map[string]interface{})
	originalFilename := fileData["filename"].(string)
	fileSize := int64(fileData["file_size"].(float64))
	downloadURL := fileData["download_url"].(string)

	logVerbose("Downloading file: %s (%s)", originalFilename, formatFileSize(fileSize))

	// Determine output path
	finalOutputPath := *outputPath
	if finalOutputPath == "" {
		finalOutputPath = filepath.Join(*outputDir, originalFilename)
	}

	// Download encrypted file
	if *showProgress {
		fmt.Printf("Downloading %s (%s)...\n", originalFilename, formatFileSize(fileSize))
	}

	encryptedData, err := downloadFile(client.client, downloadURL)
	if err != nil {
		return fmt.Errorf("file download failed: %w", err)
	}

	// Get encrypted FEK from metadata
	encryptedFEKBase64 := fileData["encrypted_fek"].(string)
	encryptedFEK, err := base64.StdEncoding.DecodeString(encryptedFEKBase64)
	if err != nil {
		return fmt.Errorf("invalid encrypted FEK: %w", err)
	}

	// Decrypt FEK with session key derived from OPAQUE export
	opaqueExportBytes := []byte(session.OPAQUEExport)

	// Validate and derive session key using unified crypto functions
	if err := crypto.ValidateOPAQUEExportKey(opaqueExportBytes); err != nil {
		return fmt.Errorf("invalid OPAQUE export key: %w", err)
	}

	sessionKey, err := crypto.DeriveSessionKey(opaqueExportBytes, crypto.SessionKeyContext)
	if err != nil {
		return fmt.Errorf("session key derivation failed: %w", err)
	}

	fek, err := crypto.DecryptGCM(encryptedFEK, sessionKey)
	if err != nil {
		return fmt.Errorf("FEK decryption failed: %w", err)
	}

	// Decrypt file
	plaintext, err := crypto.DecryptGCM(encryptedData, fek)
	if err != nil {
		return fmt.Errorf("file decryption failed: %w", err)
	}

	// Write file
	if err := os.WriteFile(finalOutputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("✅ Download completed successfully\n")
	fmt.Printf("File saved to: %s\n", finalOutputPath)
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
