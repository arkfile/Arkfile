// commands.go - Upload, download, list-files, share, and generate-test-file commands.
// Uses streaming per-chunk AES-GCM encryption via crypto_utils.go helpers.

package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
)

// ============================================================
// UPLOAD COMMAND
// ============================================================

func handleUploadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to file to upload")
	passwordType := fs.String("password-type", "account", "Password type: account or custom")
	hint := fs.String("hint", "", "Password hint (for custom password)")
	force := fs.Bool("force", false, "Force upload even if file is a duplicate")

	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client upload --file FILE [--password-type account|custom] [--hint HINT] [--force]\n\nEncrypt and upload a file using streaming per-chunk AES-GCM.\n")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("--file is required")
	}

	// Verify it's a seekable regular file
	if err := isSeekableFile(*filePath); err != nil {
		return err
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	accountKey, err := requireAccountKey()
	if err != nil {
		return err
	}
	defer clearBytes(accountKey)

	// Determine KEK based on password type
	var kek []byte
	var finalPasswordType string

	switch *passwordType {
	case "account":
		kek = accountKey
		finalPasswordType = "account"
	case "custom":
		customPass, err := readPasswordWithStrengthCheck(
			fmt.Sprintf("Enter custom password for %s: ", filepath.Base(*filePath)),
			"custom",
		)
		if err != nil {
			return fmt.Errorf("failed to read custom password: %w", err)
		}
		defer clearBytes(customPass)

		// Derive KEK from custom password using Argon2id
		// Uses a fixed domain-separation salt so the same password always produces the same KEK
		kek = crypto.DeriveCustomPasswordKey(customPass, "")
		defer clearBytes(kek)

		finalPasswordType = "custom"
	default:
		return fmt.Errorf("invalid --password-type: must be 'account' or 'custom'")
	}

	// Compute plaintext SHA-256 for deduplication
	logVerbose("Computing SHA-256 digest of %s...", *filePath)
	sha256hex, err := computeStreamingSHA256(*filePath)
	if err != nil {
		return fmt.Errorf("failed to compute SHA-256: %w", err)
	}
	logVerbose("Plaintext SHA-256: %s", sha256hex)

	// Deduplication check (unless --force)
	if !*force {
		agentClient, agentErr := NewAgentClient()
		if agentErr == nil {
			dedupResult, dedupErr := performDedupCheck(agentClient, client, session, accountKey, sha256hex)
			if dedupErr == nil && dedupResult.IsDuplicate {
				if dedupResult.Filename != "" {
					return fmt.Errorf("duplicate file: '%s' already exists (file_id: %s). Use --force to upload anyway", dedupResult.Filename, dedupResult.FileID)
				}
				return fmt.Errorf("duplicate file: already uploaded (file_id: %s). Use --force to upload anyway", dedupResult.FileID)
			}
		}
	}

	// Generate FEK
	fek, err := generateFEK()
	if err != nil {
		return fmt.Errorf("failed to generate file encryption key: %w", err)
	}
	defer clearBytes(fek)

	// Determine key type byte for envelope header
	var keyTypeByte byte
	if finalPasswordType == "account" {
		keyTypeByte = 0x01
	} else {
		keyTypeByte = 0x02
	}

	// Wrap FEK
	encryptedFEKB64, err := wrapFEK(fek, kek, finalPasswordType)
	if err != nil {
		return fmt.Errorf("failed to wrap FEK: %w", err)
	}

	// Encrypt metadata
	filename := filepath.Base(*filePath)
	encFilenameB64, fnNonceB64, encSHA256B64, shaNonceB64, err := encryptMetadata(filename, sha256hex, accountKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Get file size for progress reporting
	fileInfo, err := os.Stat(*filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	fileSizeBytes := fileInfo.Size()
	totalEncSize := calculateTotalEncryptedSize(fileSizeBytes)
	chunkSizeBytes := int64(crypto.PlaintextChunkSize())
	chunkCount := (fileSizeBytes + chunkSizeBytes - 1) / chunkSizeBytes
	if chunkCount == 0 {
		chunkCount = 1
	}

	logVerbose("Uploading %s (%s), %d chunks", filename, formatFileSize(fileSizeBytes), chunkCount)

	// Perform the streaming chunked upload
	fileID, err := doChunkedUpload(client, session, &ChunkedUploadParams{
		FilePath:        *filePath,
		FEK:             fek,
		KeyTypeByte:     keyTypeByte,
		EncryptedFEKB64: encryptedFEKB64,
		EncFilenameB64:  encFilenameB64,
		FnNonceB64:      fnNonceB64,
		EncSHA256B64:    encSHA256B64,
		ShaNonceB64:     shaNonceB64,
		PasswordType:    finalPasswordType,
		PasswordHint:    *hint,
		FileSizeBytes:   fileSizeBytes,
		TotalEncSize:    totalEncSize,
		ChunkCount:      chunkCount,
		ChunkSizeBytes:  chunkSizeBytes,
	})
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	fmt.Printf("Upload complete!\n")
	fmt.Printf("  File: %s\n", filename)
	fmt.Printf("  Size: %s\n", formatFileSize(fileSizeBytes))
	fmt.Printf("  File ID: %s\n", fileID)

	// Store digest in agent cache
	agentClient, agentErr := NewAgentClient()
	if agentErr == nil {
		if err := agentClient.AddDigest(fileID, sha256hex); err != nil {
			logVerbose("Warning: failed to store digest in cache: %v", err)
		}
	}

	return nil
}

// ChunkedUploadParams holds all parameters for a chunked upload
type ChunkedUploadParams struct {
	FilePath        string
	FEK             []byte
	KeyTypeByte     byte
	EncryptedFEKB64 string
	EncFilenameB64  string
	FnNonceB64      string
	EncSHA256B64    string
	ShaNonceB64     string
	PasswordType    string
	PasswordHint    string
	FileSizeBytes   int64
	TotalEncSize    int64
	ChunkCount      int64
	ChunkSizeBytes  int64
}

// doChunkedUpload performs the streaming chunked upload to the server.
// Opens the file, reads it in plaintext chunks, encrypts each chunk,
// and streams multipart chunks to the server's chunked upload endpoint.
func doChunkedUpload(client *HTTPClient, session *AuthSession, params *ChunkedUploadParams) (string, error) {
	chunkSize := crypto.PlaintextChunkSize()

	// Step 1: Initialize upload session
	initPayload := map[string]interface{}{
		"filename":           filepath.Base(params.FilePath),
		"total_size":         params.TotalEncSize,
		"chunk_size":         params.TotalEncSize / params.ChunkCount,
		"total_chunks":       params.ChunkCount,
		"encrypted_fek":      params.EncryptedFEKB64,
		"encrypted_filename": params.EncFilenameB64,
		"filename_nonce":     params.FnNonceB64,
		"encrypted_sha256":   params.EncSHA256B64,
		"sha256_nonce":       params.ShaNonceB64,
		"password_type":      params.PasswordType,
		"password_hint":      params.PasswordHint,
		"chunk_count":        params.ChunkCount,
		"chunk_size_bytes":   int64(chunkSize),
	}

	initResp, err := client.makeRequest("POST", "/api/uploads/init", initPayload, session.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to initialize upload: %w", err)
	}

	uploadID, ok := initResp.Data["session_id"].(string)
	if !ok || uploadID == "" {
		// Try upload_id as fallback
		uploadID, ok = initResp.Data["upload_id"].(string)
	}
	if !ok || uploadID == "" {
		uploadID = initResp.SessionID
	}
	if uploadID == "" {
		return "", fmt.Errorf("server did not return session_id")
	}

	logVerbose("Upload initialized with ID: %s", uploadID)

	// Step 2: Open file and stream chunks
	f, err := os.Open(params.FilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, chunkSize)
	var chunkIndex int64

	for {
		n, readErr := io.ReadFull(f, buf)
		if n == 0 && readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return "", fmt.Errorf("failed to read file at chunk %d: %w", chunkIndex, readErr)
		}

		plaintext := buf[:n]

		// Encrypt the chunk
		encryptedChunk, err := encryptChunk(plaintext, params.FEK, int(chunkIndex), params.KeyTypeByte)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt chunk %d: %w", chunkIndex, err)
		}

		// Upload the chunk
		if err := uploadChunk(client, session, uploadID, chunkIndex, encryptedChunk); err != nil {
			return "", fmt.Errorf("failed to upload chunk %d: %w", chunkIndex, err)
		}

		chunkIndex++

		if verbose {
			progress := float64(chunkIndex) / float64(params.ChunkCount) * 100
			logVerbose("  Chunk %d/%d uploaded (%.1f%%)", chunkIndex, params.ChunkCount, progress)
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	// Step 3: Finalize upload
	finalizePayload := map[string]interface{}{
		"upload_id":    uploadID,
		"total_chunks": chunkIndex,
	}

	finalizeResp, err := client.makeRequest("POST", "/api/uploads/"+uploadID+"/complete", finalizePayload, session.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to finalize upload: %w", err)
	}

	fileID := finalizeResp.FileID
	if fileID == "" {
		if val, ok := finalizeResp.Data["file_id"].(string); ok {
			fileID = val
		}
	}
	if fileID == "" {
		return "", fmt.Errorf("server did not return file_id after finalization")
	}

	return fileID, nil
}

// uploadChunk sends a single encrypted chunk to the server using multipart form
func uploadChunk(client *HTTPClient, session *AuthSession, uploadID string, chunkIndex int64, data []byte) error {
	pr, pw := io.Pipe()

	mw := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer mw.Close()

		_ = mw.WriteField("upload_id", uploadID)
		_ = mw.WriteField("chunk_index", fmt.Sprintf("%d", chunkIndex))

		fw, err := mw.CreateFormFile("chunk", fmt.Sprintf("chunk_%d", chunkIndex))
		if err != nil {
			pw.CloseWithError(err)
			return
		}

		if _, err := fw.Write(data); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	req, err := http.NewRequest("POST", client.baseURL+"/api/uploads/"+uploadID+"/chunks/"+fmt.Sprintf("%d", chunkIndex), pr)
	if err != nil {
		return fmt.Errorf("failed to create chunk request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("chunk upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("chunk upload returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ============================================================
// DOWNLOAD COMMAND
// ============================================================

func handleDownloadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to download")
	outputPath := fs.String("output", "", "Output file path (default: decrypted filename)")

	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client download --file-id FILE_ID [--output PATH]\n\nDownload and decrypt a file using streaming per-chunk AES-GCM.\n")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" {
		return fmt.Errorf("--file-id is required")
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	accountKey, err := requireAccountKey()
	if err != nil {
		return err
	}
	defer clearBytes(accountKey)

	// Fetch file metadata
	metaReq, err := http.NewRequest("GET", client.baseURL+"/api/files/"+*fileID+"/meta", nil)
	if err != nil {
		return fmt.Errorf("failed to create metadata request: %w", err)
	}
	metaReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

	metaResp, err := client.client.Do(metaReq)
	if err != nil {
		return fmt.Errorf("failed to fetch file metadata: %w", err)
	}
	defer metaResp.Body.Close()

	if metaResp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d for metadata request", metaResp.StatusCode)
	}

	var fileMeta ServerFileInfo
	if err := decodeJSONResponse(metaResp, &fileMeta); err != nil {
		return fmt.Errorf("failed to decode file metadata: %w", err)
	}

	// Decrypt filename for output path
	if *outputPath == "" && fileMeta.EncryptedFilename != "" && fileMeta.FilenameNonce != "" {
		decryptedName, err := decryptMetadataField(fileMeta.EncryptedFilename, fileMeta.FilenameNonce, accountKey)
		if err != nil {
			logVerbose("Warning: failed to decrypt filename: %v", err)
			*outputPath = *fileID + ".bin"
		} else {
			*outputPath = decryptedName
		}
	} else if *outputPath == "" {
		*outputPath = *fileID + ".bin"
	}

	// Determine KEK based on password type
	var kek []byte
	switch fileMeta.PasswordType {
	case "account", "":
		kek = accountKey
	case "custom":
		customPass, err := readPassword(fmt.Sprintf("Enter custom password for '%s': ", *outputPath))
		if err != nil {
			return fmt.Errorf("failed to read custom password: %w", err)
		}
		defer clearBytes(customPass)

		kek = crypto.DeriveCustomPasswordKey(customPass, "")
		defer clearBytes(kek)
	default:
		return fmt.Errorf("unsupported password type: %s", fileMeta.PasswordType)
	}

	// Unwrap FEK
	if fileMeta.EncryptedFEK == "" {
		return fmt.Errorf("file metadata missing encrypted FEK")
	}

	fek, _, err := unwrapFEK(fileMeta.EncryptedFEK, kek)
	if err != nil {
		return fmt.Errorf("failed to unwrap FEK (wrong password?): %w", err)
	}
	defer clearBytes(fek)

	logVerbose("Downloading %s (%s)...", *outputPath, formatFileSize(fileMeta.SizeBytes))

	// Create output file
	outFile, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Stream download by chunks
	if err := doChunkedDownload(client, session, *fileID, fek, fileMeta, outFile); err != nil {
		// Clean up partial output file on error
		outFile.Close()
		os.Remove(*outputPath)
		return fmt.Errorf("download failed: %w", err)
	}

	// Close file before computing SHA-256
	outFile.Close()

	fmt.Printf("Download complete!\n")
	fmt.Printf("  Saved to: %s\n", *outputPath)
	fmt.Printf("  Size: %s\n", formatFileSize(fileMeta.SizeBytes))

	// Verify SHA-256 integrity
	if fileMeta.EncryptedSHA256 != "" && fileMeta.SHA256Nonce != "" {
		expectedSHA256, err := decryptMetadataField(fileMeta.EncryptedSHA256, fileMeta.SHA256Nonce, accountKey)
		if err != nil {
			fmt.Printf("  [!] WARNING: Could not decrypt expected SHA-256: %v\n", err)
		} else {
			actualSHA256, err := computeStreamingSHA256(*outputPath)
			if err != nil {
				fmt.Printf("  [!] WARNING: Could not compute SHA-256 of output: %v\n", err)
			} else if actualSHA256 == expectedSHA256 {
				fmt.Printf("  [OK] SHA-256 verified: %s\n", actualSHA256)
			} else {
				return fmt.Errorf("[FAIL] SHA-256 mismatch!\n  Expected: %s\n  Got:      %s\n  File may be corrupt", expectedSHA256, actualSHA256)
			}
		}
	}

	return nil
}

// doChunkedDownload streams chunks from the server and decrypts each one
func doChunkedDownload(client *HTTPClient, session *AuthSession, fileID string, fek []byte, meta ServerFileInfo, outFile *os.File) error {
	chunkCount := meta.ChunkCount
	if chunkCount == 0 {
		chunkCount = 1
	}

	for i := int64(0); i < chunkCount; i++ {
		// Download chunk
		chunkURL := fmt.Sprintf("%s/api/files/%s/chunks/%d", client.baseURL, fileID, i)
		chunkReq, err := http.NewRequest("GET", chunkURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create chunk request for chunk %d: %w", i, err)
		}
		chunkReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

		chunkResp, err := client.client.Do(chunkReq)
		if err != nil {
			return fmt.Errorf("failed to download chunk %d: %w", i, err)
		}

		if chunkResp.StatusCode != http.StatusOK {
			chunkResp.Body.Close()
			return fmt.Errorf("server returned HTTP %d for chunk %d", chunkResp.StatusCode, i)
		}

		encryptedChunk, err := io.ReadAll(chunkResp.Body)
		chunkResp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read chunk %d body: %w", i, err)
		}

		// Decrypt the chunk
		plaintext, err := decryptChunk(encryptedChunk, fek, int(i))
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d: %w", i, err)
		}

		// Write plaintext to output file
		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write chunk %d to output: %w", i, err)
		}

		if verbose {
			progress := float64(i+1) / float64(chunkCount) * 100
			logVerbose("  Chunk %d/%d (%.1f%%)", i+1, chunkCount, progress)
		}
	}

	return nil
}

// ============================================================
// LIST FILES COMMAND
// ============================================================

func handleListFilesCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("list-files", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	rawOutput := fs.Bool("raw", false, "Output raw server response (no decryption)")
	limit := fs.Int("limit", 100, "Maximum number of files to list")
	offset := fs.Int("offset", 0, "Offset for pagination")

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	// Fetch file list
	url := fmt.Sprintf("/api/files?limit=%d&offset=%d", *limit, *offset)
	req, err := http.NewRequest("GET", client.baseURL+url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch file list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	if *rawOutput {
		// Just dump the raw response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}
		fmt.Println(string(body))
		return nil
	}

	var fileList ServerFileListResponse
	if err := decodeJSONResponse(resp, &fileList); err != nil {
		return fmt.Errorf("failed to decode file list: %w", err)
	}

	if *jsonOutput {
		// Decrypt filenames and output as JSON
		type DecryptedFile struct {
			FileID       string `json:"file_id"`
			Filename     string `json:"filename"`
			SizeBytes    int64  `json:"size_bytes"`
			SizeReadable string `json:"size_readable"`
			UploadDate   string `json:"upload_date"`
			PasswordType string `json:"password_type"`
			ChunkCount   int64  `json:"chunk_count"`
		}

		var accountKey []byte
		agentClient, agentErr := NewAgentClient()
		if agentErr == nil {
			accountKey, _ = agentClient.GetAccountKey()
		}

		decryptedFiles := make([]DecryptedFile, 0, len(fileList.Files))
		for _, f := range fileList.Files {
			df := DecryptedFile{
				FileID:       f.FileID,
				SizeBytes:    f.SizeBytes,
				SizeReadable: f.SizeReadable,
				UploadDate:   f.UploadDate,
				PasswordType: f.PasswordType,
				ChunkCount:   f.ChunkCount,
			}
			if accountKey != nil && f.EncryptedFilename != "" && f.FilenameNonce != "" {
				if name, err := decryptMetadataField(f.EncryptedFilename, f.FilenameNonce, accountKey); err == nil {
					df.Filename = name
				} else {
					df.Filename = "[encrypted]"
				}
			} else {
				df.Filename = "[encrypted]"
			}
			decryptedFiles = append(decryptedFiles, df)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(decryptedFiles)
	}

	// Human-readable table output
	if len(fileList.Files) == 0 {
		fmt.Println("No files found.")
		return nil
	}

	var accountKey []byte
	agentClient, agentErr := NewAgentClient()
	if agentErr == nil {
		accountKey, _ = agentClient.GetAccountKey()
	}

	fmt.Printf("%-36s  %-30s  %-10s  %-20s  %-8s\n",
		"FILE ID", "FILENAME", "SIZE", "UPLOADED", "TYPE")
	fmt.Println(strings.Repeat("-", 110))

	for _, f := range fileList.Files {
		filename := "[encrypted]"
		if accountKey != nil && f.EncryptedFilename != "" && f.FilenameNonce != "" {
			if name, err := decryptMetadataField(f.EncryptedFilename, f.FilenameNonce, accountKey); err == nil {
				filename = name
			}
		}

		// Truncate long filenames
		if len(filename) > 30 {
			filename = filename[:27] + "..."
		}

		size := f.SizeReadable
		if size == "" {
			size = formatFileSize(f.SizeBytes)
		}

		uploaded := f.UploadDate
		if len(uploaded) > 20 {
			uploaded = uploaded[:20]
		}

		fmt.Printf("%-36s  %-30s  %-10s  %-20s  %-8s\n",
			f.FileID, filename, size, uploaded, f.PasswordType)
	}

	fmt.Printf("\nTotal: %d files\n", len(fileList.Files))

	return nil
}

// ============================================================
// SHARE COMMANDS
// ============================================================

// ShareInfo represents share metadata from server
type ShareInfo struct {
	ShareID     string    `json:"share_id"`
	FileID      string    `json:"file_id"`
	ShareURL    string    `json:"share_url"`
	ExpiresAt   time.Time `json:"expires_at"`
	MaxDownload int       `json:"max_downloads"`
	Downloads   int       `json:"download_count"`
	HasPassword bool      `json:"has_password"`
	CreatedAt   time.Time `json:"created_at"`
}

func handleShareCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("subcommand required: create, list, delete, revoke, download")
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "create":
		return handleShareCreate(client, config, subArgs)
	case "list":
		return handleShareList(client, config, subArgs)
	case "delete", "revoke":
		return handleShareRevoke(client, config, subArgs)
	case "download":
		return handleShareDownload(client, config, subArgs)
	default:
		return fmt.Errorf("unknown share subcommand: %s (use create, list, delete, revoke, or download)", subcommand)
	}
}

func handleShareCreate(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share create", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to share")
	expiresHours := fs.Int("expires", 24, "Share expiry in hours (default: 24, 0 = no expiry)")
	maxDownloads := fs.Int("max-downloads", 0, "Maximum download count (0 = unlimited)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fileID == "" {
		return fmt.Errorf("--file-id is required")
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	accountKey, err := requireAccountKey()
	if err != nil {
		return err
	}
	defer clearBytes(accountKey)

	// Fetch file metadata to get encrypted FEK and metadata
	metaReq, err := http.NewRequest("GET", client.baseURL+"/api/files/"+*fileID+"/meta", nil)
	if err != nil {
		return fmt.Errorf("failed to create metadata request: %w", err)
	}
	metaReq.Header.Set("Authorization", "Bearer "+session.AccessToken)

	metaResp, err := client.client.Do(metaReq)
	if err != nil {
		return fmt.Errorf("failed to fetch file metadata: %w", err)
	}
	defer metaResp.Body.Close()

	if metaResp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d for metadata", metaResp.StatusCode)
	}

	var fileMeta ServerFileInfo
	if err := decodeJSONResponse(metaResp, &fileMeta); err != nil {
		return fmt.Errorf("failed to decode file metadata: %w", err)
	}

	// Determine source KEK to unwrap the FEK
	var sourceKEK []byte
	switch fileMeta.PasswordType {
	case "account", "":
		sourceKEK = accountKey
	case "custom":
		customPass, err := readPassword("Enter custom password for this file: ")
		if err != nil {
			return fmt.Errorf("failed to read custom password: %w", err)
		}
		defer clearBytes(customPass)
		sourceKEK = crypto.DeriveCustomPasswordKey(customPass, "")
		defer clearBytes(sourceKEK)
	}

	// Unwrap FEK
	fek, _, err := unwrapFEK(fileMeta.EncryptedFEK, sourceKEK)
	if err != nil {
		return fmt.Errorf("failed to unwrap FEK: %w", err)
	}
	defer clearBytes(fek)

	// Decrypt plaintext filename and SHA-256 (always encrypted with account key)
	filename := "[unknown]"
	if fileMeta.EncryptedFilename != "" && fileMeta.FilenameNonce != "" {
		if name, err := decryptMetadataField(fileMeta.EncryptedFilename, fileMeta.FilenameNonce, accountKey); err == nil {
			filename = name
		} else {
			logVerbose("Warning: could not decrypt filename: %v", err)
		}
	}

	sha256hex := ""
	if fileMeta.EncryptedSHA256 != "" && fileMeta.SHA256Nonce != "" {
		if hash, err := decryptMetadataField(fileMeta.EncryptedSHA256, fileMeta.SHA256Nonce, accountKey); err == nil {
			sha256hex = hash
		} else {
			logVerbose("Warning: could not decrypt SHA-256: %v", err)
		}
	}

	// Generate client-side share ID: 32 random bytes -> base64url without padding (43 chars)
	shareIDBytes := make([]byte, 32)
	if _, err := rand.Read(shareIDBytes); err != nil {
		return fmt.Errorf("failed to generate share ID: %w", err)
	}
	shareID := base64URLEncode(shareIDBytes)

	// Generate download token
	downloadToken, err := crypto.GenerateDownloadToken()
	if err != nil {
		return fmt.Errorf("failed to generate download token: %w", err)
	}

	// Always prompt for share password (shares require password per design)
	sharePass, err := readPasswordWithStrengthCheck("Enter share password: ", "share")
	if err != nil {
		return fmt.Errorf("failed to read share password: %w", err)
	}
	defer clearBytes(sharePass)

	// Generate share salt and derive share KEK
	saltB64, err := crypto.GenerateShareSalt()
	if err != nil {
		return fmt.Errorf("failed to generate share salt: %w", err)
	}

	shareKEK, err := crypto.DeriveShareKey(string(sharePass), saltB64)
	if err != nil {
		return fmt.Errorf("failed to derive share KEK: %w", err)
	}
	defer clearBytes(shareKEK)

	// Build the ShareEnvelope JSON: {fek, download_token, filename, size_bytes, sha256}
	envelopeJSON, err := crypto.CreateShareEnvelope(fek, downloadToken, filename, fileMeta.SizeBytes, sha256hex)
	if err != nil {
		return fmt.Errorf("failed to create share envelope: %w", err)
	}

	// Encrypt envelope with AES-GCM-AAD, binding it to this specific share_id + file_id
	aad := crypto.CreateAAD(shareID, *fileID)
	encryptedEnvelope, err := crypto.EncryptGCMWithAAD(envelopeJSON, shareKEK, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt share envelope: %w", err)
	}

	// Encode encrypted envelope and download token for server storage
	encryptedEnvelopeB64 := encodeBase64(encryptedEnvelope)
	downloadTokenB64 := encodeBase64(downloadToken)

	// Hash the download token for server-side verification
	downloadTokenHash, err := crypto.HashDownloadToken(downloadTokenB64)
	if err != nil {
		return fmt.Errorf("failed to hash download token: %w", err)
	}

	// Build the request payload matching the server's ShareRequest struct
	sharePayload := map[string]interface{}{
		"share_id":            shareID,
		"file_id":             *fileID,
		"salt":                saltB64,
		"encrypted_envelope":  encryptedEnvelopeB64,
		"download_token_hash": downloadTokenHash,
	}

	if *maxDownloads > 0 {
		sharePayload["max_accesses"] = *maxDownloads
	}

	if *expiresHours > 0 {
		sharePayload["expires_after_hours"] = *expiresHours
	}

	createResp, err := client.makeRequest("POST", "/api/shares", sharePayload, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to create share: %w", err)
	}

	shareURL := ""
	if val, ok := createResp.Data["share_url"].(string); ok {
		shareURL = val
	}

	fmt.Printf("Share created!\n")
	fmt.Printf("  File: %s\n", filename)
	fmt.Printf("  Share ID: %s\n", shareID)
	if shareURL != "" {
		fmt.Printf("  Share URL: %s\n", shareURL)
	}
	if *expiresHours > 0 {
		fmt.Printf("  Expires: %s\n", time.Now().Add(time.Duration(*expiresHours)*time.Hour).Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("  Expires: never\n")
	}
	fmt.Printf("  Password protected: yes\n")

	return nil
}

func handleShareList(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share list", flag.ExitOnError)
	fileID := fs.String("file-id", "", "Filter by file ID (optional)")
	jsonOutput := fs.Bool("json", false, "Output as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	url := "/api/shares"
	if *fileID != "" {
		url = "/api/files/" + *fileID + "/shares"
	}

	req, err := http.NewRequest("GET", client.baseURL+url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch shares: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if *jsonOutput {
		fmt.Println(string(body))
		return nil
	}

	// Parse and display shares
	var sharesResp struct {
		Shares []ShareInfo `json:"shares"`
	}
	if err := json.Unmarshal(body, &sharesResp); err != nil {
		// If parsing fails, just print the raw response
		fmt.Println(string(body))
		return nil
	}

	if len(sharesResp.Shares) == 0 {
		fmt.Println("No shares found.")
		return nil
	}

	fmt.Printf("%-36s  %-36s  %-20s  %-5s  %-5s\n",
		"SHARE ID", "FILE ID", "EXPIRES", "DL", "PWD")
	fmt.Println(strings.Repeat("-", 110))

	for _, s := range sharesResp.Shares {
		expires := "never"
		if !s.ExpiresAt.IsZero() {
			expires = s.ExpiresAt.Format("2006-01-02 15:04")
		}

		hasPass := "no"
		if s.HasPassword {
			hasPass = "yes"
		}

		downloads := fmt.Sprintf("%d", s.Downloads)
		if s.MaxDownload > 0 {
			downloads = fmt.Sprintf("%d/%d", s.Downloads, s.MaxDownload)
		}

		fmt.Printf("%-36s  %-36s  %-20s  %-5s  %-5s\n",
			s.ShareID, s.FileID, expires, downloads, hasPass)
	}

	return nil
}

func handleShareRevoke(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share delete", flag.ExitOnError)
	shareID := fs.String("share-id", "", "Share ID to revoke")
	fileID := fs.String("file-id", "", "File ID (required with share-id)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *shareID == "" {
		return fmt.Errorf("--share-id is required")
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	url := "/api/shares/" + *shareID
	if *fileID != "" {
		url = "/api/files/" + *fileID + "/shares/" + *shareID
	}

	req, err := http.NewRequest("DELETE", client.baseURL+url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke share: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Share %s revoked successfully\n", *shareID)
	return nil
}

func handleShareDownload(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share download", flag.ExitOnError)
	shareID := fs.String("share-id", "", "Share ID to download")
	outputPath := fs.String("output", "", "Output file path (default: filename from envelope)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *shareID == "" {
		return fmt.Errorf("--share-id is required")
	}

	// Step 1: Fetch share envelope (no auth required — public endpoint)
	// GET /api/public/shares/:id/envelope -> {share_id, file_id, salt, encrypted_envelope, size_bytes}
	envelopeURL := client.baseURL + "/api/public/shares/" + *shareID + "/envelope"
	envelopeReq, err := http.NewRequest("GET", envelopeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create envelope request: %w", err)
	}

	envelopeResp, err := client.client.Do(envelopeReq)
	if err != nil {
		return fmt.Errorf("failed to fetch share envelope: %w", err)
	}
	defer envelopeResp.Body.Close()

	if envelopeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(envelopeResp.Body)
		return fmt.Errorf("share not found or expired (HTTP %d): %s", envelopeResp.StatusCode, string(body))
	}

	var shareEnvelopeData struct {
		ShareID           string `json:"share_id"`
		FileID            string `json:"file_id"`
		Salt              string `json:"salt"`
		EncryptedEnvelope string `json:"encrypted_envelope"`
		SizeBytes         int64  `json:"size_bytes"`
	}
	if err := decodeJSONResponse(envelopeResp, &shareEnvelopeData); err != nil {
		return fmt.Errorf("failed to decode share envelope response: %w", err)
	}

	if shareEnvelopeData.Salt == "" {
		return fmt.Errorf("share envelope missing salt")
	}
	if shareEnvelopeData.EncryptedEnvelope == "" {
		return fmt.Errorf("share envelope missing encrypted_envelope")
	}
	if shareEnvelopeData.FileID == "" {
		return fmt.Errorf("share envelope missing file_id")
	}

	// Step 2: Prompt for share password and derive share KEK
	sharePass, err := readPassword("Enter share password: ")
	if err != nil {
		return fmt.Errorf("failed to read share password: %w", err)
	}
	defer clearBytes(sharePass)

	shareKEK, err := crypto.DeriveShareKey(string(sharePass), shareEnvelopeData.Salt)
	if err != nil {
		return fmt.Errorf("failed to derive share KEK: %w", err)
	}
	defer clearBytes(shareKEK)

	// Step 3: Decrypt the share envelope with AES-GCM-AAD
	// AAD = shareID + fileID (binds envelope to this specific share)
	encryptedEnvelope, err := decodeBase64(shareEnvelopeData.EncryptedEnvelope)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted envelope: %w", err)
	}

	aad := crypto.CreateAAD(shareEnvelopeData.ShareID, shareEnvelopeData.FileID)
	envelopeJSON, err := crypto.DecryptGCMWithAAD(encryptedEnvelope, shareKEK, aad)
	if err != nil {
		return fmt.Errorf("failed to decrypt share envelope (wrong password?): %w", err)
	}

	// Step 4: Parse the share envelope JSON to get FEK, download token, filename, sha256
	envelope, err := crypto.ParseShareEnvelope(envelopeJSON)
	if err != nil {
		return fmt.Errorf("failed to parse share envelope: %w", err)
	}

	// Decode FEK and download token from envelope
	fek, err := decodeBase64(envelope.FEK)
	if err != nil {
		return fmt.Errorf("failed to decode FEK from envelope: %w", err)
	}
	defer clearBytes(fek)

	downloadToken, err := decodeBase64(envelope.DownloadToken)
	if err != nil {
		return fmt.Errorf("failed to decode download token from envelope: %w", err)
	}
	downloadTokenB64 := encodeBase64(downloadToken)

	// Step 5: Get chunk metadata
	// GET /api/public/shares/:id/metadata -> {file_id, size_bytes, chunk_count, chunk_size_bytes}
	chunkMetaURL := client.baseURL + "/api/public/shares/" + *shareID + "/metadata"
	chunkMetaReq, err := http.NewRequest("GET", chunkMetaURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create chunk metadata request: %w", err)
	}

	chunkMetaResp, err := client.client.Do(chunkMetaReq)
	if err != nil {
		return fmt.Errorf("failed to fetch chunk metadata: %w", err)
	}
	defer chunkMetaResp.Body.Close()

	if chunkMetaResp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get chunk metadata (HTTP %d)", chunkMetaResp.StatusCode)
	}

	var chunkMeta struct {
		FileID         string `json:"file_id"`
		SizeBytes      int64  `json:"size_bytes"`
		ChunkCount     int64  `json:"chunk_count"`
		ChunkSizeBytes int64  `json:"chunk_size_bytes"`
	}
	if err := decodeJSONResponse(chunkMetaResp, &chunkMeta); err != nil {
		return fmt.Errorf("failed to decode chunk metadata: %w", err)
	}

	chunkCount := chunkMeta.ChunkCount
	if chunkCount == 0 {
		chunkCount = 1
	}

	// Determine output path from envelope filename
	filename := envelope.Filename
	if *outputPath == "" {
		if filename != "" {
			*outputPath = filename
		} else {
			*outputPath = *shareID + ".bin"
		}
	}

	sizeBytes := shareEnvelopeData.SizeBytes
	if sizeBytes == 0 {
		sizeBytes = chunkMeta.SizeBytes
	}

	fmt.Printf("Downloading shared file...\n")
	if filename != "" {
		fmt.Printf("  Filename: %s\n", filename)
	}
	fmt.Printf("  Size: %s\n", formatFileSize(sizeBytes))
	fmt.Printf("  Chunks: %d\n", chunkCount)

	// Step 6: Create output file
	outFile, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	// Step 7: Stream download + decrypt each chunk
	// GET /api/public/shares/:id/chunks/:chunkIndex with X-Download-Token header
	downloadFailed := false
	for i := int64(0); i < chunkCount; i++ {
		chunkURL := fmt.Sprintf("%s/api/public/shares/%s/chunks/%d", client.baseURL, *shareID, i)
		chunkReq, err := http.NewRequest("GET", chunkURL, nil)
		if err != nil {
			outFile.Close()
			os.Remove(*outputPath)
			return fmt.Errorf("failed to create chunk request: %w", err)
		}
		// Download token authenticates the chunk download (no user auth required)
		chunkReq.Header.Set("X-Download-Token", downloadTokenB64)

		chunkResp, err := client.client.Do(chunkReq)
		if err != nil {
			downloadFailed = true
			break
		}

		if chunkResp.StatusCode != http.StatusOK {
			chunkResp.Body.Close()
			downloadFailed = true
			err = fmt.Errorf("server returned HTTP %d for chunk %d", chunkResp.StatusCode, i)
			break
		}

		encChunk, readErr := io.ReadAll(chunkResp.Body)
		chunkResp.Body.Close()
		if readErr != nil {
			downloadFailed = true
			err = fmt.Errorf("failed to read chunk %d: %w", i, readErr)
			break
		}

		plaintext, decErr := decryptChunk(encChunk, fek, int(i))
		if decErr != nil {
			downloadFailed = true
			err = fmt.Errorf("failed to decrypt chunk %d: %w", i, decErr)
			break
		}

		if _, writeErr := outFile.Write(plaintext); writeErr != nil {
			downloadFailed = true
			err = fmt.Errorf("failed to write chunk %d: %w", i, writeErr)
			break
		}

		if verbose {
			progress := float64(i+1) / float64(chunkCount) * 100
			logVerbose("  Chunk %d/%d (%.1f%%)", i+1, chunkCount, progress)
		}
	}

	outFile.Close()

	if downloadFailed {
		os.Remove(*outputPath)
		return fmt.Errorf("download failed: %w", err)
	}

	fmt.Printf("Download complete!\n")
	fmt.Printf("  Saved to: %s\n", *outputPath)
	fmt.Printf("  Size: %s\n", formatFileSize(sizeBytes))

	// Step 8: Verify SHA-256 integrity against envelope hash
	if envelope.SHA256 != "" {
		actualSHA256, shaErr := computeStreamingSHA256(*outputPath)
		if shaErr != nil {
			fmt.Printf("  [!] WARNING: Could not compute SHA-256 for verification: %v\n", shaErr)
		} else if actualSHA256 == envelope.SHA256 {
			fmt.Printf("  [OK] SHA-256 verified: %s\n", actualSHA256)
		} else {
			return fmt.Errorf("[FAIL] SHA-256 mismatch!\n  Expected: %s\n  Got:      %s\n  File may be corrupt or tampered", envelope.SHA256, actualSHA256)
		}
	}

	return nil
}

// ============================================================
// GENERATE TEST FILE COMMAND
// ============================================================

func handleGenerateTestFileCommand(args []string) error {
	fs := flag.NewFlagSet("generate-test-file", flag.ExitOnError)
	filename := fs.String("filename", "test.bin", "Output filename")
	sizeMB := fs.Int("size-mb", 10, "File size in MB (alternative to --size)")
	sizeBytes := fs.Int64("size", 0, "Exact file size in bytes (overrides --size-mb)")
	pattern := fs.String("pattern", "random", "Data pattern: random, zeros, sequential")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var totalBytes int64
	if *sizeBytes > 0 {
		totalBytes = *sizeBytes
	} else {
		totalBytes = int64(*sizeMB) * 1024 * 1024
	}

	if totalBytes <= 0 {
		return fmt.Errorf("file size must be positive")
	}

	logVerbose("Generating %s test file (%s, %s pattern)...", *filename, formatFileSize(totalBytes), *pattern)

	f, err := os.OpenFile(*filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	const bufSize = 1024 * 1024 // 1MB write buffer
	buf := make([]byte, bufSize)
	remaining := totalBytes

	for remaining > 0 {
		toWrite := int64(bufSize)
		if remaining < toWrite {
			toWrite = remaining
		}
		chunk := buf[:toWrite]

		switch *pattern {
		case "zeros":
			for i := range chunk {
				chunk[i] = 0
			}
		case "sequential":
			for i := range chunk {
				chunk[i] = byte(i % 256)
			}
		default: // random
			if _, err := rand.Read(chunk); err != nil {
				return fmt.Errorf("failed to generate random data: %w", err)
			}
		}

		if _, err := f.Write(chunk); err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}

		remaining -= toWrite
	}

	fmt.Printf("Test file generated!\n")
	fmt.Printf("  Path: %s\n", *filename)
	fmt.Printf("  Size: %s (%d bytes)\n", formatFileSize(totalBytes), totalBytes)
	fmt.Printf("  Pattern: %s\n", *pattern)

	return nil
}
