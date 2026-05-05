// commands.go - Upload, download, list-files, share, and generate-test-file commands.
// Uses streaming per-chunk AES-GCM encryption via crypto_utils.go helpers.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
)

// ============================================================
// UPLOAD COMMAND
// ============================================================

// multiStringFlag implements flag.Value for repeatable --file flags.
// Each occurrence appends to the slice. This is what enables
//
//	arkfile-client upload --file a --file b --file c
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// collectUploadInputs builds the deduplicated, deterministically-ordered
// list of files to upload from the various input sources:
//   - repeatable --file flag values
//   - positional args
//   - --dir DIR (non-recursive by default; --recursive opts in)
//
// Hidden files (starting with '.') are skipped. Non-regular files are
// skipped. Symlinks that resolve outside the supplied --dir root are
// rejected so a malicious symlink cannot exfiltrate arbitrary files.
//
// Returns paths in stable sorted order so behavior is reproducible.
func collectUploadInputs(fileFlags []string, positional []string, dir string, recursive bool) ([]string, error) {
	seen := make(map[string]struct{})
	results := make([]string, 0, len(fileFlags)+len(positional))

	addPath := func(p string) error {
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("failed to resolve %s: %w", p, err)
		}
		if _, ok := seen[abs]; ok {
			return nil
		}
		if err := isSeekableFile(p); err != nil {
			return fmt.Errorf("not uploadable: %w", err)
		}
		seen[abs] = struct{}{}
		results = append(results, p)
		return nil
	}

	for _, p := range fileFlags {
		if p == "" {
			continue
		}
		if err := addPath(p); err != nil {
			return nil, err
		}
	}
	for _, p := range positional {
		if p == "" {
			continue
		}
		if err := addPath(p); err != nil {
			return nil, err
		}
	}

	if dir != "" {
		dirAbs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve --dir: %w", err)
		}
		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, werr error) error {
			if werr != nil {
				return werr
			}
			// Skip dotfiles and dot-directories.
			base := filepath.Base(path)
			if base != "." && strings.HasPrefix(base, ".") {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if info.IsDir() {
				if path == dir {
					return nil
				}
				if !recursive {
					return filepath.SkipDir
				}
				return nil
			}
			// Only regular files. This excludes sockets, pipes, devices, etc.
			if info.Mode()&os.ModeType != 0 {
				// Possibly a symlink: resolve and ensure it stays inside dirAbs.
				if info.Mode()&os.ModeSymlink != 0 {
					real, err := filepath.EvalSymlinks(path)
					if err != nil {
						logVerbose("Skipping symlink %s: %v", path, err)
						return nil
					}
					realAbs, err := filepath.Abs(real)
					if err != nil {
						return nil
					}
					rel, err := filepath.Rel(dirAbs, realAbs)
					if err != nil || strings.HasPrefix(rel, "..") {
						logVerbose("Skipping symlink that escapes --dir root: %s -> %s", path, realAbs)
						return nil
					}
					st, err := os.Stat(realAbs)
					if err != nil || !st.Mode().IsRegular() {
						return nil
					}
					// Fall through and add the resolved path.
					path = realAbs
				} else {
					return nil
				}
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return nil
			}
			if _, ok := seen[abs]; ok {
				return nil
			}
			seen[abs] = struct{}{}
			results = append(results, path)
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("failed to walk --dir: %w", walkErr)
		}
	}

	sort.Strings(results)
	return results, nil
}

func handleUploadCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	var fileFlags multiStringFlag
	fs.Var(&fileFlags, "file", "Path to a file to upload (may be repeated for multiple files)")
	dir := fs.String("dir", "", "Directory of files to upload (non-recursive by default)")
	recursive := fs.Bool("recursive", false, "When used with --dir, recurse into subdirectories")
	passwordType := fs.String("password-type", "account", "Password type: account or custom")
	hint := fs.String("hint", "", "Password hint (for custom password) -- one hint applies to every file in the batch")
	force := fs.Bool("force", false, "Force upload even if a file is a duplicate")

	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client upload [--file FILE]... [PATHS...] [--dir DIR [--recursive]] [--password-type account|custom] [--hint HINT] [--force]\n\n" +
			"Encrypt and upload one or more files sequentially using streaming per-chunk AES-GCM.\n" +
			"Multiple files may be supplied via repeated --file flags, positional path arguments, and/or a --dir.\n" +
			"One password (and one hint) applies to every file in the batch.\n" +
			"Files are uploaded one at a time. Per-file failures are logged and skipped; fatal\n" +
			"conditions (auth expired, quota exceeded, account disabled, server's per-user upload\n" +
			"session cap reached) abort the batch and the remaining files are reported as skipped.\n" +
			"The JWT is refreshed proactively between files when within 5 minutes of expiry.\n")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	files, err := collectUploadInputs([]string(fileFlags), fs.Args(), *dir, *recursive)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no files supplied: provide --file, positional arguments, and/or --dir")
	}

	// Resolve session and account key once for the whole batch.
	session, err := requireSession(config)
	if err != nil {
		return err
	}

	accountKey, err := requireAccountKey()
	if err != nil {
		return err
	}
	defer clearBytes(accountKey)

	// Determine KEK once for the whole batch. Same password applies to
	// every file -- this matches the documented UX (one prompt per
	// multi-select). Per-file custom passwords are still trivially
	// achievable by uploading one file at a time.
	var kek []byte
	var finalPasswordType string
	switch *passwordType {
	case "account":
		kek = accountKey
		finalPasswordType = "account"
	case "custom":
		customPass, err := readPasswordWithStrengthCheck(
			"Enter custom password for this batch: ",
			"custom",
		)
		if err != nil {
			return fmt.Errorf("failed to read custom password: %w", err)
		}
		defer clearBytes(customPass)
		kek = crypto.DeriveCustomPasswordKey(customPass, config.Username)
		defer clearBytes(kek)
		finalPasswordType = "custom"
	default:
		return fmt.Errorf("invalid --password-type: must be 'account' or 'custom'")
	}

	// Set up SIGINT handler so the user can interrupt cleanly between
	// files. The current file is allowed to finish; the next iteration
	// of the loop observes the flag and reports remaining files as skipped.
	interrupted := false
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	go func() {
		if _, ok := <-sigCh; ok {
			interrupted = true
		}
	}()

	if len(files) > 1 {
		fmt.Printf("Uploading %d files sequentially...\n", len(files))
	}

	succeeded := 0
	failed := 0
	skipped := 0
	var fatalReason string

	for i, path := range files {
		if interrupted {
			skipped++
			fmt.Printf("[!] %s: skipped (interrupted)\n", filepath.Base(path))
			continue
		}

		// Preemptively refresh the JWT if it's near expiry. This
		// prevents mid-chunk 401s on long batches.
		if rerr := ensureFreshSessionToken(client, session, 0); rerr != nil {
			fatalReason = fmt.Sprintf("session refresh failed before %s: %v", filepath.Base(path), rerr)
			fmt.Printf("[X] %s: %s\n", filepath.Base(path), fatalReason)
			// Mark this file failed, then mark remaining as skipped.
			failed++
			for j := i + 1; j < len(files); j++ {
				fmt.Printf("[!] %s: skipped (session expired earlier in batch)\n", filepath.Base(files[j]))
				skipped++
			}
			break
		}

		fileID, err := uploadOneFile(client, session, config, accountKey, kek, finalPasswordType, *hint, path, *force)
		if err == nil {
			succeeded++
			fmt.Printf("[OK] %s (file_id=%s)\n", filepath.Base(path), fileID)
			continue
		}

		// Classify error.
		if isFatalUploadError(err) {
			fatalReason = err.Error()
			failed++
			fmt.Printf("[X] %s: %s\n", filepath.Base(path), err)
			for j := i + 1; j < len(files); j++ {
				fmt.Printf("[!] %s: skipped (aborted after fatal error)\n", filepath.Base(files[j]))
				skipped++
			}
			break
		}

		// Non-fatal: record and continue.
		failed++
		fmt.Printf("[X] %s: %s\n", filepath.Base(path), err)
	}

	// Final summary line.
	if len(files) > 1 || failed > 0 || skipped > 0 {
		fmt.Printf("\nUploaded: %d. Failed: %d. Skipped: %d.\n", succeeded, failed, skipped)
		if fatalReason != "" {
			fmt.Printf("Aborted: %s\n", fatalReason)
		}
	}

	if failed > 0 || skipped > 0 {
		// Non-zero exit: scripts can detect partial failure cleanly.
		// We still return a Go error so main()'s logError + os.Exit(1)
		// path runs.
		return fmt.Errorf("batch finished with %d failed and %d skipped (uploaded %d/%d)",
			failed, skipped, succeeded, len(files))
	}

	return nil
}

// uploadOneFile performs the full per-file upload pipeline using the
// already-resolved session, accountKey and KEK. Used by the multi-file
// batch loop. Errors classified as fatal by isFatalUploadError() abort
// the batch; other errors mark the file as failed and the loop moves on.
func uploadOneFile(client *HTTPClient, session *AuthSession, config *ClientConfig, accountKey, kek []byte, finalPasswordType, hint, filePath string, force bool) (string, error) {
	if err := isSeekableFile(filePath); err != nil {
		return "", err
	}

	// Compute plaintext SHA-256 for deduplication.
	logVerbose("Computing SHA-256 digest of %s...", filePath)
	sha256hex, err := computeStreamingSHA256(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to compute SHA-256: %w", err)
	}
	logVerbose("Plaintext SHA-256: %s", sha256hex)

	// Deduplication check (unless --force). Duplicates are non-fatal:
	// the file is fine, just already uploaded. Reported as a skippable
	// failure so the rest of the batch can continue.
	if !force {
		agentClient, agentErr := NewAgentClient()
		if agentErr == nil {
			dedupResult, dedupErr := performDedupCheck(agentClient, client, session, accountKey, sha256hex)
			if dedupErr == nil && dedupResult.IsDuplicate {
				if dedupResult.Filename != "" {
					return "", fmt.Errorf("duplicate of '%s' (file_id=%s); use --force to upload anyway", dedupResult.Filename, dedupResult.FileID)
				}
				return "", fmt.Errorf("duplicate (file_id=%s); use --force to upload anyway", dedupResult.FileID)
			}
		}
	}

	// Generate FEK and wrap it.
	fek, err := generateFEK()
	if err != nil {
		return "", fmt.Errorf("failed to generate file encryption key: %w", err)
	}
	defer clearBytes(fek)

	keyTypeByte := byte(0x01)
	if finalPasswordType == "custom" {
		keyTypeByte = 0x02
	}

	encryptedFEKB64, err := wrapFEK(fek, kek, finalPasswordType)
	if err != nil {
		return "", fmt.Errorf("failed to wrap FEK: %w", err)
	}

	// Encrypt metadata (always with account key).
	filename := filepath.Base(filePath)
	encFilenameB64, fnNonceB64, encSHA256B64, shaNonceB64, err := encryptMetadata(filename, sha256hex, accountKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}
	fileSizeBytes := fileInfo.Size()
	if fileSizeBytes == 0 {
		return "", fmt.Errorf("cannot upload empty file (0 bytes): %s", filepath.Base(filePath))
	}
	totalEncSize := calculateTotalEncryptedSize(fileSizeBytes)
	chunkSizeBytes := int64(crypto.PlaintextChunkSize())
	chunkCount := (fileSizeBytes + chunkSizeBytes - 1) / chunkSizeBytes
	if chunkCount == 0 {
		chunkCount = 1
	}

	logVerbose("Uploading %s (%s), %d chunks", filename, formatFileSize(fileSizeBytes), chunkCount)

	fileID, err := doChunkedUpload(client, session, &ChunkedUploadParams{
		FilePath:        filePath,
		FEK:             fek,
		KeyTypeByte:     keyTypeByte,
		EncryptedFEKB64: encryptedFEKB64,
		EncFilenameB64:  encFilenameB64,
		FnNonceB64:      fnNonceB64,
		EncSHA256B64:    encSHA256B64,
		ShaNonceB64:     shaNonceB64,
		PasswordType:    finalPasswordType,
		PasswordHint:    hint,
		FileSizeBytes:   fileSizeBytes,
		TotalEncSize:    totalEncSize,
		ChunkCount:      chunkCount,
		ChunkSizeBytes:  chunkSizeBytes,
	})
	if err != nil {
		return "", fmt.Errorf("upload failed: %w", err)
	}

	logVerbose("Upload complete: file=%s size=%s file_id=%s", filename, formatFileSize(fileSizeBytes), fileID)

	// Store digest in agent cache so future uploads in the same session
	// can short-circuit duplicate uploads quickly.
	agentClient, agentErr := NewAgentClient()
	if agentErr == nil {
		if err := agentClient.AddDigest(fileID, sha256hex); err != nil {
			logVerbose("Warning: failed to store digest in cache: %v", err)
		}
	}

	return fileID, nil
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

	// Step 1: Initialize upload session - send exactly what the server expects
	initPayload := map[string]interface{}{
		"encrypted_filename":  params.EncFilenameB64,
		"filename_nonce":      params.FnNonceB64,
		"encrypted_sha256sum": params.EncSHA256B64,
		"sha256sum_nonce":     params.ShaNonceB64,
		"encrypted_fek":       params.EncryptedFEKB64,
		"total_size":          params.TotalEncSize,
		"chunk_size":          int64(chunkSize),
		"password_type":       params.PasswordType,
		"password_hint":       params.PasswordHint,
	}

	initResp, err := client.makeRequestWithSession("POST", "/api/uploads/init", initPayload, session)
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

	finalizeResp, err := client.makeRequestWithSession("POST", "/api/uploads/"+uploadID+"/complete", finalizePayload, session)
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

// uploadChunk sends a single encrypted chunk to the server as raw bytes.
// Computes SHA-256 of the encrypted chunk and sends it as X-Chunk-Hash header,
// as required by the server's UploadChunk handler.
func uploadChunk(client *HTTPClient, session *AuthSession, uploadID string, chunkIndex int64, data []byte) error {
	h := sha256.Sum256(data)
	chunkHash := hex.EncodeToString(h[:])

	url := fmt.Sprintf("%s/api/uploads/%s/chunks/%d", client.baseURL, uploadID, chunkIndex)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create chunk request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Chunk-Hash", chunkHash)
	req.ContentLength = int64(len(data))

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

		kek = crypto.DeriveCustomPasswordKey(customPass, config.Username)
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
			// Pass empty token for read-only listing (no session binding check)
			accountKey, _ = agentClient.GetAccountKey("")
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
		// Pass empty token for read-only listing (no session binding check)
		accountKey, _ = agentClient.GetAccountKey("")
	}

	sep := strings.Repeat("-", 80)
	for i, f := range fileList.Files {
		filename := "[encrypted]"
		if accountKey != nil && f.EncryptedFilename != "" && f.FilenameNonce != "" {
			if name, err := decryptMetadataField(f.EncryptedFilename, f.FilenameNonce, accountKey); err == nil {
				filename = name
			}
		}

		size := f.SizeReadable
		if size == "" {
			size = formatFileSize(f.SizeBytes)
		}

		fmt.Println(sep)
		fmt.Printf("File %d of %d\n", i+1, len(fileList.Files))
		fmt.Printf("  File ID:   %s\n", f.FileID)
		fmt.Printf("  Filename:  %s\n", filename)
		fmt.Printf("  Size:      %s\n", size)
		fmt.Printf("  Uploaded:  %s\n", f.UploadDate)
		fmt.Printf("  Type:      %s\n", f.PasswordType)
	}

	fmt.Printf("\nTotal: %d files\n", len(fileList.Files))

	return nil
}

// ============================================================
// SHARE COMMANDS
// ============================================================

// ShareInfo represents share metadata from server
type ShareInfo struct {
	ShareID       string      `json:"share_id"`
	FileID        string      `json:"file_id"`
	ShareURL      string      `json:"share_url"`
	CreatedAt     string      `json:"created_at"`
	ExpiresAt     interface{} `json:"expires_at"`
	RevokedAt     interface{} `json:"revoked_at"`
	RevokedReason interface{} `json:"revoked_reason"`
	AccessCount   int         `json:"access_count"`
	MaxAccesses   interface{} `json:"max_accesses"`
	SizeBytes     int64       `json:"size_bytes"`
	IsActive      bool        `json:"is_active"`
}

type ShareListResponse struct {
	Shares   []ShareInfo `json:"shares"`
	Limit    int         `json:"limit"`
	Offset   int         `json:"offset"`
	Returned int         `json:"returned"`
	HasMore  bool        `json:"has_more"`
}

type FileMetadataBatchResponse struct {
	Files   map[string]ServerFileInfo `json:"files"`
	Missing []string                  `json:"missing"`
}

type EnrichedShareInfo struct {
	ShareID           string `json:"share_id"`
	FileID            string `json:"file_id"`
	ShareURL          string `json:"share_url"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	RevokedAt         string `json:"revoked_at,omitempty"`
	RevokedReason     string `json:"revoked_reason,omitempty"`
	AccessCount       int    `json:"access_count"`
	MaxAccesses       *int   `json:"max_accesses,omitempty"`
	SizeBytes         int64  `json:"size_bytes"`
	IsActive          bool   `json:"is_active"`
	PasswordType      string `json:"password_type,omitempty"`
	FilenameLocal     string `json:"filename_local,omitempty"`
	SizeBytesLocal    int64  `json:"size_bytes_local,omitempty"`
	SizeReadableLocal string `json:"size_readable_local,omitempty"`
	SHA256Local       string `json:"sha256_local,omitempty"`
	MetadataDecrypted bool   `json:"metadata_decrypted"`
}

func handleShareCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("subcommand required: create, list, revoke, download")
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "create":
		return handleShareCreate(client, config, subArgs)
	case "list":
		return handleShareList(client, config, subArgs)
	case "revoke":
		return handleShareRevoke(client, config, subArgs)
	case "download":
		return handleShareDownload(client, config, subArgs)
	default:
		return fmt.Errorf("unknown share subcommand: %s (use create, list, revoke, or download)", subcommand)
	}
}

// parseDuration parses a human-friendly duration string like "2m", "24h", "7d"
// into minutes. Supported suffixes: m (minutes), h (hours), d (days).
// Returns 0 for empty string or "0" (no expiry).
func parseDuration(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}

	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration format: %q (use e.g. 2m, 24h, 7d)", s)
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]

	var num int
	if _, err := fmt.Sscanf(numStr, "%d", &num); err != nil {
		return 0, fmt.Errorf("invalid duration number: %q", numStr)
	}
	if num < 0 {
		return 0, fmt.Errorf("duration must be non-negative")
	}

	switch unit {
	case 'm':
		return num, nil
	case 'h':
		return num * 60, nil
	case 'd':
		return num * 60 * 24, nil
	default:
		return 0, fmt.Errorf("invalid duration unit %q (use m, h, or d)", string(unit))
	}
}

func handleShareCreate(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share create", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to share")
	expiresStr := fs.String("expires", "24h", "Share expiry duration (e.g. 2m, 24h, 7d; 0 = no expiry)")
	maxDownloads := fs.Int("max-downloads", 0, "Maximum download count (0 = unlimited)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Parse duration string into minutes
	expiresMinutes, err := parseDuration(*expiresStr)
	if err != nil {
		return fmt.Errorf("invalid --expires value: %w", err)
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
		sourceKEK = crypto.DeriveCustomPasswordKey(customPass, config.Username)
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
	// Retry if first character is '-' or '_' to avoid issues with shell tools and URL parsers.
	// Probability of retry: 2/64 (~3%), so this almost always succeeds on the first attempt.
	var shareID string
	shareIDBytes := make([]byte, 32)
	for {
		if _, err := rand.Read(shareIDBytes); err != nil {
			return fmt.Errorf("failed to generate share ID: %w", err)
		}
		shareID = base64URLEncode(shareIDBytes)
		if shareID[0] != '-' && shareID[0] != '_' {
			break
		}
	}

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

	if expiresMinutes > 0 {
		sharePayload["expires_after_minutes"] = expiresMinutes
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
	if expiresMinutes > 0 {
		fmt.Printf("  Expires: %s\n", time.Now().Add(time.Duration(expiresMinutes)*time.Minute).Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("  Expires: never\n")
	}
	fmt.Printf("  Password protected: yes\n")

	return nil
}

func handleShareList(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share list", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	rawOutput := fs.Bool("raw", false, "Output raw server response (no metadata enrichment)")
	limit := fs.Int("limit", 100, "Maximum number of shares to list")
	offset := fs.Int("offset", 0, "Offset for pagination")

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("/api/shares?limit=%d&offset=%d", *limit, *offset)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	if *rawOutput {
		fmt.Println(string(body))
		return nil
	}

	var sharesResp ShareListResponse
	if err := json.Unmarshal(body, &sharesResp); err != nil {
		fmt.Println(string(body))
		return nil
	}

	enrichedShares := make([]EnrichedShareInfo, 0)
	if len(sharesResp.Shares) > 0 {
		enrichedShares, err = enrichShareList(client, session, sharesResp.Shares)
		if err != nil {
			return err
		}
	}

	if *jsonOutput {
		output := map[string]interface{}{
			"shares":   enrichedShares,
			"limit":    sharesResp.Limit,
			"offset":   sharesResp.Offset,
			"returned": sharesResp.Returned,
			"has_more": sharesResp.HasMore,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	}

	if len(enrichedShares) == 0 {
		fmt.Println("No shares found.")
		return nil
	}

	sep := strings.Repeat("-", 80)
	for i, s := range enrichedShares {
		fmt.Println(sep)
		fmt.Printf("Share %d of %d\n", i+1, len(enrichedShares))
		fmt.Printf("  Share ID:  %s\n", s.ShareID)
		fmt.Printf("  File ID:   %s\n", s.FileID)

		expires := "never"
		if s.ExpiresAt != "" {
			expires = s.ExpiresAt
		}
		fmt.Printf("  Expires:   %s\n", expires)

		downloads := fmt.Sprintf("%d", s.AccessCount)
		if s.MaxAccesses != nil && *s.MaxAccesses > 0 {
			downloads = fmt.Sprintf("%d / %d", s.AccessCount, *s.MaxAccesses)
		}
		fmt.Printf("  Downloads: %s\n", downloads)

		active := "yes"
		if !s.IsActive {
			active = "no"
		}
		fmt.Printf("  Active:    %s\n", active)

		if s.RevokedAt != "" {
			reason := s.RevokedReason
			if reason == "" {
				reason = "unknown"
			}
			fmt.Printf("  Revoked:   %s (reason: %s)\n", s.RevokedAt, reason)
		}

		fmt.Printf("  Filename:  %s\n", defaultString(s.FilenameLocal, "[encrypted]"))
		fmt.Printf("  Size:      %s\n", defaultString(s.SizeReadableLocal, formatFileSize(s.SizeBytes)))
		fmt.Printf("  SHA-256:   %s\n", defaultString(s.SHA256Local, "[encrypted]"))
		fmt.Printf("  Type:      %s\n", defaultString(s.PasswordType, "unknown"))
		fmt.Printf("  URL:       %s\n", s.ShareURL)
	}
	fmt.Println(sep)

	if sharesResp.HasMore {
		fmt.Printf("\nShowing %d shares starting at offset %d. More results available.\n", sharesResp.Returned, sharesResp.Offset)
	} else {
		fmt.Printf("\nTotal shown: %d shares\n", sharesResp.Returned)
	}

	return nil
}

func enrichShareList(client *HTTPClient, session *AuthSession, shares []ShareInfo) ([]EnrichedShareInfo, error) {
	fileIDs := collectShareFileIDs(shares)
	metadataByFileID, err := fetchMetadataBatchForShares(client, session, fileIDs)
	if err != nil {
		return nil, err
	}

	var accountKey []byte
	agentClient, agentErr := NewAgentClient()
	if agentErr == nil {
		accountKey, _ = agentClient.GetAccountKey("")
	}

	enriched := make([]EnrichedShareInfo, 0, len(shares))
	for _, share := range shares {
		item := EnrichedShareInfo{
			ShareID:           share.ShareID,
			FileID:            share.FileID,
			ShareURL:          share.ShareURL,
			CreatedAt:         share.CreatedAt,
			AccessCount:       share.AccessCount,
			SizeBytes:         share.SizeBytes,
			IsActive:          share.IsActive,
			FilenameLocal:     "[encrypted]",
			SizeBytesLocal:    share.SizeBytes,
			SizeReadableLocal: formatFileSize(share.SizeBytes),
		}

		if expStr, ok := share.ExpiresAt.(string); ok {
			item.ExpiresAt = expStr
		}
		if revokedStr, ok := share.RevokedAt.(string); ok {
			item.RevokedAt = revokedStr
		}
		if reasonStr, ok := share.RevokedReason.(string); ok {
			item.RevokedReason = reasonStr
		}
		if maxF, ok := share.MaxAccesses.(float64); ok {
			max := int(maxF)
			item.MaxAccesses = &max
		}

		if meta, ok := metadataByFileID[share.FileID]; ok {
			item.PasswordType = meta.PasswordType
			if meta.SizeBytes > 0 {
				item.SizeBytes = meta.SizeBytes
				item.SizeBytesLocal = meta.SizeBytes
				item.SizeReadableLocal = formatFileSize(meta.SizeBytes)
			}

			if accountKey != nil {
				filename, filenameErr := decryptMetadataField(meta.EncryptedFilename, meta.FilenameNonce, accountKey)
				sha256sum, shaErr := decryptMetadataField(meta.EncryptedSHA256, meta.SHA256Nonce, accountKey)

				if filenameErr == nil {
					item.FilenameLocal = filename
				}
				if shaErr == nil {
					item.SHA256Local = sha256sum
				}
				item.MetadataDecrypted = filenameErr == nil || shaErr == nil
			}
		}

		enriched = append(enriched, item)
	}

	return enriched, nil
}

func collectShareFileIDs(shares []ShareInfo) []string {
	seen := make(map[string]struct{}, len(shares))
	fileIDs := make([]string, 0, len(shares))
	for _, share := range shares {
		if share.FileID == "" {
			continue
		}
		if _, ok := seen[share.FileID]; ok {
			continue
		}
		seen[share.FileID] = struct{}{}
		fileIDs = append(fileIDs, share.FileID)
	}
	sort.Strings(fileIDs)
	return fileIDs
}

func fetchMetadataBatchForShares(client *HTTPClient, session *AuthSession, fileIDs []string) (map[string]ServerFileInfo, error) {
	if len(fileIDs) == 0 {
		return map[string]ServerFileInfo{}, nil
	}

	payload, err := json.Marshal(map[string]interface{}{"file_ids": fileIDs})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata batch request: %w", err)
	}

	req, err := http.NewRequest("POST", client.baseURL+"/api/files/metadata/batch", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata batch request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata batch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("metadata batch returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var batchResp FileMetadataBatchResponse
	if err := decodeJSONResponse(resp, &batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode metadata batch response: %w", err)
	}

	if batchResp.Files == nil {
		return map[string]ServerFileInfo{}, nil
	}

	return batchResp.Files, nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func handleShareRevoke(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("share revoke", flag.ExitOnError)
	shareID := fs.String("share-id", "", "Share ID to revoke")

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

	// POST /api/shares/:id/revoke with reason
	body := bytes.NewBufferString(`{"reason":"manual"}`)
	req, err := http.NewRequest("POST", client.baseURL+"/api/shares/"+*shareID+"/revoke", body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke share: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, string(respBody))
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

func handleGenerateTOTPCommand(args []string) error {
	fs := flag.NewFlagSet("generate-totp", flag.ExitOnError)
	secret := fs.String("secret", "", "Base32 TOTP secret")
	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client generate-totp --secret SECRET\n\nGenerate a current TOTP code from a base32 secret.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secret == "" {
		return fmt.Errorf("--secret is required")
	}
	code, err := generateTOTPCode(*secret)
	if err != nil {
		return err
	}
	fmt.Println(code)
	return nil
}

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

// ============================================================
// CONTACT INFO COMMAND
// ============================================================

// ContactInfoResponse represents the API response for contact info endpoints
type ContactInfoResponse struct {
	DisplayName string          `json:"display_name"`
	Contacts    []ContactMethod `json:"contacts"`
	Notes       string          `json:"notes"`
}

// ContactMethod represents a single contact method
type ContactMethod struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
	Label string `json:"label,omitempty"`
}

func handleContactInfoCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: arkfile-client contact-info <subcommand>")
		fmt.Println()
		fmt.Println("Subcommands:")
		fmt.Println("  get       View your contact information")
		fmt.Println("  set       Set your contact information (interactive or --json)")
		fmt.Println("  delete    Delete your contact information")
		return nil
	}

	switch args[0] {
	case "get":
		return handleContactInfoGet(client, config)
	case "set":
		return handleContactInfoSet(client, config, args[1:])
	case "delete":
		return handleContactInfoDelete(client, config)
	default:
		return fmt.Errorf("unknown subcommand: %s (use: get, set, delete)", args[0])
	}
}

func handleContactInfoGet(client *HTTPClient, config *ClientConfig) error {
	session, err := requireSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("GET", "/api/user/contact-info", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get contact info: %w", err)
	}

	hasInfo, _ := resp.Data["has_contact_info"].(bool)
	if !hasInfo {
		fmt.Println("No contact information set.")
		fmt.Println("Use 'arkfile-client contact-info set' to add your contact details.")
		return nil
	}

	// Extract contact_info from response data
	contactInfoRaw, ok := resp.Data["contact_info"]
	if !ok {
		return fmt.Errorf("invalid response: missing contact_info")
	}

	// Re-marshal and unmarshal to get typed struct
	infoJSON, err := json.Marshal(contactInfoRaw)
	if err != nil {
		return fmt.Errorf("failed to parse contact info: %w", err)
	}

	var info ContactInfoResponse
	if err := json.Unmarshal(infoJSON, &info); err != nil {
		return fmt.Errorf("failed to parse contact info: %w", err)
	}

	fmt.Printf("Contact Information for %s\n", session.Username)
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

func handleContactInfoSet(client *HTTPClient, config *ClientConfig, args []string) error {
	session, err := requireSession(config)
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("contact-info set", flag.ExitOnError)
	jsonFile := fs.String("json", "", "JSON file path (use - for stdin)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var info ContactInfoResponse

	if *jsonFile != "" {
		// Load from JSON file or stdin
		var data []byte
		if *jsonFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(*jsonFile)
		}
		if err != nil {
			return fmt.Errorf("failed to read JSON: %w", err)
		}
		if err := json.Unmarshal(data, &info); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
	} else {
		// Interactive mode
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Display name (what the admin should call you): ")
		name, _ := reader.ReadString('\n')
		info.DisplayName = strings.TrimSpace(name)

		if info.DisplayName == "" {
			return fmt.Errorf("display name is required")
		}

		// Collect contact methods
		for {
			fmt.Print("Add contact method? (y/n): ")
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				break
			}

			fmt.Print("  Type (email/sms/signal/whatsapp/wechat/telegram/matrix/other): ")
			cType, _ := reader.ReadString('\n')
			cType = strings.TrimSpace(strings.ToLower(cType))

			contact := ContactMethod{Type: cType}

			if cType == "other" {
				fmt.Print("  Label (e.g. Session, Threema): ")
				label, _ := reader.ReadString('\n')
				contact.Label = strings.TrimSpace(label)
			}

			fmt.Print("  Value: ")
			value, _ := reader.ReadString('\n')
			contact.Value = strings.TrimSpace(value)

			if contact.Value == "" {
				fmt.Println("  Skipped (no value provided)")
				continue
			}

			info.Contacts = append(info.Contacts, contact)
		}

		fmt.Print("Notes for admin (optional, press Enter to skip): ")
		notes, _ := reader.ReadString('\n')
		info.Notes = strings.TrimSpace(notes)
	}

	// Send to server
	_, err = client.makeRequest("PUT", "/api/user/contact-info", info, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to save contact info: %w", err)
	}

	fmt.Println("Contact information saved successfully.")
	return nil
}

// ============================================================
// DELETE FILE COMMAND
// ============================================================

func handleDeleteFileCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("delete-file", flag.ExitOnError)
	fileID := fs.String("file-id", "", "File ID to delete")
	confirm := fs.Bool("confirm", false, "Skip confirmation prompt")

	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client delete-file --file-id FILE_ID [--confirm]\n\nPermanently delete a file from the server.\n")
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

	if !*confirm {
		fmt.Println("WARNING: This will permanently delete the file from the server.")
		fmt.Println("Consider using 'export' first to save an offline-decryptable backup (.arkbackup)")
		fmt.Println("before deleting, if this file is important.")
		fmt.Printf("\nDelete file %s? Type YES to confirm: ", *fileID)
		reader := bufio.NewReader(os.Stdin)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if strings.TrimSpace(answer) != "YES" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	_, err = client.makeRequest("DELETE", "/api/files/"+*fileID, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	// Clear digest from agent cache
	agentClient, agentErr := NewAgentClient()
	if agentErr == nil {
		if rmErr := agentClient.RemoveDigest(*fileID); rmErr != nil {
			logVerbose("Warning: failed to remove digest from cache: %v", rmErr)
		}
	}

	fmt.Printf("File %s deleted successfully.\n", *fileID)
	return nil
}

func handleContactInfoDelete(client *HTTPClient, config *ClientConfig) error {
	session, err := requireSession(config)
	if err != nil {
		return err
	}

	_, err = client.makeRequest("DELETE", "/api/user/contact-info", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to delete contact info: %w", err)
	}

	fmt.Println("Contact information deleted.")
	return nil
}
