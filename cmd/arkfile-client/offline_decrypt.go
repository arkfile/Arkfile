// offline_decrypt.go - Offline decryption of .arkbackup bundles
// Decrypts a .arkbackup bundle using only local computation. No network required.
// See docs/wip/arkbackup-export.md for the bundle format specification.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/84adam/Arkfile/crypto"
)

// bundleMeta matches the JSON metadata schema in the .arkbackup bundle
type bundleMeta struct {
	Version            int    `json:"version"`
	FileID             string `json:"file_id"`
	EncryptedFEK       string `json:"encrypted_fek"`
	PasswordType       string `json:"password_type"`
	SizeBytes          int64  `json:"size_bytes"`
	PaddedSize         int64  `json:"padded_size"`
	EncryptedFilename  string `json:"encrypted_filename"`
	FilenameNonce      string `json:"filename_nonce"`
	EncryptedSHA256Sum string `json:"encrypted_sha256sum"`
	SHA256SumNonce     string `json:"sha256sum_nonce"`
	ChunkSizeBytes     int64  `json:"chunk_size_bytes"`
	ChunkCount         int64  `json:"chunk_count"`
	EnvelopeVersion    int    `json:"envelope_version"`
	CreatedAt          string `json:"created_at"`
}

func handleDecryptBlobCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-blob", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Path to .arkbackup bundle file")
	username := fs.String("username", "", "Username (required for key derivation)")
	outputPath := fs.String("output", "", "Output file path for decrypted data")
	passwordStdin := fs.Bool("password-stdin", false, "Read password(s) from stdin (one per line)")
	accountKeyFile := fs.String("account-key-file", "", "Path to hex-encoded 32-byte account key file")
	useAgent := fs.Bool("use-agent", false, "Read account key from running agent")

	fs.Usage = func() {
		fmt.Printf("Usage: arkfile-client decrypt-blob --bundle FILE --username USER --output PATH\n\n")
		fmt.Printf("Decrypt a .arkbackup bundle offline using only local computation.\n\n")
		fmt.Printf("Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *bundlePath == "" {
		return fmt.Errorf("--bundle is required")
	}
	if *outputPath == "" {
		return fmt.Errorf("--output is required")
	}

	// Username is required unless using --account-key-file or --use-agent
	if *username == "" && *accountKeyFile == "" && !*useAgent {
		return fmt.Errorf("--username is required (needed for key derivation)")
	}

	// Step 1: Parse bundle
	meta, blobOffset, err := parseBundle(*bundlePath)
	if err != nil {
		return fmt.Errorf("failed to parse bundle: %w", err)
	}

	logVerbose("Bundle parsed: file_id=%s password_type=%s chunks=%d size=%d",
		meta.FileID, meta.PasswordType, meta.ChunkCount, meta.SizeBytes)

	// Step 2: Obtain account key
	accountKey, err := obtainAccountKey(*username, *accountKeyFile, *useAgent, *passwordStdin)
	if err != nil {
		return fmt.Errorf("failed to obtain account key: %w", err)
	}
	defer clearBytes(accountKey)

	// Step 3: Unwrap FEK
	var kek []byte
	switch meta.PasswordType {
	case "account", "":
		kek = accountKey
	case "custom":
		// Need custom password to derive custom KEK
		var customPass []byte
		if *passwordStdin {
			customPass, err = readPassword("")
			if err != nil {
				return fmt.Errorf("failed to read custom password from stdin: %w", err)
			}
		} else {
			customPass, err = readPassword("Enter the custom file password: ")
			if err != nil {
				return fmt.Errorf("failed to read custom password: %w", err)
			}
		}
		defer clearBytes(customPass)
		kek = crypto.DeriveCustomPasswordKey(customPass, *username)
		defer clearBytes(kek)
	default:
		return fmt.Errorf("unsupported password type: %s", meta.PasswordType)
	}

	fek, _, err := unwrapFEK(meta.EncryptedFEK, kek)
	if err != nil {
		return fmt.Errorf("failed to unwrap FEK (wrong password?): %w", err)
	}
	defer clearBytes(fek)

	// Step 4: Decrypt file data from bundle
	err = decryptBundleBlob(*bundlePath, blobOffset, meta, fek, *outputPath)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Step 5: Verify and report
	// Decrypt filename
	filename := "[unknown]"
	if meta.EncryptedFilename != "" && meta.FilenameNonce != "" {
		if name, decErr := decryptMetadataField(meta.EncryptedFilename, meta.FilenameNonce, accountKey); decErr == nil {
			filename = name
		} else {
			logVerbose("Warning: could not decrypt filename: %v", decErr)
		}
	}

	fmt.Printf("Decrypted: %s\n", filename)

	// Compute SHA-256 of decrypted output
	actualSHA256, err := computeStreamingSHA256(*outputPath)
	if err != nil {
		fmt.Printf("[!] WARNING: Could not compute SHA-256 of output: %v\n", err)
		return nil
	}
	fmt.Printf("SHA-256: %s\n", actualSHA256)

	// Decrypt expected SHA-256 from metadata
	if meta.EncryptedSHA256Sum != "" && meta.SHA256SumNonce != "" {
		expectedSHA256, decErr := decryptMetadataField(meta.EncryptedSHA256Sum, meta.SHA256SumNonce, accountKey)
		if decErr != nil {
			fmt.Printf("[!] WARNING: Could not decrypt expected SHA-256: %v\n", decErr)
		} else if actualSHA256 == expectedSHA256 {
			fmt.Printf("Verified: [OK] (matches encrypted metadata)\n")
		} else {
			fmt.Printf("MISMATCH: [X]\n")
			fmt.Printf("  Expected: %s\n", expectedSHA256)
			fmt.Printf("  Got:      %s\n", actualSHA256)
			return fmt.Errorf("SHA-256 verification failed")
		}
	} else {
		fmt.Printf("Verified: [!] (no SHA-256 metadata available)\n")
	}

	return nil
}

// parseBundle reads and validates the .arkbackup bundle header and returns
// the parsed metadata and the byte offset where the encrypted blob starts.
func parseBundle(path string) (*bundleMeta, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open bundle: %w", err)
	}
	defer f.Close()

	// Read 4-byte magic
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return nil, 0, fmt.Errorf("failed to read magic bytes: %w", err)
	}
	if string(magic) != "ARKB" {
		return nil, 0, fmt.Errorf("invalid bundle: expected ARKB magic, got %q", string(magic))
	}

	// Read 2-byte version (big-endian)
	versionBytes := make([]byte, 2)
	if _, err := f.Read(versionBytes); err != nil {
		return nil, 0, fmt.Errorf("failed to read version: %w", err)
	}
	version := binary.BigEndian.Uint16(versionBytes)
	if version != 1 {
		return nil, 0, fmt.Errorf("unsupported bundle version: %d (expected 1)", version)
	}

	// Read 4-byte header length (big-endian)
	headerLenBytes := make([]byte, 4)
	if _, err := f.Read(headerLenBytes); err != nil {
		return nil, 0, fmt.Errorf("failed to read header length: %w", err)
	}
	headerLen := binary.BigEndian.Uint32(headerLenBytes)

	// Sanity check header length (max 1 MiB for metadata)
	if headerLen > 1024*1024 {
		return nil, 0, fmt.Errorf("header length too large: %d bytes", headerLen)
	}

	// Read JSON metadata
	metaJSON := make([]byte, headerLen)
	if _, err := f.Read(metaJSON); err != nil {
		return nil, 0, fmt.Errorf("failed to read metadata: %w", err)
	}

	var meta bundleMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, 0, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	// Blob starts at offset 10 + headerLen
	blobOffset := int64(10) + int64(headerLen)

	return &meta, blobOffset, nil
}

// obtainAccountKey gets the account key from one of the supported sources
func obtainAccountKey(username, accountKeyFile string, useAgent, passwordStdin bool) ([]byte, error) {
	if accountKeyFile != "" {
		return readAccountKeyFromFile(accountKeyFile)
	}

	if useAgent {
		agentClient, err := NewAgentClient()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to agent: %w", err)
		}
		// Pass empty token since decrypt-blob is offline and does not require session binding
		key, err := agentClient.GetAccountKey("")
		if err != nil {
			return nil, fmt.Errorf("failed to get account key from agent: %w", err)
		}
		return key, nil
	}

	// Read password and derive account key
	var password []byte
	var err error
	if passwordStdin {
		password, err = readPassword("")
		if err != nil {
			return nil, fmt.Errorf("failed to read password from stdin: %w", err)
		}
	} else {
		password, err = readPassword("Enter your account password: ")
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer clearBytes(password)

	if username == "" {
		return nil, fmt.Errorf("username is required for key derivation")
	}

	accountKey := crypto.DeriveAccountPasswordKey(password, username)
	return accountKey, nil
}

// readAccountKeyFromFile reads a hex-encoded 32-byte key from a file
func readAccountKeyFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	hexStr := strings.TrimSpace(string(data))
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	return key, nil
}

// decryptBundleBlob reads the encrypted blob from the bundle, splits it into
// chunks, decrypts each chunk, and writes plaintext to the output file.
func decryptBundleBlob(bundlePath string, blobOffset int64, meta *bundleMeta, fek []byte, outputPath string) error {
	f, err := os.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to open bundle: %w", err)
	}
	defer f.Close()

	// Seek to blob start
	if _, err := f.Seek(blobOffset, 0); err != nil {
		return fmt.Errorf("failed to seek to blob: %w", err)
	}

	// Create output file
	outFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Split and decrypt chunks
	plaintextChunkSize := meta.ChunkSizeBytes
	if plaintextChunkSize <= 0 {
		plaintextChunkSize = crypto.PlaintextChunkSize()
	}

	gcmOverhead := int64(crypto.AesGcmOverhead())        // nonce (12) + tag (16) = 28
	envelopeHeader := int64(crypto.EnvelopeHeaderSize()) // 2 bytes

	remaining := meta.SizeBytes
	chunkIndex := 0

	for remaining > 0 {
		// Calculate this chunk's encrypted size
		overhead := gcmOverhead
		if chunkIndex == 0 {
			overhead += envelopeHeader
		}
		maxChunk := plaintextChunkSize + overhead
		actualChunk := maxChunk
		if remaining < actualChunk {
			actualChunk = remaining
		}

		// Read encrypted chunk
		chunkData := make([]byte, actualChunk)
		n, err := f.Read(chunkData)
		if err != nil {
			return fmt.Errorf("failed to read chunk %d: %w", chunkIndex, err)
		}
		chunkData = chunkData[:n]

		// Decrypt chunk
		plaintext, err := decryptChunk(chunkData, fek, chunkIndex)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d: %w", chunkIndex, err)
		}

		// Write plaintext to output
		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write chunk %d: %w", chunkIndex, err)
		}

		remaining -= int64(n)
		chunkIndex++

		if verbose {
			logVerbose("  Chunk %d decrypted (%d bytes remaining)", chunkIndex, remaining)
		}
	}

	logVerbose("Decrypted %d chunks", chunkIndex)
	return nil
}
