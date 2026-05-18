package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// FilePattern represents different test file content patterns
type FilePattern string

const (
	PatternSequential FilePattern = "sequential"
	PatternRepeated   FilePattern = "repeated"
	PatternRandom     FilePattern = "random"
	PatternZeros      FilePattern = "zeros"
)

// GenerateTestFileContent creates deterministic test file content
func GenerateTestFileContent(size int64, pattern FilePattern) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("file size must be positive, got %d", size)
	}

	if size > 2*1024*1024*1024 { // 2GB limit for safety
		return nil, fmt.Errorf("file size too large: %d bytes (max 2GB)", size)
	}

	data := make([]byte, size)

	switch pattern {
	case PatternSequential:
		for i := range data {
			data[i] = byte(i % 256)
		}
	case PatternRepeated:
		seed := []byte("Arkfile Test File Content Pattern - PHASE 1A Implementation")
		for i := 0; i < len(data); i += len(seed) {
			remaining := len(data) - i
			if remaining < len(seed) {
				copy(data[i:], seed[:remaining])
			} else {
				copy(data[i:], seed)
			}
		}
	case PatternRandom:
		if _, err := rand.Read(data); err != nil {
			return nil, fmt.Errorf("failed to generate random data: %w", err)
		}
	case PatternZeros:
		// data is already initialized to all zeros by make([]byte, size)
		// No action needed here, as byte slice default value is 0.
	default:
		return nil, fmt.Errorf("unsupported pattern: %s", pattern)
	}

	return data, nil
}

// GenerateTestFileToPath creates a test file directly to disk for memory efficiency
func GenerateTestFileToPath(filePath string, size int64, pattern FilePattern) (string, error) {
	// Validate size parameter first
	if size <= 0 {
		return "", fmt.Errorf("file size must be positive, got %d", size)
	}

	if size > 2*1024*1024*1024 { // 2GB limit for safety
		return "", fmt.Errorf("file size too large: %d bytes (max 2GB)", size)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Generate and write content in chunks to manage memory
	const chunkSize = 4 * 1024 * 1024 // 4MB chunks
	hash := sha256.New()

	var bytesWritten int64
	for bytesWritten < size {
		remaining := size - bytesWritten
		currentChunkSize := chunkSize
		if remaining < int64(currentChunkSize) {
			currentChunkSize = int(remaining)
		}

		chunk, err := GenerateTestFileContent(int64(currentChunkSize), pattern)
		if err != nil {
			return "", fmt.Errorf("failed to generate chunk: %w", err)
		}

		n, err := file.Write(chunk)
		if err != nil {
			return "", fmt.Errorf("failed to write chunk: %w", err)
		}

		hash.Write(chunk[:n])
		bytesWritten += int64(n)
	}

	// Calculate final hash
	finalHash := fmt.Sprintf("%x", hash.Sum(nil))
	return finalHash, nil
}

// CalculateFileHash computes SHA-256 hash of file content
func CalculateFileHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// CalculateFileHashFromPath computes SHA-256 hash of a file on disk
func CalculateFileHashFromPath(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to read file for hashing: %w", err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// ParseSizeString converts human-readable size strings to bytes
func ParseSizeString(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 0, fmt.Errorf("size string cannot be empty")
	}

	multipliers := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
	}

	// Simple parsing for common cases
	var size int64
	var unit string

	n, err := fmt.Sscanf(sizeStr, "%d%s", &size, &unit)
	if err != nil || n != 2 {
		// Try parsing without unit (assume bytes)
		if n, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil || n != 1 {
			return 0, fmt.Errorf("invalid size format: %s", sizeStr)
		}
		return size, nil
	}

	multiplier, exists := multipliers[unit]
	if !exists {
		return 0, fmt.Errorf("unsupported size unit: %s", unit)
	}

	result := size * multiplier
	if result < 0 || result/multiplier != size { // Check for overflow
		return 0, fmt.Errorf("size too large: %s", sizeStr)
	}

	return result, nil
}

// ChunkInfo represents metadata for a single encrypted chunk
type ChunkInfo struct {
	Index int    `json:"index"`
	File  string `json:"file"`
	Hash  string `json:"hash"`
	Size  int    `json:"size"`
}

// ChunkManifest represents metadata for chunked encryption
type ChunkManifest struct {
	Envelope    string      `json:"envelope"`
	TotalChunks int         `json:"total_chunks"`
	ChunkSize   int         `json:"chunk_size"`
	Chunks      []ChunkInfo `json:"chunks"`
}

// ToJSON serializes the manifest to JSON
func (m *ChunkManifest) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FormatFileSize converts bytes to human-readable format
func FormatFileSize(bytes int64) string {
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

// VerifyFileIntegrity verifies a file matches expected hash and size
func VerifyFileIntegrity(filePath string, expectedHash string, expectedSize int64) error {
	// Check file exists and size
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file not accessible: %w", err)
	}

	if info.Size() != expectedSize {
		return fmt.Errorf("size mismatch: expected %d bytes, got %d bytes", expectedSize, info.Size())
	}

	// Verify hash
	actualHash, err := CalculateFileHashFromPath(filePath)
	if err != nil {
		return fmt.Errorf("hash calculation failed: %w", err)
	}

	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}

// =============================================================================
// FEK ENVELOPE FORMAT
// =============================================================================
//
// The FEK (File Encryption Key) is wrapped in a 2-byte-prefixed envelope when
// stored in the file_metadata.encrypted_fek column:
//
//   [0x01][key_type][nonce (12 bytes)][ciphertext][auth_tag (16 bytes)]
//
// Where:
//   - 0x01 is the envelope version byte.
//   - key_type is 0x01 (account password) or 0x02 (custom password). Values
//     are sourced from crypto/chunking-params.json via chunking_constants.go.
//   - The AEAD authentication tag is computed with AAD =
//     BuildFEKEnvelopeAAD(file_id, key_type) (see crypto/aad.go). This binds
//     the FEK envelope to the specific file_id and key type, so an attacker
//     with DB-write access cannot substitute one user's FEK envelope into
//     another file's metadata row (Phase C, finding B-08).
//
// File data chunks themselves use a uniform layout with NO envelope prefix:
//   [nonce (12 bytes)][ciphertext][auth_tag (16 bytes)]
// Chunk AAD = BuildChunkAAD(file_id, chunk_index, total_chunks).
//
// Share envelopes use a separate mechanism with random salts and their own
// AAD construction (see crypto/share_kdf.go).
// =============================================================================

// CreateFEKEnvelopeHeader creates the 2-byte FEK envelope header.
// keyType: "account" or "custom"
func CreateFEKEnvelopeHeader(keyType string) []byte {
	envelope := make([]byte, 2)
	envelope[0] = 0x01 // Version 1

	switch keyType {
	case "account":
		envelope[1] = 0x01
	case "custom":
		envelope[1] = 0x02
	default:
		envelope[1] = 0x00 // Unknown
	}

	return envelope
}

// ParseFEKEnvelopeHeader parses a 2-byte FEK envelope header and returns the
// key type ("account" or "custom"). Returns an error for unknown version
// bytes or short input.
func ParseFEKEnvelopeHeader(envelope []byte) (version byte, keyType string, err error) {
	if len(envelope) < 2 {
		return 0, "", fmt.Errorf("FEK envelope too short: need at least 2 bytes, got %d", len(envelope))
	}

	version = envelope[0]
	if version != 0x01 {
		return 0, "", fmt.Errorf("unsupported FEK envelope version: 0x%02x (expected 0x01)", version)
	}

	switch envelope[1] {
	case 0x01:
		keyType = "account"
	case 0x02:
		keyType = "custom"
	default:
		keyType = "unknown"
	}

	return version, keyType, nil
}

// =============================================================================
// FEK (File Encryption Key) OPERATIONS
// =============================================================================

// GenerateFEK generates a cryptographically secure 32-byte File Encryption Key.
func GenerateFEK() ([]byte, error) {
	fek := make([]byte, 32)
	if _, err := rand.Read(fek); err != nil {
		return nil, fmt.Errorf("failed to generate FEK: %w", err)
	}
	return fek, nil
}

// EncryptFEK encrypts a File Encryption Key (FEK) using a key derived from
// the user's password via Argon2id, with AAD binding to the specific file.
// This creates the "Owner Envelope" stored in file_metadata.encrypted_fek.
//
// The AAD is constructed via BuildFEKEnvelopeAAD(fileID, keyTypeByte), so
// any attempt to substitute this envelope into a different file's row
// (B-08) or flip the key-type byte will fail authentication on decrypt.
//
// fileID MUST be the canonical file_id the metadata row will use. keyType
// MUST be "account" or "custom".
func EncryptFEK(fek []byte, password []byte, username, fileID, keyType string) ([]byte, error) {
	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes, got %d", len(fek))
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if fileID == "" {
		return nil, fmt.Errorf("fileID cannot be empty")
	}

	// Derive KEK based on key type
	var kek []byte
	switch keyType {
	case "account":
		kek = DeriveAccountPasswordKey(password, username)
	case "custom":
		kek = DeriveCustomPasswordKey(password, username)
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: account, custom)", keyType)
	}

	// Build envelope header [version][key_type] and the matching AAD.
	envelope := CreateFEKEnvelopeHeader(keyType)
	keyTypeByte := envelope[1]
	aad := BuildFEKEnvelopeAAD(fileID, keyTypeByte)

	// Encrypt the FEK with AAD binding.
	wrapped, err := EncryptGCMWithAAD(fek, kek, aad)
	if err != nil {
		return nil, fmt.Errorf("FEK encryption failed: %w", err)
	}

	// Output: [envelope (2)][nonce][ct][tag]
	result := make([]byte, 0, len(envelope)+len(wrapped))
	result = append(result, envelope...)
	result = append(result, wrapped...)
	return result, nil
}

// DecryptFEK decrypts a File Encryption Key (FEK) using a key derived from
// the user's password via Argon2id, verifying AAD binding to the specific
// file. Returns the decrypted FEK and the key type used during encryption.
//
// Any mismatch in fileID or in the envelope's key-type byte vs. the AAD
// causes AES-GCM authentication failure (B-08).
//
// fileID MUST be the canonical file_id from the metadata row.
func DecryptFEK(encryptedFEK []byte, password []byte, username, fileID string) ([]byte, string, error) {
	if len(encryptedFEK) < 2 {
		return nil, "", fmt.Errorf("encrypted FEK too short: need at least 2 bytes for envelope, got %d", len(encryptedFEK))
	}
	if len(password) == 0 {
		return nil, "", fmt.Errorf("password cannot be empty")
	}
	if username == "" {
		return nil, "", fmt.Errorf("username cannot be empty")
	}
	if fileID == "" {
		return nil, "", fmt.Errorf("fileID cannot be empty")
	}

	// Parse envelope header.
	envelope := encryptedFEK[:2]
	ciphertext := encryptedFEK[2:]

	_, keyType, err := ParseFEKEnvelopeHeader(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse FEK envelope: %w", err)
	}

	// Derive the matching KEK.
	var kek []byte
	switch keyType {
	case "account":
		kek = DeriveAccountPasswordKey(password, username)
	case "custom":
		kek = DeriveCustomPasswordKey(password, username)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Reconstruct the AAD that was used at encrypt time.
	keyTypeByte := envelope[1]
	aad := BuildFEKEnvelopeAAD(fileID, keyTypeByte)

	// Decrypt and verify AAD.
	fek, err := DecryptGCMWithAAD(ciphertext, kek, aad)
	if err != nil {
		return nil, "", fmt.Errorf("FEK decryption failed: %w", err)
	}

	return fek, keyType, nil
}

// =============================================================================
// METADATA OPERATIONS
// =============================================================================

// DecryptedFileMetadata represents decrypted file metadata.
type DecryptedFileMetadata struct {
	FileID       string `json:"file_id"`
	StorageID    string `json:"storage_id"`
	PasswordHint string `json:"password_hint"`
	PasswordType string `json:"password_type"`
	Filename     string `json:"filename"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	SizeReadable string `json:"size_readable"`
	UploadDate   string `json:"upload_date"`
}

// DecryptFileMetadata decrypts the encrypted_filename and encrypted_sha256sum
// metadata fields for a file using the account-derived key (Argon2id). The
// AAD on each field binds it to (fileID, field_label, ownerUsername), so
// substituting metadata between files or fields or users is rejected by the
// AEAD layer (C-19).
//
// fileID and ownerUsername must be the canonical values from the metadata
// row.
func DecryptFileMetadata(filenameNonce, encryptedFilename, sha256Nonce, encryptedSHA256 []byte, password string, username, fileID, ownerUsername string) (string, string, error) {
	if len(password) == 0 {
		return "", "", fmt.Errorf("password cannot be empty")
	}
	if username == "" {
		return "", "", fmt.Errorf("username cannot be empty")
	}
	if fileID == "" {
		return "", "", fmt.Errorf("fileID cannot be empty")
	}
	if ownerUsername == "" {
		return "", "", fmt.Errorf("ownerUsername cannot be empty")
	}

	// Metadata is always encrypted under the account key.
	derivedKey := DeriveAccountPasswordKey([]byte(password), username)

	var filename string
	if len(encryptedFilename) > 0 && len(filenameNonce) > 0 {
		decryptedFilename, err := DecryptMetadataWithDerivedKey(
			derivedKey, filenameNonce, encryptedFilename,
			fileID, AADFieldFilename, ownerUsername,
		)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt filename: %w", err)
		}
		filename = string(decryptedFilename)
	}

	var sha256sum string
	if len(encryptedSHA256) > 0 && len(sha256Nonce) > 0 {
		decryptedSHA256, err := DecryptMetadataWithDerivedKey(
			derivedKey, sha256Nonce, encryptedSHA256,
			fileID, AADFieldSha256, ownerUsername,
		)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt SHA256: %w", err)
		}
		sha256sum = string(decryptedSHA256)
	}

	return filename, sha256sum, nil
}

// DecryptMetadataWithDerivedKey decrypts a single metadata field using a
// pre-derived key. Expects separate nonce and encrypted data (the server
// stores them in separate columns). AAD is constructed via
// BuildMetadataFieldAAD(fileID, fieldName, ownerUsername) to bind the
// ciphertext to its file, field label, and owner.
//
// fieldName MUST be AADFieldFilename or AADFieldSha256.
func DecryptMetadataWithDerivedKey(derivedKey []byte, nonce, encryptedData []byte, fileID, fieldName, ownerUsername string) ([]byte, error) {
	// Validate input lengths.
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: expected 12 bytes, got %d", len(nonce))
	}
	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("invalid encrypted data length: expected at least 16 bytes for auth tag, got %d", len(encryptedData))
	}
	if fileID == "" {
		return nil, fmt.Errorf("fileID cannot be empty")
	}
	if fieldName == "" {
		return nil, fmt.Errorf("fieldName cannot be empty")
	}
	if ownerUsername == "" {
		return nil, fmt.Errorf("ownerUsername cannot be empty")
	}

	// Server stores [ciphertext][16-byte tag] and the [nonce] separately.
	// Reassemble the GCM layout [nonce][ciphertext][tag] expected by
	// DecryptGCMWithAAD.
	gcmData := make([]byte, 0, len(nonce)+len(encryptedData))
	gcmData = append(gcmData, nonce...)
	gcmData = append(gcmData, encryptedData...)

	aad := BuildMetadataFieldAAD(fileID, fieldName, ownerUsername)
	return DecryptGCMWithAAD(gcmData, derivedKey, aad)
}
