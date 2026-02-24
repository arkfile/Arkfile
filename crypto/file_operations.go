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
// ENVELOPE FORMAT (Version 0x01 - Unified FEK-based encryption)
// =============================================================================
//
// All encrypted data uses the same envelope format:
// [0x01][key_type][nonce (12 bytes)][ciphertext][auth_tag (16 bytes)]
//
// Where key_type indicates what password was used to encrypt the FEK:
//   0x01 = account password
//   0x02 = custom password
//
// Key type values are sourced from crypto/chunking-params.json via
// chunking_constants.go (KeyTypeForContext).
//
// Files are ALWAYS encrypted with a random FEK, then the FEK is encrypted
// with the user's password. This enables file sharing without re-encryption.
//
// Share operations use a separate mechanism with random salts and AES-GCM-AAD
// (see crypto/share_kdf.go). They do NOT use the envelope key type system.
// =============================================================================

// CreateEnvelope creates an envelope header for FEK-based encryption
// keyType: "account" or "custom"
func CreateEnvelope(keyType string) []byte {
	envelope := make([]byte, 2)
	envelope[0] = 0x01 // Version 1 - Unified FEK-based encryption

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

// ParseEnvelope parses an envelope header and returns the key type
func ParseEnvelope(envelope []byte) (version byte, keyType string, err error) {
	if len(envelope) < 2 {
		return 0, "", fmt.Errorf("envelope too short: need at least 2 bytes, got %d", len(envelope))
	}

	version = envelope[0]
	if version != 0x01 {
		return 0, "", fmt.Errorf("unsupported envelope version: 0x%02x (expected 0x01)", version)
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

// GenerateFEK generates a cryptographically secure 32-byte File Encryption Key
func GenerateFEK() ([]byte, error) {
	fek := make([]byte, 32)
	if _, err := rand.Read(fek); err != nil {
		return nil, fmt.Errorf("failed to generate FEK: %w", err)
	}
	return fek, nil
}

// EncryptFEK encrypts a File Encryption Key (FEK) using a key derived from
// the user's password via Argon2ID. This creates the "Owner Envelope".
func EncryptFEK(fek []byte, password []byte, username, keyType string) ([]byte, error) {
	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes, got %d", len(fek))
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	// Derive key based on key type
	var derivedKey []byte
	switch keyType {
	case "account":
		derivedKey = DeriveAccountPasswordKey(password, username)
	case "custom":
		derivedKey = DeriveCustomPasswordKey(password, username)
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: account, custom)", keyType)
	}

	// Create envelope header
	envelope := CreateEnvelope(keyType)

	// Encrypt the FEK
	encryptedFEK, err := EncryptGCM(fek, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("FEK encryption failed: %w", err)
	}

	// Prepend envelope to encrypted FEK
	result := make([]byte, len(envelope)+len(encryptedFEK))
	copy(result, envelope)
	copy(result[len(envelope):], encryptedFEK)

	return result, nil
}

// DecryptFEK decrypts a File Encryption Key (FEK) using a key derived from
// the user's password via Argon2ID. Returns the decrypted FEK and the key type.
func DecryptFEK(encryptedFEK []byte, password []byte, username string) ([]byte, string, error) {
	if len(encryptedFEK) < 2 {
		return nil, "", fmt.Errorf("encrypted FEK too short: need at least 2 bytes for envelope, got %d", len(encryptedFEK))
	}
	if len(password) == 0 {
		return nil, "", fmt.Errorf("password cannot be empty")
	}
	if username == "" {
		return nil, "", fmt.Errorf("username cannot be empty")
	}

	// Parse envelope
	envelope := encryptedFEK[:2]
	ciphertext := encryptedFEK[2:]

	_, keyType, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse FEK envelope: %w", err)
	}

	// Derive key based on key type from envelope
	var derivedKey []byte
	switch keyType {
	case "account":
		derivedKey = DeriveAccountPasswordKey(password, username)
	case "custom":
		derivedKey = DeriveCustomPasswordKey(password, username)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Decrypt the FEK
	fek, err := DecryptGCM(ciphertext, derivedKey)
	if err != nil {
		return nil, "", fmt.Errorf("FEK decryption failed: %w", err)
	}

	return fek, keyType, nil
}

// =============================================================================
// FILE ENCRYPTION/DECRYPTION (FEK-based only)
// =============================================================================

// EncryptFile encrypts file data using a FEK (File Encryption Key)
// The keyType parameter indicates what password type will be used to encrypt the FEK
func EncryptFile(data []byte, fek []byte, keyType string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encrypt empty data")
	}

	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes for AES-256, got %d", len(fek))
	}

	// Create envelope header
	envelope := CreateEnvelope(keyType)

	// Encrypt the data with FEK
	encryptedData, err := EncryptGCM(data, fek)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Prepend envelope to encrypted data
	result := make([]byte, len(envelope)+len(encryptedData))
	copy(result, envelope)
	copy(result[len(envelope):], encryptedData)

	return result, nil
}

// DecryptFile decrypts file data using a FEK (File Encryption Key)
func DecryptFile(encryptedData []byte, fek []byte) ([]byte, error) {
	if len(encryptedData) < 2 {
		return nil, fmt.Errorf("encrypted data too short: need at least 2 bytes for envelope, got %d", len(encryptedData))
	}

	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes, got %d", len(fek))
	}

	// Parse envelope (validate format)
	envelope := encryptedData[:2]
	ciphertext := encryptedData[2:]

	_, _, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to parse envelope: %w", err)
	}

	// Decrypt the data using the FEK
	plaintext, err := DecryptGCM(ciphertext, fek)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptFileToPath encrypts a file using a FEK and writes to disk
func EncryptFileToPath(inputPath, outputPath string, fek []byte, keyType string) error {
	// Read input file
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Encrypt data
	encryptedData, err := EncryptFile(inputData, fek, keyType)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Write encrypted data to output file
	if err := os.WriteFile(outputPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	return nil
}

// DecryptFileFromPath decrypts a file using a FEK and writes to disk
func DecryptFileFromPath(inputPath, outputPath string, fek []byte) error {
	// Read encrypted file
	encryptedData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Decrypt data
	plaintext, err := DecryptFile(encryptedData, fek)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Write decrypted data to output file
	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	return nil
}

// =============================================================================
// COMPLETE FEK WORKFLOW
// =============================================================================

// EncryptFileWorkflow performs the complete FEK-based encryption workflow:
// 1. Generates a random FEK
// 2. Encrypts the file with the FEK
// 3. Encrypts the FEK with the user's password (Owner Envelope)
// Returns the encrypted FEK (for storage in metadata) and the FEK itself (for immediate use)
func EncryptFileWorkflow(inputPath, outputPath string, password []byte, username, keyType string) (encryptedFEK []byte, fek []byte, err error) {
	// Generate random FEK
	fek, err = GenerateFEK()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate FEK: %w", err)
	}

	// Encrypt file with FEK
	if err := EncryptFileToPath(inputPath, outputPath, fek, keyType); err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt file: %w", err)
	}

	// Encrypt FEK with password (Owner Envelope)
	encryptedFEK, err = EncryptFEK(fek, password, username, keyType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt FEK: %w", err)
	}

	return encryptedFEK, fek, nil
}

// DecryptFileWorkflow performs the complete FEK-based decryption workflow:
// 1. Decrypts the FEK using the user's password
// 2. Decrypts the file with the FEK
func DecryptFileWorkflow(inputPath, outputPath string, encryptedFEK []byte, password []byte, username string) error {
	// Decrypt FEK
	fek, _, err := DecryptFEK(encryptedFEK, password, username)
	if err != nil {
		return fmt.Errorf("failed to decrypt FEK: %w", err)
	}

	// Decrypt file with FEK
	if err := DecryptFileFromPath(inputPath, outputPath, fek); err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	return nil
}

// =============================================================================
// METADATA OPERATIONS
// =============================================================================

// DecryptedFileMetadata represents decrypted file metadata
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

// DecryptFileMetadata decrypts encrypted filename and SHA256 metadata using stored password
// This function works with separate nonce and encrypted data fields as stored in the database
// The server stores nonces and encrypted data separately, so we need to combine them for DecryptGCM
func DecryptFileMetadata(filenameNonce, encryptedFilename, sha256Nonce, encryptedSHA256 []byte, password string, username string) (string, string, error) {
	if len(password) == 0 {
		return "", "", fmt.Errorf("password cannot be empty")
	}
	if username == "" {
		return "", "", fmt.Errorf("username cannot be empty")
	}

	// Use account password derivation (default for file metadata)
	derivedKey := DeriveAccountPasswordKey([]byte(password), username)

	// Decrypt filename
	var filename string
	if len(encryptedFilename) > 0 && len(filenameNonce) > 0 {
		decryptedFilename, err := DecryptMetadataWithDerivedKey(derivedKey, filenameNonce, encryptedFilename)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt filename: %w", err)
		}
		filename = string(decryptedFilename)
	}

	// Decrypt SHA256
	var sha256sum string
	if len(encryptedSHA256) > 0 && len(sha256Nonce) > 0 {
		decryptedSHA256, err := DecryptMetadataWithDerivedKey(derivedKey, sha256Nonce, encryptedSHA256)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt SHA256: %w", err)
		}
		sha256sum = string(decryptedSHA256)
	}

	return filename, sha256sum, nil
}

// DecryptMetadataWithDerivedKey decrypts file metadata using a pre-derived key
// This function is used by cryptocli and expects separate nonce and encrypted data parameters
func DecryptMetadataWithDerivedKey(derivedKey []byte, nonce, encryptedData []byte) ([]byte, error) {
	// Validate input lengths
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: expected 12 bytes, got %d", len(nonce))
	}
	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("invalid encrypted data length: expected at least 16 bytes for auth tag, got %d", len(encryptedData))
	}

	// The encrypted data from the database contains: [ciphertext][16-byte auth tag]
	// We need to reconstruct the format expected by DecryptGCM: [nonce][ciphertext][auth tag]
	ciphertextLen := len(encryptedData) - 16
	if ciphertextLen < 0 {
		return nil, fmt.Errorf("encrypted data too short to contain auth tag")
	}

	// Split the encrypted data
	ciphertext := encryptedData[:ciphertextLen]
	authTag := encryptedData[ciphertextLen:]

	// Reconstruct the proper GCM format: [nonce][ciphertext][auth_tag]
	gcmData := make([]byte, len(nonce)+len(ciphertext)+len(authTag))
	copy(gcmData, nonce)
	copy(gcmData[len(nonce):], ciphertext)
	copy(gcmData[len(nonce)+len(ciphertext):], authTag)

	// Now decrypt using the reconstructed data
	return DecryptGCM(gcmData, derivedKey)
}
