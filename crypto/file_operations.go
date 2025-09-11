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
	TotalChunks int         `json:"totalChunks"`
	ChunkSize   int         `json:"chunkSize"`
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

// CreatePasswordEnvelope creates an envelope header for password-based encryption
func CreatePasswordEnvelope(keyType string) []byte {
	envelope := make([]byte, 2)
	envelope[0] = 0x01 // Version 1 - Password-based Argon2ID encryption

	switch keyType {
	case "account":
		envelope[1] = 0x01
	case "custom":
		envelope[1] = 0x02
	case "share":
		envelope[1] = 0x03
	default:
		envelope[1] = 0x00 // Unknown
	}

	return envelope
}

// ParsePasswordEnvelope parses a password-based envelope header
func ParsePasswordEnvelope(envelope []byte) (version byte, keyType string, err error) {
	if len(envelope) < 2 {
		return 0, "", fmt.Errorf("envelope too short: need at least 2 bytes, got %d", len(envelope))
	}

	version = envelope[0]
	if version != 0x01 {
		return 0, "", fmt.Errorf("unsupported version: 0x%02x (expected 0x01 for password-based encryption)", version)
	}

	switch envelope[1] {
	case 0x01:
		keyType = "account"
	case 0x02:
		keyType = "custom"
	case 0x03:
		keyType = "share"
	default:
		keyType = "unknown"
	}

	return version, keyType, nil
}

// EncryptFileWithPassword encrypts file data using password-based key derivation
func EncryptFileWithPassword(data []byte, password []byte, username, keyType string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encrypt empty data")
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
	case "share":
		derivedKey = DeriveSharePasswordKey(password, username)
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: account, custom, share)", keyType)
	}

	// Create envelope header using password-based envelope function
	envelope := CreatePasswordEnvelope(keyType)

	// Encrypt the data
	encryptedData, err := EncryptGCM(data, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Prepend envelope to encrypted data
	result := make([]byte, len(envelope)+len(encryptedData))
	copy(result, envelope)
	copy(result[len(envelope):], encryptedData)

	return result, nil
}

// DecryptFileWithPassword decrypts file data using password-based key derivation
func DecryptFileWithPassword(encryptedData []byte, password []byte, username string) ([]byte, string, error) {
	if len(encryptedData) < 2 {
		return nil, "", fmt.Errorf("encrypted data too short: need at least 2 bytes for envelope, got %d", len(encryptedData))
	}

	if len(password) == 0 {
		return nil, "", fmt.Errorf("password cannot be empty")
	}

	if username == "" {
		return nil, "", fmt.Errorf("username cannot be empty")
	}

	// Parse envelope
	envelope := encryptedData[:2]
	ciphertext := encryptedData[2:]

	_, keyType, err := ParsePasswordEnvelope(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse envelope: %w", err)
	}

	// Derive key based on key type from envelope
	var derivedKey []byte
	switch keyType {
	case "account":
		derivedKey = DeriveAccountPasswordKey(password, username)
	case "custom":
		derivedKey = DeriveCustomPasswordKey(password, username)
	case "share":
		derivedKey = DeriveSharePasswordKey(password, username)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Decrypt the data
	plaintext, err := DecryptGCM(ciphertext, derivedKey)
	if err != nil {
		return nil, "", fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, keyType, nil
}

// EncryptFileToPath encrypts a file using password-based key derivation and writes to disk
func EncryptFileToPath(inputPath, outputPath string, password []byte, username, keyType string) error {
	// Read input file
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Encrypt data
	encryptedData, err := EncryptFileWithPassword(inputData, password, username, keyType)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Write encrypted data to output file
	if err := os.WriteFile(outputPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	return nil
}

// DecryptFileFromPath decrypts a file using password-based key derivation and writes to disk
func DecryptFileFromPath(inputPath, outputPath string, password []byte, username string) (string, error) {
	// Read encrypted file
	encryptedData, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Decrypt data
	plaintext, keyType, err := DecryptFileWithPassword(encryptedData, password, username)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	// Write decrypted data to output file
	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return "", fmt.Errorf("failed to write decrypted file: %w", err)
	}

	return keyType, nil
}

// EncryptFEKWithPassword encrypts a File Encryption Key (FEK) using a key derived from
// the user's password via Argon2ID.
func EncryptFEKWithPassword(fek []byte, password []byte, username, keyType string) ([]byte, error) {
	if len(fek) == 0 {
		return nil, fmt.Errorf("FEK cannot be empty")
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
	case "share":
		derivedKey = DeriveSharePasswordKey(password, username)
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: account, custom, share)", keyType)
	}

	// Create envelope header
	envelope := CreatePasswordEnvelope(keyType)

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

// DecryptFEKWithPassword decrypts a File Encryption Key (FEK) using a key derived from
// the user's password via Argon2ID. It returns the decrypted FEK and the key type.
func DecryptFEKWithPassword(encryptedFEK []byte, password []byte, username string) ([]byte, string, error) {
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

	_, keyType, err := ParsePasswordEnvelope(envelope)
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
	case "share":
		derivedKey = DeriveSharePasswordKey(password, username)
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
	// The database stores password_type separately, but for now we assume "account"
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
	var sha256 string
	if len(encryptedSHA256) > 0 && len(sha256Nonce) > 0 {
		decryptedSHA256, err := DecryptMetadataWithDerivedKey(derivedKey, sha256Nonce, encryptedSHA256)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt SHA256: %w", err)
		}
		sha256 = string(decryptedSHA256)
	}

	return filename, sha256, nil
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

// DecryptFEKFromEnvelope decrypts a File Encryption Key (FEK) from its envelope using a password.
// This is the missing link for client-side metadata decryption.
func DecryptFEKFromEnvelope(encryptedFEK, password []byte) ([]byte, error) {
	if len(encryptedFEK) < 2 {
		return nil, fmt.Errorf("encrypted FEK too short for envelope")
	}

	// Parse the envelope to determine key type
	_, keyType, err := ParsePasswordEnvelope(encryptedFEK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse FEK envelope: %w", err)
	}

	// The actual encrypted data starts after the 2-byte envelope
	ciphertext := encryptedFEK[2:]

	// Derive the key used to wrap the FEK.
	// NOTE: The salt for FEK wrapping *does not* include the username. This is a critical detail.
	// It uses a static salt based on the key type.
	var fekWrappingKey []byte
	switch keyType {
	case "account":
		fekWrappingKey, err = DeriveArgon2IDKey(password, FEKAccountSalt, UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	case "custom":
		fekWrappingKey, err = DeriveArgon2IDKey(password, FEKCustomSalt, UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	case "share":
		// Share key derivation may have other inputs; for now, align with others.
		fekWrappingKey, err = DeriveArgon2IDKey(password, FEKShareSalt, UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	default:
		return nil, fmt.Errorf("unsupported key type from envelope: %s", keyType)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to derive FEK wrapping key: %w", err)
	}

	// Decrypt the FEK.
	fek, err := DecryptGCM(ciphertext, fekWrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt FEK: %w", err)
	}

	return fek, nil
}
