package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

// CreateChunkedEncryption encrypts data into chunks using OPAQUE-derived keys
func CreateChunkedEncryption(data []byte, exportKey []byte, username, fileID string, chunkSize int, keyType string) (*ChunkManifest, map[int][]byte, error) {
	if len(exportKey) != 64 {
		return nil, nil, fmt.Errorf("export key must be 64 bytes, got %d", len(exportKey))
	}

	if chunkSize <= 0 || chunkSize > 100*1024*1024 {
		return nil, nil, fmt.Errorf("invalid chunk size: %d (must be between 1 and 100MB)", chunkSize)
	}

	// Derive file encryption key based on key type
	var fileKey []byte
	var err error
	switch keyType {
	case "account":
		fileKey, err = DeriveAccountFileKey(exportKey, username, fileID)
	case "custom":
		fileKey, err = DeriveOPAQUEFileKey(exportKey, fileID, username)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s (supported: account, custom)", keyType)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Create envelope
	envelope := CreateBasicEnvelope(keyType)

	// Split data into chunks and encrypt each
	chunks := make(map[int][]byte)
	var chunkInfos []ChunkInfo

	totalChunks := (len(data) + chunkSize - 1) / chunkSize

	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunkData := data[start:end]

		// Encrypt chunk using derived file key
		encryptedChunk, err := EncryptGCM(chunkData, fileKey)
		if err != nil {
			return nil, nil, fmt.Errorf("chunk %d encryption failed: %w", i, err)
		}

		chunks[i] = encryptedChunk

		// Calculate chunk hash
		chunkHash := CalculateFileHash(encryptedChunk)

		chunkInfos = append(chunkInfos, ChunkInfo{
			Index: i,
			File:  fmt.Sprintf("chunk_%d.enc", i),
			Hash:  chunkHash,
			Size:  len(encryptedChunk),
		})
	}

	// Create manifest
	manifest := &ChunkManifest{
		Envelope:    hex.EncodeToString(envelope),
		TotalChunks: totalChunks,
		ChunkSize:   chunkSize,
		Chunks:      chunkInfos,
	}

	return manifest, chunks, nil
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

// CreateBasicEnvelope creates a basic envelope header for testing
func CreateBasicEnvelope(keyType string) []byte {
	envelope := make([]byte, 2)
	envelope[0] = 0x01 // Version 1

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

// ParseBasicEnvelope parses a basic envelope header
func ParseBasicEnvelope(envelope []byte) (version byte, keyType string, err error) {
	if len(envelope) < 2 {
		return 0, "", fmt.Errorf("envelope too short: need at least 2 bytes, got %d", len(envelope))
	}

	version = envelope[0]

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
