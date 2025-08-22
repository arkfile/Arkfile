//go:build !js && !wasm
// +build !js,!wasm

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/84adam/Arkfile/crypto"
)

// TestChunkedCryptoLogic tests the core crypto logic that powers the WASM functions
func TestChunkedCryptoLogic(t *testing.T) {
	// Test data
	username := "test@example.com"
	fileID := "test-file"
	testData := []byte("This is test data for chunked encryption validation")

	// Mock OPAQUE export key (64 bytes)
	exportKey := make([]byte, 64)
	if _, err := rand.Read(exportKey); err != nil {
		t.Fatalf("Failed to generate export key: %v", err)
	}

	// Test account key derivation
	accountKey, err := crypto.DeriveAccountFileKey(exportKey, username, fileID)
	if err != nil {
		t.Fatalf("Failed to derive account key: %v", err)
	}

	if len(accountKey) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(accountKey))
	}

	// Test custom key derivation
	customKey, err := crypto.DeriveOPAQUEFileKey(exportKey, fileID, username)
	if err != nil {
		t.Fatalf("Failed to derive custom key: %v", err)
	}

	if len(customKey) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(customKey))
	}

	// Verify keys are different
	if string(accountKey) == string(customKey) {
		t.Fatalf("Account and custom keys should be different")
	}

	// Test chunked encryption/decryption process
	chunkSize := 16 // Small chunks for testing
	totalChunks := (len(testData) + chunkSize - 1) / chunkSize

	// Create envelope
	envelope := []byte{0x01, 0x01} // Account type

	// Encrypt chunks
	var encryptedChunks [][]byte
	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(testData) {
			end = len(testData)
		}

		chunkData := testData[start:end]

		// Create AES-GCM cipher
		block, err := aes.NewCipher(accountKey)
		if err != nil {
			t.Fatalf("Failed to create cipher for chunk %d: %v", i, err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("Failed to create GCM for chunk %d: %v", i, err)
		}

		// Generate nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("Failed to generate nonce for chunk %d: %v", i, err)
		}

		// Encrypt: [nonce][encrypted_data][tag]
		encryptedChunk := gcm.Seal(nonce, nonce, chunkData, nil)
		encryptedChunks = append(encryptedChunks, encryptedChunk)
	}

	// Simulate storage concatenation: [envelope][chunk1][chunk2]...[chunkN]
	var concatenatedData []byte
	concatenatedData = append(concatenatedData, envelope...)
	for _, chunk := range encryptedChunks {
		concatenatedData = append(concatenatedData, chunk...)
	}

	// Decrypt the concatenated data
	if len(concatenatedData) < 2 {
		t.Fatalf("Concatenated data too short")
	}

	// Read envelope
	version := concatenatedData[0]
	keyType := concatenatedData[1]
	chunksData := concatenatedData[2:]

	if version != 0x01 || keyType != 0x01 {
		t.Fatalf("Envelope mismatch: got version=0x%02x, keyType=0x%02x", version, keyType)
	}

	// Decrypt chunks
	var plaintext []byte
	offset := 0

	// Create cipher for decryption
	block, err := aes.NewCipher(accountKey)
	if err != nil {
		t.Fatalf("Failed to create decrypt cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create decrypt GCM: %v", err)
	}

	chunkIndex := 0
	for offset < len(chunksData) {
		// Check minimum data available
		if offset+gcm.NonceSize()+16 > len(chunksData) {
			t.Fatalf("Insufficient data for chunk %d at offset %d", chunkIndex, offset)
		}

		// Read nonce
		nonce := chunksData[offset : offset+gcm.NonceSize()]
		offset += gcm.NonceSize()

		// For testing, we know the expected chunk sizes
		remainingData := chunksData[offset:]
		expectedChunkDataSize := chunkSize
		if chunkIndex == totalChunks-1 {
			// Last chunk might be smaller
			expectedChunkDataSize = len(testData) - (chunkIndex * chunkSize)
		}

		// Try to decrypt with expected size + tag (16 bytes)
		expectedEncryptedSize := expectedChunkDataSize + 16
		if len(remainingData) < expectedEncryptedSize {
			expectedEncryptedSize = len(remainingData)
		}

		encryptedChunk := remainingData[:expectedEncryptedSize]

		// Decrypt
		decryptedChunk, err := gcm.Open(nil, nonce, encryptedChunk, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt chunk %d: %v", chunkIndex, err)
		}

		plaintext = append(plaintext, decryptedChunk...)
		offset += expectedEncryptedSize
		chunkIndex++
	}

	// Verify decrypted data matches original
	if len(plaintext) != len(testData) {
		t.Fatalf("Size mismatch: expected %d bytes, got %d bytes", len(testData), len(plaintext))
	}

	if string(plaintext) != string(testData) {
		t.Fatalf("Data mismatch: expected %q, got %q", string(testData), string(plaintext))
	}

	// Verify hash integrity
	originalHash := sha256.Sum256(testData)
	decryptedHash := sha256.Sum256(plaintext)

	if hex.EncodeToString(originalHash[:]) != hex.EncodeToString(decryptedHash[:]) {
		t.Fatalf("Hash mismatch")
	}

	t.Logf("✅ Chunked crypto logic test passed: processed %d bytes in %d chunks", len(testData), totalChunks)
}

// TestEnvelopeValidation tests envelope format validation
func TestEnvelopeValidation(t *testing.T) {
	testCases := []struct {
		name        string
		envelope    []byte
		shouldPass  bool
		expectedVer byte
		expectedKey byte
	}{
		{"Valid Account", []byte{0x01, 0x01}, true, 0x01, 0x01},
		{"Valid Custom", []byte{0x02, 0x02}, true, 0x02, 0x02},
		{"Too Short", []byte{0x01}, false, 0x00, 0x00},
		{"Empty", []byte{}, false, 0x00, 0x00},
		{"Invalid Version", []byte{0x99, 0x01}, false, 0x00, 0x00},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate envelope validation
			if len(tc.envelope) < 2 {
				if tc.shouldPass {
					t.Fatalf("Expected pass but envelope too short")
				}
				return // Expected failure
			}

			version := tc.envelope[0]
			keyType := tc.envelope[1]

			// Validate known versions
			if version != 0x01 && version != 0x02 {
				if tc.shouldPass {
					t.Fatalf("Expected pass but got invalid version")
				}
				return // Expected failure
			}

			// Validate key type matches version
			if version == 0x01 && keyType != 0x01 {
				if tc.shouldPass {
					t.Fatalf("Expected pass but account version has wrong key type")
				}
				return // Expected failure
			}

			if version == 0x02 && keyType != 0x02 {
				if tc.shouldPass {
					t.Fatalf("Expected pass but custom version has wrong key type")
				}
				return // Expected failure
			}

			// If we reach here, validation passed
			if !tc.shouldPass {
				t.Fatalf("Expected failure but validation passed")
			}

			if version != tc.expectedVer || keyType != tc.expectedKey {
				t.Fatalf("Values mismatch: expected v=%02x k=%02x, got v=%02x k=%02x",
					tc.expectedVer, tc.expectedKey, version, keyType)
			}
		})
	}

	t.Log("✅ Envelope validation tests passed")
}

// TestChunkSizeValidation tests chunk size constraints
func TestChunkSizeValidation(t *testing.T) {
	testCases := []struct {
		name       string
		chunkSize  int
		shouldPass bool
	}{
		{"Minimum Valid", 29, true}, // 12 (nonce) + 1 (data) + 16 (tag)
		{"Small Valid", 100, true},
		{"Large Valid", 16*1024*1024 + 28, true}, // 16MB + overhead
		{"Too Small", 28, false},                 // Less than minimum
		{"Too Large", 16*1024*1024 + 29, false},  // More than max
		{"Zero", 0, false},
		{"Negative", -1, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate chunk size validation logic
			minSize := 29                // 12 (nonce) + 1 (data) + 16 (tag)
			maxSize := 16*1024*1024 + 28 // 16MB + 28 bytes overhead

			valid := tc.chunkSize >= minSize && tc.chunkSize <= maxSize

			if valid != tc.shouldPass {
				t.Fatalf("Expected shouldPass=%v, but got valid=%v for size %d", tc.shouldPass, valid, tc.chunkSize)
			}
		})
	}

	t.Log("✅ Chunk size validation tests passed")
}
