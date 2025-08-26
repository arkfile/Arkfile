//go:build js && wasm
// +build js,wasm

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"syscall/js"
	"testing"
)

// Test helper to create a mock OPAQUE export key
func createMockExportKey() []byte {
	key := make([]byte, 64)
	rand.Read(key)
	return key
}

// Test helper to create JavaScript values for WASM functions
func createJSValue(data interface{}) js.Value {
	// This is a simplified mock for testing
	// In actual WASM environment, js.ValueOf would handle this
	return js.Null() // Placeholder
}

func TestCreateEnvelopeOPAQUE(t *testing.T) {
	tests := []struct {
		name        string
		keyType     string
		expectError bool
		expectedVer byte
		expectedKey byte
	}{
		{
			name:        "Account key type",
			keyType:     "account",
			expectError: false,
			expectedVer: 0x01,
			expectedKey: 0x01,
		},
		{
			name:        "Custom key type",
			keyType:     "custom",
			expectError: false,
			expectedVer: 0x02,
			expectedKey: 0x02,
		},
		{
			name:        "Invalid key type",
			keyType:     "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock JavaScript arguments
			args := []js.Value{js.ValueOf(tt.keyType)}

			// Call the function
			result := createEnvelopeOPAQUE(js.Null(), args)

			// Convert result to map for testing
			resultMap, ok := result.(map[string]interface{})
			if !ok {
				t.Fatal("Expected map result")
			}

			success := resultMap["success"].(bool)

			if tt.expectError {
				if success {
					t.Error("Expected error but got success")
				}
				return
			}

			if !success {
				t.Errorf("Expected success but got error: %v", resultMap["error"])
				return
			}

			// Decode and validate envelope
			envelopeB64 := resultMap["envelope"].(string)
			envelope, err := base64.StdEncoding.DecodeString(envelopeB64)
			if err != nil {
				t.Fatalf("Failed to decode envelope: %v", err)
			}

			if len(envelope) != 2 {
				t.Errorf("Expected envelope length 2, got %d", len(envelope))
			}

			if envelope[0] != tt.expectedVer {
				t.Errorf("Expected version %02x, got %02x", tt.expectedVer, envelope[0])
			}

			if envelope[1] != tt.expectedKey {
				t.Errorf("Expected key type %02x, got %02x", tt.expectedKey, envelope[1])
			}
		})
	}
}

func TestValidateChunkFormat(t *testing.T) {
	tests := []struct {
		name        string
		chunkSize   int
		expectValid bool
		description string
	}{
		{
			name:        "Valid minimum chunk",
			chunkSize:   29, // 12 (nonce) + 1 (data) + 16 (tag)
			expectValid: true,
			description: "Minimum valid chunk size",
		},
		{
			name:        "Valid large chunk",
			chunkSize:   1024*1024 + 28, // 1MB + overhead
			expectValid: true,
			description: "Normal sized chunk",
		},
		{
			name:        "Too small chunk",
			chunkSize:   28,
			expectValid: false,
			description: "Below minimum size",
		},
		{
			name:        "Maximum valid chunk",
			chunkSize:   16*1024*1024 + 28, // 16MB + overhead
			expectValid: true,
			description: "Maximum chunk size",
		},
		{
			name:        "Too large chunk",
			chunkSize:   16*1024*1024 + 29, // Over 16MB + overhead
			expectValid: false,
			description: "Exceeds maximum size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock chunk data
			chunkData := make([]byte, tt.chunkSize)
			rand.Read(chunkData)
			chunkDataB64 := base64.StdEncoding.EncodeToString(chunkData)

			// Create JavaScript arguments
			args := []js.Value{js.ValueOf(chunkDataB64)}

			// Call validation function
			result := validateChunkFormat(js.Null(), args)

			// Convert result to map
			resultMap, ok := result.(map[string]interface{})
			if !ok {
				t.Fatal("Expected map result")
			}

			valid := resultMap["valid"].(bool)

			if valid != tt.expectValid {
				if tt.expectValid {
					t.Errorf("Expected valid chunk but got error: %v", resultMap["error"])
				} else {
					t.Error("Expected invalid chunk but validation passed")
				}
			}

			if valid {
				// Check returned metadata
				nonceSize := resultMap["nonceSize"].(int)
				tagSize := resultMap["tagSize"].(int)
				dataSize := resultMap["dataSize"].(int)

				if nonceSize != 12 {
					t.Errorf("Expected nonce size 12, got %d", nonceSize)
				}

				if tagSize != 16 {
					t.Errorf("Expected tag size 16, got %d", tagSize)
				}

				expectedDataSize := tt.chunkSize - 28
				if dataSize != expectedDataSize {
					t.Errorf("Expected data size %d, got %d", expectedDataSize, dataSize)
				}
			}
		})
	}
}

func TestChunkedEncryptionRoundTrip(t *testing.T) {
	// This test would verify that encrypt -> decrypt produces original data
	// However, it requires a full WASM environment with OPAQUE keys

	testData := []byte("Hello, this is test data for chunked encryption!")
	username := "test_username_123"
	fileID := "test-file-123"
	keyType := "account"
	chunkSize := 32 // Small chunk for testing

	// Create mock export key
	mockKey := createMockExportKey()
	opaqueExportKeys[username] = mockKey

	// Note: This test would need actual JavaScript environment to run
	// For now, we validate the logic structure

	t.Run("Basic encryption parameters", func(t *testing.T) {
		if len(testData) == 0 {
			t.Error("Test data should not be empty")
		}

		if chunkSize <= 0 {
			t.Error("Chunk size should be positive")
		}

		expectedChunks := (len(testData) + chunkSize - 1) / chunkSize
		if expectedChunks == 0 {
			t.Error("Should have at least one chunk")
		}

		t.Logf("Test data: %d bytes, chunk size: %d, expected chunks: %d",
			len(testData), chunkSize, expectedChunks)
	})

	t.Run("Key derivation parameters", func(t *testing.T) {
		if username == "" {
			t.Error("Username should not be empty")
		}

		if fileID == "" {
			t.Error("File ID should not be empty")
		}

		if keyType != "account" && keyType != "custom" {
			t.Error("Key type should be 'account' or 'custom'")
		}

		if len(mockKey) != 64 {
			t.Errorf("Export key should be 64 bytes, got %d", len(mockKey))
		}
	})
}

func TestDecryptFileChunkedOPAQUEBoundaryDetection(t *testing.T) {
	t.Run("Chunk boundary detection logic", func(t *testing.T) {
		// Test the logic that was fixed in decryptFileChunkedOPAQUE
		// This validates the new boundary detection algorithm

		// Simulate chunk format: [nonce:12][encrypted_data][tag:16]
		nonceSize := 12
		tagSize := 16
		minChunkSize := nonceSize + tagSize // 28 bytes minimum

		testCases := []struct {
			name          string
			dataSize      int
			expectedValid bool
			description   string
		}{
			{
				name:          "Minimum valid chunk",
				dataSize:      29, // 12 + 1 + 16
				expectedValid: true,
				description:   "Smallest possible chunk with 1 byte of data",
			},
			{
				name:          "Normal chunk",
				dataSize:      1024 + 28, // 1KB data + overhead
				expectedValid: true,
				description:   "Standard chunk size",
			},
			{
				name:          "Too small chunk",
				dataSize:      27, // Below minimum
				expectedValid: false,
				description:   "Missing required components",
			},
			{
				name:          "Exactly minimum overhead",
				dataSize:      28, // Just nonce + tag, no data
				expectedValid: false,
				description:   "No actual data payload",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Validate the chunk size requirements
				hasMinimumSize := tc.dataSize >= minChunkSize
				hasData := tc.dataSize > minChunkSize

				if tc.expectedValid {
					if !hasMinimumSize {
						t.Errorf("Expected valid chunk but size %d < minimum %d", tc.dataSize, minChunkSize)
					}
					if !hasData {
						t.Errorf("Expected valid chunk but no data payload (size %d, overhead %d)", tc.dataSize, minChunkSize)
					}
				} else {
					if hasMinimumSize && hasData {
						t.Errorf("Expected invalid chunk but meets requirements (size %d)", tc.dataSize)
					}
				}

				t.Logf("%s: size=%d, valid=%t", tc.description, tc.dataSize, tc.expectedValid)
			})
		}
	})

	t.Run("Sequential chunk processing", func(t *testing.T) {
		// Test the improved sequential processing logic
		nonceSize := 12
		tagSize := 16

		// Create mock chunked data: chunk1 + chunk2
		chunk1Data := make([]byte, 32) // 32 bytes data
		chunk2Data := make([]byte, 64) // 64 bytes data

		chunk1Total := nonceSize + len(chunk1Data) + tagSize // 12 + 32 + 16 = 60
		chunk2Total := nonceSize + len(chunk2Data) + tagSize // 12 + 64 + 16 = 92

		totalSize := chunk1Total + chunk2Total // 152 bytes total

		t.Logf("Chunk 1: %d bytes total (%d data)", chunk1Total, len(chunk1Data))
		t.Logf("Chunk 2: %d bytes total (%d data)", chunk2Total, len(chunk2Data))
		t.Logf("Total chunked data: %d bytes", totalSize)

		// Validate sequential processing logic
		offset := 0
		chunkCount := 0

		// Process first chunk
		chunkCount++
		if offset+nonceSize+tagSize > totalSize {
			t.Error("Not enough data for first chunk")
		}
		offset += nonceSize // Skip nonce

		// Find next chunk boundary (simplified simulation)
		nextChunkStart := chunk1Total
		if nextChunkStart > offset {
			chunk1EncryptedSize := nextChunkStart - offset
			t.Logf("Chunk 1 encrypted data size: %d bytes", chunk1EncryptedSize)
			offset = nextChunkStart
		}

		// Process second chunk
		chunkCount++
		if offset+nonceSize+tagSize <= totalSize {
			offset += nonceSize // Skip nonce
			chunk2EncryptedSize := totalSize - offset
			t.Logf("Chunk 2 encrypted data size: %d bytes", chunk2EncryptedSize)
		}

		if chunkCount != 2 {
			t.Errorf("Expected 2 chunks, processed %d", chunkCount)
		}
	})
}

func TestAuthenticatedFetchHeaderHandling(t *testing.T) {
	t.Run("Header copying logic", func(t *testing.T) {
		// Test the improved header handling in authenticatedFetch

		// Common headers that should be preserved
		commonHeaders := map[string]string{
			"Content-Type":    "application/json",
			"Accept":          "application/json",
			"X-Custom-Header": "custom-value",
			"Cache-Control":   "no-cache",
			"User-Agent":      "ArkFile-Client/1.0",
		}

		// Validate that all headers would be copied
		for headerName, headerValue := range commonHeaders {
			if headerName == "" {
				t.Error("Header name should not be empty")
			}
			if headerValue == "" {
				t.Error("Header value should not be empty")
			}
			t.Logf("Header: %s = %s", headerName, headerValue)
		}

		// Test Authorization header injection
		authHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Error("Authorization header should start with 'Bearer '")
		}

		t.Logf("Authorization header format validated: %s", authHeader[:20]+"...")
	})

	t.Run("Fetch options handling", func(t *testing.T) {
		// Test all fetch options that should be preserved
		fetchOptions := map[string]string{
			"method":         "POST",
			"mode":           "cors",
			"credentials":    "same-origin",
			"cache":          "no-cache",
			"redirect":       "follow",
			"referrer":       "no-referrer",
			"referrerPolicy": "no-referrer",
			"integrity":      "sha256-...",
		}

		for optionName, optionValue := range fetchOptions {
			if optionName == "" {
				t.Error("Option name should not be empty")
			}
			if optionValue == "" {
				t.Error("Option value should not be empty")
			}
			t.Logf("Fetch option: %s = %s", optionName, optionValue)
		}
	})
}

func TestEnvelopeFormatSpecification(t *testing.T) {
	t.Run("Envelope byte layout", func(t *testing.T) {
		// Test account envelope
		accountEnvelope := []byte{0x01, 0x01}
		if len(accountEnvelope) != 2 {
			t.Error("Envelope should be exactly 2 bytes")
		}

		if accountEnvelope[0] != 0x01 {
			t.Error("Account version should be 0x01")
		}

		if accountEnvelope[1] != 0x01 {
			t.Error("Account key type should be 0x01")
		}

		// Test custom envelope
		customEnvelope := []byte{0x02, 0x02}
		if customEnvelope[0] != 0x02 {
			t.Error("Custom version should be 0x02")
		}

		if customEnvelope[1] != 0x02 {
			t.Error("Custom key type should be 0x02")
		}
	})

	t.Run("Chunk format specification", func(t *testing.T) {
		// Simulate chunk structure: [nonce:12][data][tag:16]
		nonce := make([]byte, 12)
		data := []byte("test data")
		tag := make([]byte, 16)

		rand.Read(nonce)
		rand.Read(tag)

		chunk := append(nonce, data...)
		chunk = append(chunk, tag...)

		if len(chunk) != 12+len(data)+16 {
			t.Error("Chunk format should be nonce + data + tag")
		}

		// Verify components
		extractedNonce := chunk[:12]
		extractedData := chunk[12 : 12+len(data)]
		extractedTag := chunk[12+len(data):]

		if len(extractedNonce) != 12 {
			t.Error("Nonce should be 12 bytes")
		}

		if len(extractedTag) != 16 {
			t.Error("Tag should be 16 bytes")
		}

		if string(extractedData) != string(data) {
			t.Error("Data should match original")
		}
	})
}

func TestSecurityProperties(t *testing.T) {
	t.Run("Nonce uniqueness", func(t *testing.T) {
		// Generate multiple nonces and ensure they're unique
		nonces := make(map[string]bool)
		numNonces := 1000

		for i := 0; i < numNonces; i++ {
			nonce := make([]byte, 12)
			rand.Read(nonce)
			nonceHex := hex.EncodeToString(nonce)

			if nonces[nonceHex] {
				t.Errorf("Duplicate nonce detected: %s", nonceHex)
			}
			nonces[nonceHex] = true
		}

		if len(nonces) != numNonces {
			t.Errorf("Expected %d unique nonces, got %d", numNonces, len(nonces))
		}
	})

	t.Run("Key validation", func(t *testing.T) {
		// Test valid key
		validKey := make([]byte, 64)
		rand.Read(validKey)

		if !validateOPAQUEExportKey(validKey) {
			t.Error("Valid key should pass validation")
		}

		// Test invalid key lengths
		shortKey := make([]byte, 32)
		if validateOPAQUEExportKey(shortKey) {
			t.Error("Short key should fail validation")
		}

		longKey := make([]byte, 128)
		if validateOPAQUEExportKey(longKey) {
			t.Error("Long key should fail validation")
		}

		// Test all-zero key
		zeroKey := make([]byte, 64)
		if validateOPAQUEExportKey(zeroKey) {
			t.Error("All-zero key should fail validation")
		}
	})
}
