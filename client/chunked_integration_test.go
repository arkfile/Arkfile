//go:build js && wasm
// +build js,wasm

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"syscall/js"
	"testing"
)

// TestChunkedUploadIntegration tests the complete chunked upload/download cycle
func TestChunkedUploadIntegration(t *testing.T) {
	// Test cases with different file sizes
	testCases := []struct {
		name     string
		fileSize int
		keyType  string
	}{
		{"SmallFile_1MB_Account", 1 * 1024 * 1024, "account"},
		{"MediumFile_16MB_Account", 16 * 1024 * 1024, "account"},
		{"LargeFile_32MB_Custom", 32 * 1024 * 1024, "custom"},
		{"HugeFile_100MB_Custom", 100 * 1024 * 1024, "custom"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate test file data
			originalData := make([]byte, tc.fileSize)
			if _, err := rand.Read(originalData); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			// Calculate original hash
			originalHash := sha256.Sum256(originalData)
			originalHashHex := hex.EncodeToString(originalHash[:])

			// Mock user credentials
			username := "test@example.com"
			fileID := "test-file-" + tc.name

			// Mock password (64 bytes for Argon2ID salt)
			password := make([]byte, 64)
			if _, err := rand.Read(password); err != nil {
				t.Fatalf("Failed to generate password: %v", err)
			}
			passwordB64 := base64.StdEncoding.EncodeToString(password)

			// Step 1: Store password
			storeResult := storePasswordForUser(js.Null(), []js.Value{
				js.ValueOf(username),
				js.ValueOf(passwordB64),
			})

			storeMap, ok := storeResult.(map[string]interface{})
			if !ok || !storeMap["success"].(bool) {
				t.Fatalf("Failed to store password: %v", storeMap["error"])
			}

			// Step 2: Create envelope
			envelopeResult := createPasswordEnvelope(js.Null(), []js.Value{
				js.ValueOf(tc.keyType),
			})

			envelopeMap, ok := envelopeResult.(map[string]interface{})
			if !ok || !envelopeMap["success"].(bool) {
				t.Fatalf("Failed to create envelope: %v", envelopeMap["error"])
			}

			envelopeB64 := envelopeMap["envelope"].(string)

			// Step 3: Encrypt file in chunks
			// Convert Go []byte to JS Uint8Array for WASM function
			jsArray := js.Global().Get("Uint8Array").New(len(originalData))
			js.CopyBytesToJS(jsArray, originalData)

			encryptResult := encryptFileChunkedPassword(js.Null(), []js.Value{
				jsArray,
				js.ValueOf(username),
				js.ValueOf(tc.keyType),
				js.ValueOf(fileID),
				js.ValueOf(16 * 1024 * 1024), // 16MB chunk size
			})

			encryptMap, ok := encryptResult.(map[string]interface{})
			if !ok || !encryptMap["success"].(bool) {
				t.Fatalf("Failed to encrypt file: %v", encryptMap["error"])
			}

			// Validate encryption results
			chunks := encryptMap["chunks"].([]map[string]interface{})
			totalChunks := encryptMap["totalChunks"].(int)
			returnedEnvelope := encryptMap["envelope"].(string)

			if len(chunks) != totalChunks {
				t.Fatalf("Chunk count mismatch: expected %d, got %d", totalChunks, len(chunks))
			}

			if returnedEnvelope != envelopeB64 {
				t.Fatalf("Envelope mismatch: expected %s, got %s", envelopeB64, returnedEnvelope)
			}

			// Step 4: Simulate storage concatenation (envelope + chunks)
			// This simulates what the server storage layer does
			envelopeBytes, err := base64.StdEncoding.DecodeString(envelopeB64)
			if err != nil {
				t.Fatalf("Failed to decode envelope: %v", err)
			}

			var concatenatedData []byte
			concatenatedData = append(concatenatedData, envelopeBytes...)

			for _, chunk := range chunks {
				chunkData, err := base64.StdEncoding.DecodeString(chunk["data"].(string))
				if err != nil {
					t.Fatalf("Failed to decode chunk data: %v", err)
				}
				concatenatedData = append(concatenatedData, chunkData...)
			}

			// Step 5: Decrypt concatenated data
			concatenatedB64 := base64.StdEncoding.EncodeToString(concatenatedData)

			decryptResult := decryptFileChunkedPassword(js.Null(), []js.Value{
				js.ValueOf(concatenatedB64),
				js.ValueOf(username),
				js.ValueOf(fileID),
			})

			decryptMap, ok := decryptResult.(map[string]interface{})
			if !ok || !decryptMap["success"].(bool) {
				t.Fatalf("Failed to decrypt file: %v", decryptMap["error"])
			}

			// Step 6: Validate decrypted data
			decryptedB64 := decryptMap["data"].(string)
			decryptedData, err := base64.StdEncoding.DecodeString(decryptedB64)
			if err != nil {
				t.Fatalf("Failed to decode decrypted data: %v", err)
			}

			// Verify data integrity
			if len(decryptedData) != len(originalData) {
				t.Fatalf("Size mismatch: expected %d bytes, got %d bytes", len(originalData), len(decryptedData))
			}

			// Verify hash
			decryptedHash := sha256.Sum256(decryptedData)
			decryptedHashHex := hex.EncodeToString(decryptedHash[:])

			if originalHashHex != decryptedHashHex {
				t.Fatalf("Hash mismatch: expected %s, got %s", originalHashHex, decryptedHashHex)
			}

			// Verify byte-by-byte equality (spot check first 1000 bytes)
			checkBytes := 1000
			if len(originalData) < checkBytes {
				checkBytes = len(originalData)
			}

			for i := 0; i < checkBytes; i++ {
				if originalData[i] != decryptedData[i] {
					t.Fatalf("Data mismatch at byte %d: expected 0x%02x, got 0x%02x", i, originalData[i], decryptedData[i])
				}
			}

			// Step 7: Clean up
			clearResult := clearPasswordForUser(js.Null(), []js.Value{
				js.ValueOf(username),
			})

			clearMap, ok := clearResult.(map[string]interface{})
			if !ok || !clearMap["success"].(bool) {
				t.Errorf("Failed to clear password: %v", clearMap["error"])
			}

			t.Logf("✅ %s: Successfully processed %d bytes in %d chunks", tc.name, tc.fileSize, totalChunks)
		})
	}
}

// TestChunkedEncryptionSecurity tests security properties
func TestChunkedEncryptionSecurity(t *testing.T) {
	// Mock user credentials
	username := "security-test@example.com"
	fileID := "security-test-file"

	// Generate test data
	testData := make([]byte, 64*1024) // 64KB
	if _, err := rand.Read(testData); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Mock password (64 bytes for Argon2ID salt)
	password := make([]byte, 64)
	if _, err := rand.Read(password); err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}
	passwordB64 := base64.StdEncoding.EncodeToString(password)

	// Store password
	storeResult := storePasswordForUser(js.Null(), []js.Value{
		js.ValueOf(username),
		js.ValueOf(passwordB64),
	})

	storeMap, ok := storeResult.(map[string]interface{})
	if !ok || !storeMap["success"].(bool) {
		t.Fatalf("Failed to store password: %v", storeMap["error"])
	}

	// Convert to JS array
	jsArray := js.Global().Get("Uint8Array").New(len(testData))
	js.CopyBytesToJS(jsArray, testData)

	// Test 1: Same input should produce different encrypted output (due to nonce randomness)
	encrypt1 := encryptFileChunkedPassword(js.Null(), []js.Value{
		jsArray,
		js.ValueOf(username),
		js.ValueOf("account"),
		js.ValueOf(fileID),
		js.ValueOf(32 * 1024), // 32KB chunks
	})

	encrypt2 := encryptFileChunkedPassword(js.Null(), []js.Value{
		jsArray,
		js.ValueOf(username),
		js.ValueOf("account"),
		js.ValueOf(fileID),
		js.ValueOf(32 * 1024), // 32KB chunks
	})

	encrypt1Map := encrypt1.(map[string]interface{})
	encrypt2Map := encrypt2.(map[string]interface{})

	if !encrypt1Map["success"].(bool) || !encrypt2Map["success"].(bool) {
		t.Fatalf("Encryption failed")
	}

	chunks1 := encrypt1Map["chunks"].([]map[string]interface{})
	chunks2 := encrypt2Map["chunks"].([]map[string]interface{})

	// Verify chunks are different (due to random nonces)
	if len(chunks1) != len(chunks2) {
		t.Fatalf("Chunk count mismatch between encryptions")
	}

	for i := 0; i < len(chunks1); i++ {
		chunk1Data := chunks1[i]["data"].(string)
		chunk2Data := chunks2[i]["data"].(string)

		if chunk1Data == chunk2Data {
			t.Fatalf("Chunks %d are identical (nonce reuse detected!)", i)
		}
	}

	// Test 2: Different users should produce different output
	username2 := "security-test-2@example.com"
	password2 := make([]byte, 64)
	if _, err := rand.Read(password2); err != nil {
		t.Fatalf("Failed to generate password 2: %v", err)
	}
	password2B64 := base64.StdEncoding.EncodeToString(password2)

	storeResult2 := storePasswordForUser(js.Null(), []js.Value{
		js.ValueOf(username2),
		js.ValueOf(password2B64),
	})

	storeMap2 := storeResult2.(map[string]interface{})
	if !storeMap2["success"].(bool) {
		t.Fatalf("Failed to store password 2: %v", storeMap2["error"])
	}

	encryptUser2 := encryptFileChunkedPassword(js.Null(), []js.Value{
		jsArray,
		js.ValueOf(username2), // Different user
		js.ValueOf("account"),
		js.ValueOf(fileID),
		js.ValueOf(32 * 1024),
	})

	encryptUser2Map := encryptUser2.(map[string]interface{})
	if !encryptUser2Map["success"].(bool) {
		t.Fatalf("User 2 encryption failed")
	}

	chunksUser2 := encryptUser2Map["chunks"].([]map[string]interface{})

	// Verify different users produce different ciphertext
	for i := 0; i < len(chunks1); i++ {
		chunk1Data := chunks1[i]["data"].(string)
		chunkUser2Data := chunksUser2[i]["data"].(string)

		if chunk1Data == chunkUser2Data {
			t.Fatalf("Different users produced identical chunks (key derivation failure!)")
		}
	}

	// Test 3: Account vs Custom password types should produce different output
	encryptCustom := encryptFileChunkedPassword(js.Null(), []js.Value{
		jsArray,
		js.ValueOf(username),
		js.ValueOf("custom"), // Different password type
		js.ValueOf(fileID),
		js.ValueOf(32 * 1024),
	})

	encryptCustomMap := encryptCustom.(map[string]interface{})
	if !encryptCustomMap["success"].(bool) {
		t.Fatalf("Custom encryption failed")
	}

	chunksCustom := encryptCustomMap["chunks"].([]map[string]interface{})

	// Verify different password types produce different ciphertext
	for i := 0; i < len(chunks1); i++ {
		chunk1Data := chunks1[i]["data"].(string)
		chunkCustomData := chunksCustom[i]["data"].(string)

		if chunk1Data == chunkCustomData {
			t.Fatalf("Different password types produced identical chunks")
		}
	}

	t.Log("✅ Security tests passed: Nonce uniqueness, user isolation, and password type isolation verified")

	// Cleanup
	clearPasswordForUser(js.Null(), []js.Value{js.ValueOf(username)})
	clearPasswordForUser(js.Null(), []js.Value{js.ValueOf(username2)})
}

// TestChunkedFormatValidation tests format validation
func TestChunkedFormatValidation(t *testing.T) {
	// Test envelope creation
	testCases := []struct {
		keyType     string
		shouldPass  bool
		expectedVer byte
		expectedKey byte
	}{
		{"account", true, 0x01, 0x01},
		{"custom", true, 0x01, 0x02},
		{"invalid", false, 0x01, 0x00},
		{"", false, 0x00, 0x00},
	}

	for _, tc := range testCases {
		t.Run("Envelope_"+tc.keyType, func(t *testing.T) {
			result := createPasswordEnvelope(js.Null(), []js.Value{
				js.ValueOf(tc.keyType),
			})

			resultMap, ok := result.(map[string]interface{})
			if !ok {
				t.Fatalf("Invalid result type")
			}

			if tc.shouldPass {
				if !resultMap["success"].(bool) {
					t.Fatalf("Expected success but got failure: %v", resultMap["error"])
				}

				// Decode and validate envelope
				envelopeB64 := resultMap["envelope"].(string)
				envelope, err := base64.StdEncoding.DecodeString(envelopeB64)
				if err != nil {
					t.Fatalf("Failed to decode envelope: %v", err)
				}

				if len(envelope) != 2 {
					t.Fatalf("Expected 2-byte envelope, got %d bytes", len(envelope))
				}

				if envelope[0] != tc.expectedVer {
					t.Fatalf("Version mismatch: expected 0x%02x, got 0x%02x", tc.expectedVer, envelope[0])
				}

				if envelope[1] != tc.expectedKey {
					t.Fatalf("Key type mismatch: expected 0x%02x, got 0x%02x", tc.expectedKey, envelope[1])
				}
			} else {
				if resultMap["success"].(bool) {
					t.Fatalf("Expected failure but got success")
				}
			}
		})
	}

	t.Log("✅ Format validation tests passed")
}
