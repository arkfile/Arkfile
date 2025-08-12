package crypto

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestPhase1AIntegration validates the complete PHASE 1A implementation
func TestPhase1AIntegration(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("File Generation and Verification", func(t *testing.T) {
		sizes := []int64{1024, 10 * 1024, 100 * 1024} // 1KB, 10KB, 100KB
		patterns := []FilePattern{PatternSequential, PatternRepeated, PatternRandom}

		for _, size := range sizes {
			for _, pattern := range patterns {
				t.Run(string(pattern)+"-"+FormatFileSize(size), func(t *testing.T) {
					// Generate test file
					filename := filepath.Join(tempDir, string(pattern)+"-"+FormatFileSize(size)+".dat")
					hash, err := GenerateTestFileToPath(filename, size, pattern)
					if err != nil {
						t.Fatalf("Failed to generate test file: %v", err)
					}

					// Verify file exists and has correct size
					info, err := os.Stat(filename)
					if err != nil {
						t.Fatalf("Generated file not found: %v", err)
					}

					if info.Size() != size {
						t.Errorf("File size mismatch: expected %d, got %d", size, info.Size())
					}

					// Verify hash matches
					actualHash, err := CalculateFileHashFromPath(filename)
					if err != nil {
						t.Fatalf("Failed to calculate file hash: %v", err)
					}

					if hash != actualHash {
						t.Errorf("Hash mismatch: expected %s, got %s", hash, actualHash)
					}

					// Verify file integrity
					if err := VerifyFileIntegrity(filename, hash, size); err != nil {
						t.Errorf("File integrity verification failed: %v", err)
					}
				})
			}
		}
	})

	t.Run("Basic Encryption/Decryption Workflow", func(t *testing.T) {
		// Create test file
		originalFile := filepath.Join(tempDir, "original.dat")
		testData := []byte("This is PHASE 1A test data for basic encryption workflow validation.")

		if err := os.WriteFile(originalFile, testData, 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		// Test key (32 bytes for AES-256)
		keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			t.Fatalf("Failed to decode test key: %v", err)
		}

		// Encrypt data
		encryptedData, err := EncryptGCM(testData, key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Verify encrypted data is different
		if bytes.Equal(testData, encryptedData) {
			t.Error("Encrypted data should be different from original")
		}

		// Decrypt data
		decryptedData, err := DecryptGCM(encryptedData, key)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Verify decrypted data matches original
		if !bytes.Equal(testData, decryptedData) {
			t.Error("Decrypted data does not match original")
		}

		t.Logf("✅ Encryption/Decryption workflow: original %d bytes → encrypted %d bytes → decrypted %d bytes",
			len(testData), len(encryptedData), len(decryptedData))
	})

	t.Run("Envelope Creation and Parsing", func(t *testing.T) {
		keyTypes := []string{"account", "custom", "share", "unknown_type"}
		expectedTypes := []string{"account", "custom", "share", "unknown"}

		for i, keyType := range keyTypes {
			t.Run(keyType, func(t *testing.T) {
				// Create envelope
				envelope := CreateBasicEnvelope(keyType)
				if len(envelope) != 2 {
					t.Errorf("Envelope should be 2 bytes, got %d", len(envelope))
				}

				// Parse envelope
				version, parsedType, err := ParseBasicEnvelope(envelope)
				if err != nil {
					t.Fatalf("Failed to parse envelope: %v", err)
				}

				if version != 0x01 {
					t.Errorf("Expected version 1, got %d", version)
				}

				if parsedType != expectedTypes[i] {
					t.Errorf("Expected key type %s, got %s", expectedTypes[i], parsedType)
				}

				t.Logf("✅ Envelope: %s → version=%d, type=%s", keyType, version, parsedType)
			})
		}
	})

	t.Run("Complete File Encryption with Envelope", func(t *testing.T) {
		// Generate test file
		testFile := filepath.Join(tempDir, "test-for-encryption.dat")
		hash, err := GenerateTestFileToPath(testFile, 2048, PatternRepeated)
		if err != nil {
			t.Fatalf("Failed to generate test file: %v", err)
		}

		// Read test file
		originalData, err := os.ReadFile(testFile)
		if err != nil {
			t.Fatalf("Failed to read test file: %v", err)
		}

		// Test key
		keyHex := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			t.Fatalf("Failed to decode key: %v", err)
		}

		// Encrypt with envelope
		encryptedData, err := EncryptGCM(originalData, key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		envelope := CreateBasicEnvelope("custom")
		finalData := append(envelope, encryptedData...)

		encryptedFile := filepath.Join(tempDir, "test-encrypted-with-envelope.dat")
		if err := os.WriteFile(encryptedFile, finalData, 0644); err != nil {
			t.Fatalf("Failed to write encrypted file: %v", err)
		}

		// Decrypt with envelope parsing
		encryptedFileData, err := os.ReadFile(encryptedFile)
		if err != nil {
			t.Fatalf("Failed to read encrypted file: %v", err)
		}

		// Parse envelope
		if len(encryptedFileData) < 2 {
			t.Fatal("Encrypted file too short for envelope")
		}

		version, keyType, err := ParseBasicEnvelope(encryptedFileData[:2])
		if err != nil {
			t.Fatalf("Failed to parse envelope: %v", err)
		}

		ciphertext := encryptedFileData[2:]
		decryptedData, err := DecryptGCM(ciphertext, key)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Verify integrity
		if !bytes.Equal(originalData, decryptedData) {
			t.Error("Decrypted data does not match original")
		}

		// Verify hash
		decryptedHash := CalculateFileHash(decryptedData)
		if decryptedHash != hash {
			t.Errorf("Hash mismatch after decryption: expected %s, got %s", hash, decryptedHash)
		}

		t.Logf("✅ Complete workflow: %s file → encrypted with envelope (version=%d, type=%s) → decrypted successfully",
			FormatFileSize(int64(len(originalData))), version, keyType)
	})

	t.Run("Size String Parsing", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected int64
		}{
			{"1024", 1024},
			{"1KB", 1024},
			{"10MB", 10 * 1024 * 1024},
			{"2GB", 2 * 1024 * 1024 * 1024},
		}

		for _, tc := range testCases {
			t.Run(tc.input, func(t *testing.T) {
				result, err := ParseSizeString(tc.input)
				if err != nil {
					t.Fatalf("Failed to parse size string %s: %v", tc.input, err)
				}

				if result != tc.expected {
					t.Errorf("Size mismatch for %s: expected %d, got %d", tc.input, tc.expected, result)
				}

				formatted := FormatFileSize(result)
				t.Logf("✅ %s → %d bytes → %s", tc.input, result, formatted)
			})
		}
	})
}

// TestPhase1APerformance tests performance characteristics
func TestPhase1APerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	tempDir := t.TempDir()

	t.Run("Large File Generation", func(t *testing.T) {
		// Test 10MB file generation
		largeFile := filepath.Join(tempDir, "large-test.dat")
		size := int64(10 * 1024 * 1024) // 10MB

		hash, err := GenerateTestFileToPath(largeFile, size, PatternSequential)
		if err != nil {
			t.Fatalf("Failed to generate large file: %v", err)
		}

		// Verify file
		info, err := os.Stat(largeFile)
		if err != nil {
			t.Fatalf("Large file not found: %v", err)
		}

		if info.Size() != size {
			t.Errorf("Large file size mismatch: expected %d, got %d", size, info.Size())
		}

		t.Logf("✅ Generated %s file with hash %s", FormatFileSize(size), hash[:16]+"...")
	})

	t.Run("Encryption Performance", func(t *testing.T) {
		// Generate 1MB test data
		testData, err := GenerateTestFileContent(1024*1024, PatternRandom)
		if err != nil {
			t.Fatalf("Failed to generate test data: %v", err)
		}

		// Test key
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}

		// Encrypt
		encrypted, err := EncryptGCM(testData, key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt
		decrypted, err := DecryptGCM(encrypted, key)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if !bytes.Equal(testData, decrypted) {
			t.Error("Performance test: data corruption detected")
		}

		t.Logf("✅ Successfully encrypted/decrypted %s of random data", FormatFileSize(int64(len(testData))))
	})
}
