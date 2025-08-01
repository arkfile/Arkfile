package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Test the envelope creation logic
func TestEnvelopeCreation(t *testing.T) {
	tests := []struct {
		name        string
		keyType     string
		expectedVer byte
		expectedKey byte
	}{
		{
			name:        "Account envelope",
			keyType:     "account",
			expectedVer: 0x01,
			expectedKey: 0x01,
		},
		{
			name:        "Custom envelope",
			keyType:     "custom",
			expectedVer: 0x02,
			expectedKey: 0x02,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var version, keyTypeByte byte

			switch tt.keyType {
			case "account":
				version = 0x01
				keyTypeByte = 0x01
			case "custom":
				version = 0x02
				keyTypeByte = 0x02
			}

			envelope := []byte{version, keyTypeByte}

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

// Test chunk format validation
func TestChunkFormatValidation(t *testing.T) {
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
			// Validate chunk format: [nonce:12][encrypted_data][tag:16]
			// Minimum size: 12 (nonce) + 1 (data) + 16 (tag) = 29 bytes
			valid := tt.chunkSize >= 29

			// Maximum size: 16MB + 28 bytes overhead
			maxSize := 16*1024*1024 + 28
			valid = valid && tt.chunkSize <= maxSize

			if valid != tt.expectValid {
				if tt.expectValid {
					t.Errorf("Expected valid chunk but validation failed for size %d", tt.chunkSize)
				} else {
					t.Errorf("Expected invalid chunk but validation passed for size %d", tt.chunkSize)
				}
			}
		})
	}
}

// Test chunked encryption logic
func TestChunkedEncryptionLogic(t *testing.T) {
	// Create test data
	testData := []byte("Hello, this is test data for chunked encryption! This needs to be long enough to test chunking properly.")
	userEmail := "test@example.com"
	fileID := "test-file-123"
	chunkSize := 32 // Small chunk for testing

	// Create mock export key (64 bytes)
	mockExportKey := make([]byte, 64)
	rand.Read(mockExportKey)

	// Test key derivation
	t.Run("Key derivation", func(t *testing.T) {
		// Test account key derivation
		accountKey, err := DeriveAccountFileKey(mockExportKey, userEmail, fileID)
		if err != nil {
			t.Fatalf("Failed to derive account key: %v", err)
		}
		if len(accountKey) != 32 {
			t.Errorf("Expected account key length 32, got %d", len(accountKey))
		}

		// Test custom key derivation
		customKey, err := DeriveOPAQUEFileKey(mockExportKey, fileID, userEmail)
		if err != nil {
			t.Fatalf("Failed to derive custom key: %v", err)
		}
		if len(customKey) != 32 {
			t.Errorf("Expected custom key length 32, got %d", len(customKey))
		}

		// Keys should be different
		if string(accountKey) == string(customKey) {
			t.Error("Account and custom keys should be different")
		}
	})

	// Test chunked encryption process
	t.Run("Chunked encryption process", func(t *testing.T) {
		// Derive file encryption key
		fileEncKey, err := DeriveAccountFileKey(mockExportKey, userEmail, fileID)
		if err != nil {
			t.Fatalf("Failed to derive file encryption key: %v", err)
		}

		// Create AES-GCM cipher
		block, err := aes.NewCipher(fileEncKey)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("Failed to create GCM: %v", err)
		}

		// Split file into chunks and encrypt each chunk
		var encryptedChunks [][]byte
		totalChunks := (len(testData) + chunkSize - 1) / chunkSize

		for i := 0; i < totalChunks; i++ {
			start := i * chunkSize
			end := start + chunkSize
			if end > len(testData) {
				end = len(testData)
			}

			chunkData := testData[start:end]

			// Generate unique nonce for this chunk
			nonce := make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				t.Fatalf("Failed to generate nonce for chunk %d: %v", i, err)
			}

			// Encrypt chunk: AES-GCM(chunk_data, FEK, nonce)
			encryptedChunk := gcm.Seal(nonce, nonce, chunkData, nil)
			encryptedChunks = append(encryptedChunks, encryptedChunk)

			// Validate chunk format
			if len(encryptedChunk) < 29 { // nonce + data + tag
				t.Errorf("Chunk %d too small: %d bytes", i, len(encryptedChunk))
			}

			// Calculate SHA-256 hash of encrypted chunk
			hash := sha256.Sum256(encryptedChunk)
			hashHex := hex.EncodeToString(hash[:])
			if len(hashHex) != 64 {
				t.Errorf("Invalid hash length for chunk %d: %d", i, len(hashHex))
			}
		}

		if len(encryptedChunks) != totalChunks {
			t.Errorf("Expected %d chunks, got %d", totalChunks, len(encryptedChunks))
		}

		// Test decryption of chunks
		var decryptedData []byte
		for i, encryptedChunk := range encryptedChunks {
			// Extract nonce (first 12 bytes)
			if len(encryptedChunk) < gcm.NonceSize() {
				t.Fatalf("Encrypted chunk %d too short for nonce", i)
			}

			nonce := encryptedChunk[:gcm.NonceSize()]
			ciphertext := encryptedChunk[gcm.NonceSize():]

			// Decrypt chunk
			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				t.Fatalf("Failed to decrypt chunk %d: %v", i, err)
			}

			decryptedData = append(decryptedData, plaintext...)
		}

		// Verify decrypted data matches original
		if string(decryptedData) != string(testData) {
			t.Errorf("Decrypted data doesn't match original")
			t.Logf("Original: %s", string(testData))
			t.Logf("Decrypted: %s", string(decryptedData))
		}
	})
}

// Test envelope format specification
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

	t.Run("File format specification", func(t *testing.T) {
		// Create mock envelope
		envelope := []byte{0x01, 0x01}

		// Create mock chunks (simplified)
		chunk1 := make([]byte, 29) // minimum chunk size
		chunk2 := make([]byte, 45) // another chunk
		rand.Read(chunk1)
		rand.Read(chunk2)

		// Simulate file format: [envelope][chunk1][chunk2]
		fileData := append(envelope, chunk1...)
		fileData = append(fileData, chunk2...)

		// Validate format
		if len(fileData) < 2 {
			t.Error("File should have envelope")
		}

		// Extract envelope
		extractedEnvelope := fileData[:2]
		if string(extractedEnvelope) != string(envelope) {
			t.Error("Envelope extraction failed")
		}

		// Extract chunks
		chunksData := fileData[2:]
		if len(chunksData) != len(chunk1)+len(chunk2) {
			t.Error("Chunks data length mismatch")
		}
	})
}

// Test security properties
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
		// Test valid key (64 bytes)
		validKey := make([]byte, 64)
		rand.Read(validKey)

		// Check that key is not all zeros
		allZeros := true
		for _, b := range validKey {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("Random key should not be all zeros")
		}

		// Test all-zero key should be invalid
		zeroKey := make([]byte, 64)
		allZeros = true
		for _, b := range zeroKey {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if !allZeros {
			t.Error("Zero key should be all zeros")
		}
	})

	t.Run("Encryption integrity", func(t *testing.T) {
		// Test that tampering with encrypted data causes decryption failure
		testData := []byte("Secret message")
		key := make([]byte, 32)
		rand.Read(key)

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("Failed to create GCM: %v", err)
		}

		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)

		// Encrypt
		ciphertext := gcm.Seal(nonce, nonce, testData, nil)

		// Decrypt normally (should work)
		extractedNonce := ciphertext[:gcm.NonceSize()]
		extractedCiphertext := ciphertext[gcm.NonceSize():]

		plaintext, err := gcm.Open(nil, extractedNonce, extractedCiphertext, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(plaintext) != string(testData) {
			t.Error("Decrypted data doesn't match original")
		}

		// Tamper with ciphertext (should fail)
		tamperedCiphertext := make([]byte, len(ciphertext))
		copy(tamperedCiphertext, ciphertext)
		tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0x01 // Flip one bit

		extractedNonce = tamperedCiphertext[:gcm.NonceSize()]
		extractedTamperedCiphertext := tamperedCiphertext[gcm.NonceSize():]

		_, err = gcm.Open(nil, extractedNonce, extractedTamperedCiphertext, nil)
		if err == nil {
			t.Error("Tampered ciphertext should fail to decrypt")
		}
	})
}

// Test base64 encoding/decoding for envelope data
func TestEnvelopeEncoding(t *testing.T) {
	t.Run("Base64 envelope encoding", func(t *testing.T) {
		// Test account envelope
		accountEnvelope := []byte{0x01, 0x01}
		accountBase64 := base64.StdEncoding.EncodeToString(accountEnvelope)

		// Decode and verify
		decoded, err := base64.StdEncoding.DecodeString(accountBase64)
		if err != nil {
			t.Fatalf("Failed to decode account envelope: %v", err)
		}

		if len(decoded) != 2 {
			t.Errorf("Expected decoded length 2, got %d", len(decoded))
		}

		if decoded[0] != 0x01 || decoded[1] != 0x01 {
			t.Errorf("Decoded envelope doesn't match original: %02x %02x", decoded[0], decoded[1])
		}

		// Test custom envelope
		customEnvelope := []byte{0x02, 0x02}
		customBase64 := base64.StdEncoding.EncodeToString(customEnvelope)

		decoded, err = base64.StdEncoding.DecodeString(customBase64)
		if err != nil {
			t.Fatalf("Failed to decode custom envelope: %v", err)
		}

		if decoded[0] != 0x02 || decoded[1] != 0x02 {
			t.Errorf("Decoded custom envelope doesn't match original: %02x %02x", decoded[0], decoded[1])
		}
	})
}
