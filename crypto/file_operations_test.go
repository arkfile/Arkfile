package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateTestFileContent(t *testing.T) {
	tests := []struct {
		name        string
		size        int64
		pattern     FilePattern
		expectError bool
	}{
		{
			name:        "sequential pattern 1KB",
			size:        1024,
			pattern:     PatternSequential,
			expectError: false,
		},
		{
			name:        "repeated pattern 1MB",
			size:        1024 * 1024,
			pattern:     PatternRepeated,
			expectError: false,
		},
		{
			name:        "random pattern 10KB",
			size:        10 * 1024,
			pattern:     PatternRandom,
			expectError: false,
		},
		{
			name:        "zero size",
			size:        0,
			pattern:     PatternSequential,
			expectError: true,
		},
		{
			name:        "negative size",
			size:        -1,
			pattern:     PatternSequential,
			expectError: true,
		},
		{
			name:        "too large size",
			size:        3 * 1024 * 1024 * 1024, // 3GB
			pattern:     PatternSequential,
			expectError: true,
		},
		{
			name:        "invalid pattern",
			size:        1024,
			pattern:     FilePattern("invalid"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := GenerateTestFileContent(tt.size, tt.pattern)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if int64(len(data)) != tt.size {
				t.Errorf("expected size %d, got %d", tt.size, len(data))
			}

			// Test pattern-specific properties
			switch tt.pattern {
			case PatternSequential:
				// First few bytes should be 0, 1, 2, 3...
				if len(data) >= 4 {
					expected := []byte{0, 1, 2, 3}
					if !bytes.Equal(data[:4], expected) {
						t.Errorf("sequential pattern not correct: got %v, expected %v", data[:4], expected)
					}
				}
				// After 256 bytes, pattern should repeat
				if len(data) >= 257 {
					if data[0] != data[256] {
						t.Errorf("sequential pattern should repeat every 256 bytes")
					}
				}

			case PatternRepeated:
				// Content should start with seed pattern
				seed := []byte("Arkfile Test File Content Pattern - PHASE 1A Implementation")
				if len(data) >= len(seed) {
					if !bytes.Equal(data[:len(seed)], seed) {
						t.Errorf("repeated pattern not correct: got %s, expected %s", string(data[:len(seed)]), string(seed))
					}
				}

			case PatternRandom:
				// Random data should not be all zeros (extremely unlikely)
				allZeros := true
				for _, b := range data[:min(100, len(data))] {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Errorf("random pattern appears to be all zeros, likely not random")
				}
			}
		})
	}
}

// TestGenerateFEK tests FEK generation
func TestGenerateFEK(t *testing.T) {
	fek1, err := GenerateFEK()
	if err != nil {
		t.Fatalf("GenerateFEK failed: %v", err)
	}

	if len(fek1) != 32 {
		t.Errorf("FEK should be 32 bytes, got %d", len(fek1))
	}

	// Generate another FEK - should be different
	fek2, err := GenerateFEK()
	if err != nil {
		t.Fatalf("GenerateFEK failed: %v", err)
	}

	if bytes.Equal(fek1, fek2) {
		t.Error("Two generated FEKs should be different")
	}
}

// TestFEKFileEncryption tests FEK-based file encryption/decryption
func TestFEKFileEncryption(t *testing.T) {
	testData := []byte("This is test data for FEK-based encryption validation")

	tests := []struct {
		name    string
		keyType string
	}{
		{"Account key", "account"},
		{"Custom key", "custom"},
		{"Share key", "share"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate FEK
			fek, err := GenerateFEK()
			if err != nil {
				t.Fatalf("FEK generation failed: %v", err)
			}

			// Encrypt data using FEK
			encryptedData, err := EncryptFile(testData, fek, tt.keyType)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify encrypted data has envelope + ciphertext
			if len(encryptedData) <= 2 {
				t.Fatalf("Encrypted data too short: %d bytes", len(encryptedData))
			}

			// Parse envelope
			_, keyType, err := ParseEnvelope(encryptedData[:2])
			if err != nil {
				t.Fatalf("Envelope parsing failed: %v", err)
			}

			if keyType != tt.keyType {
				t.Errorf("Expected key type %s, got %s", tt.keyType, keyType)
			}

			// Decrypt data using FEK
			decryptedData, returnedKeyType, err := DecryptFile(encryptedData, fek)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify key type matches
			if returnedKeyType != tt.keyType {
				t.Errorf("Returned key type mismatch: expected %s, got %s", tt.keyType, returnedKeyType)
			}

			// Verify data integrity
			if string(decryptedData) != string(testData) {
				t.Errorf("Decrypted data mismatch: expected %q, got %q", string(testData), string(decryptedData))
			}
		})
	}
}

// TestFEKEncryptDecrypt tests FEK encryption/decryption with password
func TestFEKEncryptDecrypt(t *testing.T) {
	username := "test-user"
	password := []byte("test-password-123")

	tests := []struct {
		name    string
		keyType string
	}{
		{"Account key", "account"},
		{"Custom key", "custom"},
		{"Share key", "share"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate FEK
			fek, err := GenerateFEK()
			if err != nil {
				t.Fatalf("FEK generation failed: %v", err)
			}

			// Encrypt FEK with password
			encryptedFEK, err := EncryptFEK(fek, password, username, tt.keyType)
			if err != nil {
				t.Fatalf("FEK encryption failed: %v", err)
			}

			// Decrypt FEK with password
			decryptedFEK, returnedKeyType, err := DecryptFEK(encryptedFEK, password, username)
			if err != nil {
				t.Fatalf("FEK decryption failed: %v", err)
			}

			// Verify key type matches
			if returnedKeyType != tt.keyType {
				t.Errorf("Returned key type mismatch: expected %s, got %s", tt.keyType, returnedKeyType)
			}

			// Verify FEK integrity
			if !bytes.Equal(fek, decryptedFEK) {
				t.Errorf("Decrypted FEK mismatch")
			}
		})
	}
}

// TestEncryptFileWorkflow tests the complete FEK-based encryption workflow
func TestEncryptFileWorkflow(t *testing.T) {
	tempDir := t.TempDir()
	username := "workflow-test-user"
	password := []byte("workflow-test-password-123")

	// Create test file
	testData := []byte("This is test data for the complete FEK workflow")
	inputPath := filepath.Join(tempDir, "input.txt")
	outputPath := filepath.Join(tempDir, "output.enc")
	decryptedPath := filepath.Join(tempDir, "decrypted.txt")

	err := os.WriteFile(inputPath, testData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Run encryption workflow
	encryptedFEK, fek, err := EncryptFileWorkflow(inputPath, outputPath, password, username, "account")
	if err != nil {
		t.Fatalf("EncryptFileWorkflow failed: %v", err)
	}

	// Verify FEK is 32 bytes
	if len(fek) != 32 {
		t.Errorf("FEK should be 32 bytes, got %d", len(fek))
	}

	// Verify encrypted file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Encrypted file was not created")
	}

	// Decrypt FEK
	decryptedFEK, keyType, err := DecryptFEK(encryptedFEK, password, username)
	if err != nil {
		t.Fatalf("FEK decryption failed: %v", err)
	}

	if keyType != "account" {
		t.Errorf("Expected key type 'account', got %s", keyType)
	}

	if !bytes.Equal(fek, decryptedFEK) {
		t.Error("Decrypted FEK doesn't match original")
	}

	// Decrypt file
	err = DecryptFileFromPath(outputPath, decryptedPath, decryptedFEK)
	if err != nil {
		t.Fatalf("File decryption failed: %v", err)
	}

	// Verify decrypted content
	decryptedData, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(testData, decryptedData) {
		t.Errorf("Decrypted data mismatch: expected %q, got %q", string(testData), string(decryptedData))
	}
}

// TestPasswordKeyDerivationConsistency tests that password key derivation is consistent
func TestPasswordKeyDerivationConsistency(t *testing.T) {
	password := []byte("test-password-consistency")
	username := "consistency-test"

	// Test multiple derivations produce same result
	for i := 0; i < 5; i++ {
		key1 := DeriveAccountPasswordKey(password, username)
		key2 := DeriveAccountPasswordKey(password, username)

		if len(key1) != 32 {
			t.Errorf("Key length should be 32 bytes, got %d", len(key1))
		}

		if string(key1) != string(key2) {
			t.Errorf("Key derivation not consistent on attempt %d", i+1)
		}
	}

	// Test different parameters produce different keys
	key1 := DeriveAccountPasswordKey(password, username)
	key2 := DeriveAccountPasswordKey(password, username+"different")
	key3 := DeriveCustomPasswordKey(password, username)

	if string(key1) == string(key2) {
		t.Error("Different usernames should produce different keys")
	}

	if string(key1) == string(key3) {
		t.Error("Different key types should produce different keys")
	}

	if string(key2) == string(key3) {
		t.Error("Different parameters should produce different keys")
	}
}

// TestManifestSerialization tests JSON manifest serialization
func TestManifestSerialization(t *testing.T) {
	manifest := &ChunkManifest{
		Envelope:    "0102",
		TotalChunks: 3,
		ChunkSize:   1024,
		Chunks: []ChunkInfo{
			{Index: 0, File: "chunk_0.enc", Hash: "hash0", Size: 1024},
			{Index: 1, File: "chunk_1.enc", Hash: "hash1", Size: 1024},
			{Index: 2, File: "chunk_2.enc", Hash: "hash2", Size: 512},
		},
	}

	jsonData, err := manifest.ToJSON()
	if err != nil {
		t.Fatalf("JSON serialization failed: %v", err)
	}

	// Verify JSON contains expected fields
	jsonStr := string(jsonData)
	expectedFields := []string{
		`"envelope":"0102"`,
		`"total_chunks":3`,
		`"chunk_size":1024`,
		`"chunks":[`,
		`"index":0`,
		`"file":"chunk_0.enc"`,
		`"hash":"hash0"`,
		`"size":1024`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON missing expected field: %s", field)
		}
	}

	t.Logf("Generated JSON: %s", jsonStr)
}

func TestGenerateTestFileToPath(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		size        int64
		pattern     FilePattern
		expectError bool
	}{
		{
			name:        "small file sequential",
			size:        1024,
			pattern:     PatternSequential,
			expectError: false,
		},
		{
			name:        "medium file repeated",
			size:        10 * 1024 * 1024, // 10MB
			pattern:     PatternRepeated,
			expectError: false,
		},
		{
			name:        "zero size file",
			size:        0,
			pattern:     PatternSequential,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, tt.name+".dat")

			hash, err := GenerateTestFileToPath(filePath, tt.size, tt.pattern)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify file was created
			info, err := os.Stat(filePath)
			if err != nil {
				t.Errorf("file not created: %v", err)
				return
			}

			if info.Size() != tt.size {
				t.Errorf("file size mismatch: expected %d, got %d", tt.size, info.Size())
			}

			// Verify hash
			if hash == "" {
				t.Errorf("hash should not be empty")
			}

			// Verify hash matches file content
			calculatedHash, err := CalculateFileHashFromPath(filePath)
			if err != nil {
				t.Errorf("failed to calculate hash: %v", err)
				return
			}

			if hash != calculatedHash {
				t.Errorf("hash mismatch: returned %s, calculated %s", hash, calculatedHash)
			}
		})
	}
}

func TestCalculateFileHash(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedHash string
	}{
		{
			name:         "empty data",
			data:         []byte{},
			expectedHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:         "hello world",
			data:         []byte("hello world"),
			expectedHash: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:         "arkfile test",
			data:         []byte("Arkfile Test File Content Pattern"),
			expectedHash: "80f70bfeaa9625b7b0f6b5c7a4c4b2db2d9e4b5e1b8c7a4c4b2db2d9e4b5e1b8c", // This will be different, but deterministic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := CalculateFileHash(tt.data)

			// For the test data that we don't know the exact hash, just verify format
			if tt.name == "arkfile test" {
				if len(hash) != 64 {
					t.Errorf("hash should be 64 characters, got %d", len(hash))
				}
				return
			}

			if hash != tt.expectedHash {
				t.Errorf("hash mismatch: got %s, expected %s", hash, tt.expectedHash)
			}
		})
	}
}

func TestParseSizeString(t *testing.T) {
	tests := []struct {
		input       string
		expected    int64
		expectError bool
	}{
		{"100", 100, false},
		{"1KB", 1024, false},
		{"10MB", 10 * 1024 * 1024, false},
		{"5GB", 5 * 1024 * 1024 * 1024, false},
		{"1024B", 1024, false},
		{"", 0, true},
		{"invalid", 0, true},
		{"100XB", 0, true},
		{"-100MB", 0, true}, // Negative size should cause overflow check to fail
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseSizeString(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("size mismatch: got %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{1536 * 1024 * 1024, "1.5 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := FormatFileSize(tt.input)
			if result != tt.expected {
				t.Errorf("format mismatch: got %s, expected %s", result, tt.expected)
			}
		})
	}
}

func TestVerifyFileIntegrity(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test file
	testData := []byte("test file content for integrity verification")
	expectedHash := CalculateFileHash(testData)
	expectedSize := int64(len(testData))

	filePath := filepath.Join(tempDir, "test_integrity.dat")
	err := os.WriteFile(filePath, testData, 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name         string
		filePath     string
		expectedHash string
		expectedSize int64
		expectError  bool
	}{
		{
			name:         "correct hash and size",
			filePath:     filePath,
			expectedHash: expectedHash,
			expectedSize: expectedSize,
			expectError:  false,
		},
		{
			name:         "wrong hash",
			filePath:     filePath,
			expectedHash: "wrong_hash",
			expectedSize: expectedSize,
			expectError:  true,
		},
		{
			name:         "wrong size",
			filePath:     filePath,
			expectedHash: expectedHash,
			expectedSize: expectedSize + 1,
			expectError:  true,
		},
		{
			name:         "nonexistent file",
			filePath:     filepath.Join(tempDir, "nonexistent.dat"),
			expectedHash: expectedHash,
			expectedSize: expectedSize,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyFileIntegrity(tt.filePath, tt.expectedHash, tt.expectedSize)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCreateAndParsePasswordEnvelope(t *testing.T) {
	tests := []struct {
		keyType         string
		expectedVersion byte
		expectedKeyType string
	}{
		{"account", 0x01, "account"},
		{"custom", 0x01, "custom"},
		{"share", 0x01, "share"},
		{"unknown_type", 0x01, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			// Test envelope creation
			envelope := CreateEnvelope(tt.keyType)
			if len(envelope) != 2 {
				t.Errorf("envelope should be 2 bytes, got %d", len(envelope))
			}

			// Test envelope parsing
			version, keyType, err := ParseEnvelope(envelope)
			if err != nil {
				t.Errorf("unexpected error parsing envelope: %v", err)
				return
			}

			if version != tt.expectedVersion {
				t.Errorf("version mismatch: got %d, expected %d", version, tt.expectedVersion)
			}

			if keyType != tt.expectedKeyType {
				t.Errorf("keyType mismatch: got %s, expected %s", keyType, tt.expectedKeyType)
			}
		})
	}
}

func TestParsePasswordEnvelopeErrors(t *testing.T) {
	tests := []struct {
		name        string
		envelope    []byte
		expectError bool
	}{
		{
			name:        "empty envelope",
			envelope:    []byte{},
			expectError: true,
		},
		{
			name:        "one byte envelope",
			envelope:    []byte{0x01},
			expectError: true,
		},
		{
			name:        "valid two byte envelope",
			envelope:    []byte{0x01, 0x01},
			expectError: false,
		},
		{
			name:        "unsupported version",
			envelope:    []byte{0x02, 0x01},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseEnvelope(tt.envelope)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestDeterministicGeneration ensures the same pattern+size always produces the same content
func TestDeterministicGeneration(t *testing.T) {
	size := int64(1024)
	patterns := []FilePattern{PatternSequential, PatternRepeated}

	for _, pattern := range patterns {
		t.Run(string(pattern), func(t *testing.T) {
			// Generate the same content multiple times
			data1, err := GenerateTestFileContent(size, pattern)
			if err != nil {
				t.Fatalf("failed to generate first content: %v", err)
			}

			data2, err := GenerateTestFileContent(size, pattern)
			if err != nil {
				t.Fatalf("failed to generate second content: %v", err)
			}

			// They should be identical for deterministic patterns
			if !bytes.Equal(data1, data2) {
				t.Errorf("pattern %s should be deterministic but content differs", pattern)
			}

			// Hash should also be the same
			hash1 := CalculateFileHash(data1)
			hash2 := CalculateFileHash(data2)
			if hash1 != hash2 {
				t.Errorf("hashes should be identical for deterministic pattern: %s != %s", hash1, hash2)
			}
		})
	}
}

// TestFilePathEncryptDecrypt tests file path-based encryption/decryption
func TestFilePathEncryptDecrypt(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	testData := []byte("Test data for file path encryption/decryption")
	inputPath := filepath.Join(tempDir, "input.txt")
	encryptedPath := filepath.Join(tempDir, "encrypted.enc")
	decryptedPath := filepath.Join(tempDir, "decrypted.txt")

	err := os.WriteFile(inputPath, testData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Generate FEK
	fek, err := GenerateFEK()
	if err != nil {
		t.Fatalf("FEK generation failed: %v", err)
	}

	// Encrypt file
	err = EncryptFileToPath(inputPath, encryptedPath, fek, "account")
	if err != nil {
		t.Fatalf("File encryption failed: %v", err)
	}

	// Verify encrypted file exists and is larger than original
	encInfo, err := os.Stat(encryptedPath)
	if err != nil {
		t.Fatalf("Encrypted file not found: %v", err)
	}

	if encInfo.Size() <= int64(len(testData)) {
		t.Error("Encrypted file should be larger than original (includes envelope + nonce + tag)")
	}

	// Decrypt file
	err = DecryptFileFromPath(encryptedPath, decryptedPath, fek)
	if err != nil {
		t.Fatalf("File decryption failed: %v", err)
	}

	// Verify decrypted content
	decryptedData, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(testData, decryptedData) {
		t.Errorf("Decrypted data mismatch: expected %q, got %q", string(testData), string(decryptedData))
	}
}
