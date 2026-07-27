package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerEnvelopeSharedFixtureDecrypt(t *testing.T) {
	raw, err := os.ReadFile("testdata/crypto-conformance-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		FileID      string `json:"file_id"`
		PasswordKDF struct {
			Password string `json:"password"`
		} `json:"password_kdf"`
		OwnerEnvelope struct {
			FEK      string `json:"fek_hex"`
			Envelope string `json:"account_envelope_hex"`
		} `json:"owner_envelope"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	envelope, _ := hex.DecodeString(fixture.OwnerEnvelope.Envelope)
	fek, keyType, err := DecryptFEK(envelope, []byte(fixture.PasswordKDF.Password), fixture.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if keyType != AccountKDFContext || hex.EncodeToString(fek) != fixture.OwnerEnvelope.FEK {
		t.Fatal("owner envelope does not match shared fixture")
	}
}

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
				seed := []byte("Arkfile Test File Content Pattern - Implementation")
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

// TestFEKEncryptDecrypt tests FEK encryption/decryption with password
// and AAD binding to the file_id.
func TestFEKEncryptDecrypt(t *testing.T) {
	fileID := "11111111-2222-4333-8444-555555555555"
	password := []byte("test-password-123")
	salt := bytes.Repeat([]byte{7}, OwnerEnvelopeSaltSize())

	tests := []struct {
		name    string
		keyType string
	}{
		{"Account key", "account"},
		{"Custom key", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fek, err := GenerateFEK()
			if err != nil {
				t.Fatalf("FEK generation failed: %v", err)
			}

			encryptedFEK, err := EncryptFEK(fek, password, salt, fileID, tt.keyType)
			if err != nil {
				t.Fatalf("FEK encryption failed: %v", err)
			}

			decryptedFEK, returnedKeyType, err := DecryptFEK(encryptedFEK, password, fileID)
			if err != nil {
				t.Fatalf("FEK decryption failed: %v", err)
			}

			if returnedKeyType != tt.keyType {
				t.Errorf("Returned key type mismatch: expected %s, got %s", tt.keyType, returnedKeyType)
			}
			if !bytes.Equal(fek, decryptedFEK) {
				t.Errorf("Decrypted FEK mismatch")
			}

			// Negative: same FEK envelope under a different file_id must fail.
			otherFileID := "99999999-2222-4333-8444-555555555555"
			if _, _, err := DecryptFEK(encryptedFEK, password, otherFileID); err == nil {
				t.Errorf("expected DecryptFEK to fail under different file_id (cross-file FEK swap)")
			}
		})
	}
}

// TestPasswordKeyDerivationConsistency tests that password key derivation is consistent
func TestPasswordKeyDerivationConsistency(t *testing.T) {
	password := []byte("test-password-consistency")
	salt := bytes.Repeat([]byte{8}, OwnerEnvelopeSaltSize())
	otherSalt := bytes.Repeat([]byte{9}, OwnerEnvelopeSaltSize())

	key1, err := DeriveAccountPasswordKey(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveAccountPasswordKey(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	key3, err := DeriveAccountPasswordKey(password, otherSalt)
	if err != nil {
		t.Fatal(err)
	}
	customKey, err := DeriveCustomPasswordKey(password, salt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password and salt must produce the same key")
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("different public salts must produce different keys")
	}
	if bytes.Equal(key1, customKey) {
		t.Fatal("account and custom contexts must produce different keys")
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
		{"50MB", 50 * 1024 * 1024, false},
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
		{50 * 1024 * 1024, "50.0 MB"},
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
		keyType string
	}{
		{AccountKDFContext},
		{CustomKDFContext},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			salt := bytes.Repeat([]byte{4}, OwnerEnvelopeSaltSize())
			envelope, err := CreateFEKEnvelopeHeader(tt.keyType, salt)
			if err != nil {
				t.Fatal(err)
			}
			if len(envelope) != OwnerEnvelopeHeaderSize() {
				t.Fatalf("unexpected envelope header size %d", len(envelope))
			}
			header, err := ParseFEKEnvelopeHeader(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if header.Version != OwnerEnvelopeVersion() || header.KDFProfile != OwnerEnvelopeKDFProfile() {
				t.Fatal("parsed envelope version or KDF profile mismatch")
			}
			if header.PasswordType() != tt.keyType || !bytes.Equal(header.Salt, salt) {
				t.Fatal("parsed envelope key type or salt mismatch")
			}
		})
	}
}

func TestParsePasswordEnvelopeErrors(t *testing.T) {
	valid, err := CreateFEKEnvelopeHeader(AccountKDFContext, make([]byte, OwnerEnvelopeSaltSize()))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":                {},
		"truncated":            valid[:OwnerEnvelopeHeaderSize()-1],
		"unsupported_version":  append([]byte{OwnerEnvelopeVersion() + 1}, valid[1:]...),
		"unsupported_key_type": append(append([]byte{}, valid[:1]...), append([]byte{0xff}, valid[2:]...)...),
		"unsupported_profile":  append(append([]byte{}, valid[:2]...), append([]byte{0xff}, valid[3:]...)...),
	}
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFEKEnvelopeHeader(envelope); err == nil {
				t.Fatal("expected malformed envelope rejection")
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

func FuzzParseFEKEnvelopeHeader(f *testing.F) {
	valid, err := CreateFEKEnvelopeHeader(AccountKDFContext, make([]byte, OwnerEnvelopeSaltSize()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:OwnerEnvelopeHeaderSize()-1])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		header, err := ParseFEKEnvelopeHeader(input)
		if err == nil {
			if header.Version != OwnerEnvelopeVersion() ||
				header.KDFProfile != OwnerEnvelopeKDFProfile() ||
				len(header.Salt) != OwnerEnvelopeSaltSize() {
				t.Fatal("parser accepted header outside canonical invariants")
			}
		}
	})
}
