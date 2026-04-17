package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/84adam/Arkfile/crypto"
)

// -- encryptChunk / decryptChunk tests --

// TestEncryptDecryptChunk_RoundTrip verifies chunk encrypt-then-decrypt produces original plaintext
func TestEncryptDecryptChunk_RoundTrip(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	plaintext := []byte("chunk data for round-trip test with reasonable length content")

	// Test chunk 0 (has envelope header)
	encrypted0, err := encryptChunk(plaintext, fek, 0, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk(index=0) failed: %v", err)
	}

	decrypted0, err := decryptChunk(encrypted0, fek, 0)
	if err != nil {
		t.Fatalf("decryptChunk(index=0) failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted0) {
		t.Error("chunk 0 round-trip: decrypted does not match original")
	}

	// Test chunk 1 (no envelope header)
	encrypted1, err := encryptChunk(plaintext, fek, 1, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk(index=1) failed: %v", err)
	}

	decrypted1, err := decryptChunk(encrypted1, fek, 1)
	if err != nil {
		t.Fatalf("decryptChunk(index=1) failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted1) {
		t.Error("chunk 1 round-trip: decrypted does not match original")
	}
}

// TestEncryptDecryptChunk_WrongFEKFails verifies decryption with wrong FEK fails
func TestEncryptDecryptChunk_WrongFEKFails(t *testing.T) {
	fek1, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK 1 failed: %v", err)
	}
	fek2, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK 2 failed: %v", err)
	}

	plaintext := []byte("secret chunk data")

	// Encrypt with fek1
	encrypted, err := encryptChunk(plaintext, fek1, 1, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	// Decrypt with fek2 must fail
	_, err = decryptChunk(encrypted, fek2, 1)
	if err == nil {
		t.Fatal("decryptChunk with wrong FEK should fail")
	}
}

// TestEncryptChunk_AccountKeyType verifies chunk 0 has the account key type byte in the envelope header
func TestEncryptChunk_AccountKeyType(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	encrypted, err := encryptChunk([]byte("test data"), fek, 0, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	// First 2 bytes should be envelope header: [version=0x01][keyType=0x01]
	if len(encrypted) < 2 {
		t.Fatal("encrypted chunk 0 too short for header")
	}
	if encrypted[0] != 0x01 {
		t.Errorf("envelope version should be 0x01, got 0x%02x", encrypted[0])
	}
	if encrypted[1] != 0x01 {
		t.Errorf("envelope key type should be 0x01 (account), got 0x%02x", encrypted[1])
	}
}

// TestEncryptChunk_CustomKeyType verifies chunk 0 has the custom key type byte in the envelope header
func TestEncryptChunk_CustomKeyType(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	encrypted, err := encryptChunk([]byte("test data"), fek, 0, 0x02)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	if len(encrypted) < 2 {
		t.Fatal("encrypted chunk 0 too short for header")
	}
	if encrypted[1] != 0x02 {
		t.Errorf("envelope key type should be 0x02 (custom), got 0x%02x", encrypted[1])
	}
}

// TestEncryptChunk_NonZeroIndexNoHeader verifies non-zero chunks do not have envelope header
func TestEncryptChunk_NonZeroIndexNoHeader(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	plaintext := []byte("chunk without header")

	encrypted0, err := encryptChunk(plaintext, fek, 0, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk(0) failed: %v", err)
	}

	encrypted1, err := encryptChunk(plaintext, fek, 1, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk(1) failed: %v", err)
	}

	headerSize := crypto.EnvelopeHeaderSize()
	// Chunk 0 should be headerSize bytes longer than chunk 1 (both encrypt same plaintext)
	expectedDiff := headerSize
	actualDiff := len(encrypted0) - len(encrypted1)
	if actualDiff != expectedDiff {
		t.Errorf("chunk 0 should be %d bytes longer than chunk 1 (header), got difference of %d", expectedDiff, actualDiff)
	}
}

// TestEncryptChunk_InvalidFEKSize verifies non-32-byte FEK is rejected
func TestEncryptChunk_InvalidFEKSize(t *testing.T) {
	_, err := encryptChunk([]byte("test"), make([]byte, 16), 0, 0x01)
	if err == nil {
		t.Error("encryptChunk should reject 16-byte FEK")
	}

	_, err = decryptChunk(make([]byte, 100), make([]byte, 16), 1)
	if err == nil {
		t.Error("decryptChunk should reject 16-byte FEK")
	}
}

// -- encryptMetadata / decryptMetadataField tests --

// TestEncryptDecryptMetadata_RoundTrip verifies metadata encrypt/decrypt round-trip
func TestEncryptDecryptMetadata_RoundTrip(t *testing.T) {
	accountKey, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	filename := "my-important-document.pdf"
	sha256hex := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"

	encFilenameB64, fnNonceB64, encSHA256B64, shaNonceB64, err := encryptMetadata(filename, sha256hex, accountKey)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	// Verify all outputs are non-empty
	if encFilenameB64 == "" || fnNonceB64 == "" || encSHA256B64 == "" || shaNonceB64 == "" {
		t.Error("all encrypted metadata fields should be non-empty")
	}

	// Decrypt filename
	decryptedFilename, err := decryptMetadataField(encFilenameB64, fnNonceB64, accountKey)
	if err != nil {
		t.Fatalf("decryptMetadataField (filename) failed: %v", err)
	}

	if decryptedFilename != filename {
		t.Errorf("filename mismatch: got %q, expected %q", decryptedFilename, filename)
	}

	// Decrypt SHA-256
	decryptedSHA256, err := decryptMetadataField(encSHA256B64, shaNonceB64, accountKey)
	if err != nil {
		t.Fatalf("decryptMetadataField (sha256) failed: %v", err)
	}

	if decryptedSHA256 != sha256hex {
		t.Errorf("sha256 mismatch: got %q, expected %q", decryptedSHA256, sha256hex)
	}
}

// TestDecryptMetadataField_WrongKey verifies decryption with wrong key fails
func TestDecryptMetadataField_WrongKey(t *testing.T) {
	key1, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey 1 failed: %v", err)
	}
	key2, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey 2 failed: %v", err)
	}

	encFilenameB64, fnNonceB64, _, _, err := encryptMetadata("secret-file.txt", "abcd1234", key1)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	// Decrypt with wrong key must fail
	_, err = decryptMetadataField(encFilenameB64, fnNonceB64, key2)
	if err == nil {
		t.Fatal("decryptMetadataField with wrong key should fail")
	}
}

// -- wrapFEK / unwrapFEK tests --

// TestWrapUnwrapFEK_AccountKey_RoundTrip verifies FEK wrapping with account key
func TestWrapUnwrapFEK_AccountKey_RoundTrip(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	kek := crypto.DeriveAccountPasswordKey([]byte("TestAccountPassword2025!"), "testuser")

	wrappedB64, err := wrapFEK(fek, kek, "account")
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}

	if wrappedB64 == "" {
		t.Fatal("wrapped FEK should not be empty")
	}

	unwrappedFEK, keyType, err := unwrapFEK(wrappedB64, kek)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}

	if keyType != "account" {
		t.Errorf("key type should be 'account', got %q", keyType)
	}

	if !bytes.Equal(fek, unwrappedFEK) {
		t.Error("unwrapped FEK does not match original")
	}
}

// TestWrapUnwrapFEK_CustomKey_RoundTrip verifies FEK wrapping with custom key
func TestWrapUnwrapFEK_CustomKey_RoundTrip(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	kek := crypto.DeriveCustomPasswordKey([]byte("TestCustomPassword2025!"), "testuser")

	wrappedB64, err := wrapFEK(fek, kek, "custom")
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}

	unwrappedFEK, keyType, err := unwrapFEK(wrappedB64, kek)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}

	if keyType != "custom" {
		t.Errorf("key type should be 'custom', got %q", keyType)
	}

	if !bytes.Equal(fek, unwrappedFEK) {
		t.Error("unwrapped FEK does not match original")
	}
}

// TestUnwrapFEK_WrongKEKFails verifies unwrapping with wrong KEK fails
func TestUnwrapFEK_WrongKEKFails(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	correctKEK := crypto.DeriveAccountPasswordKey([]byte("CorrectPassword2025!Key"), "testuser")
	wrongKEK := crypto.DeriveAccountPasswordKey([]byte("WrongPassword2025!Key!!"), "testuser")

	wrappedB64, err := wrapFEK(fek, correctKEK, "account")
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}

	_, _, err = unwrapFEK(wrappedB64, wrongKEK)
	if err == nil {
		t.Fatal("unwrapFEK with wrong KEK should fail")
	}
}

// TestWrapFEK_InvalidKeyType verifies invalid key type is rejected
func TestWrapFEK_InvalidKeyType(t *testing.T) {
	fek, _ := generateFEK()
	kek, _ := crypto.GenerateAESKey()

	_, err := wrapFEK(fek, kek, "invalid")
	if err == nil {
		t.Error("wrapFEK should reject invalid key type")
	}
}

// -- computeStreamingSHA256 tests --

// TestComputeStreamingSHA256 verifies streaming hash matches known SHA-256
func TestComputeStreamingSHA256(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "hash_test.dat")

	content := []byte("Known content for SHA-256 verification in arkfile-client")

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Compute expected hash
	expectedHash := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expectedHash[:])

	// Compute streaming hash
	actualHex, err := computeStreamingSHA256(filePath)
	if err != nil {
		t.Fatalf("computeStreamingSHA256 failed: %v", err)
	}

	if actualHex != expectedHex {
		t.Errorf("hash mismatch: got %s, expected %s", actualHex, expectedHex)
	}
}

// TestComputeStreamingSHA256_EmptyFile verifies hash of empty file
func TestComputeStreamingSHA256_EmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "empty.dat")

	if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	actualHex, err := computeStreamingSHA256(filePath)
	if err != nil {
		t.Fatalf("computeStreamingSHA256 failed: %v", err)
	}

	// SHA-256 of empty input
	expectedHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if actualHex != expectedHex {
		t.Errorf("empty file hash mismatch: got %s, expected %s", actualHex, expectedHex)
	}
}

// TestComputeStreamingSHA256_NonexistentFile verifies error for missing file
func TestComputeStreamingSHA256_NonexistentFile(t *testing.T) {
	_, err := computeStreamingSHA256("/tmp/nonexistent-file-for-arkfile-test-12345.dat")
	if err == nil {
		t.Error("computeStreamingSHA256 should fail for nonexistent file")
	}
}

// -- calculateTotalEncryptedSize tests --

// TestCalculateTotalEncryptedSize verifies size calculation for various plaintext sizes
func TestCalculateTotalEncryptedSize(t *testing.T) {
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())
	headerSize := int64(crypto.EnvelopeHeaderSize())

	tests := []struct {
		name          string
		plaintextSize int64
		expected      int64
	}{
		{
			name:          "zero bytes (empty file)",
			plaintextSize: 0,
			expected:      headerSize + overhead,
		},
		{
			name:          "one byte",
			plaintextSize: 1,
			expected:      headerSize + (1 + overhead),
		},
		{
			name:          "exactly one chunk",
			plaintextSize: chunkSize,
			expected:      headerSize + (chunkSize + overhead),
		},
		{
			name:          "one chunk + 1 byte",
			plaintextSize: chunkSize + 1,
			expected:      headerSize + (chunkSize + overhead) + (1 + overhead),
		},
		{
			name:          "two full chunks",
			plaintextSize: chunkSize * 2,
			expected:      headerSize + 2*(chunkSize+overhead),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := calculateTotalEncryptedSize(tt.plaintextSize)
			if actual != tt.expected {
				t.Errorf("plaintextSize=%d: got %d, expected %d (chunkSize=%d, overhead=%d, header=%d)",
					tt.plaintextSize, actual, tt.expected, chunkSize, overhead, headerSize)
			}
		})
	}
}

// -- generateFEK tests --

// TestGenerateFEK_LengthAndRandomness verifies FEK generation
func TestGenerateFEK_LengthAndRandomness(t *testing.T) {
	fek1, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	if len(fek1) != 32 {
		t.Errorf("FEK should be 32 bytes, got %d", len(fek1))
	}

	fek2, err := generateFEK()
	if err != nil {
		t.Fatalf("second generateFEK failed: %v", err)
	}

	if bytes.Equal(fek1, fek2) {
		t.Error("two generated FEKs should be different (random)")
	}
}

// -- isSeekableFile tests --

// TestIsSeekableFile_RegularFile verifies regular file is accepted
func TestIsSeekableFile_RegularFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "seekable.dat")

	if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	if err := isSeekableFile(filePath); err != nil {
		t.Errorf("regular file should be seekable: %v", err)
	}
}

// TestIsSeekableFile_NonexistentFile verifies error for missing file
func TestIsSeekableFile_NonexistentFile(t *testing.T) {
	if err := isSeekableFile("/tmp/nonexistent-arkfile-test-seekable-12345.dat"); err == nil {
		t.Error("nonexistent file should return error")
	}
}

// TestIsSeekableFile_Directory verifies directory is rejected
func TestIsSeekableFile_Directory(t *testing.T) {
	tempDir := t.TempDir()

	if err := isSeekableFile(tempDir); err == nil {
		t.Error("directory should not be considered a seekable file")
	}
}

// -- Multi-chunk encrypt/decrypt integration --

// TestMultiChunkEncryptDecrypt verifies encrypting and decrypting multiple chunks in sequence
// mirrors the actual upload/download flow
func TestMultiChunkEncryptDecrypt(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	chunks := [][]byte{
		[]byte("First chunk of file data with enough content to be realistic"),
		[]byte("Second chunk of data that continues the file content stream"),
		[]byte("Final partial chunk"),
	}

	var encryptedChunks [][]byte
	for i, chunk := range chunks {
		encrypted, err := encryptChunk(chunk, fek, i, 0x01)
		if err != nil {
			t.Fatalf("encryptChunk(%d) failed: %v", i, err)
		}
		encryptedChunks = append(encryptedChunks, encrypted)
	}

	// Decrypt all chunks and verify
	for i, encrypted := range encryptedChunks {
		decrypted, err := decryptChunk(encrypted, fek, i)
		if err != nil {
			t.Fatalf("decryptChunk(%d) failed: %v", i, err)
		}

		if !bytes.Equal(chunks[i], decrypted) {
			t.Errorf("chunk %d mismatch: got %q, expected %q", i, string(decrypted), string(chunks[i]))
		}
	}
}

// -- Full upload/download simulation --

// TestFullEncryptDecryptCycle simulates the complete client-side crypto flow:
// generate FEK -> wrap FEK -> encrypt chunks -> unwrap FEK -> decrypt chunks
func TestFullEncryptDecryptCycle(t *testing.T) {
	username := "cycle-test-user"
	password := []byte("CycleTestPassword2025!Secure")

	// Derive account KEK
	kek := crypto.DeriveAccountPasswordKey(password, username)

	// Generate FEK
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	// Wrap FEK with account KEK
	wrappedFEKB64, err := wrapFEK(fek, kek, "account")
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}

	// Encrypt some file data in chunks
	originalData := []byte("Complete file data that would be split across chunks in a real upload scenario")

	encrypted, err := encryptChunk(originalData, fek, 0, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	// Encrypt metadata
	filename := "test-cycle-file.dat"
	sha256hex := "deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef"

	encFnB64, fnNonceB64, encShaB64, shaNonceB64, err := encryptMetadata(filename, sha256hex, kek)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	// --- Simulate download side ---

	// Re-derive KEK from same password + username
	kek2 := crypto.DeriveAccountPasswordKey(password, username)

	// Unwrap FEK
	unwrappedFEK, keyType, err := unwrapFEK(wrappedFEKB64, kek2)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}

	if keyType != "account" {
		t.Errorf("expected key type 'account', got %q", keyType)
	}

	// Decrypt file data
	decrypted, err := decryptChunk(encrypted, unwrappedFEK, 0)
	if err != nil {
		t.Fatalf("decryptChunk failed: %v", err)
	}

	if !bytes.Equal(originalData, decrypted) {
		t.Error("decrypted file data does not match original")
	}

	// Decrypt metadata
	decryptedFilename, err := decryptMetadataField(encFnB64, fnNonceB64, kek2)
	if err != nil {
		t.Fatalf("decryptMetadataField (filename) failed: %v", err)
	}
	if decryptedFilename != filename {
		t.Errorf("filename mismatch: got %q, expected %q", decryptedFilename, filename)
	}

	decryptedSHA256, err := decryptMetadataField(encShaB64, shaNonceB64, kek2)
	if err != nil {
		t.Fatalf("decryptMetadataField (sha256) failed: %v", err)
	}
	if decryptedSHA256 != sha256hex {
		t.Errorf("sha256 mismatch: got %q, expected %q", decryptedSHA256, sha256hex)
	}
}
