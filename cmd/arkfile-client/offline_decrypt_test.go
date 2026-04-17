package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/84adam/Arkfile/crypto"
)

// createTestBundle creates a valid .arkbackup bundle file for testing
func createTestBundle(t *testing.T, meta bundleMeta, blobData []byte) string {
	t.Helper()
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "test.arkbackup")

	f, err := os.Create(bundlePath)
	if err != nil {
		t.Fatalf("failed to create test bundle: %v", err)
	}
	defer f.Close()

	// Write magic "ARKB"
	if _, err := f.Write([]byte("ARKB")); err != nil {
		t.Fatalf("failed to write magic: %v", err)
	}

	// Write version (2 bytes, big-endian)
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 1)
	if _, err := f.Write(versionBytes); err != nil {
		t.Fatalf("failed to write version: %v", err)
	}

	// Serialize metadata JSON
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	// Write header length (4 bytes, big-endian)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, uint32(len(metaJSON)))
	if _, err := f.Write(headerLenBytes); err != nil {
		t.Fatalf("failed to write header length: %v", err)
	}

	// Write metadata JSON
	if _, err := f.Write(metaJSON); err != nil {
		t.Fatalf("failed to write metadata: %v", err)
	}

	// Write blob data (encrypted chunks)
	if blobData != nil {
		if _, err := f.Write(blobData); err != nil {
			t.Fatalf("failed to write blob: %v", err)
		}
	}

	return bundlePath
}

// TestParseBundle_ValidBundle tests parsing a well-formed .arkbackup bundle
func TestParseBundle_ValidBundle(t *testing.T) {
	meta := bundleMeta{
		Version:            1,
		FileID:             "test-file-id-abc123",
		EncryptedFEK:       "ZW5jcnlwdGVkLWZlaw==",
		PasswordType:       "account",
		SizeBytes:          1024,
		PaddedSize:         1056,
		EncryptedFilename:  "ZW5jcnlwdGVkLWZpbGVuYW1l",
		FilenameNonce:      "dGVzdG5vbmNl",
		EncryptedSHA256Sum: "ZW5jcnlwdGVkLXNoYTI1Ng==",
		SHA256SumNonce:     "c2hhbm9uY2U=",
		ChunkSizeBytes:     16777216,
		ChunkCount:         1,
		EnvelopeVersion:    1,
		CreatedAt:          "2025-01-01T00:00:00Z",
	}

	blobData := []byte("fake-encrypted-blob-data-for-testing")
	bundlePath := createTestBundle(t, meta, blobData)

	parsed, blobOffset, err := parseBundle(bundlePath)
	if err != nil {
		t.Fatalf("parseBundle failed: %v", err)
	}

	// Verify parsed metadata matches
	if parsed.FileID != meta.FileID {
		t.Errorf("FileID mismatch: got %q, expected %q", parsed.FileID, meta.FileID)
	}
	if parsed.PasswordType != meta.PasswordType {
		t.Errorf("PasswordType mismatch: got %q, expected %q", parsed.PasswordType, meta.PasswordType)
	}
	if parsed.SizeBytes != meta.SizeBytes {
		t.Errorf("SizeBytes mismatch: got %d, expected %d", parsed.SizeBytes, meta.SizeBytes)
	}
	if parsed.ChunkCount != meta.ChunkCount {
		t.Errorf("ChunkCount mismatch: got %d, expected %d", parsed.ChunkCount, meta.ChunkCount)
	}
	if parsed.EncryptedFEK != meta.EncryptedFEK {
		t.Errorf("EncryptedFEK mismatch: got %q, expected %q", parsed.EncryptedFEK, meta.EncryptedFEK)
	}
	if parsed.EnvelopeVersion != meta.EnvelopeVersion {
		t.Errorf("EnvelopeVersion mismatch: got %d, expected %d", parsed.EnvelopeVersion, meta.EnvelopeVersion)
	}

	// Verify blob offset
	metaJSON, _ := json.Marshal(meta)
	expectedOffset := int64(10) + int64(len(metaJSON)) // 4 magic + 2 version + 4 header_len + header
	if blobOffset != expectedOffset {
		t.Errorf("blobOffset mismatch: got %d, expected %d", blobOffset, expectedOffset)
	}
}

// TestParseBundle_InvalidMagic tests rejection of file with wrong magic bytes
func TestParseBundle_InvalidMagic(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "bad-magic.arkbackup")

	f, _ := os.Create(bundlePath)
	f.Write([]byte("NOTB")) // Wrong magic
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 1)
	f.Write(versionBytes)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, 2)
	f.Write(headerLenBytes)
	f.Write([]byte("{}"))
	f.Close()

	_, _, err := parseBundle(bundlePath)
	if err == nil {
		t.Fatal("parseBundle should fail for invalid magic bytes")
	}
}

// TestParseBundle_InvalidVersion tests rejection of unsupported version
func TestParseBundle_InvalidVersion(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "bad-version.arkbackup")

	f, _ := os.Create(bundlePath)
	f.Write([]byte("ARKB"))
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 99) // Unsupported version
	f.Write(versionBytes)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, 2)
	f.Write(headerLenBytes)
	f.Write([]byte("{}"))
	f.Close()

	_, _, err := parseBundle(bundlePath)
	if err == nil {
		t.Fatal("parseBundle should fail for unsupported version")
	}
}

// TestParseBundle_InvalidJSON tests rejection of malformed metadata JSON
func TestParseBundle_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "bad-json.arkbackup")

	badJSON := []byte("{not valid json")
	f, _ := os.Create(bundlePath)
	f.Write([]byte("ARKB"))
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 1)
	f.Write(versionBytes)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, uint32(len(badJSON)))
	f.Write(headerLenBytes)
	f.Write(badJSON)
	f.Close()

	_, _, err := parseBundle(bundlePath)
	if err == nil {
		t.Fatal("parseBundle should fail for invalid JSON")
	}
}

// TestParseBundle_TruncatedFile tests rejection of truncated bundle
func TestParseBundle_TruncatedFile(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "truncated.arkbackup")

	// Write only magic bytes (incomplete)
	f, _ := os.Create(bundlePath)
	f.Write([]byte("AR")) // Too short
	f.Close()

	_, _, err := parseBundle(bundlePath)
	if err == nil {
		t.Fatal("parseBundle should fail for truncated file")
	}
}

// TestParseBundle_NonexistentFile tests error for missing file
func TestParseBundle_NonexistentFile(t *testing.T) {
	_, _, err := parseBundle("/tmp/nonexistent-arkbackup-test-file-12345.arkbackup")
	if err == nil {
		t.Fatal("parseBundle should fail for nonexistent file")
	}
}

// -- Section B: End-to-end bundle decrypt tests --

// TestDecryptBundleBlob_Success constructs a real encrypted .arkbackup bundle,
// then decrypts it end-to-end to verify the disaster recovery path works.
func TestDecryptBundleBlob_Success(t *testing.T) {
	username := "bundle-test-user"
	password := []byte("BundleTestPassword2025!Secure")

	// Step 1: Derive account KEK (same as production)
	kek := crypto.DeriveAccountPasswordKey(password, username)

	// Step 2: Generate FEK and wrap it
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	wrappedFEKB64, err := wrapFEK(fek, kek, "account")
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}

	// Step 3: Encrypt plaintext data as a single chunk
	originalPlaintext := []byte("This is the secret file content for disaster recovery testing. It should survive round-trip.")

	encryptedChunk, err := encryptChunk(originalPlaintext, fek, 0, 0x01)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	// Step 4: Create bundle metadata
	meta := bundleMeta{
		Version:         1,
		FileID:          "test-file-bundle-decrypt",
		EncryptedFEK:    wrappedFEKB64,
		PasswordType:    "account",
		SizeBytes:       int64(len(originalPlaintext)),
		ChunkSizeBytes:  int64(crypto.PlaintextChunkSize()),
		ChunkCount:      1,
		EnvelopeVersion: 1,
	}

	// Step 5: Write the bundle
	bundlePath := createTestBundle(t, meta, encryptedChunk)

	// Step 6: Parse the bundle back
	parsedMeta, blobOffset, err := parseBundle(bundlePath)
	if err != nil {
		t.Fatalf("parseBundle failed: %v", err)
	}

	// Step 7: Unwrap FEK using the same account KEK
	unwrappedFEK, keyType, err := unwrapFEK(parsedMeta.EncryptedFEK, kek)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}
	if keyType != "account" {
		t.Errorf("expected key type 'account', got %q", keyType)
	}

	// Step 8: Read encrypted blob from file at blobOffset
	f, err := os.Open(bundlePath)
	if err != nil {
		t.Fatalf("failed to open bundle: %v", err)
	}
	defer f.Close()

	if _, err := f.Seek(blobOffset, 0); err != nil {
		t.Fatalf("failed to seek to blob: %v", err)
	}

	encBlob, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("failed to read blob: %v", err)
	}

	// Step 9: Decrypt chunk 0
	decrypted, err := decryptChunk(encBlob, unwrappedFEK, 0)
	if err != nil {
		t.Fatalf("decryptChunk failed: %v", err)
	}

	// Step 10: Verify plaintext matches
	if !bytes.Equal(originalPlaintext, decrypted) {
		t.Errorf("decrypted content does not match original: got %d bytes, expected %d bytes",
			len(decrypted), len(originalPlaintext))
	}
}

// TestDecryptBundleBlob_WrongKey verifies that decryption with wrong password fails
func TestDecryptBundleBlob_WrongKey(t *testing.T) {
	username := "bundle-wrong-key-user"
	correctPassword := []byte("CorrectPassword2025!Secure")
	wrongPassword := []byte("WrongPassword2025!Insecure")

	// Wrap FEK with correct password
	kek := crypto.DeriveAccountPasswordKey(correctPassword, username)
	fek, _ := generateFEK()
	wrappedFEKB64, _ := wrapFEK(fek, kek, "account")

	// Try to unwrap with wrong password
	wrongKEK := crypto.DeriveAccountPasswordKey(wrongPassword, username)
	_, _, err := unwrapFEK(wrappedFEKB64, wrongKEK)
	if err == nil {
		t.Fatal("unwrapFEK with wrong password should fail")
	}
}

// TestParseBundle_HeaderTooLarge tests rejection of oversized header
func TestParseBundle_HeaderTooLarge(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "huge-header.arkbackup")

	f, _ := os.Create(bundlePath)
	f.Write([]byte("ARKB"))
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 1)
	f.Write(versionBytes)
	// Header length > 1 MiB
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, 2*1024*1024) // 2 MiB
	f.Write(headerLenBytes)
	f.Close()

	_, _, err := parseBundle(bundlePath)
	if err == nil {
		t.Fatal("parseBundle should fail for header > 1 MiB")
	}
}
