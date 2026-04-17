package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
