// offline_decrypt_test.go - Tests for .arkbackup bundle parser and offline decryption.
//
// Bundles are self-describing. Every bundle must carry
// file_id, owner_username, encrypted_fek, encrypted_filename + nonce,
// encrypted_sha256sum + nonce, password_type, size_bytes, chunk_count,
// chunk_size_bytes.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkfile/Arkfile/crypto"
)

// createTestBundle creates a valid .arkbackup bundle file for testing.
func createTestBundle(t *testing.T, meta bundleMeta, blobData []byte) string {
	t.Helper()
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "test.arkbackup")

	f, err := os.Create(bundlePath)
	if err != nil {
		t.Fatalf("failed to create test bundle: %v", err)
	}
	defer f.Close()

	// Magic
	if _, err := f.Write([]byte("ARKB")); err != nil {
		t.Fatalf("failed to write magic: %v", err)
	}
	// Version
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 1)
	if _, err := f.Write(versionBytes); err != nil {
		t.Fatalf("failed to write version: %v", err)
	}
	// Header
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, uint32(len(metaJSON)))
	if _, err := f.Write(headerLenBytes); err != nil {
		t.Fatalf("failed to write header length: %v", err)
	}
	if _, err := f.Write(metaJSON); err != nil {
		t.Fatalf("failed to write metadata: %v", err)
	}
	// Blob
	if blobData != nil {
		if _, err := f.Write(blobData); err != nil {
			t.Fatalf("failed to write blob: %v", err)
		}
	}
	return bundlePath
}

// TestParseBundle_ValidBundle exercises the basic parse path with all the
// self-describing fields populated.
func TestParseBundle_ValidBundle(t *testing.T) {
	meta := bundleMeta{
		Version:            1,
		FileID:             testFileID,
		OwnerUsername:      testOwner,
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

	bundlePath := createTestBundle(t, meta, []byte("fake-encrypted-blob-data-for-testing"))

	parsed, blobOffset, err := parseBundle(bundlePath)
	if err != nil {
		t.Fatalf("parseBundle failed: %v", err)
	}

	if parsed.FileID != meta.FileID {
		t.Errorf("FileID mismatch: got %q, expected %q", parsed.FileID, meta.FileID)
	}
	if parsed.OwnerUsername != meta.OwnerUsername {
		t.Errorf("OwnerUsername mismatch: got %q, expected %q", parsed.OwnerUsername, meta.OwnerUsername)
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

	metaJSON, _ := json.Marshal(meta)
	expectedOffset := int64(10) + int64(len(metaJSON))
	if blobOffset != expectedOffset {
		t.Errorf("blobOffset mismatch: got %d, expected %d", blobOffset, expectedOffset)
	}
}

func TestParseBundle_InvalidMagic(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "bad-magic.arkbackup")
	f, _ := os.Create(bundlePath)
	f.Write([]byte("NOTB"))
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 1)
	f.Write(versionBytes)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, 2)
	f.Write(headerLenBytes)
	f.Write([]byte("{}"))
	f.Close()
	if _, _, err := parseBundle(bundlePath); err == nil {
		t.Fatal("parseBundle should fail for invalid magic bytes")
	}
}

func TestParseBundle_InvalidVersion(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "bad-version.arkbackup")
	f, _ := os.Create(bundlePath)
	f.Write([]byte("ARKB"))
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 99)
	f.Write(versionBytes)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, 2)
	f.Write(headerLenBytes)
	f.Write([]byte("{}"))
	f.Close()
	if _, _, err := parseBundle(bundlePath); err == nil {
		t.Fatal("parseBundle should fail for unsupported version")
	}
}

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
	if _, _, err := parseBundle(bundlePath); err == nil {
		t.Fatal("parseBundle should fail for invalid JSON")
	}
}

func TestParseBundle_TruncatedFile(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "truncated.arkbackup")
	f, _ := os.Create(bundlePath)
	f.Write([]byte("AR"))
	f.Close()
	if _, _, err := parseBundle(bundlePath); err == nil {
		t.Fatal("parseBundle should fail for truncated file")
	}
}

func TestParseBundle_NonexistentFile(t *testing.T) {
	if _, _, err := parseBundle("/tmp/nonexistent-arkbackup-12345.arkbackup"); err == nil {
		t.Fatal("parseBundle should fail for nonexistent file")
	}
}

func TestParseBundle_HeaderTooLarge(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "huge-header.arkbackup")
	f, _ := os.Create(bundlePath)
	f.Write([]byte("ARKB"))
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, 1)
	f.Write(versionBytes)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, 2*1024*1024)
	f.Write(headerLenBytes)
	f.Close()
	if _, _, err := parseBundle(bundlePath); err == nil {
		t.Fatal("parseBundle should fail for header > 1 MiB")
	}
}

// -- End-to-end bundle decrypt --
//
// Build a real encrypted .arkbackup with all AAD-bound
// ciphertext, then decrypt it back end-to-end. This is the disaster
// recovery path: a user with the bundle and their account password
// must be able to recover plaintext offline.

// TestOfflineArkbackupDecrypt_WithAAD_RoundTrip constructs a one-chunk
// bundle, parses it, unwraps the FEK and decrypts chunk 0.
func TestOfflineArkbackupDecrypt_WithAAD_RoundTrip(t *testing.T) {
	username := "bundle-test-user"
	password := []byte("BundleTestPassword2025!Secure")

	kek := crypto.DeriveAccountPasswordKey(password, username)
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	fileID := testFileID

	wrappedFEKB64, err := wrapFEK(fek, kek, "account", fileID)
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}

	originalPlaintext := []byte("Self-describing bundle disaster-recovery test plaintext")

	encryptedChunk, err := encryptChunk(originalPlaintext, fek, fileID, 0, 1)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	meta := bundleMeta{
		Version:         1,
		FileID:          fileID,
		OwnerUsername:   username,
		EncryptedFEK:    wrappedFEKB64,
		PasswordType:    "account",
		SizeBytes:       int64(len(encryptedChunk)),
		ChunkSizeBytes:  int64(crypto.PlaintextChunkSize()),
		ChunkCount:      1,
		EnvelopeVersion: 1,
	}

	bundlePath := createTestBundle(t, meta, encryptedChunk)

	// Parse the bundle back and decrypt.
	parsedMeta, blobOffset, err := parseBundle(bundlePath)
	if err != nil {
		t.Fatalf("parseBundle failed: %v", err)
	}
	if parsedMeta.FileID != fileID || parsedMeta.OwnerUsername != username {
		t.Fatalf("bundle metadata round-trip mismatch")
	}

	unwrappedFEK, keyType, err := unwrapFEK(parsedMeta.EncryptedFEK, kek, parsedMeta.FileID)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}
	if keyType != "account" {
		t.Errorf("expected key type 'account', got %q", keyType)
	}

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

	decrypted, err := decryptChunk(encBlob, unwrappedFEK, parsedMeta.FileID, 0, parsedMeta.ChunkCount)
	if err != nil {
		t.Fatalf("decryptChunk failed: %v", err)
	}
	if !bytes.Equal(originalPlaintext, decrypted) {
		t.Error("decrypted content does not match original")
	}
}

// TestOfflineArkbackupDecrypt_WrongFileID_Fails proves that a bundle
// whose JSON metadata claims a different file_id than the one the FEK /
// chunks were encrypted under cannot be decrypted.
// This catches an attacker who edits the bundle JSON header in transit.
func TestOfflineArkbackupDecrypt_WrongFileID_Fails(t *testing.T) {
	username := "bundle-wrong-fileid-user"
	password := []byte("BundleWrongFileIDPassword2025")

	kek := crypto.DeriveAccountPasswordKey(password, username)
	fek, _ := generateFEK()
	wrappedFEKB64, _ := wrapFEK(fek, kek, "account", testFileID)
	encryptedChunk, _ := encryptChunk([]byte("payload"), fek, testFileID, 0, 1)

	// Bundle metadata claims testFileID2 but FEK + chunk were encrypted
	// under testFileID. unwrapFEK must fail at the AEAD layer.
	tamperedMeta := bundleMeta{
		Version:         1,
		FileID:          testFileID2, // mismatched
		OwnerUsername:   username,
		EncryptedFEK:    wrappedFEKB64,
		PasswordType:    "account",
		SizeBytes:       int64(len(encryptedChunk)),
		ChunkSizeBytes:  int64(crypto.PlaintextChunkSize()),
		ChunkCount:      1,
		EnvelopeVersion: 1,
	}
	bundlePath := createTestBundle(t, tamperedMeta, encryptedChunk)

	parsedMeta, _, err := parseBundle(bundlePath)
	if err != nil {
		t.Fatalf("parseBundle failed: %v", err)
	}
	if _, _, err := unwrapFEK(parsedMeta.EncryptedFEK, kek, parsedMeta.FileID); err == nil {
		t.Fatal("unwrapFEK with mismatched bundle file_id must fail")
	}
}

// TestOfflineArkbackupDecrypt_WrongPassword_Fails verifies wrong-password
// path fails cleanly.
func TestOfflineArkbackupDecrypt_WrongPassword_Fails(t *testing.T) {
	username := "bundle-wrong-pw-user"
	correct := []byte("CorrectPassword2025!Secure")
	wrong := []byte("WrongPassword2025!Insecure")

	kek := crypto.DeriveAccountPasswordKey(correct, username)
	fek, _ := generateFEK()
	wrappedFEKB64, _ := wrapFEK(fek, kek, "account", testFileID)

	wrongKEK := crypto.DeriveAccountPasswordKey(wrong, username)
	if _, _, err := unwrapFEK(wrappedFEKB64, wrongKEK, testFileID); err == nil {
		t.Fatal("unwrapFEK with wrong password must fail")
	}
}

// TestDecryptBlobCommand_RejectsBundleMissingOwnerUsername verifies that
// the offline decrypt CLI refuses to operate on a bundle that lacks the
// required self-describing fields. Without this guard the
// decrypter would silently call BuildMetadataFieldAAD with an empty
// ownerUsername and produce confusing AEAD failures rather than a clean
// "bundle is too old" error.
func TestDecryptBlobCommand_RejectsBundleMissingOwnerUsername(t *testing.T) {
	username := "bundle-missing-owner-user"
	password := []byte("BundleMissingOwnerPassword2025")
	kek := crypto.DeriveAccountPasswordKey(password, username)

	fek, _ := generateFEK()
	wrappedFEKB64, _ := wrapFEK(fek, kek, "account", testFileID)
	encryptedChunk, _ := encryptChunk([]byte("payload"), fek, testFileID, 0, 1)

	// OwnerUsername deliberately omitted.
	staleMeta := bundleMeta{
		Version:         1,
		FileID:          testFileID,
		EncryptedFEK:    wrappedFEKB64,
		PasswordType:    "account",
		SizeBytes:       int64(len(encryptedChunk)),
		ChunkSizeBytes:  int64(crypto.PlaintextChunkSize()),
		ChunkCount:      1,
		EnvelopeVersion: 1,
	}
	bundlePath := createTestBundle(t, staleMeta, encryptedChunk)

	// Account-key-file path so the CLI doesn't try to read a password
	// during the test. Write a hex-encoded key file the CLI can ingest.
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "key.hex")
	if err := os.WriteFile(keyFile, []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"), 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	outputPath := filepath.Join(tempDir, "out.bin")

	err := handleDecryptBlobCommand([]string{
		"--bundle", bundlePath,
		"--username", username,
		"--output", outputPath,
		"--account-key-file", keyFile,
	})
	if err == nil {
		t.Fatal("handleDecryptBlobCommand must reject a bundle missing owner_username")
	}
}
