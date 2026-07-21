// crypto_utils_test.go - Unit tests for arkfile-client crypto helpers.
//
// AAD wired into every chunk / FEK envelope / metadata field, so
// these tests exercise both the positive round-trip path and the negative
// tamper-detection path
//
//   - TestEncryptDecryptChunk_WithAAD_RoundTrip
//   - TestDecryptChunk_WrongChunkIndex_Fails
//   - TestDecryptChunk_WrongFileID_Fails
//   - TestDecryptChunk_WrongTotalChunks_Fails       (truncation)
//   - TestEncryptDecryptMetadata_WithAAD_RoundTrip
//   - TestDecryptMetadata_WrongFieldName_Fails
//   - TestDecryptMetadata_WrongOwnerUsername_Fails
//   - TestDecryptMetadata_WrongFileID_Fails
//   - TestWrapUnwrapFEK_AccountKey_RoundTrip
//   - TestWrapUnwrapFEK_CustomKey_RoundTrip
//   - TestUnwrapFEK_WrongFileID_Fails               (cross-file FEK swap)
//   - TestUnwrapFEK_WrongKEK_Fails

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkfile/Arkfile/crypto"
)

const (
	testFileID      = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	testFileID2     = "11111111-2222-3333-4444-555555555555"
	testOwner       = "alice"
	testOwner2      = "bob"
	testTotalChunks = int64(3)
)

// -- encryptChunk / decryptChunk: positive and negative AAD tests --

// TestEncryptDecryptChunk_WithAAD_RoundTrip verifies chunk encrypt-then-decrypt
// produces original plaintext when AAD inputs match.
func TestEncryptDecryptChunk_WithAAD_RoundTrip(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	plaintext := []byte("Chunk round-trip plaintext with reasonable length content")

	for _, idx := range []int64{0, 1, 2} {
		enc, err := encryptChunk(plaintext, fek, testFileID, idx, testTotalChunks)
		if err != nil {
			t.Fatalf("encryptChunk(idx=%d) failed: %v", idx, err)
		}
		dec, err := decryptChunk(enc, fek, testFileID, idx, testTotalChunks)
		if err != nil {
			t.Fatalf("decryptChunk(idx=%d) failed: %v", idx, err)
		}
		if !bytes.Equal(plaintext, dec) {
			t.Errorf("chunk %d round-trip mismatch", idx)
		}
	}
}

// TestDecryptChunk_WrongChunkIndex_Fails proves chunk reorder is detected at
// the AEAD layer.
func TestDecryptChunk_WrongChunkIndex_Fails(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	plaintext := []byte("chunk reorder negative test")

	// Encrypt as chunk 0; attempt to decrypt as chunk 1.
	enc, err := encryptChunk(plaintext, fek, testFileID, 0, testTotalChunks)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}
	if _, err := decryptChunk(enc, fek, testFileID, 1, testTotalChunks); err == nil {
		t.Fatal("decryptChunk with wrong chunk_index must fail (reorder detection)")
	}
}

// TestDecryptChunk_WrongFileID_Fails proves cross-file chunk substitution is
// detected at the AEAD layer.
func TestDecryptChunk_WrongFileID_Fails(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	plaintext := []byte("cross-file substitution negative test")

	enc, err := encryptChunk(plaintext, fek, testFileID, 0, testTotalChunks)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}
	if _, err := decryptChunk(enc, fek, testFileID2, 0, testTotalChunks); err == nil {
		t.Fatal("decryptChunk with wrong file_id must fail (substitution detection)")
	}
}

// TestDecryptChunk_WrongTotalChunks_Fails proves that the server cannot
// reduce chunk_count to truncate the file without remaining chunks failing
// decryption.
func TestDecryptChunk_WrongTotalChunks_Fails(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	plaintext := []byte("truncation negative test")

	// Encrypt with total_chunks=3; attempt to decrypt with total_chunks=2.
	enc, err := encryptChunk(plaintext, fek, testFileID, 2, 3)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}
	if _, err := decryptChunk(enc, fek, testFileID, 2, 2); err == nil {
		t.Fatal("decryptChunk with wrong total_chunks must fail (truncation detection)")
	}
}

// TestEncryptChunk_InvalidFEKSize verifies non-32-byte FEK is rejected.
func TestEncryptChunk_InvalidFEKSize(t *testing.T) {
	if _, err := encryptChunk([]byte("x"), make([]byte, 16), testFileID, 0, 1); err == nil {
		t.Error("encryptChunk should reject 16-byte FEK")
	}
	if _, err := decryptChunk(make([]byte, 100), make([]byte, 16), testFileID, 0, 1); err == nil {
		t.Error("decryptChunk should reject 16-byte FEK")
	}
}

// TestEncryptChunk_EmptyFileID verifies empty fileID is rejected.
func TestEncryptChunk_EmptyFileID(t *testing.T) {
	fek, _ := generateFEK()
	if _, err := encryptChunk([]byte("x"), fek, "", 0, 1); err == nil {
		t.Error("encryptChunk should reject empty fileID")
	}
}

// -- encryptMetadata / decryptMetadataField: positive and negative AAD tests --

// TestEncryptDecryptPasswordHint_RoundTrip verifies Account-Key encrypt
// of a custom-password hint under AADFieldPasswordHint, plus empty-omit.
func TestEncryptDecryptPasswordHint_RoundTrip(t *testing.T) {
	accountKey, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	encEmpty, nonceEmpty, err := encryptPasswordHint("", accountKey, testFileID, testOwner)
	if err != nil {
		t.Fatalf("encryptPasswordHint empty failed: %v", err)
	}
	if encEmpty != "" || nonceEmpty != "" {
		t.Fatalf("empty hint must omit both fields, got enc=%q nonce=%q", encEmpty, nonceEmpty)
	}

	hint := "my favorite color"
	encHint, hintNonce, err := encryptPasswordHint(hint, accountKey, testFileID, testOwner)
	if err != nil {
		t.Fatalf("encryptPasswordHint failed: %v", err)
	}
	if encHint == "" || hintNonce == "" {
		t.Fatal("non-empty hint must produce ciphertext and nonce")
	}

	got, err := decryptMetadataField(encHint, hintNonce, accountKey, testFileID, crypto.AADFieldPasswordHint, testOwner)
	if err != nil {
		t.Fatalf("decryptMetadataField (password hint) failed: %v", err)
	}
	if got != hint {
		t.Errorf("hint mismatch: got %q, expected %q", got, hint)
	}

	if _, err := decryptMetadataField(encHint, hintNonce, accountKey, testFileID, crypto.AADFieldFilename, testOwner); err == nil {
		t.Fatal("decrypting password hint under filename AAD label must fail")
	}
}

// TestEncryptDecryptMetadata_WithAAD_RoundTrip verifies metadata
// encrypt/decrypt round-trip when AAD inputs match.
func TestEncryptDecryptMetadata_WithAAD_RoundTrip(t *testing.T) {
	accountKey, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	filename := "secret-document.pdf"
	sha256hex := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"

	encFn, fnNonce, encSha, shaNonce, err := encryptMetadata(filename, sha256hex, accountKey, testFileID, testOwner)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	if encFn == "" || fnNonce == "" || encSha == "" || shaNonce == "" {
		t.Fatal("all encrypted metadata fields should be non-empty")
	}

	decFn, err := decryptMetadataField(encFn, fnNonce, accountKey, testFileID, crypto.AADFieldFilename, testOwner)
	if err != nil {
		t.Fatalf("decryptMetadataField (filename) failed: %v", err)
	}
	if decFn != filename {
		t.Errorf("filename mismatch: got %q, expected %q", decFn, filename)
	}

	decSha, err := decryptMetadataField(encSha, shaNonce, accountKey, testFileID, crypto.AADFieldSha256, testOwner)
	if err != nil {
		t.Fatalf("decryptMetadataField (sha256) failed: %v", err)
	}
	if decSha != sha256hex {
		t.Errorf("sha256 mismatch: got %q, expected %q", decSha, sha256hex)
	}
}

// TestDecryptMetadata_WrongFieldName_Fails proves that the encrypted
// filename ciphertext cannot be substituted into the sha256 slot or vice versa
func TestDecryptMetadata_WrongFieldName_Fails(t *testing.T) {
	accountKey, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	encFn, fnNonce, _, _, err := encryptMetadata("foo.bin", "abcd1234", accountKey, testFileID, testOwner)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	// Decrypt filename ciphertext under the sha256 field label: must fail.
	if _, err := decryptMetadataField(encFn, fnNonce, accountKey, testFileID, crypto.AADFieldSha256, testOwner); err == nil {
		t.Fatal("decryptMetadataField with wrong field name must fail")
	}
}

// TestDecryptMetadata_WrongOwnerUsername_Fails proves cross-user metadata
// row substitution is detected
func TestDecryptMetadata_WrongOwnerUsername_Fails(t *testing.T) {
	accountKey, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	encFn, fnNonce, _, _, err := encryptMetadata("foo.bin", "abcd1234", accountKey, testFileID, testOwner)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	if _, err := decryptMetadataField(encFn, fnNonce, accountKey, testFileID, crypto.AADFieldFilename, testOwner2); err == nil {
		t.Fatal("decryptMetadataField with wrong owner_username must fail")
	}
}

// TestDecryptMetadata_WrongFileID_Fails proves that moving a metadata row
// to a different file is detected.
func TestDecryptMetadata_WrongFileID_Fails(t *testing.T) {
	accountKey, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	encFn, fnNonce, _, _, err := encryptMetadata("foo.bin", "abcd1234", accountKey, testFileID, testOwner)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	if _, err := decryptMetadataField(encFn, fnNonce, accountKey, testFileID2, crypto.AADFieldFilename, testOwner); err == nil {
		t.Fatal("decryptMetadataField with wrong file_id must fail")
	}
}

// TestDecryptMetadata_WrongKey verifies plain wrong-key path also fails.
func TestDecryptMetadata_WrongKey(t *testing.T) {
	key1, _ := crypto.GenerateAESKey()
	key2, _ := crypto.GenerateAESKey()

	encFn, fnNonce, _, _, err := encryptMetadata("foo.bin", "abcd1234", key1, testFileID, testOwner)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}
	if _, err := decryptMetadataField(encFn, fnNonce, key2, testFileID, crypto.AADFieldFilename, testOwner); err == nil {
		t.Fatal("decryptMetadataField with wrong key must fail")
	}
}

// -- wrapFEK / unwrapFEK: positive and negative AAD tests --

// TestWrapUnwrapFEK_AccountKey_RoundTrip verifies FEK wrap+unwrap with
// account-key derived KEK and matching file_id.
func TestWrapUnwrapFEK_AccountKey_RoundTrip(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	kek := crypto.DeriveAccountPasswordKey([]byte("TestAccountPassword2025!"), "testuser")

	wrappedB64, err := wrapFEK(fek, kek, "account", testFileID)
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}
	if wrappedB64 == "" {
		t.Fatal("wrapped FEK should not be empty")
	}

	unwrapped, keyType, err := unwrapFEK(wrappedB64, kek, testFileID)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}
	if keyType != "account" {
		t.Errorf("key type should be 'account', got %q", keyType)
	}
	if !bytes.Equal(fek, unwrapped) {
		t.Error("unwrapped FEK does not match original")
	}
}

// TestWrapUnwrapFEK_CustomKey_RoundTrip verifies FEK wrap+unwrap with a
// custom-password derived KEK.
func TestWrapUnwrapFEK_CustomKey_RoundTrip(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	kek := crypto.DeriveCustomPasswordKey([]byte("TestCustomPassword2025!"), "testuser")

	wrappedB64, err := wrapFEK(fek, kek, "custom", testFileID)
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}
	unwrapped, keyType, err := unwrapFEK(wrappedB64, kek, testFileID)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}
	if keyType != "custom" {
		t.Errorf("key type should be 'custom', got %q", keyType)
	}
	if !bytes.Equal(fek, unwrapped) {
		t.Error("unwrapped FEK does not match original")
	}
}

// TestUnwrapFEK_WrongFileID_Fails proves that substituting one file's FEK
// envelope into another file's metadata row is detected at the AEAD layer
func TestUnwrapFEK_WrongFileID_Fails(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	kek := crypto.DeriveAccountPasswordKey([]byte("WrongFileIDPassword2025"), "testuser")

	wrappedB64, err := wrapFEK(fek, kek, "account", testFileID)
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}
	if _, _, err := unwrapFEK(wrappedB64, kek, testFileID2); err == nil {
		t.Fatal("unwrapFEK with wrong file_id must fail (cross-file FEK swap detection)")
	}
}

// TestUnwrapFEK_WrongKEK_Fails verifies plain wrong-KEK path fails.
func TestUnwrapFEK_WrongKEK_Fails(t *testing.T) {
	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}
	correctKEK := crypto.DeriveAccountPasswordKey([]byte("CorrectPassword2025!Key"), "testuser")
	wrongKEK := crypto.DeriveAccountPasswordKey([]byte("WrongPassword2025!Key!!"), "testuser")

	wrappedB64, err := wrapFEK(fek, correctKEK, "account", testFileID)
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}
	if _, _, err := unwrapFEK(wrappedB64, wrongKEK, testFileID); err == nil {
		t.Fatal("unwrapFEK with wrong KEK must fail")
	}
}

// TestWrapFEK_InvalidKeyType verifies invalid key type is rejected.
func TestWrapFEK_InvalidKeyType(t *testing.T) {
	fek, _ := generateFEK()
	kek, _ := crypto.GenerateAESKey()
	if _, err := wrapFEK(fek, kek, "invalid", testFileID); err == nil {
		t.Error("wrapFEK should reject invalid key type")
	}
}

// TestWrapFEK_EmptyFileID verifies empty fileID is rejected.
func TestWrapFEK_EmptyFileID(t *testing.T) {
	fek, _ := generateFEK()
	kek, _ := crypto.GenerateAESKey()
	if _, err := wrapFEK(fek, kek, "account", ""); err == nil {
		t.Error("wrapFEK should reject empty fileID")
	}
}

// -- computeStreamingSHA256 --

func TestComputeStreamingSHA256(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "hash_test.dat")
	content := []byte("Known content for SHA-256 verification in arkfile-client")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	expected := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expected[:])

	actual, err := computeStreamingSHA256(filePath)
	if err != nil {
		t.Fatalf("computeStreamingSHA256 failed: %v", err)
	}
	if actual != expectedHex {
		t.Errorf("hash mismatch: got %s, expected %s", actual, expectedHex)
	}
}

func TestComputeStreamingSHA256_EmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "empty.dat")
	if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}
	actual, err := computeStreamingSHA256(filePath)
	if err != nil {
		t.Fatalf("computeStreamingSHA256 failed: %v", err)
	}
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if actual != expected {
		t.Errorf("empty file hash mismatch: got %s, expected %s", actual, expected)
	}
}

func TestComputeStreamingSHA256_NonexistentFile(t *testing.T) {
	if _, err := computeStreamingSHA256("/tmp/nonexistent-arkfile-test-12345.dat"); err == nil {
		t.Error("computeStreamingSHA256 should fail for nonexistent file")
	}
}

// -- calculateTotalEncryptedSize --
//
// uniform chunk layout, no per-chunk envelope header.
// Every chunk = plaintext + GCM overhead (nonce + tag).
func TestCalculateTotalEncryptedSize(t *testing.T) {
	chunkSize := int64(crypto.PlaintextChunkSize())
	overhead := int64(crypto.AesGcmOverhead())

	tests := []struct {
		name          string
		plaintextSize int64
		expected      int64
	}{
		{
			name:          "zero bytes (empty file): single overhead-only chunk",
			plaintextSize: 0,
			expected:      overhead,
		},
		{
			name:          "one byte",
			plaintextSize: 1,
			expected:      1 + overhead,
		},
		{
			name:          "exactly one chunk",
			plaintextSize: chunkSize,
			expected:      chunkSize + overhead,
		},
		{
			name:          "one chunk + 1 byte",
			plaintextSize: chunkSize + 1,
			expected:      (chunkSize + overhead) + (1 + overhead),
		},
		{
			name:          "two full chunks",
			plaintextSize: chunkSize * 2,
			expected:      2 * (chunkSize + overhead),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := calculateTotalEncryptedSize(tt.plaintextSize)
			if actual != tt.expected {
				t.Errorf("plaintextSize=%d: got %d, expected %d (chunkSize=%d, overhead=%d)",
					tt.plaintextSize, actual, tt.expected, chunkSize, overhead)
			}
		})
	}
}

// -- generateFEK --

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

// -- isSeekableFile --

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

func TestIsSeekableFile_NonexistentFile(t *testing.T) {
	if err := isSeekableFile("/tmp/nonexistent-arkfile-seek-12345.dat"); err == nil {
		t.Error("nonexistent file should return error")
	}
}

func TestIsSeekableFile_Directory(t *testing.T) {
	tempDir := t.TempDir()
	if err := isSeekableFile(tempDir); err == nil {
		t.Error("directory should not be considered a seekable file")
	}
}

// -- Multi-chunk end-to-end --

// TestMultiChunkEncryptDecrypt mirrors the upload/download flow: encrypt
// three chunks then decrypt them in order. AAD is bound to the same
// (fileID, totalChunks) for every chunk.
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
	total := int64(len(chunks))

	var encChunks [][]byte
	for i, ch := range chunks {
		enc, err := encryptChunk(ch, fek, testFileID, int64(i), total)
		if err != nil {
			t.Fatalf("encryptChunk(%d) failed: %v", i, err)
		}
		encChunks = append(encChunks, enc)
	}

	for i, enc := range encChunks {
		dec, err := decryptChunk(enc, fek, testFileID, int64(i), total)
		if err != nil {
			t.Fatalf("decryptChunk(%d) failed: %v", i, err)
		}
		if !bytes.Equal(chunks[i], dec) {
			t.Errorf("chunk %d mismatch", i)
		}
	}
}

// -- Full upload/download simulation --

// TestFullEncryptDecryptCycle simulates: derive KEK -> wrap FEK -> encrypt
// chunk -> encrypt metadata -> unwrap FEK -> decrypt chunk -> decrypt
// metadata. All AAD-bound, all round-trips correctly.
func TestFullEncryptDecryptCycle(t *testing.T) {
	username := "cycle-test-user"
	password := []byte("CycleTestPassword2025!Secure")
	kek := crypto.DeriveAccountPasswordKey(password, username)

	fek, err := generateFEK()
	if err != nil {
		t.Fatalf("generateFEK failed: %v", err)
	}

	wrapped, err := wrapFEK(fek, kek, "account", testFileID)
	if err != nil {
		t.Fatalf("wrapFEK failed: %v", err)
	}

	original := []byte("Complete file data that would be split across chunks in a real upload scenario")
	enc, err := encryptChunk(original, fek, testFileID, 0, 1)
	if err != nil {
		t.Fatalf("encryptChunk failed: %v", err)
	}

	filename := "test-cycle-file.dat"
	sha256hex := "deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef"
	encFn, fnNonce, encSha, shaNonce, err := encryptMetadata(filename, sha256hex, kek, testFileID, username)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	// -- Simulated download side: re-derive everything from scratch. --

	kek2 := crypto.DeriveAccountPasswordKey(password, username)
	unwrapped, keyType, err := unwrapFEK(wrapped, kek2, testFileID)
	if err != nil {
		t.Fatalf("unwrapFEK failed: %v", err)
	}
	if keyType != "account" {
		t.Errorf("expected key type 'account', got %q", keyType)
	}

	dec, err := decryptChunk(enc, unwrapped, testFileID, 0, 1)
	if err != nil {
		t.Fatalf("decryptChunk failed: %v", err)
	}
	if !bytes.Equal(original, dec) {
		t.Error("decrypted file data does not match original")
	}

	decFn, err := decryptMetadataField(encFn, fnNonce, kek2, testFileID, crypto.AADFieldFilename, username)
	if err != nil {
		t.Fatalf("decryptMetadataField (filename) failed: %v", err)
	}
	if decFn != filename {
		t.Errorf("filename mismatch: got %q, expected %q", decFn, filename)
	}

	decSha, err := decryptMetadataField(encSha, shaNonce, kek2, testFileID, crypto.AADFieldSha256, username)
	if err != nil {
		t.Fatalf("decryptMetadataField (sha256) failed: %v", err)
	}
	if decSha != sha256hex {
		t.Errorf("sha256 mismatch: got %q, expected %q", decSha, sha256hex)
	}
}

// -- isFileIDConflict --
//
// Tests the heuristic used by the upload retry loop. The server returns
// "HTTP 409: file_id_conflict" via the Response.Error code; the CLI's
// makeRequest wrapper bubbles that up as an error string of roughly that
// form. isFileIDConflict scans the error string case-insensitively for
// the stable code "file_id_conflict" alongside "HTTP 409".
func TestIsFileIDConflict(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"HTTP 409 file_id_conflict", testErr("HTTP 409: file_id_conflict"), true},
		{"HTTP 409 different code", testErr("HTTP 409: some_other_error"), false},
		{"HTTP 500 not 409", testErr("HTTP 500: file_id_conflict"), false},
		{"different status code", testErr("HTTP 400: bad_request"), false},
		{"case variation accepted", testErr("HTTP 409: FILE_ID_CONFLICT"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isFileIDConflict(c.err)
			if got != c.want {
				t.Errorf("isFileIDConflict(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// testErr is a tiny helper so the test cases above can declare errors
// inline without an extra import.
type testErrString string

func (e testErrString) Error() string { return string(e) }

func testErr(s string) error { return testErrString(s) }
