package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// =============================================================================
// CROSS-LANGUAGE CONFORMANCE VECTOR
// =============================================================================
//
// The single hardcoded input/output vector below is the canonical pin that
// keeps the Go and TypeScript AAD implementations byte-identical. The exact
// same input vector and expected hex output appear in
// client/static/js/src/__tests__/aad.test.ts.
//
// If either implementation drifts (off-by-one in a length prefix, wrong
// endianness, different string encoding), both test suites fail
// immediately on this vector.
//
// To regenerate the vector after an intentional format change:
//   1. Edit BuildChunkAAD here.
//   2. Run `go test ./crypto -run TestBuildChunkAAD_CrossLanguageVector -v`.
//      The test failure log will print the actual hex.
//   3. Update both this Go test AND the matching TS test with the new hex.
// =============================================================================

const (
	// Conformance input fileID: a UUID v4 with predictable hex byte values.
	// 36 ASCII bytes, no UTF-8 multi-byte sequences. This eliminates any
	// ambiguity in how each implementation encodes "string" -> "bytes".
	conformanceFileID      = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	conformanceChunkIndex  = int64(3)
	conformanceTotalChunks = int64(10)
)

// Expected bytes for BuildChunkAAD("a1b2c3d4-...-7890", 3, 10):
//
//	[4B BE uint32 len=36] = 00 00 00 24
//	[36 bytes UTF-8 fileID] = 61 31 62 32 63 33 64 34 2d 65 35 66 36 2d
//	                          37 38 39 30 2d 61 62 63 64 2d 65 66 31 32
//	                          33 34 35 36 37 38 39 30
//	[8B BE uint64 chunkIndex=3]  = 00 00 00 00 00 00 00 03
//	[8B BE uint64 totalChunks=10] = 00 00 00 00 00 00 00 0a
//
// Total: 4 + 36 + 8 + 8 = 56 bytes.
const expectedChunkAADHex = "00000024" +
	"6131623263336434" +
	"2d65356636" +
	"2d37383930" +
	"2d61626364" +
	"2d6566313233343536373839" +
	"30" +
	"0000000000000003" +
	"000000000000000a"

func TestBuildChunkAAD_CrossLanguageVector(t *testing.T) {
	got := BuildChunkAAD(conformanceFileID, conformanceChunkIndex, conformanceTotalChunks)
	want, err := hex.DecodeString(expectedChunkAADHex)
	if err != nil {
		t.Fatalf("malformed expected hex literal in test source: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("AAD bytes mismatch.\n  got  (%d): %x\n  want (%d): %x",
			len(got), got, len(want), want)
	}
	// Sanity: length 56 = 4 + 36 + 8 + 8.
	if len(got) != 56 {
		t.Errorf("unexpected AAD length: got %d, want 56", len(got))
	}
}

// =============================================================================
// DETERMINISM + UNIQUENESS — BuildChunkAAD
// =============================================================================

func TestBuildChunkAAD_Deterministic(t *testing.T) {
	a := BuildChunkAAD("file-x", 5, 20)
	b := BuildChunkAAD("file-x", 5, 20)
	if !bytes.Equal(a, b) {
		t.Errorf("not deterministic: a=%x b=%x", a, b)
	}
}

func TestBuildChunkAAD_UniqueByChunkIndex(t *testing.T) {
	a := BuildChunkAAD("file-x", 0, 5)
	b := BuildChunkAAD("file-x", 1, 5)
	if bytes.Equal(a, b) {
		t.Errorf("AAD collided across chunkIndex change: a==b=%x", a)
	}
}

func TestBuildChunkAAD_UniqueByFileID(t *testing.T) {
	a := BuildChunkAAD("file-a", 0, 5)
	b := BuildChunkAAD("file-b", 0, 5)
	if bytes.Equal(a, b) {
		t.Errorf("AAD collided across fileID change: a==b=%x", a)
	}
}

func TestBuildChunkAAD_UniqueByTotalChunks(t *testing.T) {
	a := BuildChunkAAD("file-x", 0, 5)
	b := BuildChunkAAD("file-x", 0, 6)
	if bytes.Equal(a, b) {
		t.Errorf("AAD collided across totalChunks change: a==b=%x", a)
	}
}

// =============================================================================
// DETERMINISM + DISTINCTION — BuildFEKEnvelopeAAD
// =============================================================================

func TestBuildFEKEnvelopeAAD_Deterministic(t *testing.T) {
	a := BuildFEKEnvelopeAAD("file-x", 0x01)
	b := BuildFEKEnvelopeAAD("file-x", 0x01)
	if !bytes.Equal(a, b) {
		t.Errorf("not deterministic: a=%x b=%x", a, b)
	}
}

func TestBuildFEKEnvelopeAAD_KeyTypeDistinction(t *testing.T) {
	account := BuildFEKEnvelopeAAD("file-x", 0x01)
	custom := BuildFEKEnvelopeAAD("file-x", 0x02)
	if bytes.Equal(account, custom) {
		t.Errorf("account (0x01) and custom (0x02) FEK envelope AADs collided: %x", account)
	}
}

func TestBuildFEKEnvelopeAAD_FileIDDistinction(t *testing.T) {
	a := BuildFEKEnvelopeAAD("file-a", 0x01)
	b := BuildFEKEnvelopeAAD("file-b", 0x01)
	if bytes.Equal(a, b) {
		t.Errorf("FEK envelope AAD collided across fileID change: %x", a)
	}
}

// =============================================================================
// DETERMINISM + DISTINCTION — BuildMetadataFieldAAD
// =============================================================================

func TestBuildMetadataFieldAAD_Deterministic(t *testing.T) {
	a := BuildMetadataFieldAAD("file-x", AADFieldFilename, "alice")
	b := BuildMetadataFieldAAD("file-x", AADFieldFilename, "alice")
	if !bytes.Equal(a, b) {
		t.Errorf("not deterministic: a=%x b=%x", a, b)
	}
}

func TestBuildMetadataFieldAAD_FieldNameDistinction(t *testing.T) {
	fn := BuildMetadataFieldAAD("file-x", AADFieldFilename, "alice")
	sh := BuildMetadataFieldAAD("file-x", AADFieldSha256, "alice")
	if bytes.Equal(fn, sh) {
		t.Errorf("filename AAD collided with sha256 AAD for same fileID+owner: %x", fn)
	}
}

func TestBuildMetadataFieldAAD_UsernameDistinction(t *testing.T) {
	a := BuildMetadataFieldAAD("file-x", AADFieldFilename, "alice")
	b := BuildMetadataFieldAAD("file-x", AADFieldFilename, "bob")
	if bytes.Equal(a, b) {
		t.Errorf("metadata AAD collided across owner change: %x", a)
	}
}

func TestBuildMetadataFieldAAD_FileIDDistinction(t *testing.T) {
	a := BuildMetadataFieldAAD("file-a", AADFieldFilename, "alice")
	b := BuildMetadataFieldAAD("file-b", AADFieldFilename, "alice")
	if bytes.Equal(a, b) {
		t.Errorf("metadata AAD collided across fileID change: %x", a)
	}
}

// TestAADFieldLabels_AreCanonicalStrings is a tripwire: changing either
// label literal silently would break every previously-encrypted file's
// metadata. The constants are permanent wire-format commitments per
// phase-c.md §4.6.
func TestAADFieldLabels_AreCanonicalStrings(t *testing.T) {
	if AADFieldFilename != "encrypted_filename" {
		t.Errorf("AADFieldFilename drifted: got %q, expected exactly %q",
			AADFieldFilename, "encrypted_filename")
	}
	if AADFieldSha256 != "encrypted_sha256sum" {
		t.Errorf("AADFieldSha256 drifted: got %q, expected exactly %q",
			AADFieldSha256, "encrypted_sha256sum")
	}
}

// =============================================================================
// TAMPER-DETECTION NEGATIVE TESTS — proves AAD binding actually catches
// chunk swap / reorder / cross-file substitution / truncation at the
// AEAD layer (B-02, B-05, C-02, C-03).
// =============================================================================

func TestChunkSwapDetection(t *testing.T) {
	fek, err := GenerateFEK()
	if err != nil {
		t.Fatalf("GenerateFEK: %v", err)
	}
	plaintext0 := []byte("chunk-zero-plaintext-data")
	plaintext1 := []byte("chunk-one-plaintext-data-different-length")

	aad0 := BuildChunkAAD("file-1", 0, 3)
	aad1 := BuildChunkAAD("file-1", 1, 3)

	ct0, err := EncryptGCMWithAAD(plaintext0, fek, aad0)
	if err != nil {
		t.Fatalf("encrypt chunk 0: %v", err)
	}
	ct1, err := EncryptGCMWithAAD(plaintext1, fek, aad1)
	if err != nil {
		t.Fatalf("encrypt chunk 1: %v", err)
	}

	// Sanity: each chunk decrypts cleanly with its own AAD.
	if got, err := DecryptGCMWithAAD(ct0, fek, aad0); err != nil || !bytes.Equal(got, plaintext0) {
		t.Fatalf("chunk 0 should decrypt with its own AAD: err=%v got=%x", err, got)
	}
	if got, err := DecryptGCMWithAAD(ct1, fek, aad1); err != nil || !bytes.Equal(got, plaintext1) {
		t.Fatalf("chunk 1 should decrypt with its own AAD: err=%v got=%x", err, got)
	}

	// Attempted reorder: try to decrypt chunk 0's bytes claiming index 1.
	if _, err := DecryptGCMWithAAD(ct0, fek, aad1); err == nil {
		t.Errorf("expected AEAD failure when decrypting chunk 0 bytes as chunk 1, got success")
	}
	// And vice versa.
	if _, err := DecryptGCMWithAAD(ct1, fek, aad0); err == nil {
		t.Errorf("expected AEAD failure when decrypting chunk 1 bytes as chunk 0, got success")
	}
}

func TestCrossFileChunkSubstitution(t *testing.T) {
	fek, err := GenerateFEK()
	if err != nil {
		t.Fatalf("GenerateFEK: %v", err)
	}
	plaintext := []byte("identical plaintext, different file identity")

	aadA := BuildChunkAAD("file-A", 0, 3)
	aadB := BuildChunkAAD("file-B", 0, 3)

	ctA, err := EncryptGCMWithAAD(plaintext, fek, aadA)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Attempt cross-file substitution: file-A's chunk 0 ciphertext, decoded
	// under file-B's AAD.
	if _, err := DecryptGCMWithAAD(ctA, fek, aadB); err == nil {
		t.Errorf("expected AEAD failure on cross-file substitution, got success")
	}
}

func TestChunkTruncationDetection(t *testing.T) {
	fek, err := GenerateFEK()
	if err != nil {
		t.Fatalf("GenerateFEK: %v", err)
	}
	plaintext := []byte("last chunk of a 3-chunk file")

	// Encrypted with the truthful totalChunks=3.
	aadTruthful := BuildChunkAAD("file-x", 2, 3)
	ct, err := EncryptGCMWithAAD(plaintext, fek, aadTruthful)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Attacker rewrites DB to claim totalChunks=2, hoping the client will
	// happily decrypt the surviving chunks. Client constructs AAD with the
	// claimed (smaller) totalChunks; AEAD fails.
	aadTruncated := BuildChunkAAD("file-x", 2, 2)
	if _, err := DecryptGCMWithAAD(ct, fek, aadTruncated); err == nil {
		t.Errorf("expected AEAD failure on totalChunks=3 -> 2 truncation, got success")
	}
}

// =============================================================================
// FEK-ENVELOPE AAD ROUND-TRIP + NEGATIVE TESTS — B-08
// =============================================================================

func TestFEKEnvelopeAAD_RoundTrip(t *testing.T) {
	fek, err := GenerateFEK()
	if err != nil {
		t.Fatalf("GenerateFEK: %v", err)
	}
	kek, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}

	aad := BuildFEKEnvelopeAAD("file-x", 0x01)
	wrapped, err := EncryptGCMWithAAD(fek, kek, aad)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD: %v", err)
	}

	unwrapped, err := DecryptGCMWithAAD(wrapped, kek, aad)
	if err != nil {
		t.Fatalf("expected clean unwrap, got %v", err)
	}
	if !bytes.Equal(unwrapped, fek) {
		t.Errorf("FEK mismatch after round-trip")
	}
}

func TestFEKEnvelopeAAD_CrossFileSwap_Fails(t *testing.T) {
	fek, _ := GenerateFEK()
	kek, _ := GenerateAESKey()

	aadA := BuildFEKEnvelopeAAD("file-A", 0x01)
	aadB := BuildFEKEnvelopeAAD("file-B", 0x01)

	wrappedA, err := EncryptGCMWithAAD(fek, kek, aadA)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Attacker rewrites DB: file-B's encrypted_fek now contains file-A's
	// FEK envelope ciphertext.
	if _, err := DecryptGCMWithAAD(wrappedA, kek, aadB); err == nil {
		t.Errorf("expected AEAD failure on cross-file FEK swap, got success")
	}
}

func TestFEKEnvelopeAAD_KeyTypeFlip_Fails(t *testing.T) {
	fek, _ := GenerateFEK()
	kek, _ := GenerateAESKey()

	aadAccount := BuildFEKEnvelopeAAD("file-x", 0x01)
	aadCustom := BuildFEKEnvelopeAAD("file-x", 0x02)

	wrapped, err := EncryptGCMWithAAD(fek, kek, aadAccount)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Attacker flips the keytype byte to 0x02 in the envelope header but
	// the AEAD tag was computed under 0x01.
	if _, err := DecryptGCMWithAAD(wrapped, kek, aadCustom); err == nil {
		t.Errorf("expected AEAD failure on key-type-byte flip, got success")
	}
}

// =============================================================================
// METADATA-FIELD AAD ROUND-TRIP + NEGATIVE TESTS — C-19
// =============================================================================

func TestMetadataFieldAAD_RoundTrip(t *testing.T) {
	kek, _ := GenerateAESKey()
	plaintext := []byte("example.tar.gz")

	aad := BuildMetadataFieldAAD("file-x", AADFieldFilename, "alice")
	ct, err := EncryptGCMWithAAD(plaintext, kek, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := DecryptGCMWithAAD(ct, kek, aad)
	if err != nil {
		t.Fatalf("expected clean round-trip: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch after round-trip")
	}
}

func TestMetadataFieldAAD_FieldNameSwap_Fails(t *testing.T) {
	kek, _ := GenerateAESKey()
	plaintext := []byte("plaintext-or-filename")

	aadFilename := BuildMetadataFieldAAD("file-x", AADFieldFilename, "alice")
	aadSha := BuildMetadataFieldAAD("file-x", AADFieldSha256, "alice")

	ct, err := EncryptGCMWithAAD(plaintext, kek, aadFilename)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptGCMWithAAD(ct, kek, aadSha); err == nil {
		t.Errorf("expected AEAD failure on filename <-> sha256 ciphertext swap, got success")
	}
}

func TestMetadataFieldAAD_OwnerSwap_Fails(t *testing.T) {
	kek, _ := GenerateAESKey()
	plaintext := []byte("file.txt")

	aadAlice := BuildMetadataFieldAAD("file-x", AADFieldFilename, "alice")
	aadBob := BuildMetadataFieldAAD("file-x", AADFieldFilename, "bob")

	ct, err := EncryptGCMWithAAD(plaintext, kek, aadAlice)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptGCMWithAAD(ct, kek, aadBob); err == nil {
		t.Errorf("expected AEAD failure on owner-username change, got success")
	}
}

func TestMetadataFieldAAD_FileIDSwap_Fails(t *testing.T) {
	kek, _ := GenerateAESKey()
	plaintext := []byte("file.txt")

	aadA := BuildMetadataFieldAAD("file-A", AADFieldFilename, "alice")
	aadB := BuildMetadataFieldAAD("file-B", AADFieldFilename, "alice")

	ct, err := EncryptGCMWithAAD(plaintext, kek, aadA)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptGCMWithAAD(ct, kek, aadB); err == nil {
		t.Errorf("expected AEAD failure on metadata move to different file, got success")
	}
}
