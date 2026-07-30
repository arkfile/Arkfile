package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
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

func TestAADSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/crypto-conformance-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		FileID        string `json:"file_id"`
		OwnerUsername string `json:"owner_username"`
		OwnerHeaders  struct {
			AccountHex string `json:"account_hex"`
		} `json:"owner_headers"`
		AAD struct {
			Chunk        string `json:"chunk_zero_of_three_hex"`
			FEK          string `json:"account_fek_envelope_hex"`
			Filename     string `json:"encrypted_filename_hex"`
			SHA256       string `json:"encrypted_sha256sum_hex"`
			PasswordHint string `json:"encrypted_password_hint_hex"`
			Tags         string `json:"encrypted_tags_hex"`
		} `json:"aad"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	header, _ := hex.DecodeString(fixture.OwnerHeaders.AccountHex)
	cases := map[string]struct {
		got  []byte
		want string
	}{
		"chunk":         {BuildChunkAAD(fixture.FileID, 0, 3), fixture.AAD.Chunk},
		"fek":           {BuildFEKEnvelopeAAD(fixture.FileID, header), fixture.AAD.FEK},
		"filename":      {BuildMetadataFieldAAD(fixture.FileID, AADFieldFilename, fixture.OwnerUsername), fixture.AAD.Filename},
		"sha256":        {BuildMetadataFieldAAD(fixture.FileID, AADFieldSha256, fixture.OwnerUsername), fixture.AAD.SHA256},
		"password_hint": {BuildMetadataFieldAAD(fixture.FileID, AADFieldPasswordHint, fixture.OwnerUsername), fixture.AAD.PasswordHint},
		"tags":          {BuildMetadataFieldAAD(fixture.FileID, AADFieldTags, fixture.OwnerUsername), fixture.AAD.Tags},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if hex.EncodeToString(tc.got) != tc.want {
				t.Fatalf("%s AAD does not match shared fixture", name)
			}
		})
	}
}

// =============================================================================
// DETERMINISM + UNIQUENESS -- BuildChunkAAD
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
// DETERMINISM + DISTINCTION -- BuildFEKEnvelopeAAD
// =============================================================================

func TestBuildFEKEnvelopeAAD_Deterministic(t *testing.T) {
	header, err := CreateFEKEnvelopeHeader(AccountKDFContext, make([]byte, OwnerEnvelopeSaltSize()))
	if err != nil {
		t.Fatal(err)
	}
	a := BuildFEKEnvelopeAAD("file-x", header)
	b := BuildFEKEnvelopeAAD("file-x", header)
	if !bytes.Equal(a, b) {
		t.Errorf("not deterministic: a=%x b=%x", a, b)
	}
}

func TestBuildFEKEnvelopeAAD_KeyTypeDistinction(t *testing.T) {
	salt := make([]byte, OwnerEnvelopeSaltSize())
	accountHeader, _ := CreateFEKEnvelopeHeader(AccountKDFContext, salt)
	customHeader, _ := CreateFEKEnvelopeHeader(CustomKDFContext, salt)
	account := BuildFEKEnvelopeAAD("file-x", accountHeader)
	custom := BuildFEKEnvelopeAAD("file-x", customHeader)
	if bytes.Equal(account, custom) {
		t.Errorf("account (0x01) and custom (0x02) FEK envelope AADs collided: %x", account)
	}
}

func TestBuildFEKEnvelopeAAD_FileIDDistinction(t *testing.T) {
	header, _ := CreateFEKEnvelopeHeader(AccountKDFContext, make([]byte, OwnerEnvelopeSaltSize()))
	a := BuildFEKEnvelopeAAD("file-a", header)
	b := BuildFEKEnvelopeAAD("file-b", header)
	if bytes.Equal(a, b) {
		t.Errorf("FEK envelope AAD collided across fileID change: %x", a)
	}
}

// =============================================================================
// DETERMINISM + DISTINCTION -- BuildMetadataFieldAAD
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
// metadata. The constants are permanent wire-format commitments.
func TestAADFieldLabels_AreCanonicalStrings(t *testing.T) {
	if AADFieldFilename != "encrypted_filename" {
		t.Errorf("AADFieldFilename drifted: got %q, expected exactly %q",
			AADFieldFilename, "encrypted_filename")
	}
	if AADFieldSha256 != "encrypted_sha256sum" {
		t.Errorf("AADFieldSha256 drifted: got %q, expected exactly %q",
			AADFieldSha256, "encrypted_sha256sum")
	}
	if AADFieldPasswordHint != "encrypted_password_hint" {
		t.Errorf("AADFieldPasswordHint drifted: got %q, expected exactly %q",
			AADFieldPasswordHint, "encrypted_password_hint")
	}
	if AADFieldTags != "encrypted_tags" {
		t.Errorf("AADFieldTags drifted: got %q, expected exactly %q",
			AADFieldTags, "encrypted_tags")
	}
}

// =============================================================================
// TAMPER-DETECTION NEGATIVE TESTS -- proves AAD binding actually catches
// chunk swap / reorder / cross-file substitution / truncation at the
// AEAD layer
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
// FEK-ENVELOPE AAD ROUND-TRIP + NEGATIVE TESTS
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

	header, _ := CreateFEKEnvelopeHeader(AccountKDFContext, make([]byte, OwnerEnvelopeSaltSize()))
	aad := BuildFEKEnvelopeAAD("file-x", header)
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

	header, _ := CreateFEKEnvelopeHeader(AccountKDFContext, make([]byte, OwnerEnvelopeSaltSize()))
	aadA := BuildFEKEnvelopeAAD("file-A", header)
	aadB := BuildFEKEnvelopeAAD("file-B", header)

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

	salt := make([]byte, OwnerEnvelopeSaltSize())
	accountHeader, _ := CreateFEKEnvelopeHeader(AccountKDFContext, salt)
	customHeader, _ := CreateFEKEnvelopeHeader(CustomKDFContext, salt)
	aadAccount := BuildFEKEnvelopeAAD("file-x", accountHeader)
	aadCustom := BuildFEKEnvelopeAAD("file-x", customHeader)

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
// METADATA-FIELD AAD ROUND-TRIP + NEGATIVE TESTS
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
