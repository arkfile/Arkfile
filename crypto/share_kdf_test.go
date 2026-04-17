package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// -- Salt generation tests --

// TestGenerateShareSalt verifies salt generation produces valid base64-encoded 32-byte salts
func TestGenerateShareSalt(t *testing.T) {
	salt1, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("GenerateShareSalt failed: %v", err)
	}

	// Must be valid base64
	decoded, err := base64.StdEncoding.DecodeString(salt1)
	if err != nil {
		t.Fatalf("salt is not valid base64: %v", err)
	}

	// Must be 32 bytes when decoded
	if len(decoded) != 32 {
		t.Errorf("decoded salt should be 32 bytes, got %d", len(decoded))
	}

	// Two salts must be different (random)
	salt2, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("second GenerateShareSalt failed: %v", err)
	}

	if salt1 == salt2 {
		t.Error("two generated salts should be different (random)")
	}
}

// -- Key derivation tests --

// TestDeriveShareKey_Consistency verifies same password + salt always produces same key
func TestDeriveShareKey_Consistency(t *testing.T) {
	salt, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("GenerateShareSalt failed: %v", err)
	}

	password := "MyVacation2025PhotosForFamily!ExtraSecure"

	key1, err := DeriveShareKey(password, salt)
	if err != nil {
		t.Fatalf("first DeriveShareKey failed: %v", err)
	}

	key2, err := DeriveShareKey(password, salt)
	if err != nil {
		t.Fatalf("second DeriveShareKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("same password + salt should produce same key")
	}

	if len(key1) != int(ShareKDFParams.KeyLength) {
		t.Errorf("key length should be %d, got %d", ShareKDFParams.KeyLength, len(key1))
	}
}

// TestDeriveShareKey_DifferentPasswordProducesDifferentKey verifies password sensitivity
func TestDeriveShareKey_DifferentPasswordProducesDifferentKey(t *testing.T) {
	salt, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("GenerateShareSalt failed: %v", err)
	}

	key1, err := DeriveShareKey("CorrectPassword2025!Share", salt)
	if err != nil {
		t.Fatalf("DeriveShareKey key1 failed: %v", err)
	}

	key2, err := DeriveShareKey("WrongPassword2025!Share!", salt)
	if err != nil {
		t.Fatalf("DeriveShareKey key2 failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("different passwords should produce different keys")
	}
}

// TestDeriveShareKey_DifferentSaltProducesDifferentKey verifies salt sensitivity
func TestDeriveShareKey_DifferentSaltProducesDifferentKey(t *testing.T) {
	salt1, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("first GenerateShareSalt failed: %v", err)
	}
	salt2, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("second GenerateShareSalt failed: %v", err)
	}

	password := "SamePasswordForBothSalts2025!"

	key1, err := DeriveShareKey(password, salt1)
	if err != nil {
		t.Fatalf("DeriveShareKey key1 failed: %v", err)
	}

	key2, err := DeriveShareKey(password, salt2)
	if err != nil {
		t.Fatalf("DeriveShareKey key2 failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("different salts should produce different keys")
	}
}

// TestDeriveShareKey_InvalidSaltLength verifies wrong-length salt is rejected
func TestDeriveShareKey_InvalidSaltLength(t *testing.T) {
	// 16-byte salt encoded as base64 (should require 32 bytes)
	shortSalt := base64.StdEncoding.EncodeToString(make([]byte, 16))

	_, err := DeriveShareKey("SomePassword2025!Share", shortSalt)
	if err == nil {
		t.Error("DeriveShareKey should reject salt with wrong length")
	}
}

// TestDeriveShareKey_InvalidSaltEncoding verifies non-base64 salt is rejected
func TestDeriveShareKey_InvalidSaltEncoding(t *testing.T) {
	_, err := DeriveShareKey("SomePassword2025!Share", "not-valid-base64!!!")
	if err == nil {
		t.Error("DeriveShareKey should reject invalid base64 salt")
	}
}

// -- Download token tests --

// TestHashDownloadToken_Consistency verifies same token always produces same hash
func TestHashDownloadToken_Consistency(t *testing.T) {
	token, err := GenerateDownloadToken()
	if err != nil {
		t.Fatalf("GenerateDownloadToken failed: %v", err)
	}

	tokenB64 := base64.StdEncoding.EncodeToString(token)

	hash1, err := HashDownloadToken(tokenB64)
	if err != nil {
		t.Fatalf("first HashDownloadToken failed: %v", err)
	}

	hash2, err := HashDownloadToken(tokenB64)
	if err != nil {
		t.Fatalf("second HashDownloadToken failed: %v", err)
	}

	if hash1 != hash2 {
		t.Error("same token should always produce same hash")
	}

	if hash1 == "" {
		t.Error("hash should not be empty")
	}
}

// TestVerifyDownloadToken_Success verifies correct token matches its hash
func TestVerifyDownloadToken_Success(t *testing.T) {
	token, err := GenerateDownloadToken()
	if err != nil {
		t.Fatalf("GenerateDownloadToken failed: %v", err)
	}

	tokenB64 := base64.StdEncoding.EncodeToString(token)

	hash, err := HashDownloadToken(tokenB64)
	if err != nil {
		t.Fatalf("HashDownloadToken failed: %v", err)
	}

	valid, err := VerifyDownloadToken(tokenB64, hash)
	if err != nil {
		t.Fatalf("VerifyDownloadToken failed: %v", err)
	}

	if !valid {
		t.Error("correct token should verify against its own hash")
	}
}

// TestVerifyDownloadToken_WrongToken verifies wrong token does not match
func TestVerifyDownloadToken_WrongToken(t *testing.T) {
	token1, err := GenerateDownloadToken()
	if err != nil {
		t.Fatalf("GenerateDownloadToken failed: %v", err)
	}

	token2, err := GenerateDownloadToken()
	if err != nil {
		t.Fatalf("second GenerateDownloadToken failed: %v", err)
	}

	token1B64 := base64.StdEncoding.EncodeToString(token1)
	token2B64 := base64.StdEncoding.EncodeToString(token2)

	hash1, err := HashDownloadToken(token1B64)
	if err != nil {
		t.Fatalf("HashDownloadToken failed: %v", err)
	}

	// Verify token2 against token1's hash: must fail
	valid, err := VerifyDownloadToken(token2B64, hash1)
	if err != nil {
		t.Fatalf("VerifyDownloadToken failed: %v", err)
	}

	if valid {
		t.Error("wrong token should not verify against a different token's hash")
	}
}

// TestGenerateDownloadToken verifies token generation
func TestGenerateDownloadToken(t *testing.T) {
	token1, err := GenerateDownloadToken()
	if err != nil {
		t.Fatalf("GenerateDownloadToken failed: %v", err)
	}

	if len(token1) != 32 {
		t.Errorf("download token should be 32 bytes, got %d", len(token1))
	}

	token2, err := GenerateDownloadToken()
	if err != nil {
		t.Fatalf("second GenerateDownloadToken failed: %v", err)
	}

	if bytes.Equal(token1, token2) {
		t.Error("two download tokens should be different (random)")
	}
}

// -- Share envelope tests --

// TestCreateParseShareEnvelope_RoundTrip verifies envelope creation and parsing
func TestCreateParseShareEnvelope_RoundTrip(t *testing.T) {
	fek := make([]byte, 32)
	for i := range fek {
		fek[i] = byte(i)
	}
	downloadToken := make([]byte, 32)
	for i := range downloadToken {
		downloadToken[i] = byte(255 - i)
	}

	filename := "my-test-file.pdf"
	sizeBytes := int64(1048576) // 1MB
	sha256hex := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	envelopeJSON, err := CreateShareEnvelope(fek, downloadToken, filename, sizeBytes, sha256hex)
	if err != nil {
		t.Fatalf("CreateShareEnvelope failed: %v", err)
	}

	parsed, err := ParseShareEnvelope(envelopeJSON)
	if err != nil {
		t.Fatalf("ParseShareEnvelope failed: %v", err)
	}

	// Verify FEK
	parsedFEK, err := base64.StdEncoding.DecodeString(parsed.FEK)
	if err != nil {
		t.Fatalf("failed to decode parsed FEK: %v", err)
	}
	if !bytes.Equal(fek, parsedFEK) {
		t.Error("parsed FEK does not match original")
	}

	// Verify download token
	parsedToken, err := base64.StdEncoding.DecodeString(parsed.DownloadToken)
	if err != nil {
		t.Fatalf("failed to decode parsed download token: %v", err)
	}
	if !bytes.Equal(downloadToken, parsedToken) {
		t.Error("parsed download token does not match original")
	}

	// Verify metadata
	if parsed.Filename != filename {
		t.Errorf("filename mismatch: got %s, expected %s", parsed.Filename, filename)
	}
	if parsed.SizeBytes != sizeBytes {
		t.Errorf("size mismatch: got %d, expected %d", parsed.SizeBytes, sizeBytes)
	}
	if parsed.SHA256 != sha256hex {
		t.Errorf("sha256 mismatch: got %s, expected %s", parsed.SHA256, sha256hex)
	}
}

// TestParseShareEnvelope_MissingFEK verifies missing FEK is rejected
func TestParseShareEnvelope_MissingFEK(t *testing.T) {
	envelope := map[string]string{
		"download_token": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		// no "fek" field
	}
	data, _ := json.Marshal(envelope)

	_, err := ParseShareEnvelope(data)
	if err == nil {
		t.Error("ParseShareEnvelope should reject envelope with missing FEK")
	}
}

// TestParseShareEnvelope_MissingDownloadToken verifies missing download token is rejected
func TestParseShareEnvelope_MissingDownloadToken(t *testing.T) {
	envelope := map[string]string{
		"fek": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		// no "download_token" field
	}
	data, _ := json.Marshal(envelope)

	_, err := ParseShareEnvelope(data)
	if err == nil {
		t.Error("ParseShareEnvelope should reject envelope with missing download token")
	}
}

// TestParseShareEnvelope_InvalidJSON verifies malformed JSON is rejected
func TestParseShareEnvelope_InvalidJSON(t *testing.T) {
	_, err := ParseShareEnvelope([]byte("{not valid json"))
	if err == nil {
		t.Error("ParseShareEnvelope should reject invalid JSON")
	}
}

// -- AAD creation tests --

// TestCreateAAD verifies AAD is concatenation of share_id + file_id
func TestCreateAAD(t *testing.T) {
	shareID := "share-abc-123"
	fileID := "file-xyz-789"

	aad := CreateAAD(shareID, fileID)

	expected := []byte(shareID + fileID)
	if !bytes.Equal(aad, expected) {
		t.Errorf("AAD mismatch: got %s, expected %s", string(aad), string(expected))
	}
}

// TestCreateAAD_DifferentShareIDs verifies different share IDs produce different AAD
func TestCreateAAD_DifferentShareIDs(t *testing.T) {
	fileID := "file-same-123"

	aad1 := CreateAAD("share-001", fileID)
	aad2 := CreateAAD("share-002", fileID)

	if bytes.Equal(aad1, aad2) {
		t.Error("different share IDs should produce different AAD")
	}
}

// -- Full share envelope encrypt/decrypt cycle tests --

// TestShareEnvelopeEncryptDecrypt_FullCycle tests the complete share security model:
// DeriveShareKey -> CreateShareEnvelope -> EncryptGCMWithAAD -> DecryptGCMWithAAD -> ParseShareEnvelope
func TestShareEnvelopeEncryptDecrypt_FullCycle(t *testing.T) {
	// Generate share parameters
	salt, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("GenerateShareSalt failed: %v", err)
	}

	password := "MyShareP@ssw0rd-789q&*(::test"
	shareID := "share-full-cycle-001"
	fileID := "file-full-cycle-abc"

	// Derive share key
	shareKey, err := DeriveShareKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveShareKey failed: %v", err)
	}

	// Create envelope with file metadata
	fek := make([]byte, 32)
	for i := range fek {
		fek[i] = byte(i + 10)
	}
	downloadToken, err := GenerateDownloadToken()
	if err != nil {
		t.Fatalf("GenerateDownloadToken failed: %v", err)
	}

	filename := "vacation-photos.zip"
	sizeBytes := int64(6442450944) // 6GB
	sha256hex := "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567"

	envelopeJSON, err := CreateShareEnvelope(fek, downloadToken, filename, sizeBytes, sha256hex)
	if err != nil {
		t.Fatalf("CreateShareEnvelope failed: %v", err)
	}

	// Encrypt envelope with AAD binding
	aad := CreateAAD(shareID, fileID)
	encryptedEnvelope, err := EncryptGCMWithAAD(envelopeJSON, shareKey, aad)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD failed: %v", err)
	}

	// Decrypt envelope
	decryptedJSON, err := DecryptGCMWithAAD(encryptedEnvelope, shareKey, aad)
	if err != nil {
		t.Fatalf("DecryptGCMWithAAD failed: %v", err)
	}

	// Parse envelope
	parsed, err := ParseShareEnvelope(decryptedJSON)
	if err != nil {
		t.Fatalf("ParseShareEnvelope failed: %v", err)
	}

	// Verify all fields match originals
	parsedFEK, _ := base64.StdEncoding.DecodeString(parsed.FEK)
	if !bytes.Equal(fek, parsedFEK) {
		t.Error("FEK does not match after full cycle")
	}

	parsedToken, _ := base64.StdEncoding.DecodeString(parsed.DownloadToken)
	if !bytes.Equal(downloadToken, parsedToken) {
		t.Error("download token does not match after full cycle")
	}

	if parsed.Filename != filename {
		t.Errorf("filename mismatch: got %s, expected %s", parsed.Filename, filename)
	}
	if parsed.SizeBytes != sizeBytes {
		t.Errorf("size mismatch: got %d, expected %d", parsed.SizeBytes, sizeBytes)
	}
	if parsed.SHA256 != sha256hex {
		t.Errorf("sha256 mismatch: got %s, expected %s", parsed.SHA256, sha256hex)
	}
}

// TestShareEnvelopeEncryptDecrypt_WrongPassword verifies wrong password cannot decrypt
func TestShareEnvelopeEncryptDecrypt_WrongPassword(t *testing.T) {
	salt, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("GenerateShareSalt failed: %v", err)
	}

	correctPassword := "CorrectShareP@ssw0rd2025!"
	wrongPassword := "WrongShareP@ssw0rd2025!!"
	shareID := "share-wrong-pwd-001"
	fileID := "file-wrong-pwd-abc"

	// Derive correct share key and encrypt
	correctKey, err := DeriveShareKey(correctPassword, salt)
	if err != nil {
		t.Fatalf("DeriveShareKey failed: %v", err)
	}

	envelopeJSON, err := CreateShareEnvelope(make([]byte, 32), make([]byte, 32), "test.bin", 1024, "abcd1234")
	if err != nil {
		t.Fatalf("CreateShareEnvelope failed: %v", err)
	}

	aad := CreateAAD(shareID, fileID)
	encrypted, err := EncryptGCMWithAAD(envelopeJSON, correctKey, aad)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD failed: %v", err)
	}

	// Derive wrong key and attempt decrypt
	wrongKey, err := DeriveShareKey(wrongPassword, salt)
	if err != nil {
		t.Fatalf("DeriveShareKey wrong failed: %v", err)
	}

	_, err = DecryptGCMWithAAD(encrypted, wrongKey, aad)
	if err == nil {
		t.Fatal("decryption with wrong password-derived key should fail")
	}
}

// TestShareEnvelopeEncryptDecrypt_WrongAAD proves share envelope binding:
// an envelope encrypted for share_id_A cannot be decrypted as if it belongs to share_id_B
func TestShareEnvelopeEncryptDecrypt_WrongAAD(t *testing.T) {
	salt, err := GenerateShareSalt()
	if err != nil {
		t.Fatalf("GenerateShareSalt failed: %v", err)
	}

	password := "SharedP@ssw0rd2025!Test"
	fileID := "file-aad-test-001"

	shareKey, err := DeriveShareKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveShareKey failed: %v", err)
	}

	envelopeJSON, err := CreateShareEnvelope(make([]byte, 32), make([]byte, 32), "test.bin", 512, "beef0000")
	if err != nil {
		t.Fatalf("CreateShareEnvelope failed: %v", err)
	}

	// Encrypt with AAD for share A
	aadShareA := CreateAAD("share-id-AAA", fileID)
	encrypted, err := EncryptGCMWithAAD(envelopeJSON, shareKey, aadShareA)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD failed: %v", err)
	}

	// Attempt to decrypt with AAD for share B (different share_id, same file_id)
	aadShareB := CreateAAD("share-id-BBB", fileID)
	_, err = DecryptGCMWithAAD(encrypted, shareKey, aadShareB)
	if err == nil {
		t.Fatal("decryption with wrong AAD (different share_id) should fail - share binding violated")
	}

	// Attempt to decrypt with AAD for same share but different file (different file_id)
	aadWrongFile := CreateAAD("share-id-AAA", "file-different-999")
	_, err = DecryptGCMWithAAD(encrypted, shareKey, aadWrongFile)
	if err == nil {
		t.Fatal("decryption with wrong AAD (different file_id) should fail - file binding violated")
	}

	// Verify correct AAD still works
	_, err = DecryptGCMWithAAD(encrypted, shareKey, aadShareA)
	if err != nil {
		t.Fatalf("decryption with correct AAD should succeed: %v", err)
	}
}
