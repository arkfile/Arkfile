package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestEncryptDecryptGCM_RoundTrip verifies basic encrypt-then-decrypt produces original plaintext
func TestEncryptDecryptGCM_RoundTrip(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("This is test data for AES-256-GCM round-trip verification")

	ciphertext, err := EncryptGCM(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptGCM failed: %v", err)
	}

	// Ciphertext must be longer than plaintext (nonce + tag overhead)
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("ciphertext should be longer than plaintext: ciphertext=%d, plaintext=%d",
			len(ciphertext), len(plaintext))
	}

	decrypted, err := DecryptGCM(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptGCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted data does not match original plaintext")
	}
}

// TestEncryptDecryptGCM_EmptyPlaintext verifies encryption of empty data
func TestEncryptDecryptGCM_EmptyPlaintext(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte{}

	ciphertext, err := EncryptGCM(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptGCM failed on empty plaintext: %v", err)
	}

	decrypted, err := DecryptGCM(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptGCM failed on empty plaintext: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted empty data does not match")
	}
}

// TestEncryptDecryptGCM_LargeData verifies encryption of larger data (1MB)
func TestEncryptDecryptGCM_LargeData(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := make([]byte, 1024*1024) // 1MB
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("failed to generate random plaintext: %v", err)
	}

	ciphertext, err := EncryptGCM(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptGCM failed: %v", err)
	}

	decrypted, err := DecryptGCM(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptGCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted large data does not match original")
	}
}

// TestEncryptDecryptGCM_WrongKeyFails verifies decryption with wrong key fails
func TestEncryptDecryptGCM_WrongKeyFails(t *testing.T) {
	key1, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}
	key2, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("secret data that must not be decrypted with wrong key")

	ciphertext, err := EncryptGCM(plaintext, key1)
	if err != nil {
		t.Fatalf("EncryptGCM failed: %v", err)
	}

	_, err = DecryptGCM(ciphertext, key2)
	if err == nil {
		t.Fatal("DecryptGCM with wrong key should have failed but succeeded")
	}
}

// TestEncryptGCM_KeySizeValidation verifies that non-32-byte keys are rejected
func TestEncryptGCM_KeySizeValidation(t *testing.T) {
	plaintext := []byte("test data")

	invalidKeys := [][]byte{
		nil,
		{},
		make([]byte, 16), // 128-bit key (too short for AES-256)
		make([]byte, 24), // 192-bit key
		make([]byte, 31), // one byte too short
		make([]byte, 33), // one byte too long
		make([]byte, 64), // too long
	}

	for i, key := range invalidKeys {
		_, err := EncryptGCM(plaintext, key)
		if err == nil {
			t.Errorf("case %d: EncryptGCM should reject key of length %d", i, len(key))
		}

		_, err = DecryptGCM(plaintext, key)
		if err == nil {
			t.Errorf("case %d: DecryptGCM should reject key of length %d", i, len(key))
		}
	}
}

// TestDecryptGCM_TruncatedCiphertext verifies that truncated ciphertext is rejected
func TestDecryptGCM_TruncatedCiphertext(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	ciphertext, err := EncryptGCM([]byte("test data for truncation test"), key)
	if err != nil {
		t.Fatalf("EncryptGCM failed: %v", err)
	}

	// Try progressively shorter truncations
	truncations := []int{0, 1, 5, 12, 27} // empty, very short, less than nonce, nonce only, nonce+partial tag
	for _, length := range truncations {
		if length > len(ciphertext) {
			continue
		}
		truncated := ciphertext[:length]
		_, err := DecryptGCM(truncated, key)
		if err == nil {
			t.Errorf("DecryptGCM should fail with truncated ciphertext of length %d", length)
		}
	}
}

// TestDecryptGCM_TamperedCiphertext verifies that tampered ciphertext is rejected
func TestDecryptGCM_TamperedCiphertext(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("test data for tampering detection")

	ciphertext, err := EncryptGCM(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptGCM failed: %v", err)
	}

	// Tamper with a byte in the middle of the ciphertext (after the nonce)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	midpoint := len(tampered) / 2
	tampered[midpoint] ^= 0xFF // flip all bits of one byte

	_, err = DecryptGCM(tampered, key)
	if err == nil {
		t.Fatal("DecryptGCM should fail with tampered ciphertext")
	}
}

// TestEncryptGCM_UniqueNonces verifies that two encryptions of the same plaintext produce different ciphertext
func TestEncryptGCM_UniqueNonces(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("identical plaintext encrypted twice")

	ct1, err := EncryptGCM(plaintext, key)
	if err != nil {
		t.Fatalf("first EncryptGCM failed: %v", err)
	}

	ct2, err := EncryptGCM(plaintext, key)
	if err != nil {
		t.Fatalf("second EncryptGCM failed: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same plaintext should produce different ciphertext (unique nonces)")
	}

	// Both should decrypt to the same plaintext
	dec1, err := DecryptGCM(ct1, key)
	if err != nil {
		t.Fatalf("DecryptGCM ct1 failed: %v", err)
	}
	dec2, err := DecryptGCM(ct2, key)
	if err != nil {
		t.Fatalf("DecryptGCM ct2 failed: %v", err)
	}

	if !bytes.Equal(dec1, dec2) || !bytes.Equal(dec1, plaintext) {
		t.Error("both ciphertexts should decrypt to the same original plaintext")
	}
}

// TestGenerateAESKey verifies key generation produces correct-length random keys
func TestGenerateAESKey(t *testing.T) {
	key1, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("AES key should be 32 bytes, got %d", len(key1))
	}

	key2, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("two generated AES keys should be different (random)")
	}

	// Verify keys are not all zeros
	allZeros := true
	for _, b := range key1 {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("generated key should not be all zeros")
	}
}

// -- AAD (Additional Authenticated Data) tests --

// TestEncryptDecryptGCMWithAAD_RoundTrip verifies encrypt/decrypt with AAD
func TestEncryptDecryptGCMWithAAD_RoundTrip(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("share envelope data with AAD binding")
	aad := []byte("share-id-abc123file-id-xyz789")

	ciphertext, err := EncryptGCMWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD failed: %v", err)
	}

	decrypted, err := DecryptGCMWithAAD(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("DecryptGCMWithAAD failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted AAD data does not match original plaintext")
	}
}

// TestDecryptGCMWithAAD_WrongAADFails proves share envelope binding:
// encrypting with one AAD and decrypting with a different AAD must fail
func TestDecryptGCMWithAAD_WrongAADFails(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("share envelope that must be bound to specific share")
	correctAAD := []byte("share-id-001file-id-abc")
	wrongAAD := []byte("share-id-002file-id-abc") // different share_id

	ciphertext, err := EncryptGCMWithAAD(plaintext, key, correctAAD)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD failed: %v", err)
	}

	// Decrypt with correct AAD should work
	_, err = DecryptGCMWithAAD(ciphertext, key, correctAAD)
	if err != nil {
		t.Fatalf("DecryptGCMWithAAD with correct AAD should succeed: %v", err)
	}

	// Decrypt with wrong AAD must fail
	_, err = DecryptGCMWithAAD(ciphertext, key, wrongAAD)
	if err == nil {
		t.Fatal("DecryptGCMWithAAD with wrong AAD should fail (share binding violated)")
	}
}

// TestDecryptGCMWithAAD_NoAADFails verifies that omitting AAD during decryption fails
// when AAD was provided during encryption
func TestDecryptGCMWithAAD_NoAADFails(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("data encrypted with AAD")
	aad := []byte("required-context-binding")

	ciphertext, err := EncryptGCMWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD failed: %v", err)
	}

	// Decrypt with nil AAD must fail
	_, err = DecryptGCMWithAAD(ciphertext, key, nil)
	if err == nil {
		t.Fatal("DecryptGCMWithAAD with nil AAD should fail when AAD was used for encryption")
	}

	// Decrypt with empty AAD must also fail
	_, err = DecryptGCMWithAAD(ciphertext, key, []byte{})
	if err == nil {
		t.Fatal("DecryptGCMWithAAD with empty AAD should fail when non-empty AAD was used for encryption")
	}
}

// TestDecryptGCMWithAAD_TamperedCiphertext verifies tamper detection with AAD
func TestDecryptGCMWithAAD_TamperedCiphertext(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	plaintext := []byte("AAD-protected data")
	aad := []byte("share-context")

	ciphertext, err := EncryptGCMWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptGCMWithAAD failed: %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)/2] ^= 0xFF

	_, err = DecryptGCMWithAAD(tampered, key, aad)
	if err == nil {
		t.Fatal("DecryptGCMWithAAD should fail with tampered ciphertext")
	}
}

// TestEncryptGCMWithAAD_KeySizeValidation verifies key size checks with AAD variant
func TestEncryptGCMWithAAD_KeySizeValidation(t *testing.T) {
	plaintext := []byte("test")
	aad := []byte("context")

	_, err := EncryptGCMWithAAD(plaintext, make([]byte, 16), aad)
	if err == nil {
		t.Error("EncryptGCMWithAAD should reject 16-byte key")
	}

	_, err = DecryptGCMWithAAD(make([]byte, 50), make([]byte, 16), aad)
	if err == nil {
		t.Error("DecryptGCMWithAAD should reject 16-byte key")
	}
}
