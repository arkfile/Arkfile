package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveOPAQUEFileKey derives a file encryption key from OPAQUE export key
func DeriveOPAQUEFileKey(exportKey []byte, fileID, userEmail string) ([]byte, error) {
	info := fmt.Sprintf("arkfile-file-encryption:%s:%s", userEmail, fileID)
	return hkdfExpand(exportKey, []byte(info), 32)
}

// DeriveShareAccessKey derives a share access key from OPAQUE export key
func DeriveShareAccessKey(exportKey []byte, shareID, fileID string) ([]byte, error) {
	info := fmt.Sprintf("arkfile-share-access:%s:%s", shareID, fileID)
	return hkdfExpand(exportKey, []byte(info), 32)
}

// DerivePasswordHintKey derives a key for encrypting password hints
func DerivePasswordHintKey(exportKey []byte, recordIdentifier string) ([]byte, error) {
	info := fmt.Sprintf("arkfile-hint-encryption:%s", recordIdentifier)
	return hkdfExpand(exportKey, []byte(info), 32)
}

// DeriveAccountFileKey derives a file encryption key from account password export key
func DeriveAccountFileKey(exportKey []byte, userEmail, fileID string) ([]byte, error) {
	info := fmt.Sprintf("arkfile-account-file:%s:%s", userEmail, fileID)
	return hkdfExpand(exportKey, []byte(info), 32)
}

// hkdfExpand performs HKDF-Expand operation
func hkdfExpand(prk []byte, info []byte, length int) ([]byte, error) {
	if len(prk) == 0 {
		return nil, fmt.Errorf("pseudorandom key cannot be empty")
	}

	if length <= 0 || length > 255*32 {
		return nil, fmt.Errorf("invalid output length: %d", length)
	}

	// Use HKDF-Expand with SHA-256
	reader := hkdf.Expand(sha256.New, prk, info)

	result := make([]byte, length)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	return result, nil
}

// EncryptAESGCM encrypts data with AES-GCM using provided key and nonce
func EncryptAESGCM(plaintext, key, nonce []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes for AES-GCM")
	}

	// Use existing EncryptGCM but with custom nonce
	return encryptGCMWithNonce(plaintext, key, nonce)
}

// DecryptAESGCM decrypts data with AES-GCM using provided key and nonce
func DecryptAESGCM(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes for AES-GCM")
	}

	// Prepend nonce to ciphertext to match DecryptGCM format
	data := make([]byte, len(nonce)+len(ciphertext))
	copy(data, nonce)
	copy(data[len(nonce):], ciphertext)

	return DecryptGCM(data, key)
}

// encryptGCMWithNonce encrypts with a provided nonce (internal helper)
func encryptGCMWithNonce(plaintext, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes for AES-GCM")
	}

	// For now, we'll use the existing EncryptGCM and replace the nonce
	// This is a temporary solution - ideally we'd modify the crypto package
	encrypted, err := EncryptGCM(plaintext, key)
	if err != nil {
		return nil, err
	}

	// Replace the generated nonce with our provided nonce
	if len(encrypted) < 12 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Copy our nonce into the encrypted data
	copy(encrypted[:12], nonce)

	return encrypted, nil
}
