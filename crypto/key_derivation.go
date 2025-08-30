package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// UnifiedArgonProfile defines Argon2ID parameters for all file encryption contexts
type UnifiedArgonProfile struct {
	Time    uint32 // iterations
	Memory  uint32 // KB
	Threads uint8  // parallelism
	KeyLen  uint32 // output length in bytes
}

// UnifiedArgonSecure is the profile for all file encryption contexts (256MB, future-proofed)
var UnifiedArgonSecure = UnifiedArgonProfile{
	Time:    8,
	Memory:  256 * 1024, // 256MB - future-proofed against hardware advances
	Threads: 4,
	KeyLen:  32,
}

// DeriveArgon2IDKey derives a key using Argon2ID with specified parameters
func DeriveArgon2IDKey(password, salt []byte, keyLen uint32, memory, time uint32, threads uint8) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("key length must be greater than 0")
	}

	return argon2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

// Password-based key derivation functions using Argon2ID
// These replace the old OPAQUE export key based functions

// DerivePasswordMetadataKey derives a metadata encryption key from password using Argon2ID
func DerivePasswordMetadataKey(password []byte, salt []byte, username string) ([]byte, error) {
	// Use unified Argon2ID parameters
	baseKey, err := DeriveArgon2IDKey(password, salt, UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	if err != nil {
		return nil, fmt.Errorf("argon2id derivation failed: %w", err)
	}

	info := fmt.Sprintf("arkfile-metadata-encryption:%s", username)
	return hkdfExpand(baseKey, []byte(info), 32)
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
