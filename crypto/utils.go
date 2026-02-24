package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return b
}

// EncodeBase64 encodes bytes to base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes base64 string to bytes
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// SecureClear securely clears sensitive data from memory
func SecureClear(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// DecryptWithNonce decrypts data using AES-256-GCM with a provided nonce
// This is used when the nonce is stored separately (e.g., in database)
func DecryptWithNonce(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Combine nonce + ciphertext for DecryptGCM
	combined := append(nonce, ciphertext...)

	return DecryptGCM(combined, key)
}

// SecureCompare performs constant-time comparison of two byte slices
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
