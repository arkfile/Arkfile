package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
)

// GenerateRandomBytes creates a slice of bytes with a specified length,
// filled with cryptographically secure random data.
func GenerateRandomBytes(length int) []byte {
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		// This is a critical failure, as the OS's entropy source is failing.
		// In a real-world application, this should be handled with more care.
		panic("failed to generate random bytes: " + err.Error())
	}
	return randomBytes
}

// SecureCompare performs a constant-time comparison of two byte slices
// to prevent timing attacks.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SecureZeroBytes securely zeros out a byte slice to prevent sensitive
// data from lingering in memory.
func SecureZeroBytes(slice []byte) {
	for i := range slice {
		slice[i] = 0
	}
}

// ValidateOPAQUEExportKey validates that an OPAQUE export key has the correct format
func ValidateOPAQUEExportKey(exportKey []byte) error {
	if len(exportKey) != 64 {
		return fmt.Errorf("OPAQUE export key must be exactly 64 bytes, got %d", len(exportKey))
	}

	// Check that key is not all zeros (indicates invalid/missing key)
	allZeros := true
	for _, b := range exportKey {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return fmt.Errorf("OPAQUE export key cannot be all zeros")
	}

	return nil
}

// DeriveSecureSessionFromOPAQUE derives a session key from OPAQUE export key using HKDF
func DeriveSecureSessionFromOPAQUE(exportKey []byte) ([]byte, error) {
	if err := ValidateOPAQUEExportKey(exportKey); err != nil {
		return nil, fmt.Errorf("invalid export key: %w", err)
	}

	// Use the session key derivation from crypto/session.go
	return DeriveSessionKey(exportKey, SessionKeyContext)
}
