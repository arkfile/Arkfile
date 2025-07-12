package crypto

import (
	"crypto/rand"
	"crypto/subtle"
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
