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

// ValidatePasswordStrength validates that a password meets minimum requirements
func ValidatePasswordStrength(password []byte) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long, got %d", len(password))
	}

	if len(password) > 256 {
		return fmt.Errorf("password too long: maximum 256 characters, got %d", len(password))
	}

	// Check that password is not all the same character
	if len(password) > 1 {
		firstChar := password[0]
		allSame := true
		for _, b := range password[1:] {
			if b != firstChar {
				allSame = false
				break
			}
		}
		if allSame {
			return fmt.Errorf("password cannot be all the same character")
		}
	}

	return nil
}

// DeriveSecureSessionFromPassword derives a session key from password using Argon2ID
func DeriveSecureSessionFromPassword(password []byte, username string) ([]byte, error) {
	if err := ValidatePasswordStrength(password); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	// Derive session key using account password derivation
	sessionKey := DeriveAccountPasswordKey(password, username)

	// Use HKDF to derive final session key
	return DeriveSessionKey(sessionKey, SessionKeyContext)
}
