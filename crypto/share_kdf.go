package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// DeriveShareKey derives a key from share password using Argon2ID with unified parameters
// This is ONLY for anonymous share access, not for authenticated operations
func DeriveShareKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, UnifiedArgonSecure.Time, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Threads, UnifiedArgonSecure.KeyLen)
}

// DeriveAccountPasswordKey derives a key from account password using unified Argon2ID parameters
func DeriveAccountPasswordKey(password []byte, username string) []byte {
	salt := GenerateUserKeySalt(username, "account")
	return argon2.IDKey(password, salt, UnifiedArgonSecure.Time, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Threads, UnifiedArgonSecure.KeyLen)
}

// DeriveCustomPasswordKey derives a key from custom password using unified Argon2ID parameters
func DeriveCustomPasswordKey(password []byte, username string) []byte {
	salt := GenerateUserKeySalt(username, "custom")
	return argon2.IDKey(password, salt, UnifiedArgonSecure.Time, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Threads, UnifiedArgonSecure.KeyLen)
}

// DeriveSharePasswordKey derives a key from share password using unified Argon2ID parameters
func DeriveSharePasswordKey(password []byte, username string) []byte {
	salt := GenerateUserKeySalt(username, "share")
	return argon2.IDKey(password, salt, UnifiedArgonSecure.Time, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Threads, UnifiedArgonSecure.KeyLen)
}

// GenerateUserKeySalt creates a deterministic salt from username and key type
// This allows offline key derivation without storing additional metadata
func GenerateUserKeySalt(username, keyType string) []byte {
	// Create deterministic salt: SHA-256(username + keyType)
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(keyType))
	return h.Sum(nil)
}

// GenerateSecureSalt generates a cryptographically secure random salt
func GenerateSecureSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
