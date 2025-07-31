package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ShareArgonProfile defines Argon2ID parameters specifically for share password derivation
type ShareArgonProfile struct {
	Time    uint32 // iterations
	Memory  uint32 // KB
	Threads uint8  // parallelism
	KeyLen  uint32 // output length in bytes
}

// ShareArgonSecure is the profile for share password derivation (128MB, high security)
var ShareArgonSecure = ShareArgonProfile{
	Time:    4,
	Memory:  128 * 1024, // 128MB - ASIC resistant
	Threads: 4,
	KeyLen:  32,
}

// DeriveShareKey derives a key from share password using Argon2ID with secure parameters
// This is ONLY for anonymous share access, not for authenticated operations
func DeriveShareKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, ShareArgonSecure.Time, ShareArgonSecure.Memory, ShareArgonSecure.Threads, ShareArgonSecure.KeyLen)
}

// GenerateSecureSalt generates a cryptographically secure random salt
func GenerateSecureSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
