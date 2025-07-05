package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ArgonProfile defines Argon2ID parameters for different device capabilities
type ArgonProfile struct {
	Time    uint32 // iterations
	Memory  uint32 // KB
	Threads uint8  // parallelism
	KeyLen  uint32 // output length in bytes
}

// Predefined profiles for different use cases
var (
	// ArgonInteractive - for client-side pre-OPAQUE hardening (mobile-friendly)
	ArgonInteractive = ArgonProfile{
		Time:    1,
		Memory:  32 * 1024, // 32MB
		Threads: 2,
		KeyLen:  32,
	}

	// ArgonBalanced - for mid-range devices
	ArgonBalanced = ArgonProfile{
		Time:    2,
		Memory:  64 * 1024, // 64MB
		Threads: 2,
		KeyLen:  32,
	}

	// ArgonMaximum - for server-side post-OPAQUE hardening (maximum security)
	ArgonMaximum = ArgonProfile{
		Time:    4,
		Memory:  128 * 1024, // 128MB
		Threads: 4,
		KeyLen:  32,
	}
)

// DeviceCapability represents detected device performance tier
type DeviceCapability int

const (
	DeviceMinimal DeviceCapability = iota
	DeviceInteractive
	DeviceBalanced
	DeviceMaximum
)

// String returns string representation of device capability
func (d DeviceCapability) String() string {
	switch d {
	case DeviceMinimal:
		return "minimal"
	case DeviceInteractive:
		return "interactive"
	case DeviceBalanced:
		return "balanced"
	case DeviceMaximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// GetProfile returns the ArgonProfile for a given device capability
func (d DeviceCapability) GetProfile() ArgonProfile {
	switch d {
	case DeviceMinimal:
		// Even more conservative than Interactive for very slow devices
		return ArgonProfile{
			Time:    1,
			Memory:  16 * 1024, // 16MB
			Threads: 1,
			KeyLen:  32,
		}
	case DeviceInteractive:
		return ArgonInteractive
	case DeviceBalanced:
		return ArgonBalanced
	case DeviceMaximum:
		return ArgonMaximum
	default:
		return ArgonInteractive // Safe default
	}
}

// DeriveKeyArgon2ID derives a key using Argon2ID with the specified profile
func DeriveKeyArgon2ID(password, salt []byte, profile ArgonProfile) []byte {
	return argon2.IDKey(password, salt, profile.Time, profile.Memory, profile.Threads, profile.KeyLen)
}

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKeyFromCapability is a convenience function that derives a key using
// the appropriate profile for the given device capability
func DeriveKeyFromCapability(password, salt []byte, capability DeviceCapability) []byte {
	profile := capability.GetProfile()
	return DeriveKeyArgon2ID(password, salt, profile)
}

// ValidateProfile checks if an ArgonProfile has reasonable parameters
func ValidateProfile(profile ArgonProfile) error {
	if profile.Time == 0 {
		return fmt.Errorf("time parameter must be greater than 0")
	}
	if profile.Memory < 1024 { // At least 1MB
		return fmt.Errorf("memory parameter must be at least 1024 KB")
	}
	if profile.Threads == 0 {
		return fmt.Errorf("threads parameter must be greater than 0")
	}
	if profile.KeyLen == 0 {
		return fmt.Errorf("key length must be greater than 0")
	}
	return nil
}

// SecureCompare performs constant-time comparison of two byte slices
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// DecodeBase64 decodes a base64 string to bytes
func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
