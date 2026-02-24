package crypto

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// Session key contexts for domain separation
const (
	SessionKeyContext     = "ARKFILE_SESSION_KEY"
	JWTSigningContext     = "ARKFILE_JWT_SIGNING"
	TOTPEncryptionContext = "ARKFILE_TOTP_ENCRYPTION"
)

// DeriveSessionKey derives a session key from OPAQUE export key with domain separation
func DeriveSessionKey(opaqueExportKey []byte, context string) ([]byte, error) {

	if len(opaqueExportKey) == 0 {
		return nil, fmt.Errorf("OPAQUE export key cannot be empty")
	}

	// Use HKDF-SHA256 for key derivation with domain separation
	hkdf := hkdf.New(sha256.New, opaqueExportKey, nil, []byte(context))

	sessionKey := make([]byte, 32) // 256-bit session key
	if _, err := hkdf.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	return sessionKey, nil
}

// DeriveJWTSigningMaterial derives JWT signing material from session key
// This provides domain separation for JWT tokens
func DeriveJWTSigningMaterial(sessionKey []byte, username string) ([]byte, error) {
	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("session key must be 32 bytes")
	}
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	// Create context with username for per-user JWT material
	context := fmt.Sprintf("%s:%s", JWTSigningContext, username)

	hkdf := hkdf.New(sha256.New, sessionKey, nil, []byte(context))

	jwtMaterial := make([]byte, 32) // 256-bit JWT signing material
	if _, err := hkdf.Read(jwtMaterial); err != nil {
		return nil, fmt.Errorf("failed to derive JWT signing material: %w", err)
	}

	return jwtMaterial, nil
}

// ValidateSessionKey checks if a session key has the expected properties
func ValidateSessionKey(sessionKey []byte) error {
	if len(sessionKey) != 32 {
		return fmt.Errorf("session key must be exactly 32 bytes, got %d", len(sessionKey))
	}

	// Check that the key is not all zeros
	allZero := true
	for _, b := range sessionKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("session key cannot be all zeros")
	}

	return nil
}

// SessionKeyInfo contains metadata about a session key
type SessionKeyInfo struct {
	Username  string
	DerivedAt int64  // Unix timestamp
	Context   string // The context used for derivation
	KeyLength int    // Length in bytes
	IsValid   bool   // Whether the key passed validation
}

// CreateSessionKeyInfo creates metadata for a session key
func CreateSessionKeyInfo(username, context string, sessionKey []byte) SessionKeyInfo {
	info := SessionKeyInfo{
		Username:  username,
		Context:   context,
		KeyLength: len(sessionKey),
		IsValid:   ValidateSessionKey(sessionKey) == nil,
	}

	return info
}

// SecureZeroSessionKey securely clears session key material
func SecureZeroSessionKey(sessionKey []byte) {
	if sessionKey != nil {
		SecureClear(sessionKey)
	}
}
