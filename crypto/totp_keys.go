package crypto

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	// TOTP key contexts for domain separation
	TOTPMasterKeyContext = "ARKFILE_TOTP_MASTER_KEY"
	TOTPUserKeyContext   = "ARKFILE_TOTP_USER_KEY"
)

var (
	totpMasterKey []byte
	totpOnce      sync.Once
	totpError     error
)

// InitializeTOTPMasterKey loads or generates the TOTP master key using KeyManager (no-op in Tier-3, but kept for signature compatibility)
func InitializeTOTPMasterKey() error {
	return nil
}

// DeriveTOTPUserKey derives a user-specific TOTP encryption key from the Tier-3 master key.
// This key remains consistent for the user across all sessions.
func DeriveTOTPUserKey(username string) ([]byte, error) {
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	// Use Derived Tier-3 Master '"totp_user"' purpose key
	baseSubkey, err := DeriveTier3Subkey([]byte("totp_user"))
	if err != nil {
		return nil, fmt.Errorf("failed to derive Tier-3 user core subkey: %w", err)
	}

	// Use HKDF to derive user-specific key with domain separation
	context := fmt.Sprintf("%s:%s", TOTPUserKeyContext, username)

	hk := hkdf.New(sha256.New, baseSubkey, nil, []byte(context))

	userKey := make([]byte, 32)
	if _, err := hk.Read(userKey); err != nil {
		return nil, fmt.Errorf("failed to derive TOTP user key: %w", err)
	}

	return userKey, nil
}

// GetTOTPMasterKeyStatus returns information about the TOTP master key
func GetTOTPMasterKeyStatus() (bool, int) {
	if err := InitializeTOTPMasterKey(); err != nil {
		return false, 0
	}
	return len(totpMasterKey) > 0, len(totpMasterKey)
}

// SecureZeroTOTPKey clears a TOTP key from memory
func SecureZeroTOTPKey(key []byte) {
	if key != nil {
		SecureClear(key)
	}
}
