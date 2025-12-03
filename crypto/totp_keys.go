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

// InitializeTOTPMasterKey loads or generates the TOTP master key using KeyManager
func InitializeTOTPMasterKey() error {
	totpOnce.Do(func() {
		km, err := GetKeyManager()
		if err != nil {
			totpError = fmt.Errorf("failed to get KeyManager: %w", err)
			return
		}

		// Retrieve or generate the 32-byte master key
		// We use "totp_master_key_v1" as the ID and "totp" as the type context
		key, err := km.GetOrGenerateKey("totp_master_key_v1", "totp", 32)
		if err != nil {
			totpError = fmt.Errorf("failed to get/generate TOTP master key: %w", err)
			return
		}

		if len(key) != 32 {
			totpError = fmt.Errorf("invalid TOTP master key length: expected 32 bytes, got %d", len(key))
			return
		}

		totpMasterKey = key
	})

	return totpError
}

// DeriveTOTPUserKey derives a user-specific TOTP encryption key from the master key
// This key remains consistent for the user across all sessions
func DeriveTOTPUserKey(username string) ([]byte, error) {
	if err := InitializeTOTPMasterKey(); err != nil {
		return nil, err
	}

	if len(totpMasterKey) == 0 {
		return nil, fmt.Errorf("TOTP master key not initialized")
	}

	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	// Use HKDF to derive user-specific key with domain separation
	context := fmt.Sprintf("%s:%s", TOTPUserKeyContext, username)

	hkdf := hkdf.New(sha256.New, totpMasterKey, nil, []byte(context))

	userKey := make([]byte, 32)
	if _, err := hkdf.Read(userKey); err != nil {
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
		SecureZeroBytes(key)
	}
}
