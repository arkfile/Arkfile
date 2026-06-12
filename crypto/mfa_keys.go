package crypto

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

const (
	MFAUserKeyContext = "ARKFILE_MFA_USER_KEY"
)

// DeriveMFAUserKey derives a user-specific MFA credential encryption key from the Tier-3 master.
// This key remains consistent for the user across all sessions.
func DeriveMFAUserKey(username string) ([]byte, error) {
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	baseSubkey, err := DeriveTier3Subkey([]byte("mfa_user"))
	if err != nil {
		return nil, fmt.Errorf("failed to derive Tier-3 MFA user subkey: %w", err)
	}

	context := fmt.Sprintf("%s:%s", MFAUserKeyContext, username)

	hk := hkdf.New(sha256.New, baseSubkey, nil, []byte(context))

	userKey := make([]byte, 32)
	if _, err := hk.Read(userKey); err != nil {
		return nil, fmt.Errorf("failed to derive MFA user key: %w", err)
	}

	return userKey, nil
}

// SecureZeroMFAKey clears an MFA-derived key from memory.
func SecureZeroMFAKey(key []byte) {
	if key != nil {
		SecureClear(key)
	}
}
