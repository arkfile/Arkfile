package crypto

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

const (
	MFAUserKeyContext = "ARKFILE_MFA_USER_KEY"
)

// DeriveMFAUserKey derives a user-specific MFA credential encryption key from the loaded user-secret master.
func DeriveMFAUserKey(username string) ([]byte, error) {
	baseSubkey, err := DeriveUserSecretSubkey([]byte("mfa_user"))
	if err != nil {
		return nil, fmt.Errorf("failed to derive MFA user subkey: %w", err)
	}
	return deriveMFAUserKeyFromSubkey(baseSubkey, username)
}

// DeriveMFAUserKeyFromMaster derives a per-user MFA key from an explicit user-secret master.
func DeriveMFAUserKeyFromMaster(master []byte, username string) ([]byte, error) {
	baseSubkey, err := DeriveUserSecretSubkeyFromMaster(master, []byte("mfa_user"))
	if err != nil {
		return nil, fmt.Errorf("failed to derive MFA user subkey: %w", err)
	}
	return deriveMFAUserKeyFromSubkey(baseSubkey, username)
}

func deriveMFAUserKeyFromSubkey(baseSubkey []byte, username string) ([]byte, error) {
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
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
