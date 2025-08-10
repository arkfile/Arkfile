package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

const (
	// TOTP key contexts for domain separation
	TOTPMasterKeyContext = "ARKFILE_TOTP_MASTER_KEY"
	TOTPUserKeyContext   = "ARKFILE_TOTP_USER_KEY"
)

var (
	totpMasterKey []byte
)

// InitializeTOTPMasterKey loads or generates the TOTP master key
func InitializeTOTPMasterKey() error {
	keyPath := "/opt/arkfile/etc/keys/totp_master.key"

	// Try to load existing key
	if keyData, err := os.ReadFile(keyPath); err == nil {
		if len(keyData) == 32 {
			totpMasterKey = keyData
			return nil
		}
	}

	// Generate new master key
	totpMasterKey = make([]byte, 32)
	if _, err := rand.Read(totpMasterKey); err != nil {
		return fmt.Errorf("failed to generate TOTP master key: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create TOTP key directory: %w", err)
	}

	// Save the key with restricted permissions
	if err := os.WriteFile(keyPath, totpMasterKey, 0600); err != nil {
		return fmt.Errorf("failed to save TOTP master key: %w", err)
	}

	// Set ownership to arkfile user if running as root
	if os.Getuid() == 0 {
		// This will fail gracefully if arkfile user doesn't exist
		os.Chown(keyPath, 1000, 1000) // Typical arkfile UID/GID
	}

	return nil
}

// DeriveTOTPUserKey derives a user-specific TOTP encryption key from the master key
// This key remains consistent for the user across all sessions
func DeriveTOTPUserKey(username string) ([]byte, error) {
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
	return len(totpMasterKey) > 0, len(totpMasterKey)
}

// RotateTOTPMasterKey generates a new master key (for maintenance operations)
// WARNING: This will invalidate all existing TOTP setups
func RotateTOTPMasterKey() error {
	// Generate new key
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return fmt.Errorf("failed to generate new TOTP master key: %w", err)
	}

	// Backup old key
	keyPath := "/opt/arkfile/etc/keys/totp_master.key"
	backupPath := keyPath + ".backup"

	if len(totpMasterKey) > 0 {
		if err := os.WriteFile(backupPath, totpMasterKey, 0600); err != nil {
			return fmt.Errorf("failed to backup old TOTP master key: %w", err)
		}
	}

	// Save new key
	if err := os.WriteFile(keyPath, newKey, 0600); err != nil {
		return fmt.Errorf("failed to save new TOTP master key: %w", err)
	}

	// Update in memory
	totpMasterKey = newKey

	return nil
}

// SecureZeroTOTPKey clears a TOTP key from memory
func SecureZeroTOTPKey(key []byte) {
	if key != nil {
		SecureZeroBytes(key)
	}
}
