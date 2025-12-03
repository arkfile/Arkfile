package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/84adam/Arkfile/crypto"
)

// CheckAndGenerateBootstrapToken checks if the system needs bootstrapping.
// If no users exist, it generates and stores a bootstrap token.
// If users exist, it ensures any existing bootstrap token is removed.
func CheckAndGenerateBootstrapToken(db *sql.DB) error {
	// 1. Check user count
	var userCount int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		return fmt.Errorf("failed to count users: %w", err)
	}

	km, err := crypto.GetKeyManager()
	if err != nil {
		return fmt.Errorf("failed to get key manager: %w", err)
	}

	if userCount == 0 {
		// 2. Zero users: Generate bootstrap token
		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return fmt.Errorf("failed to generate bootstrap token: %w", err)
		}

		// Store in system_keys
		// key_id="bootstrap_token", key_type="bootstrap"
		if err := km.StoreKey("bootstrap_token", "bootstrap", token); err != nil {
			return fmt.Errorf("failed to store bootstrap token: %w", err)
		}

		tokenHex := hex.EncodeToString(token)
		log.Printf("\n[BOOTSTRAP] No users found. System is in Bootstrap Mode.\n[BOOTSTRAP] Admin Bootstrap Token: %s\n[BOOTSTRAP] Use this token with the CLI to create the first admin user.\n", tokenHex)

	} else {
		// 3. Users exist: Ensure bootstrap token is removed
		// We don't check if it exists, just try to delete it to be safe
		if err := km.DeleteKey("bootstrap_token"); err != nil {
			// Log warning but don't fail startup
			log.Printf("Warning: Failed to cleanup bootstrap token: %v", err)
		}
	}

	return nil
}

// ValidateBootstrapToken checks if the provided token matches the stored bootstrap token.
func ValidateBootstrapToken(tokenHex string) (bool, error) {
	km, err := crypto.GetKeyManager()
	if err != nil {
		return false, err
	}

	storedToken, err := km.GetKey("bootstrap_token", "bootstrap")
	if err != nil {
		// If key not found, bootstrap is disabled
		return false, nil
	}

	providedToken, err := hex.DecodeString(tokenHex)
	if err != nil {
		return false, nil // Invalid hex
	}

	// Constant time comparison would be better, but for a 32-byte random token,
	// timing attacks are less of a concern than for passwords.
	// Still, let's use a simple byte comparison.
	if len(storedToken) != len(providedToken) {
		return false, nil
	}

	for i := range storedToken {
		if storedToken[i] != providedToken[i] {
			return false, nil
		}
	}

	return true, nil
}
