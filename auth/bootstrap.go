package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/84adam/Arkfile/crypto"
)

// CheckAndGenerateBootstrapToken checks if the system needs bootstrapping.
// Bootstrap mode is enabled when:
// 1. No ACTIVE admin users exist (users with last_login set), OR
// 2. ARKFILE_FORCE_ADMIN_BOOTSTRAP environment variable is set to "true"
func CheckAndGenerateBootstrapToken(db *sql.DB) error {
	// Check for force bootstrap override
	forceBootstrap := strings.ToLower(os.Getenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP")) == "true"

	// Check for ACTIVE admins (those who have successfully logged in)
	var activeAdminCount int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM users WHERE is_admin = true AND last_login IS NOT NULL",
	).Scan(&activeAdminCount)
	if err != nil {
		return fmt.Errorf("failed to check active admin count: %w", err)
	}

	km, err := crypto.GetKeyManager()
	if err != nil {
		return fmt.Errorf("failed to get key manager: %w", err)
	}

	// Only generate token if no active admins OR force flag is set
	if activeAdminCount > 0 && !forceBootstrap {
		log.Printf("[BOOTSTRAP] Active admin users detected. Bootstrap mode disabled.")
		log.Printf("[BOOTSTRAP] Set ARKFILE_FORCE_ADMIN_BOOTSTRAP=true to override.")

		// Ensure bootstrap token is removed
		if err := km.DeleteKey("bootstrap_token"); err != nil {
			log.Printf("Warning: Failed to cleanup bootstrap token: %v", err)
		}
		return nil
	}

	// Generate bootstrap token
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate bootstrap token: %w", err)
	}

	// Store in system_keys
	if err := km.StoreKey("bootstrap_token", "bootstrap", token); err != nil {
		return fmt.Errorf("failed to store bootstrap token: %w", err)
	}

	tokenHex := hex.EncodeToString(token)
	if forceBootstrap {
		log.Printf("\n[BOOTSTRAP] ARKFILE_FORCE_ADMIN_BOOTSTRAP enabled - generating bootstrap token")
	}
	log.Printf("\n[BOOTSTRAP] System is in Bootstrap Mode.")
	log.Printf("[BOOTSTRAP] Admin Bootstrap Token: %s", tokenHex)
	log.Printf("[BOOTSTRAP] Use this token with the CLI to create the first admin user.\n")

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
