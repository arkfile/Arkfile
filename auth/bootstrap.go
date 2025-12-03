package auth

import (
	"crypto/rand"
	"crypto/subtle"
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
//
// This function is safe for multi-instance deployments - it checks if a bootstrap
// token already exists before generating a new one, preventing multiple tokens
// from being logged to different container stdout streams.
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

	// Check if bootstrap token already exists (prevents race condition in multi-instance deployments)
	existingToken, err := km.GetKey("bootstrap_token", "bootstrap")
	if err == nil && len(existingToken) > 0 {
		// Token already exists
		if !forceBootstrap {
			log.Printf("[BOOTSTRAP] Bootstrap token already exists. Use ARKFILE_FORCE_ADMIN_BOOTSTRAP=true to regenerate.")
			return nil
		}
		// Force bootstrap requested, will regenerate below
		log.Printf("[BOOTSTRAP] Force bootstrap enabled - regenerating token")
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

	// Store in system_keys (REPLACE INTO ensures database-level atomicity)
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
// Uses constant-time comparison to prevent timing attacks.
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

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(storedToken, providedToken) == 1 {
		return true, nil
	}

	return false, nil
}
