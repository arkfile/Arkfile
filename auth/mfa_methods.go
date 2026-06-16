package auth

import (
	"database/sql"
	"fmt"
)

const (
	MFAMethodTOTP      = "totp"
	MFAMethodWebAuthn  = "webauthn"
)

// GetUserMFAMethodType returns the enrolled method_type for a user with completed MFA.
// Returns empty string when MFA is not enabled or no row exists.
func GetUserMFAMethodType(db *sql.DB, username string) (string, error) {
	var methodType string
	var enabled bool
	var setupCompleted bool

	err := db.QueryRow(`
		SELECT method_type, enabled, setup_completed
		FROM user_mfa_credentials
		WHERE username = ?`, username,
	).Scan(&methodType, &enabled, &setupCompleted)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("failed to load MFA method: %w", err)
	}

	if !enabled || !setupCompleted {
		return "", nil
	}

	return methodType, nil
}

// GetPendingMFAMethodType returns method_type for an in-progress enrollment row.
func GetPendingMFAMethodType(db *sql.DB, username string) (string, error) {
	var methodType string
	var setupCompleted bool

	err := db.QueryRow(`
		SELECT method_type, setup_completed
		FROM user_mfa_credentials
		WHERE username = ?`, username,
	).Scan(&methodType, &setupCompleted)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("failed to load pending MFA method: %w", err)
	}

	if setupCompleted {
		return "", nil
	}

	return methodType, nil
}
