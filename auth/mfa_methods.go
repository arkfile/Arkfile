package auth

import (
	"database/sql"
	"fmt"
)

const (
	MFAMethodTOTP     = "totp"
	MFAMethodWebAuthn = "webauthn"
)

// GetUserMFAMethodType returns one enrolled method when exactly one is completed.
func GetUserMFAMethodType(db *sql.DB, username string) (string, error) {
	methods, err := ListCompletedLoginMethods(db, username)
	if err != nil {
		return "", fmt.Errorf("failed to load MFA methods: %w", err)
	}
	if len(methods) != 1 {
		return "", nil
	}
	return methods[0].Type, nil
}

// GetPendingMFAMethodType returns method_type for an in-progress enrollment row.
func GetPendingMFAMethodType(db *sql.DB, username string) (string, error) {
	var methodType string

	err := db.QueryRow(`
		SELECT method_type
		FROM user_mfa_credentials
		WHERE username = ? AND setup_completed = 0
		ORDER BY created_at DESC
		LIMIT 1`, username,
	).Scan(&methodType)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("failed to load pending MFA method: %w", err)
	}
	return methodType, nil
}

// BuildMFALoginResponse builds login metadata after OPAQUE password auth.
func BuildMFALoginResponse(db *sql.DB, username string) (requiresSetup bool, methods []MFALoginMethod, singleMethod string, err error) {
	completed, err := CountCompletedMethods(db, username)
	if err != nil {
		return false, nil, "", err
	}
	if completed == 0 {
		pending, pendingErr := GetPendingMFAMethodType(db, username)
		if pendingErr != nil {
			return false, nil, "", pendingErr
		}
		return true, nil, pending, nil
	}

	methods, err = ListCompletedLoginMethods(db, username)
	if err != nil {
		return false, nil, "", err
	}
	if len(methods) == 1 {
		singleMethod = methods[0].Type
	}
	return false, methods, singleMethod, nil
}
