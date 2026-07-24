package auth

import (
	"database/sql"
	"fmt"
)

const (
	MFAMethodTOTP     = "totp"
	MFAMethodWebAuthn = "webauthn"
)

// MFAChallenge is the post-OPAQUE MFA contract returned to all clients.
// When RequiresSetup is true, Methods is empty and PendingMethod may name an in-progress enrollment.
// When RequiresSetup is false, Methods lists every completed factor (always present, including length 1).
type MFAChallenge struct {
	RequiresSetup bool
	Methods       []MFALoginMethod
	PendingMethod string
}

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

// BuildMFAChallenge builds the MFA step after successful OPAQUE password auth.
func BuildMFAChallenge(db *sql.DB, username string) (*MFAChallenge, error) {
	completed, err := CountCompletedMethods(db, username)
	if err != nil {
		return nil, err
	}
	if completed == 0 {
		pending, pendingErr := GetPendingMFAMethodType(db, username)
		if pendingErr != nil {
			return nil, pendingErr
		}
		return &MFAChallenge{
			RequiresSetup: true,
			Methods:       []MFALoginMethod{},
			PendingMethod: pending,
		}, nil
	}

	methods, err := ListCompletedLoginMethods(db, username)
	if err != nil {
		return nil, err
	}
	if methods == nil {
		methods = []MFALoginMethod{}
	}
	return &MFAChallenge{
		RequiresSetup: false,
		Methods:       methods,
	}, nil
}

// ApplyMFAChallenge writes the canonical MFA fields into a JSON response data map.
// Always sets requires_mfa, requires_mfa_setup, and mfa_methods (never null).
// Sets pending_mfa_method only when setup is required and a pending enrollment exists.
func ApplyMFAChallenge(dst map[string]interface{}, ch *MFAChallenge) {
	if dst == nil || ch == nil {
		return
	}
	dst["requires_mfa"] = true
	dst["requires_mfa_setup"] = ch.RequiresSetup
	if ch.RequiresSetup {
		dst["mfa_methods"] = []MFALoginMethod{}
		if ch.PendingMethod != "" {
			dst["pending_mfa_method"] = ch.PendingMethod
		}
		return
	}
	methods := ch.Methods
	if methods == nil {
		methods = []MFALoginMethod{}
	}
	dst["mfa_methods"] = methods
}
