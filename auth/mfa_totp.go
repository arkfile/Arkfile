package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/logging"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ValidateTOTPCode validates a TOTP code with replay protection and shared MFA lockout.
func ValidateTOTPCode(db *sql.DB, username, code string) error {
	now := time.Now().UTC()
	lockState, err := getMFALockoutState(db, username)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check MFA lockout state: %w", err)
	}
	if err := checkMFALockout(db, username, now); err != nil {
		return err
	}

	mfaData, err := getMFADataByMethod(db, username, MFAMethodTOTP)
	if err != nil {
		return fmt.Errorf("failed to get MFA data: %w", err)
	}

	if !mfaData.Enabled || !mfaData.SetupCompleted {
		return fmt.Errorf("MFA not enabled for user")
	}

	secret, err := decryptTOTPSecret(mfaData.SecretEncrypted, username)
	if err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP decrypt failed for user: %s", username)
		}
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	currentTime := time.Now().UTC()
	windowStart := currentTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	valid, err := totp.ValidateCustom(code, secret, currentTime, totp.ValidateOpts{
		Period:    TOTPPeriod,
		Skew:      uint(TOTPSkew),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("TOTP validation error: %w", err)
	}

	if !valid {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP code mismatch for user: %s, window_start: %d, skew: %d",
				username, windowStart, TOTPSkew)
		}
		recordMFAFailureAndEmit(db, username, now)
		return fmt.Errorf("invalid TOTP code")
	}

	if err := checkTOTPReplay(db, username, code, currentTime); err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP replay detected for user: %s", username)
		}
		return fmt.Errorf("replay attack detected: %w", err)
	}

	clearMFAFailuresIfLocked(db, username, lockState)

	if err := logTOTPUsage(db, username, code, currentTime); err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to log TOTP usage: %v", err)
		}
	}

	updateMethodLastUsed(db, username, MFAMethodTOTP)

	return nil
}

// CanDecryptMFASecret checks whether a user's MFA credential blob decrypts (dev diagnostic helper).
func CanDecryptMFASecret(db *sql.DB, username string) (present bool, decryptable bool, enabled bool, setupCompleted bool, err error) {
	row, err := GetCredentialByMethod(db, username, MFAMethodTOTP)
	if err != nil {
		if err == sql.ErrNoRows {
			row, err = GetCredentialByMethod(db, username, MFAMethodWebAuthn)
		}
		if err != nil {
			if err == sql.ErrNoRows {
				return false, false, false, false, nil
			}
			return false, false, false, false, err
		}
	}

	present = true
	enabled = row.Enabled
	setupCompleted = row.SetupCompleted

	if row.MethodType == MFAMethodTOTP {
		_, decryptErr := decryptTOTPSecret(row.CredentialData, username)
		decryptable = decryptErr == nil
	} else {
		_, decryptErr := loadWebAuthnCredentialFromRow(username, row.CredentialData)
		decryptable = decryptErr == nil
	}

	return present, decryptable, enabled, setupCompleted, nil
}

func validateTOTPCodeInternal(secret, code string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    TOTPPeriod,
		Skew:      uint(TOTPSkew),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return valid
}

func checkTOTPReplay(db *sql.DB, username, code string, testTime time.Time) error {
	codeHash := hashString(code)
	windowStart := testTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM mfa_usage_log 
		WHERE username = ? AND code_hash = ? AND window_start = ?`,
		username, codeHash, windowStart,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check replay: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("code already used")
	}
	return nil
}

func logTOTPUsage(db *sql.DB, username, code string, testTime time.Time) error {
	codeHash := hashString(code)
	windowStart := testTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	_, err := db.Exec(`
		INSERT INTO mfa_usage_log (username, code_hash, window_start) 
		VALUES (?, ?, ?)`,
		username, codeHash, windowStart,
	)
	return err
}

func decryptTOTPSecret(encrypted []byte, username string) (string, error) {
	mfaKey, err := crypto.DeriveMFAUserKey(username)
	if err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("MFA key derivation failed for user: %s, error: %v", username, err)
		}
		return "", err
	}
	defer crypto.SecureZeroMFAKey(mfaKey)

	decrypted, err := crypto.DecryptGCM(encrypted, mfaKey)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}
