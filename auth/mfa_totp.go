package auth

import (
	"crypto/sha256"
	"crypto/subtle"
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
	return validateTOTPCodeAt(db, username, code, time.Now().UTC())
}

// validateTOTPCodeAt validates a TOTP code as of the given time. Replay protection is
// keyed on the time step the code belongs to, so each code is accepted at most once
// across all server windows in which skew still accepts it.
func validateTOTPCodeAt(db *sql.DB, username, code string, now time.Time) error {
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

	codeWindowStart, matched, err := matchTOTPWindow(secret, code, now)
	if err != nil {
		return fmt.Errorf("TOTP validation error: %w", err)
	}

	if !matched {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP code mismatch for user: %s, window_start: %d, skew: %d",
				username, now.Truncate(time.Duration(TOTPPeriod)*time.Second).Unix(), TOTPSkew)
		}
		recordMFAFailureAndEmit(db, username, now)
		return fmt.Errorf("invalid TOTP code")
	}

	if err := recordTOTPUsageOnce(db, username, code, codeWindowStart); err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP replay detected for user: %s", username)
		}
		return fmt.Errorf("replay attack detected: %w", err)
	}

	clearMFAFailuresIfLocked(db, username, lockState)

	updateMethodLastUsed(db, username, MFAMethodTOTP)

	return nil
}

// matchTOTPWindow reports which accepted window (current, previous, or next within
// TOTPSkew) the code belongs to, returning that window's start as a Unix timestamp.
func matchTOTPWindow(secret, code string, now time.Time) (int64, bool, error) {
	period := time.Duration(TOTPPeriod) * time.Second
	current := now.Truncate(period)
	offsets := []int{0}
	for i := 1; i <= TOTPSkew; i++ {
		offsets = append(offsets, -i, i)
	}

	for _, offset := range offsets {
		windowStart := current.Add(time.Duration(offset) * period)
		expected, err := totp.GenerateCodeCustom(secret, windowStart, totp.ValidateOpts{
			Period:    TOTPPeriod,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false, err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return windowStart.Unix(), true, nil
		}
	}
	return 0, false, nil
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

// recordTOTPUsageOnce records a code under the window it belongs to, failing if that
// code was already recorded. Check and insert run as one statement so concurrent
// requests carrying the same code cannot both succeed.
func recordTOTPUsageOnce(db *sql.DB, username, code string, codeWindowStart int64) error {
	codeHash := hashString(code)

	result, err := db.Exec(`
		INSERT INTO mfa_usage_log (username, code_hash, window_start)
		SELECT ?, ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM mfa_usage_log
			WHERE username = ? AND code_hash = ? AND window_start = ?
		)`,
		username, codeHash, codeWindowStart,
		username, codeHash, codeWindowStart,
	)
	if err != nil {
		return fmt.Errorf("failed to record TOTP usage: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to record TOTP usage: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("code already used")
	}
	return nil
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
