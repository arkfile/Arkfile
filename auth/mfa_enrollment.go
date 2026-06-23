package auth

import (
	"database/sql"
	"fmt"

	"github.com/84adam/Arkfile/crypto"
)

// ShouldIssueBackupCodes reports whether a setup flow should generate and persist new backup codes.
func ShouldIssueBackupCodes(db *sql.DB, username string) (bool, error) {
	count, err := CountCompletedMethods(db, username)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func storeBackupCodes(db *sql.DB, username string, codes []string, replaceExisting bool) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := storeBackupCodesTx(tx, username, codes, replaceExisting); err != nil {
		return err
	}
	return tx.Commit()
}

func storeBackupCodesTx(tx *sql.Tx, username string, codes []string, replaceExisting bool) error {
	if replaceExisting {
		if _, err := tx.Exec(`DELETE FROM user_mfa_backup_codes WHERE username = ?`, username); err != nil {
			return err
		}
	}
	for i, code := range codes {
		salt := deriveBackupCodeSalt(username, i)
		hash, err := deriveBackupCodeHash(code, salt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(
			`INSERT INTO user_mfa_backup_codes (username, code_index, code_hash) VALUES (?, ?, ?)`,
			username, i, hash,
		)
		if err != nil {
			return fmt.Errorf("store backup code: %w", err)
		}
	}
	return nil
}

// RegenerateBackupCodes replaces all backup codes for a user with a fresh set.
func RegenerateBackupCodes(db *sql.DB, username string) ([]string, error) {
	hasMFA, err := HasCompletedMFA(db, username)
	if err != nil {
		return nil, err
	}
	if !hasMFA {
		return nil, fmt.Errorf("MFA must be enabled before regenerating backup codes")
	}

	codes, err := generateBackupCodesResilient(BackupCodeCount)
	if err != nil {
		return nil, err
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := storeBackupCodesTx(tx, username, codes, true); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// CanAddMFAMethod reports whether the user may enroll the given method type.
func CanAddMFAMethod(db *sql.DB, username, methodType string) error {
	switch methodType {
	case MFAMethodTOTP, MFAMethodWebAuthn:
	default:
		return fmt.Errorf("unsupported MFA method type")
	}

	exists, err := HasMethodRow(db, username, methodType)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%s already enrolled or pending setup", methodType)
	}

	completed, err := CountCompletedMethods(db, username)
	if err != nil {
		return err
	}
	if completed >= MaxMFAMethodsPerUser {
		return fmt.Errorf("maximum number of MFA methods reached")
	}
	return nil
}

func deriveBackupCodeHash(code string, salt []byte) ([]byte, error) {
	return crypto.DeriveArgon2IDKey(
		[]byte(code),
		salt,
		crypto.UnifiedArgonSecure.KeyLen,
		crypto.UnifiedArgonSecure.Memory,
		crypto.UnifiedArgonSecure.Time,
		crypto.UnifiedArgonSecure.Threads,
	)
}
