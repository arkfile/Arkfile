package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkfile/Arkfile/logging"
)

// ValidateBackupCode validates and consumes a hashed backup code (method-agnostic).
func ValidateBackupCode(db *sql.DB, username, code string) error {
	now := time.Now().UTC()
	lockState, err := getMFALockoutState(db, username)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check MFA lockout state: %w", err)
	}
	if err := checkMFALockout(db, username, now); err != nil {
		return err
	}

	if len(code) != BackupCodeLength {
		return fmt.Errorf("invalid backup code length")
	}

	perm := make([]int, BackupCodeCount)
	for i := range perm {
		perm[i] = i
	}
	shuffleIndices(perm)

	var matchedIndex = -1
	var matchedHash []byte

	for _, codeIndex := range perm {
		salt := deriveBackupCodeSalt(username, codeIndex)
		candHash, err := deriveBackupCodeHash(code, salt)
		if err != nil {
			continue
		}

		var storedHash []byte
		var usedAt sql.NullString
		err = db.QueryRow(`
			SELECT code_hash, used_at FROM user_mfa_backup_codes 
			WHERE username = ? AND code_index = ? AND code_hash = ?`,
			username, codeIndex, candHash,
		).Scan(&storedHash, &usedAt)

		if err == nil && (!usedAt.Valid || usedAt.String == "") {
			matchedIndex = codeIndex
			matchedHash = candHash
			break
		}
	}

	if matchedIndex == -1 {
		recordMFAFailureAndEmit(db, username, now)
		return fmt.Errorf("invalid backup code")
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		UPDATE user_mfa_backup_codes 
		SET used_at = ? 
		WHERE username = ? AND code_index = ? AND code_hash = ? AND used_at IS NULL`,
		time.Now().UTC(), username, matchedIndex, matchedHash,
	)
	if err != nil {
		return fmt.Errorf("failed to consume backup code: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("race condition: backup code already consumed by concurrent request")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit consumed backup code transaction: %w", err)
	}

	clearMFAFailuresIfLocked(db, username, lockState)

	if err := logBackupCodeUsage(db, username, hex.EncodeToString(matchedHash)); err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to log backup code usage: %v", err)
		}
	}

	_, err = db.Exec(`
		UPDATE user_mfa_credentials SET last_used = ?
		WHERE username = ? AND setup_completed = 1`,
		time.Now().UTC(), username)
	if err != nil && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("Failed to update MFA last_used after backup code: %v", err)
	}

	return nil
}

func deriveBackupCodeSalt(username string, index int) []byte {
	salt := sha256.Sum256([]byte(fmt.Sprintf("arkfile-backup-code-salt:%s:%d", username, index)))
	return salt[:]
}

func generateBackupCodesResilient(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := generateSingleBackupCodeResilient()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func generateSingleBackupCodeResilient() (string, error) {
	code := make([]byte, BackupCodeLength)
	charsetLen := len(BackupCodeCharset)

	for i := 0; i < BackupCodeLength; {
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("secure random failed: %w", err)
		}

		limit := 256 - (256 % charsetLen)
		val := int(randomBytes[0])
		if val < limit {
			code[i] = BackupCodeCharset[val%charsetLen]
			i++
		}
	}
	return string(code), nil
}

func shuffleIndices(slice []int) {
	n := len(slice)
	for i := n - 1; i > 0; i-- {
		b := make([]byte, 1)
		_, _ = rand.Read(b)
		j := int(b[0]) % (i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

func logBackupCodeUsage(db *sql.DB, username, codeHash string) error {
	_, err := db.Exec(`
		INSERT INTO mfa_backup_usage (username, code_hash) 
		VALUES (?, ?)`,
		username, codeHash,
	)
	return err
}
