package auth

import (
	"database/sql"
	"fmt"
)

// AdminMFAResetStats summarizes rows removed during an admin MFA reset.
type AdminMFAResetStats struct {
	CredentialsDeleted int64
	BackupCodesDeleted int64
	UsageLogsDeleted   int64
	BackupUsageDeleted int64
	LockoutDeleted     int64
	AlreadyReset       bool
}

// AdminFullResetUserMFA deletes all MFA credentials, backup codes, usage logs, and lockout state.
func AdminFullResetUserMFA(db *sql.DB, targetUsername string) (AdminMFAResetStats, error) {
	var stats AdminMFAResetStats
	if targetUsername == "" {
		return stats, fmt.Errorf("target username is required")
	}

	var credCount, backupCount, usageCount, backupUsageCount int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_mfa_credentials WHERE username = ?`, targetUsername).Scan(&credCount); err != nil {
		return stats, fmt.Errorf("failed to count MFA credentials: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_mfa_backup_codes WHERE username = ?`, targetUsername).Scan(&backupCount); err != nil {
		return stats, fmt.Errorf("failed to count MFA backup codes: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM mfa_usage_log WHERE username = ?`, targetUsername).Scan(&usageCount); err != nil {
		return stats, fmt.Errorf("failed to count MFA usage logs: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM mfa_backup_usage WHERE username = ?`, targetUsername).Scan(&backupUsageCount); err != nil {
		return stats, fmt.Errorf("failed to count MFA backup usage logs: %w", err)
	}

	if credCount == 0 && backupCount == 0 && usageCount == 0 && backupUsageCount == 0 {
		stats.AlreadyReset = true
	}

	tx, err := db.Begin()
	if err != nil {
		return stats, fmt.Errorf("failed to start MFA reset transaction: %w", err)
	}
	defer tx.Rollback()

	deletions := []struct {
		query string
		dest  *int64
	}{
		{`DELETE FROM user_mfa_backup_codes WHERE username = ?`, &stats.BackupCodesDeleted},
		{`DELETE FROM mfa_usage_log WHERE username = ?`, &stats.UsageLogsDeleted},
		{`DELETE FROM mfa_backup_usage WHERE username = ?`, &stats.BackupUsageDeleted},
		{`DELETE FROM user_mfa_lockout WHERE username = ?`, &stats.LockoutDeleted},
		{`DELETE FROM user_mfa_credentials WHERE username = ?`, &stats.CredentialsDeleted},
	}

	for _, op := range deletions {
		res, execErr := tx.Exec(op.query, targetUsername)
		if execErr != nil {
			return stats, fmt.Errorf("failed to delete MFA data for %s: %w", targetUsername, execErr)
		}
		affected, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return stats, fmt.Errorf("failed to read MFA reset row count: %w", rowsErr)
		}
		*op.dest = affected
	}

	if err := tx.Commit(); err != nil {
		return stats, fmt.Errorf("failed to commit MFA reset transaction: %w", err)
	}

	return stats, nil
}

// AdminScopedResetUserMFA deletes one credential row. Backup codes remain if another completed credential exists.
func AdminScopedResetUserMFA(db *sql.DB, targetUsername, credentialID string) (AdminMFAResetStats, error) {
	var stats AdminMFAResetStats
	if targetUsername == "" || credentialID == "" {
		return stats, fmt.Errorf("target username and credential id are required")
	}

	row, err := GetCredentialByID(db, targetUsername, credentialID)
	if err != nil {
		return stats, err
	}
	_ = row

	tx, err := db.Begin()
	if err != nil {
		return stats, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM user_mfa_credentials WHERE username = ? AND credential_id = ?`, targetUsername, credentialID)
	if err != nil {
		return stats, err
	}
	stats.CredentialsDeleted, _ = res.RowsAffected()

	var remaining int
	if err := tx.QueryRow(`
		SELECT COUNT(*) FROM user_mfa_credentials
		WHERE username = ? AND enabled = 1 AND setup_completed = 1`,
		targetUsername,
	).Scan(&remaining); err != nil {
		return stats, err
	}

	if remaining == 0 {
		res, err = tx.Exec(`DELETE FROM user_mfa_backup_codes WHERE username = ?`, targetUsername)
		if err != nil {
			return stats, err
		}
		stats.BackupCodesDeleted, _ = res.RowsAffected()
	}

	if err := tx.Commit(); err != nil {
		return stats, err
	}
	return stats, nil
}
