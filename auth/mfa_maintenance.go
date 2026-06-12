package auth

import (
	"database/sql"
	"fmt"
	"time"
)

// CleanupMFALogs removes old MFA usage and backup-code replay logs.
func CleanupMFALogs(db *sql.DB) error {
	cutoff := time.Now().Add(-2 * time.Minute)

	_, err := db.Exec("DELETE FROM mfa_usage_log WHERE used_at < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to clean MFA usage logs: %w", err)
	}

	backupCutoff := time.Now().Add(-30 * 24 * time.Hour)
	_, err = db.Exec("DELETE FROM mfa_backup_usage WHERE used_at < ?", backupCutoff)
	if err != nil {
		return fmt.Errorf("failed to clean backup code usage logs: %w", err)
	}

	return nil
}
