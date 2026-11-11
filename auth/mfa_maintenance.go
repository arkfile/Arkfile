package auth

import (
	"database/sql"
	"fmt"
	"time"
)

// CleanupMFALogs removes old MFA usage and backup-code replay logs.
func CleanupMFALogs(db *sql.DB) error {
	// A code stays acceptable until TOTPSkew windows after its own window ends. Compare
	// integer window starts: used_at is SQLite text and does not compare reliably against
	// driver-formatted time parameters.
	retention := time.Duration((TOTPSkew+2)*TOTPPeriod) * time.Second
	windowCutoff := time.Now().Add(-retention).Unix()

	_, err := db.Exec("DELETE FROM mfa_usage_log WHERE window_start < ?", windowCutoff)
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
