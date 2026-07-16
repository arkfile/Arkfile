package handlers

import (
	"database/sql"
	"fmt"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
)

// revokeUserAccess sets is_approved=false and terminates all refresh tokens and
// JWTs for the target user. Used by AdminRevokeUser and by force-logout flows
// that also unapprove. Idempotent when the user is already unapproved.
func revokeUserAccess(db *sql.DB, targetUsername, adminUsername, jwtRevokeReason string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var isApproved bool
	err = tx.QueryRow(`SELECT is_approved FROM users WHERE username = ?`, targetUsername).Scan(&isApproved)
	if err == sql.ErrNoRows {
		return sql.ErrNoRows
	}
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}

	if _, err := tx.Exec(`UPDATE users SET is_approved = 0 WHERE username = ?`, targetUsername); err != nil {
		return fmt.Errorf("update approval: %w", err)
	}

	if err := LogAdminAction(tx, adminUsername, "revoke_user", targetUsername, "User access revoked"); err != nil {
		return fmt.Errorf("log admin action: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	if err := models.RevokeAllUserTokens(db, targetUsername); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if err := auth.RevokeAllUserJWTTokens(db, targetUsername, jwtRevokeReason); err != nil {
		return fmt.Errorf("revoke JWTs: %w", err)
	}

	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "user_revoke",
			"target_username": targetUsername,
			"was_approved":    isApproved,
		},
	)

	return nil
}

// terminateUserSessions revokes refresh tokens and JWTs without changing approval.
func terminateUserSessions(username, reason string) error {
	if err := models.RevokeAllUserTokens(database.DB, username); err != nil {
		return err
	}
	return auth.RevokeAllUserJWTTokens(database.DB, username, reason)
}
