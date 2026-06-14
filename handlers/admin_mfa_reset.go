package handlers

import (
	"net/http"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// AdminResetUserMFARequest is the body for admin full MFA reset.
// CredentialID and Label are reserved for future credential-scoped reset (Phase 9).
type AdminResetUserMFARequest struct {
	Confirm      bool   `json:"confirm"`
	CredentialID string `json:"credential_id,omitempty"`
	Label        string `json:"label,omitempty"`
}

// AdminResetUserMFA clears all MFA enrollment for a user (full reset only in v1).
func AdminResetUserMFA(c echo.Context) error {
	targetUsername := c.Param("username")
	adminUsername := auth.GetUsernameFromToken(c)

	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}

	var req AdminResetUserMFARequest
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}
	if !req.Confirm {
		return JSONError(c, http.StatusBadRequest, "Confirmation is required for MFA reset")
	}
	if req.CredentialID != "" || req.Label != "" {
		return JSONErrorCode(c, http.StatusBadRequest, "credential_scoped_reset_unsupported",
			"Credential-scoped MFA reset is not supported yet; omit credential_id and label for a full reset")
	}

	if _, err := models.GetUserByUsername(database.DB, targetUsername); err != nil {
		return JSONError(c, http.StatusNotFound, "User not found")
	}

	stats, err := auth.AdminFullResetUserMFA(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed MFA reset for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to reset user MFA")
	}

	forceLogout := false
	if !stats.AlreadyReset {
		if err := models.RevokeAllUserTokens(database.DB, targetUsername); err != nil {
			logging.ErrorLogger.Printf("Admin %s cleared MFA for %s but failed refresh-token revoke: %v", adminUsername, targetUsername, err)
			return JSONError(c, http.StatusInternalServerError, "MFA data cleared but failed to revoke user sessions; run force-logout manually")
		}
		if err := auth.RevokeAllUserJWTTokens(database.DB, targetUsername, "admin mfa reset"); err != nil {
			logging.ErrorLogger.Printf("Admin %s cleared MFA for %s but failed JWT revoke: %v", adminUsername, targetUsername, err)
			return JSONError(c, http.StatusInternalServerError, "MFA data cleared but failed to revoke user JWTs; run force-logout manually")
		}
		forceLogout = true
	}

	database.LogUserAction(targetUsername, "MFA reset by admin", adminUsername)
	database.LogUserAction(adminUsername, "reset user MFA", targetUsername)
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":            "admin_mfa_reset",
			"target_username":      targetUsername,
			"already_reset":        stats.AlreadyReset,
			"credentials_deleted":  stats.CredentialsDeleted,
			"backup_codes_deleted": stats.BackupCodesDeleted,
			"usage_logs_deleted":   stats.UsageLogsDeleted,
			"backup_usage_deleted": stats.BackupUsageDeleted,
			"force_logout":         forceLogout,
		},
	)

	message := "User MFA reset completed"
	if stats.AlreadyReset {
		message = "User has no MFA enrollment to reset"
	}

	return JSONResponse(c, http.StatusOK, message, map[string]interface{}{
		"username":             targetUsername,
		"already_reset":        stats.AlreadyReset,
		"credentials_deleted":  stats.CredentialsDeleted,
		"backup_codes_deleted": stats.BackupCodesDeleted,
		"usage_logs_deleted":   stats.UsageLogsDeleted,
		"backup_usage_deleted": stats.BackupUsageDeleted,
		"force_logout":         forceLogout,
	})
}
