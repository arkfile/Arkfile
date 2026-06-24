package handlers

import (
	"net/http"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// AdminResetUserMFARequest is the body for admin MFA reset.
type AdminResetUserMFARequest struct {
	Confirm      bool   `json:"confirm"`
	CredentialID string `json:"credential_id,omitempty"`
}

// AdminResetUserMFA clears MFA enrollment for a user (full or credential-scoped).
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

	if _, err := models.GetUserByUsername(database.DB, targetUsername); err != nil {
		return JSONError(c, http.StatusNotFound, "User not found")
	}

	var stats auth.AdminMFAResetStats
	var err error
	if req.CredentialID != "" {
		stats, err = auth.AdminScopedResetUserMFA(database.DB, targetUsername, req.CredentialID)
	} else {
		stats, err = auth.AdminFullResetUserMFA(database.DB, targetUsername)
	}
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
			"credential_id":        req.CredentialID,
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
		"credential_id":        req.CredentialID,
		"already_reset":        stats.AlreadyReset,
		"credentials_deleted":  stats.CredentialsDeleted,
		"backup_codes_deleted": stats.BackupCodesDeleted,
		"usage_logs_deleted":   stats.UsageLogsDeleted,
		"backup_usage_deleted": stats.BackupUsageDeleted,
		"force_logout":         forceLogout,
	})
}

// AdminListUserMFACredentials lists non-secret MFA metadata for admin operations.
func AdminListUserMFACredentials(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}

	summaries, err := auth.ListAdminCredentialSummaries(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to list admin MFA credentials for %s: %v", targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to list MFA credentials")
	}

	return JSONResponse(c, http.StatusOK, "MFA credentials retrieved", map[string]interface{}{
		"credentials": summaries,
	})
}
