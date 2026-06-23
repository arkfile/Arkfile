package handlers

import (
	"net/http"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/labstack/echo/v4"
)

type mfaCredentialLabelRequest struct {
	Label string `json:"label"`
}

// ListMFACredentials returns the authenticated user's enrolled MFA methods.
func ListMFACredentials(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	summaries, err := auth.ListUserCredentialSummaries(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to list MFA credentials for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to list MFA credentials")
	}

	return JSONResponse(c, http.StatusOK, "MFA credentials retrieved", map[string]interface{}{
		"credentials": summaries,
	})
}

// DeleteMFACredential removes one enrolled MFA method for the authenticated user.
func DeleteMFACredential(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	credentialID := c.Param("credential_id")
	if credentialID == "" {
		return JSONError(c, http.StatusBadRequest, "Credential id is required")
	}

	requiresSetup, err := auth.RemoveUserCredential(database.DB, username, credentialID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete MFA credential for %s: %v", username, err)
		return JSONError(c, http.StatusBadRequest, "Failed to remove MFA credential")
	}

	if err := models.RevokeAllUserTokens(database.DB, username); err != nil {
		logging.ErrorLogger.Printf("Removed MFA credential for %s but failed refresh-token revoke: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Credential removed but failed to revoke sessions")
	}
	if err := auth.RevokeAllUserJWTTokens(database.DB, username, "mfa credential removed"); err != nil {
		logging.ErrorLogger.Printf("Removed MFA credential for %s but failed JWT revoke: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Credential removed but failed to revoke sessions")
	}

	database.LogUserAction(username, "removed MFA credential", credentialID)

	return JSONResponse(c, http.StatusOK, "MFA credential removed", map[string]interface{}{
		"requires_mfa_setup": requiresSetup,
		"force_logout":       true,
	})
}

// UpdateMFACredentialLabel updates the user-private label on a security key credential.
func UpdateMFACredentialLabel(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	credentialID := c.Param("credential_id")

	var req mfaCredentialLabelRequest
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	if err := auth.UpdateWebAuthnUserLabel(database.DB, username, credentialID, req.Label); err != nil {
		logging.ErrorLogger.Printf("Failed to update MFA label for %s: %v", username, err)
		return JSONError(c, http.StatusBadRequest, "Failed to update security key label")
	}

	database.LogUserAction(username, "updated security key label", credentialID)
	return JSONResponse(c, http.StatusOK, "Security key label updated", nil)
}

// RegenerateMFABackupCodes replaces all backup codes for the authenticated user.
func RegenerateMFABackupCodes(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	codes, err := auth.RegenerateBackupCodes(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to regenerate backup codes for %s: %v", username, err)
		return JSONError(c, http.StatusBadRequest, "Failed to regenerate backup codes")
	}

	database.LogUserAction(username, "regenerated MFA backup codes", "")
	return JSONResponse(c, http.StatusOK, "Backup codes regenerated", map[string]interface{}{
		"backup_codes": codes,
	})
}
