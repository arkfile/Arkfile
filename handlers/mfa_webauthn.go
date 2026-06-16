package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/labstack/echo/v4"
)

type webAuthnCredentialRequest struct {
	// Accept the PublicKeyCredential JSON from the browser verbatim.
	Credential json.RawMessage `json:"credential"`
}

// WebAuthnRegisterBegin starts security-key enrollment.
func WebAuthnRegisterBegin(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	options, backupCodes, err := auth.WebAuthnRegisterBegin(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("WebAuthn register begin failed for %s: %v", username, err)
		if err.Error() == "MFA already enabled" {
			return JSONError(c, http.StatusConflict, err.Error())
		}
		return JSONError(c, http.StatusBadRequest, "Failed to start security key enrollment")
	}

	resp := map[string]interface{}{
		"options": options,
	}
	if len(backupCodes) > 0 {
		resp["backup_codes"] = backupCodes
	} else {
		resp["resume"] = true
	}

	database.LogUserAction(username, "initiated security key enrollment", "")
	return JSONResponse(c, http.StatusOK, "Security key enrollment started", resp)
}

// WebAuthnRegisterFinish completes security-key enrollment.
func WebAuthnRegisterFinish(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var req webAuthnCredentialRequest
	if err := c.Bind(&req); err != nil || len(req.Credential) == 0 {
		return JSONError(c, http.StatusBadRequest, "Invalid credential payload")
	}

	if err := auth.WebAuthnRegisterFinish(database.DB, username, req.Credential); err != nil {
		logging.ErrorLogger.Printf("WebAuthn register finish failed for %s: %v", username, err)
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("mfa_verify", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record MFA verify failure: %v", recordErr)
		}
		return JSONError(c, http.StatusBadRequest, "Security key enrollment verification failed")
	}

	if auth.RequiresMFAFromToken(c) {
		return completeMFARegistrationSetup(c, username, "OPAQUE+WebAuthn")
	}

	return JSONResponse(c, http.StatusOK, "Security key enrollment completed", map[string]interface{}{
		"enabled": true,
	})
}

// WebAuthnAuthBegin starts security-key authentication.
func WebAuthnAuthBegin(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	if !auth.RequiresMFAFromToken(c) {
		return JSONError(c, http.StatusBadRequest, "Token does not require MFA")
	}

	options, err := auth.WebAuthnAuthBegin(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("WebAuthn auth begin failed for %s: %v", username, err)
		return JSONError(c, http.StatusBadRequest, "Failed to start security key authentication")
	}

	return JSONResponse(c, http.StatusOK, "Security key authentication started", map[string]interface{}{
		"options": options,
	})
}

// WebAuthnAuthFinish completes security-key authentication.
func WebAuthnAuthFinish(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	if !auth.RequiresMFAFromToken(c) {
		return JSONError(c, http.StatusBadRequest, "Token does not require MFA")
	}

	var req webAuthnCredentialRequest
	if err := c.Bind(&req); err != nil || len(req.Credential) == 0 {
		return JSONError(c, http.StatusBadRequest, "Invalid credential payload")
	}

	if err := auth.WebAuthnAuthFinish(database.DB, username, req.Credential); err != nil {
		logging.ErrorLogger.Printf("WebAuthn auth finish failed for %s: %v", username, err)
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("mfa_auth", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record MFA auth failure: %v", recordErr)
		}
		return JSONError(c, http.StatusUnauthorized, "Security key authentication failed")
	}

	database.LogUserAction(username, "authenticated with security key", "")
	return completeMFALogin(c, username, "OPAQUE+WebAuthn")
}
