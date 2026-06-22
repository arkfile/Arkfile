package handlers

import (
	"net/http"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/labstack/echo/v4"
)

// AdminRotateJWTKeys generates a new active version for both JWT signing tiers
// and reloads the in-memory key rings. Previous versions remain accepted for
// verification during the overlap window so existing sessions are unaffected.
func AdminRotateJWTKeys(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	result, err := auth.RotateJWTSigningKeys()
	if err != nil {
		logging.ErrorLogger.Printf("JWT key rotation failed for %s: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to rotate JWT signing keys")
	}

	logging.LogSecurityEvent(
		logging.EventKeyRotation,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":    "jwt_signing_key_rotate",
			"temp_version": result.TempVersion,
			"full_version": result.FullVersion,
		},
	)

	return JSONResponse(c, http.StatusOK, "JWT signing keys rotated", map[string]interface{}{
		"temp_version": result.TempVersion,
		"full_version": result.FullVersion,
	})
}

// adminRetireJWTKeyRequest is the body for retiring a superseded JWT version.
type adminRetireJWTKeyRequest struct {
	Version int `json:"version"`
}

// AdminRetireJWTKeyVersion removes a superseded JWT signing key version from
// both tiers. It refuses to retire the currently active version. Call only
// after the overlap window has elapsed.
func AdminRetireJWTKeyVersion(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	var req adminRetireJWTKeyRequest
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request body")
	}
	if req.Version <= 0 {
		return JSONError(c, http.StatusBadRequest, "version must be a positive integer")
	}

	if err := auth.RetireJWTKeyVersion(req.Version); err != nil {
		logging.ErrorLogger.Printf("JWT key retirement (v%d) failed for %s: %v", req.Version, adminUsername, err)
		return JSONError(c, http.StatusConflict, err.Error())
	}

	logging.LogSecurityEvent(
		logging.EventKeyRotation,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation": "jwt_signing_key_retire",
			"version":   req.Version,
		},
	)

	return JSONResponse(c, http.StatusOK, "JWT signing key version retired", map[string]interface{}{
		"retired_version": req.Version,
	})
}

// AdminPrepareUserSecretMasterRotation issues a single-use mandate for offline user-secret master rotation.
func AdminPrepareUserSecretMasterRotation(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	mandate, expiresAt, err := auth.IssueUserSecretRotationMandate(database.DB, adminUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to issue user-secret rotation mandate for %s: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to issue rotation mandate")
	}

	logging.LogSecurityEvent(
		logging.EventKeyRotation,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":  "user_secret_master_rotation_prepare",
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		},
	)

	return JSONResponse(c, http.StatusOK, "User-secret rotation mandate issued", map[string]interface{}{
		"mandate":    mandate,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
}

// AdminPrepareEnvelopeMasterRotation issues a single-use mandate for offline
// envelope master key (ARKFILE_MASTER_KEY) rotation.
func AdminPrepareEnvelopeMasterRotation(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	mandate, expiresAt, err := auth.IssueEnvelopeRotationMandate(database.DB, adminUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to issue envelope master rotation mandate for %s: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to issue rotation mandate")
	}

	logging.LogSecurityEvent(
		logging.EventKeyRotation,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":  "envelope_master_rotation_prepare",
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		},
	)

	return JSONResponse(c, http.StatusOK, "Envelope master rotation mandate issued", map[string]interface{}{
		"mandate":    mandate,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
}
