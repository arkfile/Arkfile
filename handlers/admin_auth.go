package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
)

// Admin OPAQUE Authentication Endpoints
// These endpoints are separate from regular user authentication and include admin role verification

// AdminOpaqueAuthResponse handles server-side credential response creation for admin login
func AdminOpaqueAuthResponse(c echo.Context) error {
	var request struct {
		Username          string `json:"username"`
		CredentialRequest string `json:"credential_request"` // base64 encoded
	}
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("Admin OPAQUE auth response bind error: %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Validate username
	if request.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}

	// Try to get user and check if they are admin
	user, err := models.GetUserByUsername(database.DB, request.Username)

	var userRecord []byte
	var userRecordHex string

	useFake := false
	if err != nil {
		if err == sql.ErrNoRows {
			useFake = true
		} else {
			logging.ErrorLogger.Printf("Database check for admin %s failed: %v", request.Username, err)
			return JSONError(c, http.StatusInternalServerError, "Authentication failed")
		}
	} else if !user.IsAdmin {
		useFake = true
	}

	if useFake {
		// Derive fake user record to prevent account / privilege enumeration
		var fakeErr error
		userRecord, fakeErr = auth.DeriveFakeUserRecord(request.Username)
		if fakeErr != nil {
			logging.ErrorLogger.Printf("Failed to derive fake user record for admin %s: %v", request.Username, fakeErr)
			return JSONError(c, http.StatusInternalServerError, "Authentication failed")
		}
	} else {
		// User exists and is admin, query their real OPAQUE record
		dbErr := database.DB.QueryRow(`
			SELECT opaque_user_record FROM opaque_user_data
			WHERE username = ?`,
			request.Username).Scan(&userRecordHex)
		if dbErr != nil {
			if dbErr == sql.ErrNoRows {
				// If opaque record is missing, fall back to fake record gracefully
				var fakeErr error
				userRecord, fakeErr = auth.DeriveFakeUserRecord(request.Username)
				if fakeErr != nil {
					logging.ErrorLogger.Printf("Failed to derive fake user record for admin %s: %v", request.Username, fakeErr)
					return JSONError(c, http.StatusInternalServerError, "Authentication failed")
				}
			} else {
				logging.ErrorLogger.Printf("Database query for admin OPAQUE record %s failed: %v", request.Username, dbErr)
				return JSONError(c, http.StatusInternalServerError, "Authentication failed")
			}
		} else {
			var decodeErr error
			userRecord, decodeErr = hex.DecodeString(userRecordHex)
			if decodeErr != nil {
				logging.ErrorLogger.Printf("Failed to decode OPAQUE user record for admin %s: %v", request.Username, decodeErr)
				return JSONError(c, http.StatusInternalServerError, "Authentication failed")
			}
		}
	}

	// Debug: Log the size of the decoded record
	logging.InfoLogger.Printf("DEBUG: Admin auth - userRecordHex length: %d, userRecord length after decode: %d", len(userRecordHex), len(userRecord))

	// Decode credential request from client
	credentialRequest, err := base64.StdEncoding.DecodeString(request.CredentialRequest)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid credential request encoding")
	}

	// Create server credential response
	credentialResponse, authUServer, err := auth.CreateCredentialResponse(credentialRequest, userRecord, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create admin credential response for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication response creation failed")
	}

	// Create session for multi-step protocol
	sessionID, err := auth.CreateAuthSession(database.DB, request.Username, "admin_authentication", authUServer)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create admin auth session for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Session creation failed")
	}

	// Encode response for transmission
	responseB64 := base64.StdEncoding.EncodeToString(credentialResponse)

	logging.InfoLogger.Printf("Admin authentication initiated for user: %s", request.Username)

	return JSONResponse(c, http.StatusOK, "Authentication initiated", map[string]interface{}{
		"session_id":          sessionID,
		"credential_response": responseB64,
	})
}

// AdminOpaqueAuthFinalize completes admin authentication
func AdminOpaqueAuthFinalize(c echo.Context) error {
	var request struct {
		SessionID string `json:"session_id"`
		Username  string `json:"username"`
		AuthU     string `json:"auth_u"` // base64 encoded client authentication token
	}
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("Admin OPAQUE auth finalize bind error: %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Validate session
	sessionUsername, authUServer, err := auth.ValidateAuthSession(database.DB, request.SessionID, "admin_authentication")
	if err != nil {
		logging.ErrorLogger.Printf("Invalid admin auth session: %v", err)
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired session")
	}

	// Verify username matches session
	if sessionUsername != request.Username {
		logging.ErrorLogger.Printf("Username mismatch in admin auth: session=%s, request=%s", sessionUsername, request.Username)
		return JSONError(c, http.StatusBadRequest, "Username mismatch")
	}

	// Verify user is still an admin (double-check)
	user, err := models.GetUserByUsername(database.DB, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Admin user not found during finalization: %s", request.Username)
		// Clean up session
		auth.DeleteAuthSession(database.DB, request.SessionID)
		return JSONError(c, http.StatusUnauthorized, "Invalid credentials")
	}

	if !user.IsAdmin {
		logging.ErrorLogger.Printf("User lost admin privileges during authentication: %s", request.Username)
		// Clean up session
		auth.DeleteAuthSession(database.DB, request.SessionID)
		return JSONError(c, http.StatusUnauthorized, "Invalid credentials")
	}

	// Decode authU from client
	authUClient, err := base64.StdEncoding.DecodeString(request.AuthU)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid client auth token encoding")
	}

	// Verify authentication
	if err := auth.UserAuth(authUServer, authUClient); err != nil {
		logging.ErrorLogger.Printf("Admin OPAQUE authentication failed for %s: %v", request.Username, err)
		// Record failed login attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("admin_login", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record admin login failure: %v", recordErr)
		}
		// Clean up session
		auth.DeleteAuthSession(database.DB, request.SessionID)
		return JSONError(c, http.StatusUnauthorized, "Invalid credentials")
	}

	// Clean up auth session after successful authentication
	if err := auth.DeleteAuthSession(database.DB, request.SessionID); err != nil {
		logging.ErrorLogger.Printf("Warning: Failed to delete admin auth session for %s: %v", request.Username, err)
		// Continue - session will expire naturally
	}

	// Check if user has TOTP enabled
	totpEnabled, err := auth.IsUserMFAEnabled(database.DB, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for admin %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	// MANDATORY TOTP: All admin users must have TOTP enabled to login
	if !totpEnabled {
		logging.InfoLogger.Printf("Admin user %s authenticated via OPAQUE but TOTP setup is incomplete; allowing setup", request.Username)
		tempToken, _, err := auth.GenerateTemporaryMFAToken(request.Username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for admin %s: %v", request.Username, err)
			return JSONError(c, http.StatusInternalServerError, "Authentication failed")
		}
		return JSONResponse(c, http.StatusOK, "Two-factor authentication setup is required for admin access.", map[string]interface{}{
			"requires_mfa":       true,
			"requires_mfa_setup": true,
			"temp_token":          tempToken,
			"auth_method":         "OPAQUE",
			"is_admin":            true,
		})
	}

	// Generate temporary token that requires TOTP completion
	tempToken, _, err := auth.GenerateTemporaryMFAToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for admin %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	// Log partial admin authentication
	database.LogUserAction(request.Username, "Admin OPAQUE auth completed (multi-step), awaiting TOTP", "")
	logging.InfoLogger.Printf("Admin OPAQUE user authenticated (multi-step), TOTP required: %s", request.Username)

	return JSONResponse(c, http.StatusOK, "Admin OPAQUE authentication successful. TOTP code required.", map[string]interface{}{
		"requires_mfa": true,
		"temp_token":    tempToken,
		"auth_method":   "OPAQUE",
		"is_admin":      true,
	})
}
