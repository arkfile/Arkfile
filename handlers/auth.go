package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/utils"
)

// RefreshTokenRequest represents the request structure for refreshing a token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshToken handles refresh token requests.
// ValidateRefreshToken performs atomic rotation internally (family-revoke on reuse).
// Tokens are delivered via cookies for browser clients; the JSON body also carries
// them so non-browser clients using bearer auth can update their session.
func RefreshToken(c echo.Context) error {
	var request RefreshTokenRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request: malformed body")
	}

	// Browser clients send the refresh token via the __Host-arkfile-refresh cookie;
	// CLI clients send it in the JSON body. Accept either, prefer cookie.
	if cookieVal, err := c.Cookie(CookieRefresh); err == nil && cookieVal.Value != "" {
		request.RefreshToken = cookieVal.Value
	}

	if request.RefreshToken == "" {
		return JSONError(c, http.StatusUnauthorized, "Refresh token not found")
	}

	// Validate and rotate the refresh token atomically.
	// On reuse detection, ValidateRefreshToken revokes the family and all user JWTs internally.
	username, newRefreshToken, err := models.ValidateRefreshToken(database.DB, request.RefreshToken)
	if err != nil {
		if err == models.ErrRefreshTokenExpired {
			return JSONError(c, http.StatusUnauthorized, "Refresh token expired")
		}
		if err == models.ErrRefreshTokenReuse {
			logging.InfoLogger.Printf("SECURITY: Refresh token reuse detected for a session; all sessions revoked")
			return JSONError(c, http.StatusUnauthorized, "All tokens have been revoked for security reasons")
		}
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired refresh token")
	}

	// Generate new full-tier JWT. Refresh flow always produces a full token; a user
	// who has not completed TOTP never receives a refresh token in the first place.
	token, expirationTime, err := auth.GenerateFullAccessToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create new token")
	}

	// Issue updated cookies for browser clients; CLI clients use the JSON body.
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate CSRF token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create new token")
	}
	issueSessionCookies(c, token, newRefreshToken, csrfToken)

	database.LogUserAction(username, "refreshed token", "")
	logging.InfoLogger.Printf("Token refreshed for user: %s", username)

	return JSONResponse(c, http.StatusOK, "Token refreshed successfully", map[string]interface{}{
		"token":         token,
		"refresh_token": newRefreshToken,
		"expires_at":    expirationTime,
	})
}

// LogoutRequest represents the request structure for logging out
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Logout handles user logout
func Logout(c echo.Context) error {
	var request LogoutRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}

	// Get username from token (if authenticated)
	username := auth.GetUsernameFromToken(c)

	// Browser clients send the refresh token via cookie; CLI clients send it in the JSON body.
	// Accept either so the token is revoked regardless of client type.
	if cookieVal, err := c.Cookie(CookieRefresh); err == nil && cookieVal.Value != "" {
		if request.RefreshToken == "" {
			request.RefreshToken = cookieVal.Value
		}
	}

	// Revoke the refresh token if provided
	if request.RefreshToken != "" {
		err := models.RevokeRefreshToken(database.DB, request.RefreshToken)
		if err != nil {
			// If the token is not found, it might already be revoked, which is not a failure for the user.
			if err != models.ErrRefreshTokenNotFound {
				logging.ErrorLogger.Printf("Failed to revoke refresh token: %v", err)
				return JSONError(c, http.StatusInternalServerError, "Failed to revoke refresh token")
			}
		}
	}

	// Expire all Arkfile session cookies.
	clearSessionCookies(c)

	// Log the logout
	if username != "" {
		database.LogUserAction(username, "logged out", "")
		logging.InfoLogger.Printf("User logged out: %s", username)
	}

	return JSONResponse(c, http.StatusOK, "Logged out successfully.", nil)
}

// RevokeToken revokes a specific JWT token
func RevokeToken(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var request struct {
		Token  string `json:"token"`
		Reason string `json:"reason"`
	}

	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}

	if request.Token == "" {
		return JSONError(c, http.StatusBadRequest, "Token is required")
	}

	// Revoke the token
	err := auth.RevokeToken(database.DB, request.Token, request.Reason)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke token: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke token")
	}

	database.LogUserAction(username, "revoked token", "")
	logging.InfoLogger.Printf("Token revoked by user: %s", username)

	return JSONResponse(c, http.StatusOK, "Token revoked successfully", nil)
}

// RevokeAllTokens revokes all refresh tokens AND immediately invalidates all active JWTs
// for the current authenticated user. Use this when a session may be compromised or when
// logging out all devices simultaneously.
func RevokeAllTokens(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	// Step 1: Revoke all refresh tokens
	err := models.RevokeAllUserTokens(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all refresh tokens for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke tokens")
	}

	// Step 2: Write user_jwt_revocations row so TokenRevocationMiddleware rejects
	// all JWTs issued before now on the very next request (within cache TTL).
	err = auth.RevokeAllUserJWTTokens(database.DB, username, "user revoke-all")
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all JWT tokens for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke active tokens")
	}

	database.LogUserAction(username, "revoked all tokens", "")
	logging.InfoLogger.Printf("SECURITY: All tokens revoked for user %s", username)

	return JSONResponse(c, http.StatusOK, "All sessions have been revoked. You are now logged out of all devices.", nil)
}

// AdminForceLogout allows admin to force-logout a specific user (admin-only endpoint)
func AdminForceLogout(c echo.Context) error {
	targetUsername := c.Param("username")
	adminUsername := auth.GetUsernameFromToken(c)

	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}

	// Verify admin privileges (this should be handled by AdminMiddleware)
	// Force revoke all tokens for target user
	err := models.RevokeAllUserTokens(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to revoke tokens for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke user tokens")
	}

	// Add user-specific JWT revocation
	err = auth.RevokeAllUserJWTTokens(database.DB, targetUsername, "admin force logout")
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to revoke JWT tokens for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke user JWT tokens")
	}

	// Log security event
	database.LogUserAction(targetUsername, "force logged out by admin", adminUsername)
	database.LogUserAction(adminUsername, "force logged out user", targetUsername)
	logging.InfoLogger.Printf("ADMIN: User %s force-logged out by admin %s", targetUsername, adminUsername)

	return JSONResponse(c, http.StatusOK, "User has been force-logged out successfully", map[string]string{
		"target": targetUsername,
	})
}

// OPAQUE Authentication Endpoints

// Multi-Step OPAQUE Registration Types

// OpaqueRegisterResponseRequest represents the server response request
type OpaqueRegisterResponseRequest struct {
	RegistrationRequest string `json:"registration_request"` // base64 encoded
}

// OpaqueRegisterFinalizeRequest represents the final registration request
type OpaqueRegisterFinalizeRequest struct {
	Username           string `json:"username"`
	RegistrationRecord string `json:"registration_record"` // base64 encoded
}

// OpaqueHealthCheckResponse represents the health status of OPAQUE system
type OpaqueHealthCheckResponse struct {
	OpaqueReady       bool   `json:"opaque_ready"`
	ServerKeysLoaded  bool   `json:"server_keys_loaded"`
	DatabaseConnected bool   `json:"database_connected"`
	Status            string `json:"status"`
	Message           string `json:"message"`
}

// Multi-Step OPAQUE Registration Endpoints

// OpaqueRegisterResponse handles server-side registration response creation
func OpaqueRegisterResponse(c echo.Context) error {
	var request struct {
		Username            string `json:"username"`
		RegistrationRequest string `json:"registration_request"` // base64 encoded
	}
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("OPAQUE registration response bind error: %v", err)
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Validate username format (fail fast before creating OPAQUE session)
	if request.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}
	if err := utils.ValidateUsername(request.Username); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid username: "+err.Error())
	}

	// Check if user already exists (A-25) (using folded username search to prevent homograph / collision attacks)
	folded := utils.FoldUsername(request.Username)
	exists, err := models.UserFoldedExists(database.DB, folded)
	if err == nil && exists {
		return JSONError(c, http.StatusConflict, "Username already registered")
	}

	// Decode registration request from client
	registrationRequest, err := base64.StdEncoding.DecodeString(request.RegistrationRequest)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration request encoding")
	}

	// Create server registration response
	registrationResponse, registrationSecret, err := auth.CreateRegistrationResponse(registrationRequest)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create registration response: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Registration response creation failed")
	}

	// Create session for multi-step protocol (store the secret for later use in StoreUserRecord)
	sessionID, err := auth.CreateAuthSession(database.DB, request.Username, "registration", registrationSecret)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create registration session for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Session creation failed")
	}

	// Encode response for transmission
	responseB64 := base64.StdEncoding.EncodeToString(registrationResponse)

	return JSONResponse(c, http.StatusOK, "Registration initiated", map[string]interface{}{
		"session_id":            sessionID,
		"registration_response": responseB64,
	})
}

// OpaqueRegisterFinalize completes user registration
func OpaqueRegisterFinalize(c echo.Context) error {
	var request struct {
		SessionID          string `json:"session_id"`
		Username           string `json:"username"`
		RegistrationRecord string `json:"registration_record"` // base64 encoded
	}
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("OPAQUE registration finalize bind error: %v", err)
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Validate session and get registration secret
	sessionUsername, registrationSecret, err := auth.ValidateAuthSession(database.DB, request.SessionID, "registration")
	if err != nil {
		logging.ErrorLogger.Printf("Invalid registration session: %v", err)
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired session: "+err.Error())
	}

	// Verify username matches session
	if sessionUsername != request.Username {
		logging.ErrorLogger.Printf("Username mismatch in registration: session=%s, request=%s", sessionUsername, request.Username)
		return JSONError(c, http.StatusBadRequest, "Username mismatch")
	}

	// Validate username
	if err := utils.ValidateUsername(request.Username); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid username: "+err.Error())
	}

	// Check if user already exists (using folded username search to prevent homograph / collision attacks)
	folded := utils.FoldUsername(request.Username)
	exists, err := models.UserFoldedExists(database.DB, folded)
	if err == nil && exists {
		// Clean up session
		auth.DeleteAuthSession(database.DB, request.SessionID)
		return JSONError(c, http.StatusConflict, "Username already registered")
	}

	// Decode registration record
	registrationRecord, err := base64.StdEncoding.DecodeString(request.RegistrationRecord)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration record encoding")
	}

	// Store user record with server secret
	userRecord, err := auth.StoreUserRecord(registrationSecret, registrationRecord)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to store user record for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store user record")
	}

	// Start transaction for atomic user + OPAQUE record creation
	tx, err := database.DB.Begin()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to start transaction for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "User creation failed")
	}
	defer tx.Rollback()

	// Create user record
	_, err = models.CreateUser(tx, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create user %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "User creation failed")
	}

	// Store OPAQUE record in RFC-compliant opaque_user_data table
	_, err = tx.Exec(`
		INSERT INTO opaque_user_data 
		(username, opaque_user_record, created_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)`,
		request.Username, hex.EncodeToString(userRecord))
	if err != nil {
		logging.ErrorLogger.Printf("Failed to store OPAQUE record for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store OPAQUE record")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "User creation failed")
	}

	// Clean up session after successful registration
	if err := auth.DeleteAuthSession(database.DB, request.SessionID); err != nil {
		logging.ErrorLogger.Printf("Warning: Failed to delete registration session for %s: %v", request.Username, err)
		// Continue - session will expire naturally
	}

	// Generate temporary token for TOTP setup
	tempToken, _, err := auth.GenerateTemporaryMFAToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Registration succeeded but setup token creation failed")
	}

	// Issue temp cookie for browser clients.
	issueTempCookie(c, tempToken)

	// Log successful registration
	database.LogUserAction(request.Username, "registered with OPAQUE (multi-step), TOTP setup required", "")
	logging.InfoLogger.Printf("OPAQUE user registered (multi-step), TOTP setup required: %s", request.Username)

	return JSONResponse(c, http.StatusCreated, "Account created successfully. Two-factor authentication setup is required to complete registration.", map[string]interface{}{
		"requires_mfa_setup": true,
		"requires_mfa":       true,
		"temp_token":          tempToken,
		"auth_method":         "OPAQUE",
		"username":            request.Username,
	})
}

// Multi-Step OPAQUE Authentication Endpoints

// OpaqueAuthInitRequest represents the initial authentication request
type OpaqueAuthInitRequest struct {
	Username string `json:"username"`
}

// OpaqueAuthResponseRequest represents the credential response request
type OpaqueAuthResponseRequest struct {
	Username          string `json:"username"`
	CredentialRequest string `json:"credential_request"` // base64 encoded
}

// OpaqueAuthFinalizeRequest represents the final authentication request
type OpaqueAuthFinalizeRequest struct {
	Username string `json:"username"`
	AuthU    string `json:"auth_u"` // base64 encoded client authentication token
}

// OpaqueAuthResponse handles server-side credential response creation
func OpaqueAuthResponse(c echo.Context) error {
	var request OpaqueAuthResponseRequest
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("OPAQUE auth response bind error: %v", err)
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Validate username
	if request.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}

	// Get user record from RFC-compliant opaque_user_data table
	// Note: opaque_user_record is stored as hex-encoded string in database
	var userRecordHex string
	err := database.DB.QueryRow(`
		SELECT opaque_user_record FROM opaque_user_data
		WHERE username = ?`,
		request.Username).Scan(&userRecordHex)

	var userRecord []byte
	if err != nil {
		if err == sql.ErrNoRows {
			// Derive fake user record to prevent account enumeration (A-24)
			var fakeErr error
			userRecord, fakeErr = auth.DeriveFakeUserRecord(request.Username)
			if fakeErr != nil {
				logging.ErrorLogger.Printf("Failed to derive fake user record for %s: %v", request.Username, fakeErr)
				return JSONError(c, http.StatusInternalServerError, "Authentication failed")
			}
		} else {
			logging.ErrorLogger.Printf("Database check for %s failed: %v", request.Username, err)
			return JSONError(c, http.StatusInternalServerError, "Authentication failed")
		}
	} else {
		// Decode hex-encoded user record from database
		var decodeErr error
		userRecord, decodeErr = hex.DecodeString(userRecordHex)
		if decodeErr != nil {
			logging.ErrorLogger.Printf("Failed to decode OPAQUE user record for %s: %v", request.Username, decodeErr)
			return JSONError(c, http.StatusInternalServerError, "Authentication failed")
		}
	}

	// Decode credential request from client
	credentialRequest, err := base64.StdEncoding.DecodeString(request.CredentialRequest)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid credential request encoding")
	}

	// Create server credential response
	credentialResponse, authUServer, err := auth.CreateCredentialResponse(credentialRequest, userRecord, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create credential response for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication response creation failed")
	}

	// Create session for multi-step protocol
	sessionID, err := auth.CreateAuthSession(database.DB, request.Username, "authentication", authUServer)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create auth session for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Session creation failed")
	}

	// Encode response for transmission
	responseB64 := base64.StdEncoding.EncodeToString(credentialResponse)

	return JSONResponse(c, http.StatusOK, "Authentication initiated", map[string]interface{}{
		"session_id":          sessionID,
		"credential_response": responseB64,
	})
}

// OpaqueAuthFinalize completes user authentication
func OpaqueAuthFinalize(c echo.Context) error {
	var request struct {
		SessionID string `json:"session_id"`
		Username  string `json:"username"`
		AuthU     string `json:"auth_u"` // base64 encoded client authentication token
	}
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("OPAQUE auth finalize bind error: %v", err)
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Validate session
	sessionUsername, authUServer, err := auth.ValidateAuthSession(database.DB, request.SessionID, "authentication")
	if err != nil {
		logging.ErrorLogger.Printf("Invalid auth session: %v", err)
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired session")
	}

	// Verify username matches session
	if sessionUsername != request.Username {
		logging.ErrorLogger.Printf("Username mismatch in auth: session=%s, request=%s", sessionUsername, request.Username)
		return JSONError(c, http.StatusBadRequest, "Username mismatch")
	}

	// Decode authU from client
	authUClient, err := base64.StdEncoding.DecodeString(request.AuthU)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid client auth token encoding")
	}

	// Verify authentication
	if err := auth.UserAuth(authUServer, authUClient); err != nil {
		logging.ErrorLogger.Printf("OPAQUE authentication failed for %s: %v", request.Username, err)
		// Record failed login attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("login", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record login failure: %v", recordErr)
		}
		// Log security event for login failure
		logging.LogSecurityEventWithEntityID(
			logging.EventOpaqueLoginFailure,
			entityID,
			map[string]interface{}{
				"username": request.Username,
				"endpoint": "opaque_auth_finalize",
			},
		)
		// Clean up session
		auth.DeleteAuthSession(database.DB, request.SessionID)
		return JSONError(c, http.StatusUnauthorized, "Invalid credentials")
	}

	// Clean up auth session after successful authentication
	if err := auth.DeleteAuthSession(database.DB, request.SessionID); err != nil {
		logging.ErrorLogger.Printf("Warning: Failed to delete auth session for %s: %v", request.Username, err)
		// Continue - session will expire naturally
	}

	// Check if user has TOTP enabled
	totpEnabled, err := auth.IsUserMFAEnabled(database.DB, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	// MANDATORY TOTP: All users must complete TOTP setup to access the app.
	// If TOTP is not yet set up, issue a temp token and return requires_mfa_setup: true
	// so the client can redirect the user to finish TOTP setup rather than showing a hard error.
	if !totpEnabled {
		logging.InfoLogger.Printf("User %s authenticated via OPAQUE but TOTP setup is incomplete; redirecting to setup", request.Username)
		tempToken, _, err := auth.GenerateTemporaryMFAToken(request.Username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate TOTP setup token for %s: %v", request.Username, err)
			return JSONError(c, http.StatusInternalServerError, "Authentication failed")
		}
		issueTempCookie(c, tempToken)
		return JSONResponse(c, http.StatusOK, "Two-factor authentication setup is required to complete login.", map[string]interface{}{
			"requires_mfa":       true,
			"requires_mfa_setup": true,
			"temp_token":          tempToken,
		})
	}

	// Generate temporary token that requires TOTP completion
	tempToken, _, err := auth.GenerateTemporaryMFAToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	// Issue temp cookie for browser clients.
	issueTempCookie(c, tempToken)

	// Log partial authentication
	database.LogUserAction(request.Username, "OPAQUE auth completed (multi-step), awaiting TOTP", "")
	logging.InfoLogger.Printf("OPAQUE user authenticated (multi-step), TOTP required: %s", request.Username)

	return JSONResponse(c, http.StatusOK, "OPAQUE authentication successful. TOTP code required.", map[string]interface{}{
		"requires_mfa": true,
		"temp_token":    tempToken,
		"auth_method":   "OPAQUE",
	})
}

// OpaqueHealthCheck verifies that the OPAQUE system is functioning properly
func OpaqueHealthCheck(c echo.Context) error {
	response := OpaqueHealthCheckResponse{
		OpaqueReady:       false,
		ServerKeysLoaded:  false,
		DatabaseConnected: false,
		Status:            "unhealthy",
		Message:           "OPAQUE system not ready",
	}

	// Check OPAQUE availability
	if !auth.IsOPAQUEAvailable() {
		response.Message = "OPAQUE not available"
		return JSONResponse(c, http.StatusServiceUnavailable, "OPAQUE system not ready", response)
	}
	response.OpaqueReady = true
	response.ServerKeysLoaded = true

	// Check database connectivity
	if err := database.DB.Ping(); err != nil {
		response.Message = "Database connectivity failed: " + err.Error()
		return JSONResponse(c, http.StatusServiceUnavailable, "Database connectivity failed", response)
	}
	response.DatabaseConnected = true

	// All checks passed
	response.Status = "healthy"
	response.Message = "OPAQUE authentication system fully operational"

	return JSONResponse(c, http.StatusOK, "OPAQUE authentication system fully operational", response)
}

// TOTP Authentication Endpoints

// MFASetupRequest represents the request for TOTP setup
type MFASetupRequest struct {
	// No session key needed - JWT token provides authentication
}

// MFASetupResponse represents the response for TOTP setup
type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	QRCodeImage string   `json:"qr_code_image"` // Base64 data URI for QR code PNG
	BackupCodes []string `json:"backup_codes"`
	ManualEntry string   `json:"manual_entry"`
}

// TOTPSetup initializes TOTP setup for a user
func MFASetup(c echo.Context) error {
	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check if user already has TOTP enabled
	totpEnabled, err := auth.IsUserMFAEnabled(database.DB, username)
	if err != nil && err.Error() != "sql: no rows in result set" {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to check TOTP status")
	}

	if totpEnabled {
		return JSONError(c, http.StatusConflict, "TOTP already enabled for this user")
	}

	// Check for an existing pending (unverified) setup to avoid regenerating the secret.
	// This ensures users who saved the QR code / manual entry on their first attempt
	// can continue using the same secret after session expiry and re-login.
	pendingSetup, err := auth.GetPendingMFASetup(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check pending TOTP setup for %s: %v", username, err)
		// Fall through to generate new setup
	}

	if pendingSetup != nil {
		logging.InfoLogger.Printf("Returning existing pending TOTP setup for user: %s", username)
		return JSONResponse(c, http.StatusOK, "TOTP setup resumed", MFASetupResponse{
			Secret:      pendingSetup.Secret,
			QRCodeURL:   pendingSetup.QRCodeURL,
			QRCodeImage: pendingSetup.QRCodeImage,
			BackupCodes: pendingSetup.BackupCodes,
			ManualEntry: pendingSetup.ManualEntry,
		})
	}

	// No pending setup exists, generate a new one
	setup, err := auth.GenerateMFASetup(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate TOTP setup for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to generate TOTP setup")
	}

	// Store TOTP setup in database
	if err := auth.StoreMFASetup(database.DB, username, setup); err != nil {
		logging.ErrorLogger.Printf("Failed to store TOTP setup for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store TOTP setup")
	}

	// Log TOTP setup initiation
	database.LogUserAction(username, "initiated TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup initiated for user: %s", username)

	return JSONResponse(c, http.StatusOK, "TOTP setup initiated", MFASetupResponse{
		Secret:      setup.Secret,
		QRCodeURL:   setup.QRCodeURL,
		QRCodeImage: setup.QRCodeImage,
		BackupCodes: setup.BackupCodes,
		ManualEntry: setup.ManualEntry,
	})
}

// MFAVerifyRequest represents the request for TOTP verification
type MFAVerifyRequest struct {
	Code     string `json:"code"`
	IsBackup bool   `json:"is_backup,omitempty"`
}

// TOTPVerify completes TOTP setup by verifying a test code
func MFAVerify(c echo.Context) error {
	var request MFAVerifyRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Validate input
	if request.Code == "" {
		return JSONError(c, http.StatusBadRequest, "TOTP code is required")
	}

	if !request.IsBackup && len(request.Code) != 6 {
		return JSONError(c, http.StatusBadRequest, "TOTP code must be 6 digits")
	}

	if request.IsBackup && len(request.Code) != 10 {
		return JSONError(c, http.StatusBadRequest, "Backup code must be 10 characters")
	}

	// Complete TOTP setup
	if err := auth.CompleteMFASetup(database.DB, username, request.Code); err != nil {
		logging.ErrorLogger.Printf("Failed to complete TOTP setup for %s: %v", username, err)
		// Record failed TOTP verification attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("mfa_verify", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record TOTP verify failure: %v", recordErr)
		}
		return JSONError(c, http.StatusBadRequest, "Invalid TOTP code")
	}

	// Check if this is a temporary TOTP token (registration flow)
	isTemporaryToken := auth.RequiresMFAFromToken(c)

	// Log successful TOTP setup
	database.LogUserAction(username, "completed TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup completed for user: %s", username)

	// If this is a temporary TOTP token from registration, provide full access tokens
	if isTemporaryToken {
		// Generate full access token
		token, expirationTime, err := auth.GenerateFullAccessToken(username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to create session")
		}

		// Generate refresh token
		refreshToken, err := models.CreateRefreshToken(database.DB, username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to create session")
		}

		// Get user record for response
		user, err := models.GetUserByUsername(database.DB, username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to get user details")
		}

		// Issue session cookies and clear temp cookie.
		csrfToken, err := GenerateCSRFToken()
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate CSRF token for %s: %v", username, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to create session")
		}
		issueSessionCookies(c, token, refreshToken, csrfToken)
		c.SetCookie(&http.Cookie{
			Name: CookieTempToken, Value: "", Path: "/", MaxAge: -1,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})

		logging.InfoLogger.Printf("Registration completed with TOTP setup for user: %s", username)

		return JSONResponse(c, http.StatusOK, "TOTP setup and registration completed successfully", map[string]interface{}{
			"enabled":       true,
			"token":         token,
			"refresh_token": refreshToken,
			"expires_at":    expirationTime,
			"auth_method":   "OPAQUE+TOTP",
			"user": map[string]interface{}{
				"username":        user.Username,
				"is_approved":     user.IsApproved,
				"is_admin":        user.IsAdmin,
				"total_storage":   user.TotalStorageBytes,
				"storage_limit":   user.StorageLimitBytes,
				"storage_used_pc": user.GetStorageUsagePercent(),
			},
		})
	}

	// Regular TOTP setup completion (not during registration)
	return JSONResponse(c, http.StatusOK, "TOTP setup completed successfully", map[string]interface{}{
		"enabled": true,
	})
}

// MFAAuthRequest represents the request for TOTP authentication
type MFAAuthRequest struct {
	Code     string `json:"code"`
	IsBackup bool   `json:"is_backup,omitempty"`
}

// TOTPAuth validates a TOTP code and completes authentication
func MFAAuth(c echo.Context) error {
	var request MFAAuthRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check if token requires TOTP
	if !auth.RequiresMFAFromToken(c) {
		return JSONError(c, http.StatusBadRequest, "Token does not require TOTP")
	}

	// Validate input
	if request.Code == "" {
		return JSONError(c, http.StatusBadRequest, "TOTP code is required")
	}

	if !request.IsBackup && len(request.Code) != 6 {
		return JSONError(c, http.StatusBadRequest, "TOTP code must be 6 digits")
	}

	if request.IsBackup && len(request.Code) != 10 {
		return JSONError(c, http.StatusBadRequest, "Backup code must be 10 characters")
	}

	// Validate TOTP code or backup code
	if request.IsBackup {
		if err := auth.ValidateBackupCode(database.DB, username, request.Code); err != nil {
			// Enhanced debug logging for backup code failures (with specific failure causes)
			if debugMode := strings.ToLower(os.Getenv("DEBUG_MODE")); debugMode == "true" || debugMode == "1" {
				if strings.Contains(err.Error(), "decrypt") {
					logging.ErrorLogger.Printf("TOTP backup code decrypt failure for user: %s", username)
				} else if strings.Contains(err.Error(), "already used") {
					logging.ErrorLogger.Printf("TOTP backup code replay detected for user: %s", username)
				} else {
					logging.ErrorLogger.Printf("TOTP backup code mismatch for user: %s", username)
				}
			} else {
				logging.ErrorLogger.Printf("Failed backup code validation for %s: %v", username, err)
			}
			// Record failed TOTP auth attempt
			entityID := logging.GetOrCreateEntityID(c)
			if recordErr := recordAuthFailedAttempt("mfa_auth", entityID); recordErr != nil {
				logging.ErrorLogger.Printf("Failed to record TOTP auth failure: %v", recordErr)
			}
			return JSONError(c, http.StatusUnauthorized, "Invalid backup code")
		}
		database.LogUserAction(username, "used backup code", "")
	} else {
		if err := auth.ValidateTOTPCode(database.DB, username, request.Code); err != nil {
			// Enhanced debug logging for TOTP failures (with specific failure causes)
			if debugMode := strings.ToLower(os.Getenv("DEBUG_MODE")); debugMode == "true" || debugMode == "1" {
				if strings.Contains(err.Error(), "decrypt") {
					logging.ErrorLogger.Printf("TOTP decrypt failure for user: %s", username)
				} else if strings.Contains(err.Error(), "replay") {
					logging.ErrorLogger.Printf("TOTP replay detected for user: %s", username)
				} else if strings.Contains(err.Error(), "invalid") {
					logging.ErrorLogger.Printf("TOTP code mismatch for user: %s", username)
				} else {
					logging.ErrorLogger.Printf("TOTP validation error for user: %s, error: %v", username, err)
				}
			} else {
				logging.ErrorLogger.Printf("Failed TOTP code validation for %s: %v", username, err)
			}
			// Record failed TOTP auth attempt
			entityID := logging.GetOrCreateEntityID(c)
			if recordErr := recordAuthFailedAttempt("mfa_auth", entityID); recordErr != nil {
				logging.ErrorLogger.Printf("Failed to record TOTP auth failure: %v", recordErr)
			}
			return JSONError(c, http.StatusUnauthorized, "Invalid TOTP code")
		}
		database.LogUserAction(username, "authenticated with TOTP", "")
	}

	// Get user record
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	// Update last_login timestamp (proof-of-life)
	now := time.Now()
	_, err = database.DB.Exec(
		"UPDATE users SET last_login = ? WHERE username = ?",
		now, username,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update last_login for %s: %v", username, err)
		// Non-critical, continue
	}

	// Proof-of-Life: If an admin logs in, ensure bootstrap token is cleared
	// This handles both initial bootstrap and "force bootstrap" scenarios
	if user.IsAdmin {
		km, err := crypto.GetKeyManager()
		if err == nil {
			// Check if token exists before trying to delete (to avoid noise)
			_, err := km.GetKey("bootstrap_token", "bootstrap")
			if err == nil {
				if err := km.DeleteKey("bootstrap_token"); err != nil {
					logging.ErrorLogger.Printf("Failed to delete bootstrap token: %v", err)
				} else {
					logging.InfoLogger.Printf("Bootstrap token deleted after successful admin login")
				}
			}
		}
	}

	// Generate full access token
	token, expirationTime, err := auth.GenerateFullAccessToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session")
	}

	// Generate refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session")
	}

	// Issue session cookies for browser clients.
	// CLI clients ignore cookies and use the JSON body tokens via bearer auth.
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate CSRF token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session")
	}
	issueSessionCookies(c, token, refreshToken, csrfToken)
	// Clear temp cookie now that full auth is complete.
	c.SetCookie(&http.Cookie{
		Name: CookieTempToken, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})

	// Log successful authentication
	database.LogUserAction(username, "completed TOTP authentication", "")
	logging.InfoLogger.Printf("TOTP authentication completed for user: %s", username)

	// Log security event for successful login (OPAQUE+TOTP complete)
	loginEntityID := logging.GetOrCreateEntityID(c)
	logging.LogSecurityEventWithEntityID(
		logging.EventOpaqueLoginSuccess,
		loginEntityID,
		map[string]interface{}{
			"username":    username,
			"auth_method": "OPAQUE+TOTP",
		},
	)

	return JSONResponse(c, http.StatusOK, "TOTP authentication completed", map[string]interface{}{
		"token":         token,
		"refresh_token": refreshToken,
		"expires_at":    expirationTime,
		"auth_method":   "OPAQUE+TOTP",
		"user": map[string]interface{}{
			"username":        user.Username,
			"is_approved":     user.IsApproved,
			"is_admin":        user.IsAdmin,
			"total_storage":   user.TotalStorageBytes,
			"storage_limit":   user.StorageLimitBytes,
			"storage_used_pc": user.GetStorageUsagePercent(),
		},
	})
}

// MFAResetRequest represents the request for TOTP reset
type MFAResetRequest struct {
	BackupCode string `json:"backup_code"`
}

// MFAResetResponse represents the response for TOTP reset
type MFAResetResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
	ManualEntry string   `json:"manual_entry"`
	Message     string   `json:"message"`
	TempToken   string   `json:"temp_token"`
}

// TOTPReset resets TOTP for a user (requires valid backup code)
// RecoverWithBackupCodeRequest represents the request for the lost-device recover flow
type RecoverWithBackupCodeRequest struct {
	BackupCode string `json:"backup_code"`
}

// RecoverWithBackupCodeResponse represents the successful recovery response
type RecoverWithBackupCodeResponse struct {
	ResetToken string    `json:"reset_token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// RecoverWithBackupCode receives a backup code and returns a short-lived reset-tier JWT token (temporary arkfile-mfa-reset audience).
// Safe to call with a temp-JWT tier authentication.
func RecoverWithBackupCode(c echo.Context) error {
	var request RecoverWithBackupCodeRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return JSONError(c, http.StatusUnauthorized, "User context not found in token")
	}

	if request.BackupCode == "" || len(request.BackupCode) != 10 {
		return JSONError(c, http.StatusBadRequest, "Backup code is required (10 characters)")
	}

	// High security: Validate & burn the backup code.
	if err := auth.ValidateBackupCode(database.DB, username, request.BackupCode); err != nil {
		logging.ErrorLogger.Printf("Failed backup code recovery for %s: %v", username, err)
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("mfa_reset", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record failed backup-code recovery attempt: %v", recordErr)
		}
		return JSONError(c, http.StatusUnauthorized, "Invalid backup code")
	}

	// Success: Issue a short-lived Reset token with "arkfile-mfa-reset" audience.
	resetToken, expiresAt, err := auth.GenerateTemporaryResetToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate reset token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create reset session")
	}

	// Browser client support: Write temporary cookie.
	c.SetCookie(&http.Cookie{
		Name:     CookieTempToken,
		Value:    resetToken,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	database.LogUserAction(username, "initiated recovery with backup code", "")
	logging.InfoLogger.Printf("SECURITY: Backup code recovery session generated for user: %s", username)

	return JSONResponse(c, http.StatusOK, "Backup code verified successfully. Reset token generated.", RecoverWithBackupCodeResponse{
		ResetToken: resetToken,
		ExpiresAt:  expiresAt,
	})
}

// TOTPReset resets TOTP for a user (requires a valid full token OR reset-tier token).
func MFAReset(c echo.Context) error {
	var request MFAResetRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Get username from JWT token (supports both standard full-JWT and reset-temporary JWT tokens)
	username := auth.GetUsernameFromToken(c)

	// Enforce reset authorization claims
	claims, _ := c.Get("user").(*auth.Claims)
	if claims == nil {
		claimsFromContext, ok := auth.GetClaimsFromContext(c)
		if ok {
			claims = claimsFromContext
		}
	}

	hasResetAud := false
	if claims != nil {
		for _, aud := range claims.Audience {
			if aud == auth.AudienceReset {
				hasResetAud = true
				break
			}
		}
	}

	// If they are not authenticating via the temporary reset token path (lost-device),
	// they must provide a valid 10-char backup code.
	if !hasResetAud && (request.BackupCode == "" || len(request.BackupCode) != 10) {
		return JSONError(c, http.StatusBadRequest, "Valid backup code is required (10 characters)")
	}

	// Reset TOTP (this generates new setup and saves hashed backup codes)
	setup, err := auth.ResetMFA(database.DB, username, request.BackupCode)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to reset TOTP for %s: %v", username, err)
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("mfa_reset", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record MFA reset failure: %v", recordErr)
		}
		return JSONError(c, http.StatusUnauthorized, "Invalid backup code or TOTP reset failed")
	}

	// Log TOTP reset
	database.LogUserAction(username, "reset TOTP", "")
	logging.InfoLogger.Printf("SECURITY: TOTP reset complete for user: %s", username)

	// Issue MFA-tier temp token so /api/mfa/verify can complete re-enrollment.
	mfaToken, _, err := auth.GenerateTemporaryMFAToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate MFA verify token after reset for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "TOTP reset succeeded but verify session could not be created")
	}
	issueTempCookie(c, mfaToken)

	return JSONResponse(c, http.StatusOK, "TOTP has been reset successfully. Please update your authenticator app immediately with the new secret.", MFAResetResponse{
		Secret:      setup.Secret,
		QRCodeURL:   setup.QRCodeURL,
		BackupCodes: setup.BackupCodes,
		ManualEntry: setup.ManualEntry,
		Message:     "TOTP has been reset successfully. Please update your authenticator app immediately with the new secret.",
		TempToken:   mfaToken,
	})
}

// MFAStatusResponse represents the TOTP status response
type MFAStatusResponse struct {
	Enabled       bool       `json:"enabled"`
	SetupRequired bool       `json:"setup_required"`
	LastUsed      *time.Time `json:"last_used,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
}

// TOTPStatus returns the TOTP status for a user
func MFAStatus(c echo.Context) error {
	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check TOTP status
	totpEnabled, err := auth.IsUserMFAEnabled(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to check TOTP status")
	}

	response := MFAStatusResponse{
		Enabled:       totpEnabled,
		SetupRequired: !totpEnabled,
	}

	// If TOTP is enabled, get additional details
	if totpEnabled {
		// Note: We don't expose the actual TOTP data, just metadata
		response.SetupRequired = false
	}

	return JSONResponse(c, http.StatusOK, "TOTP status retrieved", response)
}

// GetCurrentUser returns the authenticated user's identity.
// Used by browser clients to discover username/is_admin/is_approved since
// the JWT is HttpOnly and not readable by JavaScript.
// Wired onto mfaProtectedGroup so it requires a full-tier JWT.
func GetCurrentUser(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("GetCurrentUser: failed to load user %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to get user details")
	}

	return JSONResponse(c, http.StatusOK, "User details retrieved", map[string]interface{}{
		"username":        user.Username,
		"is_approved":     user.IsApproved,
		"is_admin":        user.IsAdmin,
		"total_storage":   user.TotalStorageBytes,
		"storage_limit":   user.StorageLimitBytes,
		"storage_used_pc": user.GetStorageUsagePercent(),
	})
}
