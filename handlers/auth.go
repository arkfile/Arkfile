package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/utils"
)

// RefreshTokenRequest represents the request structure for refreshing a token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshToken handles refresh token requests
func RefreshToken(c echo.Context) error {
	var request RefreshTokenRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request: malformed body", err.Error())
	}

	if request.RefreshToken == "" {
		return JSONError(c, http.StatusUnauthorized, "Refresh token not found", "")
	}

	// Validate the refresh token
	username, err := models.ValidateRefreshToken(database.DB, request.RefreshToken)
	if err != nil {
		if err == models.ErrRefreshTokenExpired {
			return JSONError(c, http.StatusUnauthorized, "Refresh token expired", "")
		}
		if err == models.ErrUserNotFound {
			return JSONError(c, http.StatusUnauthorized, "User not found for token", "")
		}
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired refresh token", err.Error())
	}

	// LAZY REVOCATION CHECK: Check for user-wide JWT revocations during refresh token operation
	// This implements the Netflix/Spotify model where we only check revocations during refresh,
	// not on every API request. This catches edge cases like password changes and admin force-logout.
	currentTime := time.Now()
	isUserRevoked, err := auth.IsUserJWTRevoked(database.DB, username, currentTime)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check user JWT revocation for %s: %v", username, err)
		// Continue with refresh - don't fail on revocation check errors
	} else if isUserRevoked {
		// User has been force-revoked - deny refresh and log security event
		logging.InfoLogger.Printf("SECURITY: Refresh denied for force-revoked user: %s", username)
		return JSONError(c, http.StatusUnauthorized, "All tokens have been revoked for security reasons", "")
	}

	// Generate new JWT token
	token, expirationTime, err := auth.GenerateToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create new token", err.Error())
	}

	// Revoke the old refresh token for security (token rotation)
	if err := models.RevokeRefreshToken(database.DB, request.RefreshToken); err != nil {
		// Log but don't fail - the old token will expire naturally
		logging.ErrorLogger.Printf("Warning: Failed to revoke old refresh token for %s: %v", username, err)
	}

	// Generate new refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Could not create new refresh token", err.Error())
	}

	// Log the token refresh
	database.LogUserAction(username, "refreshed token", "")
	logging.InfoLogger.Printf("Token refreshed for user: %s", username)

	return JSONResponse(c, http.StatusOK, "Token refreshed successfully", map[string]interface{}{
		"token":         token,
		"refresh_token": refreshToken,
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
		return JSONError(c, http.StatusBadRequest, "Invalid request", err.Error())
	}

	// Get username from token (if authenticated)
	username := auth.GetUsernameFromToken(c)

	// Revoke the refresh token if provided
	if request.RefreshToken != "" {
		err := models.RevokeRefreshToken(database.DB, request.RefreshToken)
		if err != nil {
			// If the token is not found, it might already be revoked, which is not a failure for the user.
			if err != models.ErrRefreshTokenNotFound {
				logging.ErrorLogger.Printf("Failed to revoke refresh token: %v", err)
				return JSONError(c, http.StatusInternalServerError, "Failed to revoke refresh token", err.Error())
			}
		}
	}

	// Clear the refresh token cookie
	cookie := &http.Cookie{
		Name:     "refreshToken",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}
	c.SetCookie(cookie)

	// Log the logout
	if username != "" {
		database.LogUserAction(username, "logged out", "")
		logging.InfoLogger.Printf("User logged out: %s", username)
	}

	return JSONResponse(c, http.StatusOK, "Logged out successfully. Your access token will expire automatically within 30 minutes.", nil)
}

// RevokeToken revokes a specific JWT token
func RevokeToken(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var request struct {
		Token  string `json:"token"`
		Reason string `json:"reason"`
	}

	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request", err.Error())
	}

	if request.Token == "" {
		return JSONError(c, http.StatusBadRequest, "Token is required", "")
	}

	// Revoke the token
	err := auth.RevokeToken(database.DB, request.Token, request.Reason)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke token: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke token", err.Error())
	}

	database.LogUserAction(username, "revoked token", "")
	logging.InfoLogger.Printf("Token revoked by user: %s", username)

	return JSONResponse(c, http.StatusOK, "Token revoked successfully", nil)
}

// RevokeAllRefreshTokens revokes all refresh tokens for the current user
// Note: This does NOT revoke active JWT tokens - they will expire automatically within 30 minutes
func RevokeAllRefreshTokens(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	err := models.RevokeAllUserTokens(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all refresh tokens for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke refresh tokens", err.Error())
	}

	database.LogUserAction(username, "revoked all refresh tokens", "")
	logging.InfoLogger.Printf("All refresh tokens revoked for user: %s", username)

	return JSONResponse(c, http.StatusOK, "All refresh tokens revoked successfully. Active access tokens will expire automatically within 30 minutes.", nil)
}

// ForceRevokeAllTokens implements security-critical revocation for edge cases
// This function revokes BOTH refresh tokens AND active JWT tokens immediately
// Used for: password changes, admin force-logout, security breaches
func ForceRevokeAllTokens(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var request struct {
		Reason string `json:"reason"`
	}

	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request", err.Error())
	}

	if request.Reason == "" {
		request.Reason = "security-critical revocation"
	}

	// Step 1: Revoke all refresh tokens
	err := models.RevokeAllUserTokens(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all refresh tokens for %s during force revocation: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke tokens", err.Error())
	}

	// Step 2: Add user-specific JWT revocation entry
	// This creates a timestamp-based revocation that invalidates all JWTs issued before now
	err = auth.RevokeAllUserJWTTokens(database.DB, username, request.Reason)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all JWT tokens for %s during force revocation: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke active tokens", err.Error())
	}

	// Step 3: Log security event
	database.LogUserAction(username, "force revoked all tokens", request.Reason)
	logging.InfoLogger.Printf("SECURITY: All tokens force-revoked for user %s, reason: %s", username, request.Reason)

	return JSONResponse(c, http.StatusOK, "All tokens (including active access tokens) have been immediately revoked for security reasons.", map[string]string{
		"reason": request.Reason,
	})
}

// AdminForceLogout allows admin to force-logout a specific user (admin-only endpoint)
func AdminForceLogout(c echo.Context) error {
	// This will be used by admin endpoints - placeholder for now
	targetUsername := c.Param("username")
	adminUsername := auth.GetUsernameFromToken(c)

	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required", "")
	}

	// Verify admin privileges (this should be handled by AdminMiddleware)
	// Force revoke all tokens for target user
	err := models.RevokeAllUserTokens(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to revoke tokens for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke user tokens", err.Error())
	}

	// Add user-specific JWT revocation
	err = auth.RevokeAllUserJWTTokens(database.DB, targetUsername, "admin force logout")
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to revoke JWT tokens for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke user JWT tokens", err.Error())
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

// OpaqueRegisterInitRequest represents the initial registration request
type OpaqueRegisterInitRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

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
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// Validate username
	if request.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required", "")
	}

	// Decode registration request from client
	registrationRequest, err := base64.StdEncoding.DecodeString(request.RegistrationRequest)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration request encoding", err.Error())
	}

	// Create server registration response
	registrationResponse, registrationSecret, err := auth.CreateRegistrationResponse(registrationRequest)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create registration response: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Registration response creation failed", err.Error())
	}

	// Create session for multi-step protocol (store the secret for later use in StoreUserRecord)
	sessionID, err := auth.CreateAuthSession(database.DB, request.Username, "registration", registrationSecret)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create registration session for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Session creation failed", err.Error())
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
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// Validate session and get registration secret
	sessionUsername, registrationSecret, err := auth.ValidateAuthSession(database.DB, request.SessionID, "registration")
	if err != nil {
		logging.ErrorLogger.Printf("Invalid registration session: %v", err)
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired session: "+err.Error(), err.Error())
	}

	// Verify username matches session
	if sessionUsername != request.Username {
		logging.ErrorLogger.Printf("Username mismatch in registration: session=%s, request=%s", sessionUsername, request.Username)
		return JSONError(c, http.StatusBadRequest, "Username mismatch", "")
	}

	// Validate username
	if err := utils.ValidateUsername(request.Username); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid username: "+err.Error(), err.Error())
	}

	// Check if user already exists
	_, err = models.GetUserByUsername(database.DB, request.Username)
	if err == nil {
		// Clean up session
		auth.DeleteAuthSession(database.DB, request.SessionID)
		return JSONError(c, http.StatusConflict, "Username already registered", "")
	}

	// Decode registration record
	registrationRecord, err := base64.StdEncoding.DecodeString(request.RegistrationRecord)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration record encoding", err.Error())
	}

	// Store user record with server secret
	userRecord, err := auth.StoreUserRecord(registrationSecret, registrationRecord)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to store user record for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store user record", err.Error())
	}

	// Start transaction for atomic user + OPAQUE record creation
	tx, err := database.DB.Begin()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to start transaction for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "User creation failed", err.Error())
	}
	defer tx.Rollback()

	// Create user record
	_, err = models.CreateUser(tx, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create user %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "User creation failed", err.Error())
	}

	// Store OPAQUE record in RFC-compliant opaque_user_data table
	_, err = tx.Exec(`
		INSERT INTO opaque_user_data 
		(username, opaque_user_record, created_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)`,
		request.Username, userRecord)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to store OPAQUE record for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store OPAQUE record", err.Error())
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "User creation failed", err.Error())
	}

	// Clean up session after successful registration
	if err := auth.DeleteAuthSession(database.DB, request.SessionID); err != nil {
		logging.ErrorLogger.Printf("Warning: Failed to delete registration session for %s: %v", request.Username, err)
		// Continue - session will expire naturally
	}

	// Generate temporary token for TOTP setup
	tempToken, _, err := auth.GenerateTemporaryTOTPToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Registration succeeded but setup token creation failed", err.Error())
	}

	// Log successful registration
	database.LogUserAction(request.Username, "registered with OPAQUE (multi-step), TOTP setup required", "")
	logging.InfoLogger.Printf("OPAQUE user registered (multi-step), TOTP setup required: %s", request.Username)

	return JSONResponse(c, http.StatusCreated, "Account created successfully. Two-factor authentication setup is required to complete registration.", map[string]interface{}{
		"requires_totp_setup": true,
		"requires_totp":       true, // Added for client compatibility
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
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// Validate username
	if request.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required", "")
	}

	// Get user record from RFC-compliant opaque_user_data table
	// Note: opaque_user_record is stored as hex-encoded string in database
	var userRecordHex string
	err := database.DB.QueryRow(`
		SELECT opaque_user_record FROM opaque_user_data
		WHERE username = ?`,
		request.Username).Scan(&userRecordHex)
	if err != nil {
		logging.ErrorLogger.Printf("User not found for auth: %s", request.Username)
		// Record failed login attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("login", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record login failure: %v", recordErr)
		}
		return JSONError(c, http.StatusUnauthorized, "Invalid credentials", "")
	}

	// Decode hex-encoded user record from database
	userRecord, err := hex.DecodeString(userRecordHex)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to decode OPAQUE user record for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed", err.Error())
	}

	// Decode credential request from client
	credentialRequest, err := base64.StdEncoding.DecodeString(request.CredentialRequest)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid credential request encoding", err.Error())
	}

	// Create server credential response
	credentialResponse, authUServer, err := auth.CreateCredentialResponse(credentialRequest, userRecord, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create credential response for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication response creation failed", err.Error())
	}

	// Create session for multi-step protocol
	sessionID, err := auth.CreateAuthSession(database.DB, request.Username, "authentication", authUServer)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create auth session for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Session creation failed", err.Error())
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
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// Validate session
	sessionUsername, authUServer, err := auth.ValidateAuthSession(database.DB, request.SessionID, "authentication")
	if err != nil {
		logging.ErrorLogger.Printf("Invalid auth session: %v", err)
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired session", err.Error())
	}

	// Verify username matches session
	if sessionUsername != request.Username {
		logging.ErrorLogger.Printf("Username mismatch in auth: session=%s, request=%s", sessionUsername, request.Username)
		return JSONError(c, http.StatusBadRequest, "Username mismatch", "")
	}

	// Decode authU from client
	authUClient, err := base64.StdEncoding.DecodeString(request.AuthU)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid client auth token encoding", err.Error())
	}

	// Verify authentication
	if err := auth.UserAuth(authUServer, authUClient); err != nil {
		logging.ErrorLogger.Printf("OPAQUE authentication failed for %s: %v", request.Username, err)
		// Record failed login attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("login", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record login failure: %v", recordErr)
		}
		// Clean up session
		auth.DeleteAuthSession(database.DB, request.SessionID)
		return JSONError(c, http.StatusUnauthorized, "Invalid credentials", "")
	}

	// Clean up auth session after successful authentication
	if err := auth.DeleteAuthSession(database.DB, request.SessionID); err != nil {
		logging.ErrorLogger.Printf("Warning: Failed to delete auth session for %s: %v", request.Username, err)
		// Continue - session will expire naturally
	}

	// Check if user has TOTP enabled
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed", err.Error())
	}

	// MANDATORY TOTP: All users must have TOTP enabled to login
	if !totpEnabled {
		logging.ErrorLogger.Printf("User %s attempted login without TOTP setup", request.Username)
		return JSONError(c, http.StatusForbidden, "Two-factor authentication setup is required", "")
	}

	// Generate temporary token that requires TOTP completion
	tempToken, _, err := auth.GenerateTemporaryTOTPToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed", err.Error())
	}

	// Log partial authentication
	database.LogUserAction(request.Username, "OPAQUE auth completed (multi-step), awaiting TOTP", "")
	logging.InfoLogger.Printf("OPAQUE user authenticated (multi-step), TOTP required: %s", request.Username)

	return JSONResponse(c, http.StatusOK, "OPAQUE authentication successful. TOTP code required.", map[string]interface{}{
		"requires_totp": true,
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

// TOTPSetupRequest represents the request for TOTP setup
type TOTPSetupRequest struct {
	// No session key needed - JWT token provides authentication
}

// TOTPSetupResponse represents the response for TOTP setup
type TOTPSetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
	ManualEntry string   `json:"manual_entry"`
}

// TOTPSetup initializes TOTP setup for a user
func TOTPSetup(c echo.Context) error {
	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check if user already has TOTP enabled
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, username)
	if err != nil && err.Error() != "sql: no rows in result set" {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to check TOTP status", err.Error())
	}

	if totpEnabled {
		return JSONError(c, http.StatusConflict, "TOTP already enabled for this user", "")
	}

	// Generate TOTP setup
	setup, err := auth.GenerateTOTPSetup(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate TOTP setup for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to generate TOTP setup", err.Error())
	}

	// Store TOTP setup in database
	if err := auth.StoreTOTPSetup(database.DB, username, setup); err != nil {
		logging.ErrorLogger.Printf("Failed to store TOTP setup for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store TOTP setup", err.Error())
	}

	// Log TOTP setup initiation
	database.LogUserAction(username, "initiated TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup initiated for user: %s", username)

	return JSONResponse(c, http.StatusOK, "TOTP setup initiated", TOTPSetupResponse{
		Secret:      setup.Secret,
		QRCodeURL:   setup.QRCodeURL,
		BackupCodes: setup.BackupCodes,
		ManualEntry: setup.ManualEntry,
	})
}

// TOTPVerifyRequest represents the request for TOTP verification
type TOTPVerifyRequest struct {
	Code     string `json:"code"`
	IsBackup bool   `json:"is_backup,omitempty"`
}

// TOTPVerify completes TOTP setup by verifying a test code
func TOTPVerify(c echo.Context) error {
	var request TOTPVerifyRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Validate input
	if request.Code == "" {
		return JSONError(c, http.StatusBadRequest, "TOTP code is required", "")
	}

	if !request.IsBackup && len(request.Code) != 6 {
		return JSONError(c, http.StatusBadRequest, "TOTP code must be 6 digits", "")
	}

	if request.IsBackup && len(request.Code) != 10 {
		return JSONError(c, http.StatusBadRequest, "Backup code must be 10 characters", "")
	}

	// Complete TOTP setup
	if err := auth.CompleteTOTPSetup(database.DB, username, request.Code); err != nil {
		logging.ErrorLogger.Printf("Failed to complete TOTP setup for %s: %v", username, err)
		// Record failed TOTP verification attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("totp_verify", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record TOTP verify failure: %v", recordErr)
		}
		return JSONError(c, http.StatusBadRequest, "Invalid TOTP code", err.Error())
	}

	// Check if this is a temporary TOTP token (registration flow)
	isTemporaryToken := auth.RequiresTOTPFromToken(c)

	// Log successful TOTP setup
	database.LogUserAction(username, "completed TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup completed for user: %s", username)

	// If this is a temporary TOTP token from registration, provide full access tokens
	if isTemporaryToken {
		// Generate full access token
		token, expirationTime, err := auth.GenerateFullAccessToken(username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to create session", err.Error())
		}

		// Generate refresh token
		refreshToken, err := models.CreateRefreshToken(database.DB, username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to create session", err.Error())
		}

		// Get user record for response
		user, err := models.GetUserByUsername(database.DB, username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to get user details", err.Error())
		}

		logging.InfoLogger.Printf("Registration completed with TOTP setup for user: %s", username)

		return JSONResponse(c, http.StatusOK, "TOTP setup and registration completed successfully", map[string]interface{}{
			"enabled":       true,
			"token":         token, // Changed from access_token to token for consistency
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

// TOTPAuthRequest represents the request for TOTP authentication
type TOTPAuthRequest struct {
	Code     string `json:"code"`
	IsBackup bool   `json:"is_backup,omitempty"`
}

// TOTPAuth validates a TOTP code and completes authentication
func TOTPAuth(c echo.Context) error {
	var request TOTPAuthRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check if token requires TOTP
	if !auth.RequiresTOTPFromToken(c) {
		return JSONError(c, http.StatusBadRequest, "Token does not require TOTP", "")
	}

	// Validate input
	if request.Code == "" {
		return JSONError(c, http.StatusBadRequest, "TOTP code is required", "")
	}

	if !request.IsBackup && len(request.Code) != 6 {
		return JSONError(c, http.StatusBadRequest, "TOTP code must be 6 digits", "")
	}

	if request.IsBackup && len(request.Code) != 10 {
		return JSONError(c, http.StatusBadRequest, "Backup code must be 10 characters", "")
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
			if recordErr := recordAuthFailedAttempt("totp_auth", entityID); recordErr != nil {
				logging.ErrorLogger.Printf("Failed to record TOTP auth failure: %v", recordErr)
			}
			return JSONError(c, http.StatusUnauthorized, "Invalid backup code", err.Error())
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
			if recordErr := recordAuthFailedAttempt("totp_auth", entityID); recordErr != nil {
				logging.ErrorLogger.Printf("Failed to record TOTP auth failure: %v", recordErr)
			}
			return JSONError(c, http.StatusUnauthorized, "Invalid TOTP code", err.Error())
		}
		database.LogUserAction(username, "authenticated with TOTP", "")
	}

	// Get user record
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed", err.Error())
	}

	// Generate full access token
	token, expirationTime, err := auth.GenerateFullAccessToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session", err.Error())
	}

	// Generate refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session", err.Error())
	}

	// Log successful authentication
	database.LogUserAction(username, "completed TOTP authentication", "")
	logging.InfoLogger.Printf("TOTP authentication completed for user: %s", username)

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

// TOTPResetRequest represents the request for TOTP reset
type TOTPResetRequest struct {
	BackupCode string `json:"backup_code"`
}

// TOTPResetResponse represents the response for TOTP reset
type TOTPResetResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
	ManualEntry string   `json:"manual_entry"`
	Message     string   `json:"message"`
}

// TOTPReset resets TOTP for a user (requires valid backup code)
func TOTPReset(c echo.Context) error {
	var request TOTPResetRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Validate input
	if request.BackupCode == "" || len(request.BackupCode) != 10 {
		return JSONError(c, http.StatusBadRequest, "Valid backup code is required (10 characters)", "")
	}

	// Reset TOTP (this validates the backup code and generates new setup)
	setup, err := auth.ResetTOTP(database.DB, username, request.BackupCode)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to reset TOTP for %s: %v", username, err)
		// Record failed TOTP reset attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("totp_reset", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record TOTP reset failure: %v", recordErr)
		}
		return JSONError(c, http.StatusUnauthorized, "Invalid backup code or TOTP reset failed", err.Error())
	}

	// Log TOTP reset
	database.LogUserAction(username, "reset TOTP with backup code", "")
	logging.InfoLogger.Printf("SECURITY: TOTP reset for user: %s", username)

	return JSONResponse(c, http.StatusOK, "TOTP has been reset successfully. Please update your authenticator app immediately with the new secret.", TOTPResetResponse{
		Secret:      setup.Secret,
		QRCodeURL:   setup.QRCodeURL,
		BackupCodes: setup.BackupCodes,
		ManualEntry: setup.ManualEntry,
		Message:     "TOTP has been reset successfully. Please update your authenticator app immediately with the new secret.",
	})
}

// TOTPStatusResponse represents the TOTP status response
type TOTPStatusResponse struct {
	Enabled       bool       `json:"enabled"`
	SetupRequired bool       `json:"setup_required"`
	LastUsed      *time.Time `json:"last_used,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
}

// TOTPStatus returns the TOTP status for a user
func TOTPStatus(c echo.Context) error {
	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check TOTP status
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to check TOTP status", err.Error())
	}

	response := TOTPStatusResponse{
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
