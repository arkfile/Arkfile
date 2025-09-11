package handlers

import (
	"encoding/base64"
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

// RefreshToken handles refresh token requests
func RefreshToken(c echo.Context) error {
	var request RefreshTokenRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request: malformed body")
	}

	if request.RefreshToken == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Refresh token not found")
	}

	// Validate the refresh token
	username, err := models.ValidateRefreshToken(database.DB, request.RefreshToken)
	if err != nil {
		if err == models.ErrRefreshTokenExpired {
			return echo.NewHTTPError(http.StatusUnauthorized, "Refresh token expired")
		}
		if err == models.ErrUserNotFound {
			return echo.NewHTTPError(http.StatusUnauthorized, "User not found for token")
		}
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired refresh token")
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
		return echo.NewHTTPError(http.StatusUnauthorized, "All tokens have been revoked for security reasons")
	}

	// Generate new JWT token
	token, err := auth.GenerateToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate token for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create new token")
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
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not create new refresh token")
	}

	// Log the token refresh
	database.LogUserAction(username, "refreshed token", "")
	logging.InfoLogger.Printf("Token refreshed for user: %s", username)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":        token,
		"refreshToken": refreshToken,
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
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
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
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke refresh token")
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

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logged out successfully. Your access token will expire automatically within 30 minutes.",
	})
}

// RevokeToken revokes a specific JWT token
func RevokeToken(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var request struct {
		Token  string `json:"token"`
		Reason string `json:"reason"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if request.Token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Token is required")
	}

	// Revoke the token
	err := auth.RevokeToken(database.DB, request.Token, request.Reason)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke token: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke token")
	}

	database.LogUserAction(username, "revoked token", "")
	logging.InfoLogger.Printf("Token revoked by user: %s", username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Token revoked successfully",
	})
}

// RevokeAllRefreshTokens revokes all refresh tokens for the current user
// Note: This does NOT revoke active JWT tokens - they will expire automatically within 30 minutes
func RevokeAllRefreshTokens(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	err := models.RevokeAllUserTokens(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all refresh tokens for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke refresh tokens")
	}

	database.LogUserAction(username, "revoked all refresh tokens", "")
	logging.InfoLogger.Printf("All refresh tokens revoked for user: %s", username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "All refresh tokens revoked successfully. Active access tokens will expire automatically within 30 minutes.",
	})
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
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if request.Reason == "" {
		request.Reason = "security-critical revocation"
	}

	// Step 1: Revoke all refresh tokens
	err := models.RevokeAllUserTokens(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all refresh tokens for %s during force revocation: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke tokens")
	}

	// Step 2: Add user-specific JWT revocation entry
	// This creates a timestamp-based revocation that invalidates all JWTs issued before now
	err = auth.RevokeAllUserJWTTokens(database.DB, username, request.Reason)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all JWT tokens for %s during force revocation: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke active tokens")
	}

	// Step 3: Log security event
	database.LogUserAction(username, "force revoked all tokens", request.Reason)
	logging.InfoLogger.Printf("SECURITY: All tokens force-revoked for user %s, reason: %s", username, request.Reason)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "All tokens (including active access tokens) have been immediately revoked for security reasons.",
		"reason":  request.Reason,
	})
}

// AdminForceLogout allows admin to force-logout a specific user (admin-only endpoint)
func AdminForceLogout(c echo.Context) error {
	// This will be used by admin endpoints - placeholder for now
	targetUsername := c.Param("username")
	adminUsername := auth.GetUsernameFromToken(c)

	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	// Verify admin privileges (this should be handled by AdminMiddleware)
	// Force revoke all tokens for target user
	err := models.RevokeAllUserTokens(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to revoke tokens for %s: %v", adminUsername, targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke user tokens")
	}

	// Add user-specific JWT revocation
	err = auth.RevokeAllUserJWTTokens(database.DB, targetUsername, "admin force logout")
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to revoke JWT tokens for %s: %v", adminUsername, targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke user JWT tokens")
	}

	// Log security event
	database.LogUserAction(targetUsername, "force logged out by admin", adminUsername)
	database.LogUserAction(adminUsername, "force logged out user", targetUsername)
	logging.InfoLogger.Printf("ADMIN: User %s force-logged out by admin %s", targetUsername, adminUsername)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User has been force-logged out successfully",
		"target":  targetUsername,
	})
}

// OPAQUE Authentication Endpoints

// OpaqueRegisterRequest represents the request for OPAQUE registration
type OpaqueRegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"` // Optional email
	Password string `json:"password"`
}

// OpaqueLoginRequest represents the request for OPAQUE login
type OpaqueLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// OpaqueHealthCheckResponse represents the health status of OPAQUE system
type OpaqueHealthCheckResponse struct {
	OpaqueReady       bool   `json:"opaqueReady"`
	ServerKeysLoaded  bool   `json:"serverKeysLoaded"`
	DatabaseConnected bool   `json:"databaseConnected"`
	Status            string `json:"status"`
	Message           string `json:"message"`
}

// OpaqueRegister handles OPAQUE user registration with rock-solid reliability
func OpaqueRegister(c echo.Context) error {
	var request OpaqueRegisterRequest
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("OPAQUE registration bind error: %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Comprehensive input validation
	if err := utils.ValidateUsername(request.Username); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid username: "+err.Error())
	}

	if request.Email != "" && !strings.Contains(request.Email, "@") {
		return echo.NewHTTPError(http.StatusBadRequest, "Provided email is not valid")
	}

	// Phase 5E: Enhanced password validation with entropy checking
	result := crypto.ValidateAccountPassword(request.Password)
	if !result.MeetsRequirement {
		errorMsg := "Password does not meet security requirements"
		if len(result.Feedback) > 0 {
			errorMsg = strings.Join(result.Feedback, "; ")
		}
		return echo.NewHTTPError(http.StatusBadRequest, errorMsg)
	}

	// Check if user already exists
	_, err := models.GetUserByUsername(database.DB, request.Username)
	if err == nil {
		return echo.NewHTTPError(http.StatusConflict, "Username already registered")
	}

	// Create user record AND register OPAQUE account in single transaction
	var emailPtr *string
	if request.Email != "" {
		emailPtr = &request.Email
	}
	user, err := models.CreateUserWithOPAQUE(database.DB, request.Username, request.Password, emailPtr)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("OPAQUE user registration failed for %s: %v", request.Username, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Get OPAQUE export key from registration process
	// For Phase 5A: We need the export key to derive the session key properly
	exportKey, err := user.GetOPAQUEExportKey(database.DB, request.Password)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get OPAQUE export key during registration for %s: %v", request.Username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Validate export key from OPAQUE registration
	if err := user.ValidateOPAQUEExportKey(exportKey); err != nil {
		logging.ErrorLogger.Printf("Invalid OPAQUE export key during registration for %s: %v", request.Username, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Derive session key from OPAQUE export key using proper HKDF for Phase 5A
	sessionKey, err := crypto.DeriveSessionKey(exportKey, crypto.SessionKeyContext)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to derive session key during registration for %s: %v", request.Username, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Clear export key from memory immediately after session key derivation
	user.SecureZeroExportKey(exportKey)

	// Generate temporary token for mandatory TOTP setup
	tempToken, err := auth.GenerateTemporaryTOTPToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Username, err)
		crypto.SecureZeroSessionKey(sessionKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration succeeded but setup token creation failed")
	}

	// Encode session key for secure transmission
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	// Clear session key from memory after encoding
	crypto.SecureZeroSessionKey(sessionKey)

	// Log successful registration
	database.LogUserAction(request.Username, "registered with OPAQUE, TOTP setup required", "")
	logging.InfoLogger.Printf("OPAQUE user registered, TOTP setup required: %s", request.Username)

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message":           "Account created successfully. Two-factor authentication setup is required to complete registration.",
		"requiresTOTPSetup": true,
		"tempToken":         tempToken,
		"sessionKey":        sessionKeyB64,
		"authMethod":        "OPAQUE",
		"username":          request.Username,
	})
}

// OpaqueLogin handles OPAQUE user authentication with rock-solid reliability
func OpaqueLogin(c echo.Context) error {
	var request OpaqueLoginRequest
	if err := c.Bind(&request); err != nil {
		logging.ErrorLogger.Printf("OPAQUE login bind error: %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Input validation
	if request.Username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if request.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required")
	}

	// Note: We no longer check user approval status during login
	// Users can complete OPAQUE + TOTP authentication but will be restricted from file operations if unapproved

	// Get user to authenticate
	user, err := models.GetUserByUsername(database.DB, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("User not found for %s: %v", request.Username, err)
		// Record failed login attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("login", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record login failure: %v", recordErr)
		}
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	// Perform OPAQUE authentication via user model to get export key
	exportKey, err := user.AuthenticateOPAQUE(database.DB, request.Password)
	if err != nil {
		logging.ErrorLogger.Printf("OPAQUE authentication failed for %s: %v", request.Username, err)
		// Record failed login attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("login", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record login failure: %v", recordErr)
		}
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	// Validate export key from OPAQUE authentication
	if err := user.ValidateOPAQUEExportKey(exportKey); err != nil {
		logging.ErrorLogger.Printf("Invalid OPAQUE export key for %s: %v", request.Username, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Derive session key from OPAQUE export key using proper HKDF
	sessionKey, err := crypto.DeriveSessionKey(exportKey, crypto.SessionKeyContext)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to derive session key for %s: %v", request.Username, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Clear export key from memory immediately after session key derivation
	user.SecureZeroExportKey(exportKey)

	// Check if user has TOTP enabled
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", request.Username, err)
		crypto.SecureZeroSessionKey(sessionKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// MANDATORY TOTP: All users must have TOTP enabled to login
	if !totpEnabled {
		crypto.SecureZeroSessionKey(sessionKey)
		logging.ErrorLogger.Printf("User %s attempted login without TOTP setup", request.Username)
		return echo.NewHTTPError(http.StatusForbidden, "Two-factor authentication setup is required. Please complete TOTP setup before logging in.")
	}

	// Generate temporary token that requires TOTP completion
	tempToken, err := auth.GenerateTemporaryTOTPToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Username, err)
		crypto.SecureZeroSessionKey(sessionKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Encode session key for secure transmission
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	// Clear session key from memory immediately
	crypto.SecureZeroSessionKey(sessionKey)

	// Log partial authentication
	database.LogUserAction(request.Username, "OPAQUE auth completed, awaiting TOTP", "")
	logging.InfoLogger.Printf("OPAQUE user authenticated, TOTP required: %s", request.Username)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"requiresTOTP": true,
		"tempToken":    tempToken,
		"sessionKey":   sessionKeyB64,
		"authMethod":   "OPAQUE",
		"message":      "OPAQUE authentication successful. TOTP code required.",
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

	// Check OPAQUE provider availability
	provider := auth.GetOPAQUEProvider()
	if !provider.IsAvailable() {
		response.Message = "OPAQUE provider not available"
		return c.JSON(http.StatusServiceUnavailable, response)
	}
	response.OpaqueReady = true

	// Check database connectivity
	if err := database.DB.Ping(); err != nil {
		response.Message = "Database connectivity failed: " + err.Error()
		return c.JSON(http.StatusServiceUnavailable, response)
	}
	response.DatabaseConnected = true

	// Validate OPAQUE provider setup
	_, _, err := provider.GetServerKeys()
	if err != nil {
		response.Message = "OPAQUE server keys not available: " + err.Error()
		return c.JSON(http.StatusServiceUnavailable, response)
	}
	response.ServerKeysLoaded = true

	// All checks passed
	response.Status = "healthy"
	response.Message = "OPAQUE authentication system fully operational"

	return c.JSON(http.StatusOK, response)
}

// TOTP Authentication Endpoints

// TOTPSetupRequest represents the request for TOTP setup
type TOTPSetupRequest struct {
	SessionKey string `json:"sessionKey"`
}

// TOTPSetupResponse represents the response for TOTP setup
type TOTPSetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qrCodeUrl"`
	BackupCodes []string `json:"backupCodes"`
	ManualEntry string   `json:"manualEntry"`
}

// TOTPSetup initializes TOTP setup for a user
func TOTPSetup(c echo.Context) error {
	var request TOTPSetupRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Decode session key
	sessionKey, err := base64.StdEncoding.DecodeString(request.SessionKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid session key format")
	}
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Check if user already has TOTP enabled
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, username)
	if err != nil && err.Error() != "sql: no rows in result set" {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check TOTP status")
	}

	if totpEnabled {
		return echo.NewHTTPError(http.StatusConflict, "TOTP already enabled for this user")
	}

	// Generate TOTP setup
	setup, err := auth.GenerateTOTPSetup(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate TOTP setup for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate TOTP setup")
	}

	// Store TOTP setup in database
	if err := auth.StoreTOTPSetup(database.DB, username, setup); err != nil {
		logging.ErrorLogger.Printf("Failed to store TOTP setup for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to store TOTP setup")
	}

	// Log TOTP setup initiation
	database.LogUserAction(username, "initiated TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup initiated for user: %s", username)

	return c.JSON(http.StatusOK, TOTPSetupResponse{
		Secret:      setup.Secret,
		QRCodeURL:   setup.QRCodeURL,
		BackupCodes: setup.BackupCodes,
		ManualEntry: setup.ManualEntry,
	})
}

// TOTPVerifyRequest represents the request for TOTP verification
type TOTPVerifyRequest struct {
	Code       string `json:"code"`
	SessionKey string `json:"sessionKey"`
	IsBackup   bool   `json:"isBackup,omitempty"`
}

// TOTPVerify completes TOTP setup by verifying a test code
func TOTPVerify(c echo.Context) error {
	var request TOTPVerifyRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Validate input
	if request.Code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "TOTP code is required")
	}

	if !request.IsBackup && len(request.Code) != 6 {
		return echo.NewHTTPError(http.StatusBadRequest, "TOTP code must be 6 digits")
	}

	if request.IsBackup && len(request.Code) != 10 {
		return echo.NewHTTPError(http.StatusBadRequest, "Backup code must be 10 characters")
	}

	// Decode session key
	sessionKey, err := base64.StdEncoding.DecodeString(request.SessionKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid session key format")
	}
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Complete TOTP setup
	if err := auth.CompleteTOTPSetup(database.DB, username, request.Code); err != nil {
		logging.ErrorLogger.Printf("Failed to complete TOTP setup for %s: %v", username, err)
		// Record failed TOTP verification attempt
		entityID := logging.GetOrCreateEntityID(c)
		if recordErr := recordAuthFailedAttempt("totp_verify", entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record TOTP verify failure: %v", recordErr)
		}
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid TOTP code")
	}

	// Check if this is a temporary TOTP token (registration flow)
	isTemporaryToken := auth.RequiresTOTPFromToken(c)

	// Log successful TOTP setup
	database.LogUserAction(username, "completed TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup completed for user: %s", username)

	// If this is a temporary TOTP token from registration, provide full access tokens
	if isTemporaryToken {
		// Generate full access token
		token, err := auth.GenerateFullAccessToken(username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
		}

		// Generate refresh token
		refreshToken, err := models.CreateRefreshToken(database.DB, username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
		}

		// Get user record for response
		user, err := models.GetUserByUsername(database.DB, username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Encode session key for response
		sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

		logging.InfoLogger.Printf("Registration completed with TOTP setup for user: %s", username)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":       "TOTP setup and registration completed successfully",
			"enabled":       true,
			"access_token":  token,
			"refresh_token": refreshToken,
			"session_key":   sessionKeyB64,
			"auth_method":   "OPAQUE+TOTP",
			"user": map[string]interface{}{
				"username":        user.Username,
				"email":           user.Email,
				"is_approved":     user.IsApproved,
				"is_admin":        user.IsAdmin,
				"total_storage":   user.TotalStorageBytes,
				"storage_limit":   user.StorageLimitBytes,
				"storage_used_pc": user.GetStorageUsagePercent(),
			},
		})
	}

	// Regular TOTP setup completion (not during registration)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "TOTP setup completed successfully",
		"enabled": true,
	})
}

// TOTPAuthRequest represents the request for TOTP authentication
type TOTPAuthRequest struct {
	Code       string `json:"code"`
	SessionKey string `json:"sessionKey"`
	IsBackup   bool   `json:"isBackup,omitempty"`
}

// TOTPAuth validates a TOTP code and completes authentication
func TOTPAuth(c echo.Context) error {
	var request TOTPAuthRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check if token requires TOTP
	if !auth.RequiresTOTPFromToken(c) {
		return echo.NewHTTPError(http.StatusBadRequest, "Token does not require TOTP")
	}

	// Validate input
	if request.Code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "TOTP code is required")
	}

	if !request.IsBackup && len(request.Code) != 6 {
		return echo.NewHTTPError(http.StatusBadRequest, "TOTP code must be 6 digits")
	}

	if request.IsBackup && len(request.Code) != 10 {
		return echo.NewHTTPError(http.StatusBadRequest, "Backup code must be 10 characters")
	}

	// Decode session key
	sessionKey, err := base64.StdEncoding.DecodeString(request.SessionKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid session key format")
	}
	defer crypto.SecureZeroSessionKey(sessionKey)

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
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid backup code")
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
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid TOTP code")
		}
		database.LogUserAction(username, "authenticated with TOTP", "")
	}

	// Get user record
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Generate full access token
	token, err := auth.GenerateFullAccessToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
	}

	// Generate refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
	}

	// Encode session key for response
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	// Log successful authentication
	database.LogUserAction(username, "completed TOTP authentication", "")
	logging.InfoLogger.Printf("TOTP authentication completed for user: %s", username)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":         token,
		"refresh_token": refreshToken,
		"session_key":   sessionKeyB64,
		"auth_method":   "OPAQUE+TOTP",
		"user": map[string]interface{}{
			"username":        user.Username,
			"email":           user.Email,
			"is_approved":     user.IsApproved,
			"is_admin":        user.IsAdmin,
			"total_storage":   user.TotalStorageBytes,
			"storage_limit":   user.StorageLimitBytes,
			"storage_used_pc": user.GetStorageUsagePercent(),
		},
	})
}

// TOTPDisableRequest represents the request for TOTP disabling
type TOTPDisableRequest struct {
	CurrentCode string `json:"currentCode"`
	SessionKey  string `json:"sessionKey"`
}

// TOTPDisable disables TOTP for a user
func TOTPDisable(c echo.Context) error {
	var request TOTPDisableRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Validate input
	if request.CurrentCode == "" || len(request.CurrentCode) != 6 {
		return echo.NewHTTPError(http.StatusBadRequest, "Current TOTP code is required")
	}

	// Decode session key
	sessionKey, err := base64.StdEncoding.DecodeString(request.SessionKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid session key format")
	}
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Disable TOTP (this validates the current code)
	if err := auth.DisableTOTP(database.DB, username, request.CurrentCode); err != nil {
		logging.ErrorLogger.Printf("Failed to disable TOTP for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid TOTP code")
	}

	// Log TOTP disabling
	database.LogUserAction(username, "disabled TOTP", "")
	logging.InfoLogger.Printf("TOTP disabled for user: %s", username)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "TOTP disabled successfully",
		"enabled": false,
	})
}

// TOTPStatusResponse represents the TOTP status response
type TOTPStatusResponse struct {
	Enabled       bool       `json:"enabled"`
	SetupRequired bool       `json:"setupRequired"`
	LastUsed      *time.Time `json:"lastUsed,omitempty"`
	CreatedAt     *time.Time `json:"createdAt,omitempty"`
}

// TOTPStatus returns the TOTP status for a user
func TOTPStatus(c echo.Context) error {
	// Get username from JWT token
	username := auth.GetUsernameFromToken(c)

	// Check TOTP status
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check TOTP status")
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

	return c.JSON(http.StatusOK, response)
}
