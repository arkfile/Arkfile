package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
)

// RefreshTokenRequest represents the request structure for refreshing a token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
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
	userEmail, err := models.ValidateRefreshToken(database.DB, request.RefreshToken)
	if err != nil {
		if err == models.ErrRefreshTokenExpired {
			return echo.NewHTTPError(http.StatusUnauthorized, "Refresh token expired")
		}
		if err == models.ErrUserNotFound {
			return echo.NewHTTPError(http.StatusUnauthorized, "User not found for token")
		}
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired refresh token")
	}

	// Generate new JWT token
	token, err := auth.GenerateToken(userEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate token: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create new token")
	}

	// Generate new refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, userEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not create new refresh token")
	}

	// Log the token refresh
	database.LogUserAction(userEmail, "refreshed token", "")
	logging.InfoLogger.Printf("Token refreshed for user: %s", userEmail)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":        token,
		"refreshToken": refreshToken,
	})
}

// LogoutRequest represents the request structure for logging out
type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// Logout handles user logout
func Logout(c echo.Context) error {
	var request LogoutRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Get user email from token (if authenticated)
	email := auth.GetEmailFromToken(c)

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
	if email != "" {
		database.LogUserAction(email, "logged out", "")
		logging.InfoLogger.Printf("User logged out: %s", email)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// RevokeToken revokes a specific JWT token
func RevokeToken(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

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

	database.LogUserAction(email, "revoked token", "")
	logging.InfoLogger.Printf("Token revoked by user: %s", email)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Token revoked successfully",
	})
}

// RevokeAllTokens revokes all refresh tokens for the current user
func RevokeAllTokens(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	err := models.RevokeAllUserTokens(database.DB, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke all tokens: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke tokens")
	}

	database.LogUserAction(email, "revoked all tokens", "")
	logging.InfoLogger.Printf("All tokens revoked for user: %s", email)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "All sessions revoked successfully",
	})
}

// OPAQUE Authentication Endpoints

// OpaqueRegisterRequest represents the request for OPAQUE registration
type OpaqueRegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// OpaqueLoginRequest represents the request for OPAQUE login
type OpaqueLoginRequest struct {
	Email    string `json:"email"`
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
	if request.Email == "" || !strings.Contains(request.Email, "@") {
		return echo.NewHTTPError(http.StatusBadRequest, "Valid email address is required")
	}

	// Phase 5E: Enhanced password validation with entropy checking
	result := crypto.ValidatePasswordEntropy(request.Password, "account")
	if !result.Valid {
		return echo.NewHTTPError(http.StatusBadRequest, result.Message)
	}

	// Check if user already exists
	_, err := models.GetUserByEmail(database.DB, request.Email)
	if err == nil {
		return echo.NewHTTPError(http.StatusConflict, "Email already registered")
	}

	// Create user record AND register OPAQUE account in single transaction
	user, err := models.CreateUserWithOPAQUE(database.DB, request.Email, request.Password)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("OPAQUE user registration failed for %s: %v", request.Email, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Get OPAQUE export key from registration process
	// For Phase 5A: We need the export key to derive the session key properly
	exportKey, err := user.GetOPAQUEExportKey(database.DB, request.Password)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get OPAQUE export key during registration for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Validate export key from OPAQUE registration
	if err := user.ValidateOPAQUEExportKey(exportKey); err != nil {
		logging.ErrorLogger.Printf("Invalid OPAQUE export key during registration for %s: %v", request.Email, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Derive session key from OPAQUE export key using proper HKDF for Phase 5A
	sessionKey, err := crypto.DeriveSessionKey(exportKey, crypto.SessionKeyContext)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to derive session key during registration for %s: %v", request.Email, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Clear export key from memory immediately after session key derivation
	user.SecureZeroExportKey(exportKey)

	// Generate temporary token for mandatory TOTP setup
	tempToken, err := auth.GenerateTemporaryTOTPToken(request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Email, err)
		crypto.SecureZeroSessionKey(sessionKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration succeeded but setup token creation failed")
	}

	// Encode session key for secure transmission
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	// Clear session key from memory after encoding
	crypto.SecureZeroSessionKey(sessionKey)

	// Log successful registration
	database.LogUserAction(request.Email, "registered with OPAQUE, TOTP setup required", "")
	logging.InfoLogger.Printf("OPAQUE user registered, TOTP setup required: %s", request.Email)

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message":           "Account created successfully. Two-factor authentication setup is required to complete registration.",
		"requiresTOTPSetup": true,
		"tempToken":         tempToken,
		"sessionKey":        sessionKeyB64,
		"authMethod":        "OPAQUE",
		"email":             request.Email,
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
	if request.Email == "" || !strings.Contains(request.Email, "@") {
		return echo.NewHTTPError(http.StatusBadRequest, "Valid email address is required")
	}

	if request.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required")
	}

	// Note: We no longer check user approval status during login
	// Users can complete OPAQUE + TOTP authentication but will be restricted from file operations if unapproved

	// Get user to authenticate
	user, err := models.GetUserByEmail(database.DB, request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("User not found for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	// Perform OPAQUE authentication via user model to get export key
	exportKey, err := user.AuthenticateOPAQUE(database.DB, request.Password)
	if err != nil {
		logging.ErrorLogger.Printf("OPAQUE authentication failed for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	// Validate export key from OPAQUE authentication
	if err := user.ValidateOPAQUEExportKey(exportKey); err != nil {
		logging.ErrorLogger.Printf("Invalid OPAQUE export key for %s: %v", request.Email, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Derive session key from OPAQUE export key using proper HKDF
	sessionKey, err := crypto.DeriveSessionKey(exportKey, crypto.SessionKeyContext)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to derive session key for %s: %v", request.Email, err)
		user.SecureZeroExportKey(exportKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Clear export key from memory immediately after session key derivation
	user.SecureZeroExportKey(exportKey)

	// Check if user has TOTP enabled
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", request.Email, err)
		crypto.SecureZeroSessionKey(sessionKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// MANDATORY TOTP: All users must have TOTP enabled to login
	if !totpEnabled {
		crypto.SecureZeroSessionKey(sessionKey)
		logging.ErrorLogger.Printf("User %s attempted login without TOTP setup", request.Email)
		return echo.NewHTTPError(http.StatusForbidden, "Two-factor authentication setup is required. Please complete TOTP setup before logging in.")
	}

	// Generate temporary token that requires TOTP completion
	tempToken, err := auth.GenerateTemporaryTOTPToken(request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Email, err)
		crypto.SecureZeroSessionKey(sessionKey)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Encode session key for secure transmission
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	// Clear session key from memory immediately
	crypto.SecureZeroSessionKey(sessionKey)

	// Log partial authentication
	database.LogUserAction(request.Email, "OPAQUE auth completed, awaiting TOTP", "")
	logging.InfoLogger.Printf("OPAQUE user authenticated, TOTP required: %s", request.Email)

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

	// Get user email from JWT token
	email := auth.GetEmailFromToken(c)

	// Decode session key
	sessionKey, err := base64.StdEncoding.DecodeString(request.SessionKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid session key format")
	}
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Check if user already has TOTP enabled
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, email)
	if err != nil && err.Error() != "sql: no rows in result set" {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check TOTP status")
	}

	if totpEnabled {
		return echo.NewHTTPError(http.StatusConflict, "TOTP already enabled for this user")
	}

	// Generate TOTP setup
	setup, err := auth.GenerateTOTPSetup(email, sessionKey)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate TOTP setup for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate TOTP setup")
	}

	// Store TOTP setup in database
	if err := auth.StoreTOTPSetup(database.DB, email, setup, sessionKey); err != nil {
		logging.ErrorLogger.Printf("Failed to store TOTP setup for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to store TOTP setup")
	}

	// Log TOTP setup initiation
	database.LogUserAction(email, "initiated TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup initiated for user: %s", email)

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

	// Get user email from JWT token
	email := auth.GetEmailFromToken(c)

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
	if err := auth.CompleteTOTPSetup(database.DB, email, request.Code, sessionKey); err != nil {
		logging.ErrorLogger.Printf("Failed to complete TOTP setup for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid TOTP code")
	}

	// Check if this is a temporary TOTP token (registration flow)
	isTemporaryToken := auth.RequiresTOTPFromToken(c)

	// Log successful TOTP setup
	database.LogUserAction(email, "completed TOTP setup", "")
	logging.InfoLogger.Printf("TOTP setup completed for user: %s", email)

	// If this is a temporary TOTP token from registration, provide full access tokens
	if isTemporaryToken {
		// Generate full access token
		token, err := auth.GenerateFullAccessToken(email)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", email, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
		}

		// Generate refresh token
		refreshToken, err := models.CreateRefreshToken(database.DB, email)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", email, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
		}

		// Get user record for response
		user, err := models.GetUserByEmail(database.DB, email)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to get user record for %s: %v", email, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Encode session key for response
		sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

		logging.InfoLogger.Printf("Registration completed with TOTP setup for user: %s", email)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":       "TOTP setup and registration completed successfully",
			"enabled":       true,
			"access_token":  token,
			"refresh_token": refreshToken,
			"session_key":   sessionKeyB64,
			"auth_method":   "OPAQUE+TOTP",
			"user": map[string]interface{}{
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

	// Get user email from JWT token
	email := auth.GetEmailFromToken(c)

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
		if err := auth.ValidateBackupCode(database.DB, email, request.Code, sessionKey); err != nil {
			logging.ErrorLogger.Printf("Failed backup code validation for %s: %v", email, err)
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid backup code")
		}
		database.LogUserAction(email, "used backup code", "")
	} else {
		if err := auth.ValidateTOTPCode(database.DB, email, request.Code, sessionKey); err != nil {
			logging.ErrorLogger.Printf("Failed TOTP code validation for %s: %v", email, err)
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid TOTP code")
		}
		database.LogUserAction(email, "authenticated with TOTP", "")
	}

	// Get user record
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user record for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Generate full access token
	token, err := auth.GenerateFullAccessToken(email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
	}

	// Generate refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
	}

	// Encode session key for response
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	// Log successful authentication
	database.LogUserAction(email, "completed TOTP authentication", "")
	logging.InfoLogger.Printf("TOTP authentication completed for user: %s", email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":        token,
		"refreshToken": refreshToken,
		"sessionKey":   sessionKeyB64,
		"authMethod":   "OPAQUE+TOTP",
		"user": map[string]interface{}{
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

	// Get user email from JWT token
	email := auth.GetEmailFromToken(c)

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
	if err := auth.DisableTOTP(database.DB, email, request.CurrentCode, sessionKey); err != nil {
		logging.ErrorLogger.Printf("Failed to disable TOTP for %s: %v", email, err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid TOTP code")
	}

	// Log TOTP disabling
	database.LogUserAction(email, "disabled TOTP", "")
	logging.InfoLogger.Printf("TOTP disabled for user: %s", email)

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
	// Get user email from JWT token
	email := auth.GetEmailFromToken(c)

	// Check TOTP status
	totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", email, err)
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
