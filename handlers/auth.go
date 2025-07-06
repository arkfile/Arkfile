package handlers

import (
	"database/sql"
	"encoding/base64"
	"errors"
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
	Email            string `json:"email"`
	Password         string `json:"password"`
	DeviceCapability string `json:"deviceCapability"`
}

// OpaqueLoginRequest represents the request for OPAQUE login
type OpaqueLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// DeviceCapabilityRequest represents a request for device capability detection
type DeviceCapabilityRequest struct {
	MemoryGB        float64 `json:"memoryGB"`
	CPUCores        int     `json:"cpuCores"`
	IsMobile        bool    `json:"isMobile"`
	UserAgent       string  `json:"userAgent"`
	ForceCapability string  `json:"forceCapability,omitempty"`
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

	if len(request.Password) < 12 {
		return echo.NewHTTPError(http.StatusBadRequest, "Password must be at least 12 characters long")
	}

	if request.DeviceCapability == "" {
		request.DeviceCapability = "interactive" // Safe default
	}

	// Validate device capability
	validCapabilities := []string{"minimal", "interactive", "balanced", "maximum"}
	isValidCapability := false
	for _, valid := range validCapabilities {
		if request.DeviceCapability == valid {
			isValidCapability = true
			break
		}
	}
	if !isValidCapability {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid device capability")
	}

	// Parse device capability
	var deviceCapability crypto.DeviceCapability
	switch request.DeviceCapability {
	case "minimal":
		deviceCapability = crypto.DeviceMinimal
	case "interactive":
		deviceCapability = crypto.DeviceInteractive
	case "balanced":
		deviceCapability = crypto.DeviceBalanced
	case "maximum":
		deviceCapability = crypto.DeviceMaximum
	default:
		deviceCapability = crypto.DeviceInteractive
	}

	// Check if user already exists
	_, err := models.GetUserByEmail(database.DB, request.Email)
	if err == nil {
		return echo.NewHTTPError(http.StatusConflict, "Email already registered")
	}

	// Perform OPAQUE registration with comprehensive error handling
	err = auth.RegisterUser(database.DB, request.Email, request.Password, deviceCapability)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("OPAQUE registration failed for %s: %v", request.Email, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
	}

	// Create user record in the users table for JWT and application data
	// For OPAQUE users, we use a placeholder password since authentication is handled by OPAQUE
	user, err := models.CreateUser(database.DB, request.Email, "OPAQUE_AUTH_PLACEHOLDER")
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create user record for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete registration")
	}

	// Log successful registration
	database.LogUserAction(request.Email, "registered with OPAQUE", "")
	logging.InfoLogger.Printf("OPAQUE user registered: %s with capability %s", request.Email, request.DeviceCapability)

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message":          "Account created successfully with OPAQUE authentication",
		"authMethod":       "OPAQUE",
		"deviceCapability": request.DeviceCapability,
		"status": map[string]interface{}{
			"is_approved": user.IsApproved,
			"is_admin":    user.IsAdmin,
		},
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

	// Get user record for approval status check
	user, err := models.GetUserByEmail(database.DB, request.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Consistent timing to prevent username enumeration
			time.Sleep(100 * time.Millisecond)
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
		}
		logging.ErrorLogger.Printf("Database error during OPAQUE login for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Check user approval status
	if !user.IsApproved {
		return c.JSON(http.StatusForbidden, map[string]interface{}{
			"message":          "User account not approved",
			"userStatus":       "pending_approval",
			"registrationDate": user.CreatedAt,
		})
	}

	// Perform OPAQUE authentication
	sessionKey, err := auth.AuthenticateUser(database.DB, request.Email, request.Password)
	if err != nil {
		logging.ErrorLogger.Printf("OPAQUE authentication failed for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	// Generate JWT token for session management
	token, err := auth.GenerateToken(request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate JWT token for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication succeeded but session creation failed")
	}

	// Generate refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", request.Email, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication succeeded but session creation failed")
	}

	// Encode session key for secure transmission
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	// Clear session key from memory immediately
	crypto.SecureZeroSessionKey(sessionKey)

	// Log successful authentication
	database.LogUserAction(request.Email, "logged in with OPAQUE", "")
	logging.InfoLogger.Printf("OPAQUE user authenticated: %s", request.Email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":        token,
		"refreshToken": refreshToken,
		"sessionKey":   sessionKeyB64,
		"authMethod":   "OPAQUE",
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

// DetectDeviceCapability suggests an appropriate device capability profile
func DetectDeviceCapability(c echo.Context) error {
	var request DeviceCapabilityRequest
	if err := c.Bind(&request); err != nil {
		// If no request body, try to detect from headers
		userAgent := c.Request().Header.Get("User-Agent")
		request.UserAgent = userAgent
	}

	// If user forced a specific capability, respect it
	if request.ForceCapability != "" {
		validCapabilities := []string{"minimal", "interactive", "balanced", "maximum"}
		for _, valid := range validCapabilities {
			if request.ForceCapability == valid {
				return c.JSON(http.StatusOK, map[string]interface{}{
					"recommendedCapability": request.ForceCapability,
					"source":                "user_override",
					"description":           getCapabilityDescription(request.ForceCapability),
				})
			}
		}
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid forced capability")
	}

	// Auto-detect based on provided information
	var recommendedCapability string
	var source string

	if request.MemoryGB > 0 || request.CPUCores > 0 || request.UserAgent != "" {
		// Browser-based detection
		if request.IsMobile || strings.Contains(strings.ToLower(request.UserAgent), "mobile") {
			recommendedCapability = "interactive"
			source = "mobile_device_detected"
		} else if request.MemoryGB >= 8 && request.CPUCores >= 4 {
			recommendedCapability = "maximum"
			source = "high_performance_detected"
		} else if request.MemoryGB >= 4 && request.CPUCores >= 2 {
			recommendedCapability = "balanced"
			source = "mid_range_detected"
		} else {
			recommendedCapability = "interactive"
			source = "conservative_estimate"
		}
	} else {
		// Conservative default when no information available
		recommendedCapability = "interactive"
		source = "default_safe"
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"recommendedCapability": recommendedCapability,
		"source":                source,
		"description":           getCapabilityDescription(recommendedCapability),
		"profiles": map[string]interface{}{
			"minimal": map[string]interface{}{
				"memory":      "16MB",
				"iterations":  1,
				"threads":     1,
				"time":        "~50ms",
				"description": "Fastest, lowest security - for very old devices",
			},
			"interactive": map[string]interface{}{
				"memory":      "32MB",
				"iterations":  1,
				"threads":     2,
				"time":        "~100ms",
				"description": "Fast and compatible - recommended for mobile",
			},
			"balanced": map[string]interface{}{
				"memory":      "64MB",
				"iterations":  2,
				"threads":     2,
				"time":        "~200ms",
				"description": "Good security and performance balance",
			},
			"maximum": map[string]interface{}{
				"memory":      "128MB",
				"iterations":  4,
				"threads":     4,
				"time":        "~400ms",
				"description": "Maximum security - for high-end devices",
			},
		},
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

	// Check OPAQUE server initialization
	_, err := auth.GetOPAQUEServer()
	if err != nil {
		response.Message = "OPAQUE server not initialized: " + err.Error()
		return c.JSON(http.StatusServiceUnavailable, response)
	}
	response.OpaqueReady = true

	// Check database connectivity
	if err := database.DB.Ping(); err != nil {
		response.Message = "Database connectivity failed: " + err.Error()
		return c.JSON(http.StatusServiceUnavailable, response)
	}
	response.DatabaseConnected = true

	// Validate OPAQUE setup
	if err := auth.ValidateOPAQUESetup(database.DB); err != nil {
		response.Message = "OPAQUE setup validation failed: " + err.Error()
		return c.JSON(http.StatusServiceUnavailable, response)
	}
	response.ServerKeysLoaded = true

	// All checks passed
	response.Status = "healthy"
	response.Message = "OPAQUE authentication system fully operational"

	return c.JSON(http.StatusOK, response)
}

// Helper function to get capability description
func getCapabilityDescription(capability string) string {
	descriptions := map[string]string{
		"minimal":     "16MB memory, 1 iteration, 1 thread - fastest but lowest security",
		"interactive": "32MB memory, 1 iteration, 2 threads - fast and compatible",
		"balanced":    "64MB memory, 2 iterations, 2 threads - good balance",
		"maximum":     "128MB memory, 4 iterations, 4 threads - maximum security",
	}
	if desc, exists := descriptions[capability]; exists {
		return desc
	}
	return "Unknown capability profile"
}
