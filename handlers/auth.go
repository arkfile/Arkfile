package handlers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/auth"
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
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired refresh token")
	}

	// Generate new JWT token
	token, err := auth.GenerateToken(userEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate token: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Could not create new access token")
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
			logging.ErrorLogger.Printf("Failed to revoke refresh token: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke refresh token")
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
