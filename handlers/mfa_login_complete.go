package handlers

import (
	"net/http"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// completeMFALogin issues full session credentials after any MFA method succeeds.
func completeMFALogin(c echo.Context, username, authMethod string) error {
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	now := time.Now()
	_, err = database.DB.Exec(
		"UPDATE users SET last_login = ? WHERE username = ?",
		now, username,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update last_login for %s: %v", username, err)
	}

	if user.IsAdmin {
		km, err := crypto.GetKeyManager()
		if err == nil {
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

	token, expirationTime, err := auth.GenerateFullAccessToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session")
	}

	refreshToken, err := models.CreateRefreshToken(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session")
	}

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

	database.LogUserAction(username, "completed MFA authentication", "")
	logging.InfoLogger.Printf("MFA authentication completed for user: %s", username)

	loginEntityID := logging.GetOrCreateEntityID(c)
	logging.LogSecurityEventWithEntityID(
		logging.EventOpaqueLoginSuccess,
		loginEntityID,
		map[string]interface{}{
			"username":    username,
			"auth_method": authMethod,
		},
	)

	return JSONResponse(c, http.StatusOK, "MFA authentication completed", map[string]interface{}{
		"token":         token,
		"refresh_token": refreshToken,
		"expires_at":    expirationTime,
		"auth_method":   authMethod,
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

// completeMFARegistrationSetup issues full session after enrollment during registration flow.
func completeMFARegistrationSetup(c echo.Context, username, authMethod string) error {
	token, expirationTime, err := auth.GenerateFullAccessToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate full access token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session")
	}

	refreshToken, err := models.CreateRefreshToken(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to create session")
	}

	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user record for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to get user details")
	}

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

	database.LogUserAction(username, "completed MFA setup", "")
	logging.InfoLogger.Printf("Registration completed with MFA setup for user: %s", username)

	return JSONResponse(c, http.StatusOK, "MFA setup and registration completed successfully", map[string]interface{}{
		"enabled":       true,
		"token":         token,
		"refresh_token": refreshToken,
		"expires_at":    expirationTime,
		"auth_method":   authMethod,
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
