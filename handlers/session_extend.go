package handlers

import (
	"fmt"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/models"
)

// ExtendAuthenticatedSession rotates the refresh token and re-issues full session
// cookies for an already-authenticated browser client. Used when starting a
// long-running flow (such as BTCPay checkout) so the session window resets.
func ExtendAuthenticatedSession(c echo.Context) error {
	cookieVal, err := c.Cookie(CookieRefresh)
	if err != nil || cookieVal.Value == "" {
		return fmt.Errorf("no refresh cookie")
	}

	username, newRefreshToken, err := models.ValidateRefreshToken(database.DB, cookieVal.Value)
	if err != nil {
		return fmt.Errorf("refresh token validation: %w", err)
	}

	token, _, err := auth.GenerateFullAccessToken(username)
	if err != nil {
		return fmt.Errorf("generate access token: %w", err)
	}

	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		return fmt.Errorf("generate csrf token: %w", err)
	}

	issueSessionCookies(c, token, newRefreshToken, csrfToken)
	return nil
}
