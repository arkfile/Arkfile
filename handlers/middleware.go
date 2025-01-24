package handlers

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
)

// TLSVersionCheck middleware adds TLS version information to response headers
// and logs TLS version usage for analytics
func TLSVersionCheck(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Ensure HTTPS
		if c.Request().TLS == nil {
			return echo.NewHTTPError(http.StatusForbidden,
				"HTTPS required for this operation")
		}

		// Get TLS version string
		var versionStr string
		switch c.Request().TLS.Version {
		case tls.VersionTLS13:
			versionStr = "1.3"
		case tls.VersionTLS12:
			versionStr = "1.2"
		default:
			versionStr = fmt.Sprintf("unknown (%d)", c.Request().TLS.Version)
		}

		// Add TLS version to response headers for client detection
		c.Response().Header().Set("X-TLS-Version", versionStr)

		// Log TLS version and cipher suite for analytics
		logging.InfoLogger.Printf("TLS Connection: version=%s cipher=%s client=%s path=%s",
			versionStr,
			tls.CipherSuiteName(c.Request().TLS.CipherSuite),
			c.RealIP(),
			c.Request().URL.Path,
		)

		return next(c)
	}
}

// RequireApproved ensures the user is approved before allowing access
func RequireApproved(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		email := auth.GetEmailFromToken(c)

		// Get user details
		user, err := models.GetUserByEmail(database.DB, email)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Check if user is approved or is an admin
		if !user.IsApproved && !user.HasAdminPrivileges() {
			return echo.NewHTTPError(http.StatusForbidden, "Account pending approval")
		}

		return next(c)
	}
}

// RequireAdmin ensures the user has admin privileges before allowing access
func RequireAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		email := auth.GetEmailFromToken(c)

		// Get user details
		user, err := models.GetUserByEmail(database.DB, email)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Check if user has admin privileges
		if !user.HasAdminPrivileges() {
			return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
		}

		return next(c)
	}
}
