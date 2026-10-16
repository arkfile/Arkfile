package handlers

import (
	"database/sql"
	"net/http"
	"slices"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// SessionLifetimeMiddleware enforces server-side limits for full login
// families. Refresh performs the same clock check in ValidateRefreshSession.
func SessionLifetimeMiddleware(db *sql.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := auth.GetClaimsFromContext(c)
			if !ok {
				return JSONError(c, http.StatusUnauthorized, "Unauthorized")
			}

			// Reset-tier tokens are temporary handoff credentials, not full
			// sessions. MFAResetJWTMiddleware accepts both token tiers.
			if claims.FamilyID == "" && slices.Contains(claims.Audience, auth.AudienceReset) {
				return next(c)
			}

			if claims.FamilyID == "" {
				if claims.IssuedAt != nil && claims.IssuedAt.Time.Before(auth.ProcessStartedAt()) {
					return next(c)
				}
				clearSessionCookies(c)
				return JSONError(c, http.StatusUnauthorized, "Session identity is missing")
			}

			// Logout must remain reachable after the idle clock has elapsed so
			// it can clear cookies and preserve the family's first end reason.
			if c.Path() == "/api/logout" {
				return next(c)
			}

			family, err := models.CheckSessionFamily(db, claims.FamilyID, time.Now())
			if err != nil {
				if code := models.SessionErrorCode(err); code != "" {
					if family != nil && family.EndedNow {
						logging.InfoLogger.Printf("SECURITY: Session ended for user %s: %s", family.Username, family.EndedReason)
					}
					clearSessionCookies(c)
					return JSONErrorCode(c, http.StatusUnauthorized, code, sessionErrorMessage(code))
				}
				if err == sql.ErrNoRows {
					clearSessionCookies(c)
					return JSONError(c, http.StatusUnauthorized, "Session not found")
				}
				logging.ErrorLogger.Printf("Failed to check session family: %v", err)
				return JSONError(c, http.StatusInternalServerError, "Failed to validate session")
			}
			if family.Username != claims.Username || family.LoginKind != claims.LoginKind {
				clearSessionCookies(c)
				return JSONError(c, http.StatusUnauthorized, "Session identity does not match")
			}

			if err := models.RecordSessionActivity(db, claims.FamilyID, time.Now()); err != nil {
				if err == sql.ErrNoRows {
					return JSONError(c, http.StatusUnauthorized, "Session not found")
				}
				logging.ErrorLogger.Printf("Failed to record session activity: %v", err)
				return JSONError(c, http.StatusInternalServerError, "Failed to update session")
			}

			handlerErr := next(c)
			if handlerErr == nil && c.Path() != "/api/dev-test/sessions/shift-self" {
				if err := models.RecordSessionActivity(db, claims.FamilyID, time.Now()); err != nil && err != sql.ErrNoRows {
					logging.ErrorLogger.Printf("Failed to record completed session activity: %v", err)
				}
			}
			return handlerErr
		}
	}
}
