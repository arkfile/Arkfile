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
				clearSessionCookies(c)
				return JSONError(c, http.StatusUnauthorized, "Session identity is missing")
			}

			// Logout must remain reachable after the idle clock has elapsed so
			// it can clear cookies and preserve the family's first end reason.
			if c.Path() == "/api/logout" {
				return next(c)
			}

			now := time.Now()
			family, err := models.AuthorizeSessionUse(db, claims.FamilyID, now, sessionUseForRequest(c, db, claims.Username))
			if err != nil {
				if code := models.SessionErrorCode(err); code != "" {
					if family != nil && family.EndedNow {
						logging.InfoLogger.Printf("SECURITY: Session ended for user %s: %s", family.Username, family.EndedReason)
					}
					if family == nil || family.EndedAt != nil {
						clearSessionCookies(c)
					}
					return JSONErrorCode(c, http.StatusUnauthorized, code, sessionErrorMessage(code, family))
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

			handlerErr := next(c)
			// The clock-shift endpoints must not count as activity, or shifting
			// the caller's own family would be undone by this request.
			if handlerErr == nil && !sessionClockShiftPaths[c.Path()] {
				if err := models.RecordSessionActivity(db, claims.FamilyID, time.Now()); err != nil && err != sql.ErrNoRows {
					logging.ErrorLogger.Printf("Failed to record completed session activity: %v", err)
				}
			}
			return handlerErr
		}
	}
}

var sessionClockShiftPaths = map[string]bool{
	"/api/dev-test/sessions/shift-self":  true,
	"/api/admin/dev-test/sessions/shift": true,
}

func sessionUseForRequest(c echo.Context, db *sql.DB, username string) models.SessionUse {
	switch c.Path() {
	case "/api/uploads/:sessionId/chunks/:chunkNumber",
		"/api/uploads/:sessionId/complete",
		"/api/uploads/:sessionId/status",
		"/api/uploads/:sessionId":
		sessionID := c.Param("sessionId")
		use := models.SessionUse{
			Transfer:  true,
			GraceKind: models.GraceKindUpload,
			GraceID:   sessionID,
		}
		if started, ok := uploadSessionStartedAt(db, sessionID, username); ok {
			use.UploadStarted = &started
		}
		return use
	case "/api/files/:fileId/chunks/:chunkIndex":
		return models.SessionUse{
			Transfer:  true,
			GraceKind: models.GraceKindFile,
			GraceID:   c.Param("fileId"),
		}
	default:
		return models.SessionUse{}
	}
}

func uploadSessionStartedAt(db *sql.DB, sessionID, username string) (time.Time, bool) {
	var raw string
	err := db.QueryRow(
		`SELECT created_at FROM upload_sessions WHERE id = ? AND owner_username = ?`,
		sessionID, username,
	).Scan(&raw)
	if err != nil {
		return time.Time{}, false
	}
	started, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		if started, err = time.Parse(time.RFC3339, raw); err != nil {
			if started, err = time.Parse("2006-01-02 15:04:05", raw); err != nil {
				return time.Time{}, false
			}
		}
	}
	return started, true
}
