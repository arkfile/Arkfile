package handlers

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSessionLifetimeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE refresh_tokens (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN DEFAULT FALSE,
			last_used TIMESTAMP,
			family_id TEXT NOT NULL,
			superseded_by_hash TEXT,
			family_revoked_at TIMESTAMP
		);
		CREATE TABLE session_families (
			family_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			login_kind TEXT,
			session_started_at TIMESTAMP NOT NULL,
			last_user_activity TIMESTAMP NOT NULL,
			last_transfer_request_at TIMESTAMP,
			grace_target TEXT,
			grace_target_kind TEXT,
			grace_last_request_at TIMESTAMP,
			ended_at TIMESTAMP,
			ended_reason TEXT
		);
	`)
	require.NoError(t, err)
	return db
}

func sessionLifetimeContext(e *echo.Echo, method, path string, claims *auth.Claims) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath(path)
	c.Set("user", &jwt.Token{Claims: claims, Valid: true})
	return c, rec
}

func TestSessionLifetimeMiddlewareRejectsIdleUnexpiredToken(t *testing.T) {
	db := setupSessionLifetimeDB(t)
	defer db.Close()
	session, err := models.CreateRefreshSession(db, "idle-middleware-user", "")
	require.NoError(t, err)
	require.NoError(t, models.ShiftSessionFamilyClocks(
		db,
		session.FamilyID,
		time.Now(),
		models.SessionIdleLimit+time.Minute,
		0,
	))

	e := echo.New()
	c, rec := sessionLifetimeContext(e, http.MethodGet, "/api/files", &auth.Claims{
		Username: "idle-middleware-user",
		FamilyID: session.FamilyID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Audience:  jwt.ClaimStrings{auth.AudienceAPI},
		},
	})
	called := false
	err = SessionLifetimeMiddleware(db)(func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})(c)

	require.NoError(t, err)
	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), models.SessionErrorIdle)
}

func TestSessionLifetimeMiddlewareAllowsPreUpgradeTokenOnly(t *testing.T) {
	db := setupSessionLifetimeDB(t)
	defer db.Close()
	e := echo.New()

	oldContext, oldRecorder := sessionLifetimeContext(e, http.MethodGet, "/api/files", &auth.Claims{
		Username: "legacy-user",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(auth.ProcessStartedAt().Add(-time.Minute)),
			Audience: jwt.ClaimStrings{auth.AudienceAPI},
		},
	})
	err := SessionLifetimeMiddleware(db)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(oldContext)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, oldRecorder.Code)

	newContext, newRecorder := sessionLifetimeContext(e, http.MethodGet, "/api/files", &auth.Claims{
		Username: "missing-family-user",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			Audience: jwt.ClaimStrings{auth.AudienceAPI},
		},
	})
	err = SessionLifetimeMiddleware(db)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(newContext)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, newRecorder.Code)
}

func TestSessionLifetimeMiddlewareRecordsAcceptedActivity(t *testing.T) {
	db := setupSessionLifetimeDB(t)
	defer db.Close()
	session, err := models.CreateRefreshSession(db, "active-middleware-user", "")
	require.NoError(t, err)
	require.NoError(t, models.ShiftSessionFamilyClocks(
		db,
		session.FamilyID,
		time.Now(),
		models.SessionIdleLimit-time.Minute,
		0,
	))

	e := echo.New()
	c, rec := sessionLifetimeContext(e, http.MethodGet, "/api/files", &auth.Claims{
		Username: "active-middleware-user",
		FamilyID: session.FamilyID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Audience: jwt.ClaimStrings{auth.AudienceAPI},
		},
	})
	err = SessionLifetimeMiddleware(db)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	family, err := models.GetSessionFamily(db, session.FamilyID)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), family.LastUserActivity, 5*time.Second)
}

func TestSessionLifetimeMiddlewareLetsLogoutReachHandler(t *testing.T) {
	db := setupSessionLifetimeDB(t)
	defer db.Close()
	e := echo.New()
	c, rec := sessionLifetimeContext(e, http.MethodPost, "/api/logout", &auth.Claims{
		Username: "logout-user",
		FamilyID: "already-ended-family",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Audience: jwt.ClaimStrings{auth.AudienceAPI},
		},
	})
	err := SessionLifetimeMiddleware(db)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSessionLifetimeMiddlewareRejectsLoggedOutAccessToken(t *testing.T) {
	db := setupSessionLifetimeDB(t)
	defer db.Close()
	session, err := models.CreateRefreshSession(db, "logged-out-user", "")
	require.NoError(t, err)
	_, err = models.EndSessionFamily(db, session.FamilyID, models.SessionEndReasonLogout, time.Now())
	require.NoError(t, err)

	e := echo.New()
	c, rec := sessionLifetimeContext(e, http.MethodGet, "/api/files", &auth.Claims{
		Username: "logged-out-user",
		FamilyID: session.FamilyID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Audience: jwt.ClaimStrings{auth.AudienceAPI},
		},
	})
	err = SessionLifetimeMiddleware(db)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), models.SessionErrorLoggedOut)
}

func TestShiftOwnSessionClocksSurvivesMiddlewareCompletion(t *testing.T) {
	db := setupSessionLifetimeDB(t)
	defer db.Close()
	originalDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = originalDB })

	session, err := models.CreateRefreshSession(db, "self-shift-user", "")
	require.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/dev-test/sessions/shift-self",
		bytes.NewBufferString(`{"idle_seconds":21660}`),
	)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/dev-test/sessions/shift-self")
	c.Set("user", &jwt.Token{
		Valid: true,
		Claims: &auth.Claims{
			Username: "self-shift-user",
			FamilyID: session.FamilyID,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Audience: jwt.ClaimStrings{auth.AudienceAPI},
			},
		},
	})

	err = SessionLifetimeMiddleware(db)(ShiftOwnSessionClocks)(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	_, err = models.CheckSessionFamily(db, session.FamilyID, time.Now())
	require.ErrorIs(t, err, models.ErrSessionIdle)
}
