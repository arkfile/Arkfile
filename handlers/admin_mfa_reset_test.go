package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAdminMFAResetIntegrationDB(t *testing.T) {
	t.Helper()
	os.Setenv("DEBUG_MODE", "true")
	crypto.SetTier3MasterForTest(make([]byte, 32))

	db := openAdminMFAResetTestDB(t)
	original := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = original })
}

func openAdminMFAResetTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	schema := `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			username_folded TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			total_storage_bytes INTEGER DEFAULT 0,
			storage_limit_bytes INTEGER NOT NULL,
			is_approved BOOLEAN DEFAULT FALSE,
			approved_by TEXT,
			approved_at TIMESTAMP,
			is_admin BOOLEAN DEFAULT FALSE,
			deleted_at TIMESTAMP,
			last_login TIMESTAMP
		);
		CREATE TABLE user_mfa_credentials (
			username TEXT PRIMARY KEY,
			method_type TEXT NOT NULL DEFAULT 'totp',
			label TEXT,
			credential_data BLOB NOT NULL,
			enabled BOOLEAN DEFAULT FALSE,
			setup_completed BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_used DATETIME,
			failed_attempts_in_window INTEGER NOT NULL DEFAULT 0,
			window_started_at DATETIME,
			last_failed_attempt_at DATETIME
		);
		CREATE TABLE user_mfa_backup_codes (
			username TEXT NOT NULL,
			code_index INTEGER NOT NULL,
			code_hash BLOB NOT NULL,
			used_at TIMESTAMP,
			PRIMARY KEY (username, code_index),
			UNIQUE (username, code_hash)
		);
		CREATE TABLE mfa_usage_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			window_start INTEGER NOT NULL,
			used_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE mfa_backup_usage (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			used_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
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
		CREATE TABLE revoked_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token_id TEXT NOT NULL UNIQUE,
			username TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			reason TEXT
		);
		CREATE TABLE user_jwt_revocations (
			username TEXT PRIMARY KEY,
			revoked_at TIMESTAMP NOT NULL,
			reason TEXT
		);
		CREATE TABLE user_activity (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)
	return db
}

func insertAdminMFAResetUser(t *testing.T, db *sql.DB, username string, isAdmin bool) {
	t.Helper()
	adminFlag := 0
	if isAdmin {
		adminFlag = 1
	}
	_, err := db.Exec(`INSERT INTO users (
		username, username_folded, storage_limit_bytes, is_approved, is_admin
	) VALUES (?, ?, 1073741824, 1, ?)`, username, username, adminFlag)
	require.NoError(t, err)
}

func seedTargetMFA(t *testing.T, username string) {
	t.Helper()
	setup, err := auth.GenerateMFASetup(username)
	require.NoError(t, err)
	require.NoError(t, auth.StoreMFASetup(database.DB, username, setup))
	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	require.NoError(t, err)
	require.NoError(t, auth.CompleteMFASetup(database.DB, username, code))
}

func adminMFAResetStack(h echo.HandlerFunc) echo.HandlerFunc {
	return auth.JWTMiddleware()(auth.RequireFullJWT(RequireMFA(AdminMiddleware(h))))
}

func invokeAdminMFAReset(t *testing.T, username, token string, body map[string]interface{}) (*httptest.ResponseRecorder, error) {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+username+"/reset-mfa", bytes.NewReader(payload))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("username")
	c.SetParamValues(username)
	return rec, adminMFAResetStack(AdminResetUserMFA)(c)
}

func TestAdminResetUserMFA_Direct_Success(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const adminUsername = "reset-admin"
	const targetUsername = "reset-target"
	insertAdminMFAResetUser(t, database.DB, adminUsername, true)
	insertAdminMFAResetUser(t, database.DB, targetUsername, false)
	seedTargetMFA(t, targetUsername)

	e := echo.New()
	body := bytes.NewReader([]byte(`{"confirm":true}`))
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+targetUsername+"/reset-mfa", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	claims := &auth.Claims{Username: adminUsername}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := AdminResetUserMFA(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	enabled, err := auth.IsUserMFAEnabled(database.DB, targetUsername)
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestAdminResetUserMFA_Stack_RejectsWithoutConfirm(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const adminUsername = "reset-admin"
	insertAdminMFAResetUser(t, database.DB, adminUsername, true)
	seedTargetMFA(t, adminUsername)

	token, _, err := auth.GenerateFullAccessToken(adminUsername)
	require.NoError(t, err)

	rec, err := invokeAdminMFAReset(t, "some-user", token, map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminResetUserMFA_Stack_RejectsCredentialScopedFields(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const adminUsername = "reset-admin"
	const targetUsername = "reset-target"
	insertAdminMFAResetUser(t, database.DB, adminUsername, true)
	insertAdminMFAResetUser(t, database.DB, targetUsername, false)
	seedTargetMFA(t, adminUsername)
	seedTargetMFA(t, targetUsername)

	token, _, err := auth.GenerateFullAccessToken(adminUsername)
	require.NoError(t, err)

	rec, err := invokeAdminMFAReset(t, targetUsername, token, map[string]interface{}{
		"confirm":       true,
		"credential_id": "lost-yubikey",
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "credential_scoped_reset_unsupported", resp["error"])
}

func TestAdminResetUserMFA_Stack_AdminResetsTarget(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const adminUsername = "reset-admin"
	const targetUsername = "reset-target"
	insertAdminMFAResetUser(t, database.DB, adminUsername, true)
	insertAdminMFAResetUser(t, database.DB, targetUsername, false)
	seedTargetMFA(t, adminUsername)
	seedTargetMFA(t, targetUsername)

	token, _, err := auth.GenerateFullAccessToken(adminUsername)
	require.NoError(t, err)

	rec, err := invokeAdminMFAReset(t, targetUsername, token, map[string]interface{}{"confirm": true})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	enabled, err := auth.IsUserMFAEnabled(database.DB, targetUsername)
	require.NoError(t, err)
	assert.False(t, enabled)

	adminEnabled, err := auth.IsUserMFAEnabled(database.DB, adminUsername)
	require.NoError(t, err)
	assert.True(t, adminEnabled)
}

func TestAdminResetUserMFA_Stack_RejectsNonAdmin(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const username = "regular-user"
	insertAdminMFAResetUser(t, database.DB, username, false)
	seedTargetMFA(t, username)

	token, _, err := auth.GenerateFullAccessToken(username)
	require.NoError(t, err)

	_, err = invokeAdminMFAReset(t, username, token, map[string]interface{}{"confirm": true})
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)
}

func TestAdminResetUserMFA_Handler_RequiresConfirm(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const adminUsername = "reset-admin"
	insertAdminMFAResetUser(t, database.DB, adminUsername, true)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/bob/reset-mfa", bytes.NewReader([]byte(`{}`)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("username")
	c.SetParamValues("bob")
	c.Set("user", jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{Username: adminUsername}))

	err := AdminResetUserMFA(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminResetUserMFA_Handler_UserNotFound(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const adminUsername = "reset-admin"
	insertAdminMFAResetUser(t, database.DB, adminUsername, true)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/missing/reset-mfa", bytes.NewReader([]byte(`{"confirm":true}`)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("username")
	c.SetParamValues("missing")
	c.Set("user", jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{Username: adminUsername}))

	err := AdminResetUserMFA(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAdminResetUserMFA_Handler_RevokesTokens(t *testing.T) {
	setupAdminMFAResetIntegrationDB(t)
	const adminUsername = "reset-admin"
	const targetUsername = "reset-target"
	insertAdminMFAResetUser(t, database.DB, adminUsername, true)
	insertAdminMFAResetUser(t, database.DB, targetUsername, false)
	seedTargetMFA(t, targetUsername)

	_, err := database.DB.Exec(`INSERT INTO refresh_tokens (
		id, username, token_hash, expires_at, family_id
	) VALUES ('rt-1', ?, 'hash-1', datetime('now', '+1 day'), 'family-1')`, targetUsername)
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+targetUsername+"/reset-mfa", bytes.NewReader([]byte(`{"confirm":true}`)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)
	c.Set("user", jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{Username: adminUsername}))

	require.NoError(t, AdminResetUserMFA(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var revoked bool
	err = database.DB.QueryRow(`SELECT revoked FROM refresh_tokens WHERE id = 'rt-1'`).Scan(&revoked)
	require.NoError(t, err)
	assert.True(t, revoked)

	var revokeReason string
	err = database.DB.QueryRow(`SELECT reason FROM user_jwt_revocations WHERE username = ?`, targetUsername).Scan(&revokeReason)
	require.NoError(t, err)
	assert.Equal(t, "admin mfa reset", revokeReason)
}
