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
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRotationIntegrationDB(t *testing.T) {
	t.Helper()
	os.Setenv("DEBUG_MODE", "true")
	crypto.SetUserSecretMasterForTest(make([]byte, 32))

	db := openRotationTestDB(t)
	original := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = original })
}

func openRotationTestDB(t *testing.T) *sql.DB {
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
		CREATE TABLE user_secret_rotation_mandates (
			nonce TEXT PRIMARY KEY,
			admin_username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			consumed_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE envelope_master_rotation_mandates (
			nonce TEXT PRIMARY KEY,
			admin_username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			consumed_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)
	return db
}

func insertRotationAdminUser(t *testing.T, db *sql.DB, username string, isAdmin bool) {
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

func seedAdminMFA(t *testing.T, username string) {
	t.Helper()
	setup, err := auth.GenerateMFASetup(username)
	require.NoError(t, err)
	require.NoError(t, auth.StoreMFASetup(database.DB, username, setup))
	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	require.NoError(t, err)
	require.NoError(t, auth.CompleteMFASetup(database.DB, username, code))
}

func setFullTokenOnContext(t *testing.T, c echo.Context, username string) {
	t.Helper()
	fullToken, _, err := auth.GenerateFullAccessToken(username)
	require.NoError(t, err)
	token, err := jwt.ParseWithClaims(fullToken, &auth.Claims{}, func(tok *jwt.Token) (interface{}, error) {
		return auth.GetJWTFullPublicKey(), nil
	})
	require.NoError(t, err)
	c.Set("user", token)
}

func adminRotationStack(h echo.HandlerFunc) echo.HandlerFunc {
	return auth.JWTMiddleware()(auth.RequireFullJWT(RequireMFA(AdminMiddleware(h))))
}

func invokeAdminRotationPrepare(t *testing.T, token string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/system/prepare-user-secret-master-rotation", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := adminRotationStack(AdminPrepareUserSecretMasterRotation)(c)
	return rec, err
}

func TestAdminPrepareUserSecretMasterRotation_Direct_IssuesMandate(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "direct-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/system/prepare-user-secret-master-rotation", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	setFullTokenOnContext(t, c, adminUsername)

	err := AdminPrepareUserSecretMasterRotation(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "User-secret rotation mandate issued", resp["message"])

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	mandate, ok := data["mandate"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, mandate)
	assert.NotEmpty(t, data["expires_at"])

	payload, err := auth.VerifyUserSecretRotationMandate(mandate, auth.GetJWTFullPublicKey())
	require.NoError(t, err)
	assert.Equal(t, adminUsername, payload.AdminUsername)
}

func TestAdminPrepareEnvelopeMasterRotation_Direct_IssuesMandate(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "envelope-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/system/prepare-envelope-master-rotation", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	setFullTokenOnContext(t, c, adminUsername)

	err := AdminPrepareEnvelopeMasterRotation(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "Envelope master rotation mandate issued", resp["message"])

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	mandate, ok := data["mandate"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, mandate)
	assert.NotEmpty(t, data["expires_at"])

	payload, err := auth.VerifyEnvelopeRotationMandate(mandate, auth.GetJWTFullPublicKey())
	require.NoError(t, err)
	assert.Equal(t, adminUsername, payload.AdminUsername)
}

func TestAdminRotationStack_RejectsWithoutToken(t *testing.T) {
	setupRotationIntegrationDB(t)
	_, err := invokeAdminRotationPrepare(t, "")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestAdminRotationStack_RejectsAdminWithoutMFA(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "no-mfa-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	token, _, err := auth.GenerateFullAccessToken(adminUsername)
	require.NoError(t, err)

	_, err = invokeAdminRotationPrepare(t, token)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
}

func TestAdminRotationStack_IssuesMandateForAdminWithMFA(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "rotate-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)
	seedAdminMFA(t, adminUsername)

	token, _, err := auth.GenerateFullAccessToken(adminUsername)
	require.NoError(t, err)

	rec, err := invokeAdminRotationPrepare(t, token)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)

	mandate, ok := data["mandate"].(string)
	require.True(t, ok)
	payload, err := auth.VerifyUserSecretRotationMandate(mandate, auth.GetJWTFullPublicKey())
	require.NoError(t, err)
	assert.Equal(t, adminUsername, payload.AdminUsername)
}

func TestAdminRotationStack_RejectsNonAdminWithMFA(t *testing.T) {
	setupRotationIntegrationDB(t)
	const username = "regular-user"
	insertRotationAdminUser(t, database.DB, username, false)
	seedAdminMFA(t, username)

	token, _, err := auth.GenerateFullAccessToken(username)
	require.NoError(t, err)

	_, err = invokeAdminRotationPrepare(t, token)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)
}

func TestAdminRotationStack_RejectsTempToken(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "temp-token-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)
	seedAdminMFA(t, adminUsername)

	tempToken, _, err := auth.GenerateTemporaryMFAToken(adminUsername)
	require.NoError(t, err)

	_, err = invokeAdminRotationPrepare(t, tempToken)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestAdminPrepareUserSecretMasterRotation_EmptyUsernameFails(t *testing.T) {
	setupRotationIntegrationDB(t)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/system/prepare-user-secret-master-rotation", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := AdminPrepareUserSecretMasterRotation(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// invokeAdminJWTHandler drives a handler through the full admin middleware
// stack (JWT -> RequireFullJWT -> RequireMFA -> AdminMiddleware).
func invokeAdminJWTHandler(t *testing.T, handler echo.HandlerFunc, path, token string, body []byte) (*httptest.ResponseRecorder, error) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := adminRotationStack(handler)(c)
	return rec, err
}

// invokeAdminJWTDirect calls a handler directly with a full token already on
// the context (bypassing the middleware stack) and a JSON request body.
func invokeAdminJWTDirect(t *testing.T, handler echo.HandlerFunc, adminUsername string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	setFullTokenOnContext(t, c, adminUsername)
	err := handler(c)
	require.NoError(t, err)
	return rec
}

func TestAdminRotateJWTKeys_Direct_Success(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "jwt-rotate-direct-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	_, fullBefore, err := auth.ActiveJWTKeyVersions()
	require.NoError(t, err)

	rec := invokeAdminJWTDirect(t, AdminRotateJWTKeys, adminUsername, nil)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "JWT signing keys rotated", resp["message"])

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	fullVersion, ok := data["full_version"].(float64)
	require.True(t, ok)
	assert.Greater(t, int(fullVersion), fullBefore)
}

func TestAdminRotateJWTKeysStack_IssuesForAdminWithMFA(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "jwt-rotate-stack-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)
	seedAdminMFA(t, adminUsername)

	token, _, err := auth.GenerateFullAccessToken(adminUsername)
	require.NoError(t, err)

	rec, err := invokeAdminJWTHandler(t, AdminRotateJWTKeys, "/api/admin/system/rotate-jwt-keys", token, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAdminRotateJWTKeysStack_RejectsAdminWithoutMFA(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "jwt-rotate-nomfa-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	token, _, err := auth.GenerateFullAccessToken(adminUsername)
	require.NoError(t, err)

	_, err = invokeAdminJWTHandler(t, AdminRotateJWTKeys, "/api/admin/system/rotate-jwt-keys", token, nil)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
}

func TestAdminRetireJWTKeyVersion_RejectsActiveVersion(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "jwt-retire-active-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	_, fullActive, err := auth.ActiveJWTKeyVersions()
	require.NoError(t, err)

	body, err := json.Marshal(adminRetireJWTKeyRequest{Version: fullActive})
	require.NoError(t, err)

	rec := invokeAdminJWTDirect(t, AdminRetireJWTKeyVersion, adminUsername, body)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestAdminRetireJWTKeyVersion_RejectsInvalidVersion(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "jwt-retire-bad-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	body, err := json.Marshal(adminRetireJWTKeyRequest{Version: 0})
	require.NoError(t, err)

	rec := invokeAdminJWTDirect(t, AdminRetireJWTKeyVersion, adminUsername, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminRetireJWTKeyVersion_Direct_Success(t *testing.T) {
	setupRotationIntegrationDB(t)
	const adminUsername = "jwt-retire-ok-admin"
	insertRotationAdminUser(t, database.DB, adminUsername, true)

	// Rotate so there is a superseded, non-active version to retire.
	res, err := auth.RotateJWTSigningKeys()
	require.NoError(t, err)
	require.Greater(t, res.FullVersion, 1)

	body, err := json.Marshal(adminRetireJWTKeyRequest{Version: res.FullVersion - 1})
	require.NoError(t, err)

	rec := invokeAdminJWTDirect(t, AdminRetireJWTKeyVersion, adminUsername, body)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "JWT signing key version retired", resp["message"])
}
