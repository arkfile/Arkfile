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
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMFAIntegrationDB(t *testing.T) {
	t.Helper()
	os.Setenv("DEBUG_MODE", "true")
	crypto.SetUserSecretMasterForTest(make([]byte, 32))

	db := openMFATestDB(t)
	original := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = original })

	_, err := db.Exec(`INSERT INTO users (
		username, username_folded, storage_limit_bytes, is_approved, is_admin
	) VALUES ('backupuser', 'backupuser', 1073741824, 1, 0)`)
	require.NoError(t, err)
}

func openMFATestDB(t *testing.T) *sql.DB {
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
			credential_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			method_type TEXT NOT NULL DEFAULT 'totp',
			credential_data BLOB NOT NULL,
			enabled BOOLEAN DEFAULT FALSE,
			setup_completed BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_used DATETIME,
			UNIQUE (username, method_type)
		);
		CREATE TABLE user_mfa_lockout (
			username TEXT PRIMARY KEY,
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
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)
	return db
}

func seedMFAUserWithBackup(t *testing.T, username string) (backupCode string, totpSecret string) {
	t.Helper()
	setup, err := auth.GenerateMFASetup(username)
	require.NoError(t, err)
	require.NoError(t, auth.StoreMFASetup(database.DB, username, setup))
	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	require.NoError(t, err)
	require.NoError(t, auth.CompleteMFASetup(database.DB, username, code))
	return setup.BackupCodes[0], setup.Secret
}

func postMFAWithToken(t *testing.T, path string, body interface{}, token string, middleware ...echo.MiddlewareFunc) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := func(c echo.Context) error {
		switch path {
		case "/api/mfa/auth":
			return MFAAuth(c)
		case "/api/mfa/recover-with-backup-code":
			return RecoverWithBackupCode(c)
		case "/api/mfa/reset":
			return MFAReset(c)
		case "/api/mfa/verify":
			return MFAVerify(c)
		default:
			return echo.NewHTTPError(http.StatusNotFound)
		}
	}

	chain := handler
	for i := len(middleware) - 1; i >= 0; i-- {
		chain = middleware[i](chain)
	}
	require.NoError(t, chain(c))
	return rec
}

func TestMFAAuth_PathA_BackupCodeIssuesFullSession(t *testing.T) {
	setupMFAIntegrationDB(t)
	username := "backupuser"
	backupCode, _ := seedMFAUserWithBackup(t, username)

	mfaToken, _, err := auth.GenerateTemporaryMFAToken(username)
	require.NoError(t, err)

	rec := postMFAWithToken(t, "/api/mfa/auth", map[string]interface{}{
		"code":      backupCode,
		"is_backup": true,
	}, mfaToken, auth.MFAJWTMiddleware())

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, data["token"])

	enabled, err := auth.IsUserMFAEnabled(database.DB, username)
	require.NoError(t, err)
	assert.True(t, enabled, "path A must not remove enrolled MFA")
}

func TestMFARecoverAndReset_PathB_ResetTierWorks(t *testing.T) {
	setupMFAIntegrationDB(t)
	username := "backupuser"
	backupCode, oldSecret := seedMFAUserWithBackup(t, username)

	mfaToken, _, err := auth.GenerateTemporaryMFAToken(username)
	require.NoError(t, err)

	recoverRec := postMFAWithToken(t, "/api/mfa/recover-with-backup-code", map[string]string{
		"backup_code": backupCode,
	}, mfaToken, auth.MFAJWTMiddleware())
	assert.Equal(t, http.StatusOK, recoverRec.Code)

	var recoverResp map[string]interface{}
	require.NoError(t, json.Unmarshal(recoverRec.Body.Bytes(), &recoverResp))
	recoverData, ok := recoverResp["data"].(map[string]interface{})
	require.True(t, ok)
	resetToken, ok := recoverData["reset_token"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, resetToken)

	resetRec := postMFAWithToken(t, "/api/mfa/reset", map[string]string{}, resetToken, auth.MFAResetJWTMiddleware())
	assert.Equal(t, http.StatusOK, resetRec.Code)

	var resetResp map[string]interface{}
	require.NoError(t, json.Unmarshal(resetRec.Body.Bytes(), &resetResp))
	resetData, ok := resetResp["data"].(map[string]interface{})
	require.True(t, ok)
	newSecret, ok := resetData["secret"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, newSecret)
	assert.NotEqual(t, oldSecret, newSecret)

	verifyToken, ok := resetData["temp_token"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, verifyToken)

	enabled, err := auth.IsUserMFAEnabled(database.DB, username)
	require.NoError(t, err)
	assert.False(t, enabled, "MFA must stay inactive until verify after reset")

	verifyCode, err := totp.GenerateCode(newSecret, time.Now().UTC())
	require.NoError(t, err)

	verifyRec := postMFAWithToken(t, "/api/mfa/verify", map[string]string{
		"code": verifyCode,
	}, verifyToken, auth.MFAJWTMiddleware())
	assert.Equal(t, http.StatusOK, verifyRec.Code)

	enabled, err = auth.IsUserMFAEnabled(database.DB, username)
	require.NoError(t, err)
	assert.True(t, enabled, "verify must re-enable MFA after reset")
}
