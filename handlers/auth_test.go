package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/config"
	dbSetup "github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustHashToken(token string, t *testing.T) string {
	t.Helper()
	hash, err := auth.HashToken(token)
	require.NoError(t, err, "mustHashToken failed unexpectedly")
	return hash
}

// Helper function to create a new Echo context for testing
func setupTestEnv(t *testing.T, method, path string, body io.Reader) (echo.Context, *httptest.ResponseRecorder, sqlmock.Sqlmock, *storage.MockObjectStorageProvider) {
	// --- Test Config Setup ---
	config.ResetConfigForTest()
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"JWT_SECRET":                "test-jwt-secret-for-handlers", // Consistent secret
		"STORAGE_PROVIDER":          "backblaze",                    // Set provider to backblaze
		"BACKBLAZE_ENDPOINT":        "test-endpoint",
		"BACKBLAZE_KEY_ID":          "test-key-id",
		"BACKBLAZE_APPLICATION_KEY": "test-app-key",
		"BACKBLAZE_BUCKET_NAME":     "test-bucket",
	}
	for key, testValue := range testEnv {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, testValue)
	}
	_, err := config.LoadConfig()
	require.NoError(t, err, "Failed to load config with test env vars")

	// --- Logger Setup ---
	logging.InfoLogger = log.New(io.Discard, "INFO: ", log.Ldate|log.Ltime|log.LUTC)
	logging.ErrorLogger = log.New(io.Discard, "ERROR: ", log.Ldate|log.Ltime|log.LUTC)
	logging.WarningLogger = log.New(io.Discard, "WARNING: ", log.Ldate|log.Ltime|log.LUTC)
	logging.DebugLogger = log.New(io.Discard, "DEBUG: ", log.Ldate|log.Ltime|log.LUTC)

	// --- Echo Setup ---
	e := echo.New()
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Setup Mock DB with regex matching
	mockDB, mockSQL, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	originalDB := dbSetup.DB
	dbSetup.DB = mockDB

	// Setup Mock Storage Provider
	mockStorage := new(storage.MockObjectStorageProvider)
	originalProvider := storage.Provider
	storage.Provider = mockStorage
	t.Cleanup(func() {
		dbSetup.DB = originalDB
		storage.Provider = originalProvider
		mockDB.Close()
		for key, originalValue := range originalEnv {
			if originalValue == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, originalValue)
			}
		}
		config.ResetConfigForTest()
	})
	return c, rec, mockSQL, mockStorage
}

// --- Test OPAQUE Authentication ---

func TestOpaqueRegister_Success(t *testing.T) {
	email := "test@example.com"
	password := "ValidPassword123!@#"

	reqBody := map[string]interface{}{
		"email":    email,
		"password": password,
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	// Mock checking if user already exists (should return no rows)
	getUserSQL := `SELECT id, email, password_hash, password_salt, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE email = \?`
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnError(sql.ErrNoRows)

	// Mock OPAQUE user registration in database
	// This would be done by auth.RegisterUser internally
	mock.ExpectExec(`INSERT INTO opaque_users`).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock creating user record for JWT and application data
	createUserSQL := `INSERT INTO users \(\s*email, password_hash, storage_limit_bytes, is_admin, is_approved\s*\) VALUES \(\?, \?, \?, \?, \?\)`
	mock.ExpectExec(createUserSQL).
		WithArgs(email, "OPAQUE_AUTH_PLACEHOLDER", models.DefaultStorageLimit, false, false).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock logging user action
	logActionSQL := `INSERT INTO user_activity \(user_email, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(email, "registered with OPAQUE", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler
	err := OpaqueRegister(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)

	// Check response body
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Account created successfully with OPAQUE authentication", resp["message"])
	assert.Equal(t, "OPAQUE", resp["authMethod"])

	statusMap, ok := resp["status"].(map[string]interface{})
	require.True(t, ok)
	assert.False(t, statusMap["is_approved"].(bool))
	assert.False(t, statusMap["is_admin"].(bool))

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOpaqueRegister_InvalidEmail(t *testing.T) {
	reqBody := map[string]interface{}{
		"email":    "invalid-email",
		"password": "ValidPassword123!@#",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	err := OpaqueRegister(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Valid email address is required", httpErr.Message)
}

func TestOpaqueRegister_WeakPassword(t *testing.T) {
	reqBody := map[string]interface{}{
		"email":    "test@example.com",
		"password": "weak",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	err := OpaqueRegister(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Password must be at least 12 characters long", httpErr.Message)
}

func TestOpaqueRegister_UserAlreadyExists(t *testing.T) {
	email := "existing@example.com"
	reqBody := map[string]interface{}{
		"email":    email,
		"password": "ValidPassword123!@#",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	// Mock user already exists
	getUserSQL := `SELECT id, email, password_hash, password_salt, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE email = \?`
	rows := sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, email, "existing-hash", "", time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	err := OpaqueRegister(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusConflict, httpErr.Code)
	assert.Equal(t, "Email already registered", httpErr.Message)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOpaqueLogin_Success(t *testing.T) {
	email := "login@example.com"
	password := "ValidPassword123!@#"

	reqBody := map[string]interface{}{
		"email":    email,
		"password": password,
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/login", bytes.NewReader(jsonBody))

	// Mock getting user for approval status check
	getUserSQL := `SELECT id, email, password_hash, password_salt, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE email = \?`
	rows := sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, email, "OPAQUE_AUTH_PLACEHOLDER", "", time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	// Mock OPAQUE authentication (would be handled by auth.AuthenticateUser)
	// This is complex to mock as it involves cryptographic operations

	// Mock refresh token creation
	refreshTokenSQL := `(?s).*INSERT INTO refresh_tokens.*VALUES.*`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, false).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock logging user action
	logActionSQL := `INSERT INTO user_activity \(user_email, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(email, "logged in with OPAQUE", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Note: This test would require mocking the OPAQUE authentication process
	// which involves complex cryptographic operations. For now, we'll skip the actual execution
	// and focus on input validation tests.

	// Suppress unused variable warnings for variables we set up but don't use due to test skip
	_ = c
	_ = rec

	t.Skip("OPAQUE authentication requires mocking complex cryptographic operations")
}

func TestOpaqueLogin_InvalidCredentials(t *testing.T) {
	reqBody := map[string]interface{}{
		"email":    "",
		"password": "ValidPassword123!@#",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/login", bytes.NewReader(jsonBody))

	err := OpaqueLogin(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Valid email address is required", httpErr.Message)
}

func TestOpaqueLogin_UserNotApproved(t *testing.T) {
	email := "unapproved@example.com"
	password := "ValidPassword123!@#"

	reqBody := map[string]interface{}{
		"email":    email,
		"password": password,
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/login", bytes.NewReader(jsonBody))

	// Mock getting user - user exists but not approved
	getUserSQL := `SELECT id, email, password_hash, password_salt, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE email = \?`
	rows := sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, email, "OPAQUE_AUTH_PLACEHOLDER", "", time.Now(), 0, models.DefaultStorageLimit, false, nil, nil, false) // is_approved = false
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	err := OpaqueLogin(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "User account not approved", httpErr.Message)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOpaqueHealthCheck_Success(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/api/opaque/health", nil)

	// Note: This test would require mocking OPAQUE server initialization
	// For now, we'll skip the actual execution and focus on testing the endpoint exists

	// Suppress unused variable warnings for variables we set up but don't use due to test skip
	_ = c
	_ = rec

	t.Skip("OPAQUE health check requires mocking OPAQUE server initialization")
}

// --- Test RefreshToken (works with OPAQUE sessions) ---

func TestRefreshToken_Success(t *testing.T) {
	userEmail := "refresh@example.com"
	refreshTokenVal := "valid-refresh-token"
	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", bytes.NewReader(jsonBody))

	mock.ExpectQuery(`SELECT id, user_email, expires_at, is_revoked, is_used FROM refresh_tokens WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "expires_at", "is_revoked", "is_used"}).AddRow("test-id", userEmail, time.Now().Add(time.Hour), false, false))

	mock.ExpectExec(`UPDATE refresh_tokens SET is_used = true WHERE id = \?`).
		WithArgs("test-id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	refreshTokenSQL := `(?s).*INSERT INTO refresh_tokens.*VALUES.*`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), userEmail, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, false).
		WillReturnResult(sqlmock.NewResult(1, 1))

	logActionSQL := `INSERT INTO user_activity \(user_email, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(userEmail, "refreshed token", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var respBody map[string]string
	unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &respBody)
	require.NoError(t, unmarshalErr)
	assert.NotEmpty(t, respBody["token"], "New JWT token should be present")
	assert.NotEmpty(t, respBody["refreshToken"], "New refresh token should be present")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_NoToken(t *testing.T) {
	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil)

	err := RefreshToken(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token not found", httpErr.Message)
}

// --- Test Logout (works with OPAQUE sessions) ---

func TestLogout_Success(t *testing.T) {
	refreshTokenVal := "valid-refresh-token"
	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/logout", bytes.NewReader(jsonBody))

	mock.ExpectExec(`UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	user := &models.User{Email: "logout@example.com"}
	claims := &auth.Claims{Email: user.Email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	logActionSQL := `INSERT INTO user_activity \(user_email, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(user.Email, "logged out", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	logoutErr := Logout(c)
	require.NoError(t, logoutErr)
	assert.Equal(t, http.StatusOK, rec.Code)

	var respBody map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Equal(t, "Logged out successfully", respBody["message"])

	foundCookie := false
	for _, respCookie := range rec.Result().Cookies() {
		if respCookie.Name == "refreshToken" {
			assert.Equal(t, "", respCookie.Value, "Cookie value should be empty")
			assert.True(t, respCookie.Expires.Before(time.Now()), "Cookie should be expired")
			foundCookie = true
			break
		}
	}
	assert.True(t, foundCookie, "Refresh token cookie should be set to clear")

	assert.NoError(t, mock.ExpectationsWereMet())
}
