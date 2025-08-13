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

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
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

	// --- Entity ID Service Setup ---
	entityConfig := logging.EntityIDConfig{
		MasterSecretPath:  "",
		RotationPeriod:    24 * time.Hour,
		RetentionDays:     90,
		CleanupInterval:   24 * time.Hour,
		EmergencyRotation: true,
	}
	err = logging.InitializeEntityIDService(entityConfig)
	require.NoError(t, err, "Failed to initialize entity ID service")

	// --- Echo Setup ---
	e := echo.New()
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	// Set test IP address for entity ID generation
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "127.0.0.1")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

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
	username := "test.user.valid"
	password := "Xy8$mQ3#nP9@vK2!eR5&wL7*uT4%iO6^sA1+bC0-fG9~hJ3"

	reqBody := map[string]interface{}{
		"username": username,
		"password": password,
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	// Mock checking if user already exists (should return no rows)
	getUserSQL := `SELECT id, username, email, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	mock.ExpectQuery(getUserSQL).WithArgs(username).WillReturnError(sql.ErrNoRows)

	// Mock integrated user + OPAQUE creation transaction
	mock.ExpectBegin()
	createUserSQL := `INSERT INTO users \(\s*username, email, storage_limit_bytes, is_admin, is_approved\s*\) VALUES \(\?, \?, \?, \?, \?\)`
	mock.ExpectExec(createUserSQL).
		WithArgs(username, sqlmock.AnyArg(), models.DefaultStorageLimit, false, false).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// With static linking, OPAQUE record creation will be handled by the real implementation
	// We need to mock the OPAQUE password record creation
	opaqueRecordSQL := `INSERT INTO opaque_password_records \(\s*record_type, record_identifier, opaque_user_record, associated_username, is_active\s*\) VALUES \(\?, \?, \?, \?, \?\)`
	mock.ExpectExec(opaqueRecordSQL).
		WithArgs("account", username, sqlmock.AnyArg(), username, true).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	// Mock logging user action
	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(username, "registered with OPAQUE, TOTP setup required", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler
	err := OpaqueRegister(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)

	// Check response body
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Account created successfully. Two-factor authentication setup is required to complete registration.", resp["message"])
	assert.Equal(t, "OPAQUE", resp["authMethod"])
	assert.Equal(t, true, resp["requiresTOTPSetup"])
	assert.NotEmpty(t, resp["tempToken"])
	assert.NotEmpty(t, resp["sessionKey"])

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOpaqueRegister_InvalidUsername(t *testing.T) {
	reqBody := map[string]interface{}{
		"username": "invalid@username!",
		"password": "ValidPassword123!@#",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	err := OpaqueRegister(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Invalid username")
}

func TestOpaqueRegister_WeakPassword(t *testing.T) {
	reqBody := map[string]interface{}{
		"username": "test.user.weak.pass",
		"password": "weak",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	err := OpaqueRegister(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)

	// Updated to match new enhanced password validation feedback
	errorMessage := httpErr.Message.(string)
	assert.Contains(t, errorMessage, "Consider using 14+ characters for better security")
	assert.Contains(t, errorMessage, "Password entropy is too low")
}

func TestOpaqueRegister_UserAlreadyExists(t *testing.T) {
	username := "existing.user"
	reqBody := map[string]interface{}{
		"username": username,
		"password": "Xy8$mQ3#nP9@vK2!eR5&wL7*uT4%iO6^sA1+bC0-fG9~hJ3",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/register", bytes.NewReader(jsonBody))

	// Mock user already exists
	getUserSQL := `SELECT id, username, email, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	rows := sqlmock.NewRows([]string{"id", "username", "email", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, username, sql.NullString{}, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false)
	mock.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(rows)

	err := OpaqueRegister(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusConflict, httpErr.Code)
	assert.Equal(t, "Username already registered", httpErr.Message)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOpaqueLogin_TOTPRequired(t *testing.T) {
	username := "login.user"
	password := "ValidPassword123!@#"

	reqBody := map[string]interface{}{
		"username": username,
		"password": password,
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/login", bytes.NewReader(jsonBody))

	// Mock getting user
	getUserSQL := `SELECT id, username, email, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	rows := sqlmock.NewRows([]string{"id", "username", "email", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, username, sql.NullString{}, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false)
	mock.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(rows)

	// In mock mode, OPAQUE authentication happens entirely in memory
	mockOPAQUESuccess(t, username, password)

	// Mock TOTP check (user does NOT have TOTP enabled - this is the expected case)
	totpCheckSQL := `SELECT enabled, setup_completed FROM user_totp WHERE username = \?`
	mock.ExpectQuery(totpCheckSQL).WithArgs(username).WillReturnError(sql.ErrNoRows)

	// Execute the handler
	err := OpaqueLogin(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Two-factor authentication setup is required. Please complete TOTP setup before logging in.", httpErr.Message)

	// Verify that mock database expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOpaqueLogin_WithTOTPEnabled_Success(t *testing.T) {
	username := "login.user"
	password := "ValidPassword123!@#"

	reqBody := map[string]interface{}{
		"username": username,
		"password": password,
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/login", bytes.NewReader(jsonBody))

	// Mock getting user
	getUserSQL := `SELECT id, username, email, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	rows := sqlmock.NewRows([]string{"id", "username", "email", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, username, sql.NullString{}, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false)
	mock.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(rows)

	// In mock mode, OPAQUE authentication happens entirely in memory
	mockOPAQUESuccess(t, username, password)

	// Mock TOTP check (user HAS TOTP enabled and setup completed)
	totpCheckSQL := `SELECT enabled, setup_completed FROM user_totp WHERE username = \?`
	totpRows := sqlmock.NewRows([]string{"enabled", "setup_completed"}).AddRow(true, true)
	mock.ExpectQuery(totpCheckSQL).WithArgs(username).WillReturnRows(totpRows)

	// Note: GenerateTemporaryTOTPToken creates a JWT in memory only - no database record
	// So we don't expect any INSERT INTO refresh_tokens here

	// Mock logging user action
	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(username, "OPAQUE auth completed, awaiting TOTP", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute the handler
	err := OpaqueLogin(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Validate response structure for TOTP authentication required
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Should return TOTP authentication requirement
	assert.Equal(t, "OPAQUE authentication successful. TOTP code required.", resp["message"])
	assert.Equal(t, true, resp["requiresTOTP"])
	assert.Contains(t, resp, "tempToken", "Should include temporary token for TOTP completion")
	assert.Contains(t, resp, "sessionKey", "Should include session key")
	assert.Equal(t, "OPAQUE", resp["authMethod"])

	// Verify that mock database expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOpaqueLogin_InvalidCredentials(t *testing.T) {
	reqBody := map[string]interface{}{
		"username": "",
		"password": "ValidPassword123!@#",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/opaque/login", bytes.NewReader(jsonBody))

	err := OpaqueLogin(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Username is required")
}

// NOTE: TestOpaqueLogin_UserNotApproved test removed
// The handler no longer checks user approval during login as per the updated authentication flow
// Users can complete OPAQUE + TOTP authentication but will be restricted from file operations if unapproved

func TestOpaqueHealthCheck_Success(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/api/opaque/health", nil)

	// Test OPAQUE system health validation
	validateOPAQUEHealthy(t)

	// Execute health check handler
	err := OpaqueHealthCheck(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Validate response structure
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Check that health check returns expected structure
	assert.Contains(t, resp, "status", "Health check should include status")
}

// --- Test RefreshToken (works with OPAQUE sessions) ---

func TestRefreshToken_Success(t *testing.T) {
	username := "refresh@example.com"
	refreshTokenVal := "valid-refresh-token"
	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", bytes.NewReader(jsonBody))

	mock.ExpectQuery(`SELECT id, username, expires_at, is_revoked, is_used FROM refresh_tokens WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "expires_at", "is_revoked", "is_used"}).AddRow("test-id", username, time.Now().Add(time.Hour), false, false))

	mock.ExpectExec(`UPDATE refresh_tokens SET is_used = true WHERE id = \?`).
		WithArgs("test-id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	refreshTokenSQL := `(?s).*INSERT INTO refresh_tokens.*VALUES.*`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), username, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, false).
		WillReturnResult(sqlmock.NewResult(1, 1))

	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(username, "refreshed token", "").
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

	username := "logoutuser"
	user := &models.User{Username: username, Email: stringPtr("logout@example.com")}
	claims := &auth.Claims{Username: user.Username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(user.Username, "logged out", "").
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
