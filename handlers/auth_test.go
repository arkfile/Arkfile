package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/84adam/arkfile/utils"
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
// Copied from handlers_test.go
func setupTestEnv(t *testing.T, method, path string, body io.Reader) (echo.Context, *httptest.ResponseRecorder, sqlmock.Sqlmock, *storage.MockObjectStorageProvider) {
	// --- Test Config Setup ---
	config.ResetConfigForTest()
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"JWT_SECRET":                "test-jwt-secret-for-handlers", // Consistent secret
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
	// Added validator to Echo instance
	// val, err := utils.NewValidator()
	// require.NoError(t, err, "Failed to create validator for Echo instance")
	// e.Validator = val // This caused issues if not present in all setupTestEnvs, but it's fine as handlers call Validate explicitly.

	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Setup Mock DB with regex matching like other working tests
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

// --- Test Register ---

func TestRegister_Success(t *testing.T) {
	email := "test@example.com"
	password := "ValidPass123!@OK" // Use a valid password according to rules

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values, assign mockStorage to _
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody))

	// Mock CreateUser call's DB interaction: INSERT user
	// Ensure the SQL query string matches EXACTLY, including whitespace.
	createUserSQL := `INSERT INTO users \(\s*email, password, storage_limit_bytes, is_admin, is_approved\s*\) VALUES \(\?, \?, \?, \?, \?\)`
	mock.ExpectExec(createUserSQL).
		WithArgs(email, sqlmock.AnyArg(), models.DefaultStorageLimit, false, false). // Args: email, hashedPass, limit, isAdmin, isApproved
		WillReturnResult(sqlmock.NewResult(1, 1))                                    // Mock LastInsertId = 1, RowsAffected = 1

	// Mocks for LogUserAction within the handler. From database/database.go:
	// SQL: "INSERT INTO user_activity (user_email, action, target) VALUES (?, ?, ?)"
	// Args: email, action, target
	logActionSQL := `INSERT INTO user_activity \(user_email, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(email, "registered", ""). // Correct args for registration
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler
	err := Register(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)

	// Check response body
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Account created successfully", resp["message"])
	statusMap, ok := resp["status"].(map[string]interface{})
	require.True(t, ok)
	assert.False(t, statusMap["is_approved"].(bool))
	assert.False(t, statusMap["is_admin"].(bool))

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_InvalidEmail(t *testing.T) {
	reqBody := map[string]string{"email": "invalid-email", "password": "ValidPass123!@OK"}
	jsonBody, _ := json.Marshal(reqBody)
	// Update call to accept 4 return values
	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Mock DB/storage not needed, ignore recorder

	err := Register(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Invalid email format", httpErr.Message)
}

func TestRegister_PasswordComplexityFail(t *testing.T) {
	// Using a password that fails the validator
	invalidPassword := "short" // Fails length check
	reqBody := map[string]string{"email": "test@example.com", "password": invalidPassword}
	jsonBody, _ := json.Marshal(reqBody)
	// Update call to accept 4 return values
	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Mock DB/storage not needed, ignore recorder

	err := Register(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	// Check if the message matches the specific error from the validator
	assert.Equal(t, utils.ErrPasswordTooShort.Error(), httpErr.Message.(string))

	// Test another complexity failure
	invalidPassword = "ValidPassword123" // Missing Special - from the list ` + "`" + `~!@#$%^&*()-_=+[]{}|;:,.<>?` + "`" + `
	reqBody = map[string]string{"email": "test@example.com", "password": invalidPassword}
	jsonBody, _ = json.Marshal(reqBody)
	// Update call to accept 4 return values
	c, _, _, _ = setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Ignore recorder

	err = Register(c)
	// Note: Relies on the error message defined in utils.ErrPasswordMissingSpecial
	// Assuming ErrPasswordMissingSpecial based on previous context
	require.Error(t, err)
	httpErr, ok = err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, utils.ErrPasswordMissingSpecial.Error(), httpErr.Message.(string)) // Check exact error message
}

func TestRegister_DuplicateEmail(t *testing.T) {
	email := "duplicate@example.com"
	password := "ValidPass123!@OK"

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Ignore recorder

	// Mock CreateUser call inside the database exec to return a UNIQUE constraint error
	createUserSQL := `INSERT INTO users \(\s*email, password, storage_limit_bytes, is_admin, is_approved\s*\) VALUES \(\?, \?, \?, \?, \?\)`
	mock.ExpectExec(createUserSQL).
		WithArgs(email, sqlmock.AnyArg(), models.DefaultStorageLimit, false, false).
		WillReturnError(fmt.Errorf("UNIQUE constraint failed: users.email")) // Simulate specific DB error string

	// Execute handler
	err := Register(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusConflict, httpErr.Code)
	assert.Equal(t, "Email already registered", httpErr.Message)

	// Ensure all SQL expectations were met (that the failing query was called)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_CreateUserInternalError(t *testing.T) {
	email := "fail@example.com"
	password := "ValidPass123!@OK"
	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Ignore recorder

	// Mock a generic DB error during user creation
	createUserSQL := `INSERT INTO users \(\s*email, password, storage_limit_bytes, is_admin, is_approved\s*\) VALUES \(\?, \?, \?, \?, \?\)`
	mock.ExpectExec(createUserSQL).
		WithArgs(email, sqlmock.AnyArg(), models.DefaultStorageLimit, false, false).
		WillReturnError(fmt.Errorf("some generic database error"))

	// Execute handler
	err := Register(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to create user", httpErr.Message)

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Test Login ---

func TestLogin_Success(t *testing.T) {
	email := "login@example.com"
	password := "password123"

	body := map[string]string{"email": email, "password": password}
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Hash password *after* config is loaded by setupTestEnv
	hashedPassword, err := auth.HashPassword(password)
	require.NoError(t, err)

	// Consistent query definition with other tests
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`

	rows := sqlmock.NewRows([]string{"id", "email", "password", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, email, string(hashedPassword), time.Now(), int64(0), models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	mockDB.ExpectExec(`(?s).*INSERT INTO refresh_tokens.*VALUES.*`).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, false).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectExec(`INSERT INTO user_activity \(user_email, action, target\) VALUES \(\?, \?, \?\)`).
		WithArgs(email, "logged in", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = Login(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err) // Check for unmarshal error
	assert.NotEmpty(t, resp["token"])
	assert.NotEmpty(t, resp["refreshToken"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

func TestLogin_UserNotFound(t *testing.T) {
	email := "notfound@example.com"
	password := "ValidPass123!@OK"
	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Mock GetUserByEmail to return sql.ErrNoRows
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnError(sql.ErrNoRows)

	// Execute handler
	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid credentials", httpErr.Message)

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_WrongPassword(t *testing.T) {
	email := "login@example.com"
	correctPassword := "ValidPass123!@OK"
	wrongPassword := "WrongPassword!123"

	reqBody := map[string]string{"email": email, "password": wrongPassword}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Mock GetUserByEmail - return user with the *correct* hashed password
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	// Hash the *correct* password with auth package for the mock DB row
	hashedCorrectPassword, _ := auth.HashPassword(correctPassword)
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedCorrectPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	// Login handler calls user.VerifyPassword, which uses bcrypt.CompareHashAndPassword
	// No further DB interaction expected if password fails

	// Execute handler
	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid credentials", httpErr.Message)

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_UserNotApproved(t *testing.T) {
	email := "notapproved@example.com"
	password := "ValidPass123!@OK" // Valid password

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Mock GetUserByEmail to return an unapproved user
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	// Hash the password with auth package for the mock DB row since check happens after fetching
	hashedPassword, _ := auth.HashPassword(password)
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		2, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, false, nil, nil, false, // User is NOT approved
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	// No token creation or logging should happen for an unapproved user

	// Execute handler
	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "User account not approved", httpErr.Message)

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_CreateTokenInternalError(t *testing.T) {
	email := "tokenfail@example.com"
	password := "ValidPass123!@OK"

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	hashedPassword, _ := auth.HashPassword(password)
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(`SELECT id, email, password, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE email = \?`).WithArgs(email).WillReturnRows(rows)

	originalSecret := config.GetConfig().Security.JWTSecret
	config.GetConfig().Security.JWTSecret = ""
	defer func() {
		config.GetConfig().Security.JWTSecret = originalSecret
	}()

	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to create refresh token", httpErr.Message)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_CreateRefreshTokenInternalError(t *testing.T) {
	email := "refreshtokenfail@example.com"
	password := "ValidPass123!@OK"

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	hashedPassword, _ := auth.HashPassword(password)
	rowsUser := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rowsUser)

	refreshTokenSQL := `(?s).*INSERT INTO refresh_tokens.*VALUES.*`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, false).
		WillReturnError(fmt.Errorf("failed to save refresh token"))

	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to create refresh token", httpErr.Message)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_RefreshTokenDBError(t *testing.T) {
	email := "login@example.com"
	password := "ValidPass123!@OK"
	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	hashedPassword, _ := auth.HashPassword(password)
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	refreshTokenSQL := `(?s).*INSERT INTO refresh_tokens.*VALUES.*`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, false).
		WillReturnError(fmt.Errorf("DB error creating refresh token"))

	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to create refresh token", httpErr.Message)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Test RefreshToken ---

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

func TestRefreshToken_NoCookie(t *testing.T) {
	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil)

	err := RefreshToken(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token not found", httpErr.Message)
}
func TestRefreshToken_InvalidToken(t *testing.T) {
	refreshTokenVal := "invalid-refresh-token"
	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", bytes.NewReader(jsonBody))

	mock.ExpectQuery(`SELECT id, user_email, expires_at, is_revoked, is_used FROM refresh_tokens WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid or expired refresh token", httpErr.Message)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_TokenExpired(t *testing.T) {
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")

	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", bytes.NewReader(jsonBody))

	mock.ExpectQuery(`SELECT id, user_email, expires_at, is_revoked, is_used FROM refresh_tokens WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "expires_at", "is_revoked", "is_used"}).AddRow("test-id", "user@test.com", time.Now().Add(-time.Hour), false, false))

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid or expired refresh token", httpErr.Message)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_UserNotFoundForToken(t *testing.T) {
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")

	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", bytes.NewReader(jsonBody))

	mock.ExpectQuery(`SELECT id, user_email, expires_at, is_revoked, is_used FROM refresh_tokens WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(errors.New("user not found for token"))

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid or expired refresh token", httpErr.Message)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_CreateJWTError(t *testing.T) {
	userEmail := "jwtcreatefail@example.com"
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")

	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", bytes.NewReader(jsonBody))

	originalSecret := config.GetConfig().Security.JWTSecret
	config.GetConfig().Security.JWTSecret = "" // Invalid: too short
	defer func() { config.GetConfig().Security.JWTSecret = originalSecret }()

	mock.ExpectQuery(`SELECT id, user_email, expires_at, is_revoked, is_used FROM refresh_tokens WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "expires_at", "is_revoked", "is_used"}).AddRow("test-id", userEmail, time.Now().Add(time.Hour), false, false))

	mock.ExpectExec(`UPDATE refresh_tokens SET is_used = true WHERE id = \?`).
		WithArgs("test-id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Could not create new refresh token", httpErr.Message)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Test Logout ---

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

func TestLogout_NoRefreshToken(t *testing.T) {
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/logout", nil)
	user := &models.User{Email: "nocookie@example.com"}
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
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogout_DeleteTokenDBError(t *testing.T) {
	refreshTokenVal := "valid-refresh-token"
	reqBody := map[string]string{"refreshToken": refreshTokenVal}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/logout", bytes.NewReader(jsonBody))
	user := &models.User{Email: "dberror@example.com"}
	claims := &auth.Claims{Email: user.Email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mock.ExpectExec(`UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("database error on delete"))

	logoutErr := Logout(c)
	require.Error(t, logoutErr)
	httpErr, ok := logoutErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to revoke refresh token", httpErr.Message)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Additional Test Case Suggestions ---
//
// === General Auth & Security ===
// - TestEmailCaseSensitivity: Check if emails are treated case-sensitively or insensitively during registration and login.
//   (e.g., can "user@example.com" and "User@example.com" be registered as different accounts? Can one log in as the other?).
// - TestInvalidJWTSecret: Test scenarios where the JWT_SECRET in config is too short, empty, or significantly changed
//   after tokens have been issued, to ensure token validation fails as expected.
// - TestRateLimiting: If rate limiting is implemented for login, registration, or refresh attempts, add tests for these.
// - TestCookieSecurityFlags: If refresh token cookies are set with HttpOnly, Secure, SameSite flags, ensure these are verified.
//   (Though this might be more of an e2e/integration test aspect if Echo handles setting them directly from config).
//
// === For Register Handler ===
// - TestRegister_EmptyCredentials: Test with empty email string or empty password string.
// - TestRegister_PasswordPolicyVariations: (If `utils.ValidatePasswordComplexity` has multiple rules beyond length/special char)
//   Create a table-driven test to cover all individual password complexity rule failures (e.g., missing uppercase, missing lowercase, missing number).
// - TestRegister_LogUserActionFailure: Simulate an error during `database.LogUserAction` to check if user registration
//   still proceeds correctly (core functionality vs. secondary logging).
//
// === For Login Handler ===
// - TestLogin_EmptyCredentials: Test with empty email string or empty password string.
// - TestLogin_UserDisabled: If a user can be "disabled" or "locked" (beyond just `is_approved = false`), test login attempts for such users.
// - TestLogin_SuccessfulLogin_VerifyResponseStructure: More detailed assertions on the structure of the `user` object in the success response,
//   especially for calculated fields like `storage_used_pc` with edge values (0 storage, full storage, limit 0).
// - TestLogin_RefreshTokenModelInteractionFailures:
//   - Simulate `models.CreateRefreshToken` returning an error for reasons other than DB write (e.g., if it had internal validation).
//
// === For RefreshToken Handler ===
// - TestRefreshToken_UserNowUnapproved: User has a valid refresh token, but their `is_approved` status in the DB
//   was set to `false` after the refresh token was issued. The refresh should likely fail or yield a token for an unapproved user.
// - TestRefreshToken_UserNowAdminOrNot: If user's admin status changes after refresh token issuance, how does the new JWT reflect this?
// - TestRefreshToken_UnderlyingDBErrors:
//   - Simulate `models.GetRefreshTokenByHash` DB query failing for reasons other than `sql.ErrNoRows` (e.g., connection issue).
//   - Simulate `models.MarkRefreshTokenUsed` (the `UPDATE ... SET is_used = true`) failing due to a DB error.
// - TestRefreshToken_NewJWTClaims: More detailed verification of all claims (jti, iss, aud, exp, iat, nbf, email) in the *newly issued* JWT.
// - TestRefreshToken_ConcurrentUsage: (Advanced) Attempt to use the same refresh token concurrently to see if the `is_used` flag
//   reliably prevents replay/multiple new JWTs. This may indicate a need for stricter locking or a more robust rotation scheme.
//
// === For Logout Handler ===
// - TestLogout_MalformedCookieValue: Refresh token cookie exists, but its value is malformed or not a valid token format.
// - TestLogout_UserContextError: If `c.Get("user")` (the JWT claims) is missing or malformed, how does Logout behave?
//   (Though it primarily acts on the refresh token cookie for deletion).
// - TestLogout_Idempotency: Call logout twice with the same valid refresh token. The first should succeed, the second
//   should also succeed (or fail gracefully, e.g. token not found), and the cookie should remain cleared.
// - TestLogout_ClearCookieFailure: (Difficult to mock net/http cookie setting) but consider if the Echo context's
//   `c.SetCookie()` could fail and how that would be handled.
