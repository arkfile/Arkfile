package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"  // Added
	"log" // Added
	"net/http"
	"net/http/httptest"
	"os" // Added
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert" // Added
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/config"
	dbSetup "github.com/84adam/arkfile/database" // Added
	"github.com/84adam/arkfile/logging"          // Added
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage" // Added
	"github.com/84adam/arkfile/utils"
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

	// Setup Mock DB
	mockDB, mockSQL, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
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
	createUserSQL := `INSERT INTO users (
			email, password, storage_limit_bytes, is_admin, is_approved
		) VALUES (?, ?, ?, ?, ?)`
	mock.ExpectExec(createUserSQL).
		WithArgs(email, sqlmock.AnyArg(), models.DefaultStorageLimit, false, false). // Args: email, hashedPass, limit, isAdmin, isApproved
		WillReturnResult(sqlmock.NewResult(1, 1))                                    // Mock LastInsertId = 1, RowsAffected = 1

	// Mocks for LogUserAction within the handler. From database/database.go:
	// SQL: "INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)"
	// Args: email, action, filename
	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
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
	createUserSQL := `INSERT INTO users (
			email, password, storage_limit_bytes, is_admin, is_approved
		) VALUES (?, ?, ?, ?, ?)`
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
	createUserSQL := `INSERT INTO users (
			email, password, storage_limit_bytes, is_admin, is_approved
		) VALUES (?, ?, ?, ?, ?)`
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
	password := "ValidPass123!@OK"

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Mock GetUserByEmail - needs the exact query from models/user.go
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`

	// Simulate a valid password hash with configured cost
	hashedPasswordBytes, _ := bcrypt.GenerateFromPassword([]byte(password), config.GetConfig().Security.BcryptCost) // Use config value
	hashedPassword := string(hashedPasswordBytes)

	// Define rows returned by the mock query
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), // Mock data for the user
		0, models.DefaultStorageLimit,
		true, sql.NullString{String: "admin@test.com", Valid: true}, sql.NullTime{Time: time.Now(), Valid: true}, false, // Approved user
	)

	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	// Mock CreateRefreshToken - Use Exact SQL String (Corrected)
	// Actual SQL: INSERT INTO refresh_tokens ( id, user_email, token_hash, expires_at ) VALUES (?, ?, ?, ?)
	refreshTokenSQL := `INSERT INTO refresh_tokens (
			id, user_email, token_hash, expires_at
		) VALUES (?, ?, ?, ?)`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg()). // id, email, hash, expiry
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock LogUserAction
	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
	mock.ExpectExec(logActionSQL).
		WithArgs(email, "logged in", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler
	err := Login(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Check response body for token, refreshToken, and user info
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["token"], "JWT token should be present")
	assert.NotEmpty(t, resp["refreshToken"], "Refresh token should be present")
	userInfo, ok := resp["user"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, email, userInfo["email"])
	assert.True(t, userInfo["is_approved"].(bool))
	assert.False(t, userInfo["is_admin"].(bool))

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
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
	// Hash the *correct* password with configured cost for the mock DB row
	hashedCorrectPasswordBytes, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), config.GetConfig().Security.BcryptCost) // Use config value
	hashedCorrectPassword := string(hashedCorrectPasswordBytes)
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
	// Hash the password with configured cost for the mock DB row since check happens after fetching
	hashedPasswordBytes, _ := bcrypt.GenerateFromPassword([]byte(password), config.GetConfig().Security.BcryptCost)
	hashedPassword := string(hashedPasswordBytes)
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

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Mock GetUserByEmail (successful)
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	hashedPasswordBytes, _ := bcrypt.GenerateFromPassword([]byte(password), config.GetConfig().Security.BcryptCost)
	hashedPassword := string(hashedPasswordBytes)
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	// Temporarily set a bad JWT key to force token creation error
	// This requires modifying the global config for this specific test case.
	// Be careful with global state changes in tests.
	originalSecret := config.GetConfig().Security.JWTSecret
	config.GetConfig().Security.JWTSecret = "" // Set to empty to cause signing error
	defer func() {
		config.GetConfig().Security.JWTSecret = originalSecret // Restore original secret
	}()

	// Execute handler
	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to create token", httpErr.Message) // Message from auth.CreateJWTToken

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_CreateRefreshTokenInternalError(t *testing.T) {
	email := "refreshtokenfail@example.com"
	password := "ValidPass123!@OK"

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Mock GetUserByEmail (successful)
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	hashedPasswordBytes, _ := bcrypt.GenerateFromPassword([]byte(password), config.GetConfig().Security.BcryptCost)
	hashedPassword := string(hashedPasswordBytes)
	rowsUser := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rowsUser)

	// Mock CreateRefreshToken to fail
	refreshTokenSQL := `INSERT INTO refresh_tokens (
			id, user_email, token_hash, expires_at
		) VALUES (?, ?, ?, ?)`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("failed to save refresh token")) // Simulate DB error

	// Execute handler
	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to create refresh token", httpErr.Message)

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Appended from handlers_test.go
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
	hashedPasswordBytes, _ := bcrypt.GenerateFromPassword([]byte(password), config.GetConfig().Security.BcryptCost)
	hashedPassword := string(hashedPasswordBytes)
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	refreshTokenSQL := `INSERT INTO refresh_tokens (
			id, user_email, token_hash, expires_at
		) VALUES (?, ?, ?, ?)`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fmt.Errorf("DB error creating refresh token"))

	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	// The handler Login actually returns "Failed to create refresh token" when auth.CreateRefreshToken fails. Original test had "Login failed".
	// Let's stick to the actual message from handler if auth.CreateRefreshToken fails.
	assert.Equal(t, "Failed to create refresh token", httpErr.Message)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Test RefreshToken ---

func TestRefreshToken_Success(t *testing.T) {
	// Setup: Create a valid user and a valid refresh token for that user.
	userEmail := "refresh@example.com"
	mockUser := &models.User{
		ID:         1,
		Email:      userEmail,
		Password:   "hashedPassword", // Not used directly by Refresh handler
		IsApproved: true,
		IsAdmin:    false,
	}

	// Create a refresh token string (this would be the actual token from a cookie)
	refreshTokenVal, genErr := auth.GenerateRefreshToken() // Generate a new one just for the test
	require.NoError(t, genErr, "GenerateRefreshToken failed")
	hashedRefreshToken, hashErr := auth.HashToken(refreshTokenVal)
	require.NoError(t, hashErr, "HashToken failed")
	tokenExpiry := time.Now().Add(config.GetConfig().Security.RefreshTokenDuration)

	// Use setupTestEnv to get context and mock DB
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil)

	// Minimal config for JWT key - directly modify global config for test
	originalSecret := config.GetConfig().Security.JWTSecret
	originalRefreshDuration := config.GetConfig().Security.RefreshTokenDuration
	// Use a valid length secret for HS256 for the test to pass CreateJWTToken
	if len(config.GetConfig().Security.JWTSecret) < 32 {
		config.GetConfig().Security.JWTSecret = "testsecretkey12345678901234567890" // Must be >= 32 bytes for HS256
	}
	config.GetConfig().Security.RefreshTokenDuration = 24 * time.Hour
	defer func() {
		config.GetConfig().Security.JWTSecret = originalSecret
		config.GetConfig().Security.RefreshTokenDuration = originalRefreshDuration
	}()

	// Put the refresh token in a cookie
	cookie := new(http.Cookie)
	cookie.Name = config.GetConfig().Security.RefreshTokenCookieName
	cookie.Value = refreshTokenVal
	c.Request().AddCookie(cookie)

	// Mock GetRefreshTokenByHash
	// SQL: SELECT id, user_email, token_hash, expires_at FROM refresh_tokens WHERE token_hash = ?
	getRefreshTokenSQL := `SELECT id, user_email, token_hash, expires_at FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectQuery(getRefreshTokenSQL).
		WithArgs(hashedRefreshToken).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "token_hash", "expires_at"}).
			AddRow("test-token-id", userEmail, hashedRefreshToken, tokenExpiry))

	// Mock GetUserByEmail for creating the new JWT
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	mock.ExpectQuery(getUserSQL).WithArgs(userEmail).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "email", "password", "created_at",
			"total_storage_bytes", "storage_limit_bytes",
			"is_approved", "approved_by", "approved_at", "is_admin",
		}).AddRow(
			mockUser.ID, mockUser.Email, mockUser.Password, time.Now(),
			0, models.DefaultStorageLimit,
			mockUser.IsApproved, nil, nil, mockUser.IsAdmin,
		))

	// Execute handler
	handlerCallErr := RefreshToken((c))
	require.NoError(t, handlerCallErr)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Check response body for new JWT token
	var respBody map[string]string
	unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &respBody)
	require.NoError(t, unmarshalErr)
	assert.NotEmpty(t, respBody["token"], "New JWT token should be present")

	// Verify the new token
	tokenString := respBody["token"]
	parsedToken, err := jwt.ParseWithClaims(tokenString, &auth.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.GetConfig().Security.JWTSecret), nil
	})
	require.NoError(t, err)
	assert.True(t, parsedToken.Valid)
	claims, ok := parsedToken.Claims.(*auth.Claims)
	require.True(t, ok)
	assert.Equal(t, userEmail, claims.Email)

	// Check database expectations
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_NoCookie(t *testing.T) {
	c, _ /*rec*/, _, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil) // DB not needed, rec not used

	err := RefreshToken(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token not found", httpErr.Message)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	c, _ /*rec*/, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil) // rec not used

	// Add a malformed/invalid refresh token cookie
	cookie := new(http.Cookie)
	cookie.Name = config.GetConfig().Security.RefreshTokenCookieName // Use configured cookie name
	cookie.Value = "invalid-token-value"                             // This token's hash won't match anything in DB
	c.Request().AddCookie(cookie)

	// Mock GetRefreshTokenByHash to return sql.ErrNoRows
	getRefreshTokenSQL := `SELECT id, user_email, token_hash, expires_at FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectQuery(getRefreshTokenSQL).
		WithArgs(mustHashToken("invalid-token-value", t)). // Hash the token as the DB stores hashes
		WillReturnError(sql.ErrNoRows)                     // Simulate token not found

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid refresh token", httpErr.Message) // Message from handler
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_TokenExpired(t *testing.T) {
	userEmail := "expired@example.com"
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")
	hashedRefreshToken, hashErr := auth.HashToken(refreshTokenVal)
	require.NoError(t, hashErr, "HashToken failed")
	expiredTime := time.Now().Add(-1 * time.Hour) // Token expired an hour ago

	c, _ /*rec*/, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil) // rec not used

	cookie := new(http.Cookie)
	cookie.Name = config.GetConfig().Security.RefreshTokenCookieName // Use configured cookie name
	cookie.Value = refreshTokenVal
	c.Request().AddCookie(cookie)

	getRefreshTokenSQL := `SELECT id, user_email, token_hash, expires_at FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectQuery(getRefreshTokenSQL).
		WithArgs(hashedRefreshToken).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "token_hash", "expires_at"}).
			AddRow("test-token-id", userEmail, hashedRefreshToken, expiredTime)) // Return expired token

	// Expect DeleteRefreshTokenByHash to be called because the token is expired
	deleteTokenSQL := `DELETE FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectExec(deleteTokenSQL).WithArgs(hashedRefreshToken).WillReturnResult(sqlmock.NewResult(1, 1))

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token expired", httpErr.Message) // Message from handler
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_UserNotFoundForToken(t *testing.T) {
	userEmail := "usergone@example.com" // User associated with token but no longer exists
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")
	hashedRefreshToken, hashErr := auth.HashToken(refreshTokenVal)
	require.NoError(t, hashErr, "HashToken failed")
	tokenExpiry := time.Now().Add(config.GetConfig().Security.RefreshTokenDuration)

	c, _ /*rec*/, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil) // rec not used
	originalSecret := config.GetConfig().Security.JWTSecret
	if len(config.GetConfig().Security.JWTSecret) < 32 {
		config.GetConfig().Security.JWTSecret = "testsecretkey12345678901234567890"
	}
	defer func() { config.GetConfig().Security.JWTSecret = originalSecret }()

	cookie := new(http.Cookie)
	cookie.Name = config.GetConfig().Security.RefreshTokenCookieName
	cookie.Value = refreshTokenVal
	c.Request().AddCookie(cookie)

	getRefreshTokenSQL := `SELECT id, user_email, token_hash, expires_at FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectQuery(getRefreshTokenSQL).
		WithArgs(hashedRefreshToken).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "token_hash", "expires_at"}).
			AddRow("test-token-id", userEmail, hashedRefreshToken, tokenExpiry))

	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	mock.ExpectQuery(getUserSQL).WithArgs(userEmail).WillReturnError(sql.ErrNoRows)

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "User not found for token", httpErr.Message)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRefreshToken_CreateJWTError(t *testing.T) {
	userEmail := "jwtcreatefail@example.com"
	mockUser := &models.User{ID: 1, Email: userEmail, IsApproved: true}
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")
	hashedRefreshToken, hashErr := auth.HashToken(refreshTokenVal)
	require.NoError(t, hashErr, "HashToken failed")
	tokenExpiry := time.Now().Add(config.GetConfig().Security.RefreshTokenDuration)

	c, _ /*rec*/, mock, _ := setupTestEnv(t, http.MethodPost, "/refresh", nil) // rec not used

	originalSecret := config.GetConfig().Security.JWTSecret
	config.GetConfig().Security.JWTSecret = "" // Invalid: too short
	defer func() { config.GetConfig().Security.JWTSecret = originalSecret }()

	cookie := new(http.Cookie)
	cookie.Name = config.GetConfig().Security.RefreshTokenCookieName
	cookie.Value = refreshTokenVal
	c.Request().AddCookie(cookie)

	getRefreshTokenSQL := `SELECT id, user_email, token_hash, expires_at FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectQuery(getRefreshTokenSQL).
		WithArgs(hashedRefreshToken).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "token_hash", "expires_at"}).
			AddRow("test-token-id", userEmail, hashedRefreshToken, tokenExpiry))

	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	mock.ExpectQuery(getUserSQL).WithArgs(userEmail).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "email", "password", "created_at",
			"total_storage_bytes", "storage_limit_bytes",
			"is_approved", "approved_by", "approved_at", "is_admin",
		}).AddRow(
			mockUser.ID, mockUser.Email, "pwd", time.Now(),
			0, models.DefaultStorageLimit, mockUser.IsApproved, nil, nil, false,
		))

	refreshCallErr := RefreshToken(c)
	require.Error(t, refreshCallErr)
	httpErr, ok := refreshCallErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to create new token", httpErr.Message)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Test Logout ---

func TestLogout_Success(t *testing.T) {
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")
	hashedRefreshToken, hashErr := auth.HashToken(refreshTokenVal)
	require.NoError(t, hashErr, "HashToken failed")

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/logout", nil)

	cookie := new(http.Cookie)
	cookie.Name = config.GetConfig().Security.RefreshTokenCookieName // Correct cookie name
	cookie.Value = refreshTokenVal
	c.Request().AddCookie(cookie)

	user := &models.User{Email: "logout@example.com"}
	c.Set("user", &auth.Claims{Email: user.Email, RegisteredClaims: jwt.RegisteredClaims{}})

	deleteTokenSQL := `DELETE FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectExec(deleteTokenSQL).
		WithArgs(hashedRefreshToken).
		WillReturnResult(sqlmock.NewResult(1, 1))

	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
	mock.ExpectExec(logActionSQL).
		WithArgs(user.Email, "logged out", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	logoutErr := Logout(c)
	require.NoError(t, logoutErr)
	assert.Equal(t, http.StatusOK, rec.Code)

	var respBody map[string]string
	unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &respBody)
	require.NoError(t, unmarshalErr)
	assert.Equal(t, "Logged out successfully", respBody["message"])

	foundCookie := false
	for _, respCookie := range rec.Result().Cookies() {
		if respCookie.Name == config.GetConfig().Security.RefreshTokenCookieName { // Correct cookie name
			assert.Equal(t, "", respCookie.Value, "Cookie value should be empty")
			assert.True(t, respCookie.MaxAge < 0, "Cookie MaxAge should be negative")
			foundCookie = true
			break
		}
	}
	assert.True(t, foundCookie, "Refresh token cookie should be set to clear")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogout_NoCookie(t *testing.T) {
	c, _ /*rec*/, mock, _ := setupTestEnv(t, http.MethodPost, "/logout", nil) // rec not used
	user := &models.User{Email: "nocookie@example.com"}
	c.Set("user", &auth.Claims{Email: user.Email, RegisteredClaims: jwt.RegisteredClaims{}})

	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
	mock.ExpectExec(logActionSQL).
		WithArgs(user.Email, "logged out", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	logoutErr := Logout(c)
	require.NoError(t, logoutErr) // Handler returns OK even if no cookie
	// assert.Equal(t, http.StatusOK, rec.Code) // rec is commented out
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogout_DeleteTokenDBError(t *testing.T) {
	refreshTokenVal, genErr := auth.GenerateRefreshToken()
	require.NoError(t, genErr, "GenerateRefreshToken failed")
	hashedRefreshToken, hashErr := auth.HashToken(refreshTokenVal)
	require.NoError(t, hashErr, "HashToken failed")

	c, _ /*rec*/, mock, _ := setupTestEnv(t, http.MethodPost, "/logout", nil) // rec not used
	user := &models.User{Email: "dberror@example.com"}
	c.Set("user", &auth.Claims{Email: user.Email, RegisteredClaims: jwt.RegisteredClaims{}})

	cookie := new(http.Cookie)
	cookie.Name = config.GetConfig().Security.RefreshTokenCookieName // Correct cookie name
	cookie.Value = refreshTokenVal
	c.Request().AddCookie(cookie)

	deleteTokenSQL := `DELETE FROM refresh_tokens WHERE token_hash = ?`
	mock.ExpectExec(deleteTokenSQL).
		WithArgs(hashedRefreshToken).
		WillReturnError(fmt.Errorf("database error on delete"))

	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
	mock.ExpectExec(logActionSQL).
		WithArgs(user.Email, "logged out", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	logoutErr := Logout(c)
	require.Error(t, logoutErr)
	httpErr, ok := logoutErr.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to delete refresh token", httpErr.Message)
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
