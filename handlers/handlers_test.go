package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log" // Import log package
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt" // Import bcrypt

	// Aliasing imports to avoid conflicts if necessary, and for clarity
	// "github.com/84adam/arkfile/auth"      // Assuming auth setup for context might be needed later
	"github.com/84adam/arkfile/config"           // Import config package
	dbSetup "github.com/84adam/arkfile/database" // Need to access the global DB variable to replace it
	"github.com/84adam/arkfile/logging"          // Import logging package
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/utils"
)

// Helper function to create a new Echo context for testing
// Returns context, recorder, and mock db instance controller
func setupTestEnv(t *testing.T, method, path string, body io.Reader) (echo.Context, *httptest.ResponseRecorder, sqlmock.Sqlmock) {
	// --- Test Config Setup ---
	// Reset config to allow reloading with test env vars
	config.ResetConfigForTest()

	// Store original env vars and set test values
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"JWT_SECRET":                "test-jwt-secret-for-handlers",
		"BACKBLAZE_ENDPOINT":        "test-endpoint",
		"BACKBLAZE_KEY_ID":          "test-key-id",
		"BACKBLAZE_APPLICATION_KEY": "test-app-key", // Note the key name difference
		"BACKBLAZE_BUCKET_NAME":     "test-bucket",
	}

	for key, testValue := range testEnv {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, testValue)
	}

	// Load config with test env vars
	_, err := config.LoadConfig()
	require.NoError(t, err, "Failed to load config with test env vars")

	// --- Logger Setup ---
	// Initialize loggers to discard output to prevent file writing during tests
	logging.InfoLogger = log.New(io.Discard, "INFO: ", log.Ldate|log.Ltime|log.LUTC)
	logging.ErrorLogger = log.New(io.Discard, "ERROR: ", log.Ldate|log.Ltime|log.LUTC)
	logging.WarningLogger = log.New(io.Discard, "WARNING: ", log.Ldate|log.Ltime|log.LUTC)
	logging.DebugLogger = log.New(io.Discard, "DEBUG: ", log.Ldate|log.Ltime|log.LUTC)
	// Alternatively, could call logging.InitLogging(&logging.LogConfig{...}) with appropriate test settings

	// --- Echo Setup ---
	e := echo.New()
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Setup Mock DB
	// Use QueryMatcherEqual for exact query matching (reverted)
	mockDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)

	// Replace the global database connection with the mock
	originalDB := dbSetup.DB
	dbSetup.DB = mockDB
	t.Cleanup(func() {
		// Restore original DB
		dbSetup.DB = originalDB
		mockDB.Close()

		// Restore original env vars
		for key, originalValue := range originalEnv {
			if originalValue == "" {
				os.Unsetenv(key) // Unset if it was originally unset
			} else {
				os.Setenv(key, originalValue)
			}
		}
		// Reset config again after tests in this file are done
		config.ResetConfigForTest()
	})

	return c, rec, mock
}

// --- Test Register ---

func TestRegister_Success(t *testing.T) {
	email := "test@example.com"
	password := "ValidPass123!@OK" // Use a valid password according to rules

	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody))

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
	c, _, _ := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Mock DB not strictly needed here, ignore recorder

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
	c, _, _ := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Mock DB not strictly needed here, ignore recorder

	err := Register(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	// Check if the message matches the specific error from the validator
	assert.Equal(t, utils.ErrPasswordTooShort.Error(), httpErr.Message.(string))

	// Test another complexity failure
	invalidPassword = "ValidPassword123" // Missing Special - from the list `~!@#$%^&*()-_=+[]{}|;:,.<>?
	reqBody = map[string]string{"email": "test@example.com", "password": invalidPassword}
	jsonBody, _ = json.Marshal(reqBody)
	c, _, _ = setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Ignore recorder

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

	c, _, mock := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Ignore recorder

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

	c, _, mock := setupTestEnv(t, http.MethodPost, "/register", bytes.NewReader(jsonBody)) // Ignore recorder

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

	c, rec, mock := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

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

	c, _, mock := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

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

	c, _, mock := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

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

func TestLogin_RefreshTokenDBError(t *testing.T) {
	email := "login@example.com"
	password := "ValidPass123!@OK"
	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

	// Mock GetUserByEmail successful
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	// Hash with configured cost for the mock DB row
	hashedPasswordBytes, _ := bcrypt.GenerateFromPassword([]byte(password), config.GetConfig().Security.BcryptCost) // Use config value
	hashedPassword := string(hashedPasswordBytes)
	rows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(
		1, email, hashedPassword, time.Now(), 0, models.DefaultStorageLimit, true, nil, nil, false,
	)
	mock.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(rows)

	// Mock CreateRefreshToken to fail - Use Exact SQL String (Corrected)
	// Actual SQL: INSERT INTO refresh_tokens ( id, user_email, token_hash, expires_at ) VALUES (?, ?, ?, ?)
	refreshTokenSQL := `INSERT INTO refresh_tokens (
			id, user_email, token_hash, expires_at
		) VALUES (?, ?, ?, ?)`
	mock.ExpectExec(refreshTokenSQL).
		WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg(), sqlmock.AnyArg()). // id, email, hash, expiry
		WillReturnError(fmt.Errorf("DB error creating refresh token"))         // Simulate failure

	// Execute handler
	err := Login(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Login failed", httpErr.Message) // Handler returns generic message

	// Ensure all SQL expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Test UploadFile ---
// ... TODO: Add UploadFile tests using setupTestEnv and sqlmock ...
// Requires mocks for GetUserByEmail, DB transaction (Begin, Exec, Commit/Rollback)
// Also requires mocking Minio client interactions

// --- Test DownloadFile ---
// ... TODO: Add DownloadFile tests using setupTestEnv and sqlmock ...
// Requires mocks for DB queries (owner check, metadata)
// Also requires mocking Minio client GetObject

// --- Test ListFiles ---
// ... TODO: Add ListFiles tests using setupTestEnv and sqlmock ...
// Requires mocks for DB queries (list files, get user storage)

// --- Test DeleteFile ---
// ... TODO: Add DeleteFile tests using setupTestEnv and sqlmock ...
// Requires mocks for DB transaction (Begin, QueryRow, Exec, Commit/Rollback)
// Also requires mocking storage.RemoveFile (needs interface/mock for storage)

// --- Mock Minio Client (Example Placeholder) ---
/*
type MockMinioClient struct {
	mock.Mock // Using testify/mock for example
}

// Implement methods used by handlers (PutObject, GetObject, RemoveObject etc.)
// Need to define an interface for the storage layer first to allow mocking.

func (m *MockMinioClient) PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	args := m.Called(ctx, bucketName, objectName, reader, objectSize, opts)
	// Example: return minio.UploadInfo{}, args.Error(0)
	panic("MockMinioClient.PutObject not fully implemented")
}
// ... etc ...
*/
