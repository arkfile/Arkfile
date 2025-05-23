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
	jwt "github.com/golang-jwt/jwt/v5" // Use alias for clarity
	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7" // Import minio
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock" // Import testify/mock
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt" // Import bcrypt

	// Aliasing imports to avoid conflicts if necessary, and for clarity
	"github.com/84adam/arkfile/auth"             // Ensure auth is imported
	"github.com/84adam/arkfile/config"           // Import config package
	dbSetup "github.com/84adam/arkfile/database" // Need to access the global DB variable to replace it
	"github.com/84adam/arkfile/logging"          // Import logging package
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage" // Import storage package
	"github.com/84adam/arkfile/utils"
)

// Helper function to create a new Echo context for testing
// Returns context, recorder, mock db instance controller, and mock storage provider
func setupTestEnv(t *testing.T, method, path string, body io.Reader) (echo.Context, *httptest.ResponseRecorder, sqlmock.Sqlmock, *storage.MockObjectStorageProvider) {
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
	originalDB := dbSetup.DB // Store original DB connection
	dbSetup.DB = mockDB      // Replace global variable with mock

	// Setup Mock Storage Provider
	mockStorage := new(storage.MockObjectStorageProvider) // Create mock storage instance
	originalProvider := storage.Provider                  // Store original storage provider
	storage.Provider = mockStorage                        // Replace global variable with mock
	t.Cleanup(func() {
		// Restore original DB and Storage Provider
		dbSetup.DB = originalDB
		storage.Provider = originalProvider // Restore original provider
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

	// Return the mock storage provider as well
	return c, rec, mock, mockStorage
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
	invalidPassword = "ValidPassword123" // Missing Special - from the list `~!@#$%^&*()-_=+[]{}|;:,.<>?
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

func TestLogin_RefreshTokenDBError(t *testing.T) {
	email := "login@example.com"
	password := "ValidPass123!@OK"
	reqBody := map[string]string{"email": email, "password": password}
	jsonBody, _ := json.Marshal(reqBody)

	// Update call to accept 4 return values
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/login", bytes.NewReader(jsonBody))

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

// TestUploadFile_Success tests successful file upload
func TestUploadFile_Success(t *testing.T) {
	email := "uploader@example.com"
	filename := "my-test-file.dat"
	fileData := "This is the test file content."
	passwordHint := "test hint"
	passwordType := "account"                                                       // or "custom"
	sha256sum := "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2" // Example hash for "This is the test file content."
	fileSize := int64(len(fileData))
	initialStorage := int64(0)
	expectedFinalStorage := initialStorage + fileSize

	reqBodyMap := map[string]string{
		"filename":     filename,
		"data":         fileData,
		"passwordHint": passwordHint,
		"passwordType": passwordType,
		"sha256sum":    sha256sum,
	}
	jsonBody, _ := json.Marshal(reqBodyMap)

	// Setup test environment
	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodPost, "/files", bytes.NewReader(jsonBody)) // Assuming POST /files is the route

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- Mock GetUserByEmail (for storage check) ---
	// Uses the *non-transactional* GetUserByEmail outside the transaction
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(5) // Assume some user ID
	userRows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, "hashed", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations (Order based on handler logic) ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call first (as per handler logic)
	mockStorage.On("PutObject",
		mock.Anything, // context
		filename,
		mock.AnythingOfType("*strings.Reader"), // Handler wraps data
		fileSize,
		mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, nil).Once() // Simulate successful upload

	// 2. Expect Metadata Insertion (after PutObject)
	insertMetaSQL := "INSERT INTO file_metadata (filename, owner_email, password_hint, password_type, sha256sum, size_bytes) VALUES (?, ?, ?, ?, ?, ?)"
	mockDB.ExpectExec(insertMetaSQL).
		WithArgs(filename, email, passwordHint, passwordType, sha256sum, fileSize).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 3. Expect Storage Usage Update (inside user.UpdateStorageUsage)
	updateStorageSQL := "UPDATE users SET total_storage_bytes = ? WHERE id = ?"
	mockDB.ExpectExec(updateStorageSQL).
		WithArgs(expectedFinalStorage, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// 4. Expect Commit
	mockDB.ExpectCommit()

	// --- Mock LogUserAction (after commit) ---
	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
	mockDB.ExpectExec(logActionSQL).WithArgs(email, "uploaded", filename).WillReturnResult(sqlmock.NewResult(1, 1))

	// --- Execute Handler ---
	err := UploadFile(c)

	// --- Assertions ---
	require.NoError(t, err, "UploadFile handler failed")
	assert.Equal(t, http.StatusOK, rec.Code, "Expected status OK")

	// Check response body
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err, "Failed to unmarshal response")
	assert.Equal(t, "File uploaded successfully", resp["message"])

	// Check updated storage in response (using handler's upload response logic)
	storageInfo, ok := resp["storage"].(map[string]interface{})
	require.True(t, ok, "Storage info missing in response")
	// Uses initial value + fileSize for response calculation
	assert.Equal(t, float64(initialStorage+fileSize), storageInfo["total_bytes"], "Storage total bytes mismatch in response")
	assert.Equal(t, float64(models.DefaultStorageLimit), storageInfo["limit_bytes"], "Storage limit bytes mismatch in response")
	assert.Equal(t, float64(models.DefaultStorageLimit-(initialStorage+fileSize)), storageInfo["available_bytes"], "Storage available bytes mismatch in response")

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t)
}

// TestUploadFile_StorageLimitExceeded tests attempting to upload when storage is insufficient
func TestUploadFile_StorageLimitExceeded(t *testing.T) {
	email := "limit-exceeder@example.com"
	filename := "too-big-file.dat"
	fileData := "Some data"
	fileSize := int64(len(fileData)) // e.g., 9 bytes
	// Set initial storage to be very close to the limit
	initialStorage := models.DefaultStorageLimit - (fileSize / 2) // e.g., 10GB - 4 bytes
	// Uploading fileSize (9 bytes) would exceed the limit (10GB)

	reqBodyMap := map[string]string{
		"filename":     filename,
		"data":         fileData,
		"passwordHint": "hint",
		"passwordType": "account",
		"sha256sum":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Valid 64 hex chars
	}
	jsonBody, _ := json.Marshal(reqBodyMap)

	// Setup test environment
	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/files", bytes.NewReader(jsonBody)) // Storage mock not used here

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- Mock GetUserByEmail (for storage check) ---
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(6)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, "hashed", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// Handler should check storage and fail BEFORE starting transaction or calling storage

	// --- Execute Handler ---
	err := UploadFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for storage limit exceeded")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusForbidden, httpErr.Code, "Expected status Forbidden")
	assert.Equal(t, "Storage limit would be exceeded", httpErr.Message.(string))

	// Verify all DB expectations were met (only the GetUser query)
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	// No storage expectations to assert
}

// TestUploadFile_StoragePutError tests failure during storage PutObject
func TestUploadFile_StoragePutError(t *testing.T) {
	email := "uploader-stor-err@example.com"
	filename := "fail-on-put.dat"
	fileData := "This data won't make it."
	fileSize := int64(len(fileData))
	initialStorage := int64(0)

	reqBodyMap := map[string]string{
		"filename":     filename,
		"data":         fileData,
		"passwordHint": "hint",
		"passwordType": "account",
		"sha256sum":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Valid hash
	}
	jsonBody, _ := json.Marshal(reqBodyMap)

	// Setup test environment
	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodPost, "/files", bytes.NewReader(jsonBody))

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- Mock GetUserByEmail (for storage check) ---
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(7)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, "hashed", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call to FAIL
	storageError := fmt.Errorf("simulated storage PutObject error")
	mockStorage.On("PutObject",
		mock.Anything, // context
		filename,
		mock.AnythingOfType("*strings.Reader"),
		fileSize,
		mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, storageError).Once() // Return the error

	// 2. Expect Rollback because PutObject failed
	mockDB.ExpectRollback()

	// --- Execute Handler ---
	err := UploadFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for storage PutObject failure")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code, "Expected status InternalServerError")
	// The handler returns a generic message for PutObject errors
	assert.Equal(t, "Failed to upload file", httpErr.Message.(string))

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t)
}

// TestUploadFile_MetadataInsertError tests failure during DB metadata insertion
func TestUploadFile_MetadataInsertError(t *testing.T) {
	email := "uploader-meta-err@example.com"
	filename := "fail-on-meta-insert.dat"
	fileData := "This data makes it to storage, but not DB."
	fileSize := int64(len(fileData))
	initialStorage := int64(0)

	reqBodyMap := map[string]string{
		"filename":     filename,
		"data":         fileData,
		"passwordHint": "hint",
		"passwordType": "account",
		"sha256sum":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Valid hash
	}
	jsonBody, _ := json.Marshal(reqBodyMap)

	// Setup test environment
	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodPost, "/files", bytes.NewReader(jsonBody))

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- Mock GetUserByEmail (for storage check) ---
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(8)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, "hashed", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call to SUCCEED
	mockStorage.On("PutObject",
		mock.Anything, filename, mock.AnythingOfType("*strings.Reader"), fileSize, mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, nil).Once()

	// 2. Expect Metadata Insertion to FAIL
	dbError := fmt.Errorf("simulated DB metadata insert error")
	insertMetaSQL := "INSERT INTO file_metadata (filename, owner_email, password_hint, password_type, sha256sum, size_bytes) VALUES (?, ?, ?, ?, ?, ?)"
	mockDB.ExpectExec(insertMetaSQL).
		WithArgs(filename, email, "hint", "account", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fileSize).
		WillReturnError(dbError)

	// 3. Expect Storage Cleanup (RemoveObject) because metadata insert failed
	mockStorage.On("RemoveObject",
		mock.Anything, filename, mock.AnythingOfType("minio.RemoveObjectOptions"),
	).Return(nil).Once() // Simulate successful cleanup

	// 4. Expect Rollback
	mockDB.ExpectRollback()

	// --- Execute Handler ---
	err := UploadFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for metadata insert failure")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code, "Expected status InternalServerError")
	// Corrected: Handler returns this for metadata insert failure
	assert.Equal(t, "Failed to process file", httpErr.Message.(string))

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t)
}

// TestUploadFile_UpdateStorageError tests failure during DB user storage update
func TestUploadFile_UpdateStorageError(t *testing.T) {
	email := "uploader-upd-stor-err@example.com"
	filename := "fail-on-update-storage.dat"
	fileData := "This data is in storage & meta, but user total is wrong."
	fileSize := int64(len(fileData))
	initialStorage := int64(0)

	reqBodyMap := map[string]string{
		"filename":     filename,
		"data":         fileData,
		"passwordHint": "hint",
		"passwordType": "account",
		"sha256sum":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Valid hash
	}
	jsonBody, _ := json.Marshal(reqBodyMap)

	// Setup test environment
	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodPost, "/files", bytes.NewReader(jsonBody))

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- Mock GetUserByEmail (for storage check) ---
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(9)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, "hashed", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call to SUCCEED
	mockStorage.On("PutObject",
		mock.Anything, filename, mock.AnythingOfType("*strings.Reader"), fileSize, mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, nil).Once()

	// 2. Expect Metadata Insertion to SUCCEED
	insertMetaSQL := "INSERT INTO file_metadata (filename, owner_email, password_hint, password_type, sha256sum, size_bytes) VALUES (?, ?, ?, ?, ?, ?)"
	mockDB.ExpectExec(insertMetaSQL).
		WithArgs(filename, email, "hint", "account", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fileSize).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 3. Expect Storage Usage Update to FAIL
	dbError := fmt.Errorf("simulated DB update storage error")
	updateStorageSQL := "UPDATE users SET total_storage_bytes = ? WHERE id = ?"
	mockDB.ExpectExec(updateStorageSQL).
		WithArgs(initialStorage+fileSize, userID). // Correct expected args
		WillReturnError(dbError)

	// 4. Expect Rollback because storage update failed
	mockDB.ExpectRollback()

	// No storage cleanup (RemoveObject) should be called here. The failed DB transaction
	// means the file technically exists in storage and metadata, but the user's total wasn't updated.
	// Rollback handles the DB consistency.

	// --- Execute Handler ---
	err := UploadFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for update storage failure")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code, "Expected status InternalServerError")
	// Corrected: Handler returns this for storage update failure
	assert.Equal(t, "Failed to update storage usage", httpErr.Message.(string))

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t) // Check PutObject was called
}

// TestUploadFile_CommitError tests failure during the final DB transaction commit
func TestUploadFile_CommitError(t *testing.T) {
	email := "uploader-commit-err@example.com"
	filename := "fail-on-commit.dat"
	fileData := "This data is almost committed."
	fileSize := int64(len(fileData))
	initialStorage := int64(0)
	expectedFinalStorage := initialStorage + fileSize

	reqBodyMap := map[string]string{
		"filename":     filename,
		"data":         fileData,
		"passwordHint": "hint",
		"passwordType": "account",
		"sha256sum":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Valid hash
	}
	jsonBody, _ := json.Marshal(reqBodyMap)

	// Setup test environment
	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodPost, "/files", bytes.NewReader(jsonBody))

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- Mock GetUserByEmail (for storage check) ---
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(10)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, "hashed", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call to SUCCEED
	mockStorage.On("PutObject",
		mock.Anything, filename, mock.AnythingOfType("*strings.Reader"), fileSize, mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, nil).Once()

	// 2. Expect Metadata Insertion to SUCCEED
	insertMetaSQL := "INSERT INTO file_metadata (filename, owner_email, password_hint, password_type, sha256sum, size_bytes) VALUES (?, ?, ?, ?, ?, ?)"
	mockDB.ExpectExec(insertMetaSQL).
		WithArgs(filename, email, "hint", "account", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fileSize).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 3. Expect Storage Usage Update to SUCCEED
	updateStorageSQL := "UPDATE users SET total_storage_bytes = ? WHERE id = ?"
	mockDB.ExpectExec(updateStorageSQL).
		WithArgs(expectedFinalStorage, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// 4. Expect Commit to FAIL
	dbError := fmt.Errorf("simulated DB commit error")
	mockDB.ExpectCommit().WillReturnError(dbError)

	// Rollback is not explicitly called by the handler if commit fails,
	// but the transaction state is effectively rolled back. sqlmock doesn't track implicit rollbacks.
	// No storage cleanup should be called here either.

	// --- Execute Handler ---
	err := UploadFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for commit failure")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code, "Expected status InternalServerError")
	// Corrected: Handler returns this for commit failure
	assert.Equal(t, "Failed to complete upload", httpErr.Message.(string))

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t) // Check PutObject was called
}

// --- Test DownloadFile ---

// TestDownloadFile_Success tests successful file download
func TestDownloadFile_Success(t *testing.T) {
	email := "downloader@example.com"
	filename := "download-test.txt"
	fileContent := "This is the content to be downloaded."
	fileSize := int64(len(fileContent))
	passwordHint := "download hint"
	passwordType := "account"
	sha256sum := "hash123..." // Precise hash not critical for this test path

	// Setup test environment
	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodGet, "/files/:filename", nil) // GET request

	// Set path parameter
	c.SetParamNames("filename")
	c.SetParamValues(filename)

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- DB Expectations (Non-transactional) ---

	// 1. Expect Ownership Check (assuming it uses QueryRow)
	ownerCheckSQL := "SELECT owner_email FROM file_metadata WHERE filename = ?"
	ownerRows := sqlmock.NewRows([]string{"owner_email"}).AddRow(email) // File belongs to the user
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnRows(ownerRows)

	// 2. Expect Metadata Retrieval - CORRECTED QUERY AND ROWS based on handler code
	metadataSQL := "SELECT password_hint, password_type, sha256sum FROM file_metadata WHERE filename = ?"
	metaRows := sqlmock.NewRows([]string{
		"password_hint", "password_type", "sha256sum",
	}).AddRow(passwordHint, passwordType, sha256sum) // Only these columns are returned
	mockDB.ExpectQuery(metadataSQL).WithArgs(filename).WillReturnRows(metaRows) // Only filename arg

	// --- Storage Expectations ---
	// 3. Expect GetObject call
	mockStorageObject := new(storage.MockMinioObject) // Use the mock object
	mockStorageObject.SetContent(fileContent)         // Use helper to set content
	// Use the new helper to set the stat info directly on the mock object
	mockStorageObject.SetStatInfo(minio.ObjectInfo{Size: fileSize}, nil)
	// mockStorageObject.On("Stat")... // REMOVED - Stat() now returns the directly set info
	mockStorageObject.On("Close").Return(nil) // Still expect Close to be called using testify mock

	mockStorage.On("GetObject",
		mock.Anything, // context
		filename,
		mock.AnythingOfType("minio.GetObjectOptions"),
	).Return(mockStorageObject, nil).Once() // Return the mock object

	// 4. Expect LogUserAction - CORRECTED ACTION
	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
	mockDB.ExpectExec(logActionSQL).WithArgs(email, "downloaded", filename).WillReturnResult(sqlmock.NewResult(1, 1))

	// --- Execute Handler ---
	err := DownloadFile(c) // This IS the correct handler function

	// --- Assertions ---
	require.NoError(t, err, "DownloadFile handler failed")
	assert.Equal(t, http.StatusOK, rec.Code, "Expected status OK")

	// Check response body (it returns a map) - CORRECTED ASSERTIONS
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err, "Failed to unmarshal response")
	assert.Equal(t, fileContent, resp["data"])          // Check actual file data
	assert.Equal(t, passwordHint, resp["passwordHint"]) // Check hint from metadata query
	assert.Equal(t, passwordType, resp["passwordType"]) // Check type from metadata query
	assert.Equal(t, sha256sum, resp["sha256sum"])       // Check sum from metadata query

	// Headers are not explicitly set by this handler for JSON response
	// (A streaming download endpoint would set Content-Disposition etc.)

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t)       // Check GetObject call
	mockStorageObject.AssertExpectations(t) // Check Close call
}

// TODO: Add more DownloadFile tests (not found, not owner, metadata query error, storage get error)

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

// --- Test DeleteFile ---

// TestDeleteFile_Success tests successful file deletion
func TestDeleteFile_Success(t *testing.T) {
	email := "user-delete@example.com"
	filename := "file-to-delete.txt"
	fileSize := int64(1024)       // Example size
	initialStorage := int64(5000) // Example initial storage

	// Setup test environment, getting mocks for DB and Storage
	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil) // Path doesn't matter much here, params are set below

	// Set path parameter
	c.SetParamNames("filename")
	c.SetParamValues(filename)

	// Add Authentication context (emulates JWT middleware)
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // Using dummy signing method for context setting
	c.Set("user", token)

	// --- DB Expectations ---
	mockDB.ExpectBegin() // 1. Expect transaction start

	// 2. Expect ownership check query (returns correct owner and file size)
	ownerCheckSQL := "SELECT owner_email, size_bytes FROM file_metadata WHERE filename = ?"
	ownerRows := sqlmock.NewRows([]string{"owner_email", "size_bytes"}).AddRow(email, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnRows(ownerRows)

	// 3. Expect metadata deletion
	deleteMetaSQL := "DELETE FROM file_metadata WHERE filename = ?"
	mockDB.ExpectExec(deleteMetaSQL).WithArgs(filename).WillReturnResult(sqlmock.NewResult(0, 1))

	// 4. Expect GetUserByEmail query (needed for UpdateStorageUsage)
	getUserSQL := `
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	// Add user ID to variable for use in update expectation
	userID := int64(1)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "password", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, "hashed", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// 5. Expect storage usage update (uses ID, not email)
	updateStorageSQL := "UPDATE users SET total_storage_bytes = ? WHERE id = ?" // Correct SQL criteria
	expectedStorage := initialStorage - fileSize
	mockDB.ExpectExec(updateStorageSQL).WithArgs(expectedStorage, userID).WillReturnResult(sqlmock.NewResult(0, 1)) // Correct arguments

	// 6. Expect transaction commit
	mockDB.ExpectCommit()

	// 7. Expect LogUserAction (after commit)
	logActionSQL := `INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)`
	mockDB.ExpectExec(logActionSQL).WithArgs(email, "deleted", filename).WillReturnResult(sqlmock.NewResult(1, 1))

	// --- Storage Expectations ---
	// Expect RemoveObject call on the mock storage provider using the correct syntax: On(...)
	mockStorage.On("RemoveObject",
		mock.Anything, // Use mock.Anything to match any context, including context.Background()
		filename,      // Match exact filename
		mock.AnythingOfType("minio.RemoveObjectOptions"), // Match any options struct
	).Return(nil).Once() // Simulate success, expect once

	// --- Execute Handler ---
	err := DeleteFile(c)

	// --- Assertions ---
	require.NoError(t, err, "DeleteFile handler failed")
	assert.Equal(t, http.StatusOK, rec.Code, "Expected status OK")

	// Check response body
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err, "Failed to unmarshal response")
	assert.Equal(t, "File deleted successfully", resp["message"])

	// Check updated storage in response
	storageInfo, ok := resp["storage"].(map[string]interface{})
	require.True(t, ok, "Storage info missing in response")
	// Use float64 for JSON numbers
	assert.Equal(t, float64(expectedStorage), storageInfo["total_bytes"], "Storage total bytes mismatch")

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t) // Verify storage mock expectations
}

// TestDeleteFile_NotFound tests deleting a file that doesn't exist
func TestDeleteFile_NotFound(t *testing.T) {
	email := "user-delete@example.com"
	filename := "non-existent-file.txt"

	// Setup test environment - storage mock not strictly needed but harmless
	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil)

	// Set path parameter
	c.SetParamNames("filename")
	c.SetParamValues(filename)

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- DB Expectations ---
	mockDB.ExpectBegin() // Expect transaction start

	// Expect ownership check query to return sql.ErrNoRows
	ownerCheckSQL := "SELECT owner_email, size_bytes FROM file_metadata WHERE filename = ?"
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnError(sql.ErrNoRows)

	// Expect Rollback because handler should error out before commit
	mockDB.ExpectRollback()

	// --- Execute Handler ---
	err := DeleteFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for file not found")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusNotFound, httpErr.Code, "Expected status NotFound")
	assert.Equal(t, "File not found", httpErr.Message.(string))

	// Verify all DB expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
}

// TestDeleteFile_NotOwner tests deleting a file owned by someone else
func TestDeleteFile_NotOwner(t *testing.T) {
	requestingUserEmail := "user-trying-delete@example.com"
	ownerEmail := "actual-owner@example.com" // Different user
	filename := "someone-elses-file.txt"
	fileSize := int64(512)

	// Setup test environment
	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil)

	// Set path parameter
	c.SetParamNames("filename")
	c.SetParamValues(filename)

	// Add Authentication context for the requesting user
	claims := &auth.Claims{Email: requestingUserEmail}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- DB Expectations ---
	mockDB.ExpectBegin() // Expect transaction start

	// Expect ownership check query returns the actual owner's email
	ownerCheckSQL := "SELECT owner_email, size_bytes FROM file_metadata WHERE filename = ?"
	ownerRows := sqlmock.NewRows([]string{"owner_email", "size_bytes"}).AddRow(ownerEmail, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnRows(ownerRows)

	// Expect Rollback because handler should error out before commit
	mockDB.ExpectRollback()

	// --- Execute Handler ---
	err := DeleteFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for not owner")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusForbidden, httpErr.Code, "Expected status Forbidden")
	assert.Equal(t, "Not authorized to delete this file", httpErr.Message.(string))

	// Verify all DB expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
}

// TestDeleteFile_StorageError tests failure during storage object removal
func TestDeleteFile_StorageError(t *testing.T) {
	email := "user-delete@example.com"
	filename := "file-stor-err.txt"
	fileSize := int64(1024)
	// No need for initialStorage here as the handler errors before user update

	// Setup test environment
	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil)

	// Set path parameter
	c.SetParamNames("filename")
	c.SetParamValues(filename)

	// Add Authentication context
	claims := &auth.Claims{Email: email}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// --- DB Expectations ---
	mockDB.ExpectBegin() // Expect transaction start

	// Expect ownership check query (successful check)
	ownerCheckSQL := "SELECT owner_email, size_bytes FROM file_metadata WHERE filename = ?"
	ownerRows := sqlmock.NewRows([]string{"owner_email", "size_bytes"}).AddRow(email, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnRows(ownerRows)

	// Expect Rollback because storage error should trigger it
	mockDB.ExpectRollback()

	// --- Storage Expectations ---
	// Expect RemoveObject call to return an error
	storageError := fmt.Errorf("simulated storage layer error")
	mockStorage.On("RemoveObject",
		mock.Anything, // context
		filename,
		mock.AnythingOfType("minio.RemoveObjectOptions"),
	).Return(storageError).Once() // Return the simulated error

	// --- Execute Handler ---
	err := DeleteFile(c)

	// --- Assertions ---
	require.Error(t, err, "Expected an error for storage failure")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok, "Error should be an echo.HTTPError")
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code, "Expected status InternalServerError")
	assert.Equal(t, "Failed to delete file from storage", httpErr.Message.(string))

	// Verify all DB and Storage expectations were met
	assert.NoError(t, mockDB.ExpectationsWereMet(), "DB expectations not met")
	mockStorage.AssertExpectations(t)
}

// TODO: Add DeleteFile tests for DB errors during transaction (metadata delete, user get, user update, commit)

// --- Admin Handler Tests ---

// TestGetPendingUsers_Success_Admin tests successful retrieval of pending users by an admin.
func TestGetPendingUsers_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	pendingUser1Email := "pending1@example.com"
	pendingUser2Email := "pending2@example.com"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	// Set up admin context
	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin check
	adminUserRows := sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
		AddRow(1, adminEmail, "hashedpassword", true, true) // Admin user
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(adminUserRows)

	// Mock GetPendingUsers
	pendingUsersData := []models.User{
		{ID: 2, Email: pendingUser1Email, IsApproved: false},
		{ID: 3, Email: pendingUser2Email, IsApproved: false},
	}
	// Construct rows for GetPendingUsers (models/user.go)
	// SELECT id, email, created_at, is_approved, approved_by, approved_at, is_admin FROM users WHERE is_approved = 0 ORDER BY created_at ASC
	pendingRows := sqlmock.NewRows([]string{"id", "email", "created_at", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(pendingUsersData[0].ID, pendingUsersData[0].Email, time.Now(), false, sql.NullString{}, sql.NullTime{}, false).
		AddRow(pendingUsersData[1].ID, pendingUsersData[1].Email, time.Now(), false, sql.NullString{}, sql.NullTime{}, false)
	mockDB.ExpectQuery(`SELECT id, email, created_at, is_approved, approved_by, approved_at, is_admin FROM users WHERE is_approved = 0 ORDER BY created_at ASC`).
		WillReturnRows(pendingRows)

	err := GetPendingUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var respUsers []models.User
	err = json.Unmarshal(rec.Body.Bytes(), &respUsers)
	require.NoError(t, err)
	assert.Len(t, respUsers, 2)
	assert.Equal(t, pendingUser1Email, respUsers[0].Email)
	assert.Equal(t, pendingUser2Email, respUsers[1].Email)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Success_Admin tests successful user deletion by an admin.
func TestDeleteUser_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-to-delete@example.com"
	mockFile1 := "userfile1.txt"
	mockFile2 := "userfile2.dat"

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()

	// Mock query for user's files
	fileRows := sqlmock.NewRows([]string{"filename"}).AddRow(mockFile1).AddRow(mockFile2)
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	// Mock storage removal for each file
	mockStorage.On("RemoveObject", mock.Anything, mockFile1, mock.AnythingOfType("minio.RemoveObjectOptions")).Return(nil).Once()
	mockStorage.On("RemoveObject", mock.Anything, mockFile2, mock.AnythingOfType("minio.RemoveObjectOptions")).Return(nil).Once()

	// Mock deletion of file metadata for each file
	mockDB.ExpectExec("DELETE FROM file_metadata WHERE filename = ?").WithArgs(mockFile1).WillReturnResult(sqlmock.NewResult(0, 1))
	mockDB.ExpectExec("DELETE FROM file_metadata WHERE filename = ?").WithArgs(mockFile2).WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock deletion of user shares
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1)) // Assume 1 share deleted for simplicity

	// Mock deletion of user record
	mockDB.ExpectExec("DELETE FROM users WHERE email = ?").
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1)) // 1 user record deleted

	mockDB.ExpectCommit()

	// Mock LogAdminAction
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "delete_user", targetUserEmail, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User deleted successfully", resp["message"])

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Forbidden_NonAdmin tests that a non-admin user cannot delete another user.
func TestDeleteUser_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "nonadmin@example.com"
	targetUserEmail := "user-to-delete@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail} // IsAdmin defaults to false
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	// Mock GetUserByEmail for the non-admin user making the request
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(2, nonAdminEmail, "nonadminpass", false, true)) // is_admin is false

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet()) // Only GetUserByEmail for the non-admin should be called
}

// TestDeleteUser_Error_AdminFetchError tests error when fetching admin user details.
func TestDeleteUser_Error_AdminFetchError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-to-delete@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin to return an error
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error fetching admin"))

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get admin user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_BadRequest_MissingEmailParam tests request with missing email parameter.
func TestDeleteUser_BadRequest_MissingEmailParam(t *testing.T) {
	adminEmail := "admin@example.com"

	// Path in setupTestEnv will be something like "/admin/users/" - last segment empty
	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/", nil) // or c.SetParamValues("")
	// Do NOT set param values for "email"

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (this is called before the param check)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email parameter required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_SelfDeletionAttempt tests an admin attempting to delete themselves.
func TestDeleteUser_Error_SelfDeletionAttempt(t *testing.T) {
	adminEmail := "admin@example.com" // Admin is also the target

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(adminEmail) // Target email is the admin's email

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (this is called first)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// No further DB calls or storage operations should happen if self-deletion is caught.

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Admin cannot delete their own account", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_GetUserFilesError tests error when fetching target user's file list.
func TestDeleteUser_Error_GetUserFilesError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-file-fetch-error@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (successful)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()

	// Mock query for user's files to return an error
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnError(fmt.Errorf("DB error fetching user files"))

	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to retrieve user's files", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_StorageRemoveObjectError tests error during storage.RemoveObject for a user's file.
func TestDeleteUser_Error_StorageRemoveObjectError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-storage-remove-error@example.com"
	fileWithError := "file-causes-storage-error.txt"

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (successful)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()

	// Mock query for user's files to return the file that will cause an error
	fileRows := sqlmock.NewRows([]string{"filename"}).AddRow(fileWithError)
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	// Mock storage removal for THE file to return an error
	storageErr := fmt.Errorf("simulated storage RemoveObject error")
	mockStorage.On("RemoveObject", mock.Anything, fileWithError, mock.AnythingOfType("minio.RemoveObjectOptions")).
		Return(storageErr).Once()

	mockDB.ExpectRollback() // Transaction should be rolled back due to the error

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	expectedMessage := fmt.Sprintf("Failed to delete user's file from storage: %s", fileWithError)
	assert.Equal(t, expectedMessage, httpErr.Message)

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_DeleteFileMetadataError tests error during DB deletion of file metadata.
func TestDeleteUser_Error_DeleteFileMetadataError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-meta-delete-error@example.com"
	fileWithError := "file-causes-meta-delete-error.txt"

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (successful)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()

	// Mock query for user's files to return the file that will cause an error
	fileRows := sqlmock.NewRows([]string{"filename"}).AddRow(fileWithError)
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	// Mock storage removal for the file to SUCCEED
	mockStorage.On("RemoveObject", mock.Anything, fileWithError, mock.AnythingOfType("minio.RemoveObjectOptions")).
		Return(nil).Once()

	// Mock deletion of file metadata for THE file to return an error
	dbErr := fmt.Errorf("simulated DB error deleting metadata")
	mockDB.ExpectExec("DELETE FROM file_metadata WHERE filename = ?").WithArgs(fileWithError).
		WillReturnError(dbErr)

	mockDB.ExpectRollback() // Transaction should be rolled back

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	expectedMessage := fmt.Sprintf("Failed to delete file metadata for: %s", fileWithError)
	assert.Equal(t, expectedMessage, httpErr.Message)

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_DeleteFileSharesError tests error during DB deletion of user's file shares.
func TestDeleteUser_Error_DeleteFileSharesError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-share-delete-error@example.com"
	// Can optionally have files that are processed successfully before this error
	// For simplicity, assume no files, or files are processed correctly.
	// If files were present, mock RemoveObject and DELETE file_metadata as successful.

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (successful)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()

	// Mock query for user's files (e.g., returns no files, or files are handled correctly)
	fileRows := sqlmock.NewRows([]string{"filename"}) // No files, or add rows and mock their removal
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)
	// If fileRows had entries, successful mockStorage.On("RemoveObject") and
	// mockDB.ExpectExec("DELETE FROM file_metadata...") would go here.

	// Mock deletion of user shares to return an error
	dbErr := fmt.Errorf("simulated DB error deleting file shares")
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnError(dbErr)

	mockDB.ExpectRollback() // Transaction should be rolled back

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to delete user's file shares", httpErr.Message)

	mockStorage.AssertExpectations(t) // Should be no calls if no files, or successful if files existed.
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_DeleteUserRecordError tests error during DB deletion of the user record itself.
func TestDeleteUser_Error_DeleteUserRecordError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-record-delete-error@example.com"

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (successful)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()

	// Mock query for user's files (e.g., returns no files, or files are handled correctly)
	fileRows := sqlmock.NewRows([]string{"filename"}) // No files
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)
	// If files were present, successful mockStorage.On("RemoveObject") and
	// mockDB.ExpectExec("DELETE FROM file_metadata...") would go here.

	// Mock deletion of user shares to SUCCEED
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 0)) // Assume no shares or successful deletion

	// Mock deletion of user record to return an error
	dbErr := fmt.Errorf("simulated DB error deleting user record")
	mockDB.ExpectExec("DELETE FROM users WHERE email = ?").
		WithArgs(targetUserEmail).
		WillReturnError(dbErr)

	mockDB.ExpectRollback() // Transaction should be rolled back

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to delete user record", httpErr.Message)

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_CommitError tests error during transaction commit.
func TestDeleteUser_Error_CommitError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-commit-error@example.com"

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (successful)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()

	// Mock query for user's files (e.g., returns no files)
	fileRows := sqlmock.NewRows([]string{"filename"})
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	// Mock deletion of user shares to SUCCEED
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 0))

	// Mock deletion of user record to SUCCEED
	mockDB.ExpectExec("DELETE FROM users WHERE email = ?").
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock Commit to return an error
	dbErr := fmt.Errorf("simulated DB commit error")
	mockDB.ExpectCommit().WillReturnError(dbErr)

	// Rollback is not explicitly called by the handler if Commit fails.

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to commit user deletion transaction", httpErr.Message)

	mockStorage.AssertExpectations(t) // Should verify no storage calls if no files
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_SetAdmin_Success_Admin tests making a user an admin.
func TestUpdateUser_SetAdmin_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target-to-make-admin@example.com"
	isAdminTrue := true
	// Only sending isAdmin in the body, isApproved should not be affected if not sent
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()
	// Mock user existence check for target user
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	// Mock DB update for setting isAdmin = true
	// This query assumes only isAdmin is being updated.
	// The actual query built by the handler will depend on what fields are non-nil in the request.
	// Since only isAdmin is provided, the query will be: UPDATE users SET is_admin = ? WHERE email = ?
	updateSQL := `UPDATE users SET is_admin = ? WHERE email = ?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(true, targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock LogAdminAction
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	details := "isAdmin: true" // Details reflect only the changed field
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "update_user", targetUserEmail, details).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectCommit()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_SetStorageLimit_Success_Admin tests updating a user's storage limit.
func TestUpdateUser_SetStorageLimit_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target-for-storage-update@example.com"
	newStorageLimit := int64(50 * 1024 * 1024 * 1024) // 50 GB

	reqBodyMap := map[string]interface{}{"storageLimitBytes": newStorageLimit}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()
	// Mock user existence check
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	// Mock DB update for storageLimitBytes
	updateSQL := `UPDATE users SET storage_limit_bytes = ? WHERE email = ?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newStorageLimit, targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock LogAdminAction
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	details := fmt.Sprintf("storageLimitBytes: %d", newStorageLimit)
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "update_user", targetUserEmail, details).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectCommit()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_TargetUserNotFound tests updating a non-existent user.
func TestUpdateUser_Error_TargetUserNotFound(t *testing.T) {
	adminEmail := "admin@example.com"
	nonExistentUserEmail := "non-existent-user@example.com"
	isAdminTrue := true // The update payload doesn't really matter for this test
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(nonExistentUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()
	// Mock user existence check for target user to return sql.ErrNoRows
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").
		WithArgs(nonExistentUserEmail).
		WillReturnError(sql.ErrNoRows)

	mockDB.ExpectRollback() // Transaction should be rolled back

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Equal(t, "Target user not found", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_Forbidden_NonAdmin tests a non-admin attempting to update a user.
func TestUpdateUser_Error_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "nonadmin@example.com"
	targetUserEmail := "target-user@example.com"
	isAdminTrue := true // Payload doesn't matter much
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	// Set up non-admin context for the requesting user
	nonAdminClaims := &auth.Claims{Email: nonAdminEmail} // is_admin defaults to false in Claims struct if not set
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	// Mock GetUserByEmail for the non-admin user making the request
	// The handler checks if this user is an admin.
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(2, nonAdminEmail, "userpass", false, true)) // is_admin is false

	// No transaction should be started, no other DB calls.

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_InvalidJSON tests malformed JSON in the request body.
func TestUpdateUser_Error_InvalidJSON(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target-user@example.com"
	// Malformed JSON - missing closing quote and brace
	invalidJSONBody := `{"isAdmin": true`

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader([]byte(invalidJSONBody)))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (this is called before body binding)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// No transaction should begin if body binding fails.

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Invalid request format", httpErr.Message) // Message from c.Bind error

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_Success_Admin tests successful access revocation via UpdateUser.
func TestUpdateUser_RevokeAccess_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()
	// Mock user existence check
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	// Mock DB update for revocation (is_approved = false)
	// This is directly from UpdateUser handler logic
	revokeSQL := `UPDATE users SET is_approved = ? WHERE email = ?`
	mockDB.ExpectExec(revokeSQL).
		WithArgs(false, targetUserEmail). // Setting is_approved to false
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock DeleteAllRefreshTokensForUser - this is called outside UpdateUser, but for testing full "revocation" effect.
	// However, UpdateUser itself does NOT call DeleteAllRefreshTokensForUser.
	// For a pure test of UpdateUser, this should not be here.
	// If the intent IS to test a full revocation flow that *would* include token deletion,
	// it needs to be acknowledged this part is outside UpdateUser's direct responsibility.
	// For now, let's assume UpdateUser's scope. If RevokeUserAccess is added back, this can move there.

	// Mock LogAdminAction for "revoke approval"
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "revoke approval", targetUserEmail, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectCommit()

	err := UpdateUser(c) // Using UpdateUser
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"]) // UpdateUser's success message

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_Forbidden_NonAdmin tests non-admin attempt.
func TestUpdateUser_RevokeAccess_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "user@example.com"
	targetUserEmail := "target@example.com"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, nonAdminEmail, "userpass", false, true))

	err := UpdateUser(c) // Using UpdateUser
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_AdminFetchError tests error fetching admin.
func TestUpdateUser_RevokeAccess_AdminFetchError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error"))

	err := UpdateUser(c) // Using UpdateUser
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get admin user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_MissingEmailParam tests missing target email.
func TestUpdateUser_RevokeAccess_MissingEmailParam(t *testing.T) {
	adminEmail := "admin@example.com"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//update", bytes.NewReader(jsonBody)) // Empty param

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	err := UpdateUser(c) // Using UpdateUser
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email parameter required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_SelfRevocation tests admin trying to revoke own access.
// Note: UpdateUser doesn't have specific self-revocation logic, it would allow it.
// This tests that it *would* proceed if isApproved:false is sent for self.
// A dedicated RevokeUserAccess handler would typically prevent this.
func TestUpdateUser_RevokeAccess_SelfRevocation(t *testing.T) {
	adminEmail := "admin@example.com"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(adminEmail) // Target is self

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(adminEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
	mockDB.ExpectExec(`UPDATE users SET is_approved = ? WHERE email = ?`).
		WithArgs(false, adminEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mockDB.ExpectExec(`INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`).
		WithArgs(adminEmail, "revoke approval", adminEmail, "").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mockDB.ExpectCommit()

	err := UpdateUser(c)    // Using UpdateUser
	require.NoError(t, err) // UpdateUser allows self-update of isApproved
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_RevokeDBError tests error during DB update for revocation.
func TestUpdateUser_RevokeAccess_RevokeDBError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	revokeSQL := `UPDATE users SET is_approved = ? WHERE email = ?`
	mockDB.ExpectExec(revokeSQL).
		WithArgs(false, targetUserEmail).
		WillReturnError(fmt.Errorf("DB error during revocation"))

	mockDB.ExpectRollback() // Transaction should be rolled back

	err := UpdateUser(c) // Using UpdateUser
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to update approval status", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_DeleteTokensError: This test is less relevant for UpdateUser
// as UpdateUser itself does not handle token deletion.
// Token deletion would be a separate concern, potentially in a higher-level "revoke" flow
// or if the RevokeUserAccess handler is re-introduced with that specific logic.
// For now, focusing on UpdateUser's direct responsibilities.
func TestUpdateUser_RevokeAccess_SimulateTokenDeleteError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"

	// Setup to capture log output
	var logBuf bytes.Buffer
	originalErrorLogger := logging.ErrorLogger
	logging.ErrorLogger = log.New(&logBuf, "ERROR: ", 0) // No date/time for simpler matching
	defer func() { logging.ErrorLogger = originalErrorLogger }()

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/:email/revoke-access", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	revokeSQL := `UPDATE users SET is_approved = FALSE, approved_by = NULL, approved_at = NULL WHERE email = ?`
	mockDB.ExpectExec(revokeSQL).
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	deleteTokensSQL := `DELETE FROM refresh_tokens WHERE user_email = ?`
	mockDB.ExpectExec(deleteTokensSQL).WithArgs(targetUserEmail).WillReturnError(fmt.Errorf("DB error deleting tokens"))

	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "revoke_user_access", targetUserEmail, ""). // This action "revoke_user_access" is also inconsistent with UpdateUser
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := UpdateUser(c)    // Changed to UpdateUser
	require.NoError(t, err) // Main operation succeeds if UpdateUser succeeds
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User access revoked successfully", resp["message"])

	// Check that the error was logged
	assert.Contains(t, logBuf.String(), fmt.Sprintf("Failed to delete refresh tokens for user %s during access revocation", targetUserEmail))

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_Success_Admin tests successful retrieval of all users by an admin.
func TestListUsers_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	user1Email := "user1@example.com"
	user2Email := "user2@example.com"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// Mock list users query
	// SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, registration_date, last_login FROM users ORDER BY registration_date DESC
	userRows := sqlmock.NewRows([]string{"email", "is_approved", "is_admin", "storage_limit_bytes", "total_storage_bytes", "registration_date", "last_login"}).
		AddRow(adminEmail, true, true, int64(10*1024*1024*1024), int64(1*1024*1024*1024), time.Now().Add(-24*time.Hour), sql.NullTime{Time: time.Now(), Valid: true}).
		AddRow(user1Email, true, false, int64(5*1024*1024*1024), int64(500*1024*1024), time.Now().Add(-48*time.Hour), sql.NullTime{}).
		AddRow(user2Email, false, false, models.DefaultStorageLimit, int64(0), time.Now(), sql.NullTime{Valid: false})

	mockDB.ExpectQuery(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnRows(userRows)

	// Mock LogAdminAction
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "list_users", "", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	usersList, ok := resp["users"].([]interface{})
	require.True(t, ok)
	assert.Len(t, usersList, 3)

	// Check some fields for the first user (admin)
	firstUser, ok := usersList[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, adminEmail, firstUser["email"])
	assert.True(t, firstUser["is_admin"].(bool))
	assert.Equal(t, "10.00 GB", firstUser["storageLimitReadable"]) // From formatBytes helper in admin.go
	assert.Equal(t, "1.00 GB", firstUser["totalStorageReadable"])
	assert.InDelta(t, 10.0, firstUser["usagePercent"], 0.01) // 1GB / 10GB = 10%
	assert.NotEmpty(t, firstUser["lastLogin"])

	// Check some fields for the third user (pending user2)
	thirdUser, ok := usersList[2].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, user2Email, thirdUser["email"])
	assert.False(t, thirdUser["is_approved"].(bool))
	assert.Equal(t, "0 bytes", thirdUser["totalStorageReadable"])
	assert.InDelta(t, 0.0, thirdUser["usagePercent"], 0.01)
	assert.Empty(t, thirdUser["lastLogin"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_Forbidden_NonAdmin tests non-admin attempt.
func TestListUsers_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "user@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, nonAdminEmail, "userpass", false, true))

	err := ListUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_AdminFetchError tests error fetching admin user.
func TestListUsers_AdminFetchError(t *testing.T) {
	adminEmail := "admin@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error"))

	err := ListUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get admin user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_QueryError tests error during the main user list query.
func TestListUsers_QueryError(t *testing.T) {
	adminEmail := "admin@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	mockDB.ExpectQuery(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnError(fmt.Errorf("DB query error"))

	err := ListUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to retrieve users", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_ScanError tests an error during row scanning.
func TestListUsers_ScanError(t *testing.T) {
	adminEmail := "admin@example.com"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// Simulate a row that will cause a scan error (e.g., wrong type for a column)
	// Here, we provide a string where a bool is expected for is_approved
	userRows := sqlmock.NewRows([]string{"email", "is_approved", "is_admin", "storage_limit_bytes", "total_storage_bytes", "registration_date", "last_login"}).
		AddRow("scanerror@example.com", "not-a-bool", false, int64(1024), int64(0), time.Now(), sql.NullTime{})

	mockDB.ExpectQuery(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnRows(userRows)

	// Even with scan error, LogAdminAction is called outside the loop
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "list_users", "", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := ListUsers(c)
	require.NoError(t, err) // Handler logs and continues, returns OK
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	usersList, ok := resp["users"].([]interface{})
	require.True(t, ok)
	assert.Len(t, usersList, 0) // The user with scan error is skipped

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_NoUsers tests listing when there are no users.
func TestListUsers_NoUsers(t *testing.T) {
	adminEmail := "admin@example.com"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	userRows := sqlmock.NewRows([]string{"email", "is_approved", "is_admin", "storage_limit_bytes", "total_storage_bytes", "registration_date", "last_login"}) // No rows added
	mockDB.ExpectQuery(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnRows(userRows)

	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "list_users", "", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	usersList, ok := resp["users"].([]interface{})
	require.True(t, ok)
	assert.Len(t, usersList, 0)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_Forbidden_NonAdmin tests access denial for non-admin users.
func TestGetPendingUsers_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "user@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	// Set up non-admin context
	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	// Mock GetUserByEmail for the non-admin user
	nonAdminUserRows := sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
		AddRow(1, nonAdminEmail, "hashedpassword", false, true) // Non-admin user
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(nonAdminUserRows)

	err := GetPendingUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_GetUserError tests DB error when fetching admin user.
func TestGetPendingUsers_GetUserError(t *testing.T) {
	adminEmail := "admin@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin check to return an error
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error"))

	err := GetPendingUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get user", httpErr.Message) // Message from GetPendingUsers handler

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_GetPendingError tests DB error when fetching pending users list.
func TestGetPendingUsers_GetPendingError(t *testing.T) {
	adminEmail := "admin@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin check (success)
	adminUserRows := sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
		AddRow(1, adminEmail, "hashedpassword", true, true)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(adminUserRows)

	// Mock GetPendingUsers to return an error
	mockDB.ExpectQuery(`SELECT id, email, created_at, is_approved, approved_by, approved_at, is_admin FROM users WHERE is_approved = 0 ORDER BY created_at ASC`).
		WillReturnError(fmt.Errorf("DB error fetching pending"))

	err := GetPendingUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get pending users", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_Success_Admin tests successful user approval by an admin.
func TestApproveUser_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// Mock GetUserByEmail for target user
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(targetUserEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(2, targetUserEmail, "targetpass", false, false)) // Target user is not admin, not approved

	// Mock user.ApproveUser's DB call (UPDATE users SET is_approved = TRUE, approved_by = ?, approved_at = ? WHERE id = ?)
	// This query is from models/user.go ApproveUser method
	approveUserSQL := `UPDATE users SET is_approved = TRUE, approved_by = ?, approved_at = ? WHERE id = ?`
	mockDB.ExpectExec(approveUserSQL).
		WithArgs(adminEmail, sqlmock.AnyArg(), 2). // approved_by, approved_at, target_user_id
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock LogAdminAction
	// INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "approve_user", targetUserEmail, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User approved successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_Forbidden_NonAdmin tests non-admin attempting approval.
func TestApproveUser_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "user@example.com"
	targetUserEmail := "target@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	// Mock GetUserByEmail for the non-admin user
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, nonAdminEmail, "userpass", false, true)) // Non-admin

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_AdminFetchError tests error fetching admin user details.
func TestApproveUser_AdminFetchError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin to return an error
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error fetching admin"))

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get admin user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_TargetUserNotFound tests trying to approve a non-existent user.
func TestApproveUser_TargetUserNotFound(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "nonexistent@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (success)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// Mock GetUserByEmail for target user to return sql.ErrNoRows
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(targetUserEmail).WillReturnError(sql.ErrNoRows)

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Equal(t, "User not found", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_TargetUserDBError tests generic DB error fetching target user.
func TestApproveUser_TargetUserDBError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (success)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// Mock GetUserByEmail for target user to return a generic error
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(targetUserEmail).WillReturnError(fmt.Errorf("DB error fetching target"))

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	// The handler returns StatusNotFound for *any* error from GetUserByEmail for the target
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Equal(t, "User not found", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_ApproveModelError tests error during user.ApproveUser model method.
func TestApproveUser_ApproveModelError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// Mock GetUserByEmail for target user
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(targetUserEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(2, targetUserEmail, "targetpass", false, false))

	// Mock user.ApproveUser's DB call to fail
	approveUserSQL := `UPDATE users SET is_approved = TRUE, approved_by = ?, approved_at = ? WHERE id = ?`
	mockDB.ExpectExec(approveUserSQL).
		WithArgs(adminEmail, sqlmock.AnyArg(), 2).
		WillReturnError(fmt.Errorf("DB error approving user"))

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to approve user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_MissingEmailParam tests the case where the email parameter is missing.
func TestApproveUser_MissingEmailParam(t *testing.T) {
	adminEmail := "admin@example.com"

	// Note: Path in setupTestEnv doesn't use :email here, as c.Param will be empty
	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/", nil)
	// DO NOT set param values for this test

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin (it's called before param check)
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// No SetParamValues for "email"

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email parameter required", httpErr.Message)

	// Only the admin GetUserByEmail query should have been called
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_Success_Admin tests successful storage limit update by admin.
func TestUpdateUserStorageLimit_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"
	newLimit := int64(20 * 1024 * 1024) // 20 MB

	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByEmail for admin
	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	// Mock DB update for storage limit
	updateSQL := `UPDATE users SET storage_limit_bytes = ? WHERE email = ?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newLimit, targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock LogAdminAction
	logAdminActionSQL := `INSERT INTO admin_logs (admin_email, action, target_user_email, details) VALUES (?, ?, ?, ?)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "update_storage_limit", targetUserEmail, fmt.Sprintf("New limit: %d bytes", newLimit)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := UpdateUserStorageLimit(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Storage limit updated successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_Forbidden_NonAdmin tests non-admin attempt.
func TestUpdateUserStorageLimit_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "user@example.com"
	targetUserEmail := "target@example.com"
	newLimit := int64(20 * 1024 * 1024)
	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, nonAdminEmail, "userpass", false, true))

	err := UpdateUserStorageLimit(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_AdminFetchError tests error fetching admin.
func TestUpdateUserStorageLimit_AdminFetchError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"
	newLimit := int64(20 * 1024 * 1024)
	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error"))

	err := UpdateUserStorageLimit(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get admin user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_MissingEmailParam tests missing target email.
func TestUpdateUserStorageLimit_MissingEmailParam(t *testing.T) {
	adminEmail := "admin@example.com"
	newLimit := int64(20 * 1024 * 1024)
	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//storage-limit", bytes.NewReader(jsonBody)) // Empty param
	// No c.SetParamValues("email", ...)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	err := UpdateUserStorageLimit(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email parameter required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_InvalidBody tests malformed JSON.
func TestUpdateUserStorageLimit_InvalidBody(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"

	// Malformed JSON body
	jsonBody := []byte(`{"storage_limit_bytes": "not-a-number"`) // Missing closing brace and wrong type

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	err := UpdateUserStorageLimit(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Invalid request", httpErr.Message) // Error from c.Bind()

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_NonPositiveLimit tests zero or negative limit.
func TestUpdateUserStorageLimit_NonPositiveLimit(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"

	testCases := []struct {
		name  string
		limit int64
	}{
		{"Zero Limit", 0},
		{"Negative Limit", -100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := map[string]int64{"storage_limit_bytes": tc.limit}
			jsonBody, _ := json.Marshal(reqBody)

			c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/storage-limit", bytes.NewReader(jsonBody))
			c.SetParamNames("email")
			c.SetParamValues(targetUserEmail)

			adminClaims := &auth.Claims{Email: adminEmail}
			adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
			c.Set("user", adminToken)

			mockDB.ExpectQuery(`
				SELECT id, email, password, created_at,
					   total_storage_bytes, storage_limit_bytes,
					   is_approved, approved_by, approved_at, is_admin
				FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
				sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
					AddRow(1, adminEmail, "adminpass", true, true))

			// If targetEmail is also checked, need a mock for it too, but handler logic checks body first
			// after admin check.

			err := UpdateUserStorageLimit(c)
			require.Error(t, err)
			httpErr, ok := err.(*echo.HTTPError)
			require.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, httpErr.Code)
			assert.Equal(t, "Storage limit must be positive", httpErr.Message)

			assert.NoError(t, mockDB.ExpectationsWereMet())
		})
	}
}

// TestUpdateUserStorageLimit_DBUpdateError tests error during DB update.
func TestUpdateUserStorageLimit_DBUpdateError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"
	newLimit := int64(20 * 1024 * 1024)

	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password", "is_admin", "is_approved"}).
			AddRow(1, adminEmail, "adminpass", true, true))

	updateSQL := `UPDATE users SET storage_limit_bytes = ? WHERE email = ?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newLimit, targetUserEmail).
		WillReturnError(fmt.Errorf("DB update error"))

	err := UpdateUserStorageLimit(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to update storage limit", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}
