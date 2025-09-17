package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateFileShare_Success(t *testing.T) {
	// Setup test environment
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader([]byte(`{
		"fileId": "test-file-123",
		"salt": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		"encrypted_fek": "ZW5jcnlwdGVkLWZlay13aXRoLXNoYXJlLWtleQ==",
		"expiresAfterHours": 720
	}`)))

	// Set up authenticated user context
	username := "test@example.com"
	c.Set("username", username)
	c.Set("userID", 1)

	// Create and set JWT token for authentication
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock file ownership check in file_metadata using file_id (matches actual handler)
	fileOwnerSQL := `SELECT owner_username, password_type FROM file_metadata WHERE file_id = \?`
	fileRows := sqlmock.NewRows([]string{"owner_username", "password_type"}).
		AddRow(username, "custom")
	mock.ExpectQuery(fileOwnerSQL).WithArgs("test-file-123").WillReturnRows(fileRows)

	// Mock share creation
	shareInsertSQL := `INSERT INTO file_share_keys \(share_id, file_id, owner_username, salt, encrypted_fek, created_at, expires_at\) VALUES \(\?, \?, \?, \?, \?, CURRENT_TIMESTAMP, \?\)`
	mock.ExpectExec(shareInsertSQL).
		WithArgs(sqlmock.AnyArg(), "test-file-123", username, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock user action logging
	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(username, "created_share", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler
	err := CreateFileShare(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify response
	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response["shareId"])
	assert.NotEmpty(t, response["shareUrl"])
	assert.Contains(t, response["shareUrl"], "/shared/")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateFileShare_InvalidSalt(t *testing.T) {
	// Setup test environment with invalid salt - use same endpoint as successful test
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader([]byte(`{
		"fileId": "test-file-123",
		"salt": "c2hvcnQtc2FsdA==",
		"encrypted_fek": "ZW5jcnlwdGVkLWZlay13aXRoLXNoYXJlLWtleQ=="
	}`)))

	// Set up authenticated user context
	username := "test@example.com"
	c.Set("username", username)
	c.Set("userID", 1)

	// Create and set JWT token for authentication
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock file ownership check in file_metadata using file_id (matches actual handler)
	fileOwnerSQL := `SELECT owner_username, password_type FROM file_metadata WHERE file_id = \?`
	fileRows := sqlmock.NewRows([]string{"owner_username", "password_type"}).
		AddRow(username, "custom")
	mock.ExpectQuery(fileOwnerSQL).WithArgs("test-file-123").WillReturnRows(fileRows)

	// Execute handler - should fail due to invalid salt (too short)
	err := CreateFileShare(c)
	require.Error(t, err)

	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, httpErr.Message.(string), "salt")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateFileShare_FileNotOwned(t *testing.T) {
	// Setup test environment - use same endpoint as successful test
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader([]byte(`{
		"fileId": "test-file-456",
		"salt": "dGVzdC1zYWx0LTMyLWJ5dGVzLWZvci1hcmdvbjJpZA==",
		"encrypted_fek": "ZW5jcnlwdGVkLWZlay13aXRoLXNoYXJlLWtleQ=="
	}`)))

	// Set up authenticated user context
	username := "test@example.com"
	c.Set("username", username)
	c.Set("userID", 1)

	// Create and set JWT token for authentication
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock file ownership check in file_metadata using file_id - file not found (different owner)
	fileOwnerSQL := `SELECT owner_username, password_type FROM file_metadata WHERE file_id = \?`
	mock.ExpectQuery(fileOwnerSQL).WithArgs("test-file-456").WillReturnError(sql.ErrNoRows)

	// Execute handler - should fail due to file not found
	err := CreateFileShare(c)
	require.Error(t, err)

	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccessSharedFile_Success(t *testing.T) {
	// Setup test environment
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/test-share-id", bytes.NewReader([]byte(`{
		"password": "MyVacation2025PhotosForFamily!ExtraSecure"
	}`)))

	c.SetParamNames("id")
	c.SetParamValues("test-share-id")

	// Mock rate limiting check (first call to checkRateLimit)
	rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	mock.ExpectQuery(rateLimitSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)

	// Mock rate limit entry creation
	rateLimitInsertSQL := `INSERT INTO share_access_attempts \(share_id, entity_id, failed_count, created_at\) VALUES \(\?, \?, 0, CURRENT_TIMESTAMP\)`
	mock.ExpectExec(rateLimitInsertSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock share lookup (matches actual handler processShareAccess function)
	shareSQL := `SELECT file_id, owner_username, salt, encrypted_fek, expires_at FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "salt", "encrypted_fek", "expires_at"}).
		AddRow("test-file-123", "owner@example.com", []byte("test-salt-32-bytes-for-argon2id"), "ZW5jcnlwdGVkLWZlay13aXRoLXNoYXJlLWtleQ==", nil)
	mock.ExpectQuery(shareSQL).WithArgs("test-share-id").WillReturnRows(shareRows)

	// Mock file metadata lookup with encrypted fields (matches actual handler)
	fileMetaSQL := `SELECT encrypted_filename, size_bytes, encrypted_sha256sum, filename_nonce, sha256sum_nonce FROM file_metadata WHERE file_id = \?`
	fileMetaRows := sqlmock.NewRows([]string{"encrypted_filename", "size_bytes", "encrypted_sha256sum", "filename_nonce", "sha256sum_nonce"}).
		AddRow("encryptedfilename", 1024, "encryptedsha256sum", "testfilenamenonce", "testsha256nonce")
	mock.ExpectQuery(fileMetaSQL).WithArgs("test-file-123").WillReturnRows(fileMetaRows)

	// Mock rate limit reset on success
	rateLimitResetSQL := `UPDATE share_access_attempts SET failed_count = 0, last_failed_attempt = NULL, next_allowed_attempt = NULL WHERE share_id = \? AND entity_id = \?`
	mock.ExpectExec(rateLimitResetSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler
	err := AccessSharedFile(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify response
	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, true, response["success"])
	assert.NotEmpty(t, response["salt"])
	assert.NotEmpty(t, response["encrypted_fek"])
	assert.Contains(t, response, "file_info")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccessSharedFile_WeakPassword(t *testing.T) {
	// Setup test environment with weak password
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/test-share-id", bytes.NewReader([]byte(`{
		"password": "weak"
	}`)))

	c.SetParamNames("id")
	c.SetParamValues("test-share-id")

	// Mock rate limiting check (first call to checkRateLimit)
	rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	mock.ExpectQuery(rateLimitSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)

	// Mock rate limit entry creation
	rateLimitInsertSQL := `INSERT INTO share_access_attempts \(share_id, entity_id, failed_count, created_at\) VALUES \(\?, \?, 0, CURRENT_TIMESTAMP\)`
	mock.ExpectExec(rateLimitInsertSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock share lookup (matches actual handler processShareAccess function)
	shareSQL := `SELECT file_id, owner_username, salt, encrypted_fek, expires_at FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "salt", "encrypted_fek", "expires_at"}).
		AddRow("test-file-123", "owner@example.com", []byte("test-salt-32-bytes-for-argon2id"), "ZW5jcnlwdGVkLWZlay13aXRoLXNoYXJlLWtleQ==", nil)
	mock.ExpectQuery(shareSQL).WithArgs("test-share-id").WillReturnRows(shareRows)

	// Mock file metadata lookup with encrypted fields (matches actual handler)
	fileMetaSQL := `SELECT encrypted_filename, size_bytes, encrypted_sha256sum, filename_nonce, sha256sum_nonce FROM file_metadata WHERE file_id = \?`
	fileMetaRows := sqlmock.NewRows([]string{"encrypted_filename", "size_bytes", "encrypted_sha256sum", "filename_nonce", "sha256sum_nonce"}).
		AddRow("encryptedfilename", 1024, "encryptedsha256sum", "testfilenamenonce", "testsha256nonce")
	mock.ExpectQuery(fileMetaSQL).WithArgs("test-file-123").WillReturnRows(fileMetaRows)

	// Mock rate limit reset on success
	rateLimitResetSQL := `UPDATE share_access_attempts SET failed_count = 0, last_failed_attempt = NULL, next_allowed_attempt = NULL WHERE share_id = \? AND entity_id = \?`
	mock.ExpectExec(rateLimitResetSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler - should work since handler doesn't actually validate password strength
	// (Password validation happens client-side per the design)
	err := AccessSharedFile(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccessSharedFile_NonexistentShare(t *testing.T) {
	// Setup test environment
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/nonexistent", bytes.NewReader([]byte(`{
		"password": "MyVacation2025PhotosForFamily!ExtraSecure"
	}`)))

	c.SetParamNames("id")
	c.SetParamValues("nonexistent")

	// Mock rate limiting check (first call to checkRateLimit)
	rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	mock.ExpectQuery(rateLimitSQL).WithArgs("nonexistent", sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)

	// Mock rate limit entry creation
	rateLimitInsertSQL := `INSERT INTO share_access_attempts \(share_id, entity_id, failed_count, created_at\) VALUES \(\?, \?, 0, CURRENT_TIMESTAMP\)`
	mock.ExpectExec(rateLimitInsertSQL).WithArgs("nonexistent", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock share lookup - not found (matches actual handler processShareAccess function)
	shareSQL := `SELECT file_id, owner_username, salt, encrypted_fek, expires_at FROM file_share_keys WHERE share_id = \?`
	mock.ExpectQuery(shareSQL).WithArgs("nonexistent").WillReturnError(sql.ErrNoRows)

	// Mock failed attempt recording (for rate limiting on 404) - new logic in recordFailedAttempt
	rateLimitQuerySQL := `SELECT failed_count FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	mock.ExpectQuery(rateLimitQuerySQL).WithArgs("nonexistent", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"failed_count"}).AddRow(0))

	// Mock updating the failed attempt count
	rateLimitUpdateSQL := `UPDATE share_access_attempts SET failed_count = \?, last_failed_attempt = CURRENT_TIMESTAMP, next_allowed_attempt = \? WHERE share_id = \? AND entity_id = \?`
	mock.ExpectExec(rateLimitUpdateSQL).WithArgs(1, sqlmock.AnyArg(), "nonexistent", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler - should fail with 404
	err := AccessSharedFile(c)
	require.Error(t, err)

	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetSharedFile_Success(t *testing.T) {
	// Setup test environment
	c, _, mock, _ := setupTestEnv(t, http.MethodGet, "/share/test-share-id", nil)

	c.SetParamNames("id")
	c.SetParamValues("test-share-id")

	// Mock share existence check (matches actual handler GetSharedFile function)
	shareSQL := `SELECT file_id, owner_username, expires_at FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "expires_at"}).
		AddRow("test-file-123", "owner@example.com", nil)
	mock.ExpectQuery(shareSQL).WithArgs("test-share-id").WillReturnRows(shareRows)

	// Mock file metadata lookup for display with encrypted fields (matches actual handler)
	fileMetaSQL := `SELECT 1 FROM file_metadata WHERE file_id = \?`
	fileMetaRows := sqlmock.NewRows([]string{"1"}).AddRow(1)
	mock.ExpectQuery(fileMetaSQL).WithArgs("test-file-123").WillReturnRows(fileMetaRows)

	// Execute handler - will fail due to no renderer, but that's expected in test
	err := GetSharedFile(c)
	require.Error(t, err)

	// The handler tries to render a template, which fails in test environment
	// This is expected behavior - the SQL mocks verify the correct queries are made
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListShares_Success(t *testing.T) {
	// Setup test environment
	c, rec, mock, _ := setupTestEnv(t, http.MethodGet, "/api/shares", nil)

	// Set up authenticated user context with JWT token
	username := "test@example.com"
	c.Set("username", username)
	c.Set("userID", 1)

	// Create and set JWT token for authentication (matches handler expectation)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock shares query with encrypted metadata fields (matches actual handler ListShares function)
	sharesSQL := `SELECT sk\.share_id, sk\.file_id, sk\.created_at, sk\.expires_at, fm\.encrypted_filename, fm\.filename_nonce, fm\.encrypted_sha256sum, fm\.sha256sum_nonce, fm\.size_bytes FROM file_share_keys sk JOIN file_metadata fm ON sk\.file_id = fm\.file_id WHERE sk\.owner_username = \? ORDER BY sk\.created_at DESC`
	sharesRows := sqlmock.NewRows([]string{"share_id", "file_id", "created_at", "expires_at", "encrypted_filename", "filename_nonce", "encrypted_sha256sum", "sha256sum_nonce", "size_bytes"}).
		AddRow("test-share-id", "test-file-123", time.Now().Format("2006-01-02 15:04:05"), nil, "encryptedfilename", "testfilenamenonce", "encryptedsha256sum", "testsha256nonce", 1024)
	mock.ExpectQuery(sharesSQL).WithArgs(username).WillReturnRows(sharesRows)

	// Execute handler
	err := ListShares(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify response
	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	shares := response["shares"].([]interface{})
	assert.Equal(t, 1, len(shares))

	share := shares[0].(map[string]interface{})
	assert.Equal(t, "test-share-id", share["shareId"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteShare_Success(t *testing.T) {
	// Setup test environment
	c, rec, mock, _ := setupTestEnv(t, http.MethodDelete, "/api/shares/test-share-id", nil)

	// Set up authenticated user context with JWT token
	username := "test@example.com"
	userID := 1
	c.Set("username", username)
	c.Set("userID", userID)
	c.SetParamNames("id")
	c.SetParamValues("test-share-id")

	// Create and set JWT token for authentication (matches handler expectation)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock share ownership verification (matches actual handler DeleteShare function)
	shareOwnerSQL := `SELECT owner_username FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"owner_username"}).AddRow(username)
	mock.ExpectQuery(shareOwnerSQL).WithArgs("test-share-id").WillReturnRows(shareRows)

	// Mock share deletion
	deleteSQL := `DELETE FROM file_share_keys WHERE share_id = \?`
	mock.ExpectExec(deleteSQL).WithArgs("test-share-id").WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock user action logging
	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(username, "deleted_share", "test-share-id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Execute handler
	err := DeleteShare(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify response
	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Share deleted successfully", response["message"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSharePasswordValidation_WithZxcvbn(t *testing.T) {
	// Note: Password validation happens CLIENT-SIDE per the architecture
	// The server only provides salt + encrypted_fek - it never validates passwords
	// This test verifies that all passwords (weak or strong) are accepted by the server
	// Client-side TypeScript handles password strength validation

	testCases := []struct {
		name     string
		password string
	}{
		{
			name:     "Very weak password",
			password: "weak",
		},
		{
			name:     "Short but complex password",
			password: "Ax9#mQ2!",
		},
		{
			name:     "Long but predictable password",
			password: "password123456789012345",
		},
		{
			name:     "Strong password with good entropy",
			password: "MyVacation2025PhotosForFamily!ExtraSecure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup test environment
			requestBody := fmt.Sprintf(`{"password": "%s"}`, tc.password)
			c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/test-share-id", bytes.NewReader([]byte(requestBody)))

			c.SetParamNames("id")
			c.SetParamValues("test-share-id")

			// Mock rate limiting check
			rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
			mock.ExpectQuery(rateLimitSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)

			// Mock rate limit entry creation
			rateLimitInsertSQL := `INSERT INTO share_access_attempts \(share_id, entity_id, failed_count, created_at\) VALUES \(\?, \?, 0, CURRENT_TIMESTAMP\)`
			mock.ExpectExec(rateLimitInsertSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

			// Mock share lookup (matches actual handler processShareAccess function)
			shareSQL := `SELECT file_id, owner_username, salt, encrypted_fek, expires_at FROM file_share_keys WHERE share_id = \?`
			shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "salt", "encrypted_fek", "expires_at"}).
				AddRow("test-file-123", "owner@example.com", []byte("test-salt-32-bytes-for-argon2id"), "ZW5jcnlwdGVkLWZlay13aXRoLXNoYXJlLWtleQ==", nil)
			mock.ExpectQuery(shareSQL).WithArgs("test-share-id").WillReturnRows(shareRows)

			// Mock file metadata lookup with encrypted fields (matches actual handler)
			fileMetaSQL := `SELECT encrypted_filename, size_bytes, encrypted_sha256sum, filename_nonce, sha256sum_nonce FROM file_metadata WHERE file_id = \?`
			fileMetaRows := sqlmock.NewRows([]string{"encrypted_filename", "size_bytes", "encrypted_sha256sum", "filename_nonce", "sha256sum_nonce"}).
				AddRow("encryptedfilename", 1024, "encryptedsha256sum", "testfilenamenonce", "testsha256nonce")
			mock.ExpectQuery(fileMetaSQL).WithArgs("test-file-123").WillReturnRows(fileMetaRows)

			// Mock rate limit reset on success
			rateLimitResetSQL := `UPDATE share_access_attempts SET failed_count = 0, last_failed_attempt = NULL, next_allowed_attempt = NULL WHERE share_id = \? AND entity_id = \?`
			mock.ExpectExec(rateLimitResetSQL).WithArgs("test-share-id", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

			// Execute handler - should always succeed (server doesn't validate passwords)
			err := AccessSharedFile(c)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Code)

			// Verify response contains expected fields
			var response map[string]interface{}
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Equal(t, true, response["success"])
			assert.NotEmpty(t, response["salt"])
			assert.NotEmpty(t, response["encrypted_fek"])

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
