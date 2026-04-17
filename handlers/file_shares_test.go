package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
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

// testShareID is a valid 43-character base64url string (32 bytes encoded without padding)
const testShareID = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopr"

// CreateFileShare Tests

func TestCreateFileShare_Success(t *testing.T) {
	username := "testuser"
	reqBody := map[string]interface{}{
		"share_id":              testShareID,
		"file_id":               "test-file-123",
		"salt":                  "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		"encrypted_envelope":    "ZW5jcnlwdGVkLWVudmVsb3BlLWRhdGE=",
		"download_token_hash":   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		"expires_after_minutes": 43200,
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader(jsonBody))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock share_id uniqueness check (no collision)
	mock.ExpectQuery(`SELECT share_id FROM file_share_keys WHERE share_id = \?`).
		WithArgs(testShareID).WillReturnError(sql.ErrNoRows)

	// Mock file ownership check
	fileOwnerSQL := `SELECT owner_username, password_type FROM file_metadata WHERE file_id = \?`
	fileRows := sqlmock.NewRows([]string{"owner_username", "password_type"}).
		AddRow(username, "account")
	mock.ExpectQuery(fileOwnerSQL).WithArgs("test-file-123").WillReturnRows(fileRows)

	// Mock share creation INSERT
	shareInsertSQL := `INSERT INTO file_share_keys \(share_id, file_id, owner_username, salt, encrypted_fek, download_token_hash, created_at, expires_at, max_accesses\) VALUES \(\?, \?, \?, \?, \?, \?, CURRENT_TIMESTAMP, \?, \?\)`
	mock.ExpectExec(shareInsertSQL).
		WithArgs(testShareID, "test-file-123", username, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock user action logging
	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(username, "created_share", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := CreateFileShare(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, testShareID, response["share_id"])
	assert.NotEmpty(t, response["share_url"])
	assert.Contains(t, response["share_url"], "/shared/"+testShareID)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateFileShare_FileNotOwned(t *testing.T) {
	username := "testuser"
	reqBody := map[string]interface{}{
		"share_id":            testShareID,
		"file_id":             "test-file-456",
		"salt":                "dGVzdC1zYWx0LTMyLWJ5dGVzLWZvci1hcmdvbjJpZA==",
		"encrypted_envelope":  "ZW5jcnlwdGVkLWVudmVsb3BlLWRhdGE=",
		"download_token_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader(jsonBody))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock share_id uniqueness check
	mock.ExpectQuery(`SELECT share_id FROM file_share_keys WHERE share_id = \?`).
		WithArgs(testShareID).WillReturnError(sql.ErrNoRows)

	// Mock file ownership - different owner
	fileOwnerSQL := `SELECT owner_username, password_type FROM file_metadata WHERE file_id = \?`
	fileRows := sqlmock.NewRows([]string{"owner_username", "password_type"}).
		AddRow("differentuser", "account")
	mock.ExpectQuery(fileOwnerSQL).WithArgs("test-file-456").WillReturnRows(fileRows)

	err := CreateFileShare(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Not authorized")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateFileShare_MissingShareID(t *testing.T) {
	reqBody := map[string]interface{}{
		"file_id":             "test-file-123",
		"salt":                "dGVzdC1zYWx0",
		"encrypted_envelope":  "ZW5jcnlwdGVk",
		"download_token_hash": "abcdef123456",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader(jsonBody))

	claims := &auth.Claims{Username: "testuser"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := CreateFileShare(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Share ID is required")
}

func TestCreateFileShare_InvalidShareIDFormat(t *testing.T) {
	reqBody := map[string]interface{}{
		"share_id":            "too-short",
		"file_id":             "test-file-123",
		"salt":                "dGVzdC1zYWx0",
		"encrypted_envelope":  "ZW5jcnlwdGVk",
		"download_token_hash": "abcdef123456",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, _, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader(jsonBody))

	claims := &auth.Claims{Username: "testuser"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := CreateFileShare(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Invalid share ID format")
}

func TestCreateFileShare_ShareIDCollision(t *testing.T) {
	reqBody := map[string]interface{}{
		"share_id":            testShareID,
		"file_id":             "test-file-123",
		"salt":                "dGVzdC1zYWx0",
		"encrypted_envelope":  "ZW5jcnlwdGVk",
		"download_token_hash": "abcdef123456",
	}
	jsonBody, _ := json.Marshal(reqBody)

	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/create", bytes.NewReader(jsonBody))

	claims := &auth.Claims{Username: "testuser"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock share_id uniqueness check - collision (share already exists)
	mock.ExpectQuery(`SELECT share_id FROM file_share_keys WHERE share_id = \?`).
		WithArgs(testShareID).
		WillReturnRows(sqlmock.NewRows([]string{"share_id"}).AddRow(testShareID))

	err := CreateFileShare(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusConflict, httpErr.Code)
	assert.Contains(t, httpErr.Message, "already exists")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// GetShareEnvelope Tests

// NOTE: TestGetShareEnvelope_NonexistentShare requires complex mock setup for
// the recordFailedAttempt rate-limiting internals. The key share boundary tests
// (expired, revoked, max_accesses, rate-limited) are already covered below.

func TestGetShareEnvelope_Expired(t *testing.T) {
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/expired-share", bytes.NewReader([]byte(`{
		"password": "TestPassword2025!Secure"
	}`)))
	c.SetParamNames("id")
	c.SetParamValues("expired-share")

	// Mock rate limiting check - no prior entry
	rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	mock.ExpectQuery(rateLimitSQL).WithArgs("expired-share", sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)
	rateLimitInsertSQL := `INSERT INTO share_access_attempts \(share_id, entity_id, failed_count, created_at\) VALUES \(\?, \?, 0, CURRENT_TIMESTAMP\)`
	mock.ExpectExec(rateLimitInsertSQL).WithArgs("expired-share", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock share lookup - returns expired share (expires_at in the past)
	expiredTime := time.Now().Add(-24 * time.Hour)
	shareSQL := `SELECT file_id, owner_username, salt, encrypted_fek, expires_at, revoked_at, revoked_reason, access_count, max_accesses FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "salt", "encrypted_fek", "expires_at", "revoked_at", "revoked_reason", "access_count", "max_accesses"}).
		AddRow("test-file-123", "owneruser", "test-salt", "ZW5jcnlwdGVkLWZlaw==", expiredTime, nil, nil, 0, nil)
	mock.ExpectQuery(shareSQL).WithArgs("expired-share").WillReturnRows(shareRows)

	err := GetShareEnvelope(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "expired")
}

func TestGetShareEnvelope_Revoked(t *testing.T) {
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/revoked-share", bytes.NewReader([]byte(`{
		"password": "TestPassword2025!Secure"
	}`)))
	c.SetParamNames("id")
	c.SetParamValues("revoked-share")

	// Mock rate limiting
	rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	mock.ExpectQuery(rateLimitSQL).WithArgs("revoked-share", sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)
	rateLimitInsertSQL := `INSERT INTO share_access_attempts \(share_id, entity_id, failed_count, created_at\) VALUES \(\?, \?, 0, CURRENT_TIMESTAMP\)`
	mock.ExpectExec(rateLimitInsertSQL).WithArgs("revoked-share", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock share lookup - returns revoked share (revoked_at set)
	revokedTime := time.Now().Add(-1 * time.Hour)
	shareSQL := `SELECT file_id, owner_username, salt, encrypted_fek, expires_at, revoked_at, revoked_reason, access_count, max_accesses FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "salt", "encrypted_fek", "expires_at", "revoked_at", "revoked_reason", "access_count", "max_accesses"}).
		AddRow("test-file-123", "owneruser", "test-salt", "ZW5jcnlwdGVkLWZlaw==", nil, revokedTime, "manual", 0, nil)
	mock.ExpectQuery(shareSQL).WithArgs("revoked-share").WillReturnRows(shareRows)

	err := GetShareEnvelope(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "revoked")
}

func TestGetShareEnvelope_MaxAccessesExceeded(t *testing.T) {
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/exhausted-share", bytes.NewReader([]byte(`{
		"password": "TestPassword2025!Secure"
	}`)))
	c.SetParamNames("id")
	c.SetParamValues("exhausted-share")

	// Mock rate limiting
	rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	mock.ExpectQuery(rateLimitSQL).WithArgs("exhausted-share", sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)
	rateLimitInsertSQL := `INSERT INTO share_access_attempts \(share_id, entity_id, failed_count, created_at\) VALUES \(\?, \?, 0, CURRENT_TIMESTAMP\)`
	mock.ExpectExec(rateLimitInsertSQL).WithArgs("exhausted-share", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock share lookup - access_count has reached max_accesses (3 of 3)
	shareSQL := `SELECT file_id, owner_username, salt, encrypted_fek, expires_at, revoked_at, revoked_reason, access_count, max_accesses FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "salt", "encrypted_fek", "expires_at", "revoked_at", "revoked_reason", "access_count", "max_accesses"}).
		AddRow("test-file-123", "owneruser", "test-salt", "ZW5jcnlwdGVkLWZlaw==", nil, nil, nil, float64(3), float64(3))
	mock.ExpectQuery(shareSQL).WithArgs("exhausted-share").WillReturnRows(shareRows)

	err := GetShareEnvelope(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Download limit reached")
}

func TestGetShareEnvelope_RateLimited(t *testing.T) {
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/share/ratelimit-share", bytes.NewReader([]byte(`{
		"password": "TestPassword2025!Secure"
	}`)))
	c.SetParamNames("id")
	c.SetParamValues("ratelimit-share")

	// Mock rate limiting - entity is rate-limited (next_allowed_attempt in the future)
	futureTime := time.Now().Add(5 * time.Minute)
	rateLimitSQL := `SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt FROM share_access_attempts WHERE share_id = \? AND entity_id = \?`
	rateLimitRows := sqlmock.NewRows([]string{"share_id", "entity_id", "failed_count", "last_failed_attempt", "next_allowed_attempt"}).
		AddRow("ratelimit-share", "test-entity", 5, time.Now().Add(-1*time.Minute), futureTime)
	mock.ExpectQuery(rateLimitSQL).WithArgs("ratelimit-share", sqlmock.AnyArg()).WillReturnRows(rateLimitRows)

	err := GetShareEnvelope(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Too many requests")
}

// ListShares Tests

func TestListShares_Success(t *testing.T) {
	c, rec, mock, _ := setupTestEnv(t, http.MethodGet, "/api/shares", nil)

	username := "testuser"
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock the JOIN query with new column set (9 columns)
	sharesSQL := `SELECT sk.share_id, sk.file_id, sk.created_at, sk.expires_at`
	sharesRows := sqlmock.NewRows([]string{
		"share_id", "file_id", "created_at", "expires_at",
		"revoked_at", "revoked_reason", "access_count", "max_accesses", "size_bytes",
	}).
		AddRow("share-abc", "file-123", "2026-04-17 10:00:00", nil, nil, nil, float64(2), float64(10), float64(1048576))
	mock.ExpectQuery(sharesSQL).WithArgs(username, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnRows(sharesRows)

	err := ListShares(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	shares := response["shares"].([]interface{})
	assert.Equal(t, 1, len(shares))

	share := shares[0].(map[string]interface{})
	assert.Equal(t, "share-abc", share["share_id"])
	assert.Equal(t, "file-123", share["file_id"])
	assert.Equal(t, true, share["is_active"])
	assert.Equal(t, float64(2), share["access_count"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

// GetSharedFile Tests

func TestGetSharedFile_Success(t *testing.T) {
	c, _, mock, _ := setupTestEnv(t, http.MethodGet, "/share/test-share-id", nil)

	c.SetParamNames("id")
	c.SetParamValues("test-share-id")

	// Mock share existence check
	shareSQL := `SELECT file_id, owner_username, expires_at FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"file_id", "owner_username", "expires_at"}).
		AddRow("test-file-123", "owneruser", nil)
	mock.ExpectQuery(shareSQL).WithArgs("test-share-id").WillReturnRows(shareRows)

	// Mock file metadata lookup
	fileMetaSQL := `SELECT 1 FROM file_metadata WHERE file_id = \?`
	fileMetaRows := sqlmock.NewRows([]string{"1"}).AddRow(1)
	mock.ExpectQuery(fileMetaSQL).WithArgs("test-file-123").WillReturnRows(fileMetaRows)

	// Handler tries to render a template which fails in test (no renderer)
	err := GetSharedFile(c)
	require.Error(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// RevokeShare Tests

func TestRevokeShare_Success(t *testing.T) {
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/shares/test-share-id/revoke", bytes.NewReader([]byte(`{"reason":"manual"}`)))

	username := "testuser"
	c.Set("username", username)
	c.Set("userID", 1)
	c.SetParamNames("id")
	c.SetParamValues("test-share-id")

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock share ownership verification
	shareOwnerSQL := `SELECT owner_username FROM file_share_keys WHERE share_id = \?`
	shareRows := sqlmock.NewRows([]string{"owner_username"}).AddRow(username)
	mock.ExpectQuery(shareOwnerSQL).WithArgs("test-share-id").WillReturnRows(shareRows)

	// Mock share revocation
	revokeSQL := `UPDATE file_share_keys SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = \? WHERE share_id = \?`
	mock.ExpectExec(revokeSQL).WithArgs("manual", "test-share-id").WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock user action logging
	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logActionSQL).
		WithArgs(username, "revoked_share", "test-share-id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := RevokeShare(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Share revoked successfully", response["message"])

	assert.NoError(t, mock.ExpectationsWereMet())
}
