package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/models"
)

// Test DeleteFile

// TestDeleteFile_Success tests successful file deletion
func TestDeleteFile_Success(t *testing.T) {
	username := "user-delete"
	fileID := "file-to-delete-123"
	fileSize := int64(1024)
	initialStorage := int64(5000)

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/files/:fileId", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	// Query matches the direct SQL in DeleteFile handler
	ownerCheckSQL := `SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE file_id = \?`
	storageID := "test-storage-id-456"
	ownerRows := sqlmock.NewRows([]string{"owner_username", "storage_id", "size_bytes"}).AddRow(username, storageID, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(fileID).WillReturnRows(ownerRows)

	// DeleteFile removes from storage first, then deletes metadata
	mockStorage.On("RemoveObject", mock.Anything, storageID, mock.AnythingOfType("storage.RemoveObjectOptions")).Return(nil).Once()

	deleteMetaSQL := `DELETE FROM file_metadata WHERE file_id = \?`
	mockDB.ExpectExec(deleteMetaSQL).WithArgs(fileID).WillReturnResult(sqlmock.NewResult(0, 1))

	// Query matches models.GetUserByUsername function
	getUserSQL := `SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	userID := int64(1)
	userRows := sqlmock.NewRows([]string{
		"id", "username", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, username, time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	updateStorageSQL := `UPDATE users SET total_storage_bytes = \? WHERE id = \?`
	expectedStorage := initialStorage - fileSize
	mockDB.ExpectExec(updateStorageSQL).WithArgs(expectedStorage, userID).WillReturnResult(sqlmock.NewResult(0, 1))
	mockDB.ExpectCommit()

	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mockDB.ExpectExec(logActionSQL).WithArgs(username, "deleted", fileID).WillReturnResult(sqlmock.NewResult(1, 1))

	err := DeleteFile(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "File deleted successfully", resp["message"])
	storageInfo, ok := resp["storage"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(expectedStorage), storageInfo["total_bytes"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
	mockStorage.AssertExpectations(t)
}

// TestDeleteFile_NotFound tests deleting a file that doesn't exist
func TestDeleteFile_NotFound(t *testing.T) {
	username := "user-delete"
	fileID := "non-existent-file-123"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/files/:fileId", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	ownerCheckSQL := `SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE file_id = \?`
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(fileID).WillReturnError(fmt.Errorf("sql: no rows in result set")) // Simulate sql.ErrNoRows

	mockDB.ExpectRollback()

	err := DeleteFile(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Equal(t, "File not found", httpErr.Message.(string))

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteFile_NotOwner tests deleting a file owned by someone else
func TestDeleteFile_NotOwner(t *testing.T) {
	requestingUsername := "user-trying-delete"
	ownerUsername := "actual-owner"
	fileID := "someone-elses-file-456"
	fileSize := int64(512)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/files/:fileId", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: requestingUsername}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	ownerCheckSQL := `SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE file_id = \?`
	storageID := "test-storage-id-789"
	ownerRows := sqlmock.NewRows([]string{"owner_username", "storage_id", "size_bytes"}).AddRow(ownerUsername, storageID, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(fileID).WillReturnRows(ownerRows)
	mockDB.ExpectRollback()

	err := DeleteFile(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Not authorized to delete this file", httpErr.Message.(string))

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteFile_StorageError tests failure during storage object removal
func TestDeleteFile_StorageError(t *testing.T) {
	username := "user-delete"
	fileID := "file-stor-err-789"
	fileSize := int64(1024)

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/files/:fileId", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	ownerCheckSQL := `SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE file_id = \?`
	storageID := "test-storage-id-999"
	ownerRows := sqlmock.NewRows([]string{"owner_username", "storage_id", "size_bytes"}).AddRow(username, storageID, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(fileID).WillReturnRows(ownerRows)

	storageError := fmt.Errorf("simulated storage layer error")
	mockStorage.On("RemoveObject", mock.Anything, storageID, mock.AnythingOfType("storage.RemoveObjectOptions")).Return(storageError).Once()
	mockDB.ExpectRollback()

	err := DeleteFile(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to delete file from storage", httpErr.Message.(string))

	assert.NoError(t, mockDB.ExpectationsWereMet())
	mockStorage.AssertExpectations(t)
}

// TestListRecentFileMetadata tests the GET /api/files/metadata endpoint
func TestListRecentFileMetadata(t *testing.T) {
	username := "testuser"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files/metadata", nil)
	c.SetParamNames("limit", "offset")

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Setup mock DB response for models.GetRecentFileMetadataByOwner
	query := `SELECT file_id, password_type, filename_nonce, encrypted_filename,
		       sha256sum_nonce, encrypted_sha256sum, size_bytes, upload_date
		FROM file_metadata
		WHERE owner_username = \?
		ORDER BY upload_date DESC
		LIMIT \? OFFSET \?`

	rows := sqlmock.NewRows([]string{
		"file_id", "password_type", "filename_nonce", "encrypted_filename",
		"sha256sum_nonce", "encrypted_sha256sum", "size_bytes", "upload_date",
	}).AddRow(
		"file-1", "account", "nonce1", "encName1", "shaNonce1", "encSha1", 1024, "2024-01-01 12:00:00",
	)

	mockDB.ExpectQuery(query).WithArgs(username, 100, 0).WillReturnRows(rows)

	err := ListRecentFileMetadata(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, float64(100), resp["limit"])
	assert.Equal(t, float64(0), resp["offset"])
	assert.Equal(t, float64(1), resp["returned"])
	assert.Equal(t, false, resp["has_more"])

	files := resp["files"].([]interface{})
	assert.Len(t, files, 1)
	file0 := files[0].(map[string]interface{})
	assert.Equal(t, "file-1", file0["file_id"])
	assert.Equal(t, "encName1", file0["encrypted_filename"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetFileMetadataBatch tests the POST /api/files/metadata/batch endpoint
func TestGetFileMetadataBatch(t *testing.T) {
	username := "testuser"
	reqBody := `{"file_ids": ["file-1", "file-2", "file-999"]}`

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/api/files/metadata/batch", bytes.NewReader([]byte(reqBody)))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Setup mock DB response for models.GetFileMetadataBatchByOwner
	query := `SELECT file_id, password_type, filename_nonce, encrypted_filename,
		       sha256sum_nonce, encrypted_sha256sum, size_bytes, upload_date
		FROM file_metadata
		WHERE owner_username = \? AND file_id IN \(\?,\?,\?\)`

	rows := sqlmock.NewRows([]string{
		"file_id", "password_type", "filename_nonce", "encrypted_filename",
		"sha256sum_nonce", "encrypted_sha256sum", "size_bytes", "upload_date",
	}).AddRow(
		"file-1", "account", "nonce1", "encName1", "shaNonce1", "encSha1", 1024, "2024-01-01 12:00:00",
	).AddRow(
		"file-2", "custom", "nonce2", "encName2", "shaNonce2", "encSha2", 2048, "2024-01-02 12:00:00",
	)
	// Specifically omitting file-999 to test missing logic

	mockDB.ExpectQuery(query).WithArgs(username, "file-1", "file-2", "file-999").WillReturnRows(rows)

	err := GetFileMetadataBatch(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	filesMap := resp["files"].(map[string]interface{})
	assert.Contains(t, filesMap, "file-1")
	assert.Contains(t, filesMap, "file-2")
	assert.NotContains(t, filesMap, "file-999")

	missing := resp["missing"].([]interface{})
	assert.Len(t, missing, 1)
	assert.Equal(t, "file-999", missing[0])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// -- Priority 5: ListFiles + GetFileMeta tests --

// TestListFiles_NoFiles tests that a user with no files gets empty list and correct storage info
func TestListFiles_NoFiles(t *testing.T) {
	username := "user-no-files"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files", nil)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock DB.Ping()
	mockDB.ExpectPing()

	// Mock GetFilesByOwner - returns empty result set
	filesSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes, upload_date FROM file_metadata WHERE owner_username = \? ORDER BY upload_date DESC`
	mockDB.ExpectQuery(filesSQL).WithArgs(username).WillReturnRows(
		sqlmock.NewRows([]string{"id", "file_id", "storage_id", "owner_username", "password_hint", "password_type", "filename_nonce", "encrypted_filename", "sha256sum_nonce", "encrypted_sha256sum", "encrypted_file_sha256sum", "encrypted_fek", "size_bytes", "padded_size", "chunk_count", "chunk_size_bytes", "upload_date"}),
	)

	// Mock GetUserByUsername for storage info
	getUserSQL := `SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	userRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(int64(1), username, time.Now(), int64(0), models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	err := ListFiles(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Files should be nil or empty
	files := resp["files"]
	assert.Nil(t, files, "files should be nil for empty list")

	// Storage info should be present
	storage := resp["storage"].(map[string]interface{})
	assert.Equal(t, float64(0), storage["total_bytes"])
	assert.NotEmpty(t, storage["limit_readable"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListFiles_WithFiles tests that a user's files are correctly listed
func TestListFiles_WithFiles(t *testing.T) {
	username := "user-with-files"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files", nil)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectPing()

	filesSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes, upload_date FROM file_metadata WHERE owner_username = \? ORDER BY upload_date DESC`
	fileRows := sqlmock.NewRows([]string{"id", "file_id", "storage_id", "owner_username", "password_hint", "password_type", "filename_nonce", "encrypted_filename", "sha256sum_nonce", "encrypted_sha256sum", "encrypted_file_sha256sum", "encrypted_fek", "size_bytes", "padded_size", "chunk_count", "chunk_size_bytes", "upload_date"}).
		AddRow(int64(1), "file-1", "stor-1", username, "", "account", "nonce1", "encName1", "shaNonce1", "encSha1", "", "encFek1", int64(1024), nil, int64(1), int64(16777216), "2024-01-01 12:00:00").
		AddRow(int64(2), "file-2", "stor-2", username, "hint", "custom", "nonce2", "encName2", "shaNonce2", "encSha2", "", "encFek2", int64(2048), nil, int64(1), int64(16777216), "2024-01-02 12:00:00")
	mockDB.ExpectQuery(filesSQL).WithArgs(username).WillReturnRows(fileRows)

	getUserSQL := `SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	userRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(int64(1), username, time.Now(), int64(3072), models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	err := ListFiles(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	files := resp["files"].([]interface{})
	assert.Equal(t, 2, len(files))

	file0 := files[0].(map[string]interface{})
	assert.Equal(t, "file-1", file0["file_id"])
	assert.Equal(t, "account", file0["password_type"])

	file1 := files[1].(map[string]interface{})
	assert.Equal(t, "file-2", file1["file_id"])
	assert.Equal(t, "custom", file1["password_type"])

	storage := resp["storage"].(map[string]interface{})
	assert.Equal(t, float64(3072), storage["total_bytes"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListFiles_DBError tests that a DB error returns 500
func TestListFiles_DBError(t *testing.T) {
	username := "user-db-error"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files", nil)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectPing()

	filesSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes, upload_date FROM file_metadata WHERE owner_username = \? ORDER BY upload_date DESC`
	mockDB.ExpectQuery(filesSQL).WithArgs(username).WillReturnError(fmt.Errorf("database connection lost"))

	err := ListFiles(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetFileMeta_Success tests successful file metadata retrieval by owner
func TestGetFileMeta_Success(t *testing.T) {
	username := "file-owner"
	fileID := "test-file-meta-123"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files/:fileId/meta", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock GetFileByFileID
	fileSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes, upload_date FROM file_metadata WHERE file_id = \?`
	fileRows := sqlmock.NewRows([]string{"id", "file_id", "storage_id", "owner_username", "password_hint", "password_type", "filename_nonce", "encrypted_filename", "sha256sum_nonce", "encrypted_sha256sum", "encrypted_file_sha256sum", "encrypted_fek", "size_bytes", "padded_size", "chunk_count", "chunk_size_bytes", "upload_date"}).
		AddRow(int64(1), fileID, "stor-1", username, "", "account", "nonce1", "encName1", "shaNonce1", "encSha1", "", "encFek1", int64(5000000), nil, int64(1), int64(16777216), "2024-01-01 12:00:00")
	mockDB.ExpectQuery(fileSQL).WithArgs(fileID).WillReturnRows(fileRows)

	// Mock GetUserByUsername for approval check
	getUserSQL := `SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	userRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(int64(1), username, time.Now(), int64(5000000), models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	err := GetFileMeta(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, fileID, resp["file_id"])
	assert.Equal(t, "encFek1", resp["encrypted_fek"])
	assert.Equal(t, "account", resp["password_type"])
	assert.Equal(t, float64(5000000), resp["size_bytes"])
	assert.NotNil(t, resp["chunk_size"])
	assert.NotNil(t, resp["total_chunks"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetFileMeta_NotOwner tests that non-owner cannot access file metadata (privacy enforcement)
func TestGetFileMeta_NotOwner(t *testing.T) {
	requestingUser := "not-the-owner"
	actualOwner := "actual-owner"
	fileID := "someone-elses-file"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files/:fileId/meta", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: requestingUser}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock GetFileByFileID - returns file owned by someone else
	fileSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes, upload_date FROM file_metadata WHERE file_id = \?`
	fileRows := sqlmock.NewRows([]string{"id", "file_id", "storage_id", "owner_username", "password_hint", "password_type", "filename_nonce", "encrypted_filename", "sha256sum_nonce", "encrypted_sha256sum", "encrypted_file_sha256sum", "encrypted_fek", "size_bytes", "padded_size", "chunk_count", "chunk_size_bytes", "upload_date"}).
		AddRow(int64(1), fileID, "stor-1", actualOwner, "", "account", "nonce1", "encName1", "shaNonce1", "encSha1", "", "encFek1", int64(1024), nil, int64(1), int64(16777216), "2024-01-01 12:00:00")
	mockDB.ExpectQuery(fileSQL).WithArgs(fileID).WillReturnRows(fileRows)

	err := GetFileMeta(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "Access denied")

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetFileMeta_FileNotFound tests 404 for nonexistent file
func TestGetFileMeta_FileNotFound(t *testing.T) {
	username := "file-owner"
	fileID := "nonexistent-file"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files/:fileId/meta", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock GetFileByFileID - file not found
	fileSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes, upload_date FROM file_metadata WHERE file_id = \?`
	mockDB.ExpectQuery(fileSQL).WithArgs(fileID).WillReturnError(sql.ErrNoRows)

	err := GetFileMeta(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetFileMeta_UnapprovedUser tests that unapproved user cannot access file metadata
func TestGetFileMeta_UnapprovedUser(t *testing.T) {
	username := "unapproved-user"
	fileID := "test-file-unapproved"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/files/:fileId/meta", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock GetFileByFileID - file owned by requesting user
	fileSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes, upload_date FROM file_metadata WHERE file_id = \?`
	fileRows := sqlmock.NewRows([]string{"id", "file_id", "storage_id", "owner_username", "password_hint", "password_type", "filename_nonce", "encrypted_filename", "sha256sum_nonce", "encrypted_sha256sum", "encrypted_file_sha256sum", "encrypted_fek", "size_bytes", "padded_size", "chunk_count", "chunk_size_bytes", "upload_date"}).
		AddRow(int64(1), fileID, "stor-1", username, "", "account", "nonce1", "encName1", "shaNonce1", "encSha1", "", "encFek1", int64(1024), nil, int64(1), int64(16777216), "2024-01-01 12:00:00")
	mockDB.ExpectQuery(fileSQL).WithArgs(fileID).WillReturnRows(fileRows)

	// Mock GetUserByUsername - user NOT approved
	getUserSQL := `SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	userRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(int64(1), username, time.Now(), int64(0), models.DefaultStorageLimit, false, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	err := GetFileMeta(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Contains(t, httpErr.Message, "pending approval")

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// Additional Test Case Suggestions
//
// For DownloadFile Handler (handlers.DownloadFile)
// - TestDownloadFile_MetadataNotFound: File metadata doesn't exist in 'file_metadata' table (sql.ErrNoRows on owner check).
// - TestDownloadFile_NotOwner: Authenticated user is not the owner of the file.
// - TestDownloadFile_DBOwnerQueryError: General DB error when querying for file owner.
// - TestDownloadFile_DBMetadataQueryError: General DB error when querying for password_hint, password_type, sha256sum.
// - TestDownloadFile_StorageGetObjectError: storage.Provider.GetObject() returns an error (e.g., S3 object not found, S3 permissions error).
// - TestDownloadFile_StorageObjectReadError: io.ReadAll(object) fails after successfully obtaining the object stream.
// - TestDownloadFile_LogUserActionFailure: (Lower priority) Simulate failure in database.LogUserAction, ensure download still proceeds.
//
// For ListFiles Handler (handlers.ListFiles)
// - TestListFiles_Success_NoFiles: User has no files; API should return an empty list for "files" and correct storage info.
// - TestListFiles_Success_WithFiles: User has multiple files; verify all files are listed with correct metadata (filename, hints, type, hash, size, readable size, date).
// - TestListFiles_Success_StorageCalculations: Verify the 'storage' part of the response (total, limit, available, usage_percent) is accurate for various scenarios (empty, partially full, full). Check formatBytes helper implicitly.
// - TestListFiles_DBQueryError_FileListing: DB error occurs when querying 'file_metadata' for the list of files.
// - TestListFiles_DBScanError_FileRow: DB error occurs during rows.Scan() for an individual file row.
// - TestListFiles_DBGetUserError_StorageInfo: DB error occurs when models.GetUserByUsername is called to fetch user storage info.
// - TestListFiles_Pagination: If pagination is implemented, test different page sizes, page numbers, and edge cases.
// - TestListFiles_Sorting: If sorting options are implemented (e.g., by date, name, size), test them.
//
// For DeleteFile Handler (handlers.DeleteFile)
//   (Existing tests cover Success, NotFound, NotOwner, StorageError)
// - TestDeleteFile_TransactionBeginError: Simulate failure in database.DB.Begin().
// - TestDeleteFile_DBOwnerCheckError_Generic: Simulate a generic DB error (not sql.ErrNoRows) during the
