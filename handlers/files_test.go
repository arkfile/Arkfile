package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
)

// --- Test DownloadFile ---

// TestDownloadFile_Success tests successful file download
func TestDownloadFile_Success(t *testing.T) {
	username := "downloader"
	filename := "download-test.txt"
	fileContent := "This is the content to be downloaded."
	fileSize := int64(len(fileContent))
	passwordHint := "download hint"
	passwordType := "account"
	sha256sum := "hash123..." // Precise hash not critical for this test path

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodGet, "/files/:filename", nil)
	c.SetParamNames("filename")
	c.SetParamValues(filename)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Check if user is approved - add user query
	getUserSQL := `SELECT id, username, email, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = ?`
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, username, "test@example.com", time.Now(), 1000, 10000000, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	// Updated query to match actual handler
	metadataSQL := "SELECT storage_id, owner_username, password_hint, password_type, sha256sum, size_bytes FROM file_metadata WHERE filename = ?"
	storageID := "test-storage-id-123"
	metaRows := sqlmock.NewRows([]string{"storage_id", "owner_username", "password_hint", "password_type", "sha256sum", "size_bytes"}).
		AddRow(storageID, username, passwordHint, passwordType, sha256sum, fileSize)
	mockDB.ExpectQuery(metadataSQL).WithArgs(filename).WillReturnRows(metaRows)

	mockStorageObject := new(storage.MockMinioObject)
	mockStorageObject.SetContent(fileContent)
	mockStorageObject.SetStatInfo(minio.ObjectInfo{Size: fileSize}, nil)
	mockStorageObject.On("Close").Return(nil)
	mockStorage.On("GetObjectWithoutPadding", mock.Anything, storageID, fileSize, mock.AnythingOfType("minio.GetObjectOptions")).Return(mockStorageObject, nil).Once()

	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mockDB.ExpectExec(logActionSQL).WithArgs(username, "downloaded", filename).WillReturnResult(sqlmock.NewResult(1, 1))

	err := DownloadFile(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, fileContent, resp["data"])
	assert.Equal(t, passwordHint, resp["passwordHint"])
	assert.Equal(t, passwordType, resp["passwordType"])
	assert.Equal(t, sha256sum, resp["sha256sum"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
	mockStorage.AssertExpectations(t)
	mockStorageObject.AssertExpectations(t)
}

// --- Test DeleteFile ---

// TestDeleteFile_Success tests successful file deletion
func TestDeleteFile_Success(t *testing.T) {
	username := "user-delete"
	filename := "file-to-delete.txt"
	fileSize := int64(1024)
	initialStorage := int64(5000)

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil)
	c.SetParamNames("filename")
	c.SetParamValues(filename)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	// Updated query to match actual handler - includes storage_id
	ownerCheckSQL := "SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE filename = ?"
	storageID := "test-storage-id-456"
	ownerRows := sqlmock.NewRows([]string{"owner_username", "storage_id", "size_bytes"}).AddRow(username, storageID, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnRows(ownerRows)

	deleteMetaSQL := `DELETE FROM file_metadata WHERE filename = \?`
	mockDB.ExpectExec(deleteMetaSQL).WithArgs(filename).WillReturnResult(sqlmock.NewResult(0, 1))

	getUserSQL := `
		SELECT id, username, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`
	userID := int64(1)
	userRows := sqlmock.NewRows([]string{
		"id", "username", "email", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, username, "test@example.com", time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	updateStorageSQL := `UPDATE users SET total_storage_bytes = \? WHERE id = \?`
	expectedStorage := initialStorage - fileSize
	mockDB.ExpectExec(updateStorageSQL).WithArgs(expectedStorage, userID).WillReturnResult(sqlmock.NewResult(0, 1))
	mockDB.ExpectCommit()

	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mockDB.ExpectExec(logActionSQL).WithArgs(username, "deleted", filename).WillReturnResult(sqlmock.NewResult(1, 1))
	mockStorage.On("RemoveObject", mock.Anything, storageID, mock.AnythingOfType("minio.RemoveObjectOptions")).Return(nil).Once()

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
	filename := "non-existent-file.txt"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil)
	c.SetParamNames("filename")
	c.SetParamValues(filename)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	ownerCheckSQL := "SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE filename = ?"
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnError(fmt.Errorf("sql: no rows in result set")) // Simulate sql.ErrNoRows

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
	filename := "someone-elses-file.txt"
	fileSize := int64(512)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil)
	c.SetParamNames("filename")
	c.SetParamValues(filename)
	claims := &auth.Claims{Username: requestingUsername}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	ownerCheckSQL := "SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE filename = ?"
	storageID := "test-storage-id-789"
	ownerRows := sqlmock.NewRows([]string{"owner_username", "storage_id", "size_bytes"}).AddRow(ownerUsername, storageID, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnRows(ownerRows)
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
	filename := "file-stor-err.txt"
	fileSize := int64(1024)

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/files/:filename", nil)
	c.SetParamNames("filename")
	c.SetParamValues(filename)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	mockDB.ExpectBegin()
	ownerCheckSQL := "SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE filename = ?"
	storageID := "test-storage-id-999"
	ownerRows := sqlmock.NewRows([]string{"owner_username", "storage_id", "size_bytes"}).AddRow(username, storageID, fileSize)
	mockDB.ExpectQuery(ownerCheckSQL).WithArgs(filename).WillReturnRows(ownerRows)
	mockDB.ExpectRollback()

	storageError := fmt.Errorf("simulated storage layer error")
	mockStorage.On("RemoveObject", mock.Anything, storageID, mock.AnythingOfType("minio.RemoveObjectOptions")).Return(storageError).Once()

	err := DeleteFile(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to delete file from storage", httpErr.Message.(string))

	assert.NoError(t, mockDB.ExpectationsWereMet())
	mockStorage.AssertExpectations(t)
}

// --- Additional Test Case Suggestions ---
//
// === For DownloadFile Handler (handlers.DownloadFile) ===
// - TestDownloadFile_MetadataNotFound: File metadata doesn't exist in 'file_metadata' table (sql.ErrNoRows on owner check).
// - TestDownloadFile_NotOwner: Authenticated user is not the owner of the file.
// - TestDownloadFile_DBOwnerQueryError: General DB error when querying for file owner.
// - TestDownloadFile_DBMetadataQueryError: General DB error when querying for password_hint, password_type, sha256sum.
// - TestDownloadFile_StorageGetObjectError: storage.Provider.GetObject() returns an error (e.g., S3 object not found, S3 permissions error).
// - TestDownloadFile_StorageObjectReadError: io.ReadAll(object) fails after successfully obtaining the object stream.
// - TestDownloadFile_LogUserActionFailure: (Lower priority) Simulate failure in database.LogUserAction, ensure download still proceeds.
//
// === For ListFiles Handler (handlers.ListFiles) ===
// - TestListFiles_Success_NoFiles: User has no files; API should return an empty list for "files" and correct storage info.
// - TestListFiles_Success_WithFiles: User has multiple files; verify all files are listed with correct metadata (filename, hints, type, hash, size, readable size, date).
// - TestListFiles_Success_StorageCalculations: Verify the 'storage' part of the response (total, limit, available, usage_percent) is accurate for various scenarios (empty, partially full, full). Check formatBytes helper implicitly.
// - TestListFiles_DBQueryError_FileListing: DB error occurs when querying 'file_metadata' for the list of files.
// - TestListFiles_DBScanError_FileRow: DB error occurs during rows.Scan() for an individual file row.
// - TestListFiles_DBGetUserError_StorageInfo: DB error occurs when models.GetUserByEmail is called to fetch user storage info.
// - TestListFiles_Pagination: If pagination is implemented, test different page sizes, page numbers, and edge cases.
// - TestListFiles_Sorting: If sorting options are implemented (e.g., by date, name, size), test them.
//
// === For DeleteFile Handler (handlers.DeleteFile) ===
//   (Existing tests cover Success, NotFound, NotOwner, StorageError)
// - TestDeleteFile_TransactionBeginError: Simulate failure in database.DB.Begin().
// - TestDeleteFile_DBOwnerCheckError_Generic: Simulate a generic DB error (not sql.ErrNoRows) during the
