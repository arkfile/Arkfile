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

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
)

// --- Test DownloadFile ---

// TestDownloadFile_Success tests successful file download with encrypted metadata
func TestDownloadFile_Success(t *testing.T) {
	username := "downloader"
	fileID := "test-file-id-123"
	fileContent := "This is the content to be downloaded."
	fileSize := int64(len(fileContent))
	passwordHint := "download hint"
	passwordType := "account"
	// Base64 encoded encrypted metadata for testing
	encryptedFilename := "ZW5jcnlwdGVkRmlsZW5hbWU=" // "encryptedFilename" in base64
	filenameNonce := "bm9uY2VGaWxlbmFtZQ=="         // "nonceFilename" in base64
	encryptedSha256sum := "ZW5jcnlwdGVkU2hhMjU2"    // "encryptedSha256" in base64
	sha256sumNonce := "bm9uY2VTaGEyNTY="            // "nonceSha256" in base64

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodGet, "/files/:fileId", nil)
	c.SetParamNames("fileId")
	c.SetParamValues(fileID)
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Query matches models.GetFileByFileID function
	metadataSQL := `SELECT id, file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, COALESCE\(encrypted_file_sha256sum, ''\), encrypted_fek, size_bytes, padded_size, upload_date FROM file_metadata WHERE file_id = \?`
	storageID := "test-storage-id-123"
	paddedSize := fileSize + 1024 // Mock padded size
	metaRows := sqlmock.NewRows([]string{"id", "file_id", "storage_id", "owner_username", "password_hint", "password_type", "filename_nonce", "encrypted_filename", "sha256sum_nonce", "encrypted_sha256sum", "encrypted_file_sha256sum", "encrypted_fek", "size_bytes", "padded_size", "upload_date"}).
		AddRow(1, fileID, storageID, username, passwordHint, passwordType, filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum, "", "", fileSize, paddedSize, time.Now())
	mockDB.ExpectQuery(metadataSQL).WithArgs(fileID).WillReturnRows(metaRows)

	// Check if user is approved - add user query (matches models.GetUserByUsername)
	getUserSQL := `SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes, is_approved, approved_by, approved_at, is_admin FROM users WHERE username = \?`
	userRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, username, time.Now(), 1000, 10000000, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(userRows)

	mockStorageObject := new(storage.MockMinioObject)
	mockStorageObject.SetContent(fileContent)
	mockStorageObject.SetStatInfo(minio.ObjectInfo{Size: fileSize}, nil)
	mockStorageObject.On("Close").Return(nil)
	mockStorage.On("GetObjectWithoutPadding", mock.Anything, storageID, fileSize, mock.AnythingOfType("minio.GetObjectOptions")).Return(mockStorageObject, nil).Once()

	logActionSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mockDB.ExpectExec(logActionSQL).WithArgs(username, "downloaded", fileID).WillReturnResult(sqlmock.NewResult(1, 1))

	err := DownloadFile(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify file content
	assert.Equal(t, fileContent, rec.Body.String())
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, fmt.Sprintf("attachment; filename=%s", fileID), rec.Header().Get("Content-Disposition"))
	assert.Equal(t, fmt.Sprintf("%d", fileSize), rec.Header().Get("Content-Length"))

	assert.NoError(t, mockDB.ExpectationsWereMet())
	mockStorage.AssertExpectations(t)
	mockStorageObject.AssertExpectations(t)
}

// --- Test DeleteFile ---

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
	mockStorage.On("RemoveObject", mock.Anything, storageID, mock.AnythingOfType("minio.RemoveObjectOptions")).Return(nil).Once()

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
	mockStorage.On("RemoveObject", mock.Anything, storageID, mock.AnythingOfType("minio.RemoveObjectOptions")).Return(storageError).Once()
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

// --- Additional Test Case Suggestions ---
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
