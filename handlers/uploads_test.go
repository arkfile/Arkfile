package handlers

import (
	"bytes"
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
)

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
		SELECT id, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(5) // Assume some user ID
	userRows := sqlmock.NewRows([]string{
		"id", "email", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
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

	// Add RemoveObject expectation in case of any error handling during upload
	mockStorage.On("RemoveObject",
		mock.Anything, // context
		filename,
		mock.AnythingOfType("minio.RemoveObjectOptions"),
	).Return(nil).Maybe() // Use Maybe() since it might not be called in success case

	// 2. Expect Metadata Insertion (after PutObject)
	insertMetaSQL := `INSERT INTO file_metadata \(filename, owner_email, password_hint, password_type, sha256sum, size_bytes\) VALUES \(\?, \?, \?, \?, \?, \?\)`
	mockDB.ExpectExec(insertMetaSQL).
		WithArgs(filename, email, passwordHint, passwordType, sha256sum, fileSize).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 3. Expect Storage Usage Update (inside user.UpdateStorageUsage)
	updateStorageSQL := `UPDATE users SET total_storage_bytes = \? WHERE id = \?`
	mockDB.ExpectExec(updateStorageSQL).
		WithArgs(expectedFinalStorage, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// 4. Expect Commit
	mockDB.ExpectCommit()

	// --- Mock LogUserAction (after commit) ---
	logActionSQL := `INSERT INTO user_activity \(user_email, action, target\) VALUES \(\?, \?, \?\)`
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
		SELECT id, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(6)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
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
		SELECT id, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(7)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
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
		SELECT id, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(8)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call to SUCCEED
	mockStorage.On("PutObject",
		mock.Anything, filename, mock.AnythingOfType("*strings.Reader"), fileSize, mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, nil).Once()

	// 2. Expect Metadata Insertion to FAIL
	dbError := fmt.Errorf("simulated DB metadata insert error")
	insertMetaSQL := `INSERT INTO file_metadata \(filename, owner_email, password_hint, password_type, sha256sum, size_bytes\) VALUES \(\?, \?, \?, \?, \?, \?\)`
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
		SELECT id, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(9)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call to SUCCEED
	mockStorage.On("PutObject",
		mock.Anything, filename, mock.AnythingOfType("*strings.Reader"), fileSize, mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, nil).Once()

	// 2. Expect Metadata Insertion to SUCCEED
	insertMetaSQL := `INSERT INTO file_metadata \(filename, owner_email, password_hint, password_type, sha256sum, size_bytes\) VALUES \(\?, \?, \?, \?, \?, \?\)`
	mockDB.ExpectExec(insertMetaSQL).
		WithArgs(filename, email, "hint", "account", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fileSize).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 3. Expect Storage Usage Update to FAIL
	dbError := fmt.Errorf("simulated DB update storage error")
	updateStorageSQL := `UPDATE users SET total_storage_bytes = \? WHERE id = \?`
	mockDB.ExpectExec(updateStorageSQL).
		WithArgs(initialStorage+fileSize, userID). // Correct expected args
		WillReturnError(dbError)

	// 4. Expect Rollback because storage update failed
	mockDB.ExpectRollback()

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

// --- Additional Test Case Suggestions ---
//
// === For UploadFile Handler (Simple Upload - handlers.UploadFile) ===
// - TestUploadFile_InvalidRequest_MissingFields: Test with missing required fields in the JSON request (e.g., `filename`, `data`, `sha256sum`).
// - TestUploadFile_EmptyFile: Upload a file where `data` is an empty string and `fileSize` is 0. This should usually succeed.
// - TestUploadFile_InvalidSHA256Format: Provide an SHA256 sum that is not a 64-character hexadecimal string.
// - TestUploadFile_InvalidPasswordType: Provide a `passwordType` other than the allowed values (e.g., "account", "custom").
// - TestUploadFile_FilenameConstraints: If there are filename constraints (e.g., length, allowed characters, path components), test these.
// - TestUploadFile_GetUserError_PreTransaction: Simulate `models.GetUserByEmail` failing *before* the DB transaction begins (during the initial storage capacity check).
// - TestUploadFile_TransactionBeginError: Simulate `database.DB.Begin()` failing.
// - TestUploadFile_DuplicateFilename: (If filenames must be unique per user or globally) Test uploading a file with a name that already exists for that user,
//   expecting a failure (likely at the metadata insertion step due to a UNIQUE constraint).
// - TestUploadFile_LogUserActionFailure: (Lower priority) Simulate `database.LogUserAction` failing after a successful upload and commit.
//   The core upload should still be considered successful.
// - TestUploadFile_UnapprovedUser: Attempt an upload by a user whose `is_approved` status is false. (Depends on middleware or handler checks).
//
// === For Chunked Upload Handlers (if tests are to be added to this file) ===
//   (Handlers: InitiateChunkedUpload, UploadChunk, CompleteChunkedUpload, GetUploadSessionStatus, ListChunks, AbortChunkedUpload)
//
//   **InitiateChunkedUpload:**
//   - TestInitiate_Success: Valid request, session created in DB, S3 multipart upload initiated (if applicable).
//   - TestInitiate_StorageLimitExceeded: Requested total_size exceeds user's available storage.
//   - TestInitiate_InvalidInput: Missing/invalid filename, total_size (e.g., 0 or negative), chunk_size (e.g., 0, too small, larger than total_size).
//   - TestInitiate_StorageError_CreateMultipart: If using S3, simulate an error from `CreateMultipartUpload`.
//   - TestInitiate_DBError_SaveSession: Error saving the upload session metadata to the database.
//
//   **UploadChunk:**
//   - TestUploadChunk_Success: Upload a valid chunk for an existing session. Verify ETag, IV, etc. are stored.
//   - TestUploadChunk_InvalidSessionID: Session ID in the path/request does not exist.
//   - TestUploadChunk_ChunkNumberOutOfBounds: Chunk number is < 1 or > total_chunks for the session.
//   - TestUploadChunk_SHA256Mismatch: Provided SHA256 hash for the chunk data does not match the calculated hash.
//   - TestUploadChunk_StorageError_UploadPart: Error from S3 `UploadPart`.
//   - TestUploadChunk_DBError_SaveChunkMetadata: Error saving chunk metadata to the database.
//   - TestUploadChunk_SessionAlreadyCompletedOrAborted: Attempt to upload a chunk to a session that's no longer active.
//
//   **CompleteChunkedUpload:**
//   - TestComplete_Success: All chunks are present and valid; S3 multipart completion succeeds; session status, file metadata, and user storage updated.
//   - TestComplete_SessionNotFound: Session ID does not exist.
//   - TestComplete_MissingChunks: Not all chunks have been uploaded yet.
//   - TestComplete_ChunkVerificationFailure: (If applicable) One or more chunks fail a final verification step.
//   - TestComplete_StorageError_CompleteMultipart: Error from S3 `CompleteMultipartUpload`.
//   - TestComplete_DBError_UpdateSession: Error updating the upload session status.
//   - TestComplete_DBError_CreateFileMetadata: Error creating the final `file_metadata` record.
//   - TestComplete_DBError_UpdateUserStorage: Error updating the user's total storage usage.
//
//   **GetUploadSessionStatus:**
//   - TestGetStatus_InProgress: Correctly report status for an ongoing upload.
//   - TestGetStatus_Completed: Correctly report status for a completed upload.
//   - TestGetStatus_Failed: Correctly report status for a failed/aborted upload.
//   - TestGetStatus_SessionNotFound: Session ID does not exist.
//
//   **ListChunks:**
//   - TestListChunks_Success: List all uploaded chunks for a given session, verify details.
//   - TestListChunks_NoChunksUploaded: Session exists but no chunks uploaded yet.
//   - TestListChunks_SessionNotFound: Session ID does not exist.
//
//   **AbortChunkedUpload (if such an endpoint exists):**
//   - TestAbort_Success: Successfully abort an ongoing upload session. Verify S3 multipart abort (if applicable) and DB status update.
//   - TestAbort_SessionNotFound: Session ID does not exist.
//   - TestAbort_SessionAlreadyCompleted: Attempt to abort an already completed session.
//   - TestAbort_StorageError_AbortMultipart: Error from S3 `AbortMultipartUpload`.
//   - TestAbort_DBError_UpdateSession: Error updating session status in the database.

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
		SELECT id, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`
	userID := int64(10)
	userRows := sqlmock.NewRows([]string{
		"id", "email", "created_at",
		"total_storage_bytes", "storage_limit_bytes",
		"is_approved", "approved_by", "approved_at", "is_admin",
	}).AddRow(userID, email, time.Now(), initialStorage, models.DefaultStorageLimit, true, nil, nil, false)
	mockDB.ExpectQuery(getUserSQL).WithArgs(email).WillReturnRows(userRows)

	// --- Transactional and Storage Expectations ---
	mockDB.ExpectBegin()

	// 1. Expect PutObject call to SUCCEED
	mockStorage.On("PutObject",
		mock.Anything, filename, mock.AnythingOfType("*strings.Reader"), fileSize, mock.AnythingOfType("minio.PutObjectOptions"),
	).Return(minio.UploadInfo{}, nil).Once()

	// 2. Expect Metadata Insertion to SUCCEED
	insertMetaSQL := `INSERT INTO file_metadata \(filename, owner_email, password_hint, password_type, sha256sum, size_bytes\) VALUES \(\?, \?, \?, \?, \?, \?\)`
	mockDB.ExpectExec(insertMetaSQL).
		WithArgs(filename, email, "hint", "account", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fileSize).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// 3. Expect Storage Usage Update to SUCCEED
	updateStorageSQL := `UPDATE users SET total_storage_bytes = \? WHERE id = \?`
	mockDB.ExpectExec(updateStorageSQL).
		WithArgs(expectedFinalStorage, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// 4. Expect Commit to FAIL
	dbError := fmt.Errorf("simulated DB commit error")
	mockDB.ExpectCommit().WillReturnError(dbError)

	// 5. Add RemoveObject expectation in case of commit failure
	mockStorage.On("RemoveObject",
		mock.Anything, filename, mock.AnythingOfType("minio.RemoveObjectOptions"),
	).Return(nil).Maybe() // Use Maybe() since the handler behavior on commit error may vary

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
