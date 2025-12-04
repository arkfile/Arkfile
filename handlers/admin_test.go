package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

// setupAdminEnv sets up the ADMIN_USERNAMES environment variable for tests
func setupAdminEnv(adminUsername string) func() {
	oldAdminUsernames := os.Getenv("ADMIN_USERNAMES")
	os.Setenv("ADMIN_USERNAMES", adminUsername)
	return func() {
		os.Setenv("ADMIN_USERNAMES", oldAdminUsernames)
	}
}

// --- Admin Handler Tests ---

// TestGetPendingUsers_Success_Admin tests successful retrieval of pending users by an admin.
func TestGetPendingUsers_Success_Admin(t *testing.T) {
	adminUsername := "admin.user.test"
	pendingUser1Username := "pending.user.one"
	pendingUser2Username := "pending.user.two"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	// Set up admin context
	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByUsername for admin check
	adminUserRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true) // Admin user
	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(adminUserRows)

	// Mock GetPendingUsers
	pendingUsersData := []models.User{
		{ID: 2, Username: pendingUser1Username, IsApproved: false},
		{ID: 3, Username: pendingUser2Username, IsApproved: false},
	}
	// Construct rows for GetPendingUsers (models/user.go)
	pendingRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes"}).
		AddRow(pendingUsersData[0].ID, pendingUsersData[0].Username, time.Now(), int64(0), models.DefaultStorageLimit).
		AddRow(pendingUsersData[1].ID, pendingUsersData[1].Username, time.Now(), int64(0), models.DefaultStorageLimit)

	// This query must exactly match the one in models.GetPendingUsers
	mockDB.ExpectQuery(`
		SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes
		FROM users
		WHERE is_approved = false
		ORDER BY created_at ASC`).WillReturnRows(pendingRows)

	err := GetPendingUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Data    []models.User `json:"data"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Len(t, response.Data, 2)
	assert.Equal(t, pendingUser1Username, response.Data[0].Username)
	assert.Equal(t, pendingUser2Username, response.Data[1].Username)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// --- Additional Test Case Suggestions ---
//
// General for all Admin Endpoints
// - Test with an expired admin JWT token.
// - Test with a JWT token that is valid but belongs to a user who was an admin but has since had their admin rights revoked
//   (depends on token validation and user status check logic).
// - Test atomicity: If an operation involves multiple DB changes or external calls (like storage), ensure that a failure
//   at any step correctly rolls back previous steps or leaves the system in a consistent state.
// - Test for correct and detailed logging of admin actions in various scenarios (successes, failures, specific errors).
// - If admin actions are rate-limited, add tests to verify rate-limiting behavior.
//
// For GetPendingUsers
// - TestGetPendingUsers_NoPendingUsers: Ensure it returns an empty list and HTTP 200 OK when no users are pending approval.
// - TestGetPendingUsers_Pagination: If pagination is ever added, test various page sizes, page numbers, and edge cases.
//
// For ApproveUser (now part of UpdateUser if `isApproved: true` is sent)
// - (Covered by UpdateUser tests, but if ApproveUser were a standalone endpoint again):
//   - TestApproveUser_AlreadyApproved: Attempt to approve a user who is already approved.
//     The behavior should be idempotent (e.g., return success without change) or a specific status/error.
//
// For UpdateUser
// - TestUpdateUser_MultipleFields: Update multiple fields simultaneously (e.g., `isAdmin` and `storageLimitBytes`)
//   to ensure all changes are applied correctly in one request.
// - TestUpdateUser_RevokeAdminStatus: Specifically test changing `isAdmin` from `true` to `false`.
// - TestUpdateUser_StorageLimit_LowerThanUsage: Attempt to set `storageLimitBytes` to a value lower than the
//   user's current `totalStorageBytes`. This should likely result in a validation error (e.g., HTTP 400).
// - TestUpdateUser_InvalidDataTypes: Test with invalid data types in the JSON payload for fields being updated
//   (e.g., `isAdmin: "true_string"` instead of `true`, `storageLimitBytes: "100GB_string"`).
//   (Current `InvalidJSON` test covers malformed JSON, this is more about valid JSON structure but wrong data types).
// - TestUpdateUser_LogDetailsFormat: Ensure the details logged in `admin_logs` correctly reflect all fields changed for various combinations of updates.
//
// For DeleteUser
// - TestDeleteUser_TargetUserHasNoFiles: Ensure successful deletion of a user who has no files in storage and no file metadata.
// - TestDeleteUser_LogAdminActionFailure: Simulate an error during the `LogAdminAction` step to see how the handler
//   behaves (ideally, the core delete operation should still succeed, and the logging failure noted). This is lower priority.
// - TestDeleteUser_TargetUserNotFoundInDB: Ensure it handles the case where the user to be deleted doesn't exist in the DB,
//   returning a 404 Not Found or similar appropriate error (currently tested by checking target user existence via SELECT 1).
//
// For ListUsers
// - TestListUsers_PaginationAndFiltering: If pagination or filtering (e.g., by approval status, admin status) is added,
//   test these features thoroughly.
// - TestListUsers_UserWithMaxStorage: Include a test case where a user has storage usage exactly equal to their limit to check percentage calculations.
// - TestListUsers_UserWithNullLastLogin: Covered by existing success case, but ensure it's always handled gracefully.
//
// For UpdateUserStorageLimit (subset of UpdateUser, but if treated as specific endpoint)
// - TestUpdateUserStorageLimit_BelowCurrentUsage: Try to set storage limit below the user's current actual usage.
//   This should ideally be a bad request (HTTP 400).
//
// Other Potential Admin Functions (if they exist or are planned)
// - RevokeUserApproval (if separate from UpdateUser isApproved:false):
//   - Success, target not found, already revoked, DB errors.
//   - Test if associated refresh tokens are revoked.
// - ViewUserDetails:
//   - Success, target not found, forbidden (non-admin).
// - ViewAdminLogs:
//   - Success, no logs, pagination, filtering by admin, by action, by target user, by date range.
//   - Forbidden (non-admin).
// - SystemStatus/HealthCheck_AdminView:
//   - Endpoint providing detailed system status for admins (DB connectivity, storage provider status, etc.).
// - ManageAPITokens (if server-side API tokens for services exist):
//   - Create, list, revoke API tokens.
// - GlobalSettingsManagement:
//   - If there are app-wide settings configurable by admins (e.g., default storage limit for new users,
//     maintenance mode toggle), test these endpoints.

// TestDeleteUser_Success_Admin tests successful user deletion by an admin.
func TestDeleteUser_Success_Admin(t *testing.T) {
	adminUsername := "admin.user.test"
	targetUsername := "user.to.delete"
	mockFile1 := "userfile1.txt"
	mockFile2 := "userfile2.dat"

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetUserByUsername for admin
	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	// Mock query for user's files using NEW schema with file_id and storage_id
	fileRows := sqlmock.NewRows([]string{"file_id", "storage_id"}).
		AddRow("file-id-1", mockFile1).
		AddRow("file-id-2", mockFile2)
	mockDB.ExpectQuery("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnRows(fileRows)

	// Mock storage removal for each file
	mockStorage.On("RemoveObject", mock.Anything, mockFile1, mock.AnythingOfType("storage.RemoveObjectOptions")).Return(nil).Once()
	mockStorage.On("RemoveObject", mock.Anything, mockFile2, mock.AnythingOfType("storage.RemoveObjectOptions")).Return(nil).Once()

	// Mock deletion of file metadata for each file using file_id (not storage_id)
	mockDB.ExpectExec("DELETE FROM file_metadata WHERE file_id = ?").WithArgs("file-id-1").WillReturnResult(sqlmock.NewResult(0, 1))
	mockDB.ExpectExec("DELETE FROM file_metadata WHERE file_id = ?").WithArgs("file-id-2").WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock deletion of user shares
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock deletion of user record
	mockDB.ExpectExec("DELETE FROM users WHERE username = ?").
		WithArgs(targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock LogAdminAction
	logAdminActionSQL := `INSERT INTO admin_logs \(admin_username, action, target_username, details\) VALUES \(\?, \?, \?, \?\)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminUsername, "delete_user", targetUsername, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectCommit()

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User deleted successfully", resp["message"])

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Forbidden_NonAdmin tests that a non-admin user cannot delete another user.
func TestDeleteUser_Forbidden_NonAdmin(t *testing.T) {
	nonAdminUsername := "non-admin-user"
	targetUsername := "user-to-delete"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	nonAdminClaims := &auth.Claims{Username: nonAdminUsername}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(nonAdminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, nonAdminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admin privileges required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_AdminFetchError tests error when fetching admin user details.
func TestDeleteUser_Error_AdminFetchError(t *testing.T) {
	adminUsername := "admin.user.test"
	targetUsername := "user.to.delete"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnError(fmt.Errorf("DB error fetching admin"))

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get admin user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_BadRequest_MissingUsernameParam tests request with missing username parameter.
func TestDeleteUser_BadRequest_MissingUsernameParam(t *testing.T) {
	adminUsername := "admin-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Username parameter required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_SelfDeletionAttempt tests an admin attempting to delete themselves.
func TestDeleteUser_Error_SelfDeletionAttempt(t *testing.T) {
	adminUsername := "admin-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(adminUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Cannot delete your own account", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_GetUserFilesError tests error when fetching target user's file list.
func TestDeleteUser_Error_GetUserFilesError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "user-with-file-fetch-error"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	mockDB.ExpectQuery("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnError(fmt.Errorf("DB error fetching user files"))

	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to retrieve user's files", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_StorageRemoveObjectError tests error during storage.RemoveObject.
func TestDeleteUser_Error_StorageRemoveObjectError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "user-with-storage-remove-error"
	fileWithError := "file-causes-storage-error.txt"

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"file_id", "storage_id"}).AddRow("file-id-error", fileWithError)
	mockDB.ExpectQuery("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnRows(fileRows)

	storageErr := fmt.Errorf("simulated storage RemoveObject error")
	mockStorage.On("RemoveObject", mock.Anything, fileWithError, mock.AnythingOfType("storage.RemoveObjectOptions")).
		Return(storageErr).Once()

	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	expectedMessage := fmt.Sprintf("Failed to delete user's file from storage: %s", fileWithError)
	assert.Equal(t, expectedMessage, resp["message"])

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_DeleteFileMetadataError tests error during DB deletion of file metadata.
func TestDeleteUser_Error_DeleteFileMetadataError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "user-with-meta-delete-error"
	fileWithError := "file-causes-meta-delete-error.txt"

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"file_id", "storage_id"}).AddRow("file-id-meta-error", fileWithError)
	mockDB.ExpectQuery("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnRows(fileRows)

	mockStorage.On("RemoveObject", mock.Anything, fileWithError, mock.AnythingOfType("storage.RemoveObjectOptions")).
		Return(nil).Once()

	dbErr := fmt.Errorf("simulated DB error deleting metadata")
	mockDB.ExpectExec("DELETE FROM file_metadata WHERE file_id = ?").WithArgs("file-id-meta-error").
		WillReturnError(dbErr)

	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	expectedMessage := fmt.Sprintf("Failed to delete file metadata for: %s", fileWithError)
	assert.Equal(t, expectedMessage, resp["message"])

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_DeleteFileSharesError tests error during DB deletion of user's file shares.
func TestDeleteUser_Error_DeleteFileSharesError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "user-with-share-delete-error"

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"file_id", "storage_id"})
	mockDB.ExpectQuery("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnRows(fileRows)

	dbErr := fmt.Errorf("simulated DB error deleting file shares")
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnError(dbErr)

	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to delete user's file shares", resp["message"])

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_DeleteUserRecordError tests error during DB deletion of the user record.
func TestDeleteUser_Error_DeleteUserRecordError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "user-with-record-delete-error"

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"file_id", "storage_id"})
	mockDB.ExpectQuery("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnRows(fileRows)

	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_username = ?").
		WithArgs(targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 0))

	dbErr := fmt.Errorf("simulated DB error deleting user record")
	mockDB.ExpectExec("DELETE FROM users WHERE username = ?").
		WithArgs(targetUsername).
		WillReturnError(dbErr)

	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to delete user record", resp["message"])

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_CommitError tests error during transaction commit.
func TestDeleteUser_Error_LogAdminActionFailure(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "user-with-log-error"

	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)
	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?").WithArgs(targetUsername).WillReturnRows(sqlmock.NewRows([]string{"file_id", "storage_id"}))
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_username = ?").WithArgs(targetUsername).WillReturnResult(sqlmock.NewResult(0, 0))
	mockDB.ExpectExec("DELETE FROM users WHERE username = ?").WithArgs(targetUsername).WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock the logging action to fail.
	mockDB.ExpectExec("INSERT INTO admin_logs \\(admin_username, action, target_username, details\\) VALUES \\(\\?, \\?, \\?, \\?\\)").
		WithArgs(adminUsername, "delete_user", targetUsername, "").
		WillReturnError(fmt.Errorf("simulated log failure"))
	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to log admin action", resp["message"])
	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_SetAdmin_Success_Admin tests making a user an admin.
func TestUpdateUser_SetAdmin_Success_Admin(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-to-make-admin"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"is_admin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE username = ?").WithArgs(targetUsername).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	updateSQL := `UPDATE users SET is_admin = \? WHERE username = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(true, targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_username, action, target_username, details\) VALUES \(\?, \?, \?, \?\)`
	details := "Updated fields: isAdmin: true"
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminUsername, "update_user", targetUsername, details).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectCommit()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_SetStorageLimit_Success_Admin tests updating a user's storage limit.
func TestUpdateUser_SetStorageLimit_Success_Admin(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-for-storage-update"
	newStorageLimit := int64(50 * 1024 * 1024 * 1024) // 50 GB

	reqBodyMap := map[string]interface{}{"storage_limit_bytes": newStorageLimit}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE username = ?").WithArgs(targetUsername).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	updateSQL := `UPDATE users SET storage_limit_bytes = \? WHERE username = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newStorageLimit, targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_username, action, target_username, details\) VALUES \(\?, \?, \?, \?\)`
	details := fmt.Sprintf("Updated fields: storageLimitBytes: %d", newStorageLimit)
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminUsername, "update_user", targetUsername, details).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectCommit()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_TargetUserNotFound tests updating a non-existent user.
func TestUpdateUser_Error_TargetUserNotFound(t *testing.T) {
	adminUsername := "admin-user"
	nonExistentUsername := "non-existent-user"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"is_admin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(nonExistentUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE username = ?").
		WithArgs(nonExistentUsername).
		WillReturnError(sql.ErrNoRows)

	mockDB.ExpectRollback()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Target user not found", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_Forbidden_NonAdmin tests a non-admin attempting to update a user.
func TestUpdateUser_Error_Forbidden_NonAdmin(t *testing.T) {
	nonAdminUsername := "non-admin-user"
	targetUsername := "target-user"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"is_admin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	nonAdminClaims := &auth.Claims{Username: nonAdminUsername}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(nonAdminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, nonAdminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admin privileges required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_InvalidJSON tests malformed JSON in the request body.
func TestUpdateUser_Error_InvalidJSON(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	invalidJSONBody := `{"is_admin": true`

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader([]byte(invalidJSONBody)))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Invalid request", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_EmptyBody tests request body with no updatable fields.
func TestUpdateUser_Error_EmptyBody(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	emptyJSONBody := `{}`

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader([]byte(emptyJSONBody)))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "No updatable fields provided", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_AdminDetailsFetchError tests error when fetching admin user details.
func TestUpdateUser_Error_AdminDetailsFetchError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"is_admin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnError(fmt.Errorf("DB error fetching admin"))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get admin user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_InvalidTargetUsernameParam tests error when target username parameter is missing.
func TestUpdateUser_Error_InvalidTargetUsernameParam(t *testing.T) {
	adminUsername := "admin-user"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"is_admin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//update", bytes.NewReader(jsonBody))

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Username parameter required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_Success_Admin tests successful access revocation via UpdateUser.
func TestUpdateUser_RevokeAccess_Success_Admin(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"is_approved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)
	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))
	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE username = ?").WithArgs(targetUsername).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
	mockDB.ExpectExec(`UPDATE users SET is_approved = \? WHERE username = \?`).
		WithArgs(false, targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mockDB.ExpectExec("INSERT INTO admin_logs \\(admin_username, action, target_username, details\\) VALUES \\(\\?, \\?, \\?, \\?\\)").
		WithArgs(adminUsername, "update_user", targetUsername, "Updated fields: isApproved: false").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mockDB.ExpectCommit()

	err := UpdateUser(c)
	require.NoError(t, err)

	// Since token deletion now happens in a goroutine, we can't reliably mock it here in a simple unit test.
	// We'll trust the handler calls it and test token deletion's effect in an integration test.
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"])
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_Forbidden_NonAdmin tests non-admin attempt.
func TestUpdateUser_RevokeAccess_Forbidden_NonAdmin(t *testing.T) {
	nonAdminUsername := "non-admin-user"
	targetUsername := "target-user"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"is_approved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	nonAdminClaims := &auth.Claims{Username: nonAdminUsername}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(nonAdminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admin privileges required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_AdminFetchError tests error fetching admin.
func TestUpdateUser_RevokeAccess_AdminFetchError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"is_approved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnError(fmt.Errorf("DB error"))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get admin user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_MissingUsernameParam tests missing target username.
func TestUpdateUser_RevokeAccess_MissingUsernameParam(t *testing.T) {
	adminUsername := "admin-user"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"is_approved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//update", bytes.NewReader(jsonBody))

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Username parameter required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_SelfRevocation tests admin trying to revoke own access.
func TestUpdateUser_RevokeAccess_SelfRevocation(t *testing.T) {
	adminUsername := "admin-user"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"is_approved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(adminUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	// Expect the transaction to start, then immediately get rolled back due to the error
	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE username = ?").WithArgs(adminUsername).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
	mockDB.ExpectRollback()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admins cannot revoke their own approval status.", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_RevokeDBError tests error during DB update for revocation.
func TestUpdateUser_RevokeAccess_RevokeDBError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"is_approved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE username = ?").WithArgs(targetUsername).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	revokeSQL := `UPDATE users SET is_approved = \? WHERE username = \?`
	mockDB.ExpectExec(revokeSQL).
		WithArgs(false, targetUsername).
		WillReturnError(fmt.Errorf("DB error during revocation"))

	mockDB.ExpectRollback()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to update approval status", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_SimulateTokenDeleteError - This test is more for a RevokeUserAccess handler that includes token deletion.
func TestUpdateUser_RevokeAccess_SimulateTokenDeleteError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	var logBuf bytes.Buffer
	originalErrorLogger := logging.ErrorLogger
	logging.ErrorLogger = log.New(&logBuf, "ERROR: ", 0)
	defer func() { logging.ErrorLogger = originalErrorLogger }()

	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"is_approved": &isApprovedFalse} // Update body for UpdateUser
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/update", bytes.NewReader(jsonBody)) // Use UpdateUser endpoint
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE username = ?").WithArgs(targetUsername).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	// UpdateUser sets is_approved - simulate this failing
	updateSQL := `UPDATE users SET is_approved = \? WHERE username = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(false, targetUsername).
		WillReturnError(fmt.Errorf("DB error updating approval status"))

	mockDB.ExpectRollback()

	err := UpdateUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to update approval status", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_Success_Admin tests successful retrieval of all users by an admin.
func TestListUsers_Success_Admin(t *testing.T) {
	adminUsername := "admin-user"
	user1Username := "user-1"
	user2Username := "user-2"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)
	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	// Define user data with specific registration dates for deterministic ordering.
	regDateUser2 := time.Now()
	regDateAdmin := time.Now().Add(-24 * time.Hour)
	regDateUser1 := time.Now().Add(-48 * time.Hour)

	userRows := sqlmock.NewRows([]string{"username", "is_approved", "is_admin", "storage_limit_bytes", "total_storage_bytes", "registration_date", "last_login"}).
		AddRow(user2Username, false, false, models.DefaultStorageLimit, int64(0), regDateUser2, sql.NullTime{Valid: false}).
		AddRow(adminUsername, true, true, int64(10*1024*1024*1024), int64(1*1024*1024*1024), regDateAdmin, sql.NullTime{Time: time.Now(), Valid: true}).
		AddRow(user1Username, true, false, int64(5*1024*1024*1024), int64(500*1024*1024), regDateUser1, sql.NullTime{})

	mockDB.ExpectQuery(`
		SELECT username, is_approved, is_admin, storage_limit_bytes, total_storage_bytes,
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnRows(userRows)
	mockDB.ExpectExec("INSERT INTO admin_logs \\(admin_username, action, target_username, details\\) VALUES \\(\\?, \\?, \\?, \\?\\)").
		WithArgs(adminUsername, "list_users", "", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "Response data should be a map")

	usersList, ok := data["users"].([]interface{})
	require.True(t, ok, "Users list should be a slice")
	assert.Len(t, usersList, 2)

	// Assert based on the correct order (user2, user1) - admin is filtered out
	user2, ok := usersList[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, user2Username, user2["username"])
	assert.False(t, user2["is_approved"].(bool))
	assert.Equal(t, "0 B", user2["total_storage_readable"])
	assert.InDelta(t, 0.0, user2["usage_percent"], 0.01)
	assert.Empty(t, user2["last_login"])

	user1, ok := usersList[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, user1Username, user1["username"])
	assert.True(t, user1["is_approved"].(bool))
	assert.False(t, user1["is_admin"].(bool))
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_Forbidden_NonAdmin tests non-admin attempt.
func TestListUsers_Forbidden_NonAdmin(t *testing.T) {
	nonAdminUsername := "non-admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	nonAdminClaims := &auth.Claims{Username: nonAdminUsername}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(nonAdminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admin privileges required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_AdminFetchError tests error fetching admin user.
func TestListUsers_AdminFetchError(t *testing.T) {
	adminUsername := "admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnError(fmt.Errorf("DB error"))

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get admin user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_QueryError tests error during the main user list query.
func TestListUsers_QueryError(t *testing.T) {
	adminUsername := "admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT username, is_approved, is_admin, storage_limit_bytes, total_storage_bytes,
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnError(fmt.Errorf("DB query error"))

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to retrieve users", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_ScanError tests an error during row scanning.
func TestListUsers_ScanError(t *testing.T) {
	adminUsername := "admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	userRows := sqlmock.NewRows([]string{"username", "is_approved", "is_admin", "storage_limit_bytes", "total_storage_bytes", "registration_date", "last_login"}).
		AddRow("scan-error-user", "not-a-bool", false, int64(1024), int64(0), time.Now(), sql.NullTime{})

	mockDB.ExpectQuery(`
		SELECT username, is_approved, is_admin, storage_limit_bytes, total_storage_bytes,
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnRows(userRows)

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Error processing user data", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestListUsers_NoUsers tests listing when there are no users.
func TestListUsers_NoUsers(t *testing.T) {
	adminUsername := "admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	// Simulate sql.ErrNoRows for the user list query
	mockDB.ExpectQuery(`
		SELECT username, is_approved, is_admin, storage_limit_bytes, total_storage_bytes,
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnError(sql.ErrNoRows)

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "Response data should be a map")

	usersList, ok := data["users"].([]interface{})
	assert.True(t, ok, "Users list should be a slice")
	assert.Len(t, usersList, 0, "Users list should be empty")

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_Forbidden_NonAdmin tests access denial for non-admin users.
func TestGetPendingUsers_Forbidden_NonAdmin(t *testing.T) {
	nonAdminUsername := "non-admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	nonAdminClaims := &auth.Claims{Username: nonAdminUsername}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	nonAdminUserRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, nonAdminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false)
	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(nonAdminUsername).WillReturnRows(nonAdminUserRows)

	err := GetPendingUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admin privileges required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_GetUserError tests DB error when fetching admin user.
func TestGetPendingUsers_GetUserError(t *testing.T) {
	adminUsername := "admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnError(fmt.Errorf("DB error"))

	err := GetPendingUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_GetPendingError tests DB error when fetching pending users list.
func TestGetPendingUsers_GetPendingError(t *testing.T) {
	adminUsername := "admin-user"
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	adminUserRows := sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true)
	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(adminUserRows)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at, total_storage_bytes, storage_limit_bytes
		FROM users
		WHERE is_approved = false
		ORDER BY created_at ASC`).
		WillReturnError(fmt.Errorf("DB error fetching pending"))

	err := GetPendingUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get pending users", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_Success_Admin tests successful user approval by an admin.
func TestApproveUser_Success_Admin(t *testing.T) {
	adminUsername := "admin-user"

	// Set admin username in environment for isAdminUsername check
	cleanup := setupAdminEnv(adminUsername)
	defer cleanup()
	targetUsername := "target-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(targetUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, targetUsername, time.Now(), int64(0), models.DefaultStorageLimit, false, sql.NullString{}, sql.NullTime{}, false))

	mockDB.ExpectExec(`UPDATE users SET is_approved = true, approved_by = \?, approved_at = \? WHERE id = \?`).
		WithArgs(adminUsername, sqlmock.AnyArg(), 2).
		WillReturnResult(sqlmock.NewResult(1, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_username, action, target_username, details\) VALUES \(\?, \?, \?, \?\)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminUsername, "approve_user", targetUsername, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User approved successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_Forbidden_NonAdmin tests non-admin attempting approval.
func TestApproveUser_Forbidden_NonAdmin(t *testing.T) {
	nonAdminUsername := "non-admin-user"
	targetUsername := "target-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	nonAdminClaims := &auth.Claims{Username: nonAdminUsername}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(nonAdminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admin privileges required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_AdminFetchError tests error fetching admin user details.
func TestApproveUser_AdminFetchError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnError(fmt.Errorf("DB error fetching admin"))

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get admin user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_TargetUserNotFound tests trying to approve a non-existent user.
func TestApproveUser_TargetUserNotFound(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "nonexistent-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(targetUsername).WillReturnError(sql.ErrNoRows)

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "User not found", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_TargetUserDBError tests generic DB error fetching target user.
func TestApproveUser_TargetUserDBError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(targetUsername).WillReturnError(fmt.Errorf("DB error fetching target"))

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "User not found", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_ApproveModelError tests error during user.ApproveUser model method.
func TestApproveUser_ApproveModelError(t *testing.T) {
	adminUsername := "admin-user"

	// Set admin username in environment for isAdminUsername check
	cleanup := setupAdminEnv(adminUsername)
	defer cleanup()
	targetUsername := "target-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:username", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(targetUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, targetUsername, time.Now(), int64(0), models.DefaultStorageLimit, false, sql.NullString{}, sql.NullTime{}, false))

	mockDB.ExpectExec(`UPDATE users SET is_approved = true, approved_by = \?, approved_at = \? WHERE id = \?`).
		WithArgs(adminUsername, sqlmock.AnyArg(), 2).
		WillReturnError(fmt.Errorf("DB error approving user"))

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to approve user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_MissingUsernameParam tests the case where the username parameter is missing.
func TestApproveUser_MissingUsernameParam(t *testing.T) {
	adminUsername := "admin-user"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/", nil)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := ApproveUser(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Username parameter required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_Success_Admin tests successful storage limit update by admin.
func TestUpdateUserStorageLimit_Success_Admin(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	newLimit := int64(20 * 1024 * 1024) // 20 MB

	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	updateSQL := `UPDATE users SET storage_limit_bytes = \? WHERE username = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newLimit, targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_username, action, target_username, details\) VALUES \(\?, \?, \?, \?\)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminUsername, "update_storage_limit", targetUsername, fmt.Sprintf("New limit: %d bytes", newLimit)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := UpdateUserStorageLimit(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Storage limit updated successfully", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_Forbidden_NonAdmin tests non-admin attempt.
func TestUpdateUserStorageLimit_Forbidden_NonAdmin(t *testing.T) {
	nonAdminUsername := "non-admin-user"
	targetUsername := "target-user"
	newLimit := int64(20 * 1024 * 1024)
	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	nonAdminClaims := &auth.Claims{Username: nonAdminUsername}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
				SELECT id, username, created_at,
					   total_storage_bytes, storage_limit_bytes,
					   is_approved, approved_by, approved_at, is_admin
				FROM users WHERE username = ?`).WithArgs(nonAdminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := UpdateUserStorageLimit(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Admin privileges required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_AdminFetchError tests error fetching admin.
func TestUpdateUserStorageLimit_AdminFetchError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	newLimit := int64(20 * 1024 * 1024)
	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnError(fmt.Errorf("DB error"))

	err := UpdateUserStorageLimit(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to get admin user", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_MissingUsernameParam tests missing target username.
func TestUpdateUserStorageLimit_MissingUsernameParam(t *testing.T) {
	adminUsername := "admin-user"
	newLimit := int64(20 * 1024 * 1024)
	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//storage-limit", bytes.NewReader(jsonBody))

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUserStorageLimit(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Username parameter required", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_InvalidBody tests malformed JSON.
func TestUpdateUserStorageLimit_InvalidBody(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	jsonBody := []byte(`{"storage_limit_bytes": "not-a-number"`)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUserStorageLimit(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Invalid request", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUserStorageLimit_NonPositiveLimit tests zero or negative limit.
func TestUpdateUserStorageLimit_NonPositiveLimit(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"

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

			c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/storage-limit", bytes.NewReader(jsonBody))
			c.SetParamNames("username")
			c.SetParamValues(targetUsername)

			adminClaims := &auth.Claims{Username: adminUsername}
			adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
			c.Set("user", adminToken)

			mockDB.ExpectQuery(`
				SELECT id, username, created_at,
					   total_storage_bytes, storage_limit_bytes,
					   is_approved, approved_by, approved_at, is_admin
				FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
				sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
					AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

			err := UpdateUserStorageLimit(c)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			var resp map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &resp)
			assert.Equal(t, "Storage limit must be positive", resp["message"])

			assert.NoError(t, mockDB.ExpectationsWereMet())
		})
	}
}

// TestUpdateUserStorageLimit_DBUpdateError tests error during DB update.
func TestUpdateUserStorageLimit_DBUpdateError(t *testing.T) {
	adminUsername := "admin-user"
	targetUsername := "target-user"
	newLimit := int64(20 * 1024 * 1024)

	reqBody := map[string]int64{"storage_limit_bytes": newLimit}
	jsonBody, _ := json.Marshal(reqBody)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:username/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`).WithArgs(adminUsername).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminUsername, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	updateSQL := `UPDATE users SET storage_limit_bytes = \? WHERE username = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newLimit, targetUsername).
		WillReturnError(fmt.Errorf("DB update error"))

	err := UpdateUserStorageLimit(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "Failed to update storage limit", resp["message"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}
