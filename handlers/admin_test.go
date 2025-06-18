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
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
)

// setupAdminEnv sets up the ADMIN_EMAILS environment variable for tests
func setupAdminEnv(adminEmail string) func() {
	oldAdminEmails := os.Getenv("ADMIN_EMAILS")
	os.Setenv("ADMIN_EMAILS", adminEmail)
	return func() {
		os.Setenv("ADMIN_EMAILS", oldAdminEmails)
	}
}

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
	adminUserRows := sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, adminEmail, "hashedpassword", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true) // Admin user
	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(adminUserRows)

	// Mock GetPendingUsers
	pendingUsersData := []models.User{
		{ID: 2, Email: pendingUser1Email, IsApproved: false},
		{ID: 3, Email: pendingUser2Email, IsApproved: false},
	}
	// Construct rows for GetPendingUsers (models/user.go)
	pendingRows := sqlmock.NewRows([]string{"id", "email", "created_at", "total_storage_bytes", "storage_limit_bytes"}).
		AddRow(pendingUsersData[0].ID, pendingUsersData[0].Email, time.Now(), int64(0), models.DefaultStorageLimit).
		AddRow(pendingUsersData[1].ID, pendingUsersData[1].Email, time.Now(), int64(0), models.DefaultStorageLimit)

	// This query must exactly match the one in models.GetPendingUsers
	mockDB.ExpectQuery(`
		SELECT id, email, created_at, total_storage_bytes, storage_limit_bytes
		FROM users
		WHERE is_approved = false
		ORDER BY created_at ASC`).WillReturnRows(pendingRows)

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

// --- Additional Test Case Suggestions ---
//
// === General for all Admin Endpoints ===
// - Test with an expired admin JWT token.
// - Test with a JWT token that is valid but belongs to a user who was an admin but has since had their admin rights revoked
//   (depends on token validation and user status check logic).
// - Test atomicity: If an operation involves multiple DB changes or external calls (like storage), ensure that a failure
//   at any step correctly rolls back previous steps or leaves the system in a consistent state.
// - Test for correct and detailed logging of admin actions in various scenarios (successes, failures, specific errors).
// - If admin actions are rate-limited, add tests to verify rate-limiting behavior.
//
// === For GetPendingUsers ===
// - TestGetPendingUsers_NoPendingUsers: Ensure it returns an empty list and HTTP 200 OK when no users are pending approval.
// - TestGetPendingUsers_Pagination: If pagination is ever added, test various page sizes, page numbers, and edge cases.
//
// === For ApproveUser (now part of UpdateUser if `isApproved: true` is sent) ===
// - (Covered by UpdateUser tests, but if ApproveUser were a standalone endpoint again):
//   - TestApproveUser_AlreadyApproved: Attempt to approve a user who is already approved.
//     The behavior should be idempotent (e.g., return success without change) or a specific status/error.
//
// === For UpdateUser ===
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
// === For DeleteUser ===
// - TestDeleteUser_TargetUserHasNoFiles: Ensure successful deletion of a user who has no files in storage and no file metadata.
// - TestDeleteUser_LogAdminActionFailure: Simulate an error during the `LogAdminAction` step to see how the handler
//   behaves (ideally, the core delete operation should still succeed, and the logging failure noted). This is lower priority.
// - TestDeleteUser_TargetUserNotFoundInDB: Ensure it handles the case where the user to be deleted doesn't exist in the DB,
//   returning a 404 Not Found or similar appropriate error (currently tested by checking target user existence via SELECT 1).
//
// === For ListUsers ===
// - TestListUsers_PaginationAndFiltering: If pagination or filtering (e.g., by approval status, admin status) is added,
//   test these features thoroughly.
// - TestListUsers_UserWithMaxStorage: Include a test case where a user has storage usage exactly equal to their limit to check percentage calculations.
// - TestListUsers_UserWithNullLastLogin: Covered by existing success case, but ensure it's always handled gracefully.
//
// === For UpdateUserStorageLimit (subset of UpdateUser, but if treated as specific endpoint) ===
// - TestUpdateUserStorageLimit_BelowCurrentUsage: Try to set storage limit below the user's current actual usage.
//   This should ideally be a bad request (HTTP 400).
//
// === Other Potential Admin Functions (if they exist or are planned) ===
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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

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
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock deletion of user record
	mockDB.ExpectExec("DELETE FROM users WHERE email = ?").
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock LogAdminAction
	logAdminActionSQL := `INSERT INTO admin_logs \(admin_email, action, target_email, details\) VALUES \(\?, \?, \?, \?\)`
	mockDB.ExpectExec(logAdminActionSQL).
		WithArgs(adminEmail, "delete_user", targetUserEmail, "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mockDB.ExpectCommit()

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

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, nonAdminEmail, "nonadminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	assert.Equal(t, "Admin privileges required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
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

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

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
	adminEmail := "admin@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(adminEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Cannot delete your own account", httpErr.Message)

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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

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

// TestDeleteUser_Error_StorageRemoveObjectError tests error during storage.RemoveObject.
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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"filename"}).AddRow(fileWithError)
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	storageErr := fmt.Errorf("simulated storage RemoveObject error")
	mockStorage.On("RemoveObject", mock.Anything, fileWithError, mock.AnythingOfType("minio.RemoveObjectOptions")).
		Return(storageErr).Once()

	mockDB.ExpectRollback()

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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"filename"}).AddRow(fileWithError)
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	mockStorage.On("RemoveObject", mock.Anything, fileWithError, mock.AnythingOfType("minio.RemoveObjectOptions")).
		Return(nil).Once()

	dbErr := fmt.Errorf("simulated DB error deleting metadata")
	mockDB.ExpectExec("DELETE FROM file_metadata WHERE filename = ?").WithArgs(fileWithError).
		WillReturnError(dbErr)

	mockDB.ExpectRollback()

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

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"filename"})
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	dbErr := fmt.Errorf("simulated DB error deleting file shares")
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnError(dbErr)

	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to delete user's file shares", httpErr.Message)

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestDeleteUser_Error_DeleteUserRecordError tests error during DB deletion of the user record.
func TestDeleteUser_Error_DeleteUserRecordError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-record-delete-error@example.com"

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()

	fileRows := sqlmock.NewRows([]string{"filename"})
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnRows(fileRows)

	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_email = ?").
		WithArgs(targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 0))

	dbErr := fmt.Errorf("simulated DB error deleting user record")
	mockDB.ExpectExec("DELETE FROM users WHERE email = ?").
		WithArgs(targetUserEmail).
		WillReturnError(dbErr)

	mockDB.ExpectRollback()

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
func TestDeleteUser_Error_LogAdminActionFailure(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "user-with-log-error@example.com"

	c, _, mockDB, mockStorage := setupTestEnv(t, http.MethodDelete, "/admin/users/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)
	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT filename FROM file_metadata WHERE owner_email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{}))
	mockDB.ExpectExec("DELETE FROM file_shares WHERE owner_email = ?").WithArgs(targetUserEmail).WillReturnResult(sqlmock.NewResult(0, 0))
	mockDB.ExpectExec("DELETE FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock the logging action to fail.
	mockDB.ExpectExec("INSERT INTO admin_logs \\(admin_email, action, target_email, details\\) VALUES \\(\\?, \\?, \\?, \\?\\)").
		WithArgs(adminEmail, "delete_user", targetUserEmail, "").
		WillReturnError(fmt.Errorf("simulated log failure"))
	mockDB.ExpectRollback()

	err := DeleteUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to log admin action", httpErr.Message)
	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_SetAdmin_Success_Admin tests making a user an admin.
func TestUpdateUser_SetAdmin_Success_Admin(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target-to-make-admin@example.com"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	updateSQL := `UPDATE users SET is_admin = \? WHERE email = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(true, targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_email, action, target_email, details\) VALUES \(\?, \?, \?, \?\)`
	details := "Updated fields: isAdmin: true"
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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	updateSQL := `UPDATE users SET storage_limit_bytes = \? WHERE email = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newStorageLimit, targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_email, action, target_email, details\) VALUES \(\?, \?, \?, \?\)`
	details := fmt.Sprintf("Updated fields: storageLimitBytes: %d", newStorageLimit)
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
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(nonExistentUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").
		WithArgs(nonExistentUserEmail).
		WillReturnError(sql.ErrNoRows)

	mockDB.ExpectRollback()

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
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, nonAdminEmail, "userpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

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
	invalidJSONBody := `{"isAdmin": true`

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader([]byte(invalidJSONBody)))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Invalid request", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_EmptyBody tests request body with no updatable fields.
func TestUpdateUser_Error_EmptyBody(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target-user@example.com"
	emptyJSONBody := `{}`

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader([]byte(emptyJSONBody)))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "No updatable fields provided", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_AdminDetailsFetchError tests error when fetching admin user details.
func TestUpdateUser_Error_AdminDetailsFetchError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target-user@example.com"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error fetching admin"))

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get admin user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_Error_InvalidTargetEmailParam tests error when target email parameter is missing.
func TestUpdateUser_Error_InvalidTargetEmailParam(t *testing.T) {
	adminEmail := "admin@example.com"
	isAdminTrue := true
	reqBodyMap := map[string]interface{}{"isAdmin": &isAdminTrue}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//update", bytes.NewReader(jsonBody))

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email parameter required", httpErr.Message)

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
	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))
	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
	mockDB.ExpectExec(`UPDATE users SET is_approved = \? WHERE email = \?`).
		WithArgs(false, targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mockDB.ExpectExec("INSERT INTO admin_logs \\(admin_email, action, target_email, details\\) VALUES \\(\\?, \\?, \\?, \\?\\)").
		WithArgs(adminEmail, "update_user", targetUserEmail, "Updated fields: isApproved: false").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mockDB.ExpectCommit()

	err := UpdateUser(c)
	require.NoError(t, err)

	// Since token deletion now happens in a goroutine, we can't reliably mock it here in a simple unit test.
	// We'll trust the handler calls it and test token deletion's effect in an integration test.
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "User updated successfully", resp["message"])
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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminEmail, "userpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

	err := UpdateUser(c)
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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error"))

	err := UpdateUser(c)
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

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//update", bytes.NewReader(jsonBody))

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email parameter required", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_SelfRevocation tests admin trying to revoke own access.
func TestUpdateUser_RevokeAccess_SelfRevocation(t *testing.T) {
	adminEmail := "admin@example.com"
	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse}
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(adminEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	// Expect the transaction to start, then immediately get rolled back due to the error
	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(adminEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
	mockDB.ExpectRollback()

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Admins cannot revoke their own approval status.", httpErr.Message)

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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	revokeSQL := `UPDATE users SET is_approved = \? WHERE email = \?`
	mockDB.ExpectExec(revokeSQL).
		WithArgs(false, targetUserEmail).
		WillReturnError(fmt.Errorf("DB error during revocation"))

	mockDB.ExpectRollback()

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to update approval status", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestUpdateUser_RevokeAccess_SimulateTokenDeleteError - This test is more for a RevokeUserAccess handler that includes token deletion.
func TestUpdateUser_RevokeAccess_SimulateTokenDeleteError(t *testing.T) {
	adminEmail := "admin@example.com"
	targetUserEmail := "target@example.com"
	var logBuf bytes.Buffer
	originalErrorLogger := logging.ErrorLogger
	logging.ErrorLogger = log.New(&logBuf, "ERROR: ", 0)
	defer func() { logging.ErrorLogger = originalErrorLogger }()

	isApprovedFalse := false
	reqBodyMap := map[string]interface{}{"isApproved": &isApprovedFalse} // Update body for UpdateUser
	jsonBody, _ := json.Marshal(reqBodyMap)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/update", bytes.NewReader(jsonBody)) // Use UpdateUser endpoint
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectBegin()
	mockDB.ExpectQuery("SELECT 1 FROM users WHERE email = ?").WithArgs(targetUserEmail).WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	// UpdateUser sets is_approved - simulate this failing
	updateSQL := `UPDATE users SET is_approved = \? WHERE email = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(false, targetUserEmail).
		WillReturnError(fmt.Errorf("DB error updating approval status"))

	mockDB.ExpectRollback()

	err := UpdateUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to update approval status", httpErr.Message)

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
	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	// Define user data with specific registration dates for deterministic ordering.
	regDateUser2 := time.Now()
	regDateAdmin := time.Now().Add(-24 * time.Hour)
	regDateUser1 := time.Now().Add(-48 * time.Hour)

	userRows := sqlmock.NewRows([]string{"email", "is_approved", "is_admin", "storage_limit_bytes", "total_storage_bytes", "registration_date", "last_login"}).
		AddRow(user2Email, false, false, models.DefaultStorageLimit, int64(0), regDateUser2, sql.NullTime{Valid: false}).
		AddRow(adminEmail, true, true, int64(10*1024*1024*1024), int64(1*1024*1024*1024), regDateAdmin, sql.NullTime{Time: time.Now(), Valid: true}).
		AddRow(user1Email, true, false, int64(5*1024*1024*1024), int64(500*1024*1024), regDateUser1, sql.NullTime{})

	mockDB.ExpectQuery(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnRows(userRows)
	mockDB.ExpectExec("INSERT INTO admin_logs \\(admin_email, action, target_email, details\\) VALUES \\(\\?, \\?, \\?, \\?\\)").
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
	assert.Len(t, usersList, 2)

	// Assert based on the correct order (user2, user1) - admin is filtered out
	user2, ok := usersList[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, user2Email, user2["email"])
	assert.False(t, user2["isApproved"].(bool))
	assert.Equal(t, "0 B", user2["totalStorageReadable"])
	assert.InDelta(t, 0.0, user2["usagePercent"], 0.01)
	assert.Empty(t, user2["lastLogin"])

	user1, ok := usersList[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, user1Email, user1["email"])
	assert.True(t, user1["isApproved"].(bool))
	assert.False(t, user1["isAdmin"].(bool))
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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminEmail, "userpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

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
		SELECT id, email, password_hash, password_salt, created_at,
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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

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
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	userRows := sqlmock.NewRows([]string{"email", "is_approved", "is_admin", "storage_limit_bytes", "total_storage_bytes", "registration_date", "last_login"}).
		AddRow("scanerror@example.com", "not-a-bool", false, int64(1024), int64(0), time.Now(), sql.NullTime{})

	mockDB.ExpectQuery(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnRows(userRows)

	err := ListUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Error processing user data", httpErr.Message)

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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	// Simulate sql.ErrNoRows for the user list query
	mockDB.ExpectQuery(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`).WillReturnError(sql.ErrNoRows)

	err := ListUsers(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	usersList, ok := resp["users"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, usersList, 0, "Users list should be empty")

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_Forbidden_NonAdmin tests access denial for non-admin users.
func TestGetPendingUsers_Forbidden_NonAdmin(t *testing.T) {
	nonAdminEmail := "user@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	nonAdminClaims := &auth.Claims{Email: nonAdminEmail}
	nonAdminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, nonAdminClaims)
	c.Set("user", nonAdminToken)

	nonAdminUserRows := sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, nonAdminEmail, "hashedpassword", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false)
	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnError(fmt.Errorf("DB error"))

	err := GetPendingUsers(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	assert.Equal(t, "Failed to get user", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestGetPendingUsers_GetPendingError tests DB error when fetching pending users list.
func TestGetPendingUsers_GetPendingError(t *testing.T) {
	adminEmail := "admin@example.com"
	c, _, mockDB, _ := setupTestEnv(t, http.MethodGet, "/admin/users/pending", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	adminUserRows := sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
		AddRow(1, adminEmail, "hashedpassword", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true)
	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(adminUserRows)

	mockDB.ExpectQuery(`
		SELECT id, email, created_at, total_storage_bytes, storage_limit_bytes
		FROM users
		WHERE is_approved = false
		ORDER BY created_at ASC`).
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

	// Set admin email in environment for isAdminEmail check
	cleanup := setupAdminEnv(adminEmail)
	defer cleanup()
	targetUserEmail := "target@example.com"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(targetUserEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, targetUserEmail, "targetpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, false, sql.NullString{}, sql.NullTime{}, false))

	mockDB.ExpectExec(`UPDATE users SET is_approved = true, approved_by = \?, approved_at = \? WHERE id = \?`).
		WithArgs(adminEmail, sqlmock.AnyArg(), 2).
		WillReturnResult(sqlmock.NewResult(1, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_email, action, target_email, details\) VALUES \(\?, \?, \?, \?\)`
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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminEmail, "userpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(targetUserEmail).WillReturnError(fmt.Errorf("DB error fetching target"))

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	assert.Equal(t, "User not found", httpErr.Message)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestApproveUser_ApproveModelError tests error during user.ApproveUser model method.
func TestApproveUser_ApproveModelError(t *testing.T) {
	adminEmail := "admin@example.com"

	// Set admin email in environment for isAdminEmail check
	cleanup := setupAdminEnv(adminEmail)
	defer cleanup()
	targetUserEmail := "target@example.com"

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/:email", nil)
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(targetUserEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(2, targetUserEmail, "targetpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, false, sql.NullString{}, sql.NullTime{}, false))

	mockDB.ExpectExec(`UPDATE users SET is_approved = true, approved_by = \?, approved_at = \? WHERE id = \?`).
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

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPost, "/admin/users/approve/", nil)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := ApproveUser(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email parameter required", httpErr.Message)

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

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	updateSQL := `UPDATE users SET storage_limit_bytes = \? WHERE email = \?`
	mockDB.ExpectExec(updateSQL).
		WithArgs(newLimit, targetUserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	logAdminActionSQL := `INSERT INTO admin_logs \(admin_email, action, target_email, details\) VALUES \(\?, \?, \?, \?\)`
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
				SELECT id, email, password_hash, password_salt, created_at,
					   total_storage_bytes, storage_limit_bytes,
					   is_approved, approved_by, approved_at, is_admin
				FROM users WHERE email = ?`).WithArgs(nonAdminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, nonAdminEmail, "userpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, false))

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
		SELECT id, email, password_hash, password_salt, created_at,
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

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users//storage-limit", bytes.NewReader(jsonBody))

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

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
	jsonBody := []byte(`{"storage_limit_bytes": "not-a-number"`)

	c, _, mockDB, _ := setupTestEnv(t, http.MethodPut, "/admin/users/:email/storage-limit", bytes.NewReader(jsonBody))
	c.SetParamNames("email")
	c.SetParamValues(targetUserEmail)

	adminClaims := &auth.Claims{Email: adminEmail}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	err := UpdateUserStorageLimit(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Invalid request", httpErr.Message)

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
				SELECT id, email, password_hash, password_salt, created_at,
					   total_storage_bytes, storage_limit_bytes,
					   is_approved, approved_by, approved_at, is_admin
				FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
				sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
					AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

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
		SELECT id, email, password_hash, password_salt, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`).WithArgs(adminEmail).WillReturnRows(
		sqlmock.NewRows([]string{"id", "email", "password_hash", "password_salt", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, adminEmail, "adminpass", nil, time.Now(), int64(0), models.DefaultStorageLimit, true, sql.NullString{}, sql.NullTime{}, true))

	updateSQL := `UPDATE users SET storage_limit_bytes = \? WHERE email = \?`
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
