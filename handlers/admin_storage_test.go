package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/storage"
)

// TestAdminStorageStatus_SingleProvider tests the storage status endpoint with a single provider.
func TestAdminStorageStatus_SingleProvider(t *testing.T) {
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/admin/storage/status", nil)

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock storage_providers query (single provider)
	providerRows := sqlmock.NewRows([]string{
		"provider_id", "provider_type", "bucket_name", "endpoint", "region", "role", "env_var_prefix",
		"is_active", "total_objects", "total_size_bytes", "cost_per_tb_cents", "last_verified_at",
	}).AddRow(
		"seaweedfs-local", "seaweedfs", "arkfile", "http://localhost:8333", "", "primary", "SEAWEEDFS",
		true, int64(50), int64(1048576), nil, nil,
	)
	mockDB.ExpectQuery(`SELECT provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix`).
		WillReturnRows(providerRows)

	// Mock total files count
	mockDB.ExpectQuery(`SELECT COUNT\(\*\) FROM file_metadata`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(50)))

	err := AdminStorageStatus(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Storage status retrieved", resp["message"])

	data := resp["data"].(map[string]interface{})
	assert.Equal(t, false, data["replication_enabled"])
	assert.Equal(t, float64(50), data["total_files"])

	providers := data["providers"].([]interface{})
	assert.Len(t, providers, 1)
	prov := providers[0].(map[string]interface{})
	assert.Equal(t, "seaweedfs-local", prov["provider_id"])
	assert.Equal(t, "primary", prov["role"])
	assert.Equal(t, float64(50), prov["total_objects"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminStorageStatus_MultiProvider tests storage status with two providers.
func TestAdminStorageStatus_MultiProvider(t *testing.T) {
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/admin/storage/status", nil)

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Set up secondary provider on registry
	mockSecondary := &storage.MockObjectStorageProvider{}
	storage.Registry.SetSecondary(mockSecondary, "wasabi-us-central-1")
	t.Cleanup(func() {
		storage.Registry.SetSecondary(nil, "")
	})

	// Mock storage_providers query (two providers)
	providerRows := sqlmock.NewRows([]string{
		"provider_id", "provider_type", "bucket_name", "endpoint", "region", "role", "env_var_prefix",
		"is_active", "total_objects", "total_size_bytes", "cost_per_tb_cents", "last_verified_at",
	}).
		AddRow("seaweedfs-local", "seaweedfs", "arkfile", "http://localhost:8333", "", "primary", "SEAWEEDFS",
			true, int64(100), int64(2097152), nil, nil).
		AddRow("wasabi-us-central-1", "wasabi", "arkfile-backup", "https://s3.wasabisys.com", "us-central-1", "secondary", "WASABI",
			true, int64(80), int64(1048576), int64(599), "2026-04-17 12:00:00")
	mockDB.ExpectQuery(`SELECT provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix`).
		WillReturnRows(providerRows)

	// Mock total files count
	mockDB.ExpectQuery(`SELECT COUNT\(\*\) FROM file_metadata`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(100)))

	// Mock replication gap count (multi-provider)
	mockDB.ExpectQuery(`SELECT COUNT\(\*\) FROM file_metadata fm`).
		WithArgs(2).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(80)))

	err := AdminStorageStatus(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	data := resp["data"].(map[string]interface{})
	providers := data["providers"].([]interface{})
	assert.Len(t, providers, 2)

	prov0 := providers[0].(map[string]interface{})
	assert.Equal(t, "seaweedfs-local", prov0["provider_id"])
	assert.Equal(t, "primary", prov0["role"])

	prov1 := providers[1].(map[string]interface{})
	assert.Equal(t, "wasabi-us-central-1", prov1["provider_id"])
	assert.Equal(t, "secondary", prov1["role"])
	assert.Equal(t, float64(599), prov1["cost_per_tb_cents"])
	assert.Equal(t, "2026-04-17 12:00:00", prov1["last_verified_at"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminSetPrimary_WrongTier tests promoting a tertiary provider directly to primary.
func TestAdminSetPrimary_WrongTier(t *testing.T) {
	reqBody := `{"provider_id":"tertiary-prov"}`
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/set-primary", bytes.NewReader([]byte(reqBody)))

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetStorageProviderRole returns "tertiary"
	mockDB.ExpectQuery(`SELECT role FROM storage_providers WHERE provider_id = \?`).
		WithArgs("tertiary-prov").
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("tertiary"))

	err := AdminSetPrimary(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Promote to secondary first")

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminSetPrimary_ProviderNotFound tests promoting a nonexistent provider.
func TestAdminSetPrimary_ProviderNotFound(t *testing.T) {
	reqBody := `{"provider_id":"nonexistent"}`
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/set-primary", bytes.NewReader([]byte(reqBody)))

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`SELECT role FROM storage_providers WHERE provider_id = \?`).
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	err := AdminSetPrimary(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminTaskStatus_ReturnsProgress tests task status retrieval with progress data.
func TestAdminTaskStatus_ReturnsProgress(t *testing.T) {
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/admin/storage/task/:taskId", nil)
	c.SetParamNames("taskId")
	c.SetParamValues("task-abc-123")

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock GetAdminTask query
	taskRows := sqlmock.NewRows([]string{
		"task_id", "task_type", "status", "admin_username", "progress_current", "progress_total",
		"started_at", "completed_at", "error_message", "details", "created_at", "updated_at",
	}).AddRow(
		"task-abc-123", "copy-all", "running", "admin-user", 45, 100,
		"2026-04-17 10:00:00", nil, nil,
		`{"source_provider_id":"primary-1","destination_provider_id":"secondary-1","files_copied":45,"bytes_copied":47185920}`,
		"2026-04-17 09:55:00", "2026-04-17 10:05:00",
	)
	mockDB.ExpectQuery(`SELECT task_id, task_type, status, admin_username, progress_current, progress_total`).
		WithArgs("task-abc-123").
		WillReturnRows(taskRows)

	err := AdminTaskStatus(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Task status retrieved", resp["message"])

	data := resp["data"].(map[string]interface{})
	assert.Equal(t, "task-abc-123", data["task_id"])
	assert.Equal(t, "copy-all", data["task_type"])
	assert.Equal(t, "running", data["status"])
	assert.Equal(t, float64(45), data["progress_current"])
	assert.Equal(t, float64(100), data["progress_total"])
	assert.Equal(t, "2026-04-17 10:00:00", data["started_at"])

	// Details should be parsed as JSON object
	details, ok := data["details"].(map[string]interface{})
	require.True(t, ok, "details should be a parsed JSON object")
	assert.Equal(t, "primary-1", details["source_provider_id"])
	assert.Equal(t, float64(45), details["files_copied"])

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminTaskStatus_NotFound tests task status for a nonexistent task.
func TestAdminTaskStatus_NotFound(t *testing.T) {
	c, rec, mockDB, _ := setupTestEnv(t, http.MethodGet, "/api/admin/storage/task/:taskId", nil)
	c.SetParamNames("taskId")
	c.SetParamValues("nonexistent-task")

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	mockDB.ExpectQuery(`SELECT task_id, task_type, status, admin_username, progress_current, progress_total`).
		WithArgs("nonexistent-task").
		WillReturnError(sql.ErrNoRows)

	err := AdminTaskStatus(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminVerifyStorage_Success tests the verify-storage endpoint with mocked S3 operations.
// RunVerification does PutObject -> GetObject -> hash verify -> RemoveObject on the provider.
func TestAdminVerifyStorage_Success(t *testing.T) {
	c, rec, mockDB, mockStorage := setupTestEnv(t, http.MethodPost, "/api/admin/system/verify-storage",
		bytes.NewReader([]byte(`{}`)))

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Mock provider_type lookup for primary
	mockDB.ExpectQuery(`SELECT provider_type FROM storage_providers WHERE provider_id = \?`).
		WithArgs("mock-test").
		WillReturnRows(sqlmock.NewRows([]string{"provider_type"}).AddRow("seaweedfs"))

	// RunVerification will call PutObject, GetObject, RemoveObject on the mock provider
	// PutObject: upload 1MB test data
	mockStorage.On("PutObject", mock.Anything, ".arkfile-verify-storage-test", mock.Anything, int64(1048576), mock.Anything).
		Return(storage.UploadInfo{}, nil).Once()

	// GetObject: download and verify
	testData := make([]byte, 1048576) // 1MB zeros matching RunVerification
	mockObj := &storage.MockStoredObject{}
	mockObj.Content = bytes.NewReader(testData)
	mockObj.On("Close").Return(nil)
	mockStorage.On("GetObject", mock.Anything, ".arkfile-verify-storage-test", storage.GetObjectOptions{}).
		Return(mockObj, nil).Once()

	// RemoveObject: cleanup
	mockStorage.On("RemoveObject", mock.Anything, ".arkfile-verify-storage-test", storage.RemoveObjectOptions{}).
		Return(nil).Once()

	// Mock last_verified_at update
	mockDB.ExpectExec(`UPDATE storage_providers SET last_verified_at`).
		WithArgs("mock-test").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := AdminVerifyStorage(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, true, resp["success"])
	assert.Equal(t, "Storage verification passed", resp["message"])

	data := resp["data"].(map[string]interface{})
	assert.Equal(t, true, data["verified"])
	assert.Equal(t, true, data["upload_ok"])
	assert.Equal(t, true, data["download_ok"])
	assert.Equal(t, true, data["hash_match_ok"])
	assert.Equal(t, true, data["delete_ok"])

	mockStorage.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminCancelTask_NotFound tests canceling a task that doesn't exist.
func TestAdminCancelTask_NotFound(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/cancel-task/:taskId", nil)
	c.SetParamNames("taskId")
	c.SetParamValues("nonexistent-task")

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Initialize task runner for this test
	originalRunner := taskRunner
	InitTaskRunner(2)
	t.Cleanup(func() {
		taskRunner = originalRunner
	})

	err := AdminCancelTask(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "not found or not running")
}

// TestAdminSwapProviders_NoSecondary tests swapping when no secondary is configured.
func TestAdminSwapProviders_NoSecondary(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/swap-providers", nil)

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Registry has no secondary (default from setupTestEnv)
	err := AdminSwapProviders(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "No secondary provider")
}

// TestAdminCopyFile_MissingFields tests copy-file with missing required fields.
func TestAdminCopyFile_MissingFields(t *testing.T) {
	reqBody := `{"file_id":"","source_provider_id":"","destination_provider_id":""}`
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/copy-file", bytes.NewReader([]byte(reqBody)))

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	err := AdminCopyFile(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "file_id, source_provider_id, and destination_provider_id are required")
}

// TestAdminCopyFile_NoTaskRunner tests copy-file when the task runner is not initialized.
func TestAdminCopyFile_NoTaskRunner(t *testing.T) {
	reqBody := `{"file_id":"file-123","source_provider_id":"prov-a","destination_provider_id":"prov-b"}`
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/copy-file", bytes.NewReader([]byte(reqBody)))

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	// Ensure task runner is nil
	originalRunner := taskRunner
	taskRunner = nil
	t.Cleanup(func() {
		taskRunner = originalRunner
	})

	err := AdminCopyFile(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "Task runner not initialized")
}

// TestAdminCopyAll_MissingFields tests copy-all with missing required fields.
func TestAdminCopyAll_MissingFields(t *testing.T) {
	reqBody := `{"source_provider_id":"","destination_provider_id":""}`
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/copy-all", bytes.NewReader([]byte(reqBody)))

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	err := AdminCopyAll(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "source_provider_id and destination_provider_id are required")
}

// TestAdminCopyUserFiles_MissingFields tests copy-user-files with missing required fields.
func TestAdminCopyUserFiles_MissingFields(t *testing.T) {
	reqBody := `{"username":"","source_provider_id":"prov-a","destination_provider_id":"prov-b"}`
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/admin/storage/copy-user-files", bytes.NewReader([]byte(reqBody)))

	adminClaims := &auth.Claims{Username: "admin-user"}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	err := AdminCopyUserFiles(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "username, source_provider_id, and destination_provider_id are required")
}
