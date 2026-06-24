package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/storage"
)

// TestTaskRunner_ConcurrencyLimit verifies that the semaphore channel capacity
// matches the configured maxWorkers, and that maxWorkers=0 defaults to 2.
func TestTaskRunner_ConcurrencyLimit(t *testing.T) {
	// Save and restore global taskRunner
	original := taskRunner
	t.Cleanup(func() { taskRunner = original })

	// Default: maxWorkers=0 should default to 2
	InitTaskRunner(0)
	tr := GetTaskRunner()
	require.NotNil(t, tr)
	assert.Equal(t, 2, cap(tr.semaphore))

	// Explicit: maxWorkers=5
	InitTaskRunner(5)
	tr = GetTaskRunner()
	require.NotNil(t, tr)
	assert.Equal(t, 5, cap(tr.semaphore))

	// Negative: maxWorkers=-1 should default to 2
	InitTaskRunner(-1)
	tr = GetTaskRunner()
	require.NotNil(t, tr)
	assert.Equal(t, 2, cap(tr.semaphore))
}

// TestTaskRunner_CancelTask_Success verifies that CancelTask invokes the
// registered cancel function and returns true for an active task.
func TestTaskRunner_CancelTask_Success(t *testing.T) {
	original := taskRunner
	t.Cleanup(func() { taskRunner = original })

	InitTaskRunner(2)
	tr := GetTaskRunner()
	require.NotNil(t, tr)

	// Simulate an active task by registering a cancel function directly
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tr.mu.Lock()
	tr.activeTasks["test-task-123"] = cancel
	tr.mu.Unlock()

	// CancelTask should find it and call cancel
	result := tr.CancelTask("test-task-123")
	assert.True(t, result)

	// Verify the context was actually canceled
	assert.Error(t, ctx.Err())
	assert.Equal(t, context.Canceled, ctx.Err())
}

// TestTaskRunner_CancelTask_NotFound verifies that CancelTask returns false
// for a task ID that is not in the active tasks map.
func TestTaskRunner_CancelTask_NotFound(t *testing.T) {
	original := taskRunner
	t.Cleanup(func() { taskRunner = original })

	InitTaskRunner(2)
	tr := GetTaskRunner()
	require.NotNil(t, tr)

	result := tr.CancelTask("nonexistent-task")
	assert.False(t, result)
}

// TestGetTaskRunner_BeforeAndAfterInit verifies that GetTaskRunner returns nil
// before initialization and the runner after InitTaskRunner is called.
func TestGetTaskRunner_BeforeAndAfterInit(t *testing.T) {
	original := taskRunner
	t.Cleanup(func() { taskRunner = original })

	// Reset to nil
	taskRunner = nil
	assert.Nil(t, GetTaskRunner())

	// Initialize
	InitTaskRunner(3)
	tr := GetTaskRunner()
	assert.NotNil(t, tr)
	assert.Equal(t, 3, cap(tr.semaphore))
}

// TestTaskRunner_ActiveTasksMapInitialized verifies that the activeTasks map
// is properly initialized and empty after creation.
func TestTaskRunner_ActiveTasksMapInitialized(t *testing.T) {
	original := taskRunner
	t.Cleanup(func() { taskRunner = original })

	InitTaskRunner(2)
	tr := GetTaskRunner()
	require.NotNil(t, tr)

	tr.mu.RLock()
	defer tr.mu.RUnlock()
	assert.NotNil(t, tr.activeTasks)
	assert.Empty(t, tr.activeTasks)
}

// TestAbortStaleMultipartUploads_Success verifies that stale multipart uploads are aborted and cleared.
func TestAbortStaleMultipartUploads_Success(t *testing.T) {
	db, mockDB, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	originalDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = originalDB })

	// Set up registry and Mock Storage
	originalRegistry := storage.Registry
	t.Cleanup(func() { storage.Registry = originalRegistry })

	mockPrimary := &storage.MockObjectStorageProvider{}
	storage.Registry = storage.NewProviderRegistry(mockPrimary, "mock-primary")

	// Set up expected database queries
	rows := sqlmock.NewRows([]string{"id", "storage_id", "storage_upload_id"}).
		AddRow("session-123", "stor-123", "upload-abc")
	mockDB.ExpectQuery(`SELECT id, storage_id, storage_upload_id`).
		WillReturnRows(rows)

	mockPrimary.On("AbortMultipartUpload", mock.Anything, "stor-123", "upload-abc").Return(nil)

	mockDB.ExpectExec(`UPDATE upload_sessions SET storage_upload_id = NULL WHERE id = \?`).
		WithArgs("session-123").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Manually run abortAbandonedMultipartUploads
	abortAbandonedMultipartUploads(context.Background())

	assert.NoError(t, mockDB.ExpectationsWereMet())
	mockPrimary.AssertExpectations(t)
}

// TestGarbageCollectOrphanedStorageObjects_Success verifies that unreferenced storage objects are garbage collected.
func TestGarbageCollectOrphanedStorageObjects_Success(t *testing.T) {
	db, mockDB, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	originalDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = originalDB })

	originalRegistry := storage.Registry
	t.Cleanup(func() { storage.Registry = originalRegistry })

	mockPrimary := &storage.MockObjectStorageProvider{}
	storage.Registry = storage.NewProviderRegistry(mockPrimary, "mock-primary")

	// 1. Query for file_metadata
	metaRows := sqlmock.NewRows([]string{"storage_id"}).AddRow("referenced-meta-123")
	mockDB.ExpectQuery(`SELECT DISTINCT storage_id FROM file_metadata`).
		WillReturnRows(metaRows)

	// 2. Query for upload_sessions
	sessRows := sqlmock.NewRows([]string{"storage_id"}).AddRow("referenced-sess-456")
	mockDB.ExpectQuery(`SELECT DISTINCT storage_id FROM upload_sessions`).
		WillReturnRows(sessRows)

	// Mock S3 responses
	// ListObjects returns a referenced key and an orphaned key
	mockPrimary.On("ListObjects", mock.Anything).Return([]string{"referenced-meta-123", "orphaned-999"}, nil)

	// GetObject for the orphaned key to perform Stat
	mockObj := &storage.MockStoredObject{}
	mockObj.SetStatInfo(storage.ObjectInfo{
		Size:         500,
		LastModified: time.Now().Add(-2 * time.Hour), // Older than 1 hour -> should be deleted
	}, nil)

	mockPrimary.On("GetObject", mock.Anything, "orphaned-999", mock.Anything).Return(mockObj, nil)
	mockObj.On("Close").Return(nil)

	// Orphaned key should be removed
	mockPrimary.On("RemoveObject", mock.Anything, "orphaned-999", mock.Anything).Return(nil)

	// Run cleanup
	removeOrphanedStorageObjects(context.Background())

	assert.NoError(t, mockDB.ExpectationsWereMet())
	mockPrimary.AssertExpectations(t)
}
