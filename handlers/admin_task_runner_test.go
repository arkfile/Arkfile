package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
