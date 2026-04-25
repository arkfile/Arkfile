package models

import (
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAdminTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`INSERT INTO admin_tasks`).
		WithArgs(sqlmock.AnyArg(), "copy-all", "admin-user", 100).
		WillReturnResult(sqlmock.NewResult(1, 1))

	taskID, err := CreateAdminTask(db, "copy-all", "admin-user", 100)
	assert.NoError(t, err)
	assert.NotEmpty(t, taskID)
	// UUID format: 8-4-4-4-12
	assert.Len(t, taskID, 36)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateAdminTask_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`INSERT INTO admin_tasks`).
		WithArgs(sqlmock.AnyArg(), "copy-file", "admin-user", 1).
		WillReturnError(assert.AnError)

	taskID, err := CreateAdminTask(db, "copy-file", "admin-user", 1)
	assert.Error(t, err)
	assert.Empty(t, taskID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetAdminTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	rows := sqlmock.NewRows([]string{
		"task_id", "task_type", "status", "admin_username", "progress_current", "progress_total",
		"started_at", "completed_at", "error_message", "details", "created_at", "updated_at",
	}).AddRow(
		"task-123", "copy-all", "running", "admin-user", 25, 100,
		"2026-01-01 10:00:00", nil, nil, `{"source_provider_id":"prov-1"}`,
		"2026-01-01 09:00:00", "2026-01-01 10:05:00",
	)

	mock.ExpectQuery(`SELECT task_id, task_type, status, admin_username, progress_current, progress_total`).
		WithArgs("task-123").
		WillReturnRows(rows)

	task, err := GetAdminTask(db, "task-123")
	assert.NoError(t, err)
	require.NotNil(t, task)
	assert.Equal(t, "task-123", task.TaskID)
	assert.Equal(t, "copy-all", task.TaskType)
	assert.Equal(t, "running", task.Status)
	assert.Equal(t, "admin-user", task.AdminUsername)
	assert.Equal(t, 25, task.ProgressCurrent)
	assert.Equal(t, 100, task.ProgressTotal)
	assert.True(t, task.StartedAt.Valid)
	assert.False(t, task.CompletedAt.Valid)
	assert.False(t, task.ErrorMessage.Valid)
	assert.True(t, task.Details.Valid)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetAdminTask_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT task_id, task_type, status, admin_username, progress_current, progress_total`).
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	task, err := GetAdminTask(db, "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, task)
	assert.Equal(t, sql.ErrNoRows, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateAdminTaskStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE admin_tasks SET status = \?`).
		WithArgs("completed", "task-123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = UpdateAdminTaskStatus(db, "task-123", "completed")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateAdminTaskProgress(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE admin_tasks SET progress_current = \?`).
		WithArgs(50, "task-123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = UpdateAdminTaskProgress(db, "task-123", 50)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateAdminTaskDetails(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	detailsJSON := `{"files_copied":10,"bytes_copied":1048576}`
	mock.ExpectExec(`UPDATE admin_tasks SET details = \?`).
		WithArgs(detailsJSON, "task-123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = UpdateAdminTaskDetails(db, "task-123", detailsJSON)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStartAdminTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE admin_tasks SET status = 'running', started_at = CURRENT_TIMESTAMP`).
		WithArgs("task-123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = StartAdminTask(db, "task-123")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCompleteAdminTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	details := `{"files_copied":100,"bytes_copied":10485760}`
	mock.ExpectExec(`UPDATE admin_tasks SET status = 'completed', completed_at = CURRENT_TIMESTAMP, details = \?`).
		WithArgs(details, "task-123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = CompleteAdminTask(db, "task-123", details)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestFailAdminTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE admin_tasks SET status = 'failed', completed_at = CURRENT_TIMESTAMP, error_message = \?`).
		WithArgs("copy operation failed: network error", "task-123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = FailAdminTask(db, "task-123", "copy operation failed: network error")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMarkStaleTasksAsFailed(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE admin_tasks`).
		WillReturnResult(sqlmock.NewResult(0, 3))

	affected, err := MarkStaleTasksAsFailed(db)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), affected)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMarkStaleTasksAsFailed_NoStaleTasks(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE admin_tasks`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	affected, err := MarkStaleTasksAsFailed(db)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), affected)
	assert.NoError(t, mock.ExpectationsWereMet())
}
