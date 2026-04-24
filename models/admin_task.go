package models

import (
	"database/sql"

	"github.com/google/uuid"
)

// AdminTask represents a row in the admin_tasks table.
// Tracks background task progress for long-running admin operations.
type AdminTask struct {
	TaskID          string         `json:"task_id"`
	TaskType        string         `json:"task_type"` // "copy-all", "copy-user-files", "copy-file"
	Status          string         `json:"status"`    // "pending", "running", "completed", "failed", "canceled"
	AdminUsername   string         `json:"admin_username"`
	ProgressCurrent int            `json:"progress_current"`
	ProgressTotal   int            `json:"progress_total"`
	StartedAt       sql.NullString `json:"started_at"`
	CompletedAt     sql.NullString `json:"completed_at"`
	ErrorMessage    sql.NullString `json:"error_message"`
	Details         sql.NullString `json:"details"` // JSON text for task-specific metadata
	CreatedAt       sql.NullString `json:"created_at"`
	UpdatedAt       sql.NullString `json:"updated_at"`
}

// CreateAdminTask inserts a new admin task record and returns the generated task ID.
func CreateAdminTask(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, taskType, adminUsername string, progressTotal int) (string, error) {
	taskID := uuid.New().String()
	_, err := db.Exec(`
		INSERT INTO admin_tasks (task_id, task_type, status, admin_username, progress_total)
		VALUES (?, ?, 'pending', ?, ?)`,
		taskID, taskType, adminUsername, progressTotal,
	)
	if err != nil {
		return "", err
	}
	return taskID, nil
}

// GetAdminTask retrieves an admin task by its ID.
func GetAdminTask(db interface {
	QueryRow(string, ...interface{}) *sql.Row
}, taskID string) (*AdminTask, error) {
	t := &AdminTask{}
	err := db.QueryRow(`
		SELECT task_id, task_type, status, admin_username, progress_current, progress_total,
		       started_at, completed_at, error_message, details, created_at, updated_at
		FROM admin_tasks WHERE task_id = ?`, taskID,
	).Scan(
		&t.TaskID, &t.TaskType, &t.Status, &t.AdminUsername, &t.ProgressCurrent, &t.ProgressTotal,
		&t.StartedAt, &t.CompletedAt, &t.ErrorMessage, &t.Details, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// UpdateAdminTaskStatus updates the status of a task.
func UpdateAdminTaskStatus(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, taskID, status string) error {
	_, err := db.Exec(`
		UPDATE admin_tasks SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE task_id = ?`,
		status, taskID,
	)
	return err
}

// UpdateAdminTaskProgress updates the progress counters of a task.
func UpdateAdminTaskProgress(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, taskID string, progressCurrent int) error {
	_, err := db.Exec(`
		UPDATE admin_tasks SET progress_current = ?, updated_at = CURRENT_TIMESTAMP WHERE task_id = ?`,
		progressCurrent, taskID,
	)
	return err
}

// UpdateAdminTaskDetails updates the details JSON field of a task (used for live progress).
func UpdateAdminTaskDetails(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, taskID string, details string) error {
	_, err := db.Exec(`
		UPDATE admin_tasks SET details = ?, updated_at = CURRENT_TIMESTAMP WHERE task_id = ?`,
		details, taskID,
	)
	return err
}

// StartAdminTask marks a task as running with a started_at timestamp.
func StartAdminTask(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, taskID string) error {
	_, err := db.Exec(`
		UPDATE admin_tasks SET status = 'running', started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE task_id = ?`, taskID,
	)
	return err
}

// CompleteAdminTask marks a task as completed with final details.
func CompleteAdminTask(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, taskID string, details string) error {
	_, err := db.Exec(`
		UPDATE admin_tasks SET status = 'completed', completed_at = CURRENT_TIMESTAMP, details = ?, updated_at = CURRENT_TIMESTAMP
		WHERE task_id = ?`, details, taskID,
	)
	return err
}

// FailAdminTask marks a task as failed with an error message.
func FailAdminTask(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, taskID string, errorMessage string) error {
	_, err := db.Exec(`
		UPDATE admin_tasks SET status = 'failed', completed_at = CURRENT_TIMESTAMP, error_message = ?, updated_at = CURRENT_TIMESTAMP
		WHERE task_id = ?`, errorMessage, taskID,
	)
	return err
}

// MarkStaleTasksAsFailed finds tasks stuck in "running" status (from a previous server crash)
// and marks them as failed. Called on server startup.
func MarkStaleTasksAsFailed(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}) (int64, error) {
	result, err := db.Exec(`
		UPDATE admin_tasks
		SET status = 'failed', error_message = 'Server restarted while task was running', completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE status = 'running'`,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
