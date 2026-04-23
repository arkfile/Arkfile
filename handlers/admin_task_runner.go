package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
)

// TaskRunner manages background copy tasks with concurrency control and cancellation.
type TaskRunner struct {
	mu          sync.RWMutex
	activeTasks map[string]context.CancelFunc // task_id -> cancel function
	semaphore   chan struct{}                 // limits concurrent tasks
}

// Global task runner instance, initialized on server startup.
var taskRunner *TaskRunner

// InitTaskRunner creates the global task runner. Called from main.go on startup.
func InitTaskRunner(maxWorkers int) {
	if maxWorkers <= 0 {
		maxWorkers = 2 // default concurrency for copy tasks
	}
	taskRunner = &TaskRunner{
		activeTasks: make(map[string]context.CancelFunc),
		semaphore:   make(chan struct{}, maxWorkers),
	}
	log.Printf("Task runner initialized (max workers: %d)", maxWorkers)
}

// GetTaskRunner returns the global task runner.
func GetTaskRunner() *TaskRunner {
	return taskRunner
}

// CancelTask requests cancellation of a running task.
func (tr *TaskRunner) CancelTask(taskID string) bool {
	tr.mu.RLock()
	cancel, ok := tr.activeTasks[taskID]
	tr.mu.RUnlock()
	if ok {
		cancel()
		return true
	}
	return false
}

// CopyTaskDetails holds the JSON-serializable details stored in admin_tasks.details.
type CopyTaskDetails struct {
	SourceProviderID string `json:"source_provider_id"`
	DestProviderID   string `json:"destination_provider_id"`
	Verify           bool   `json:"verify"`
	SkipExisting     bool   `json:"skip_existing"`
	Username         string `json:"username,omitempty"` // set for copy-user-files
	FilesCopied      int    `json:"files_copied"`
	FilesSkipped     int    `json:"files_skipped"`
	FilesFailed      int    `json:"files_failed"`
	BytesCopied      int64  `json:"bytes_copied"`
}

// CopyTaskRequest describes a copy operation submitted by an admin API handler.
type CopyTaskRequest struct {
	TaskType      string // "copy-all", "copy-user-files", "copy-file"
	AdminUsername string
	SourceID      string
	DestID        string
	Verify        bool
	SkipExisting  bool
	Username      string // only for copy-user-files
	FileID        string // only for copy-file
}

// SubmitCopyTask creates an admin_tasks row, then runs the copy in a background goroutine.
// Returns the task ID immediately.
func (tr *TaskRunner) SubmitCopyTask(req CopyTaskRequest) (string, error) {
	source := storage.Registry.GetProvider(req.SourceID)
	if source == nil {
		return "", fmt.Errorf("source provider %s not found", req.SourceID)
	}
	dest := storage.Registry.GetProvider(req.DestID)
	if dest == nil {
		return "", fmt.Errorf("destination provider %s not found", req.DestID)
	}

	// Build list of files to copy
	var files []fileCopyItem
	var err error

	switch req.TaskType {
	case "copy-file":
		files, err = buildSingleFileCopyList(req.FileID)
	case "copy-user-files":
		files, err = buildUserFileCopyList(req.Username)
	case "copy-all":
		files, err = buildAllFileCopyList()
	default:
		return "", fmt.Errorf("unknown task type: %s", req.TaskType)
	}
	if err != nil {
		return "", fmt.Errorf("failed to build file list: %w", err)
	}

	taskID, err := models.CreateAdminTask(database.DB, req.TaskType, req.AdminUsername, len(files))
	if err != nil {
		return "", fmt.Errorf("failed to create task record: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tr.mu.Lock()
	tr.activeTasks[taskID] = cancel
	tr.mu.Unlock()

	go tr.runCopyTask(ctx, taskID, req, source, dest, files)

	return taskID, nil
}

// fileCopyItem is a file to be copied between providers.
type fileCopyItem struct {
	FileID     string
	StorageID  string
	PaddedSize int64
}

func buildSingleFileCopyList(fileID string) ([]fileCopyItem, error) {
	var storageID string
	var paddedSizeRaw interface{}
	err := database.DB.QueryRow(
		"SELECT storage_id, padded_size FROM file_metadata WHERE file_id = ?", fileID,
	).Scan(&storageID, &paddedSizeRaw)
	if err != nil {
		return nil, err
	}
	paddedSize := toInt64FromInterface(paddedSizeRaw)
	return []fileCopyItem{{FileID: fileID, StorageID: storageID, PaddedSize: paddedSize}}, nil
}

func buildUserFileCopyList(username string) ([]fileCopyItem, error) {
	rows, err := database.DB.Query(
		"SELECT file_id, storage_id, padded_size FROM file_metadata WHERE owner_username = ?", username,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFileCopyItems(rows)
}

func buildAllFileCopyList() ([]fileCopyItem, error) {
	rows, err := database.DB.Query("SELECT file_id, storage_id, padded_size FROM file_metadata")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFileCopyItems(rows)
}

func scanFileCopyItems(rows *sql.Rows) ([]fileCopyItem, error) {
	var items []fileCopyItem
	for rows.Next() {
		var item fileCopyItem
		var paddedSizeRaw interface{}
		if err := rows.Scan(&item.FileID, &item.StorageID, &paddedSizeRaw); err != nil {
			return nil, err
		}
		item.PaddedSize = toInt64FromInterface(paddedSizeRaw)
		items = append(items, item)
	}
	return items, rows.Err()
}

// toInt64FromInterface converts rqlite numeric types to int64.
func toInt64FromInterface(v interface{}) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case float64:
		return int64(val)
	case nil:
		return 0
	default:
		return 0
	}
}

// runCopyTask is the background goroutine that performs the copy work.
func (tr *TaskRunner) runCopyTask(
	ctx context.Context,
	taskID string,
	req CopyTaskRequest,
	source, dest storage.ObjectStorageProvider,
	files []fileCopyItem,
) {
	// Acquire semaphore slot
	tr.semaphore <- struct{}{}
	defer func() { <-tr.semaphore }()

	// Clean up active task tracking when done
	defer func() {
		tr.mu.Lock()
		delete(tr.activeTasks, taskID)
		tr.mu.Unlock()
	}()

	// Mark task as running
	if err := models.StartAdminTask(database.DB, taskID); err != nil {
		logging.ErrorLogger.Printf("Task %s: failed to mark as running: %v", taskID, err)
		return
	}

	details := CopyTaskDetails{
		SourceProviderID: req.SourceID,
		DestProviderID:   req.DestID,
		Verify:           req.Verify,
		SkipExisting:     req.SkipExisting,
		Username:         req.Username,
	}

	for i, file := range files {
		// Check for cancellation between files
		if ctx.Err() != nil {
			models.UpdateAdminTaskStatus(database.DB, taskID, "canceled")
			logging.InfoLogger.Printf("Task %s: canceled at file %d/%d", taskID, i, len(files))
			return
		}

		// Skip if already active on destination
		if req.SkipExisting {
			locs, _ := models.GetActiveFileStorageLocations(database.DB, file.FileID)
			alreadyExists := false
			for _, loc := range locs {
				if loc.ProviderID == req.DestID {
					alreadyExists = true
					break
				}
			}
			if alreadyExists {
				details.FilesSkipped++
				models.UpdateAdminTaskProgress(database.DB, taskID, i+1)
				continue
			}
		}

		// Insert pending location
		models.InsertFileStorageLocation(database.DB, file.FileID, req.DestID, file.StorageID, "pending")

		// Perform the copy
		copyHash, copyErr := storage.Registry.CopyObjectBetweenProviders(
			ctx, file.StorageID, source, dest, file.PaddedSize,
		)

		if copyErr != nil {
			logging.ErrorLogger.Printf("Task %s: copy failed for file %s: %v", taskID, file.FileID, copyErr)
			models.UpdateFileStorageLocationStatus(database.DB, file.FileID, req.DestID, "failed")
			details.FilesFailed++
			models.UpdateAdminTaskProgress(database.DB, taskID, i+1)
			continue
		}

		// Verify hash if requested and available
		if req.Verify {
			var expectedHash sql.NullString
			database.DB.QueryRow(
				"SELECT stored_blob_sha256sum FROM file_metadata WHERE file_id = ?", file.FileID,
			).Scan(&expectedHash)

			if expectedHash.Valid && expectedHash.String != "" && copyHash != expectedHash.String {
				logging.ErrorLogger.Printf("Task %s: hash mismatch for file %s (expected %s, got %s)",
					taskID, file.FileID, expectedHash.String, copyHash)
				models.UpdateFileStorageLocationStatus(database.DB, file.FileID, req.DestID, "failed")
				details.FilesFailed++
				models.UpdateAdminTaskProgress(database.DB, taskID, i+1)
				continue
			}
		}

		// Mark location as active and update stats
		models.UpdateFileStorageLocationStatus(database.DB, file.FileID, req.DestID, "active")
		models.IncrementStorageProviderStats(database.DB, req.DestID, 1, file.PaddedSize)
		details.FilesCopied++
		details.BytesCopied += file.PaddedSize
		models.UpdateAdminTaskProgress(database.DB, taskID, i+1)
	}

	// Complete the task
	detailsJSON, _ := json.Marshal(details)
	if err := models.CompleteAdminTask(database.DB, taskID, string(detailsJSON)); err != nil {
		logging.ErrorLogger.Printf("Task %s: failed to mark complete: %v", taskID, err)
	}

	logging.InfoLogger.Printf("Task %s: completed (copied: %d, skipped: %d, failed: %d, bytes: %d)",
		taskID, details.FilesCopied, details.FilesSkipped, details.FilesFailed, details.BytesCopied)
}
