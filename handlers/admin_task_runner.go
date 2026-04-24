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
	CurrentFileBytes int64  `json:"current_file_bytes"` // bytes copied for file in progress
	CurrentFileSize  int64  `json:"current_file_size"`  // total size of file in progress
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

	// persistDetails writes the current details snapshot to the DB so task-status
	// always reflects the latest state (skipped/copied/failed counts, byte progress).
	persistDetails := func() {
		detailsSnap, _ := json.Marshal(details)
		models.UpdateAdminTaskDetails(database.DB, taskID, string(detailsSnap))
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
				persistDetails()
				models.UpdateAdminTaskProgress(database.DB, taskID, i+1)
				continue
			}
		}

		// Insert pending location
		models.InsertFileStorageLocation(database.DB, file.FileID, req.DestID, file.StorageID, "pending")

		// Track current file progress for large file visibility
		details.CurrentFileBytes = 0
		details.CurrentFileSize = file.PaddedSize
		persistDetails()

		// Progress callback updates task details in DB after each multipart part
		onProgress := func(bytesCopied int64) {
			details.CurrentFileBytes = bytesCopied
			persistDetails()
		}

		// Perform the copy
		copyHash, copyErr := storage.Registry.CopyObjectBetweenProviders(
			ctx, file.StorageID, source, dest, file.PaddedSize, onProgress,
		)

		if copyErr != nil {
			logging.ErrorLogger.Printf("Task %s: copy failed for file %s: %v", taskID, file.FileID, copyErr)
			models.UpdateFileStorageLocationStatus(database.DB, file.FileID, req.DestID, "failed")
			details.FilesFailed++
			details.CurrentFileBytes = 0
			details.CurrentFileSize = 0
			persistDetails()
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
				details.CurrentFileBytes = 0
				details.CurrentFileSize = 0
				persistDetails()
				models.UpdateAdminTaskProgress(database.DB, taskID, i+1)
				continue
			}
		}

		// Mark location as active and update stats
		models.UpdateFileStorageLocationStatus(database.DB, file.FileID, req.DestID, "active")
		models.IncrementStorageProviderStats(database.DB, req.DestID, 1, file.PaddedSize)
		details.FilesCopied++
		details.BytesCopied += file.PaddedSize
		details.CurrentFileBytes = 0
		details.CurrentFileSize = 0
		persistDetails()
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

// VerifyTaskRequest describes a verify-all operation submitted by an admin API handler.
type VerifyTaskRequest struct {
	AdminUsername string
	ProviderID    string // empty means all providers
	Fix           bool   // if true, mark missing files as "missing" in DB
	Concurrency   int    // parallel HEAD requests (default 10)
}

// VerifyTaskDetails holds the JSON-serializable details stored in admin_tasks.details.
type VerifyTaskDetails struct {
	ProviderID   string `json:"provider_id,omitempty"` // empty means all providers
	Fix          bool   `json:"fix"`
	Concurrency  int    `json:"concurrency"`
	VerifiedOK   int    `json:"verified_ok"`
	Missing      int    `json:"missing"`
	SizeMismatch int    `json:"size_mismatch"`
	Errors       int    `json:"errors"`
}

// fileVerifyItem is a file location to verify.
type fileVerifyItem struct {
	FileID     string
	ProviderID string
	StorageID  string
	PaddedSize int64
}

// SubmitVerifyTask creates an admin_tasks row and runs the verification in background.
func (tr *TaskRunner) SubmitVerifyTask(req VerifyTaskRequest) (string, error) {
	if req.Concurrency <= 0 {
		req.Concurrency = 10
	}

	// Build list of file locations to verify
	var items []fileVerifyItem
	var err error

	if req.ProviderID != "" {
		// Verify only files on a specific provider
		provider := storage.Registry.GetProvider(req.ProviderID)
		if provider == nil {
			return "", fmt.Errorf("provider %s not found", req.ProviderID)
		}
		items, err = buildVerifyList(req.ProviderID)
	} else {
		// Verify all providers
		items, err = buildVerifyListAll()
	}
	if err != nil {
		return "", fmt.Errorf("failed to build verify list: %w", err)
	}

	taskID, err := models.CreateAdminTask(database.DB, "verify-all", req.AdminUsername, len(items))
	if err != nil {
		return "", fmt.Errorf("failed to create task record: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tr.mu.Lock()
	tr.activeTasks[taskID] = cancel
	tr.mu.Unlock()

	go tr.runVerifyTask(ctx, taskID, req, items)

	return taskID, nil
}

func buildVerifyList(providerID string) ([]fileVerifyItem, error) {
	rows, err := database.DB.Query(`
		SELECT fsl.file_id, fsl.provider_id, fsl.storage_id, COALESCE(fm.padded_size, fm.size_bytes)
		FROM file_storage_locations fsl
		JOIN file_metadata fm ON fsl.file_id = fm.file_id
		WHERE fsl.provider_id = ? AND fsl.status = 'active'`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVerifyItems(rows)
}

func buildVerifyListAll() ([]fileVerifyItem, error) {
	rows, err := database.DB.Query(`
		SELECT fsl.file_id, fsl.provider_id, fsl.storage_id, COALESCE(fm.padded_size, fm.size_bytes)
		FROM file_storage_locations fsl
		JOIN file_metadata fm ON fsl.file_id = fm.file_id
		WHERE fsl.status = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVerifyItems(rows)
}

func scanVerifyItems(rows *sql.Rows) ([]fileVerifyItem, error) {
	var items []fileVerifyItem
	for rows.Next() {
		var item fileVerifyItem
		var paddedSizeRaw interface{}
		if err := rows.Scan(&item.FileID, &item.ProviderID, &item.StorageID, &paddedSizeRaw); err != nil {
			return nil, err
		}
		item.PaddedSize = toInt64FromInterface(paddedSizeRaw)
		items = append(items, item)
	}
	return items, rows.Err()
}

// runVerifyTask is the background goroutine that performs HEAD-based verification.
func (tr *TaskRunner) runVerifyTask(
	ctx context.Context,
	taskID string,
	req VerifyTaskRequest,
	items []fileVerifyItem,
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

	details := VerifyTaskDetails{
		ProviderID:  req.ProviderID,
		Fix:         req.Fix,
		Concurrency: req.Concurrency,
	}

	persistDetails := func() {
		detailsSnap, _ := json.Marshal(details)
		models.UpdateAdminTaskDetails(database.DB, taskID, string(detailsSnap))
	}

	// Use a semaphore for concurrency control
	sem := make(chan struct{}, req.Concurrency)
	var mu sync.Mutex
	processed := 0

	type verifyResult struct {
		index        int
		ok           bool
		missing      bool
		sizeMismatch bool
		err          error
	}

	resultsCh := make(chan verifyResult, len(items))

	for i, item := range items {
		// Check for cancellation
		if ctx.Err() != nil {
			break
		}

		sem <- struct{}{}
		go func(idx int, itm fileVerifyItem) {
			defer func() { <-sem }()

			provider := storage.Registry.GetProvider(itm.ProviderID)
			if provider == nil {
				resultsCh <- verifyResult{index: idx, err: fmt.Errorf("provider %s not found", itm.ProviderID)}
				return
			}

			size, err := provider.HeadObject(ctx, itm.StorageID)
			if err != nil {
				// Object is missing or unreachable
				resultsCh <- verifyResult{index: idx, missing: true}
				return
			}

			// Check size against padded_size
			if itm.PaddedSize > 0 && size != itm.PaddedSize {
				resultsCh <- verifyResult{index: idx, sizeMismatch: true}
				return
			}

			resultsCh <- verifyResult{index: idx, ok: true}
		}(i, item)
	}

	// Collect results
	for range items {
		if ctx.Err() != nil {
			break
		}

		r := <-resultsCh
		mu.Lock()
		processed++

		if r.ok {
			details.VerifiedOK++
		} else if r.missing {
			details.Missing++
			if req.Fix {
				models.UpdateFileStorageLocationStatus(database.DB, items[r.index].FileID, items[r.index].ProviderID, "missing")
			}
		} else if r.sizeMismatch {
			details.SizeMismatch++
			if req.Fix {
				models.UpdateFileStorageLocationStatus(database.DB, items[r.index].FileID, items[r.index].ProviderID, "missing")
			}
		} else if r.err != nil {
			details.Errors++
		}

		// Update progress periodically (every 50 items or when done)
		if processed%50 == 0 || processed == len(items) {
			persistDetails()
			models.UpdateAdminTaskProgress(database.DB, taskID, processed)
		}
		mu.Unlock()
	}

	if ctx.Err() != nil {
		models.UpdateAdminTaskStatus(database.DB, taskID, "canceled")
		logging.InfoLogger.Printf("Task %s: canceled at %d/%d", taskID, processed, len(items))
		return
	}

	// Final persist
	persistDetails()
	models.UpdateAdminTaskProgress(database.DB, taskID, len(items))

	detailsJSON, _ := json.Marshal(details)
	if err := models.CompleteAdminTask(database.DB, taskID, string(detailsJSON)); err != nil {
		logging.ErrorLogger.Printf("Task %s: failed to mark complete: %v", taskID, err)
	}

	// Recalculate cached provider stats from ground truth after verification.
	// This corrects any drift in total_objects/total_size_bytes on storage_providers.
	verifiedProviders := make(map[string]bool)
	for _, item := range items {
		verifiedProviders[item.ProviderID] = true
	}
	for provID := range verifiedProviders {
		if err := models.RecalculateProviderStats(database.DB, provID); err != nil {
			logging.ErrorLogger.Printf("Task %s: failed to recalculate stats for provider %s: %v", taskID, provID, err)
		}
	}

	logging.InfoLogger.Printf("Task %s: verify-all completed (ok: %d, missing: %d, size_mismatch: %d, errors: %d)",
		taskID, details.VerifiedOK, details.Missing, details.SizeMismatch, details.Errors)
}
