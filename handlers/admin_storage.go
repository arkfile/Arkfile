package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
)

// AdminVerifyStorage handles POST /api/admin/system/verify-storage
// Runs a full S3 round-trip test (upload, download, hash verify, delete).
// If provider_id is specified in the JSON body, verifies that provider;
// otherwise defaults to the primary provider.
func AdminVerifyStorage(c echo.Context) error {
	var req struct {
		ProviderID string `json:"provider_id"`
	}
	c.Bind(&req)

	var provider storage.ObjectStorageProvider
	var providerName string

	if req.ProviderID != "" {
		provider = storage.Registry.GetProvider(req.ProviderID)
		if provider == nil {
			return JSONError(c, http.StatusBadRequest, "Provider not found: "+req.ProviderID)
		}
		// Look up the provider type from the database for accurate logging
		var dbProviderType string
		err := database.DB.QueryRow(
			"SELECT provider_type FROM storage_providers WHERE provider_id = ?", req.ProviderID,
		).Scan(&dbProviderType)
		if err == nil && dbProviderType != "" {
			providerName = dbProviderType
		} else {
			providerName = req.ProviderID
		}
	} else {
		provider = storage.Registry.Primary()
		primaryID := storage.Registry.PrimaryID()
		var dbProviderType string
		database.DB.QueryRow(
			"SELECT provider_type FROM storage_providers WHERE provider_id = ?", primaryID,
		).Scan(&dbProviderType)
		if dbProviderType != "" {
			providerName = dbProviderType
		} else {
			providerName = primaryID
		}
	}

	result := storage.RunVerification(providerName, provider)

	if result.Verified {
		// Update last_verified_at for the provider
		targetID := req.ProviderID
		if targetID == "" {
			targetID = storage.Registry.PrimaryID()
		}
		database.DB.Exec(
			"UPDATE storage_providers SET last_verified_at = CURRENT_TIMESTAMP WHERE provider_id = ?",
			targetID,
		)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Storage verification passed",
			"data":    result,
		})
	}

	return c.JSON(http.StatusInternalServerError, map[string]interface{}{
		"success": false,
		"message": "Storage verification failed",
		"data":    result,
	})
}

// AdminStorageStatus handles GET /api/admin/storage/status
// Returns configured providers, file counts, sync status, and cost info.
func AdminStorageStatus(c echo.Context) error {
	// Query all storage providers from DB
	rows, err := database.DB.Query(`
		SELECT provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix,
		       is_active, total_objects, total_size_bytes, cost_per_tb_cents, last_verified_at
		FROM storage_providers
		ORDER BY CASE role WHEN 'primary' THEN 1 WHEN 'secondary' THEN 2 WHEN 'tertiary' THEN 3 ELSE 4 END`)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to query storage providers")
	}
	defer rows.Close()

	var providers []map[string]interface{}
	for rows.Next() {
		var providerID, providerType, bucketName, endpoint, region, role, envVarPrefix string
		var isActiveRaw interface{}
		var totalObjectsRaw, totalSizeBytesRaw, costPerTBCentsRaw interface{}
		var lastVerifiedAt sql.NullString

		if err := rows.Scan(&providerID, &providerType, &bucketName, &endpoint, &region, &role, &envVarPrefix,
			&isActiveRaw, &totalObjectsRaw, &totalSizeBytesRaw, &costPerTBCentsRaw, &lastVerifiedAt); err != nil {
			logging.ErrorLogger.Printf("AdminStorageStatus: scan error: %v", err)
			continue
		}

		p := map[string]interface{}{
			"provider_id":      providerID,
			"provider_type":    providerType,
			"bucket_name":      bucketName,
			"region":           region,
			"role":             role,
			"env_var_prefix":   envVarPrefix,
			"is_active":        toBool(isActiveRaw),
			"total_objects":    toInt64(totalObjectsRaw),
			"total_size_bytes": toInt64(totalSizeBytesRaw),
		}

		if costPerTBCentsRaw != nil {
			p["cost_per_tb_cents"] = toInt64(costPerTBCentsRaw)
		} else {
			p["cost_per_tb_cents"] = nil
		}

		if lastVerifiedAt.Valid {
			p["last_verified_at"] = lastVerifiedAt.String
		} else {
			p["last_verified_at"] = nil
		}

		providers = append(providers, p)
	}

	// Compute sync stats
	var totalFiles int64
	database.DB.QueryRow("SELECT COUNT(*) FROM file_metadata").Scan(&totalFiles)

	// Count files on all configured active providers
	var fullyReplicated, partiallyReplicated int64
	configuredProviders := 0
	if storage.Registry.Primary() != nil {
		configuredProviders++
	}
	if storage.Registry.HasSecondary() {
		configuredProviders++
	}
	if storage.Registry.HasTertiary() {
		configuredProviders++
	}

	if configuredProviders > 1 {
		// Files on all configured providers
		database.DB.QueryRow(`
			SELECT COUNT(*) FROM file_metadata fm
			WHERE (SELECT COUNT(DISTINCT fsl.provider_id) FROM file_storage_locations fsl
			       WHERE fsl.file_id = fm.file_id AND fsl.status = 'active') >= ?`,
			configuredProviders,
		).Scan(&fullyReplicated)

		partiallyReplicated = totalFiles - fullyReplicated
	}

	cfg, _ := config.LoadConfig()
	replicationEnabled := false
	if cfg != nil {
		replicationEnabled = cfg.Storage.EnableUploadReplication
	}

	return JSONResponse(c, http.StatusOK, "Storage status retrieved", map[string]interface{}{
		"providers":            providers,
		"total_files":          totalFiles,
		"fully_replicated":     fullyReplicated,
		"partially_replicated": partiallyReplicated,
		"replication_enabled":  replicationEnabled,
	})
}

// AdminSyncStatus handles GET /api/admin/storage/sync-status
// Returns detailed breakdown of file locations and replication gaps.
func AdminSyncStatus(c echo.Context) error {
	var totalFiles int64
	database.DB.QueryRow("SELECT COUNT(*) FROM file_metadata").Scan(&totalFiles)

	primaryID := storage.Registry.PrimaryID()
	secondaryID := storage.Registry.SecondaryID()
	tertiaryID := storage.Registry.TertiaryID()
	hasSecondary := storage.Registry.HasSecondary()
	hasTertiary := storage.Registry.HasTertiary()

	// Helper: check if a file is active on a given provider
	// Uses a subquery pattern: EXISTS (SELECT 1 FROM fsl WHERE file_id=? AND provider_id=? AND status='active')
	activeOn := func(providerID string) string {
		return fmt.Sprintf("EXISTS (SELECT 1 FROM file_storage_locations fsl WHERE fsl.file_id = fm.file_id AND fsl.provider_id = '%s' AND fsl.status = 'active')", providerID)
	}
	notActiveOn := func(providerID string) string {
		return fmt.Sprintf("NOT EXISTS (SELECT 1 FROM file_storage_locations fsl WHERE fsl.file_id = fm.file_id AND fsl.provider_id = '%s' AND fsl.status = 'active')", providerID)
	}

	var onPrimaryOnly, onSecondaryOnly, onTertiaryOnly int64
	var onAllConfigured, onPrimaryAndSecondary, onPrimaryAndTertiary, onSecondaryAndTertiary int64

	if hasSecondary && hasTertiary {
		// Three providers configured: compute full combination matrix
		q := func(p, s, t string) int64 {
			var count int64
			database.DB.QueryRow("SELECT COUNT(*) FROM file_metadata fm WHERE " + p + " AND " + s + " AND " + t).Scan(&count)
			return count
		}
		onAllConfigured = q(activeOn(primaryID), activeOn(secondaryID), activeOn(tertiaryID))
		onPrimaryAndSecondary = q(activeOn(primaryID), activeOn(secondaryID), notActiveOn(tertiaryID))
		onPrimaryAndTertiary = q(activeOn(primaryID), notActiveOn(secondaryID), activeOn(tertiaryID))
		onSecondaryAndTertiary = q(notActiveOn(primaryID), activeOn(secondaryID), activeOn(tertiaryID))
		onPrimaryOnly = q(activeOn(primaryID), notActiveOn(secondaryID), notActiveOn(tertiaryID))
		onSecondaryOnly = q(notActiveOn(primaryID), activeOn(secondaryID), notActiveOn(tertiaryID))
		onTertiaryOnly = q(notActiveOn(primaryID), notActiveOn(secondaryID), activeOn(tertiaryID))
	} else if hasSecondary {
		// Two providers configured
		q := func(p, s string) int64 {
			var count int64
			database.DB.QueryRow("SELECT COUNT(*) FROM file_metadata fm WHERE " + p + " AND " + s).Scan(&count)
			return count
		}
		onAllConfigured = q(activeOn(primaryID), activeOn(secondaryID))
		onPrimaryOnly = q(activeOn(primaryID), notActiveOn(secondaryID))
		onSecondaryOnly = q(notActiveOn(primaryID), activeOn(secondaryID))
		// onPrimaryAndSecondary is the same as onAllConfigured in two-provider mode
		onPrimaryAndSecondary = onAllConfigured
	}
	// Single provider: all counts stay 0; total_files is the only relevant number

	// Failed locations
	failedRows, err := database.DB.Query(`
		SELECT fsl.file_id, fsl.provider_id, fsl.status, fm.owner_username
		FROM file_storage_locations fsl
		JOIN file_metadata fm ON fsl.file_id = fm.file_id
		WHERE fsl.status = 'failed'
		LIMIT 50`)
	var failedLocations []map[string]interface{}
	if err == nil {
		defer failedRows.Close()
		for failedRows.Next() {
			var fileID, providerID, status, owner string
			if err := failedRows.Scan(&fileID, &providerID, &status, &owner); err == nil {
				failedLocations = append(failedLocations, map[string]interface{}{
					"file_id":        fileID,
					"provider_id":    providerID,
					"status":         status,
					"owner_username": owner,
				})
			}
		}
	}

	// Orphaned blobs (delete_failed)
	orphanedRows, err := database.DB.Query(`
		SELECT file_id, provider_id, status
		FROM file_storage_locations
		WHERE status = 'delete_failed'
		LIMIT 50`)
	var orphanedBlobs []map[string]interface{}
	if err == nil {
		defer orphanedRows.Close()
		for orphanedRows.Next() {
			var fileID, providerID, status string
			if err := orphanedRows.Scan(&fileID, &providerID, &status); err == nil {
				orphanedBlobs = append(orphanedBlobs, map[string]interface{}{
					"file_id":     fileID,
					"provider_id": providerID,
					"status":      status,
				})
			}
		}
	}

	return JSONResponse(c, http.StatusOK, "Sync status retrieved", map[string]interface{}{
		"total_files":               totalFiles,
		"on_all_configured":         onAllConfigured,
		"on_primary_only":           onPrimaryOnly,
		"on_secondary_only":         onSecondaryOnly,
		"on_tertiary_only":          onTertiaryOnly,
		"on_primary_and_secondary":  onPrimaryAndSecondary,
		"on_primary_and_tertiary":   onPrimaryAndTertiary,
		"on_secondary_and_tertiary": onSecondaryAndTertiary,
		"failed_locations":          failedLocations,
		"orphaned_blobs":            orphanedBlobs,
	})
}

// AdminCopyAll handles POST /api/admin/storage/copy-all
func AdminCopyAll(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	var req struct {
		SourceProviderID string `json:"source_provider_id"`
		DestProviderID   string `json:"destination_provider_id"`
		Verify           bool   `json:"verify"`
		SkipExisting     bool   `json:"skip_existing"`
	}
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}
	if req.SourceProviderID == "" || req.DestProviderID == "" {
		return JSONError(c, http.StatusBadRequest, "source_provider_id and destination_provider_id are required")
	}

	tr := GetTaskRunner()
	if tr == nil {
		return JSONError(c, http.StatusInternalServerError, "Task runner not initialized")
	}

	taskID, err := tr.SubmitCopyTask(CopyTaskRequest{
		TaskType:      "copy-all",
		AdminUsername: adminUsername,
		SourceID:      req.SourceProviderID,
		DestID:        req.DestProviderID,
		Verify:        req.Verify,
		SkipExisting:  req.SkipExisting,
	})
	if err != nil {
		return JSONError(c, http.StatusBadRequest, err.Error())
	}

	return JSONResponse(c, http.StatusOK, "Copy task queued", map[string]interface{}{
		"task_id":   taskID,
		"task_type": "copy-all",
		"status":    "pending",
	})
}

// AdminCopyUserFiles handles POST /api/admin/storage/copy-user-files
func AdminCopyUserFiles(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	var req struct {
		Username         string `json:"username"`
		SourceProviderID string `json:"source_provider_id"`
		DestProviderID   string `json:"destination_provider_id"`
		Verify           bool   `json:"verify"`
		SkipExisting     bool   `json:"skip_existing"`
	}
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}
	if req.Username == "" || req.SourceProviderID == "" || req.DestProviderID == "" {
		return JSONError(c, http.StatusBadRequest, "username, source_provider_id, and destination_provider_id are required")
	}

	tr := GetTaskRunner()
	if tr == nil {
		return JSONError(c, http.StatusInternalServerError, "Task runner not initialized")
	}

	taskID, err := tr.SubmitCopyTask(CopyTaskRequest{
		TaskType:      "copy-user-files",
		AdminUsername: adminUsername,
		SourceID:      req.SourceProviderID,
		DestID:        req.DestProviderID,
		Verify:        req.Verify,
		SkipExisting:  req.SkipExisting,
		Username:      req.Username,
	})
	if err != nil {
		return JSONError(c, http.StatusBadRequest, err.Error())
	}

	return JSONResponse(c, http.StatusOK, "Copy task queued", map[string]interface{}{
		"task_id":   taskID,
		"task_type": "copy-user-files",
		"status":    "pending",
	})
}

// AdminCopyFile handles POST /api/admin/storage/copy-file
func AdminCopyFile(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	var req struct {
		FileID           string `json:"file_id"`
		SourceProviderID string `json:"source_provider_id"`
		DestProviderID   string `json:"destination_provider_id"`
		Verify           bool   `json:"verify"`
	}
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}
	if req.FileID == "" || req.SourceProviderID == "" || req.DestProviderID == "" {
		return JSONError(c, http.StatusBadRequest, "file_id, source_provider_id, and destination_provider_id are required")
	}

	tr := GetTaskRunner()
	if tr == nil {
		return JSONError(c, http.StatusInternalServerError, "Task runner not initialized")
	}

	taskID, err := tr.SubmitCopyTask(CopyTaskRequest{
		TaskType:      "copy-file",
		AdminUsername: adminUsername,
		SourceID:      req.SourceProviderID,
		DestID:        req.DestProviderID,
		Verify:        req.Verify,
		FileID:        req.FileID,
	})
	if err != nil {
		return JSONError(c, http.StatusBadRequest, err.Error())
	}

	return JSONResponse(c, http.StatusOK, "Copy task queued", map[string]interface{}{
		"task_id":   taskID,
		"task_type": "copy-file",
		"status":    "pending",
	})
}

// AdminTaskStatus handles GET /api/admin/storage/task/:taskId
func AdminTaskStatus(c echo.Context) error {
	taskID := c.Param("taskId")
	if taskID == "" {
		return JSONError(c, http.StatusBadRequest, "Task ID is required")
	}

	task, err := models.GetAdminTask(database.DB, taskID)
	if err != nil {
		if err == sql.ErrNoRows {
			return JSONError(c, http.StatusNotFound, "Task not found")
		}
		return JSONError(c, http.StatusInternalServerError, "Failed to get task status")
	}

	resp := map[string]interface{}{
		"task_id":          task.TaskID,
		"task_type":        task.TaskType,
		"status":           task.Status,
		"admin_username":   task.AdminUsername,
		"progress_current": task.ProgressCurrent,
		"progress_total":   task.ProgressTotal,
	}

	if task.StartedAt.Valid {
		resp["started_at"] = task.StartedAt.String
	}
	if task.CompletedAt.Valid {
		resp["completed_at"] = task.CompletedAt.String
	}
	if task.ErrorMessage.Valid {
		resp["error_message"] = task.ErrorMessage.String
	}
	if task.Details.Valid {
		var details map[string]interface{}
		if json.Unmarshal([]byte(task.Details.String), &details) == nil {
			resp["details"] = details
		} else {
			resp["details"] = task.Details.String
		}
	}

	return JSONResponse(c, http.StatusOK, "Task status retrieved", resp)
}

// AdminCancelTask handles POST /api/admin/storage/cancel-task/:taskId
func AdminCancelTask(c echo.Context) error {
	taskID := c.Param("taskId")
	if taskID == "" {
		return JSONError(c, http.StatusBadRequest, "Task ID is required")
	}

	tr := GetTaskRunner()
	if tr == nil {
		return JSONError(c, http.StatusInternalServerError, "Task runner not initialized")
	}

	if tr.CancelTask(taskID) {
		return JSONResponse(c, http.StatusOK, "Task cancellation requested", map[string]interface{}{
			"task_id": taskID,
		})
	}

	return JSONError(c, http.StatusNotFound, "Task not found or not running")
}

// AdminSetPrimary handles POST /api/admin/storage/set-primary
func AdminSetPrimary(c echo.Context) error {
	var req struct {
		ProviderID string `json:"provider_id"`
	}
	if err := c.Bind(&req); err != nil || req.ProviderID == "" {
		return JSONError(c, http.StatusBadRequest, "provider_id is required")
	}

	// Validate: target must currently be secondary
	currentRole, err := models.GetStorageProviderRole(database.DB, req.ProviderID)
	if err != nil {
		return JSONError(c, http.StatusNotFound, "Provider not found")
	}
	if currentRole != "secondary" {
		if currentRole == "tertiary" {
			return JSONError(c, http.StatusBadRequest, "Cannot promote tertiary directly to primary. Promote to secondary first, then to primary.")
		}
		return JSONError(c, http.StatusBadRequest, "Provider must be secondary to promote to primary")
	}

	oldPrimaryID := storage.Registry.PrimaryID()

	// Swap roles in DB
	database.DB.Exec("UPDATE storage_providers SET role = 'primary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", req.ProviderID)
	database.DB.Exec("UPDATE storage_providers SET role = 'secondary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", oldPrimaryID)

	// DB role change is persisted. In-memory registry will be updated on next server
	// restart when roles are read from the database. For immediate effect without
	// restart, a SwapPrimarySecondary method on the registry would be needed.
	_ = oldPrimaryID

	return JSONResponse(c, http.StatusOK, "Primary provider updated", map[string]interface{}{
		"previous_primary":   oldPrimaryID,
		"new_primary":        req.ProviderID,
		"previous_secondary": req.ProviderID,
		"new_secondary":      oldPrimaryID,
		"message":            "Primary provider updated. New uploads will use " + req.ProviderID + ". Restart server to fully apply in-memory registry changes.",
	})
}

// AdminSetSecondary handles POST /api/admin/storage/set-secondary
func AdminSetSecondary(c echo.Context) error {
	var req struct {
		ProviderID string `json:"provider_id"`
	}
	if err := c.Bind(&req); err != nil || req.ProviderID == "" {
		return JSONError(c, http.StatusBadRequest, "provider_id is required")
	}

	currentRole, err := models.GetStorageProviderRole(database.DB, req.ProviderID)
	if err != nil {
		return JSONError(c, http.StatusNotFound, "Provider not found")
	}

	if currentRole == "secondary" {
		return JSONError(c, http.StatusBadRequest, "Provider is already secondary")
	}

	if currentRole == "primary" {
		// Demoting primary to secondary: old secondary becomes primary
		oldSecID := storage.Registry.SecondaryID()
		database.DB.Exec("UPDATE storage_providers SET role = 'secondary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", req.ProviderID)
		database.DB.Exec("UPDATE storage_providers SET role = 'primary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", oldSecID)
		return JSONResponse(c, http.StatusOK, "Roles updated", map[string]interface{}{
			"message": "Roles swapped. Restart server to fully apply in-memory registry changes.",
		})
	}

	if currentRole == "tertiary" {
		// Promoting tertiary to secondary: old secondary becomes tertiary
		oldSecID := storage.Registry.SecondaryID()
		database.DB.Exec("UPDATE storage_providers SET role = 'secondary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", req.ProviderID)
		database.DB.Exec("UPDATE storage_providers SET role = 'tertiary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", oldSecID)
		return JSONResponse(c, http.StatusOK, "Roles updated", map[string]interface{}{
			"message": "Tertiary promoted to secondary. Restart server to fully apply in-memory registry changes.",
		})
	}

	return JSONError(c, http.StatusBadRequest, "Invalid current role for provider")
}

// AdminSetTertiary handles POST /api/admin/storage/set-tertiary
func AdminSetTertiary(c echo.Context) error {
	var req struct {
		ProviderID string `json:"provider_id"`
	}
	if err := c.Bind(&req); err != nil || req.ProviderID == "" {
		return JSONError(c, http.StatusBadRequest, "provider_id is required")
	}

	currentRole, err := models.GetStorageProviderRole(database.DB, req.ProviderID)
	if err != nil {
		return JSONError(c, http.StatusNotFound, "Provider not found")
	}
	if currentRole != "secondary" {
		if currentRole == "primary" {
			return JSONError(c, http.StatusBadRequest, "Cannot demote primary directly to tertiary. Demote to secondary first, then to tertiary.")
		}
		return JSONError(c, http.StatusBadRequest, "Provider must be secondary to demote to tertiary")
	}

	oldTertiaryID := storage.Registry.TertiaryID()

	database.DB.Exec("UPDATE storage_providers SET role = 'tertiary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", req.ProviderID)
	if oldTertiaryID != "" {
		database.DB.Exec("UPDATE storage_providers SET role = 'secondary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", oldTertiaryID)
	}

	return JSONResponse(c, http.StatusOK, "Roles updated", map[string]interface{}{
		"message": "Provider demoted to tertiary. Restart server to fully apply in-memory registry changes.",
	})
}

// AdminSwapProviders handles POST /api/admin/storage/swap-providers
func AdminSwapProviders(c echo.Context) error {
	if !storage.Registry.HasSecondary() {
		return JSONError(c, http.StatusBadRequest, "No secondary provider configured to swap with")
	}

	primaryID := storage.Registry.PrimaryID()
	secondaryID := storage.Registry.SecondaryID()

	database.DB.Exec("UPDATE storage_providers SET role = 'secondary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", primaryID)
	database.DB.Exec("UPDATE storage_providers SET role = 'primary', updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?", secondaryID)

	return JSONResponse(c, http.StatusOK, "Providers swapped", map[string]interface{}{
		"previous_primary":   primaryID,
		"new_primary":        secondaryID,
		"previous_secondary": secondaryID,
		"new_secondary":      primaryID,
		"message":            "Providers swapped in database. Restart server to fully apply in-memory registry changes.",
	})
}

// AdminSetCost handles POST /api/admin/storage/set-cost
func AdminSetCost(c echo.Context) error {
	var req struct {
		ProviderID     string `json:"provider_id"`
		CostPerTBCents int64  `json:"cost_per_tb_cents"`
	}
	if err := c.Bind(&req); err != nil || req.ProviderID == "" {
		return JSONError(c, http.StatusBadRequest, "provider_id is required")
	}

	_, err := database.DB.Exec(
		"UPDATE storage_providers SET cost_per_tb_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE provider_id = ?",
		req.CostPerTBCents, req.ProviderID,
	)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to update cost")
	}

	return JSONResponse(c, http.StatusOK, "Cost updated", map[string]interface{}{
		"provider_id":       req.ProviderID,
		"cost_per_tb_cents": req.CostPerTBCents,
	})
}

// AdminAlertsSummary handles GET /api/admin/alerts/summary
// Returns storage health warnings for the admin CLI login alert display.
func AdminAlertsSummary(c echo.Context) error {
	var replicationFailures, syncGaps, orphanedBlobs, staleTasks int64

	database.DB.QueryRow(
		"SELECT COUNT(*) FROM file_storage_locations WHERE status = 'failed'",
	).Scan(&replicationFailures)

	database.DB.QueryRow(
		"SELECT COUNT(*) FROM file_storage_locations WHERE status = 'delete_failed'",
	).Scan(&orphanedBlobs)

	database.DB.QueryRow(
		"SELECT COUNT(*) FROM admin_tasks WHERE status = 'running'",
	).Scan(&staleTasks)

	// Sync gaps: files not on all configured active providers
	configuredProviders := 1
	if storage.Registry.HasSecondary() {
		configuredProviders++
	}
	if storage.Registry.HasTertiary() {
		configuredProviders++
	}
	if configuredProviders > 1 {
		database.DB.QueryRow(`
			SELECT COUNT(*) FROM file_metadata fm
			WHERE (SELECT COUNT(DISTINCT fsl.provider_id) FROM file_storage_locations fsl
			       WHERE fsl.file_id = fm.file_id AND fsl.status = 'active') < ?`,
			configuredProviders,
		).Scan(&syncGaps)
	}

	hasAlerts := replicationFailures > 0 || syncGaps > 0 || orphanedBlobs > 0 || staleTasks > 0
	message := ""
	if hasAlerts {
		parts := []string{}
		if replicationFailures > 0 {
			parts = append(parts, formatAlertCount(replicationFailures, "replication failure", "replication failures"))
		}
		if syncGaps > 0 {
			parts = append(parts, formatAlertCount(syncGaps, "file not fully replicated", "files not fully replicated"))
		}
		if orphanedBlobs > 0 {
			parts = append(parts, formatAlertCount(orphanedBlobs, "orphaned blob", "orphaned blobs"))
		}
		if staleTasks > 0 {
			parts = append(parts, formatAlertCount(staleTasks, "stale task", "stale tasks"))
		}
		message = joinAlertParts(parts) + ". Run 'storage-sync-status' for details."
	}

	return JSONResponse(c, http.StatusOK, "Alerts summary retrieved", map[string]interface{}{
		"storage_alerts": map[string]interface{}{
			"replication_failures": replicationFailures,
			"sync_gaps":            syncGaps,
			"orphaned_blobs":       orphanedBlobs,
			"stale_tasks":          staleTasks,
		},
		"has_alerts": hasAlerts,
		"message":    message,
	})
}

func formatAlertCount(count int64, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", count, plural)
}

func joinAlertParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}

// AdminVerifyAll handles POST /api/admin/storage/verify-all
// Initiates a background task that performs HEAD requests against all active
// file_storage_locations to confirm S3 objects exist and sizes match.
func AdminVerifyAll(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	var req struct {
		ProviderID  string `json:"provider_id"`
		Fix         bool   `json:"fix"`
		Concurrency int    `json:"concurrency"`
	}
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}

	tr := GetTaskRunner()
	if tr == nil {
		return JSONError(c, http.StatusInternalServerError, "Task runner not initialized")
	}

	taskID, err := tr.SubmitVerifyTask(VerifyTaskRequest{
		AdminUsername: adminUsername,
		ProviderID:    req.ProviderID,
		Fix:           req.Fix,
		Concurrency:   req.Concurrency,
	})
	if err != nil {
		return JSONError(c, http.StatusBadRequest, err.Error())
	}

	return JSONResponse(c, http.StatusOK, "Verify task queued", map[string]interface{}{
		"task_id":   taskID,
		"task_type": "verify-all",
		"status":    "pending",
	})
}
