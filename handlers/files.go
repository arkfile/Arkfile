package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

const (
	defaultMetadataPageLimit = 100
	maxMetadataPageLimit     = 500
	maxMetadataBatchSize     = 500
)

type FileMetadataBatchRequest struct {
	FileIDs []string `json:"file_ids"`
}

func parseLimitOffset(c echo.Context, defaultLimit, maxLimit int) (int, int, error) {
	limit := defaultLimit
	offset := 0

	if limitStr := c.QueryParam("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid limit")
		}
		if parsed < 1 {
			return 0, 0, fmt.Errorf("limit must be at least 1")
		}
		if parsed > maxLimit {
			parsed = maxLimit
		}
		limit = parsed
	}

	if offsetStr := c.QueryParam("offset"); offsetStr != "" {
		parsed, err := strconv.Atoi(offsetStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset")
		}
		if parsed < 0 {
			return 0, 0, fmt.Errorf("offset must be non-negative")
		}
		offset = parsed
	}

	return limit, offset, nil
}

// GetFileMeta returns encrypted file metadata needed for download initialization
func GetFileMeta(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	// Get file metadata using the new encrypted schema
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during meta retrieval: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Verify ownership
	if file.OwnerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Check if user is approved for file operations
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
	}

	if !user.IsApproved {
		return echo.NewHTTPError(http.StatusForbidden, "Account pending approval. File downloads are restricted until your account is approved by an administrator. You can still access other features of your account.")
	}

	// Calculate chunk size and total chunks from config
	chunkSize := crypto.PlaintextChunkSize()
	totalChunks := (file.SizeBytes + chunkSize - 1) / chunkSize

	logging.InfoLogger.Printf("File metadata requested: file_id %s by %s (size: %d bytes, chunks: %d)", fileID, username, file.SizeBytes, totalChunks)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":               file.FileID,
		"encrypted_filename":    file.EncryptedFilename,  // Already base64 strings
		"filename_nonce":        file.FilenameNonce,      // Already base64 strings
		"encrypted_sha256sum":   file.EncryptedSha256sum, // Already base64 strings
		"sha256sum_nonce":       file.Sha256sumNonce,     // Already base64 strings
		"encrypted_fek":         file.EncryptedFEK,       // Already base64 strings
		"password_hint":         file.PasswordHint,
		"password_type":         file.PasswordType,
		"size_bytes":            file.SizeBytes,
		"chunk_size":            chunkSize,
		"total_chunks":          totalChunks,
		"chunk_count":           file.ChunkCount,
		"chunk_size_bytes":      file.ChunkSizeBytes,
		"encrypted_file_sha256": file.EncryptedFileSha256sum.Valid && file.EncryptedFileSha256sum.String != "",
	})
}

// ListRecentFileMetadata returns a paginated recent metadata listing for the
// authenticated owner. This endpoint is intended for owner-side local metadata
// decryption workflows and does not expose FEKs or chunk/download details.
func ListRecentFileMetadata(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authentication token")
	}

	limit, offset, err := parseLimitOffset(c, defaultMetadataPageLimit, maxMetadataPageLimit)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	files, err := models.GetRecentFileMetadataByOwner(database.DB, username, limit, offset)
	if err != nil {
		logging.ErrorLogger.Printf("ListRecentFileMetadata failed for user '%s': %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"files":    files,
		"limit":    limit,
		"offset":   offset,
		"returned": len(files),
		"has_more": len(files) == limit,
	})
}

// GetFileMetadataBatch returns lightweight encrypted metadata for an explicit
// batch of owner-owned file IDs.
func GetFileMetadataBatch(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authentication token")
	}

	var request FileMetadataBatchRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body: "+err.Error())
	}

	if len(request.FileIDs) > maxMetadataBatchSize {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("file_ids batch size exceeds maximum of %d", maxMetadataBatchSize))
	}

	files, err := models.GetFileMetadataBatchByOwner(database.DB, username, request.FileIDs)
	if err != nil {
		logging.ErrorLogger.Printf("GetFileMetadataBatch failed for user '%s': %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata batch")
	}

	fileMap := make(map[string]interface{}, len(files))
	returned := make(map[string]struct{}, len(files))
	for _, file := range files {
		fileMap[file.FileID] = file
		returned[file.FileID] = struct{}{}
	}

	missing := make([]string, 0)
	for _, fileID := range request.FileIDs {
		if _, ok := returned[fileID]; !ok {
			missing = append(missing, fileID)
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"files":   fileMap,
		"missing": missing,
	})
}

// GetFileEnvelope returns the encrypted FEK and metadata for a file (for share creation)
func GetFileEnvelope(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	// Get file metadata
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during envelope retrieval: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Verify ownership
	if file.OwnerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Return the envelope data needed for client-side re-encryption
	return c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":       file.FileID,
		"encrypted_fek": file.EncryptedFEK,
		"password_type": file.PasswordType,
	})
}

// ListFiles returns a list of files owned by the user with encrypted metadata
func ListFiles(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		logging.Log(logging.ERROR, "ListFiles: Failed to extract username from JWT token")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authentication token")
	}

	// Verify database connection
	if database.DB == nil {
		logging.Log(logging.ERROR, "ListFiles: Database connection is nil")
		return echo.NewHTTPError(http.StatusInternalServerError, "Database connection error")
	}

	// Test database connection with a simple ping
	if err := database.DB.Ping(); err != nil {
		logging.Log(logging.ERROR, "ListFiles: Database ping failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Database connection error")
	}

	// Get files using the models function with encrypted metadata support
	files, err := models.GetFilesByOwner(database.DB, username)
	if err != nil {
		logging.Log(logging.ERROR, "ListFiles: GetFilesByOwner failed for user '%s': %v", username, err)
		// Log the specific SQL error details if available
		if sqlErr, ok := err.(interface{ Error() string }); ok {
			logging.Log(logging.ERROR, "ListFiles: SQL Error details: %s", sqlErr.Error())
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve files")
	}

	// Prepare response data structure for files
	type FileListResponseItem struct {
		*models.FileMetadataForClient
		SizeReadable string `json:"size_readable"`
	}

	var fileList []FileListResponseItem
	for _, file := range files {
		clientMeta := file.ToClientMetadata()
		fileList = append(fileList, FileListResponseItem{
			FileMetadataForClient: clientMeta,
			SizeReadable:          formatBytes(file.SizeBytes),
		})
	}

	// Get user's storage information
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user storage info: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get storage info")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"files": fileList,
		"storage": map[string]interface{}{
			"total_bytes":        user.TotalStorageBytes,
			"total_readable":     formatBytes(user.TotalStorageBytes),
			"limit_bytes":        user.StorageLimitBytes,
			"limit_readable":     formatBytes(user.StorageLimitBytes),
			"available_bytes":    user.StorageLimitBytes - user.TotalStorageBytes,
			"available_readable": formatBytes(user.StorageLimitBytes - user.TotalStorageBytes),
			"usage_percent":      user.GetStorageUsagePercent(),
		},
	})
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// AdminContactsHandler returns admin contact information for user support
func AdminContactsHandler(c echo.Context) error {
	// Get admin usernames from configuration system
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to load config for admin contacts: %v", err)
		// Fallback to default
		return c.JSON(http.StatusOK, map[string]interface{}{
			"adminUsernames": []string{"default-admin"},
			"adminContact":   "admin@example.com",
			"message":        "Contact information for administrators",
		})
	}

	adminUsernames := cfg.Deployment.AdminUsernames
	adminContact := cfg.Deployment.AdminContact

	// Fallback if no admin usernames configured
	if len(adminUsernames) == 0 {
		adminUsernames = []string{"default-admin"}
	}

	// Fallback for admin contact if not configured
	if adminContact == "" {
		adminContact = "admin@example.com"
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"adminUsernames": adminUsernames,
		"adminContact":   adminContact,
		"message":        "Contact information for administrators",
	})
}
