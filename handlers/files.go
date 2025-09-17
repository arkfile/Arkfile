package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

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

	// Calculate chunk size and total chunks (16MB = 16 * 1024 * 1024 = 16777216)
	const chunkSize int64 = 16 * 1024 * 1024
	totalChunks := (file.SizeBytes + chunkSize - 1) / chunkSize

	logging.InfoLogger.Printf("File metadata requested: file_id %s by %s (size: %d bytes, chunks: %d)", fileID, username, file.SizeBytes, totalChunks)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"encrypted_filename":    base64.StdEncoding.EncodeToString(file.EncryptedFilename),
		"filename_nonce":        base64.StdEncoding.EncodeToString(file.FilenameNonce),
		"encrypted_sha256sum":   base64.StdEncoding.EncodeToString(file.EncryptedSha256sum),
		"sha256sum_nonce":       base64.StdEncoding.EncodeToString(file.Sha256sumNonce),
		"encrypted_fek":         base64.StdEncoding.EncodeToString(file.EncryptedFEK),
		"password_hint":         file.PasswordHint,
		"password_type":         file.PasswordType,
		"size_bytes":            file.SizeBytes,
		"chunk_size":            chunkSize,
		"total_chunks":          totalChunks,
		"encrypted_file_sha256": file.EncryptedFileSha256sum.Valid && file.EncryptedFileSha256sum.String != "",
	})
}

// ListFiles returns a list of files owned by the user with encrypted metadata
func ListFiles(c echo.Context) error {
	// Enhanced debugging: Log the start of the function
	logging.InfoLogger.Printf("ListFiles: Starting file listing request")

	// Step 1: Extract username from JWT token
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		logging.ErrorLogger.Printf("ListFiles: Failed to extract username from JWT token")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authentication token")
	}
	logging.InfoLogger.Printf("ListFiles: Successfully extracted username: %s", username)

	// Step 2: Verify database connection
	if database.DB == nil {
		logging.ErrorLogger.Printf("ListFiles: Database connection is nil")
		return echo.NewHTTPError(http.StatusInternalServerError, "Database connection error")
	}

	// Test database connection with a simple ping
	if err := database.DB.Ping(); err != nil {
		logging.ErrorLogger.Printf("ListFiles: Database ping failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Database connection error")
	}
	logging.InfoLogger.Printf("ListFiles: Database connection verified successfully")

	// Step 3: Get files using the models function with encrypted metadata support
	logging.InfoLogger.Printf("ListFiles: Calling GetFilesByOwner for username: %s", username)
	files, err := models.GetFilesByOwner(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("ListFiles: GetFilesByOwner failed for user '%s': %v", username, err)
		// Log the specific SQL error details if available
		if sqlErr, ok := err.(interface{ Error() string }); ok {
			logging.ErrorLogger.Printf("ListFiles: SQL Error details: %s", sqlErr.Error())
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve files")
	}

	logging.InfoLogger.Printf("ListFiles: Successfully retrieved %d files for user: %s", len(files), username)

	// Refactored to use ToClientMetadata for consistency and correctness
	type FileListResponseItem struct {
		*models.FileMetadataForClient
		SizeReadable string `json:"size_readable"`
	}

	var fileList []FileListResponseItem
	for _, file := range files {
		fileList = append(fileList, FileListResponseItem{
			FileMetadataForClient: file.ToClientMetadata(),
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
			"adminUsernames": []string{"admin.user.2024"},
			"adminContact":   "admin@arkfile.demo",
			"message":        "Contact information for administrators",
		})
	}

	adminUsernames := cfg.Deployment.AdminUsernames
	adminContact := cfg.Deployment.AdminContact

	// Fallback if no admin usernames configured
	if len(adminUsernames) == 0 {
		adminUsernames = []string{"admin.user.2024"}
	}

	// Fallback for admin contact if not configured
	if adminContact == "" {
		adminContact = "admin@arkfile.demo"
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"adminUsernames": adminUsernames,
		"adminContact":   adminContact,
		"message":        "Contact information for administrators",
	})
}
