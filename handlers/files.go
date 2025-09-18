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
		"encrypted_file_sha256": file.EncryptedFileSha256sum.Valid && file.EncryptedFileSha256sum.String != "",
	})
}

// ListFiles returns a list of files owned by the user with encrypted metadata
func ListFiles(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		logging.Log(logging.ERROR, "ListFiles: Failed to extract username from JWT token")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authentication token")
	}
	logging.Log(logging.DEBUG, "ListFiles: Successfully extracted username: %s", username)

	// Step 2: Verify database connection
	if database.DB == nil {
		logging.Log(logging.ERROR, "ListFiles: Database connection is nil")
		return echo.NewHTTPError(http.StatusInternalServerError, "Database connection error")
	}

	// Test database connection with a simple ping
	if err := database.DB.Ping(); err != nil {
		logging.Log(logging.ERROR, "ListFiles: Database ping failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Database connection error")
	}
	logging.Log(logging.DEBUG, "ListFiles: Database connection verified successfully")

	// Step 3: Get files using the models function with encrypted metadata support
	logging.Log(logging.DEBUG, "ListFiles: Calling GetFilesByOwner for username: %s", username)
	files, err := models.GetFilesByOwner(database.DB, username)
	if err != nil {
		logging.Log(logging.ERROR, "ListFiles: GetFilesByOwner failed for user '%s': %v", username, err)
		// Log the specific SQL error details if available
		if sqlErr, ok := err.(interface{ Error() string }); ok {
			logging.Log(logging.ERROR, "ListFiles: SQL Error details: %s", sqlErr.Error())
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve files")
	}

	logging.Log(logging.DEBUG, "ListFiles: Successfully retrieved %d files for user: %s", len(files), username)

	// Refactored to use ToClientMetadata for consistency and correctness with debug logging
	type FileListResponseItem struct {
		*models.FileMetadataForClient
		SizeReadable string `json:"size_readable"`
	}

	var fileList []FileListResponseItem
	for _, file := range files {
		// DEBUG: Log raw metadata values from database
		logging.Log(logging.DEBUG, "File %s - Raw values from DB:", file.FileID)
		logging.Log(logging.DEBUG, "  filename_nonce: '%s' (length: %d)", file.FilenameNonce, len(file.FilenameNonce))
		logging.Log(logging.DEBUG, "  encrypted_filename: '%s' (length: %d)", file.EncryptedFilename, len(file.EncryptedFilename))
		logging.Log(logging.DEBUG, "  sha256sum_nonce: '%s' (length: %d)", file.Sha256sumNonce, len(file.Sha256sumNonce))
		logging.Log(logging.DEBUG, "  encrypted_sha256sum: '%s' (length: %d)", file.EncryptedSha256sum, len(file.EncryptedSha256sum))

		clientMeta := file.ToClientMetadata()

		// DEBUG: Log values after ToClientMetadata conversion
		logging.Log(logging.DEBUG, "File %s - After ToClientMetadata CONVERSION:", file.FileID)
		logging.Log(logging.DEBUG, "  filename_nonce: '%s' (length: %d)", clientMeta.FilenameNonce, len(clientMeta.FilenameNonce))
		logging.Log(logging.DEBUG, "  encrypted_filename: '%s' (length: %d)", clientMeta.EncryptedFilename, len(clientMeta.EncryptedFilename))
		logging.Log(logging.DEBUG, "  sha256sum_nonce: '%s' (length: %d)", clientMeta.Sha256sumNonce, len(clientMeta.Sha256sumNonce))
		logging.Log(logging.DEBUG, "  encrypted_sha256sum: '%s' (length: %d)", clientMeta.EncryptedSha256sum, len(clientMeta.EncryptedSha256sum))

		// TEST BASE64 DECODE FOR DOUBLE-ENCODING DETECTION
		if len(clientMeta.FilenameNonce) > 0 {
			if decoded, err := base64.StdEncoding.DecodeString(clientMeta.FilenameNonce); err == nil {
				logging.Log(logging.DEBUG, "[DEBUG_TEST] Successfully decoded filename_nonce: %d bytes -> %d bytes", len(clientMeta.FilenameNonce), len(decoded))
			} else {
				logging.Log(logging.DEBUG, "[DEBUG_TEST] ERROR decoding filename_nonce: %v", err)
			}
		}

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
