package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/config"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
	"github.com/84adam/arkfile/utils"
)

// Echo is the global echo instance used for routing
var Echo *echo.Echo

// UploadFile handles file uploads
func UploadFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	// Get user for storage checks
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
	}

	var request struct {
		Filename     string `json:"filename"`
		Data         string `json:"data"`
		PasswordHint string `json:"passwordHint"`
		PasswordType string `json:"passwordType"`
		SHA256Sum    string `json:"sha256sum"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate SHA-256 hash format
	if len(request.SHA256Sum) != 64 || !utils.IsHexString(request.SHA256Sum) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid SHA-256 hash")
	}

	// Validate password type
	if request.PasswordType != "account" && request.PasswordType != "custom" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid password type")
	}

	// Check if file size would exceed user's limit
	fileSize := int64(len(request.Data))
	if !user.CheckStorageAvailable(fileSize) {
		return echo.NewHTTPError(http.StatusForbidden, "Storage limit would be exceeded")
	}

	// Generate storage ID and calculate padded size
	storageID := models.GenerateStorageID()
	paddingCalculator := utils.NewPaddingCalculator()
	paddedSize, err := paddingCalculator.CalculatePaddedSize(fileSize)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to calculate padding: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process file")
	}

	// Start transaction for atomic storage update
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback() // Rollback if not committed

	// Store file in object storage backend using storage ID and padding
	_, err = storage.Provider.PutObjectWithPadding(
		c.Request().Context(),
		storageID, // Use UUID instead of filename
		strings.NewReader(request.Data),
		fileSize,
		paddedSize,
		minio.PutObjectOptions{ContentType: "application/octet-stream"},
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to upload file: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to upload file")
	}

	// Store metadata in database with storage_id and padded_size
	_, err = tx.Exec(
		"INSERT INTO file_metadata (filename, storage_id, owner_email, password_hint, password_type, sha256sum, size_bytes, padded_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		request.Filename, storageID, email, request.PasswordHint, request.PasswordType, request.SHA256Sum, fileSize, paddedSize,
	)
	if err != nil {
		// If metadata storage fails, delete the uploaded file using storage.Provider
		storage.Provider.RemoveObject(c.Request().Context(), storageID, minio.RemoveObjectOptions{})
		logging.ErrorLogger.Printf("Failed to store file metadata: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process file")
	}

	// Update user's storage usage
	if err := user.UpdateStorageUsage(tx, fileSize); err != nil {
		logging.ErrorLogger.Printf("Failed to update storage usage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete upload")
	}

	database.LogUserAction(email, "uploaded", request.Filename)
	logging.InfoLogger.Printf("File uploaded: %s (storage_id: %s) by %s (size: %d bytes, padded: %d bytes)",
		request.Filename, storageID, email, fileSize, paddedSize)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "File uploaded successfully",
		"storage_id": storageID,
		"storage": map[string]interface{}{
			// Use the user.TotalStorageBytes which was updated in memory by UpdateStorageUsage
			"total_bytes": user.TotalStorageBytes,
			"limit_bytes": user.StorageLimitBytes,
			// Calculate available based on the updated total
			"available_bytes": user.StorageLimitBytes - user.TotalStorageBytes,
		},
	})
}

// DownloadFile handles file downloads
func DownloadFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")

	// Get file metadata including storage_id and original size
	var fileMetadata struct {
		StorageID    string
		OwnerEmail   string
		PasswordHint string
		PasswordType string
		SHA256Sum    string
		SizeBytes    int64
	}
	err := database.DB.QueryRow(
		"SELECT storage_id, owner_email, password_hint, password_type, sha256sum, size_bytes FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&fileMetadata.StorageID, &fileMetadata.OwnerEmail, &fileMetadata.PasswordHint,
		&fileMetadata.PasswordType, &fileMetadata.SHA256Sum, &fileMetadata.SizeBytes)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error during download: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Verify ownership
	if fileMetadata.OwnerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Get file from object storage backend using storage ID and remove padding
	reader, err := storage.Provider.GetObjectWithoutPadding(
		c.Request().Context(),
		fileMetadata.StorageID, // Use storage ID instead of filename
		fileMetadata.SizeBytes, // Original size to strip padding
		minio.GetObjectOptions{},
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve file via provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to read file: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read file")
	}

	database.LogUserAction(email, "downloaded", filename)
	logging.InfoLogger.Printf("File downloaded: %s (storage_id: %s) by %s", filename, fileMetadata.StorageID, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":         string(data),
		"passwordHint": fileMetadata.PasswordHint,
		"passwordType": fileMetadata.PasswordType,
		"sha256sum":    fileMetadata.SHA256Sum,
	})
}

// ListFiles returns a list of files owned by the user
func ListFiles(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	rows, err := database.DB.Query(`
		SELECT filename, storage_id, password_hint, password_type, sha256sum, size_bytes, upload_date 
		FROM file_metadata 
		WHERE owner_email = ?
		ORDER BY upload_date DESC
	`, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to list files: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve files")
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var file struct {
			Filename     string
			StorageID    string
			PasswordHint string
			PasswordType string
			SHA256Sum    string
			SizeBytes    int64
			UploadDate   string
		}

		if err := rows.Scan(&file.Filename, &file.StorageID, &file.PasswordHint, &file.PasswordType, &file.SHA256Sum, &file.SizeBytes, &file.UploadDate); err != nil {
			logging.ErrorLogger.Printf("Error scanning file row: %v", err)
			continue
		}

		files = append(files, map[string]interface{}{
			"filename":      file.Filename,
			"storage_id":    file.StorageID,
			"passwordHint":  file.PasswordHint,
			"passwordType":  file.PasswordType,
			"sha256sum":     file.SHA256Sum,
			"size_bytes":    file.SizeBytes,
			"size_readable": formatBytes(file.SizeBytes),
			"uploadDate":    file.UploadDate,
		})
	}

	// Get user's storage information
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user storage info: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get storage info")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"files": files,
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
	// Get admin emails from configuration system
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to load config for admin contacts: %v", err)
		// Fallback to default
		return c.JSON(http.StatusOK, map[string]interface{}{
			"adminEmails": []string{"admin@arkfile.demo"},
			"message":     "Contact information for administrators",
		})
	}

	adminEmails := cfg.Deployment.AdminEmails

	// Fallback if no admin emails configured
	if len(adminEmails) == 0 {
		adminEmails = []string{"admin@arkfile.demo"}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"adminEmails": adminEmails,
		"message":     "Contact information for administrators",
	})
}
