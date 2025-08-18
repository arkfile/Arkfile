package handlers

import (
	"encoding/base64"
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

// UploadFile handles file uploads with encrypted metadata
func UploadFile(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	// Get user for storage checks and approval status
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
	}

	// Check if user is approved for file operations
	if !user.IsApproved {
		return echo.NewHTTPError(http.StatusForbidden, "Account pending approval. File uploads are restricted until your account is approved by an administrator. You can still access other features of your account.")
	}

	var request struct {
		Data               string `json:"data"`
		PasswordHint       string `json:"passwordHint"`
		PasswordType       string `json:"passwordType"`
		EncryptedFilename  string `json:"encryptedFilename"`
		FilenameNonce      string `json:"filenameNonce"`
		EncryptedSha256sum string `json:"encryptedSha256sum"`
		Sha256sumNonce     string `json:"sha256sumNonce"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate encrypted metadata is provided
	if request.EncryptedFilename == "" || request.FilenameNonce == "" ||
		request.EncryptedSha256sum == "" || request.Sha256sumNonce == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing encrypted metadata")
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

	// Generate file ID and decode encrypted metadata for storage
	fileID := models.GenerateFileID()

	// Decode base64 encoded encrypted data and nonces
	encryptedFilenameBytes, err := base64.StdEncoding.DecodeString(request.EncryptedFilename)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid encrypted filename encoding")
	}

	filenameNonceBytes, err := base64.StdEncoding.DecodeString(request.FilenameNonce)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid filename nonce encoding")
	}

	encryptedSha256sumBytes, err := base64.StdEncoding.DecodeString(request.EncryptedSha256sum)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid encrypted sha256sum encoding")
	}

	sha256sumNonceBytes, err := base64.StdEncoding.DecodeString(request.Sha256sumNonce)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid sha256sum nonce encoding")
	}

	// Store metadata in database with encrypted fields
	_, err = tx.Exec(
		"INSERT INTO file_metadata (file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, size_bytes, padded_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		fileID, storageID, username, request.PasswordHint, request.PasswordType, filenameNonceBytes, encryptedFilenameBytes, sha256sumNonceBytes, encryptedSha256sumBytes, fileSize, paddedSize,
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

	database.LogUserAction(username, "uploaded", fileID)
	logging.InfoLogger.Printf("File uploaded by %s (file_id: %s, storage_id: %s, size: %d bytes, padded: %d bytes)",
		username, fileID, storageID, fileSize, paddedSize)

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

// DownloadFile handles file downloads with encrypted metadata
func DownloadFile(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId") // Now uses fileId instead of filename

	// Check if user is approved for file operations
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
	}

	if !user.IsApproved {
		return echo.NewHTTPError(http.StatusForbidden, "Account pending approval. File downloads are restricted until your account is approved by an administrator. You can still access other features of your account.")
	}

	// Get file metadata using the new encrypted schema
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during download: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Verify ownership
	if file.OwnerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Get file from object storage backend using storage ID and remove padding
	reader, err := storage.Provider.GetObjectWithoutPadding(
		c.Request().Context(),
		file.StorageID, // Use storage ID instead of filename
		file.SizeBytes, // Original size to strip padding
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

	database.LogUserAction(username, "downloaded", fileID)
	logging.InfoLogger.Printf("File downloaded: file_id %s (storage_id: %s) by %s", fileID, file.StorageID, username)

	// Return encrypted metadata for client-side decryption
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":               string(data),
		"passwordHint":       file.PasswordHint,
		"passwordType":       file.PasswordType,
		"filenameNonce":      base64.StdEncoding.EncodeToString(file.FilenameNonce),
		"encryptedFilename":  base64.StdEncoding.EncodeToString(file.EncryptedFilename),
		"sha256sumNonce":     base64.StdEncoding.EncodeToString(file.Sha256sumNonce),
		"encryptedSha256sum": base64.StdEncoding.EncodeToString(file.EncryptedSha256sum),
	})
}

// ListFiles returns a list of files owned by the user with encrypted metadata
func ListFiles(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	// Get files using the models function with encrypted metadata support
	files, err := models.GetFilesByOwner(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to list files: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve files")
	}

	// Convert files to client metadata format
	var fileList []map[string]interface{}
	for _, file := range files {
		clientMetadata := file.ToClientMetadata()
		fileMetadata := map[string]interface{}{
			"file_id":            file.FileID,
			"storage_id":         file.StorageID,
			"passwordHint":       file.PasswordHint,
			"passwordType":       file.PasswordType,
			"filenameNonce":      base64.StdEncoding.EncodeToString(clientMetadata.FilenameNonce),
			"encryptedFilename":  base64.StdEncoding.EncodeToString(clientMetadata.EncryptedFilename),
			"sha256sumNonce":     base64.StdEncoding.EncodeToString(clientMetadata.Sha256sumNonce),
			"encryptedSha256sum": base64.StdEncoding.EncodeToString(clientMetadata.EncryptedSha256sum),
			"size_bytes":         file.SizeBytes,
			"size_readable":      formatBytes(file.SizeBytes),
			"uploadDate":         file.UploadDate,
		}
		fileList = append(fileList, fileMetadata)
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
