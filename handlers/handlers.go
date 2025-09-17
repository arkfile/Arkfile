package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
	"github.com/84adam/Arkfile/utils"
)

// Echo is the global echo instance used for routing
var Echo *echo.Echo

// formatFileSize formats bytes to human readable format
// Shared utility function used across handlers
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	if exp >= len(units) {
		return fmt.Sprintf("%d B", bytes)
	}

	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

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
		PasswordHint       string `json:"password_hint"`
		PasswordType       string `json:"password_type"`
		EncryptedFilename  string `json:"encrypted_filename"`
		FilenameNonce      string `json:"filename_nonce"`
		EncryptedSha256sum string `json:"encrypted_sha256sum"`
		Sha256sumNonce     string `json:"sha256sum_nonce"`
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
