package handlers

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
)

// DownloadFile streams the complete file to the client, internally chunked at 16MB
func DownloadFile(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	// Get file metadata using the models function
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during file download: %v", err)
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
		return echo.NewHTTPError(http.StatusForbidden, "Account pending approval. File downloads are restricted until your account is approved by an administrator.")
	}

	// Get the complete file from storage using storage_id
	reader, err := storage.Provider.GetObject(c.Request().Context(), file.StorageID, minio.GetObjectOptions{})
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file %s (storage_id: %s) from storage provider: %v", fileID, file.StorageID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file from storage")
	}
	defer reader.Close()

	// Set headers for file download
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileID))
	c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", file.SizeBytes))

	// Log the download
	logging.InfoLogger.Printf("File download: file_id=%s by %s (size: %d bytes)", fileID, username, file.SizeBytes)

	// Log user activity
	database.LogUserAction(username, "downloaded", fileID)

	// Stream the complete file to the client
	// The storage provider will internally handle chunking for large files
	return c.Stream(http.StatusOK, "application/octet-stream", reader)
}
