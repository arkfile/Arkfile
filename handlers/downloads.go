package handlers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"

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
	// Handle padded files if necessary
	var reader io.ReadCloser

	if file.PaddedSize.Valid && file.PaddedSize.Int64 > file.SizeBytes {
		reader, err = storage.Provider.GetObjectWithoutPadding(c.Request().Context(), file.StorageID, file.SizeBytes, storage.GetObjectOptions{})
	} else {
		reader, err = storage.Provider.GetObject(c.Request().Context(), file.StorageID, storage.GetObjectOptions{})
	}

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

// DownloadFileChunk streams a specific chunk of a file to the client
// GET /api/files/:fileId/chunks/:chunkIndex
// Returns the specified chunk (0-indexed) of the file
func DownloadFileChunk(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")
	chunkIndexStr := c.Param("chunkIndex")

	// Parse chunk index
	chunkIndex, err := parseChunkIndex(chunkIndexStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk index")
	}

	// Get file metadata using the models function
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during chunk download: %v", err)
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

	// Validate chunk index against file's chunk count
	if chunkIndex < 0 || chunkIndex >= file.ChunkCount {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid chunk index: must be between 0 and %d", file.ChunkCount-1))
	}

	// Calculate byte range for this chunk
	chunkSizeBytes := file.ChunkSizeBytes
	if chunkSizeBytes <= 0 {
		chunkSizeBytes = models.DefaultChunkSizeBytes
	}

	startByte := chunkIndex * chunkSizeBytes
	endByte := startByte + chunkSizeBytes - 1

	// Adjust for padded files - use original size for range calculation
	actualFileSize := file.SizeBytes
	if file.PaddedSize.Valid && file.PaddedSize.Int64 > file.SizeBytes {
		// File is padded, we need to ensure we don't read past the original size
		if endByte >= actualFileSize {
			endByte = actualFileSize - 1
		}
	} else {
		// No padding, use size_bytes directly
		if endByte >= actualFileSize {
			endByte = actualFileSize - 1
		}
	}

	// Calculate actual chunk size for this chunk
	actualChunkSize := endByte - startByte + 1
	if actualChunkSize <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk range")
	}

	// Get the chunk from storage using byte range
	// GetObjectChunk takes offset and length, not start and end
	reader, err := storage.Provider.GetObjectChunk(c.Request().Context(), file.StorageID, startByte, actualChunkSize)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get chunk %d of file %s (storage_id: %s) from storage provider: %v", chunkIndex, fileID, file.StorageID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve chunk from storage")
	}
	defer reader.Close()

	// Set headers for chunk download
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", actualChunkSize))
	c.Response().Header().Set("X-Chunk-Index", fmt.Sprintf("%d", chunkIndex))
	c.Response().Header().Set("X-Total-Chunks", fmt.Sprintf("%d", file.ChunkCount))
	c.Response().Header().Set("X-Chunk-Size", fmt.Sprintf("%d", chunkSizeBytes))
	c.Response().Header().Set("X-File-Size", fmt.Sprintf("%d", file.SizeBytes))
	c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startByte, endByte, file.SizeBytes))

	// Log the chunk download (only log first and last chunk to reduce noise)
	if chunkIndex == 0 || chunkIndex == file.ChunkCount-1 {
		logging.InfoLogger.Printf("Chunk download: file_id=%s chunk=%d/%d by %s (bytes %d-%d)", fileID, chunkIndex, file.ChunkCount, username, startByte, endByte)
	}

	// Stream the chunk to the client
	return c.Stream(http.StatusOK, "application/octet-stream", reader)
}

// parseChunkIndex parses a chunk index string to int64
func parseChunkIndex(s string) (int64, error) {
	n := int64(0)
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid chunk index")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// GetFileDownloadMetadata returns metadata about a file's chunks for resumable downloads
// GET /api/files/:fileId/metadata
func GetFileDownloadMetadata(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	// Get file metadata using the models function
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during chunk info request: %v", err)
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

	// Return chunk information
	return c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":          file.FileID,
		"size_bytes":       file.SizeBytes,
		"chunk_count":      file.ChunkCount,
		"chunk_size_bytes": file.ChunkSizeBytes,
	})
}
