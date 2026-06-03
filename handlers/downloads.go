package handlers

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
)

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

	// Calculate byte range for this chunk.
	// every encrypted chunk is uniform
	// [nonce (12)][ciphertext][tag (16)] = plaintext_chunk_size + 28. There
	// is no chunk-0 envelope-header prefix in the chunk stream; the FEK
	// envelope lives in file_metadata.encrypted_fek separately.
	//
	// chunk_size_bytes in the DB is the PLAINTEXT chunk size; the stored
	// object contains the encrypted-chunk stream. Range requests are
	// always bounded by file.SizeBytes (the encrypted-stream length), never
	// by file.PaddedSize: padding lives at byte offsets [size_bytes,
	// padded_size) and must never be returned as decryptable chunk data.
	plaintextChunkSize := file.ChunkSizeBytes
	if plaintextChunkSize <= 0 {
		plaintextChunkSize = crypto.PlaintextChunkSize()
	}

	gcmOverhead := int64(crypto.AesGcmOverhead()) // nonce (12) + tag (16) = 28
	encChunkSize := gcmOverhead + plaintextChunkSize

	startByte := chunkIndex * encChunkSize
	endByte := startByte + encChunkSize - 1

	// Bound the final chunk by the encrypted-stream length, not padded_size.
	if endByte >= file.SizeBytes {
		endByte = file.SizeBytes - 1
	}

	// Calculate actual chunk size for this chunk
	actualChunkSize := endByte - startByte + 1
	if actualChunkSize <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk range")
	}

	// Get the chunk from storage using byte range with three-tier fallback
	reader, _, err := storage.Registry.GetObjectChunkWithFallback(c.Request().Context(), file.StorageID, startByte, actualChunkSize)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get chunk %d of file %s (storage_id: %s) from all providers: %v", chunkIndex, fileID, file.StorageID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve chunk from storage")
	}
	defer reader.Close()

	// Set headers for chunk download
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", actualChunkSize))
	c.Response().Header().Set("X-Chunk-Index", fmt.Sprintf("%d", chunkIndex))
	c.Response().Header().Set("X-Total-Chunks", fmt.Sprintf("%d", file.ChunkCount))
	c.Response().Header().Set("X-Chunk-Size", fmt.Sprintf("%d", plaintextChunkSize))
	c.Response().Header().Set("X-File-Size", fmt.Sprintf("%d", file.SizeBytes))
	c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startByte, endByte, file.SizeBytes))

	// Log the chunk download (only log first and last chunk to reduce noise)
	if chunkIndex == 0 || chunkIndex == file.ChunkCount-1 {
		logging.InfoLogger.Printf("Chunk download: file_id=%s chunk=%d/%d (bytes %d-%d)", fileID, chunkIndex, file.ChunkCount, startByte, endByte)
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
