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

	// Calculate byte range for this chunk
	// IMPORTANT: chunk_size_bytes in the DB is the PLAINTEXT chunk size, but the
	// stored object contains ENCRYPTED chunks. Each encrypted chunk is larger due to:
	//   - Chunk 0: envelope header (2 bytes) + AES-GCM nonce (12 bytes) + plaintext + GCM tag (16 bytes)
	//   - Chunk 1+: AES-GCM nonce (12 bytes) + plaintext + GCM tag (16 bytes)
	// We must use encrypted chunk sizes for byte-range calculations in storage.
	plaintextChunkSize := file.ChunkSizeBytes
	if plaintextChunkSize <= 0 {
		plaintextChunkSize = crypto.PlaintextChunkSize()
	}

	gcmOverhead := int64(crypto.AesGcmOverhead())        // nonce (12) + tag (16) = 28
	envelopeHeader := int64(crypto.EnvelopeHeaderSize()) // 2 bytes (chunk 0 only)

	// Encrypted chunk sizes
	chunk0EncSize := envelopeHeader + gcmOverhead + plaintextChunkSize
	regularEncSize := gcmOverhead + plaintextChunkSize

	var startByte, encChunkSize int64
	if chunkIndex == 0 {
		startByte = 0
		encChunkSize = chunk0EncSize
	} else {
		startByte = chunk0EncSize + (chunkIndex-1)*regularEncSize
		encChunkSize = regularEncSize
	}

	endByte := startByte + encChunkSize - 1

	// Adjust for padded files or last chunk - use actual stored size
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
	reader, err := storage.Registry.Primary().GetObjectChunk(c.Request().Context(), file.StorageID, startByte, actualChunkSize)
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
	c.Response().Header().Set("X-Chunk-Size", fmt.Sprintf("%d", plaintextChunkSize))
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
