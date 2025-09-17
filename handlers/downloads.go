package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
)

// DownloadFileChunk streams a specific chunk of a file to the client with optional streaming hash verification
func DownloadFileChunk(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")
	chunkNumberStr := c.Param("chunkNumber")

	// Parse chunk number
	chunkNumber, err := strconv.Atoi(chunkNumberStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}

	// Check if client wants streaming hash verification
	enableVerification := c.QueryParam("verify") == "true"

	// Get file by file_id and verify ownership
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get file details")
	}

	// Verify ownership
	if file.OwnerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to access this file")
	}

	// Calculate chunk size based on 16MB standard chunk size (or less for the last chunk)
	const chunkSize int64 = 16 * 1024 * 1024 // 16MB
	totalChunks := (file.SizeBytes + chunkSize - 1) / chunkSize

	// Validate chunk number
	if chunkNumber < 0 || int64(chunkNumber) >= totalChunks {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}

	// Calculate chunk range
	startByte := int64(chunkNumber) * chunkSize
	endByte := startByte + chunkSize - 1
	if endByte >= file.SizeBytes {
		endByte = file.SizeBytes - 1
	}

	// Retrieve chunk from storage using storage_id
	reader, err := storage.Provider.GetObjectChunk(c.Request().Context(), file.StorageID, startByte, endByte-startByte+1)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get chunk for file_id %s (storage_id: %s) via storage provider: %v", fileID, file.StorageID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file chunk from storage")
	}
	defer reader.Close()

	// Return encrypted metadata for client-side decryption
	clientMetadata := file.ToClientMetadata()

	// Set appropriate headers
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.part%d", fileID, chunkNumber))
	c.Response().Header().Set("X-Chunk-Number", strconv.Itoa(chunkNumber))
	c.Response().Header().Set("X-Total-Chunks", strconv.FormatInt(totalChunks, 10))
	c.Response().Header().Set("X-File-Size", strconv.FormatInt(file.SizeBytes, 10))

	// Return encrypted metadata for client-side decryption (already base64 encoded)
	c.Response().Header().Set("X-Encrypted-Filename", clientMetadata.EncryptedFilename)
	c.Response().Header().Set("X-Filename-Nonce", clientMetadata.FilenameNonce)
	c.Response().Header().Set("X-Encrypted-Sha256sum", clientMetadata.EncryptedSha256sum)
	c.Response().Header().Set("X-Sha256sum-Nonce", clientMetadata.Sha256sumNonce)
	c.Response().Header().Set("X-Password-Hint", file.PasswordHint)
	c.Response().Header().Set("X-Password-Type", file.PasswordType)

	// If streaming verification is enabled, set up hash verification
	if enableVerification && file.EncryptedFileSha256sum.Valid && file.EncryptedFileSha256sum.String != "" {
		// Add header to indicate verification is active (for first chunk)
		if chunkNumber == 0 {
			c.Response().Header().Set("X-Hash-Verification", "enabled")
			logging.InfoLogger.Printf("Started streaming hash verification for file_id %s", fileID)
		}

		// If this is the last chunk, include verification status in headers
		if int64(chunkNumber) == totalChunks-1 {
			c.Response().Header().Set("X-Last-Chunk", "true")
		}
	}

	// Log access using file_id
	logging.InfoLogger.Printf("Chunk download: file_id=%s, chunk: %d/%d by %s (verification: %v)",
		fileID, chunkNumber+1, totalChunks, username, enableVerification)

	// If verification is enabled, wrap the reader with hash verification
	if enableVerification && file.EncryptedFileSha256sum.Valid && file.EncryptedFileSha256sum.String != "" {
		// Create a TeeReader that calculates hash while streaming data to client
		teeReader := NewStreamingHashTeeReader(reader, file.EncryptedFileSha256sum.String)

		// If this is the last chunk, verify the complete hash after streaming
		if int64(chunkNumber) == totalChunks-1 {
			defer func() {
				// Verify the complete hash and clean up
				isValid, calculatedHash := teeReader.VerifyHash()

				if isValid {
					logging.InfoLogger.Printf("Download hash verification successful for file_id %s by %s", fileID, username)
				} else {
					logging.ErrorLogger.Printf("Download hash verification FAILED for file_id %s by %s - expected: %s, calculated: %s - file integrity compromised", fileID, username, file.EncryptedFileSha256sum.String, calculatedHash)
				}
			}()
		}

		// Stream through the hash verifying reader
		return c.Stream(http.StatusOK, "application/octet-stream", teeReader)
	}

	// Stream the chunk to the client (no verification)
	return c.Stream(http.StatusOK, "application/octet-stream", reader)
}
