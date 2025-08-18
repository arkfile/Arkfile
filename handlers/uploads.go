package handlers

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
	"github.com/84adam/arkfile/utils"
)

// CreateUploadSession initializes a new chunked upload
func CreateUploadSession(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var request struct {
		// Client sends encrypted metadata
		EncryptedFilename  string `json:"encryptedFilename"`
		FilenameNonce      string `json:"filenameNonce"`
		EncryptedSha256sum string `json:"encryptedSha256sum"`
		Sha256sumNonce     string `json:"sha256sumNonce"`

		TotalSize    int64  `json:"totalSize"`
		ChunkSize    int    `json:"chunkSize"`
		PasswordHint string `json:"passwordHint"`
		PasswordType string `json:"passwordType"`
		EnvelopeData string `json:"envelopeData"` // Phase 1: base64 envelope
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate encrypted metadata format
	if request.EncryptedFilename == "" || request.FilenameNonce == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing encrypted filename or nonce")
	}
	if request.EncryptedSha256sum == "" || request.Sha256sumNonce == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing encrypted SHA256 or nonce")
	}

	// Validate base64 encoding of encrypted data and nonces
	if _, err := base64.StdEncoding.DecodeString(request.EncryptedFilename); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid encrypted filename encoding")
	}
	if _, err := base64.StdEncoding.DecodeString(request.FilenameNonce); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid filename nonce encoding")
	}
	if _, err := base64.StdEncoding.DecodeString(request.EncryptedSha256sum); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid encrypted SHA256 encoding")
	}
	if _, err := base64.StdEncoding.DecodeString(request.Sha256sumNonce); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid SHA256 nonce encoding")
	}

	// Validate password type
	if request.PasswordType != "account" && request.PasswordType != "custom" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid password type")
	}

	// Phase 1: Validate and process envelope data
	var envelopeData []byte
	var envelopeVersion, envelopeKeyType byte

	if request.EnvelopeData != "" {
		// Decode envelope data
		var err error
		envelopeData, err = base64.StdEncoding.DecodeString(request.EnvelopeData)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid envelope data encoding")
		}

		// Validate envelope format: must be exactly 2 bytes
		if len(envelopeData) != 2 {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid envelope format: must be 2 bytes")
		}

		envelopeVersion = envelopeData[0]
		envelopeKeyType = envelopeData[1]

		// Validate envelope consistency with password type
		switch request.PasswordType {
		case "account":
			if envelopeVersion != 0x01 || envelopeKeyType != 0x01 {
				return echo.NewHTTPError(http.StatusBadRequest, "Envelope mismatch: expected account envelope (0x01, 0x01)")
			}
		case "custom":
			if envelopeVersion != 0x02 || envelopeKeyType != 0x02 {
				return echo.NewHTTPError(http.StatusBadRequest, "Envelope mismatch: expected custom envelope (0x02, 0x02)")
			}
		}

		logging.InfoLogger.Printf("Envelope validation successful: version=0x%02x, keyType=0x%02x for %s",
			envelopeVersion, envelopeKeyType, request.PasswordType)
	}

	// Check user's storage limit and approval status
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	// Check if user is approved for file operations
	if !user.IsApproved {
		return echo.NewHTTPError(http.StatusForbidden, "Account pending approval. File uploads are restricted until your account is approved by an administrator. You can still access other features of your account.")
	}

	if !user.CheckStorageAvailable(request.TotalSize) {
		return echo.NewHTTPError(http.StatusForbidden, "Storage limit would be exceeded")
	}

	// Create upload session
	sessionID := uuid.New().String()
	fileID := models.GenerateFileID() // Generate file_id for the new encrypted metadata system
	totalChunks := (request.TotalSize + int64(request.ChunkSize) - 1) / int64(request.ChunkSize)

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Generate storage ID and calculate padded size
	storageID := models.GenerateStorageID()
	paddingCalculator := utils.NewPaddingCalculator()
	paddedSize, err := paddingCalculator.CalculatePaddedSize(request.TotalSize)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to calculate padding: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process file")
	}

	// Decode encrypted metadata for storage
	encryptedFilename, _ := base64.StdEncoding.DecodeString(request.EncryptedFilename)
	filenameNonce, _ := base64.StdEncoding.DecodeString(request.FilenameNonce)
	encryptedSha256sum, _ := base64.StdEncoding.DecodeString(request.EncryptedSha256sum)
	sha256sumNonce, _ := base64.StdEncoding.DecodeString(request.Sha256sumNonce)

	// Create upload session record with encrypted metadata
	_, err = tx.Exec(
		"INSERT INTO upload_sessions (id, file_id, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, owner_username, total_size, chunk_size, total_chunks, password_hint, password_type, storage_id, padded_size, envelope_data, envelope_version, envelope_key_type, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sessionID, fileID, encryptedFilename, filenameNonce, encryptedSha256sum, sha256sumNonce, username, request.TotalSize, request.ChunkSize, totalChunks, request.PasswordHint, request.PasswordType, storageID, paddedSize, envelopeData, envelopeVersion, envelopeKeyType, "in_progress", time.Now().Add(24*time.Hour),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create upload session")
	}

	// Initialize multipart upload in storage with sessionID metadata
	metadata := map[string]string{
		"session-id":     sessionID,
		"owner-username": username,
	}

	// Get the concrete MinioStorage implementation via type assertion
	minioProvider, ok := storage.Provider.(*storage.MinioStorage)
	if !ok {
		logging.ErrorLogger.Print("Storage provider is not the expected Minio implementation for multipart upload")
		return echo.NewHTTPError(http.StatusInternalServerError, "Storage system configuration error")
	}

	uploadID, err := minioProvider.InitiateMultipartUpload(c.Request().Context(), storageID, metadata)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to initiate multipart upload for file_id %s (storage_id: %s) via provider: %v", fileID, storageID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to initialize storage upload")
	}

	// Update upload session with storage upload ID
	_, err = tx.Exec(
		"UPDATE upload_sessions SET storage_upload_id = ? WHERE id = ?",
		uploadID, sessionID,
	)
	if err != nil {
		// Abort the multipart upload if we can't update the database (using minioProvider)
		// Note: minioProvider should still be in scope here from the assertion above.
		if minioProvider != nil {
			minioProvider.AbortMultipartUpload(c.Request().Context(), storageID, uploadID)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update upload session")
	}

	if err := tx.Commit(); err != nil {
		// Attempt to abort the storage upload if we can't commit (using minioProvider)
		if minioProvider != nil {
			minioProvider.AbortMultipartUpload(c.Request().Context(), storageID, uploadID)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	logging.InfoLogger.Printf("Upload session created: %s by %s (file_id: %s, size: %d bytes)",
		sessionID, username, fileID, request.TotalSize)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"sessionId":   sessionID,
		"fileId":      fileID, // Return file_id for client reference
		"chunkSize":   request.ChunkSize,
		"totalChunks": totalChunks,
		"expiresAt":   time.Now().Add(24 * time.Hour),
	})
}

// GetSharedFileByShareID is deprecated - use the new anonymous share system in file_shares.go
// This function is kept temporarily for backwards compatibility but should not be used
func GetSharedFileByShareID(c echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "This endpoint has been replaced by the new anonymous share system. Please use /api/share/:id instead.")
}

// DownloadFileChunk streams a specific chunk of a file to the client
func DownloadFileChunk(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")
	chunkNumberStr := c.Param("chunkNumber")

	// Parse chunk number
	chunkNumber, err := strconv.Atoi(chunkNumberStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}

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

	// Return encrypted metadata for client-side decryption (base64 encoded)
	c.Response().Header().Set("X-Encrypted-Filename", base64.StdEncoding.EncodeToString(clientMetadata.EncryptedFilename))
	c.Response().Header().Set("X-Filename-Nonce", base64.StdEncoding.EncodeToString(clientMetadata.FilenameNonce))
	c.Response().Header().Set("X-Encrypted-Sha256sum", base64.StdEncoding.EncodeToString(clientMetadata.EncryptedSha256sum))
	c.Response().Header().Set("X-Sha256sum-Nonce", base64.StdEncoding.EncodeToString(clientMetadata.Sha256sumNonce))
	c.Response().Header().Set("X-Password-Hint", file.PasswordHint)
	c.Response().Header().Set("X-Password-Type", file.PasswordType)

	// Log access using file_id
	logging.InfoLogger.Printf("Chunk download: file_id=%s, chunk: %d/%d by %s", fileID, chunkNumber+1, totalChunks, username)

	// Stream the chunk to the client
	return c.Stream(http.StatusOK, "application/octet-stream", reader)
}

// CancelUpload aborts an in-progress upload session
func CancelUpload(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	sessionID := c.Param("sessionId")

	// Verify session exists and belongs to user
	var (
		ownerUsername   string
		fileID          string
		storageID       string
		storageUploadID string
		status          string
	)

	err := database.DB.QueryRow(
		"SELECT owner_username, file_id, storage_id, storage_upload_id, status FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerUsername, &fileID, &storageID, &storageUploadID, &status)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Verify ownership
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized for this upload session")
	}

	// Only in-progress uploads can be canceled
	if status != "in_progress" {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Cannot cancel upload in %s status", status))
	}

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Mark the session as canceled
	_, err = tx.Exec(
		"UPDATE upload_sessions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		"canceled", sessionID,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update session status")
	}

	// Abort the multipart upload in storage using storage provider interface
	if storageUploadID != "" && storageID != "" {
		err = storage.Provider.AbortMultipartUpload(c.Request().Context(), storageID, storageUploadID)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to abort storage upload via storage provider: %v", err)
			// Continue anyway - we still want to mark the session as canceled in the database
		}
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	logging.InfoLogger.Printf("Upload canceled: %s, file_id: %s by %s", sessionID, fileID, username)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Upload canceled successfully",
	})
}

// GetUploadStatus returns the status of an upload session including which chunks have been uploaded
func GetUploadStatus(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	sessionID := c.Param("sessionId")

	// Verify session exists and belongs to user
	var (
		ownerUsername      string
		fileID             string
		encryptedFilename  []byte
		filenameNonce      []byte
		encryptedSha256sum []byte
		sha256sumNonce     []byte
		status             string
		totalChunks        int
		totalSize          int64
		createdAt          time.Time
		expiresAt          time.Time
	)

	err := database.DB.QueryRow(
		"SELECT owner_username, file_id, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, status, total_chunks, total_size, created_at, expires_at FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerUsername, &fileID, &encryptedFilename, &filenameNonce, &encryptedSha256sum, &sha256sumNonce, &status, &totalChunks, &totalSize, &createdAt, &expiresAt)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Verify ownership
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized for this upload session")
	}

	// Get uploaded chunk numbers
	rows, err := database.DB.Query(
		"SELECT chunk_number FROM upload_chunks WHERE session_id = ? ORDER BY chunk_number ASC",
		sessionID,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve uploaded chunks")
	}
	defer rows.Close()

	var uploadedChunks []int
	for rows.Next() {
		var chunkNumber int
		if err := rows.Scan(&chunkNumber); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to scan chunk data")
		}
		uploadedChunks = append(uploadedChunks, chunkNumber)
	}

	if err = rows.Err(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error reading chunk data")
	}

	// Calculate upload progress percentage
	progress := float64(len(uploadedChunks)) / float64(totalChunks) * 100.0

	return c.JSON(http.StatusOK, map[string]interface{}{
		"sessionId":          sessionID,
		"fileId":             fileID,
		"encryptedFilename":  base64.StdEncoding.EncodeToString(encryptedFilename),
		"filenameNonce":      base64.StdEncoding.EncodeToString(filenameNonce),
		"encryptedSha256sum": base64.StdEncoding.EncodeToString(encryptedSha256sum),
		"sha256sumNonce":     base64.StdEncoding.EncodeToString(sha256sumNonce),
		"status":             status,
		"totalChunks":        totalChunks,
		"uploadedChunks":     uploadedChunks,
		"progress":           progress,
		"totalSize":          totalSize,
		"createdAt":          createdAt,
		"expiresAt":          expiresAt,
		"isExpired":          time.Now().After(expiresAt),
	})
}

// UploadChunk handles individual chunk uploads
func UploadChunk(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	sessionID := c.Param("sessionId")
	chunkNumberStr := c.Param("chunkNumber")

	// Parse chunk number
	chunkNumber, err := strconv.Atoi(chunkNumberStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}

	// Verify session exists and belongs to user
	var (
		ownerUsername   string
		fileID          string
		storageID       string
		storageUploadID string
		status          string
		totalChunks     int
	)

	err = database.DB.QueryRow(
		"SELECT owner_username, file_id, storage_id, storage_upload_id, status, total_chunks FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerUsername, &fileID, &storageID, &storageUploadID, &status, &totalChunks)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Verify ownership
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized for this upload session")
	}

	// Verify session status
	if status != "in_progress" {
		return echo.NewHTTPError(http.StatusBadRequest, "Upload session is not in progress")
	}

	// Verify chunk number is valid
	if chunkNumber < 0 || chunkNumber >= totalChunks {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}

	// Get chunk hash from headers (IV header maintained for backwards compatibility)
	chunkHash := c.Request().Header.Get("X-Chunk-Hash")

	if chunkHash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing chunk hash")
	}

	// Validate chunk hash format
	if len(chunkHash) != 64 || !utils.IsHexString(chunkHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk hash format")
	}

	// Phase 2: Validate chunk format - chunks are now [nonce][encrypted_data][tag]
	// No envelope validation needed since envelopes are stored separately
	contentLength := c.Request().ContentLength
	if contentLength != -1 {
		// Minimum chunk size: 12 (nonce) + 1 (data) + 16 (tag) = 29 bytes
		if contentLength < 29 {
			return echo.NewHTTPError(http.StatusBadRequest, "Chunk too small: minimum 29 bytes required")
		}

		// Maximum chunk size: 16MB + 28 bytes overhead
		maxChunkSize := int64(16*1024*1024 + 28)
		if contentLength > maxChunkSize {
			return echo.NewHTTPError(http.StatusBadRequest, "Chunk too large: maximum 16MB + 28 bytes allowed")
		}
	}

	// Minio part numbers are 1-based (consistent with Minio SDK, assuming provider implements this detail)
	minioPartNumber := chunkNumber + 1

	// Stream chunk directly to storage using storage provider interface
	part, err := storage.Provider.UploadPart(
		c.Request().Context(),
		storageID, // Use storage ID instead of filename
		storageUploadID,
		minioPartNumber,
		c.Request().Body,
		-1, // Unknown size, will read until EOF
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to upload chunk %d via storage provider: %v", minioPartNumber, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to upload chunk to storage")
	}

	// Since minio.CompletePart doesn't have a Size field/method, we'll estimate the size
	// from the object length or set a default value
	chunkSize := int64(-1) // Default value indicating unknown size

	// Record chunk metadata in database
	// Note: IV is no longer needed since chunks contain their own nonces
	_, err = database.DB.Exec(
		"INSERT INTO upload_chunks (session_id, chunk_number, chunk_hash, chunk_size, etag) VALUES (?, ?, ?, ?, ?)",
		sessionID, chunkNumber, chunkHash, chunkSize, part.ETag,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to record chunk metadata")
	}

	logging.InfoLogger.Printf("Chunk uploaded: %s, file_id: %s, chunk: %d/%d",
		sessionID, fileID, chunkNumber+1, totalChunks)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"chunkNumber": chunkNumber,
		"etag":        part.ETag,
	})
}

// CompleteUpload finalizes a chunked upload
func CompleteUpload(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	sessionID := c.Param("sessionId")

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Get session details
	var (
		ownerUsername      string
		fileID             string
		storageID          string
		storageUploadID    string
		paddedSize         int64
		status             string
		totalChunks        int
		totalSize          int64
		encryptedFilename  []byte
		filenameNonce      []byte
		encryptedSha256sum []byte
		sha256sumNonce     []byte
		passwordHint       string
		passwordType       string
	)

	err = tx.QueryRow(
		"SELECT owner_username, file_id, storage_id, storage_upload_id, padded_size, status, total_chunks, total_size, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, password_hint, password_type FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(
		&ownerUsername, &fileID, &storageID, &storageUploadID, &paddedSize, &status, &totalChunks,
		&totalSize, &encryptedFilename, &filenameNonce, &encryptedSha256sum, &sha256sumNonce, &passwordHint, &passwordType,
	)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Verify ownership
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized for this upload session")
	}

	// Verify session status
	if status != "in_progress" {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Upload session is %s, not in progress", status))
	}

	// Verify all chunks were uploaded
	var uploadedChunks int
	err = tx.QueryRow(
		"SELECT COUNT(*) FROM upload_chunks WHERE session_id = ?",
		sessionID,
	).Scan(&uploadedChunks)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to count uploaded chunks")
	}

	if uploadedChunks != totalChunks {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Not all chunks uploaded (%d/%d)", uploadedChunks, totalChunks))
	}

	// Get all chunk parts for completing the multipart upload
	rows, err := tx.Query(
		"SELECT chunk_number, etag FROM upload_chunks WHERE session_id = ? ORDER BY chunk_number ASC",
		sessionID,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve chunk metadata")
	}
	defer rows.Close()

	// Collect the parts info required by MinIO
	var parts []minio.CompletePart
	for rows.Next() {
		var chunkNumber int
		var etag string
		if err := rows.Scan(&chunkNumber, &etag); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to scan chunk data")
		}

		// Convert to MinIO's part number (1-based)
		parts = append(parts, minio.CompletePart{
			PartNumber: chunkNumber + 1,
			ETag:       etag,
		})
	}

	if err = rows.Err(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error reading chunk data")
	}

	// Phase 3: Get envelope data from upload session
	var envelopeData []byte
	err = tx.QueryRow(
		"SELECT envelope_data FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&envelopeData)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve envelope data")
	}

	// Complete the multipart upload with envelope concatenation
	if len(envelopeData) > 0 {
		// Use envelope-aware completion for chunked uploads
		err = storage.Provider.CompleteMultipartUploadWithEnvelope(
			c.Request().Context(),
			storageID,
			storageUploadID,
			parts,
			envelopeData,
			totalSize,
			paddedSize,
		)
	} else {
		// Fall back to regular padding completion for non-chunked uploads
		err = storage.Provider.CompleteMultipartUploadWithPadding(
			c.Request().Context(),
			storageID,
			storageUploadID,
			parts,
			totalSize,
			paddedSize,
		)
	}

	if err != nil {
		logging.ErrorLogger.Printf("Failed to complete storage upload via storage provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to complete storage upload: %v", err))
	}

	// Get encrypted file hash from request if provided
	var encryptedHash string
	if c.Request().Header.Get("X-Encrypted-Hash") != "" {
		encryptedHash = c.Request().Header.Get("X-Encrypted-Hash")
		// Validate hash format
		if len(encryptedHash) != 64 || !utils.IsHexString(encryptedHash) {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid encrypted hash format")
		}
	}

	// Mark upload session as completed
	_, err = tx.Exec(
		"UPDATE upload_sessions SET status = ?, encrypted_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		"completed", encryptedHash, sessionID,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update session status")
	}

	// Create file metadata record using encrypted metadata and new schema
	// Note: Using the transaction version of the database connection
	_, err = tx.Exec(`
		INSERT INTO file_metadata (
			file_id, storage_id, owner_username, password_hint, password_type,
			filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, size_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fileID, storageID, username, passwordHint, passwordType,
		filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum, totalSize,
	)
	if err != nil {
		// Handle duplicate file_id (should be extremely rare with UUID v4)
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "file_id") {
			return echo.NewHTTPError(http.StatusConflict, "File ID conflict occurred")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file metadata")
	}

	// Update user's storage usage
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	if err := user.UpdateStorageUsage(tx, totalSize); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	logging.InfoLogger.Printf("Upload completed: %s, file_id: %s by %s (size: %d bytes)",
		sessionID, fileID, username, totalSize)

	database.LogUserAction(username, "uploaded", fileID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "File uploaded successfully",
		"storage": map[string]interface{}{
			"total_bytes":     user.TotalStorageBytes + totalSize,
			"limit_bytes":     user.StorageLimitBytes,
			"available_bytes": user.StorageLimitBytes - (user.TotalStorageBytes + totalSize),
		},
	})
}

// DeleteFile handles file deletion
func DeleteFile(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback() // Rollback if not committed

	// Verify file ownership and get file size and storage_id
	var ownerUsername string
	var storageID string
	var fileSize int64
	err = tx.QueryRow(
		"SELECT owner_username, storage_id, size_bytes FROM file_metadata WHERE file_id = ?",
		fileID,
	).Scan(&ownerUsername, &storageID, &fileSize)

	if err != nil {
		// If there is any error (including sql.ErrNoRows), treat it as 'not found'.
		if err != sql.ErrNoRows {
			logging.ErrorLogger.Printf("Database error checking file ownership for deletion: %v", err)
		}
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	// Verify ownership
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to delete this file")
	}

	// Remove from object storage using storage ID
	err = storage.Provider.RemoveObject(c.Request().Context(), storageID, minio.RemoveObjectOptions{})
	if err != nil {
		logging.ErrorLogger.Printf("Failed to remove file from storage via provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file from storage")
	}

	// Delete metadata from database
	_, err = tx.Exec("DELETE FROM file_metadata WHERE file_id = ?", fileID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete file metadata: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file metadata")
	}

	// Update user's storage usage (reduce by file size)
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Use negative value to reduce storage usage
	if err := user.UpdateStorageUsage(tx, -fileSize); err != nil {
		logging.ErrorLogger.Printf("Failed to update storage usage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete file deletion")
	}

	database.LogUserAction(username, "deleted", fileID)
	logging.InfoLogger.Printf("File deleted: file_id=%s by %s", fileID, username)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "File deleted successfully",
		"storage": map[string]interface{}{
			// Use the user.TotalStorageBytes already updated in memory by UpdateStorageUsage
			"total_bytes": user.TotalStorageBytes,
			"limit_bytes": user.StorageLimitBytes,
			// Calculate available based on the updated total
			"available_bytes": user.StorageLimitBytes - user.TotalStorageBytes,
		},
	})
}
