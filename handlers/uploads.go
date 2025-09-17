package handlers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
	"github.com/84adam/Arkfile/utils"
)

// Global streaming hash state management
var (
	streamingHashStates = make(map[string]*StreamingHashState)
	hashStateMutex      sync.RWMutex
)

// CreateUploadSession initializes a new chunked upload
func CreateUploadSession(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var request struct {
		// Client sends encrypted metadata
		EncryptedFilename  string `json:"encrypted_filename"`
		FilenameNonce      string `json:"filename_nonce"`
		EncryptedSha256sum string `json:"encrypted_sha256sum"`
		Sha256sumNonce     string `json:"sha256sum_nonce"`
		EncryptedFek       string `json:"encrypted_fek"`

		TotalSize    int64  `json:"total_size"`
		ChunkSize    int    `json:"chunk_size"`
		PasswordHint string `json:"password_hint"`
		PasswordType string `json:"password_type"`
	}

	// Bind the JSON request body to the struct
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid JSON request: "+err.Error())
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
	if _, err := base64.StdEncoding.DecodeString(request.EncryptedFek); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid encrypted FEK encoding")
	}

	// Validate password type
	if request.PasswordType != "account" && request.PasswordType != "custom" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid password type")
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

	// Create upload session - with safe chunk size validation
	sessionID := uuid.New().String()
	fileID := models.GenerateFileID() // Generate file_id for the new encrypted metadata system

	// Validate and set default chunk size to prevent divide by zero
	if request.ChunkSize <= 0 {
		logging.InfoLogger.Printf("Invalid chunk_size %d received, defaulting to 16MB (16,777,216 bytes)", request.ChunkSize)
		request.ChunkSize = 16 * 1024 * 1024 // 16MB default
	}

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

	encryptedFek, _ := base64.StdEncoding.DecodeString(request.EncryptedFek)

	// Create upload session record with encrypted metadata
	_, err = tx.Exec(
		"INSERT INTO upload_sessions (id, file_id, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, encrypted_fek, owner_username, total_size, chunk_size, total_chunks, password_hint, password_type, storage_id, padded_size, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sessionID, fileID, encryptedFilename, filenameNonce, encryptedSha256sum, sha256sumNonce, encryptedFek, username, request.TotalSize, request.ChunkSize, totalChunks, request.PasswordHint, request.PasswordType, storageID, paddedSize, "in_progress", time.Now().Add(24*time.Hour),
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
		// Abort the multipart upload if we can't update the database
		minioProvider.AbortMultipartUpload(c.Request().Context(), storageID, uploadID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update upload session")
	}

	if err := tx.Commit(); err != nil {
		// Attempt to abort the storage upload if we can't commit (using minioProvider)
		if minioProvider != nil && uploadID != "" {
			minioProvider.AbortMultipartUpload(c.Request().Context(), storageID, uploadID)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	logging.InfoLogger.Printf("Upload session created: %s by %s (file_id: %s, size: %d bytes)",
		sessionID, username, fileID, request.TotalSize)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"session_id":   sessionID,
		"file_id":      fileID, // Return file_id for client reference
		"chunk_size":   request.ChunkSize,
		"total_chunks": totalChunks,
		"expires_at":   time.Now().Add(24 * time.Hour),
	})
}

// GetSharedFileByShareID is deprecated - use the new anonymous share system in file_shares.go
// This function is kept temporarily for backwards compatibility but should not be used
func GetSharedFileByShareID(c echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "This endpoint has been replaced by the new anonymous share system. Please use /api/share/:id instead.")
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
		logging.ErrorLogger.Printf("Failed to get upload session details for sessionID %s: %v", sessionID, err)
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
		filenameNonceRaw   interface{} // Use interface{} to handle RQLite base64 BLOB returns
		encryptedSha256sum []byte
		sha256sumNonceRaw  interface{} // Use interface{} to handle RQLite base64 BLOB returns
		status             string
		totalChunks        int
		totalSizeFloat     sql.NullFloat64 // Handle scientific notation
		createdAtStr       string          // Scan as string first to handle RQLite timestamp format
		expiresAtStr       string          // Scan as string first to handle RQLite timestamp format
	)

	err := database.DB.QueryRow(
		"SELECT owner_username, file_id, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, status, total_chunks, total_size, created_at, expires_at FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerUsername, &fileID, &encryptedFilename, &filenameNonceRaw, &encryptedSha256sum, &sha256sumNonceRaw, &status, &totalChunks, &totalSizeFloat, &createdAtStr, &expiresAtStr)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Parse timestamp strings to time.Time
	var createdAt, expiresAt time.Time
	if createdAtStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr); parseErr == nil {
			createdAt = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			createdAt = parsedTime
		} else {
			// Fallback to current time if parsing fails
			createdAt = time.Now()
		}
	}

	if expiresAtStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", expiresAtStr); parseErr == nil {
			expiresAt = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, expiresAtStr); parseErr == nil {
			expiresAt = parsedTime
		} else {
			// Fallback to future time if parsing fails
			expiresAt = time.Now().Add(24 * time.Hour)
		}
	}

	// Verify ownership
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized for this upload session")
	}

	// Handle FilenameNonce - may be a base64 string from rqlite
	var filenameNonce []byte
	switch v := filenameNonceRaw.(type) {
	case []byte:
		filenameNonce = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to decode base64 for filename_nonce: %v", err))
		}
		filenameNonce = decoded
	case nil:
		filenameNonce = nil
	default:
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Unexpected type for filename_nonce: %T", v))
	}

	// Handle Sha256sumNonce - may be a base64 string from rqlite
	var sha256sumNonce []byte
	switch v := sha256sumNonceRaw.(type) {
	case []byte:
		sha256sumNonce = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to decode base64 for sha256sum_nonce: %v", err))
		}
		sha256sumNonce = decoded
	case nil:
		sha256sumNonce = nil
	default:
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Unexpected type for sha256sum_nonce: %T", v))
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

	var totalSize int64
	if totalSizeFloat.Valid {
		totalSize = int64(totalSizeFloat.Float64)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"session_id":          sessionID,
		"file_id":             fileID,
		"encrypted_filename":  base64.StdEncoding.EncodeToString(encryptedFilename),
		"filename_nonce":      base64.StdEncoding.EncodeToString(filenameNonce),
		"encrypted_sha256sum": base64.StdEncoding.EncodeToString(encryptedSha256sum),
		"sha256sum_nonce":     base64.StdEncoding.EncodeToString(sha256sumNonce),
		"status":              status,
		"total_chunks":        totalChunks,
		"uploaded_chunks":     uploadedChunks,
		"progress":            progress,
		"total_size":          totalSize,
		"created_at":          createdAt,
		"expires_at":          expiresAt,
		"is_expired":          time.Now().After(expiresAt),
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
		storageUploadID sql.NullString
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

	// Phase 2: Validate chunk format based on chunk number
	// Chunk 0: [2-byte envelope][nonce][encrypted_data][tag] = 2 + 12 + 1 + 16 = 31 bytes minimum
	// Chunks 1-N: [nonce][encrypted_data][tag] = 12 + 1 + 16 = 29 bytes minimum
	contentLength := c.Request().ContentLength
	if contentLength != -1 {
		var minChunkSize int64
		var description string

		if chunkNumber == 0 {
			// Chunk 0 includes envelope: 2 (envelope) + 12 (nonce) + 1 (data) + 16 (tag) = 31 bytes
			minChunkSize = 31
			description = "minimum 31 bytes required (includes envelope)"
		} else {
			// Regular chunks: 12 (nonce) + 1 (data) + 16 (tag) = 29 bytes
			minChunkSize = 29
			description = "minimum 29 bytes required"
		}

		if contentLength < minChunkSize {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Chunk %d too small: %s", chunkNumber, description))
		}

		// Maximum chunk size: 16MB + envelope overhead (2 bytes for chunk 0) + crypto overhead (28 bytes)
		maxEnvelopeOverhead := int64(2) // Only for chunk 0
		if chunkNumber != 0 {
			maxEnvelopeOverhead = 0
		}
		maxChunkSize := int64(16*1024*1024) + maxEnvelopeOverhead + 28
		if contentLength > maxChunkSize {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Chunk %d too large: maximum %d bytes allowed", chunkNumber, maxChunkSize))
		}
	}

	// Minio part numbers are 1-based (consistent with Minio SDK, assuming provider implements this detail)
	minioPartNumber := chunkNumber + 1

	// Read the chunk data to calculate hash while streaming to storage
	chunkData, err := io.ReadAll(c.Request().Body)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to read chunk data for hash calculation: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read chunk data")
	}

	// Get or create streaming hash state for this session
	hashStateMutex.Lock()
	hashState, exists := streamingHashStates[sessionID]
	if !exists {
		hashState = NewStreamingHashState(sessionID)
		streamingHashStates[sessionID] = hashState
		logging.InfoLogger.Printf("Initialized streaming hash state for session %s", sessionID)
	}
	hashStateMutex.Unlock()

	// Add this chunk to the running hash calculation
	_, err = hashState.WriteChunk(chunkData)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update streaming hash for session %s, chunk %d: %v", sessionID, chunkNumber, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to calculate streaming hash")
	}

	// Create a reader from the chunk data for uploading to storage
	chunkReader := bytes.NewReader(chunkData)

	var etag string
	if storageUploadID.Valid && storageUploadID.String != "" {
		// Use multipart upload for large files
		part, err := storage.Provider.UploadPart(
			c.Request().Context(),
			storageID, // Use storage ID instead of filename
			storageUploadID.String,
			minioPartNumber,
			chunkReader,
			int64(len(chunkData)), // Use actual chunk data length
		)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to upload chunk %d via storage provider: %v", minioPartNumber, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to upload chunk to storage")
		}
		etag = part.ETag
	} else {
		// For small files, we store chunks temporarily and will use PutObject during completion
		// For now, we just generate a fake etag to satisfy the database constraint
		etag = fmt.Sprintf("chunk-%d-%s", chunkNumber, sessionID[:8])
		logging.InfoLogger.Printf("Storing chunk %d for regular upload (small file)", chunkNumber+1)
	}

	// Get the actual chunk size from the request content length
	chunkSize := c.Request().ContentLength

	// Record chunk metadata in database
	// Note: IV is no longer needed since chunks contain their own nonces
	_, err = database.DB.Exec(
		"INSERT INTO upload_chunks (session_id, chunk_number, chunk_hash, chunk_size, etag) VALUES (?, ?, ?, ?, ?)",
		sessionID, chunkNumber, chunkHash, chunkSize, etag,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to record chunk metadata")
	}

	logging.InfoLogger.Printf("Chunk uploaded: %s, file_id: %s, chunk: %d/%d",
		sessionID, fileID, chunkNumber+1, totalChunks)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"chunk_number": chunkNumber,
		"etag":         etag,
	})
}

// CompleteUpload finalizes a chunked upload
func CompleteUpload(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	sessionID := c.Param("sessionId")

	logging.InfoLogger.Printf("Attempting to complete upload for sessionID: '%s' by user: '%s'", sessionID, username)

	// Step 1: Get session details (excluding BLOBs) without a transaction first.
	var (
		ownerUsername      string
		fileID             sql.NullString
		storageID          sql.NullString
		storageUploadID    sql.NullString
		paddedSizeFloat    sql.NullFloat64 // Handle scientific notation from DB
		status             string
		totalChunks        int
		totalSizeFloat     sql.NullFloat64 // Handle scientific notation from DB
		passwordHint       sql.NullString
		passwordType       sql.NullString
		encryptedFilename  []byte
		filenameNonce      []byte
		encryptedSha256sum []byte
		sha256sumNonce     []byte
		encryptedFek       []byte
	)

	// Query for most data, keeping BLOBs separate. Read large numbers as floats.
	err := database.DB.QueryRow(
		`SELECT owner_username, file_id, storage_id, storage_upload_id, padded_size, status, total_chunks, 
                total_size, password_hint, password_type, encrypted_filename, filename_nonce, 
                encrypted_sha256sum, sha256sum_nonce, encrypted_fek 
         FROM upload_sessions WHERE id = ?`,
		sessionID,
	).Scan(
		&ownerUsername, &fileID, &storageID, &storageUploadID, &paddedSizeFloat, &status, &totalChunks,
		&totalSizeFloat, &passwordHint, &passwordType, &encryptedFilename, &filenameNonce, &encryptedSha256sum, &sha256sumNonce, &encryptedFek,
	)

	if err == sql.ErrNoRows {
		logging.ErrorLogger.Printf("CompleteUpload Error: Session not found in database for sessionID: '%s'. This is the point of failure.", sessionID)
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Failed to get upload session details (part 1) for sessionID %s: %v", sessionID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Manually cast float64 values from DB to int64.
	var totalSize int64
	if totalSizeFloat.Valid {
		totalSize = int64(totalSizeFloat.Float64)
	}

	logging.InfoLogger.Printf("CompleteUpload: DB query (part 1) successful for sessionID: '%s'. Status: '%s'.", sessionID, status)

	// Step 2: Envelope handling removed - envelope is now part of chunk 0

	// Step 3: Perform validation checks on the retrieved data.
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized for this upload session")
	}
	if status != "in_progress" {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Upload session is %s, not in progress", status))
	}

	// Verify all chunks were uploaded.
	var uploadedChunks int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM upload_chunks WHERE session_id = ?", sessionID).Scan(&uploadedChunks)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to count uploaded chunks")
	}
	if uploadedChunks != totalChunks {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Not all chunks uploaded (%d/%d)", uploadedChunks, totalChunks))
	}

	// Get all chunk parts for completing the multipart upload.
	rows, err := database.DB.Query("SELECT chunk_number, etag FROM upload_chunks WHERE session_id = ? ORDER BY chunk_number ASC", sessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve chunk metadata")
	}
	defer rows.Close()

	var parts []minio.CompletePart
	for rows.Next() {
		var chunkNumber int
		var etag string
		if err := rows.Scan(&chunkNumber, &etag); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to scan chunk data")
		}
		parts = append(parts, minio.CompletePart{PartNumber: chunkNumber + 1, ETag: etag})
	}
	if err = rows.Err(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error reading chunk data")
	}

	// Step 4: Get the streaming hash calculated during chunk uploads
	hashStateMutex.RLock()
	hashState, hashExists := streamingHashStates[sessionID]
	hashStateMutex.RUnlock()

	var serverCalculatedHash string
	if hashExists {
		// Finalize the streaming hash calculation
		serverCalculatedHash = hashState.FinalizeHash()
		logging.InfoLogger.Printf("Streaming hash calculated for session %s: %s", sessionID, serverCalculatedHash)

		// Clean up the hash state since upload is completing
		hashStateMutex.Lock()
		delete(streamingHashStates, sessionID)
		hashStateMutex.Unlock()
	} else {
		logging.ErrorLogger.Printf("No streaming hash state found for session %s - this should not happen", sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Hash calculation failed - no streaming state found")
	}

	// Step 5: Complete the multipart upload in storage (using streaming hash instead of storage-calculated hash)
	// Use standard CompleteMultipartUpload since envelope is now part of chunk 0
	err = storage.Provider.CompleteMultipartUpload(c.Request().Context(), storageID.String, storageUploadID.String, parts)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to complete storage upload via storage provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to complete storage upload: %v", err))
	}

	// Step 6: Begin the final, short-lived transaction now that I/O is complete.
	tx, err := database.DB.Begin()
	if err != nil {
		logging.ErrorLogger.Printf("CRITICAL: Failed to start transaction after completing storage upload for session %s. Orphaned file may exist: %s", sessionID, storageID.String)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start database transaction")
	}
	defer tx.Rollback()

	// Update session status.
	if _, err := tx.Exec("UPDATE upload_sessions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", "completed", sessionID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update session status")
	}

	// Create the final file metadata record.
	_, err = tx.Exec(`
		INSERT INTO file_metadata (file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, encrypted_file_sha256sum, encrypted_fek, size_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fileID.String, storageID.String, username, passwordHint.String, passwordType.String, filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum, serverCalculatedHash, encryptedFek, totalSize,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "file_id") {
			return echo.NewHTTPError(http.StatusConflict, "File ID conflict occurred")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file metadata")
	}

	// Update user's storage usage.
	user, err := models.GetUserByUsername(tx, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}
	if err := user.UpdateStorageUsage(tx, totalSize); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Commit the transaction.
	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	logging.InfoLogger.Printf("Upload completed: %s, file_id: %s by %s (size: %d bytes)", sessionID, fileID.String, username, totalSize)
	database.LogUserAction(username, "uploaded", fileID.String)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":               "File uploaded successfully",
		"file_id":               fileID.String,
		"storage_id":            storageID.String, // Expose storage ID for test verification
		"encrypted_file_sha256": serverCalculatedHash,
		"storage": map[string]interface{}{
			"total_bytes":     user.TotalStorageBytes,
			"limit_bytes":     user.StorageLimitBytes,
			"available_bytes": user.StorageLimitBytes - user.TotalStorageBytes,
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
	user, err := models.GetUserByUsername(tx, username)
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
