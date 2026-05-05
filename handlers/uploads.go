package handlers

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
	"github.com/84adam/Arkfile/utils"
)

// Global streaming hash state management
var (
	streamingHashStates  = make(map[string]*StreamingHashState) // hashes encrypted data only (pre-padding)
	storedBlobHashStates = make(map[string]*StreamingHashState) // hashes all bytes sent to S3 (including padding)
	hashStateMutex       sync.RWMutex
)

// Per-user cap on concurrent in-progress upload sessions. A buggy or hostile
// client can otherwise open arbitrary numbers of init'd-but-never-completed
// sessions, occupying storage they have not yet finalized and starving
// themselves of the ability to upload anything new. The cap is per-user, so
// it never affects unrelated users. See docs/wip/general-enhancements.md
// item 4.
const maxInProgressUploadSessionsPerUser = 4

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

	// Basic validation - ensure required fields are not empty (base64 format validation removed for Phase 1A)
	// Client is responsible for providing properly formatted base64 strings

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
		logging.InfoLogger.Printf("Invalid chunk_size %d received, defaulting to configured plaintext chunk size", request.ChunkSize)
		request.ChunkSize = int(crypto.PlaintextChunkSize())
	}

	// Compute the expected number of chunks from the *encrypted* total size.
	//
	// The client sends request.TotalSize as the total encrypted byte count, which
	// is larger than the plaintext file size. Each encrypted chunk carries
	// AES-GCM overhead: nonce (12 bytes) + tag (16 bytes) = 28 bytes.
	// The first chunk additionally has a 2-byte envelope header prepended.
	//
	// Dividing the encrypted total by the *plaintext* chunk size (as was done
	// previously) overcounts by 1 for files whose plaintext size is exactly
	// N × PlaintextChunkSize, because the header+overhead bytes push the
	// encrypted size just over the next multiple of ChunkSize.
	//
	// The correct derivation:
	//   encryptedChunkSize = ChunkSize + 28  (plaintext + GCM overhead)
	//   effectiveSize      = TotalSize - 2   (strip the one-time 2-byte header)
	//   totalChunks        = ceil(effectiveSize / encryptedChunkSize)
	//
	// This matches the number of uploadChunk requests the client will actually make.
	const aesGcmOverheadBytes = 28 // nonce(12) + tag(16)
	const envelopeHeaderBytes = 2  // version(1) + keyType(1), prepended to chunk 0 only
	encryptedChunkSize := int64(request.ChunkSize) + aesGcmOverheadBytes
	effectiveEncryptedSize := request.TotalSize - envelopeHeaderBytes
	if effectiveEncryptedSize <= 0 {
		effectiveEncryptedSize = encryptedChunkSize // empty file: at least 1 chunk
	}
	totalChunks := (effectiveEncryptedSize + encryptedChunkSize - 1) / encryptedChunkSize

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Per-user concurrent in-progress upload session cap with opportunistic
	// stale-session cleanup. Both queries are scoped to the calling user, so
	// they cannot interfere with other users. The cleanup marks expired
	// in-progress sessions as 'abandoned' so they no longer count toward the
	// cap. The count is taken inside the same transaction as the subsequent
	// INSERT, so we cannot race past the cap. See docs/wip/general-enhancements.md
	// item 4.
	if _, err := tx.Exec(
		`UPDATE upload_sessions
		    SET status = 'abandoned', updated_at = CURRENT_TIMESTAMP
		  WHERE owner_username = ?
		    AND status = 'in_progress'
		    AND expires_at < CURRENT_TIMESTAMP`,
		username,
	); err != nil {
		logging.ErrorLogger.Printf("Failed to mark expired upload sessions as abandoned for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to clean up stale upload sessions")
	}

	var inProgressCount int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`,
		username,
	).Scan(&inProgressCount); err != nil {
		logging.ErrorLogger.Printf("Failed to count in-progress upload sessions for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify upload session capacity")
	}
	if inProgressCount >= maxInProgressUploadSessionsPerUser {
		logging.InfoLogger.Printf("User %s blocked at upload session cap (%d in-progress, max %d)",
			username, inProgressCount, maxInProgressUploadSessionsPerUser)
		// Stable error code 'too_many_in_progress_uploads' lets clients switch
		// on a code rather than parsing English. Aligned with the standing
		// pattern in docs/wip/general-enhancements.md item 9.
		return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
			"success": false,
			"error":   "too_many_in_progress_uploads",
			"message": fmt.Sprintf("You have %d upload(s) already in progress (max %d). Cancel one or wait for it to complete or expire.", inProgressCount, maxInProgressUploadSessionsPerUser),
			"data": map[string]interface{}{
				"in_progress_count": inProgressCount,
				"max_in_progress":   maxInProgressUploadSessionsPerUser,
			},
		})
	}

	// Generate storage ID and calculate padded size
	storageID := models.GenerateStorageID()
	paddingCalculator := utils.NewPaddingCalculator()
	paddedSize, err := paddingCalculator.CalculatePaddedSize(request.TotalSize)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to calculate padding: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process file")
	}

	// Store encrypted metadata as base64 strings directly (no binary conversion)
	// This eliminates double-encoding issues and simplifies the architecture
	// Ensure metadata is not already base64-encoded to prevent double-encoding
	encryptedFilename := request.EncryptedFilename
	filenameNonce := request.FilenameNonce
	encryptedSha256sum := request.EncryptedSha256sum
	sha256sumNonce := request.Sha256sumNonce
	encryptedFek := request.EncryptedFek

	// Note: Encrypted metadata values arrive from client already base64-encoded.
	// Do NOT re-encode them — store as-is to prevent double-encoding.

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

	uploadID, err := storage.Registry.Primary().InitiateMultipartUpload(c.Request().Context(), storageID, metadata)
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
		storage.Registry.Primary().AbortMultipartUpload(c.Request().Context(), storageID, uploadID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update upload session")
	}

	if err := tx.Commit(); err != nil {
		// Attempt to abort the storage upload if we can't commit
		if uploadID != "" {
			storage.Registry.Primary().AbortMultipartUpload(c.Request().Context(), storageID, uploadID)
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
		err = storage.Registry.Primary().AbortMultipartUpload(c.Request().Context(), storageID, storageUploadID)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to abort storage upload via storage provider: %v", err)
			// Continue anyway - we still want to mark the session as canceled in the database
		}
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	// Clean up any in-progress hash states for this session
	hashStateMutex.Lock()
	delete(streamingHashStates, sessionID)
	delete(storedBlobHashStates, sessionID)
	hashStateMutex.Unlock()

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
		encryptedFilename  string // Now stored as base64 strings directly
		filenameNonce      string // Now stored as base64 strings directly
		encryptedSha256sum string // Now stored as base64 strings directly
		sha256sumNonce     string // Now stored as base64 strings directly
		status             string
		totalChunks        int
		totalSizeFloat     sql.NullFloat64 // Handle scientific notation
		createdAtStr       string          // Scan as string first to handle RQLite timestamp format
		expiresAtStr       string          // Scan as string first to handle RQLite timestamp format
	)

	err := database.DB.QueryRow(
		"SELECT owner_username, file_id, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, status, total_chunks, total_size, created_at, expires_at FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerUsername, &fileID, &encryptedFilename, &filenameNonce, &encryptedSha256sum, &sha256sumNonce, &status, &totalChunks, &totalSizeFloat, &createdAtStr, &expiresAtStr)

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
		"encrypted_filename":  encryptedFilename,  // Already base64 strings
		"filename_nonce":      filenameNonce,      // Already base64 strings
		"encrypted_sha256sum": encryptedSha256sum, // Already base64 strings
		"sha256sum_nonce":     sha256sumNonce,     // Already base64 strings
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

	// Verify session exists and belongs to user.
	// Numeric columns use interface{} because rqlite may return int64 or float64.
	var (
		ownerUsername   string
		fileID          string
		storageID       string
		storageUploadID sql.NullString
		status          string
		totalChunks     int
		totalSizeRaw    interface{}
		paddedSizeRaw   interface{}
	)

	err = database.DB.QueryRow(
		"SELECT owner_username, file_id, storage_id, storage_upload_id, status, total_chunks, total_size, padded_size FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerUsername, &fileID, &storageID, &storageUploadID, &status, &totalChunks, &totalSizeRaw, &paddedSizeRaw)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("UploadChunk: failed to read session %s: %v", sessionID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Convert total_size from interface{} to int64
	var totalSize int64
	switch v := totalSizeRaw.(type) {
	case int64:
		totalSize = v
	case float64:
		totalSize = int64(v)
	default:
		logging.ErrorLogger.Printf("UploadChunk: unexpected type %T for total_size in session %s", totalSizeRaw, sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read session total_size")
	}

	// Convert padded_size from interface{} to int64
	var paddedSize int64
	switch v := paddedSizeRaw.(type) {
	case int64:
		paddedSize = v
	case float64:
		paddedSize = int64(v)
	default:
		logging.ErrorLogger.Printf("UploadChunk: unexpected type %T for padded_size in session %s", paddedSizeRaw, sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read session padded_size")
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

	// Get chunk hash from header (SHA-256 hex of encrypted chunk bytes)
	chunkHash := c.Request().Header.Get("X-Chunk-Hash")

	if chunkHash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing chunk hash")
	}

	// Validate chunk hash format
	if len(chunkHash) != 64 || !isHexString(chunkHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk hash format")
	}

	// Phase 2: Validate chunk format based on chunk number
	// Chunk 0: [envelope][nonce][encrypted_data][tag] = envelope + nonce + 1 + tag bytes minimum
	// Chunks 1-N: [nonce][encrypted_data][tag] = nonce + 1 + tag bytes minimum
	contentLength := c.Request().ContentLength
	gcmOverhead := int64(crypto.AesGcmOverhead()) // nonce + tag
	envelopeSize := int64(crypto.EnvelopeHeaderSize())
	if contentLength != -1 {
		var minChunkSize int64
		var description string

		if chunkNumber == 0 {
			// Chunk 0 includes envelope header + nonce + at least 1 byte data + tag
			minChunkSize = envelopeSize + gcmOverhead + 1
			description = fmt.Sprintf("minimum %d bytes required (includes envelope)", minChunkSize)
		} else {
			// Regular chunks: nonce + at least 1 byte data + tag
			minChunkSize = gcmOverhead + 1
			description = fmt.Sprintf("minimum %d bytes required", minChunkSize)
		}

		if contentLength < minChunkSize {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Chunk %d too small: %s", chunkNumber, description))
		}

		// Maximum chunk size: plaintext chunk size + envelope overhead (chunk 0 only) + crypto overhead
		maxEnvelopeOverhead := envelopeSize // Only for chunk 0
		if chunkNumber != 0 {
			maxEnvelopeOverhead = 0
		}
		maxChunkSize := crypto.PlaintextChunkSize() + maxEnvelopeOverhead + gcmOverhead
		if contentLength > maxChunkSize {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Chunk %d too large: maximum %d bytes allowed", chunkNumber, maxChunkSize))
		}
	}

	// Part numbers are 1-based (consistent with S3 API)
	partNumber := chunkNumber + 1

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

	// Add this chunk to the running hash calculation (hash only real encrypted data, not padding)
	_, err = hashState.WriteChunk(chunkData)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update streaming hash for session %s, chunk %d: %v", sessionID, chunkNumber, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to calculate streaming hash")
	}

	// For the last chunk, append crypto-random padding bytes to obscure file size
	// in the storage backend. Padding is appended AFTER hashing so the streaming
	// hash covers only the real encrypted data. The combined (chunk + padding) is
	// uploaded as a single S3 part, avoiding the S3 5MB minimum part size issue
	// that would occur if padding were a separate part.
	uploadData := chunkData
	if chunkNumber == totalChunks-1 && paddedSize > totalSize {
		paddingSize := paddedSize - totalSize
		paddingBytes := make([]byte, paddingSize)
		if _, randErr := cryptoRand.Read(paddingBytes); randErr != nil {
			logging.ErrorLogger.Printf("Failed to generate padding bytes for session %s: %v", sessionID, randErr)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate padding")
		}
		uploadData = append(chunkData, paddingBytes...)
		logging.InfoLogger.Printf("Last chunk %d: appended %d bytes of padding (encrypted: %d, padded total: %d)",
			chunkNumber, paddingSize, totalSize, paddedSize)
	}

	// Update stored blob hash with ALL data sent to S3 (including padding on last chunk).
	// For non-last chunks uploadData == chunkData, so both hashes see the same bytes.
	// For the last chunk, this hash additionally includes the padding bytes.
	hashStateMutex.Lock()
	blobHashState, blobExists := storedBlobHashStates[sessionID]
	if !blobExists {
		blobHashState = NewStreamingHashState(sessionID)
		storedBlobHashStates[sessionID] = blobHashState
	}
	hashStateMutex.Unlock()

	if _, err := blobHashState.WriteChunk(uploadData); err != nil {
		logging.ErrorLogger.Printf("Failed to update stored blob hash for session %s, chunk %d: %v", sessionID, chunkNumber, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to calculate stored blob hash")
	}

	// Create a seekable reader from the upload data for S3
	chunkReader := bytes.NewReader(uploadData)

	var etag string
	if storageUploadID.Valid && storageUploadID.String != "" {
		part, err := storage.Registry.Primary().UploadPart(
			c.Request().Context(),
			storageID,
			storageUploadID.String,
			partNumber,
			chunkReader,
			int64(len(uploadData)),
		)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to upload chunk %d via storage provider: %v", partNumber, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to upload chunk to storage")
		}
		etag = part.ETag
	} else {
		logging.ErrorLogger.Printf("Upload session %s has no storage upload ID", sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Upload session has no storage upload ID")
	}

	// Record the size of data uploaded (including padding for last chunk)
	chunkSize := int64(len(uploadData))

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

	// Step 1: Get session details without a transaction first.
	// Numeric columns are scanned as interface{} to handle rqlite returning
	// int64 or float64 depending on value magnitude. Type switches convert
	// them cleanly — no NullFloat64 workarounds.
	var (
		ownerUsername   string
		fileID          sql.NullString
		storageID       sql.NullString
		storageUploadID sql.NullString
		status          string
		totalChunks     int
		passwordHint    sql.NullString
		passwordType    sql.NullString
	)

	// interface{} scans for numeric fields (rqlite may return int64 or float64)
	var totalSizeRaw interface{}
	var chunkSizeRaw interface{}
	var paddedSizeRaw interface{}

	// []byte scans for metadata fields to prevent double-encoding during JSON marshaling
	var encryptedFilenameBytes []byte
	var filenameNonceBytes []byte
	var encryptedSha256sumBytes []byte
	var sha256sumNonceBytes []byte
	var encryptedFekBytes []byte

	err := database.DB.QueryRow(
		`SELECT owner_username, file_id, storage_id, storage_upload_id, status, total_chunks,
                total_size, chunk_size, padded_size, password_hint, password_type, encrypted_filename, filename_nonce,
                encrypted_sha256sum, sha256sum_nonce, encrypted_fek
         FROM upload_sessions WHERE id = ?`,
		sessionID,
	).Scan(
		&ownerUsername, &fileID, &storageID, &storageUploadID, &status, &totalChunks,
		&totalSizeRaw, &chunkSizeRaw, &paddedSizeRaw, &passwordHint, &passwordType,
		&encryptedFilenameBytes, &filenameNonceBytes, &encryptedSha256sumBytes, &sha256sumNonceBytes, &encryptedFekBytes,
	)

	if err == sql.ErrNoRows {
		logging.ErrorLogger.Printf("CompleteUpload: session not found for sessionID: '%s'", sessionID)
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("CompleteUpload: failed to read session %s: %v", sessionID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}

	// Convert []byte to string for file_metadata table
	encryptedFilename := string(encryptedFilenameBytes)
	filenameNonce := string(filenameNonceBytes)
	encryptedSha256sum := string(encryptedSha256sumBytes)
	sha256sumNonce := string(sha256sumNonceBytes)
	encryptedFek := string(encryptedFekBytes)

	// Convert total_size with explicit type handling
	var declaredSize int64
	switch v := totalSizeRaw.(type) {
	case int64:
		declaredSize = v
	case float64:
		declaredSize = int64(v)
	default:
		logging.ErrorLogger.Printf("CompleteUpload: unexpected type %T for total_size in session %s", totalSizeRaw, sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to read total_size: unexpected type %T", totalSizeRaw))
	}

	// Convert chunk_size with explicit type handling
	var chunkSizeBytes int64
	switch v := chunkSizeRaw.(type) {
	case int64:
		chunkSizeBytes = v
	case float64:
		chunkSizeBytes = int64(v)
	default:
		logging.ErrorLogger.Printf("CompleteUpload: unexpected type %T for chunk_size in session %s", chunkSizeRaw, sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to read chunk_size: unexpected type %T", chunkSizeRaw))
	}

	// Convert padded_size with explicit type handling
	var paddedSize int64
	switch v := paddedSizeRaw.(type) {
	case int64:
		paddedSize = v
	case float64:
		paddedSize = int64(v)
	case nil:
		// padded_size should always be set; fail if missing
		logging.ErrorLogger.Printf("CompleteUpload: padded_size is NULL for session %s", sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Missing padded_size in upload session")
	default:
		logging.ErrorLogger.Printf("CompleteUpload: unexpected type %T for padded_size in session %s", paddedSizeRaw, sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to read padded_size: unexpected type %T", paddedSizeRaw))
	}

	logging.InfoLogger.Printf("CompleteUpload: session %s read OK. Status: '%s', declared size: %d, padded size: %d", sessionID, status, declaredSize, paddedSize)

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

	var parts []storage.CompletePart
	for rows.Next() {
		var chunkNumber int
		var etag string
		if err := rows.Scan(&chunkNumber, &etag); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to scan chunk data")
		}
		parts = append(parts, storage.CompletePart{PartNumber: chunkNumber + 1, ETag: etag})
	}
	if err = rows.Err(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error reading chunk data")
	}

	// Step 4: Get the streaming hashes calculated during chunk uploads
	hashStateMutex.RLock()
	hashState, hashExists := streamingHashStates[sessionID]
	blobHashState, blobHashExists := storedBlobHashStates[sessionID]
	hashStateMutex.RUnlock()

	var serverCalculatedHash string
	if hashExists {
		serverCalculatedHash = hashState.FinalizeHash()
		logging.InfoLogger.Printf("Encrypted data hash for session %s: %s", sessionID, serverCalculatedHash)
	} else {
		logging.ErrorLogger.Printf("No streaming hash state found for session %s", sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Hash calculation failed - no streaming state found")
	}

	var storedBlobHash string
	if blobHashExists {
		storedBlobHash = blobHashState.FinalizeHash()
		logging.InfoLogger.Printf("Stored blob hash for session %s: %s", sessionID, storedBlobHash)
	} else {
		logging.ErrorLogger.Printf("No stored blob hash state found for session %s", sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Blob hash calculation failed - no streaming state found")
	}

	// Clean up both hash states since upload is completing
	hashStateMutex.Lock()
	delete(streamingHashStates, sessionID)
	delete(storedBlobHashStates, sessionID)
	hashStateMutex.Unlock()

	// Step 5: Complete the multipart upload in storage.
	// Padding was already appended to the last chunk during UploadChunk,
	// so no separate padding part is needed here.
	err = storage.Registry.Primary().CompleteMultipartUpload(c.Request().Context(), storageID.String, storageUploadID.String, parts)
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

	// Compute actual stored size from the server's own chunk records.
	// This is the authoritative byte count of what was actually received and stored.
	// Scan as interface{} because rqlite returns large sums as float64 in scientific notation.
	var actualStoredSizeRaw interface{}
	err = database.DB.QueryRow(
		"SELECT COALESCE(SUM(chunk_size), 0) FROM upload_chunks WHERE session_id = ?",
		sessionID,
	).Scan(&actualStoredSizeRaw)
	if err != nil {
		logging.ErrorLogger.Printf("CompleteUpload: failed to sum chunk sizes for session %s: %v", sessionID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to calculate stored size")
	}
	var actualStoredSize int64
	switch v := actualStoredSizeRaw.(type) {
	case int64:
		actualStoredSize = v
	case float64:
		actualStoredSize = int64(v)
	default:
		logging.ErrorLogger.Printf("CompleteUpload: unexpected type %T for SUM(chunk_size) in session %s", actualStoredSizeRaw, sessionID)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to read stored size: unexpected type %T", actualStoredSizeRaw))
	}

	// Validate: total stored bytes (including padding on last chunk) must equal padded_size.
	if actualStoredSize != paddedSize {
		logging.ErrorLogger.Printf(
			"Upload size mismatch for session %s: expected padded size %d bytes, server stored %d bytes",
			sessionID, paddedSize, actualStoredSize,
		)
		storage.Registry.Primary().RemoveObject(c.Request().Context(), storageID.String, storage.RemoveObjectOptions{})
		return echo.NewHTTPError(http.StatusBadRequest, "Upload size mismatch: stored size does not match expected padded size")
	}

	// Calculate chunk_count from the encrypted data size (not padded)
	var chunkCount int64 = 1
	if declaredSize > 0 && chunkSizeBytes > 0 {
		chunkCount = (declaredSize + chunkSizeBytes - 1) / chunkSizeBytes
	}

	// Create the final file metadata record with chunk info for resumable downloads.
	// size_bytes = declaredSize (the encrypted ciphertext size, used for chunk byte-range calculations on download).
	// padded_size = paddedSize (the actual S3 object size, includes crypto-random padding appended to the last chunk).
	// encrypted_file_sha256sum = hash of encrypted data only (pre-padding).
	// stored_blob_sha256sum = hash of all bytes stored in S3 (encrypted data + padding).
	_, err = tx.Exec(`
		INSERT INTO file_metadata (file_id, storage_id, owner_username, password_hint, password_type, filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, encrypted_file_sha256sum, stored_blob_sha256sum, encrypted_fek, size_bytes, padded_size, chunk_count, chunk_size_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fileID.String, storageID.String, username, passwordHint.String, passwordType.String, filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum, serverCalculatedHash, storedBlobHash, encryptedFek, declaredSize, paddedSize, chunkCount, chunkSizeBytes,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "file_id") {
			return echo.NewHTTPError(http.StatusConflict, "File ID conflict occurred")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file metadata")
	}

	// Record the file's storage location on the primary provider.
	if err := models.InsertFileStorageLocation(tx, fileID.String, storage.Registry.PrimaryID(), storageID.String, "active"); err != nil {
		logging.ErrorLogger.Printf("Failed to insert file_storage_location for file %s on provider %s: %v", fileID.String, storage.Registry.PrimaryID(), err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to record storage location")
	}

	// Update the primary provider's cached object count and total size.
	if err := models.IncrementStorageProviderStats(tx, storage.Registry.PrimaryID(), 1, paddedSize); err != nil {
		logging.ErrorLogger.Printf("Failed to update provider stats for %s: %v", storage.Registry.PrimaryID(), err)
		// Non-fatal: stats can be recalculated later, don't block the upload
	}

	// Update user's storage usage with the encrypted data size (not padded).
	// Padding is an infrastructure cost, not counted against user quotas.
	user, err := models.GetUserByUsername(tx, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}
	if err := user.UpdateStorageUsage(tx, declaredSize); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Commit the transaction.
	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	logging.InfoLogger.Printf("Upload completed: %s, file_id: %s by %s (size: %d bytes)", sessionID, fileID.String, username, actualStoredSize)
	database.LogUserAction(username, "uploaded", fileID.String)

	// Background replication to secondary provider (if enabled and configured).
	// The upload response is returned immediately; replication happens asynchronously.
	replicateToSecondary(fileID.String, storageID.String, paddedSize)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":               "File uploaded successfully",
		"file_id":               fileID.String,
		"storage_id":            storageID.String,
		"encrypted_file_sha256": serverCalculatedHash,
		"storage": map[string]interface{}{
			"total_bytes":     user.TotalStorageBytes,
			"limit_bytes":     user.StorageLimitBytes,
			"available_bytes": user.StorageLimitBytes - user.TotalStorageBytes,
		},
	})
}

// isHexString checks if a string contains only hexadecimal characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// DeleteFile handles file deletion across all storage providers
func DeleteFile(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Verify file ownership and get file size, padded size, and storage_id
	// Note: rqlite returns numbers as float64, so we scan into float64 and convert
	var ownerUsername string
	var storageID string
	var fileSizeF float64
	var paddedSizeF sql.NullFloat64
	err = tx.QueryRow(
		"SELECT owner_username, storage_id, size_bytes, padded_size FROM file_metadata WHERE file_id = ?",
		fileID,
	).Scan(&ownerUsername, &storageID, &fileSizeF, &paddedSizeF)
	fileSize := int64(fileSizeF)

	// paddedSize is used for provider stats (actual S3 object size)
	paddedSize := fileSize
	if paddedSizeF.Valid {
		paddedSize = int64(paddedSizeF.Float64)
	}

	if err != nil {
		if err != sql.ErrNoRows {
			logging.ErrorLogger.Printf("Database error checking file ownership for deletion: %v", err)
		}
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	// Verify ownership
	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to delete this file")
	}

	// Query all active storage locations for this file
	locations, err := models.GetActiveFileStorageLocations(database.DB, fileID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to query storage locations for file %s: %v", fileID, err)
		// Fall through to primary-only delete if location query fails
		locations = nil
	}

	if len(locations) > 0 {
		// Multi-provider delete via registry
		removeLocations := make([]storage.RemoveLocation, len(locations))
		for i, loc := range locations {
			removeLocations[i] = storage.RemoveLocation{
				ProviderID: loc.ProviderID,
				StorageID:  loc.StorageID,
			}
		}
		results := storage.Registry.RemoveObjectAll(c.Request().Context(), removeLocations)
		for _, result := range results {
			if result.Success {
				models.UpdateFileStorageLocationStatus(database.DB, fileID, result.ProviderID, "deleted")
				if statsErr := models.IncrementStorageProviderStats(database.DB, result.ProviderID, -1, -paddedSize); statsErr != nil {
					logging.ErrorLogger.Printf("Failed to decrement provider stats for %s: %v", result.ProviderID, statsErr)
				}
			} else {
				logging.ErrorLogger.Printf("Failed to delete file %s from provider %s: %v", fileID, result.ProviderID, result.Error)
				models.UpdateFileStorageLocationStatus(database.DB, fileID, result.ProviderID, "delete_failed")
			}
		}
	} else {
		// No location records (pre-existing file or query failed): delete from primary
		err = storage.Registry.Primary().RemoveObject(c.Request().Context(), storageID, storage.RemoveObjectOptions{})
		if err != nil {
			logging.ErrorLogger.Printf("Failed to remove file from primary storage: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file from storage")
		}
	}

	// Delete metadata from database (cascades to file_storage_locations via FK)
	_, err = tx.Exec("DELETE FROM file_metadata WHERE file_id = ?", fileID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete file metadata: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file metadata")
	}

	// Update user's storage usage (reduce by encrypted data size, not padded)
	user, err := models.GetUserByUsername(tx, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

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
			"total_bytes":     user.TotalStorageBytes,
			"limit_bytes":     user.StorageLimitBytes,
			"available_bytes": user.StorageLimitBytes - user.TotalStorageBytes,
		},
	})
}

// replicateToSecondary kicks off a background goroutine to copy a newly uploaded
// file from the primary provider to the secondary provider. This is a no-op when
// ENABLE_UPLOAD_REPLICATION is false or no secondary provider is configured.
// The function returns immediately; replication status is tracked in
// file_storage_locations (pending -> active or failed).
func replicateToSecondary(fileID, storageID string, paddedSize int64) {
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Storage.EnableUploadReplication {
		return
	}
	if !storage.Registry.HasSecondary() {
		return
	}

	secondaryID := storage.Registry.SecondaryID()

	// Insert a "pending" location row for the secondary provider
	if err := models.InsertFileStorageLocation(database.DB, fileID, secondaryID, storageID, "pending"); err != nil {
		logging.ErrorLogger.Printf("Replication: failed to insert pending location for file %s on %s: %v", fileID, secondaryID, err)
		return
	}

	go func() {
		ctx := context.Background()

		copyHash, copyErr := storage.Registry.CopyObjectBetweenProviders(
			ctx,
			storageID,
			storage.Registry.Primary(),
			storage.Registry.Secondary(),
			paddedSize,
			nil,
		)

		if copyErr != nil {
			logging.ErrorLogger.Printf("Replication: failed to copy file %s to %s: %v", fileID, secondaryID, copyErr)
			models.UpdateFileStorageLocationStatus(database.DB, fileID, secondaryID, "failed")
			return
		}

		// Verify hash if stored_blob_sha256sum is available
		var expectedHash sql.NullString
		database.DB.QueryRow("SELECT stored_blob_sha256sum FROM file_metadata WHERE file_id = ?", fileID).Scan(&expectedHash)
		if expectedHash.Valid && expectedHash.String != "" && copyHash != expectedHash.String {
			logging.ErrorLogger.Printf("Replication: hash mismatch for file %s on %s (expected %s, got %s)", fileID, secondaryID, expectedHash.String, copyHash)
			models.UpdateFileStorageLocationStatus(database.DB, fileID, secondaryID, "failed")
			return
		}

		// Mark as active and update provider stats
		models.UpdateFileStorageLocationStatus(database.DB, fileID, secondaryID, "active")
		if err := models.IncrementStorageProviderStats(database.DB, secondaryID, 1, paddedSize); err != nil {
			logging.ErrorLogger.Printf("Replication: failed to update stats for %s: %v", secondaryID, err)
		}

		logging.InfoLogger.Printf("Replication: file %s copied to %s (hash: %s)", fileID, secondaryID, copyHash)
	}()
}
