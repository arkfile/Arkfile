package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"
	"golang.org/x/crypto/bcrypt"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
)

// BCRYPT_COST sets the work factor for bcrypt password hashing
// Higher values are more secure but slower
const BCRYPT_COST = 14

// CreateUploadSession initializes a new chunked upload
func CreateUploadSession(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	
	var request struct {
		Filename     string `json:"filename"`
		TotalSize    int64  `json:"totalSize"`
		ChunkSize    int    `json:"chunkSize"`
		OriginalHash string `json:"originalHash"`
		PasswordHint string `json:"passwordHint"`
		PasswordType string `json:"passwordType"`
	}
	
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}
	
	// Validate SHA-256 hash format
	if len(request.OriginalHash) != 64 || !isHexString(request.OriginalHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid SHA-256 hash")
	}
	
	// Validate password type
	if request.PasswordType != "account" && request.PasswordType != "custom" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid password type")
	}
	
	// Check user's storage limit
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}
	
	if !user.CheckStorageAvailable(request.TotalSize) {
		return echo.NewHTTPError(http.StatusForbidden, "Storage limit would be exceeded")
	}
	
	// Create upload session
	sessionID := uuid.New().String()
	totalChunks := (request.TotalSize + int64(request.ChunkSize) - 1) / int64(request.ChunkSize)
	
	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()
	
	// Create upload session record
	_, err = tx.Exec(
		"INSERT INTO upload_sessions (id, filename, owner_email, total_size, chunk_size, total_chunks, original_hash, password_hint, password_type, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sessionID, request.Filename, email, request.TotalSize, request.ChunkSize, totalChunks, request.OriginalHash, request.PasswordHint, request.PasswordType, "in_progress", time.Now().Add(24*time.Hour),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create upload session")
	}
	
	// Initialize multipart upload in storage with sessionID metadata
	metadata := map[string]string{
		"session-id": sessionID,
		"owner-email": email,
	}
	uploadID, err := storage.InitiateMultipartUpload(c.Request().Context(), request.Filename, metadata)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to initialize storage upload")
	}
	
	// Update upload session with storage upload ID
	_, err = tx.Exec(
		"UPDATE upload_sessions SET storage_upload_id = ? WHERE id = ?",
		uploadID, sessionID,
	)
	if err != nil {
		// Abort the multipart upload if we can't update the database
		storage.AbortMultipartUpload(c.Request().Context(), request.Filename, uploadID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update upload session")
	}
	
	if err := tx.Commit(); err != nil {
		// Attempt to abort the storage upload if we can't commit
		storage.AbortMultipartUpload(c.Request().Context(), request.Filename, uploadID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}
	
	logging.InfoLogger.Printf("Upload session created: %s by %s for file: %s (size: %d bytes)",
		sessionID, email, request.Filename, request.TotalSize)
	
	return c.JSON(http.StatusOK, map[string]interface{}{
		"sessionId": sessionID,
		"chunkSize": request.ChunkSize,
		"totalChunks": totalChunks,
		"expiresAt": time.Now().Add(24*time.Hour),
	})
}

// GetSharedFile retrieves a shared file by its share ID, checking password if required
func GetSharedFile(c echo.Context) error {
	shareID := c.Param("shareId")
	password := c.FormValue("password")
	
	// Get share details
	var (
		fileID              string
		ownerEmail          string
		isPasswordProtected bool
		passwordHash        string
		expiresAt           *time.Time
	)
	
	err := database.DB.QueryRow(
		"SELECT file_id, owner_email, is_password_protected, password_hash, expires_at FROM file_shares WHERE id = ?",
		shareID,
	).Scan(&fileID, &ownerEmail, &isPasswordProtected, &passwordHash, &expiresAt)
	
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Shared file not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get share details")
	}
	
	// Check if share has expired
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return echo.NewHTTPError(http.StatusGone, "This share link has expired")
	}
	
	// Check password if required
	if isPasswordProtected {
		if password == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Password required")
		}
		
		// Verify password using bcrypt
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid password")
		}
	}
	
	// Get file metadata to prepare for download
	var (
		filename        string
		size            int64
		passwordHint    string
		passwordType    string
		originalHash    string
	)
	
	// Try in file_metadata first
	err = database.DB.QueryRow(
		"SELECT filename, size_bytes, password_hint, password_type, sha256sum FROM file_metadata WHERE filename = ?",
		fileID,
	).Scan(&filename, &size, &passwordHint, &passwordType, &originalHash)
	
	if err == sql.ErrNoRows {
		// Check in completed uploads
		err = database.DB.QueryRow(
			"SELECT filename, total_size, password_hint, password_type, original_hash FROM upload_sessions WHERE filename = ? AND status = 'completed'",
			fileID,
		).Scan(&filename, &size, &passwordHint, &passwordType, &originalHash)
		
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "File no longer exists")
		} else if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get file details")
		}
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get file details")
	}
	
	// Generate download URL
	expiry := time.Hour // 1 hour expiry for the actual download link
	downloadURL, err := storage.GetPresignedURL(fileID, expiry)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate download URL")
	}
	
	// Log file access
	database.LogUserAction(ownerEmail, "shared", fileID)
	logging.InfoLogger.Printf("Shared file access: %s, file: %s", shareID, fileID)
	
	return c.JSON(http.StatusOK, map[string]interface{}{
		"fileId":       fileID,
		"filename":     filename,
		"size":         size,
		"downloadUrl":  downloadURL,
		"owner":        ownerEmail,
		"hash":         originalHash,
		"passwordHint": passwordHint,
		"passwordType": passwordType,
	})
}

// ShareFile creates a shareable link for a file with optional password and expiration
func ShareFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	
	var request struct {
		FileID              string `json:"fileId"`
		PasswordProtected   bool   `json:"passwordProtected"`
		Password            string `json:"password,omitempty"`
		ExpiresAfterHours   int    `json:"expiresAfterHours"`
	}
	
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}
	
	// Validate file ownership
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?", 
		request.FileID,
	).Scan(&ownerEmail)
	
	if err == sql.ErrNoRows {
		// Check in upload_sessions table
		err = database.DB.QueryRow(
			"SELECT owner_email FROM upload_sessions WHERE filename = ? AND status = 'completed'",
			request.FileID,
		).Scan(&ownerEmail)
		
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		} else if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file ownership")
		}
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file ownership")
	}
	
	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to share this file")
	}
	
	// Generate unique share ID
	shareID := uuid.New().String()
	
	// Calculate expiration time
	var expiresAt *time.Time
	if request.ExpiresAfterHours > 0 {
		expiry := time.Now().Add(time.Duration(request.ExpiresAfterHours) * time.Hour)
		expiresAt = &expiry
	}
	
	// Handle password if provided
	var passwordHash string
	if request.PasswordProtected && request.Password != "" {
		// Use bcrypt with high work factor (14) for secure password hashing
		hashedBytes, err := bcrypt.GenerateFromPassword([]byte(request.Password), BCRYPT_COST)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process share password")
		}
		passwordHash = string(hashedBytes)
	}
	
	// Create file share record
	_, err = database.DB.Exec(
		"INSERT INTO file_shares (id, file_id, owner_email, is_password_protected, password_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)",
		shareID, request.FileID, email, request.PasswordProtected, passwordHash, expiresAt,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file share")
	}
	
	logging.InfoLogger.Printf("File shared: %s by %s, share ID: %s", request.FileID, email, shareID)
	
	// Base path for the share URL
	host := c.Request().Host
	scheme := "https"
	if strings.Contains(host, "localhost") {
		scheme = "http"
	}
	
	shareURL := fmt.Sprintf("%s://%s/shared/%s", scheme, host, shareID)
	
	return c.JSON(http.StatusOK, map[string]interface{}{
		"shareId": shareID,
		"shareUrl": shareURL,
		"isPasswordProtected": request.PasswordProtected,
		"expiresAt": expiresAt,
	})
}

// DownloadFileChunk streams a specific chunk of a file to the client
func DownloadFileChunk(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	fileID := c.Param("fileId")
	chunkNumberStr := c.Param("chunkNumber")
	
	// Parse chunk number
	chunkNumber, err := strconv.Atoi(chunkNumberStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}
	
	// Get file metadata and verify ownership
	var (
		filename        string
		ownerEmail      string
		size            int64
		passwordHint    string
		passwordType    string
		originalHash    string
	)
	
	// First check if it's a regular file
	err = database.DB.QueryRow(
		"SELECT filename, owner_email, size_bytes, password_hint, password_type, sha256sum FROM file_metadata WHERE filename = ?",
		fileID,
	).Scan(&filename, &ownerEmail, &size, &passwordHint, &passwordType, &originalHash)
	
	if err == sql.ErrNoRows {
		// Not found as a regular file, check completed upload sessions
		err = database.DB.QueryRow(
			"SELECT filename, owner_email, total_size, password_hint, password_type, original_hash FROM upload_sessions WHERE filename = ? AND status = 'completed'",
			fileID,
		).Scan(&filename, &ownerEmail, &size, &passwordHint, &passwordType, &originalHash)
		
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		} else if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get file details")
		}
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get file details")
	}
	
	// Verify ownership
	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to access this file")
	}
	
	// Calculate chunk size based on 16MB standard chunk size (or less for the last chunk)
	const chunkSize int64 = 16 * 1024 * 1024 // 16MB
	totalChunks := (size + chunkSize - 1) / chunkSize
	
	// Validate chunk number
	if chunkNumber < 0 || int64(chunkNumber) >= totalChunks {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}
	
	// Calculate chunk range
	startByte := int64(chunkNumber) * chunkSize
	endByte := startByte + chunkSize - 1
	if endByte >= size {
		endByte = size - 1
	}
	
	// Retrieve chunk from storage
	reader, err := storage.GetObjectChunk(c.Request().Context(), fileID, startByte, endByte-startByte+1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file chunk from storage")
	}
	defer reader.Close()
	
	// Set appropriate headers
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.part%d", fileID, chunkNumber))
	c.Response().Header().Set("X-Chunk-Number", strconv.Itoa(chunkNumber))
	c.Response().Header().Set("X-Total-Chunks", strconv.FormatInt(totalChunks, 10))
	c.Response().Header().Set("X-File-Size", strconv.FormatInt(size, 10))
	c.Response().Header().Set("X-Original-Hash", originalHash)
	c.Response().Header().Set("X-Password-Hint", passwordHint)
	c.Response().Header().Set("X-Password-Type", passwordType)
	
	// Log access
	logging.InfoLogger.Printf("Chunk download: %s, chunk: %d/%d by %s", fileID, chunkNumber+1, totalChunks, email)
	
	// Stream the chunk to the client
	return c.Stream(http.StatusOK, "application/octet-stream", reader)
}

// CancelUpload aborts an in-progress upload session
func CancelUpload(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	sessionID := c.Param("sessionId")
	
	// Verify session exists and belongs to user
	var (
		ownerEmail      string
		filename        string
		storageUploadID string
		status          string
	)
	
	err := database.DB.QueryRow(
		"SELECT owner_email, filename, storage_upload_id, status FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerEmail, &filename, &storageUploadID, &status)
	
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}
	
	// Verify ownership
	if ownerEmail != email {
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
	
	// Abort the multipart upload in storage
	if storageUploadID != "" {
		err = storage.AbortMultipartUpload(c.Request().Context(), filename, storageUploadID)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to abort storage upload: %v", err)
			// Continue anyway - we still want to mark the session as canceled in the database
		}
	}
	
	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}
	
	logging.InfoLogger.Printf("Upload canceled: %s, file: %s by %s", sessionID, filename, email)
	
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Upload canceled successfully",
	})
}

// Helper function to check if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// GetUploadStatus returns the status of an upload session including which chunks have been uploaded
func GetUploadStatus(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	sessionID := c.Param("sessionId")
	
	// Verify session exists and belongs to user
	var (
		ownerEmail  string
		filename    string
		status      string
		totalChunks int
		totalSize   int64
		createdAt   time.Time
		expiresAt   time.Time
	)
	
	err := database.DB.QueryRow(
		"SELECT owner_email, filename, status, total_chunks, total_size, created_at, expires_at FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerEmail, &filename, &status, &totalChunks, &totalSize, &createdAt, &expiresAt)
	
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}
	
	// Verify ownership
	if ownerEmail != email {
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
		"sessionId":      sessionID,
		"filename":       filename,
		"status":         status,
		"totalChunks":    totalChunks,
		"uploadedChunks": uploadedChunks,
		"progress":       progress,
		"totalSize":      totalSize,
		"createdAt":      createdAt,
		"expiresAt":      expiresAt,
		"isExpired":      time.Now().After(expiresAt),
	})
}

// UploadChunk handles individual chunk uploads
func UploadChunk(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	sessionID := c.Param("sessionId")
	chunkNumberStr := c.Param("chunkNumber")
	
	// Parse chunk number
	chunkNumber, err := strconv.Atoi(chunkNumberStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk number")
	}
	
	// Verify session exists and belongs to user
	var (
		ownerEmail      string
		filename        string
		storageUploadID string
		status          string
		totalChunks     int
	)
	
	err = database.DB.QueryRow(
		"SELECT owner_email, filename, storage_upload_id, status, total_chunks FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(&ownerEmail, &filename, &storageUploadID, &status, &totalChunks)
	
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}
	
	// Verify ownership
	if ownerEmail != email {
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
	
	// Get chunk hash and IV from headers
	chunkHash := c.Request().Header.Get("X-Chunk-Hash")
	ivBase64 := c.Request().Header.Get("X-Chunk-IV")
	
	if chunkHash == "" || ivBase64 == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing required chunk metadata")
	}
	
	// Validate chunk hash format
	if len(chunkHash) != 64 || !isHexString(chunkHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk hash format")
	}
	
	// Minio part numbers are 1-based
	minioPartNumber := chunkNumber + 1
	
	// Stream chunk directly to storage (no buffering in memory)
	part, err := storage.UploadPart(
		c.Request().Context(),
		filename,
		storageUploadID,
		minioPartNumber,
		c.Request().Body,
		-1, // Unknown size, will read until EOF
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to upload chunk to storage")
	}
	
	// Record chunk metadata in database
	_, err = database.DB.Exec(
		"INSERT INTO upload_chunks (session_id, chunk_number, chunk_hash, chunk_size, iv, etag) VALUES (?, ?, ?, ?, ?, ?)",
		sessionID, chunkNumber, chunkHash, part.Size, ivBase64, part.ETag,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to record chunk metadata")
	}
	
	logging.InfoLogger.Printf("Chunk uploaded: %s, file: %s, chunk: %d/%d, size: %d bytes",
		sessionID, filename, chunkNumber+1, totalChunks, part.Size)
	
	return c.JSON(http.StatusOK, map[string]interface{}{
		"chunkNumber": chunkNumber,
		"size": part.Size,
		"etag": part.ETag,
	})
}

// CompleteUpload finalizes a chunked upload
func CompleteUpload(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	sessionID := c.Param("sessionId")
	
	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()
	
	// Get session details
	var (
		ownerEmail      string
		filename        string
		storageUploadID string
		status          string
		totalChunks     int
		totalSize       int64
		originalHash    string
		passwordHint    string
		passwordType    string
	)
	
	err = tx.QueryRow(
		"SELECT owner_email, filename, storage_upload_id, status, total_chunks, total_size, original_hash, password_hint, password_type FROM upload_sessions WHERE id = ?",
		sessionID,
	).Scan(
		&ownerEmail, &filename, &storageUploadID, &status, &totalChunks, 
		&totalSize, &originalHash, &passwordHint, &passwordType,
	)
	
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Upload session not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get session details")
	}
	
	// Verify ownership
	if ownerEmail != email {
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
	
	// Complete the multipart upload in storage
	err = storage.CompleteMultipartUpload(c.Request().Context(), filename, storageUploadID, parts)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to complete storage upload: %v", err))
	}
	
	// Get encrypted file hash from request if provided
	var encryptedHash string
	if c.Request().Header.Get("X-Encrypted-Hash") != "" {
		encryptedHash = c.Request().Header.Get("X-Encrypted-Hash")
		// Validate hash format
		if len(encryptedHash) != 64 || !isHexString(encryptedHash) {
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
	
	// Create file metadata record
	_, err = tx.Exec(
		"INSERT INTO file_metadata (filename, owner_email, password_hint, password_type, sha256sum, size_bytes) VALUES (?, ?, ?, ?, ?, ?)",
		filename, email, passwordHint, passwordType, originalHash, totalSize,
	)
	if err != nil {
		// Handle duplicate filenames
		if strings.Contains(err.Error(), "UNIQUE") {
			return echo.NewHTTPError(http.StatusConflict, "A file with this name already exists")
		}
		
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file metadata")
	}
	
	// Update user's storage usage
	user, err := models.GetUserByEmail(database.DB, email)
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
	
	logging.InfoLogger.Printf("Upload completed: %s, file: %s by %s (size: %d bytes)",
		sessionID, filename, email, totalSize)
	
	database.LogUserAction(email, "uploaded", filename)
	
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "File uploaded successfully",
		"storage": map[string]interface{}{
			"total_bytes":     user.TotalStorage + totalSize,
			"limit_bytes":     user.StorageLimit,
			"available_bytes": user.StorageLimit - (user.TotalStorage + totalSize),
		},
	})
}
