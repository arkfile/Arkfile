package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/storage"
)

// ShareRequest represents a file sharing request (Argon2id-based anonymous shares)
type ShareRequest struct {
	ShareID           string `json:"share_id"` // Client-generated share ID
	FileID            string `json:"file_id"`
	Salt              string `json:"salt"`                // Base64-encoded 32-byte salt
	EncryptedEnvelope string `json:"encrypted_envelope"`  // Base64-encoded Share Envelope (FEK + Download Token) encrypted with AAD
	DownloadTokenHash string `json:"download_token_hash"` // SHA-256 hash of the Download Token
	ExpiresAfterHours int    `json:"expires_after_hours"` // Optional expiration
}

// ShareResponse represents a file share creation response
type ShareResponse struct {
	ShareID   string     `json:"share_id"`
	ShareURL  string     `json:"share_url"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ShareAccessRequest represents an anonymous share access request
type ShareAccessRequest struct {
	Password string `json:"password"` // Share password for client-side Argon2id derivation
}

// ShareAccessResponse represents the response for anonymous share access
type ShareAccessResponse struct {
	Success      bool           `json:"success"`
	Salt         string         `json:"salt,omitempty"`          // Base64-encoded salt for Argon2id
	EncryptedFEK string         `json:"encrypted_fek,omitempty"` // Base64-encoded encrypted FEK
	FileInfo     *ShareFileInfo `json:"file_info,omitempty"`
	Error        string         `json:"error,omitempty"`
	Message      string         `json:"message,omitempty"`
	RetryAfter   int            `json:"retry_after,omitempty"` // For rate limiting
}

// ShareFileInfo contains metadata about the shared file
type ShareFileInfo struct {
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	SHA256Sum   string `json:"sha256sum,omitempty"`
}

// CreateFileShare creates a new Argon2id-based anonymous file share
func CreateFileShare(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	var request ShareRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body: "+err.Error())
	}

	// Validate required fields
	if request.ShareID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Share ID is required")
	}

	// Validate share_id format (43-character base64url without padding)
	if !isValidShareID(request.ShareID) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid share ID format")
	}

	// Check for share_id uniqueness (prevent collisions)
	var existingShareID string
	err := database.DB.QueryRow("SELECT share_id FROM file_share_keys WHERE share_id = ?", request.ShareID).Scan(&existingShareID)
	if err == nil {
		// Share ID already exists - return 409 Conflict
		logging.WarningLogger.Printf("Share ID collision detected: %s", request.ShareID[:8])
		return echo.NewHTTPError(http.StatusConflict, "Share ID already exists, please retry")
	} else if err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("Database error checking share_id uniqueness: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate share ID")
	}

	if request.FileID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "File ID is required")
	}
	if request.Salt == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Salt is required")
	}
	if request.EncryptedEnvelope == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Encrypted envelope is required")
	}
	if request.DownloadTokenHash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Download Token Hash is required")
	}

	// Validate that the user owns the file using the new encrypted schema
	var ownerUsername string
	var passwordType string

	err = database.DB.QueryRow(
		"SELECT owner_username, password_type FROM file_metadata WHERE file_id = ?",
		request.FileID,
	).Scan(&ownerUsername, &passwordType)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking file_metadata for file %s: %v", request.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file ownership")
	}

	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to share this file")
	}

	// Calculate expiration time
	var expiresAt *time.Time
	if request.ExpiresAfterHours > 0 {
		expiry := time.Now().Add(time.Duration(request.ExpiresAfterHours) * time.Hour)
		expiresAt = &expiry
	}

	// Create file share record - store salt as base64 string directly
	_, err = database.DB.Exec(`
		INSERT INTO file_share_keys (share_id, file_id, owner_username, salt, encrypted_fek, download_token_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`,
		request.ShareID, request.FileID, username, request.Salt, request.EncryptedEnvelope, request.DownloadTokenHash, expiresAt,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create file share record for file %s: %v", request.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file share")
	}

	// Construct share URL
	host := c.Request().Host
	scheme := "https"
	if c.Request().Header.Get("X-Forwarded-Proto") == "http" || (c.Echo().Debug && c.Request().TLS == nil) {
		isHTTP := c.Request().Header.Get("X-Forwarded-Proto") == "http"
		isHTTPS := c.Request().Header.Get("X-Forwarded-Proto") == "https"

		if c.Echo().Debug && !isHTTPS {
			scheme = "http"
		} else if isHTTP {
			scheme = "http"
		}
	}

	origin := c.Request().Header.Get("Origin")
	var baseURL string
	if origin != "" {
		expectedOriginPrefixHttp := "http://" + host
		expectedOriginPrefixHttps := "https://" + host
		if strings.HasPrefix(origin, expectedOriginPrefixHttp) || strings.HasPrefix(origin, expectedOriginPrefixHttps) {
			baseURL = origin
		} else {
			baseURL = scheme + "://" + host
		}
	} else {
		baseURL = scheme + "://" + host
	}
	shareURL := baseURL + "/shared/" + request.ShareID

	createdAt := time.Now()
	logging.InfoLogger.Printf("Anonymous share created: file=%s, share_id=%s..., owner=%s", request.FileID, request.ShareID[:8], username)
	database.LogUserAction(username, "created_share", fmt.Sprintf("file:%s, share:%s...", request.FileID, request.ShareID[:8]))

	return c.JSON(http.StatusOK, ShareResponse{
		ShareID:   request.ShareID,
		ShareURL:  shareURL,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	})
}

// GetShareEnvelope returns the encrypted FEK and metadata for a share (for client-side decryption)
func GetShareEnvelope(c echo.Context) error {
	shareID := c.Param("id")
	if shareID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Share ID is required")
	}

	// Get EntityID for rate limiting
	entityID := logging.GetOrCreateEntityID(c)

	// Check basic rate limiting for metadata requests
	allowed, delay, rateLimitErr := checkRateLimit(shareID, entityID)
	if rateLimitErr != nil {
		logging.ErrorLogger.Printf("Rate limit check failed: %v", rateLimitErr)
		// Continue on error to avoid blocking legitimate users
	} else if !allowed {
		c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", int(delay.Seconds())))
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many requests")
	}

	// Query share data from database
	var share struct {
		FileID            string
		OwnerUsername     string
		Salt              string
		EncryptedEnvelope string
		ExpiresAt         *time.Time
		RevokedAt         *time.Time
		RevokedReason     sql.NullString
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_username, salt, encrypted_fek, expires_at, revoked_at, revoked_reason
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerUsername,
		&share.Salt,
		&share.EncryptedEnvelope,
		&share.ExpiresAt,
		&share.RevokedAt,
		&share.RevokedReason,
	)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Check if share has been revoked
	if share.RevokedAt != nil {
		reason := "Share has been revoked"
		if share.RevokedReason.Valid && share.RevokedReason.String != "" {
			reason += ": " + share.RevokedReason.String
		}
		return echo.NewHTTPError(http.StatusForbidden, reason)
	}

	// Get file metadata for display (encrypted metadata needs client-side decryption)
	var fileInfo ShareFileInfo
	var size sql.NullInt64
	var encryptedFilename string
	var encryptedSha256sum string
	var filenameNonce string
	var sha256sumNonce string

	err = database.DB.QueryRow(`
		SELECT encrypted_filename, size_bytes, encrypted_sha256sum, filename_nonce, sha256sum_nonce
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(
		&encryptedFilename,
		&size,
		&encryptedSha256sum,
		&filenameNonce,
		&sha256sumNonce,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	// Populate file info
	fileInfo.Filename = encryptedFilename   // Already base64
	fileInfo.SHA256Sum = encryptedSha256sum // Already base64
	if size.Valid {
		fileInfo.Size = size.Int64
	}

	// Log metadata access
	logging.InfoLogger.Printf("Share envelope accessed: share_id=%s..., file=%s, entity_id=%s", shareID[:8], share.FileID, entityID)

	// Return share envelope data
	return c.JSON(http.StatusOK, map[string]interface{}{
		"share_id":            shareID,
		"file_id":             share.FileID,
		"salt":                share.Salt,
		"encrypted_envelope":  share.EncryptedEnvelope,
		"encrypted_filename":  encryptedFilename,
		"filename_nonce":      filenameNonce,
		"encrypted_sha256sum": encryptedSha256sum,
		"sha256sum_nonce":     sha256sumNonce,
		"size_bytes":          fileInfo.Size,
	})
}

// RevokeShare revokes a share
func RevokeShare(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	shareID := c.Param("id")

	var request struct {
		Reason string `json:"reason"`
	}
	if err := c.Bind(&request); err != nil {
		// Reason is optional, so ignore bind errors
	}

	// Check if share exists and belongs to user
	var ownerUsername string
	err := database.DB.QueryRow(
		"SELECT owner_username FROM file_share_keys WHERE share_id = ?",
		shareID,
	).Scan(&ownerUsername)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking share ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Revoke share
	_, err = database.DB.Exec(`
		UPDATE file_share_keys 
		SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = ? 
		WHERE share_id = ?
	`, request.Reason, shareID)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to revoke share: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke share")
	}

	database.LogUserAction(username, "revoked_share", shareID)
	logging.InfoLogger.Printf("Share revoked: %s by %s", shareID, username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Share revoked successfully",
	})
}

// GetSharedFile renders the share access page
func GetSharedFile(c echo.Context) error {
	shareID := c.Param("id")

	// Validate share exists and get basic info (no password required for page display)
	var share struct {
		FileID        string
		OwnerUsername string
		ExpiresAt     *time.Time
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_username, expires_at
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerUsername,
		&share.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		return c.File("client/static/errors/404.html")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Verify file exists in the new encrypted metadata schema
	var fileExists bool
	err = database.DB.QueryRow(`
		SELECT 1
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(&fileExists)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to verify file metadata for share display %s: %v", share.FileID, err)
		// Continue anyway - the shared.html page will handle missing files
	}

	// Log page access (no password required)
	entityID := logging.GetOrCreateEntityID(c)
	logging.InfoLogger.Printf("Share page accessed: share_id=%s..., file=%s, entity_id=%s", shareID[:8], share.FileID, entityID)

	// Serve the static shared.html file
	return c.File("client/static/shared.html")
}

// ListShares returns all shares created by a user
func ListShares(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)

	// Query shares with encrypted metadata (stored as base64 strings)
	rows, err := database.DB.Query(`
		SELECT sk.share_id, sk.file_id, sk.created_at, sk.expires_at,
			   fm.encrypted_filename, fm.filename_nonce, fm.encrypted_sha256sum, fm.sha256sum_nonce, fm.size_bytes
		FROM file_share_keys sk
		JOIN file_metadata fm ON sk.file_id = fm.file_id
		WHERE sk.owner_username = ?
		ORDER BY sk.created_at DESC
	`, username)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to query shares: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve shares")
	}
	defer rows.Close()

	var shares []map[string]interface{}
	for rows.Next() {
		var share struct {
			ShareID            string
			FileID             string
			CreatedAt          string
			ExpiresAt          sql.NullString
			EncryptedFilename  string
			FilenameNonce      string
			EncryptedSha256sum string
			Sha256sumNonce     string
			Size               sql.NullFloat64 // rqlite returns numbers as float64
		}

		if err := rows.Scan(
			&share.ShareID,
			&share.FileID,
			&share.CreatedAt,
			&share.ExpiresAt,
			&share.EncryptedFilename,
			&share.FilenameNonce,
			&share.EncryptedSha256sum,
			&share.Sha256sumNonce,
			&share.Size,
		); err != nil {
			logging.ErrorLogger.Printf("Error scanning share row: %v", err)
			continue
		}

		// Build share URL
		baseURL := c.Request().Header.Get("Origin")
		if baseURL == "" {
			baseURL = "https://" + c.Request().Host
		}

		shareURL := baseURL + "/shared/" + share.ShareID

		// Format response with encrypted metadata for client-side decryption (already base64 strings)
		shareData := map[string]interface{}{
			"share_id":            share.ShareID,
			"file_id":             share.FileID,
			"encrypted_filename":  share.EncryptedFilename,  // Already base64 - no encoding needed
			"filename_nonce":      share.FilenameNonce,      // Already base64 - no encoding needed
			"encrypted_sha256sum": share.EncryptedSha256sum, // Already base64 - no encoding needed
			"sha256sum_nonce":     share.Sha256sumNonce,     // Already base64 - no encoding needed
			"share_url":           shareURL,
			"created_at":          share.CreatedAt,
		}

		if share.Size.Valid {
			shareData["size"] = int64(share.Size.Float64)
		}

		if share.ExpiresAt.Valid {
			shareData["expires_at"] = share.ExpiresAt.String
		} else {
			shareData["expires_at"] = nil
		}

		shares = append(shares, shareData)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"shares": shares,
		},
	})
}

// DeleteShare deletes a share
func DeleteShare(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	shareID := c.Param("id")

	// Check if share exists and belongs to user
	var ownerUsername string
	err := database.DB.QueryRow(
		"SELECT owner_username FROM file_share_keys WHERE share_id = ?",
		shareID,
	).Scan(&ownerUsername)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking share ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	if ownerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Delete share
	_, err = database.DB.Exec("DELETE FROM file_share_keys WHERE share_id = ?", shareID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete share: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete share")
	}

	database.LogUserAction(username, "deleted_share", shareID)
	logging.InfoLogger.Printf("Share deleted: %s by %s", shareID, username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Share deleted successfully",
	})
}

// DownloadSharedFile handles downloading a shared file (after successful password verification)
func DownloadSharedFile(c echo.Context) error {
	shareID := c.Param("id")

	// Get Download Token from header
	downloadToken := c.Request().Header.Get("X-Download-Token")
	if downloadToken == "" {
		logging.WarningLogger.Printf("Download attempt without token: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Download token required")
	}

	// Validate share exists and isn't expired/revoked
	var share struct {
		FileID            string
		OwnerUsername     string
		ExpiresAt         *time.Time
		RevokedAt         *time.Time
		RevokedReason     sql.NullString
		DownloadTokenHash string
		AccessCount       int
		MaxAccesses       sql.NullInt64
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_username, expires_at, revoked_at, revoked_reason, 
		       download_token_hash, access_count, max_accesses
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerUsername,
		&share.ExpiresAt,
		&share.RevokedAt,
		&share.RevokedReason,
		&share.DownloadTokenHash,
		&share.AccessCount,
		&share.MaxAccesses,
	)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has been revoked
	if share.RevokedAt != nil {
		reason := "Share has been revoked"
		if share.RevokedReason.Valid && share.RevokedReason.String != "" {
			reason += ": " + share.RevokedReason.String
		}
		logging.WarningLogger.Printf("Download attempt on revoked share: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, reason)
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		logging.WarningLogger.Printf("Download attempt on expired share: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Validate Download Token using constant-time comparison
	computedHash, err := hashDownloadToken(downloadToken)
	if err != nil {
		logging.WarningLogger.Printf("Invalid download token format: share_id=%s, error=%v", shareID[:8], err)
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}

	if !constantTimeCompare(computedHash, share.DownloadTokenHash) {
		logging.WarningLogger.Printf("Invalid download token: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}

	// Check if max accesses limit has been reached
	if share.MaxAccesses.Valid && share.AccessCount >= int(share.MaxAccesses.Int64) {
		logging.WarningLogger.Printf("Download attempt on exhausted share: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
	}

	// Increment access count atomically using a transaction
	tx, err := database.DB.Begin()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to begin transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}
	defer tx.Rollback()

	// Lock the row and increment access_count
	var newAccessCount int
	err = tx.QueryRow(`
		UPDATE file_share_keys 
		SET access_count = access_count + 1 
		WHERE share_id = ? 
		RETURNING access_count
	`, shareID).Scan(&newAccessCount)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to increment access count: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if we've reached max_accesses and auto-revoke if so
	if share.MaxAccesses.Valid && newAccessCount >= int(share.MaxAccesses.Int64) {
		_, err = tx.Exec(`
			UPDATE file_share_keys 
			SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = ? 
			WHERE share_id = ?
		`, "max_downloads_reached", shareID)

		if err != nil {
			logging.ErrorLogger.Printf("Failed to auto-revoke share: %v", err)
			// Continue anyway - the download should still succeed
		} else {
			logging.InfoLogger.Printf("Share auto-revoked (max downloads): share_id=%s", shareID[:8])
		}
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Get file metadata using the new encrypted schema (stored as base64 strings)
	var storageID string
	var size sql.NullInt64
	var encryptedFilename string
	var filenameNonce string
	var encryptedSha256sum string
	var sha256sumNonce string

	err = database.DB.QueryRow(`
		SELECT storage_id, size_bytes, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(&storageID, &size, &encryptedFilename, &filenameNonce, &encryptedSha256sum, &sha256sumNonce)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	// Get file from object storage using storage_id
	object, err := storage.Provider.GetObject(
		c.Request().Context(),
		storageID, // Use storage_id for object storage access
		storage.GetObjectOptions{},
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve file from storage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
	}
	defer object.Close()

	// Log download
	entityID := logging.GetOrCreateEntityID(c)
	logging.InfoLogger.Printf("Shared file downloaded: share_id=%s..., file=%s, entity_id=%s", shareID[:8], share.FileID, entityID)

	// Set response headers for binary streaming
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("X-Encrypted-Filename", encryptedFilename)
	c.Response().Header().Set("X-Filename-Nonce", filenameNonce)
	c.Response().Header().Set("X-Encrypted-SHA256", encryptedSha256sum)
	c.Response().Header().Set("X-SHA256-Nonce", sha256sumNonce)

	if size.Valid {
		c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", size.Int64))
	}

	// Stream the encrypted file data directly
	c.Response().WriteHeader(http.StatusOK)
	_, err = io.Copy(c.Response().Writer, object)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to stream file: %v", err)
		return err
	}

	return nil
}

// GetShareDownloadMetadata returns metadata about a shared file's chunks for resumable downloads
// GET /api/shares/:id/metadata
func GetShareDownloadMetadata(c echo.Context) error {
	shareID := c.Param("id")
	if shareID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Share ID is required")
	}

	// Get EntityID for rate limiting
	entityID := logging.GetOrCreateEntityID(c)

	// Check basic rate limiting for metadata requests
	allowed, delay, rateLimitErr := checkRateLimit(shareID, entityID)
	if rateLimitErr != nil {
		logging.ErrorLogger.Printf("Rate limit check failed: %v", rateLimitErr)
	} else if !allowed {
		c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", int(delay.Seconds())))
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many requests")
	}

	// Query share data from database
	var share struct {
		FileID        string
		ExpiresAt     *time.Time
		RevokedAt     *time.Time
		RevokedReason sql.NullString
	}

	err := database.DB.QueryRow(`
		SELECT file_id, expires_at, revoked_at, revoked_reason
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.ExpiresAt,
		&share.RevokedAt,
		&share.RevokedReason,
	)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Check if share has been revoked
	if share.RevokedAt != nil {
		reason := "Share has been revoked"
		if share.RevokedReason.Valid && share.RevokedReason.String != "" {
			reason += ": " + share.RevokedReason.String
		}
		return echo.NewHTTPError(http.StatusForbidden, reason)
	}

	// Get file chunk info
	var sizeBytes int64
	var chunkCount int64
	var chunkSizeBytes int64

	err = database.DB.QueryRow(`
		SELECT size_bytes, chunk_count, chunk_size_bytes
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(&sizeBytes, &chunkCount, &chunkSizeBytes)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	// Handle legacy files without chunk info
	if chunkCount == 0 {
		chunkCount = 1
	}
	if chunkSizeBytes == 0 {
		chunkSizeBytes = 16 * 1024 * 1024 // 16MB default
	}

	logging.InfoLogger.Printf("Share chunk info accessed: share_id=%s..., file=%s, entity_id=%s", shareID[:8], share.FileID, entityID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":          share.FileID,
		"size_bytes":       sizeBytes,
		"chunk_count":      chunkCount,
		"chunk_size_bytes": chunkSizeBytes,
	})
}

// DownloadShareChunk handles downloading a specific chunk of a shared file
// GET /api/shares/:id/chunks/:chunkIndex
func DownloadShareChunk(c echo.Context) error {
	shareID := c.Param("id")
	chunkIndexStr := c.Param("chunkIndex")

	// Parse chunk index
	chunkIndex, err := parseChunkIndex(chunkIndexStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk index")
	}

	// Get Download Token from header
	downloadToken := c.Request().Header.Get("X-Download-Token")
	if downloadToken == "" {
		logging.WarningLogger.Printf("Chunk download attempt without token: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Download token required")
	}

	// Validate share exists and isn't expired/revoked
	var share struct {
		FileID            string
		OwnerUsername     string
		ExpiresAt         *time.Time
		RevokedAt         *time.Time
		RevokedReason     sql.NullString
		DownloadTokenHash string
		AccessCount       int
		MaxAccesses       sql.NullInt64
	}

	err = database.DB.QueryRow(`
		SELECT file_id, owner_username, expires_at, revoked_at, revoked_reason, 
		       download_token_hash, access_count, max_accesses
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerUsername,
		&share.ExpiresAt,
		&share.RevokedAt,
		&share.RevokedReason,
		&share.DownloadTokenHash,
		&share.AccessCount,
		&share.MaxAccesses,
	)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has been revoked
	if share.RevokedAt != nil {
		reason := "Share has been revoked"
		if share.RevokedReason.Valid && share.RevokedReason.String != "" {
			reason += ": " + share.RevokedReason.String
		}
		logging.WarningLogger.Printf("Chunk download attempt on revoked share: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, reason)
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		logging.WarningLogger.Printf("Chunk download attempt on expired share: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Validate Download Token using constant-time comparison
	computedHash, err := hashDownloadToken(downloadToken)
	if err != nil {
		logging.WarningLogger.Printf("Invalid download token format: share_id=%s, error=%v", shareID[:8], err)
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}

	if !constantTimeCompare(computedHash, share.DownloadTokenHash) {
		logging.WarningLogger.Printf("Invalid download token: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}

	// Check if max accesses limit has been reached (only block NEW downloads on chunk 0)
	// For chunks 1+, allow the download to continue even if limit was just reached
	// This ensures in-progress downloads can complete all chunks
	if chunkIndex == 0 && share.MaxAccesses.Valid && share.AccessCount >= int(share.MaxAccesses.Int64) {
		logging.WarningLogger.Printf("Chunk download attempt on exhausted share: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
	}

	// Get file metadata
	var storageID string
	var sizeBytes int64
	var chunkCount int64
	var chunkSizeBytes int64

	err = database.DB.QueryRow(`
		SELECT storage_id, size_bytes, chunk_count, chunk_size_bytes
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(&storageID, &sizeBytes, &chunkCount, &chunkSizeBytes)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	// Handle legacy files without chunk info
	if chunkCount == 0 {
		chunkCount = 1
	}
	if chunkSizeBytes == 0 {
		chunkSizeBytes = 16 * 1024 * 1024 // 16MB default
	}

	// Validate chunk index
	if chunkIndex < 0 || chunkIndex >= chunkCount {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid chunk index: must be between 0 and %d", chunkCount-1))
	}

	// Calculate byte range for this chunk
	startByte := chunkIndex * chunkSizeBytes
	endByte := startByte + chunkSizeBytes - 1

	// Adjust for last chunk
	if endByte >= sizeBytes {
		endByte = sizeBytes - 1
	}

	// Calculate actual chunk size
	actualChunkSize := endByte - startByte + 1
	if actualChunkSize <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk range")
	}

	// Increment access count only on first chunk download
	// NOTE: We do NOT auto-revoke here because that would block subsequent chunks
	// for the user who just started downloading. The access_count check above
	// (only applied to chunk 0) is sufficient to prevent new downloads.
	if chunkIndex == 0 {
		_, err = database.DB.Exec(`
			UPDATE file_share_keys 
			SET access_count = access_count + 1 
			WHERE share_id = ?
		`, shareID)

		if err != nil {
			logging.ErrorLogger.Printf("Failed to increment access count: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
		}

		// Log if this was the last allowed download
		if share.MaxAccesses.Valid && share.AccessCount+1 >= int(share.MaxAccesses.Int64) {
			logging.InfoLogger.Printf("Share exhausted (max downloads reached): share_id=%s", shareID[:8])
		}
	}

	// Get the chunk from storage
	reader, err := storage.Provider.GetObjectChunk(c.Request().Context(), storageID, startByte, actualChunkSize)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get chunk %d of file %s from storage: %v", chunkIndex, share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve chunk from storage")
	}
	defer reader.Close()

	// Set headers for chunk download
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", actualChunkSize))
	c.Response().Header().Set("X-Chunk-Index", fmt.Sprintf("%d", chunkIndex))
	c.Response().Header().Set("X-Total-Chunks", fmt.Sprintf("%d", chunkCount))
	c.Response().Header().Set("X-Chunk-Size", fmt.Sprintf("%d", chunkSizeBytes))
	c.Response().Header().Set("X-File-Size", fmt.Sprintf("%d", sizeBytes))
	c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startByte, endByte, sizeBytes))

	// Log chunk download (only first and last to reduce noise)
	if chunkIndex == 0 || chunkIndex == chunkCount-1 {
		entityID := logging.GetOrCreateEntityID(c)
		logging.InfoLogger.Printf("Share chunk download: share_id=%s..., chunk=%d/%d, entity_id=%s", shareID[:8], chunkIndex, chunkCount, entityID)
	}

	// Stream the chunk
	return c.Stream(http.StatusOK, "application/octet-stream", reader)
}

// generateShareID creates a cryptographically secure 256-bit share ID using Base64 URL-safe encoding
func generateShareID() (string, error) {
	// Generate 256-bit (32 bytes) of cryptographically secure randomness
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Use Base64 URL-safe encoding without padding for clean URLs (43 characters)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes), nil
}

// hashDownloadToken computes SHA-256 hash of a Download Token
func hashDownloadToken(downloadTokenBase64 string) (string, error) {
	// Decode the base64 token
	token, err := base64.StdEncoding.DecodeString(downloadTokenBase64)
	if err != nil {
		return "", fmt.Errorf("invalid download token encoding: %w", err)
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(token)

	// Return as base64
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// constantTimeCompare performs constant-time comparison of two base64-encoded hashes
func constantTimeCompare(hash1Base64, hash2Base64 string) bool {
	// Decode both hashes
	hash1, err1 := base64.StdEncoding.DecodeString(hash1Base64)
	hash2, err2 := base64.StdEncoding.DecodeString(hash2Base64)

	// If either decode fails, return false
	if err1 != nil || err2 != nil {
		return false
	}

	// Use crypto/subtle for constant-time comparison
	return subtle.ConstantTimeCompare(hash1, hash2) == 1
}

// isValidShareID validates that a share_id is in the correct format
// Expected format: 43-character base64url string (32 bytes without padding)
func isValidShareID(shareID string) bool {
	// Check length (32 bytes base64url encoded without padding = 43 characters)
	if len(shareID) != 43 {
		return false
	}

	// Check that it only contains valid base64url characters (A-Z, a-z, 0-9, -, _)
	for _, c := range shareID {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}

	return true
}
