package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/storage"
)

// ShareRequest represents a file sharing request (Argon2id-based anonymous shares)
type ShareRequest struct {
	FileID            string `json:"file_id"`
	SharePassword     string `json:"share_password"`      // Share password for Argon2id derivation (client-side only)
	Salt              string `json:"salt"`                // Base64-encoded 32-byte salt
	EncryptedFEK      string `json:"encrypted_fek"`       // Base64-encoded FEK encrypted with Argon2id-derived key
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
	if request.FileID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "File ID is required")
	}
	if request.Salt == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Salt is required")
	}
	if request.EncryptedFEK == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Encrypted FEK is required")
	}

	// Validate that the user owns the file using the new encrypted schema
	var ownerUsername string
	var passwordType string

	err := database.DB.QueryRow(
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

	// For account-encrypted files, require custom password for sharing
	if passwordType == "account" {
		return echo.NewHTTPError(http.StatusBadRequest,
			"This file is encrypted with your account password. To share it, first add a custom password for this file.")
	}

	// Basic validation - ensure required fields are not empty
	// Salt validation removed for Phase 1A - client is responsible for providing valid base64 strings

	// Generate cryptographically secure share ID
	shareID, err := generateShareID()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate share ID: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create share")
	}

	// Calculate expiration time
	var expiresAt *time.Time
	if request.ExpiresAfterHours > 0 {
		expiry := time.Now().Add(time.Duration(request.ExpiresAfterHours) * time.Hour)
		expiresAt = &expiry
	}

	// Create file share record - store salt as base64 string directly
	_, err = database.DB.Exec(`
		INSERT INTO file_share_keys (share_id, file_id, owner_username, salt, encrypted_fek, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`,
		shareID, request.FileID, username, request.Salt, request.EncryptedFEK, expiresAt,
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
	shareURL := baseURL + "/shared/" + shareID

	createdAt := time.Now()
	logging.InfoLogger.Printf("Anonymous share created: file=%s, share_id=%s, owner=%s", request.FileID, shareID, username)
	database.LogUserAction(username, "created_share", fmt.Sprintf("file:%s, share:%s", request.FileID, shareID))

	return c.JSON(http.StatusOK, ShareResponse{
		ShareID:   shareID,
		ShareURL:  shareURL,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	})
}

// GetShareInfo gets share metadata without password verification for frontend initialization
func GetShareInfo(c echo.Context) error {
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

	// Query share data from database (no password required for metadata)
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
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Get file metadata for display (encrypted metadata needs client-side decryption)
	var fileInfo ShareFileInfo
	var size sql.NullInt64
	var encryptedFilename string
	var encryptedSha256sum string

	err = database.DB.QueryRow(`
		SELECT encrypted_filename, size_bytes, encrypted_sha256sum
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(
		&encryptedFilename,
		&size,
		&encryptedSha256sum,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		// Use fallback file info - filename will be decrypted client-side
		fileInfo.Filename = "encrypted_file"
		fileInfo.Size = 0
		fileInfo.SHA256Sum = "encrypted"
	} else {
		// For share info, we can't decrypt the filename/sha256sum server-side
		// Client will need to decrypt these after successful password verification
		fileInfo.Filename = "encrypted_file"
		fileInfo.SHA256Sum = "encrypted"
		if size.Valid {
			fileInfo.Size = size.Int64
		}
	}

	// Log metadata access
	logging.InfoLogger.Printf("Share info accessed: share_id=%s, file=%s, entity_id=%s", shareID, share.FileID, entityID)

	// Return share metadata (no sensitive data like salt or encrypted FEK)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"success":           true,
		"share_id":          shareID,
		"file_info":         &fileInfo,
		"requires_password": true, // All Argon2id shares require password
	})
}

// AccessSharedFile handles anonymous share access with Argon2id password verification
func AccessSharedFile(c echo.Context) error {
	shareID := c.Param("id")

	var request ShareAccessRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if request.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required")
	}

	// Use rate limiting wrapper to ensure failed attempts are recorded
	return RateLimitShareAccess(shareID, c, func() error {
		return processShareAccess(shareID, request, c)
	})
}

// processShareAccess processes the actual share access logic
func processShareAccess(shareID string, request ShareAccessRequest, c echo.Context) error {
	// Validate share exists and isn't expired
	var share struct {
		FileID        string
		OwnerUsername string
		Salt          string // Now stored as base64 string directly
		EncryptedFEK  string
		ExpiresAt     *time.Time
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_username, salt, encrypted_fek, expires_at
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerUsername,
		&share.Salt,
		&share.EncryptedFEK,
		&share.ExpiresAt,
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

	// Get file metadata with encrypted fields (stored as base64 strings)
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

	// Return encrypted metadata for client-side decryption (already base64 strings)
	fileInfo.Filename = encryptedFilename   // Already base64 - no encoding needed
	fileInfo.SHA256Sum = encryptedSha256sum // Already base64 - no encoding needed
	if size.Valid {
		fileInfo.Size = size.Int64
	}

	// NOTE: Password verification is done CLIENT-SIDE with Argon2id
	// Server never sees the actual password, only provides salt + encrypted_fek
	// Client must derive Argon2id key and attempt FEK decryption

	// Log successful access
	entityID := logging.GetOrCreateEntityID(c)
	logging.InfoLogger.Printf("Share accessed: share_id=%s, file=%s, entity_id=%s", shareID, share.FileID, entityID)

	// Return salt and encrypted FEK for client-side Argon2id decryption
	return c.JSON(http.StatusOK, ShareAccessResponse{
		Success:      true,
		Salt:         share.Salt, // Already base64 string - no encoding needed
		EncryptedFEK: share.EncryptedFEK,
		FileInfo:     &fileInfo,
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
	logging.InfoLogger.Printf("Share page accessed: share_id=%s, file=%s, entity_id=%s", shareID, share.FileID, entityID)

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
			Size               sql.NullInt64
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
			shareData["size"] = share.Size.Int64
		}

		if share.ExpiresAt.Valid {
			shareData["expires_at"] = share.ExpiresAt.String
		} else {
			shareData["expires_at"] = nil
		}

		shares = append(shares, shareData)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"shares": shares,
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

	// Validate share exists and isn't expired
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
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
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
		minio.GetObjectOptions{},
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve file from storage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
	}
	defer object.Close()

	data, err := io.ReadAll(object)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to read file: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read file")
	}

	// Log download
	entityID := logging.GetOrCreateEntityID(c)
	logging.InfoLogger.Printf("Shared file downloaded: share_id=%s, file=%s, entity_id=%s", shareID, share.FileID, entityID)

	// Return encrypted file data and encrypted metadata for client-side decryption (encrypted metadata already base64)
	response := map[string]interface{}{
		"data":                base64.StdEncoding.EncodeToString(data), // Data needs encoding as it's binary
		"encrypted_filename":  encryptedFilename,                       // Already base64 - no encoding needed
		"filename_nonce":      filenameNonce,                           // Already base64 - no encoding needed
		"encrypted_sha256sum": encryptedSha256sum,                      // Already base64 - no encoding needed
		"sha256sum_nonce":     sha256sumNonce,                          // Already base64 - no encoding needed
	}

	if size.Valid {
		response["size"] = size.Int64
	}

	return c.JSON(http.StatusOK, response)
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
