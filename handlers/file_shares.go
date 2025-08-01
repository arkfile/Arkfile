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

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/storage"
)

// ShareRequest represents a file sharing request (Argon2id-based anonymous shares)
type ShareRequest struct {
	FileID            string `json:"fileId"`
	SharePassword     string `json:"sharePassword"`     // Share password for Argon2id derivation (client-side only)
	Salt              string `json:"salt"`              // Base64-encoded 32-byte salt
	EncryptedFEK      string `json:"encrypted_fek"`     // Base64-encoded FEK encrypted with Argon2id-derived key
	ExpiresAfterHours int    `json:"expiresAfterHours"` // Optional expiration
}

// ShareResponse represents a file share creation response
type ShareResponse struct {
	ShareID   string     `json:"shareId"`
	ShareURL  string     `json:"shareUrl"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
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
	RetryAfter   int            `json:"retryAfter,omitempty"` // For rate limiting
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
	email := auth.GetEmailFromToken(c)

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

	// Validate that the user owns the file
	var ownerEmail string
	var multiKey bool
	var passwordType string
	var foundInMetadata, foundInUploadSessions bool

	// Check file_metadata first
	err := database.DB.QueryRow(
		"SELECT owner_email, multi_key, password_type FROM file_metadata WHERE filename = ?",
		request.FileID,
	).Scan(&ownerEmail, &multiKey, &passwordType)

	if err == nil {
		foundInMetadata = true
	} else if err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("Database error checking file_metadata for file %s: %v", request.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file ownership")
	}

	// If not found in file_metadata, check upload_sessions
	if !foundInMetadata {
		var usOwnerEmail string
		var usPasswordType string
		var usMultiKey sql.NullBool

		err = database.DB.QueryRow(
			"SELECT owner_email, password_type, multi_key FROM upload_sessions WHERE filename = ? AND status = 'completed'",
			request.FileID,
		).Scan(&usOwnerEmail, &usPasswordType, &usMultiKey)

		if err == nil {
			foundInUploadSessions = true
			ownerEmail = usOwnerEmail
			passwordType = usPasswordType
			multiKey = usMultiKey.Valid && usMultiKey.Bool
		} else if err != sql.ErrNoRows {
			logging.ErrorLogger.Printf("Database error checking upload_sessions for file %s: %v", request.FileID, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file ownership")
		}
	}

	if !foundInMetadata && !foundInUploadSessions {
		return echo.NewHTTPError(http.StatusNotFound, "File not found or not yet fully processed")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to share this file")
	}

	// For account-encrypted files that aren't multi-key, require re-encryption first
	if !multiKey && passwordType == "account" {
		return echo.NewHTTPError(http.StatusBadRequest,
			"This file is encrypted with your account password. To share it, first add a custom password or enable multi-key access for this file.")
	}

	// Validate salt and encrypted FEK format
	saltBytes, err := base64.StdEncoding.DecodeString(request.Salt)
	if err != nil || len(saltBytes) != 32 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid salt format (must be 32 bytes, base64-encoded)")
	}

	_, err = base64.StdEncoding.DecodeString(request.EncryptedFEK)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid encrypted FEK format (must be base64-encoded)")
	}

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

	// Create file share record
	_, err = database.DB.Exec(`
		INSERT INTO file_share_keys (share_id, file_id, owner_email, salt, encrypted_fek, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`,
		shareID, request.FileID, email, saltBytes, request.EncryptedFEK, expiresAt,
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
	logging.InfoLogger.Printf("Anonymous share created: file=%s, share_id=%s, owner=%s", request.FileID, shareID, email)
	database.LogUserAction(email, "created_share", fmt.Sprintf("file:%s, share:%s", request.FileID, shareID))

	return c.JSON(http.StatusOK, ShareResponse{
		ShareID:   shareID,
		ShareURL:  shareURL,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
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

	// Apply rate limiting wrapper
	return RateLimitShareAccess(shareID, c, func() error {
		return processShareAccess(shareID, request, c)
	})
}

// processShareAccess processes the actual share access logic
func processShareAccess(shareID string, request ShareAccessRequest, c echo.Context) error {
	// Validate share exists and isn't expired
	var share struct {
		FileID       string
		OwnerEmail   string
		Salt         []byte
		EncryptedFEK string
		ExpiresAt    *time.Time
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_email, salt, encrypted_fek, expires_at
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerEmail,
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

	// Get file metadata
	var fileInfo ShareFileInfo
	var size sql.NullInt64

	err = database.DB.QueryRow(`
		SELECT filename, size_bytes, sha256sum
		FROM file_metadata
		WHERE filename = ?
	`, share.FileID).Scan(
		&fileInfo.Filename,
		&size,
		&fileInfo.SHA256Sum,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

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
		Salt:         base64.StdEncoding.EncodeToString(share.Salt),
		EncryptedFEK: share.EncryptedFEK,
		FileInfo:     &fileInfo,
	})
}

// GetSharedFile renders the share access page
func GetSharedFile(c echo.Context) error {
	shareID := c.Param("id")

	// Validate share exists and get basic info (no password required for page display)
	var share struct {
		FileID     string
		OwnerEmail string
		ExpiresAt  *time.Time
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_email, expires_at
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerEmail,
		&share.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		return c.Render(http.StatusNotFound, "error", map[string]interface{}{
			"title":   "Share Not Found",
			"message": "The requested share link does not exist or has been removed.",
		})
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking share %s: %v", shareID, err)
		return c.Render(http.StatusInternalServerError, "error", map[string]interface{}{
			"title":   "Server Error",
			"message": "Failed to process request. Please try again later.",
		})
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return c.Render(http.StatusForbidden, "error", map[string]interface{}{
			"title":   "Share Link Expired",
			"message": "This share link has expired and is no longer accessible.",
		})
	}

	// Get file metadata for display
	var filename string
	err = database.DB.QueryRow(`
		SELECT filename
		FROM file_metadata
		WHERE filename = ?
	`, share.FileID).Scan(&filename)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for share display %s: %v", share.FileID, err)
		filename = share.FileID // Fallback to file ID
	}

	// Log page access (no password required)
	entityID := logging.GetOrCreateEntityID(c)
	logging.InfoLogger.Printf("Share page accessed: share_id=%s, file=%s, entity_id=%s", shareID, share.FileID, entityID)

	// Render share page with file info
	return c.Render(http.StatusOK, "share", map[string]interface{}{
		"title":    "Download Shared File",
		"shareId":  shareID,
		"fileName": filename,
	})
}

// ListShares returns all shares created by a user
func ListShares(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	// Query shares
	rows, err := database.DB.Query(`
		SELECT sk.share_id, sk.file_id, sk.created_at, sk.expires_at,
			   fm.filename, fm.size_bytes
		FROM file_share_keys sk
		JOIN file_metadata fm ON sk.file_id = fm.filename
		WHERE sk.owner_email = ?
		ORDER BY sk.created_at DESC
	`, email)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to query shares: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve shares")
	}
	defer rows.Close()

	var shares []map[string]interface{}
	for rows.Next() {
		var share struct {
			ShareID   string
			FileID    string
			CreatedAt string
			ExpiresAt sql.NullString
			Filename  string
			Size      sql.NullInt64
		}

		if err := rows.Scan(
			&share.ShareID,
			&share.FileID,
			&share.CreatedAt,
			&share.ExpiresAt,
			&share.Filename,
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

		// Format response
		shareData := map[string]interface{}{
			"shareId":   share.ShareID,
			"fileId":    share.FileID,
			"filename":  share.Filename,
			"shareUrl":  shareURL,
			"createdAt": share.CreatedAt,
		}

		if share.Size.Valid {
			shareData["size"] = share.Size.Int64
		}

		if share.ExpiresAt.Valid {
			shareData["expiresAt"] = share.ExpiresAt.String
		} else {
			shareData["expiresAt"] = nil
		}

		shares = append(shares, shareData)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"shares": shares,
	})
}

// DeleteShare deletes a share
func DeleteShare(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	shareID := c.Param("id")

	// Check if share exists and belongs to user
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_share_keys WHERE share_id = ?",
		shareID,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking share ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Delete share
	_, err = database.DB.Exec("DELETE FROM file_share_keys WHERE share_id = ?", shareID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete share: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete share")
	}

	database.LogUserAction(email, "deleted_share", shareID)
	logging.InfoLogger.Printf("Share deleted: %s by %s", shareID, email)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Share deleted successfully",
	})
}

// DownloadSharedFile handles downloading a shared file (after successful password verification)
func DownloadSharedFile(c echo.Context) error {
	shareID := c.Param("id")

	// Validate share exists and isn't expired
	var share struct {
		FileID     string
		OwnerEmail string
		ExpiresAt  *time.Time
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_email, expires_at
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerEmail,
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

	// Get file metadata
	var filename string
	var size sql.NullInt64

	err = database.DB.QueryRow(`
		SELECT filename, size_bytes
		FROM file_metadata
		WHERE filename = ?
	`, share.FileID).Scan(&filename, &size)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	// Get file from object storage
	object, err := storage.Provider.GetObject(
		c.Request().Context(),
		share.FileID, // bucketName is handled by the provider
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

	// Return encrypted file data for client-side decryption
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":     base64.StdEncoding.EncodeToString(data),
		"filename": filename,
		"size":     size.Int64,
	})
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
