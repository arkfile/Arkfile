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

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/storage"
)

// ShareDetails contains common data for file shares
type ShareDetails struct {
	FileID            string
	OwnerEmail        string
	PasswordProtected bool
	ExpiresAt         *time.Time
}

// FileMetadata contains common metadata about shared files
type FileMetadata struct {
	Filename     string
	PasswordHint string
	SHA256Sum    string
	MultiKey     bool
	Size         int64
	PasswordType string
}

// validateShareAccess checks if a share exists, isn't expired, and returns share details
func validateShareAccess(shareID string) (*ShareDetails, int, string, error) {
	var share ShareDetails

	err := database.DB.QueryRow(`
		SELECT file_id, owner_email, is_password_protected, expires_at
		FROM file_shares 
		WHERE id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerEmail,
		&share.PasswordProtected,
		&share.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		return nil, http.StatusNotFound, "Share not found", err
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking share: %v", err)
		return nil, http.StatusInternalServerError, "Failed to process request", err
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return nil, http.StatusForbidden, "Share link has expired", fmt.Errorf("share expired")
	}

	// Update last accessed time
	_, err = database.DB.Exec(
		"UPDATE file_shares SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?",
		shareID,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update last accessed time: %v", err)
		// Continue anyway, as this is not critical
	}

	return &share, http.StatusOK, "", nil
}

// getFileMetadata retrieves metadata for a file
func getFileMetadata(fileID string) (*FileMetadata, int, string, error) {
	var metadata FileMetadata
	var size sql.NullInt64

	err := database.DB.QueryRow(`
		SELECT filename, password_hint, sha256sum, multi_key, size_bytes, password_type
		FROM file_metadata
		WHERE filename = ?
	`, fileID).Scan(
		&metadata.Filename,
		&metadata.PasswordHint,
		&metadata.SHA256Sum,
		&metadata.MultiKey,
		&size,
		&metadata.PasswordType,
	)

	if err == sql.ErrNoRows {
		return nil, http.StatusNotFound, "File metadata not found", err
	} else if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata: %v", err)
		return nil, http.StatusInternalServerError, "Failed to retrieve file metadata", err
	}

	if size.Valid {
		metadata.Size = size.Int64
	}

	return &metadata, http.StatusOK, "", nil
}

// getErrorTitle returns an appropriate error title based on HTTP status code
func getErrorTitle(status int) string {
	switch status {
	case http.StatusNotFound:
		return "Share Not Found"
	case http.StatusForbidden:
		return "Share Link Expired"
	default:
		return "Server Error"
	}
}

// ShareRequest represents a file sharing request.
type ShareRequest struct {
	FileID            string `json:"fileId"`
	PasswordProtected bool   `json:"passwordProtected"`
	SharePassword     string `json:"sharePassword,omitempty"` // Plain text password for OPAQUE registration
	ExpiresAfterHours int    `json:"expiresAfterHours"`
}

// ShareResponse represents a file share creation response payload.
type ShareResponse struct {
	ShareID             string     `json:"shareId"`
	ShareURL            string     `json:"shareUrl"`
	IsPasswordProtected bool       `json:"isPasswordProtected"`
	ExpiresAt           *time.Time `json:"expiresAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
}

// ShareFile creates a sharing link for a file using OPAQUE authentication
func ShareFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	var request ShareRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body: "+err.Error())
	}

	if request.FileID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "File ID is required.")
	}

	// Validate file ownership and get metadata
	var ownerEmail string
	var multiKey bool       // From file_metadata or upload_sessions
	var passwordType string // Password type from file_metadata or upload_sessions
	var foundInMetadata, foundInUploadSessions bool

	// Try file_metadata first
	err := database.DB.QueryRow(
		"SELECT owner_email, multi_key, password_type FROM file_metadata WHERE filename = ?",
		request.FileID,
	).Scan(&ownerEmail, &multiKey, &passwordType)

	if err == nil {
		foundInMetadata = true
	} else if err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("Database error checking file_metadata for file %s: %v", request.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file ownership.")
	}

	// If not found in file_metadata, try upload_sessions (for completed uploads)
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
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file ownership.")
		}
	}

	if !foundInMetadata && !foundInUploadSessions {
		return echo.NewHTTPError(http.StatusNotFound, "File not found or not yet fully processed.")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to share this file.")
	}

	// If the file is account-encrypted but not multi-key enabled, require re-encryption first
	if !multiKey && passwordType == "account" {
		return echo.NewHTTPError(http.StatusBadRequest,
			"This file is encrypted with your account password. To share it, first add a custom password or enable multi-key access for this file.")
	}

	// Generate unique share ID
	shareID := generateShareID()

	// Calculate expiration time
	var expiresAt *time.Time
	if request.ExpiresAfterHours > 0 {
		expiry := time.Now().Add(time.Duration(request.ExpiresAfterHours) * time.Hour)
		expiresAt = &expiry
	}

	var opaqueRecordID *int64

	// Handle password-protected shares with OPAQUE
	if request.PasswordProtected && request.SharePassword != "" {
		// Initialize OPAQUE password manager
		opm := auth.NewOPAQUEPasswordManager()

		// Register share password with OPAQUE
		err = opm.RegisterSharePassword(shareID, request.FileID, email, request.SharePassword)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to register share password: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create password-protected share")
		}

		// Get the record ID for the foreign key
		var recordID int64
		err = database.DB.QueryRow(`
			SELECT id FROM opaque_password_records 
			WHERE record_identifier = ? AND is_active = TRUE`,
			fmt.Sprintf("share:%s", shareID)).Scan(&recordID)

		if err != nil {
			logging.ErrorLogger.Printf("Failed to get OPAQUE record ID: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to link share password")
		}

		opaqueRecordID = &recordID
	} else if request.PasswordProtected {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required when password protection is enabled.")
	}

	// Create file share record
	_, err = database.DB.Exec(`
		INSERT INTO file_shares (id, file_id, owner_email, is_password_protected, opaque_record_id, created_at, expires_at) 
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`,
		shareID, request.FileID, email, request.PasswordProtected, opaqueRecordID, expiresAt,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create file share record for file %s: %v", request.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file share.")
	}

	// Construct the share URL
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
	logging.InfoLogger.Printf("File shared: %s by %s, share ID: %s", request.FileID, email, shareID)
	database.LogUserAction(email, "created_share", fmt.Sprintf("file:%s, share:%s", request.FileID, shareID))

	return c.JSON(http.StatusOK, ShareResponse{
		ShareID:             shareID,
		ShareURL:            shareURL,
		IsPasswordProtected: request.PasswordProtected,
		ExpiresAt:           expiresAt,
		CreatedAt:           createdAt,
	})
}

// ListShares returns all shares created by a user
func ListShares(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	// Query shares
	rows, err := database.DB.Query(`
		SELECT s.id, s.file_id, s.is_password_protected, s.created_at, s.expires_at, s.last_accessed,
			   f.password_hint, f.multi_key
		FROM file_shares s
		JOIN file_metadata f ON s.file_id = f.filename
		WHERE s.owner_email = ?
		ORDER BY s.created_at DESC
	`, email)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to query shares: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve shares")
	}
	defer rows.Close()

	var shares []map[string]interface{}
	for rows.Next() {
		var share struct {
			ID                  string
			FileID              string
			IsPasswordProtected bool
			CreatedAt           string
			ExpiresAt           sql.NullString
			LastAccessed        sql.NullString
			PasswordHint        string
			MultiKey            bool
		}

		if err := rows.Scan(
			&share.ID,
			&share.FileID,
			&share.IsPasswordProtected,
			&share.CreatedAt,
			&share.ExpiresAt,
			&share.LastAccessed,
			&share.PasswordHint,
			&share.MultiKey,
		); err != nil {
			logging.ErrorLogger.Printf("Error scanning share row: %v", err)
			continue
		}

		// Build share URL
		baseURL := c.Request().Header.Get("Origin")
		if baseURL == "" {
			baseURL = "https://" + c.Request().Host
		}

		shareURL := baseURL + "/shared/" + share.ID

		// Format response
		shareData := map[string]interface{}{
			"id":                  share.ID,
			"fileId":              share.FileID,
			"shareUrl":            shareURL,
			"isPasswordProtected": share.IsPasswordProtected,
			"createdAt":           share.CreatedAt,
			"passwordHint":        share.PasswordHint,
			"multiKey":            share.MultiKey,
		}

		if share.ExpiresAt.Valid {
			shareData["expiresAt"] = share.ExpiresAt.String
		} else {
			shareData["expiresAt"] = nil
		}

		if share.LastAccessed.Valid {
			shareData["lastAccessed"] = share.LastAccessed.String
		} else {
			shareData["lastAccessed"] = nil
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
		"SELECT owner_email FROM file_shares WHERE id = ?",
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
	_, err = database.DB.Exec("DELETE FROM file_shares WHERE id = ?", shareID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete share: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete share")
	}

	database.LogUserAction(email, "deleted share", shareID)
	logging.InfoLogger.Printf("Share deleted: %s by %s", shareID, email)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Share deleted successfully",
	})
}

// GetSharedFile handles shared file access
func GetSharedFile(c echo.Context) error {
	shareID := c.Param("id")

	// Validate share access using the helper function
	shareDetails, status, message, err := validateShareAccess(shareID)
	if err != nil {
		return c.Render(status, "error", map[string]interface{}{
			"title":   getErrorTitle(status),
			"message": message,
		})
	}

	// Get file metadata using the helper function
	fileMetadata, status, message, err := getFileMetadata(shareDetails.FileID)
	if err != nil {
		return c.Render(status, "error", map[string]interface{}{
			"title":   getErrorTitle(status),
			"message": message,
		})
	}

	// Log access
	logging.InfoLogger.Printf("Shared file access: %s, file: %s", shareID, shareDetails.FileID)

	// Render share page with file info
	return c.Render(http.StatusOK, "share", map[string]interface{}{
		"title":             "Download Shared File",
		"shareId":           shareID,
		"fileName":          fileMetadata.Filename,
		"passwordProtected": shareDetails.PasswordProtected,
		"passwordHint":      fileMetadata.PasswordHint,
		"sha256Sum":         fileMetadata.SHA256Sum,
		"isMultiKey":        fileMetadata.MultiKey,
	})
}

// AuthenticateShare handles share password verification using OPAQUE
func AuthenticateShare(c echo.Context) error {
	shareID := c.Param("id")

	var request struct {
		Password string `json:"password"` // Plain text password for OPAQUE authentication
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate share access
	shareDetails, status, message, err := validateShareAccess(shareID)
	if err != nil {
		return echo.NewHTTPError(status, message)
	}

	// Check if share is password protected
	if !shareDetails.PasswordProtected {
		return echo.NewHTTPError(http.StatusBadRequest, "Share is not password protected")
	}

	if request.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required")
	}

	// Initialize OPAQUE password manager
	opm := auth.NewOPAQUEPasswordManager()

	// Authenticate with OPAQUE
	recordIdentifier := fmt.Sprintf("share:%s", shareID)
	exportKey, err := opm.AuthenticatePassword(recordIdentifier, request.Password)
	if err != nil {
		logging.ErrorLogger.Printf("Share authentication failed for %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid password")
	}
	defer crypto.SecureZeroBytes(exportKey) // Secure cleanup

	// Derive file access key from export key for client use
	fileAccessKey, err := crypto.DeriveShareAccessKey(exportKey, shareID, shareDetails.FileID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to derive file access key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
	}

	// Log successful authentication
	logging.InfoLogger.Printf("Share authentication successful: %s", shareID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":       "Authentication successful",
		"fileAccessKey": fmt.Sprintf("%x", fileAccessKey), // Hex-encoded for client
	})
}

// DownloadSharedFile handles downloading a shared file
func DownloadSharedFile(c echo.Context) error {
	shareID := c.Param("id")

	// Validate share access using the helper function
	shareDetails, status, message, err := validateShareAccess(shareID)
	if err != nil {
		return echo.NewHTTPError(status, message)
	}

	// Get file metadata using the helper function
	fileMetadata, status, message, err := getFileMetadata(shareDetails.FileID)
	if err != nil {
		return echo.NewHTTPError(status, message)
	}

	// Get file from object storage using storage.Provider
	object, err := storage.Provider.GetObject(
		c.Request().Context(),
		shareDetails.FileID, // bucketName is handled by the provider
		minio.GetObjectOptions{},
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve file from storage via provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
	}
	defer object.Close()

	data, err := io.ReadAll(object)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to read file: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read file")
	}

	// QA / TODO: Should we update last accessed time at this point?

	// Log access
	logging.InfoLogger.Printf("Downloaded shared file: %s, file: %s", shareID, shareDetails.FileID)

	// Return file data along with metadata for client-side decryption
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":         string(data),
		"filename":     fileMetadata.Filename,
		"sha256sum":    fileMetadata.SHA256Sum,
		"passwordHint": fileMetadata.PasswordHint,
		"isMultiKey":   fileMetadata.MultiKey,
	})
}

// generateShareID creates a cryptographically secure 256-bit share ID using Base64 URL-safe encoding
func generateShareID() string {
	// Generate 256-bit (32 bytes) of cryptographically secure randomness
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to UUID if crypto/rand fails (should never happen in production)
		logging.ErrorLogger.Printf("Failed to generate secure random bytes for share ID, falling back to UUID: %v", err)
		return uuid.New().String()
	}

	// Use Base64 URL-safe encoding without padding for clean URLs (43 characters)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes)
}
