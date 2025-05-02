package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"
	"golang.org/x/crypto/bcrypt"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/config"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/storage"
)

// ShareDetails contains common data for file shares
type ShareDetails struct {
	FileID            string
	OwnerEmail        string
	PasswordProtected bool
	PasswordHash      string
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
		SELECT file_id, owner_email, is_password_protected, password_hash, expires_at
		FROM file_shares 
		WHERE id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.OwnerEmail,
		&share.PasswordProtected,
		&share.PasswordHash,
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

// verifySharePassword compares the provided password with the stored hash
func verifySharePassword(shareDetails *ShareDetails, password string) (bool, error) {
	if !shareDetails.PasswordProtected || shareDetails.PasswordHash == "" {
		return true, nil // No password required
	}

	if password == "" {
		return false, nil // Password required but not provided
	}

	// Verify password using bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(shareDetails.PasswordHash), []byte(password))
	if err != nil {
		// Add a small delay to mitigate timing attacks
		// QA / TODO: review this mitigation approach: are there any better ways to do this?
		time.Sleep(100 * time.Millisecond)
		return false, err
	}

	return true, nil
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

// ShareRequest represents a file sharing request
type ShareRequest struct {
	FileID            string `json:"fileId"`
	PasswordProtected bool   `json:"passwordProtected"`
	PasswordHash      string `json:"passwordHash"`
	ExpiresAfterHours int    `json:"expiresAfterHours"`
}

// ShareResponse represents a file share response
type ShareResponse struct {
	ID        string `json:"id"`
	ShareURL  string `json:"shareUrl"`
	Expiry    string `json:"expiry,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// ShareFile creates a sharing link for a file
func ShareFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	var request ShareRequest
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate expiry (if set)
	var expiresAt *time.Time
	if request.ExpiresAfterHours > 0 {
		expiry := time.Now().Add(time.Duration(request.ExpiresAfterHours) * time.Hour)
		expiresAt = &expiry
	}

	// Check if the file exists and user owns it
	var ownerEmail string
	var multiKey bool
	err := database.DB.QueryRow(
		"SELECT owner_email, multi_key FROM file_metadata WHERE filename = ?",
		request.FileID,
	).Scan(&ownerEmail, &multiKey)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error during share creation: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// If the file is account-encrypted but not multi-key enabled, require re-encryption first
	if !multiKey {
		var passwordType string
		err = database.DB.QueryRow(
			"SELECT password_type FROM file_metadata WHERE filename = ?",
			request.FileID,
		).Scan(&passwordType)

		if err != nil {
			logging.ErrorLogger.Printf("Database error checking password type: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check file encryption type")
		}

		if passwordType == "account" {
			return echo.NewHTTPError(http.StatusBadRequest,
				"This file is encrypted with your account password. To share it, first add a custom password using the file's sharing options.")
		}
	}

	// Generate a random share ID
	shareID := generateShareID()

	// Hash the password if share is password protected
	var passwordHash string
	if request.PasswordProtected && request.PasswordHash != "" {
		// Generate bcrypt hash with cost from configuration
		hash, err := bcrypt.GenerateFromPassword([]byte(request.PasswordHash), config.GetConfig().Security.BcryptCost) // Use config value
		if err != nil {
			logging.ErrorLogger.Printf("Failed to hash password: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process password")
		}
		passwordHash = string(hash)
	}

	// Create share record
	insertStmt := `
		INSERT INTO file_shares 
		(id, file_id, owner_email, is_password_protected, password_hash, created_at, expires_at) 
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
	`

	_, err = database.DB.Exec(
		insertStmt,
		shareID,
		request.FileID,
		email,
		request.PasswordProtected,
		passwordHash,
		expiresAt,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to create share record: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create share")
	}

	// Build share URL
	baseURL := c.Request().Header.Get("Origin")
	if baseURL == "" {
		baseURL = "https://" + c.Request().Host
	}

	shareURL := baseURL + "/shared/" + shareID

	var response ShareResponse
	response.ID = shareID
	response.ShareURL = shareURL
	response.CreatedAt = time.Now().Format(time.RFC3339)

	if expiresAt != nil {
		response.Expiry = expiresAt.Format(time.RFC3339)
	}

	database.LogUserAction(email, "shared", request.FileID)
	logging.InfoLogger.Printf("File shared: %s by %s", request.FileID, email)

	return c.JSON(http.StatusOK, response)
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

// AuthenticateShare handles share password verification
func AuthenticateShare(c echo.Context) error {
	shareID := c.Param("id")

	var request struct {
		Password string `json:"password"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate share access using the helper function
	shareDetails, status, message, err := validateShareAccess(shareID)
	if err != nil {
		return echo.NewHTTPError(status, message)
	}

	// Verify password using helper function
	valid, err := verifySharePassword(shareDetails, request.Password)
	if !valid {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid password")
	}
	if err != nil {
		logging.ErrorLogger.Printf("Error verifying password: %v", err)
	}

	// Log successful authentication
	logging.InfoLogger.Printf("Share authentication successful: %s", shareID)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Authentication successful",
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

// generateShareID creates a random share ID
func generateShareID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return time.Now().Format("20060102150405") + "fallback"
	}
	return hex.EncodeToString(b)
}
