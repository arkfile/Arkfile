package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	arkcrypto "github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/storage"
)

// ShareRequest represents a file sharing request (Argon2id-based anonymous shares)
type ShareRequest struct {
	ShareID             string `json:"share_id"` // Client-generated share ID
	FileID              string `json:"file_id"`
	Salt                string `json:"salt"`                  // Base64-encoded 32-byte salt
	EncryptedEnvelope   string `json:"encrypted_envelope"`    // Base64-encoded Share Envelope (FEK + Download Token) encrypted with AAD
	DownloadTokenHash   string `json:"download_token_hash"`   // SHA-256 hash of the Download Token
	ExpiresAfterMinutes int    `json:"expires_after_minutes"` // Optional expiration in minutes (0 = no expiration)
	MaxAccesses         *int   `json:"max_accesses"`          // Optional download limit (nil = unlimited)
}

// ShareResponse represents a file share creation response
type ShareResponse struct {
	ShareID   string     `json:"share_id"`
	ShareURL  string     `json:"share_url"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
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

	// Validate max_accesses if provided (must be >= 1)
	if request.MaxAccesses != nil && *request.MaxAccesses < 1 {
		return echo.NewHTTPError(http.StatusBadRequest, "Max accesses must be at least 1")
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
	if request.ExpiresAfterMinutes > 0 {
		expiry := time.Now().Add(time.Duration(request.ExpiresAfterMinutes) * time.Minute)
		expiresAt = &expiry
	}

	// Convert max_accesses pointer to sql.NullInt64 for the INSERT
	var maxAccesses sql.NullInt64
	if request.MaxAccesses != nil {
		maxAccesses = sql.NullInt64{Int64: int64(*request.MaxAccesses), Valid: true}
	}

	// Create file share record - store salt as base64 string directly
	_, err = database.DB.Exec(`
		INSERT INTO file_share_keys (share_id, file_id, owner_username, salt, encrypted_fek, download_token_hash, created_at, expires_at, max_accesses)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)`,
		request.ShareID, request.FileID, username, request.Salt, request.EncryptedEnvelope, request.DownloadTokenHash, expiresAt, maxAccesses,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create file share record for file %s: %v", request.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create file share")
	}

	// Construct share URL using configured BASE_URL when available.
	// BASE_URL is the authoritative public-facing base URL set by the operator in secrets.env.
	// Without it, c.Request().Host reflects the internal proxy address (e.g. localhost:8443)
	// rather than the public domain, producing broken share URLs behind a reverse proxy.
	cfg := config.GetConfig()
	var baseURL string
	if cfg.Server.BaseURL != "" {
		baseURL = cfg.Server.BaseURL
	} else {
		// Fallback for local/dev deployments where BASE_URL is not configured
		origin := c.Request().Header.Get("Origin")
		if origin != "" {
			baseURL = origin
		} else {
			scheme := "https"
			if c.Echo().Debug && c.Request().TLS == nil {
				scheme = "http"
			}
			baseURL = scheme + "://" + c.Request().Host
		}
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

// GetShareEnvelope returns the encrypted envelope and salt for a share.
// The server does NOT receive or process share passwords. Share key derivation
// (Argon2id) and envelope decryption happen entirely client-side.
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
		AccessCount       float64
		MaxAccesses       sql.NullFloat64
	}

	err := database.DB.QueryRow(`
		SELECT file_id, owner_username, salt, encrypted_fek, expires_at, revoked_at, revoked_reason,
		       access_count, max_accesses
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
		&share.AccessCount,
		&share.MaxAccesses,
	)

	if err == sql.ErrNoRows {
		prefix := shareID[:min(8, len(shareID))]
		// Log share-not-found for security monitoring (share enumeration detection)
		logging.LogSecurityEventWithEntityID(
			logging.EventShareNotFound,
			entityID,
			map[string]interface{}{
				"endpoint":        "get_share_envelope",
				"share_id_prefix": prefix,
			},
		)
		// Notify enumeration guard for progressive rate limiting
		NotifyShareNotFound(entityID, prefix)
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

	// Check if max accesses limit has been reached
	if share.MaxAccesses.Valid && int64(share.AccessCount) >= int64(share.MaxAccesses.Float64) {
		return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
	}

	// Get file size (plaintext metadata like filename/sha256 is inside the encrypted
	// ShareEnvelope, decrypted client-side with the share password — no need to send
	// server-side encrypted metadata that share recipients cannot decrypt)
	// Note: rqlite returns numbers as float64, so we scan into float64 and convert
	var sizeF sql.NullFloat64
	err = database.DB.QueryRow(`
		SELECT size_bytes
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(&sizeF)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	var sizeBytes int64
	if sizeF.Valid {
		sizeBytes = int64(sizeF.Float64)
	}

	// Log metadata access
	logging.InfoLogger.Printf("Share envelope accessed: share_id=%s..., file=%s, entity_id=%s", shareID[:8], share.FileID, entityID)

	// Return share envelope data (metadata is inside the encrypted envelope)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"share_id":           shareID,
		"file_id":            share.FileID,
		"salt":               share.Salt,
		"encrypted_envelope": share.EncryptedEnvelope,
		"size_bytes":         sizeBytes,
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

	if request.Reason == "" {
		request.Reason = "manual"
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
		prefix := shareID[:min(8, len(shareID))]
		// Log share-not-found for security monitoring (share enumeration detection)
		entityID := logging.GetOrCreateEntityID(c)
		logging.LogSecurityEventWithEntityID(
			logging.EventShareNotFound,
			entityID,
			map[string]interface{}{
				"endpoint":        "get_shared_file",
				"share_id_prefix": prefix,
			},
		)
		// Notify enumeration guard for progressive rate limiting
		NotifyShareNotFound(entityID, prefix)
		return c.HTML(http.StatusNotFound, read404Page())
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return c.HTML(http.StatusForbidden, read403Page())
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
	limit, offset, err := parseLimitOffset(c, defaultMetadataPageLimit, maxMetadataPageLimit)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Query shares (owner already has file metadata via /api/files endpoints —
	// no need to duplicate encrypted metadata here)
	rows, err := database.DB.Query(`
		SELECT sk.share_id, sk.file_id, sk.created_at, sk.expires_at,
		       sk.revoked_at, sk.revoked_reason, sk.access_count, sk.max_accesses,
		       fm.size_bytes
		FROM file_share_keys sk
		JOIN file_metadata fm ON sk.file_id = fm.file_id
		WHERE sk.owner_username = ?
		ORDER BY sk.created_at DESC
		LIMIT ? OFFSET ?
	`, username, limit, offset)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to query shares: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve shares")
	}
	defer rows.Close()

	var shares []map[string]interface{}
	for rows.Next() {
		var share struct {
			ShareID       string
			FileID        string
			CreatedAt     string
			ExpiresAt     sql.NullString
			RevokedAt     sql.NullString
			RevokedReason sql.NullString
			AccessCount   sql.NullFloat64
			MaxAccesses   sql.NullFloat64
			Size          sql.NullFloat64 // rqlite returns numbers as float64
		}

		if err := rows.Scan(
			&share.ShareID,
			&share.FileID,
			&share.CreatedAt,
			&share.ExpiresAt,
			&share.RevokedAt,
			&share.RevokedReason,
			&share.AccessCount,
			&share.MaxAccesses,
			&share.Size,
		); err != nil {
			logging.ErrorLogger.Printf("Error scanning share row: %v", err)
			continue
		}

		// Build share URL using configured BASE_URL when available (same logic as CreateFileShare)
		cfg := config.GetConfig()
		var baseURL string
		if cfg.Server.BaseURL != "" {
			baseURL = cfg.Server.BaseURL
		} else {
			baseURL = c.Request().Header.Get("Origin")
			if baseURL == "" {
				baseURL = "https://" + c.Request().Host
			}
		}

		shareURL := baseURL + "/shared/" + share.ShareID

		// Compute is_active: not revoked, not expired, and not exhausted
		isActive := true
		if share.RevokedAt.Valid {
			isActive = false
		}
		if share.ExpiresAt.Valid && share.ExpiresAt.String != "" {
			if expiry, err := time.Parse(time.RFC3339, share.ExpiresAt.String); err == nil {
				if time.Now().After(expiry) {
					isActive = false
					if !share.RevokedAt.Valid {
						database.DB.Exec(`
							UPDATE file_share_keys
							SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'time'
							WHERE share_id = ?
						`, share.ShareID)
						share.RevokedAt = sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true}
						share.RevokedReason = sql.NullString{String: "time", Valid: true}
					}
				}
			}
		}
		// Mark exhausted shares as inactive (max download limit reached)
		if isActive && share.MaxAccesses.Valid && int64(share.AccessCount.Float64) >= int64(share.MaxAccesses.Float64) {
			isActive = false
			if !share.RevokedAt.Valid {
				database.DB.Exec(`
					UPDATE file_share_keys
					SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'exhausted'
					WHERE share_id = ?
				`, share.ShareID)
				share.RevokedAt = sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true}
				share.RevokedReason = sql.NullString{String: "exhausted", Valid: true}
			}
		}

		shareData := map[string]interface{}{
			"share_id":     share.ShareID,
			"file_id":      share.FileID,
			"share_url":    shareURL,
			"created_at":   share.CreatedAt,
			"access_count": int64(share.AccessCount.Float64),
			"is_active":    isActive,
		}

		if share.Size.Valid {
			shareData["size_bytes"] = int64(share.Size.Float64)
		}

		if share.ExpiresAt.Valid {
			shareData["expires_at"] = share.ExpiresAt.String
		} else {
			shareData["expires_at"] = nil
		}

		if share.RevokedAt.Valid {
			shareData["revoked_at"] = share.RevokedAt.String
		} else {
			shareData["revoked_at"] = nil
		}

		if share.RevokedReason.Valid {
			shareData["revoked_reason"] = share.RevokedReason.String
		} else {
			shareData["revoked_reason"] = nil
		}

		if share.MaxAccesses.Valid {
			shareData["max_accesses"] = int64(share.MaxAccesses.Float64)
		} else {
			shareData["max_accesses"] = nil
		}

		shares = append(shares, shareData)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"shares":   shares,
		"limit":    limit,
		"offset":   offset,
		"returned": len(shares),
		"has_more": len(shares) == limit,
	})
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
		AccessCount   float64
		MaxAccesses   sql.NullFloat64
	}

	err := database.DB.QueryRow(`
		SELECT file_id, expires_at, revoked_at, revoked_reason,
		       access_count, max_accesses
		FROM file_share_keys 
		WHERE share_id = ?
	`, shareID).Scan(
		&share.FileID,
		&share.ExpiresAt,
		&share.RevokedAt,
		&share.RevokedReason,
		&share.AccessCount,
		&share.MaxAccesses,
	)

	if err == sql.ErrNoRows {
		prefix := shareID[:min(8, len(shareID))]
		// Log share-not-found for security monitoring (share enumeration detection)
		logging.LogSecurityEventWithEntityID(
			logging.EventShareNotFound,
			entityID,
			map[string]interface{}{
				"endpoint":        "get_share_download_metadata",
				"share_id_prefix": prefix,
			},
		)
		// Notify enumeration guard for progressive rate limiting
		NotifyShareNotFound(entityID, prefix)
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

	// Check if max accesses limit has been reached
	if share.MaxAccesses.Valid && int64(share.AccessCount) >= int64(share.MaxAccesses.Float64) {
		return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
	}

	// Get file chunk info
	// Note: rqlite returns numbers as float64, so we scan into float64 and convert
	var sizeBytes float64
	var chunkCount float64
	var chunkSizeBytes float64

	err = database.DB.QueryRow(`
		SELECT size_bytes, chunk_count, chunk_size_bytes
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(&sizeBytes, &chunkCount, &chunkSizeBytes)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	// Convert to int64 for use
	sizeBytesInt := int64(sizeBytes)
	chunkCountInt := int64(chunkCount)
	chunkSizeBytesInt := int64(chunkSizeBytes)

	// Handle legacy files without chunk info
	if chunkCountInt == 0 {
		chunkCountInt = 1
	}
	if chunkSizeBytesInt == 0 {
		chunkSizeBytesInt = arkcrypto.PlaintextChunkSize() // default from config
	}

	logging.InfoLogger.Printf("Share chunk info accessed: share_id=%s..., file=%s, entity_id=%s", shareID[:8], share.FileID, entityID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":          share.FileID,
		"size_bytes":       sizeBytesInt,
		"chunk_count":      chunkCountInt,
		"chunk_size_bytes": chunkSizeBytesInt,
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
		AccessCount       float64
		MaxAccesses       sql.NullFloat64
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
		entityID := logging.GetOrCreateEntityID(c)
		logging.WarningLogger.Printf("Invalid download token: share_id=%s, entity_id=%s", shareID[:8], entityID)
		logging.LogSecurityEventWithEntityID(
			logging.EventInvalidDownloadToken,
			entityID,
			map[string]interface{}{
				"endpoint":        "download_share_chunk",
				"share_id_prefix": shareID[:min(8, len(shareID))],
				"chunk_index":     chunkIndex,
			},
		)
		// Record failed attempt for per-share-ID progressive rate limiting
		if recordErr := recordFailedAttempt(shareID, entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record invalid token attempt: %v", recordErr)
		}
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}

	// Check if max accesses limit has been reached (only block NEW downloads on chunk 0)
	// For chunks 1+, allow the download to continue even if limit was just reached
	// This ensures in-progress downloads can complete all chunks
	if chunkIndex == 0 && share.MaxAccesses.Valid && int64(share.AccessCount) >= int64(share.MaxAccesses.Float64) {
		logging.WarningLogger.Printf("Chunk download attempt on exhausted share: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
	}

	// Get file metadata
	// Note: rqlite returns numbers as float64, so we scan into float64 and convert
	var storageID string
	var sizeBytesF float64
	var chunkCountF float64
	var chunkSizeBytesF float64

	err = database.DB.QueryRow(`
		SELECT storage_id, size_bytes, chunk_count, chunk_size_bytes
		FROM file_metadata
		WHERE file_id = ?
	`, share.FileID).Scan(&storageID, &sizeBytesF, &chunkCountF, &chunkSizeBytesF)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to get file metadata for %s: %v", share.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file metadata")
	}

	// Convert to int64 for use
	sizeBytes := int64(sizeBytesF)
	chunkCount := int64(chunkCountF)
	chunkSizeBytes := int64(chunkSizeBytesF)

	// Handle legacy files without chunk info
	if chunkCount == 0 {
		chunkCount = 1
	}
	if chunkSizeBytes == 0 {
		chunkSizeBytes = arkcrypto.PlaintextChunkSize() // default from config
	}

	// Validate chunk index
	if chunkIndex < 0 || chunkIndex >= chunkCount {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid chunk index: must be between 0 and %d", chunkCount-1))
	}

	// Calculate byte range for this chunk
	// IMPORTANT: chunk_size_bytes in the DB is the PLAINTEXT chunk size, but the
	// stored object contains ENCRYPTED chunks. Each encrypted chunk is larger due to:
	//   - Chunk 0: envelope header (2 bytes) + AES-GCM nonce (12 bytes) + plaintext + GCM tag (16 bytes)
	//   - Chunk 1+: AES-GCM nonce (12 bytes) + plaintext + GCM tag (16 bytes)
	// We must use encrypted chunk sizes for byte-range calculations in storage.
	gcmOverhead := int64(arkcrypto.AesGcmOverhead())        // nonce (12) + tag (16) = 28
	envelopeHeader := int64(arkcrypto.EnvelopeHeaderSize()) // 2 bytes (chunk 0 only)

	// Encrypted chunk sizes
	chunk0EncSize := envelopeHeader + gcmOverhead + chunkSizeBytes
	regularEncSize := gcmOverhead + chunkSizeBytes

	var startByte, encChunkSize int64
	if chunkIndex == 0 {
		startByte = 0
		encChunkSize = chunk0EncSize
	} else {
		startByte = chunk0EncSize + (chunkIndex-1)*regularEncSize
		encChunkSize = regularEncSize
	}

	endByte := startByte + encChunkSize - 1

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
		if share.MaxAccesses.Valid && int64(share.AccessCount)+1 >= int64(share.MaxAccesses.Float64) {
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

// isValidShareID validates that a share_id is in the correct format.
// Expected format: 43-character base64url string (32 bytes without padding).
// NOTE: Clients (Go CLI and TypeScript) ensure the first character is alphanumeric
// (never '-' or '_') to avoid issues with shell tools and URL parsers.
// The server accepts all valid base64url characters for robustness.
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
