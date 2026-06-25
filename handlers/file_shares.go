package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/config"
	arkcrypto "github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/storage"
	"github.com/arkfile/Arkfile/utils"
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

func publicShareBaseURL(c echo.Context) (string, error) {
	cfg := config.GetConfig()
	if baseURL := strings.TrimSpace(cfg.Server.BaseURL); baseURL != "" {
		return strings.TrimRight(baseURL, "/"), nil
	}

	if utils.IsProductionEnvironment() {
		return "", fmt.Errorf("BASE_URL is required for share URL construction in production")
	}

	host := strings.TrimSpace(c.Request().Host)
	if host == "" {
		return "", fmt.Errorf("request host is unavailable for share URL construction")
	}

	scheme := "https"
	if c.Echo().Debug && c.Request().TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + host, nil
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

	baseURL, err := publicShareBaseURL(c)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to construct share URL for file %s: %v", request.FileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Share URL configuration error")
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

	shareURL := baseURL + "/shared/" + request.ShareID

	createdAt := time.Now()
	logging.InfoLogger.Printf("Anonymous share created: file=%s, share_id=%s...", request.FileID, request.ShareID[:8])
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
		// Notify enumeration guard with full share ID for accurate uniqueness tracking
		NotifyShareNotFound(entityID, shareID)
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Check if share has been revoked.
	// To prevent sensitive owner-supplied comments from leaking to anonymous clients,
	// we only leak standard machine-parsable system-wide categories if they are 'time' or 'exhausted'.
	// Any other reason gets redacted to a generic "Share has been revoked" message.
	if share.RevokedAt != nil {
		reason := "Share has been revoked"
		if share.RevokedReason.Valid && (share.RevokedReason.String == "time" || share.RevokedReason.String == "exhausted") {
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

// IssueShareDownloadTicket exchanges the static download token (recovered from
// the decrypted share envelope) for a short-lived, entity-bound download
// ticket. Recipients call this after successfully decrypting the envelope, then
// present the returned ticket as X-Share-Ticket on chunk fetches. This replaces
// the never-rotated static download token as the per-chunk credential: a ticket
// captured from a compromised channel expires within minutes and is bound to
// the recipient's entity ID, so it cannot be reused by a different party and
// does not outlive the share.
//
// The static token's hash is still verified here as proof that the caller
// actually decrypted the envelope (i.e. knew the share password). The share's
// expiry, revocation, and max-accesses state are enforced exactly as in the
// chunk path; issuance does not consume a max-accesses slot (that happens
// atomically on chunk 0 in DownloadShareChunk).
//
// POST /api/public/shares/:id/ticket  { "download_token": "<base64>" }
func IssueShareDownloadTicket(c echo.Context) error {
	shareID := c.Param("id")
	if shareID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Share ID is required")
	}

	entityID := logging.GetOrCreateEntityID(c)

	// Basic rate limiting (same per-share-ID limiter as the envelope path).
	allowed, delay, rateLimitErr := checkRateLimit(shareID, entityID)
	if rateLimitErr != nil {
		logging.ErrorLogger.Printf("Rate limit check failed: %v", rateLimitErr)
	} else if !allowed {
		c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", int(delay.Seconds())))
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many requests")
	}

	var request struct {
		DownloadToken string `json:"download_token"`
	}
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body: "+err.Error())
	}
	if request.DownloadToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Download token is required")
	}

	// Load share state and enforce expiry / revocation / exhaustion.
	var downloadTokenHash string
	var expiresAt *time.Time
	var revokedAt *time.Time
	var revokedReason sql.NullString
	var accessCount float64
	var maxAccesses sql.NullFloat64

	err := database.DB.QueryRow(`
		SELECT download_token_hash, expires_at, revoked_at, revoked_reason,
		       access_count, max_accesses
		FROM file_share_keys
		WHERE share_id = ?
	`, shareID).Scan(
		&downloadTokenHash,
		&expiresAt,
		&revokedAt,
		&revokedReason,
		&accessCount,
		&maxAccesses,
	)

	if err == sql.ErrNoRows {
		prefix := shareID[:min(8, len(shareID))]
		logging.LogSecurityEventWithEntityID(
			logging.EventShareNotFound,
			entityID,
			map[string]interface{}{
				"endpoint":        "issue_share_download_ticket",
				"share_id_prefix": prefix,
			},
		)
		NotifyShareNotFound(entityID, shareID)
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	if expiresAt != nil && time.Now().After(*expiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}
	if revokedAt != nil {
		reason := "Share has been revoked"
		if revokedReason.Valid && (revokedReason.String == "time" || revokedReason.String == "exhausted") {
			reason += ": " + revokedReason.String
		}
		return echo.NewHTTPError(http.StatusForbidden, reason)
	}
	if maxAccesses.Valid && int64(accessCount) >= int64(maxAccesses.Float64) {
		return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
	}

	// Verify the static download token (proof of envelope decryption).
	computedHash, err := hashDownloadToken(request.DownloadToken)
	if err != nil {
		logging.WarningLogger.Printf("Invalid download token format at ticket issuance: share_id=%s, error=%v", shareID[:8], err)
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}
	if !constantTimeCompare(computedHash, downloadTokenHash) {
		logging.WarningLogger.Printf("Invalid download token at ticket issuance: share_id=%s, entity_id=%s", shareID[:8], entityID)
		logging.LogSecurityEventWithEntityID(
			logging.EventInvalidDownloadToken,
			entityID,
			map[string]interface{}{
				"endpoint":        "issue_share_download_ticket",
				"share_id_prefix": shareID[:min(8, len(shareID))],
			},
		)
		if recordErr := recordFailedAttempt(shareID, entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record invalid token attempt: %v", recordErr)
		}
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}

	// Issue the ticket bound to this recipient's entity ID.
	ticketKey, err := arkcrypto.GetShareTicketKey()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to obtain share ticket key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to issue ticket")
	}

	ticket, err := arkcrypto.IssueShareTicket(ticketKey, shareID, entityID, time.Now())
	if err != nil {
		logging.ErrorLogger.Printf("Failed to issue share ticket: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to issue ticket")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"share_id":   shareID,
		"ticket":     ticket,
		"expires_in": int(arkcrypto.ShareTicketTTL.Seconds()),
	})
}

// validateShareDownloadCredential verifies the per-chunk download credential
// presented by the caller. It prefers the short-lived X-Share-Ticket (bound to
// the requesting entity ID) and falls back to the static X-Download-Token for
// compatibility during the client transition. A failed check records a rate
// limit attempt and returns an echo HTTP error.
func validateShareDownloadCredential(c echo.Context, shareID, storedTokenHash string, chunkIndex int64) error {
	entityID := logging.GetOrCreateEntityID(c)

	if ticket := c.Request().Header.Get("X-Share-Ticket"); ticket != "" {
		ticketKey, err := arkcrypto.GetShareTicketKey()
		if err != nil {
			logging.ErrorLogger.Printf("Failed to obtain share ticket key: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate ticket")
		}
		if _, err := arkcrypto.VerifyShareTicket(ticketKey, ticket, shareID, entityID, time.Now()); err != nil {
			logging.WarningLogger.Printf("Invalid share ticket: share_id=%s, entity_id=%s, error=%v", shareID[:8], entityID, err)
			logging.LogSecurityEventWithEntityID(
				logging.EventInvalidDownloadToken,
				entityID,
				map[string]interface{}{
					"endpoint":        "download_share_chunk",
					"share_id_prefix": shareID[:min(8, len(shareID))],
					"chunk_index":     chunkIndex,
					"credential":      "ticket",
				},
			)
			if recordErr := recordFailedAttempt(shareID, entityID); recordErr != nil {
				logging.ErrorLogger.Printf("Failed to record invalid ticket attempt: %v", recordErr)
			}
			return echo.NewHTTPError(http.StatusForbidden, "Invalid download ticket")
		}
		return nil
	}

	// Fallback: static download token (proof-of-decryption bearer).
	downloadToken := c.Request().Header.Get("X-Download-Token")
	if downloadToken == "" {
		logging.WarningLogger.Printf("Chunk download attempt without credential: share_id=%s", shareID[:8])
		return echo.NewHTTPError(http.StatusForbidden, "Download credential required")
	}

	computedHash, err := hashDownloadToken(downloadToken)
	if err != nil {
		logging.WarningLogger.Printf("Invalid download token format: share_id=%s, error=%v", shareID[:8], err)
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}
	if !constantTimeCompare(computedHash, storedTokenHash) {
		logging.WarningLogger.Printf("Invalid download token: share_id=%s, entity_id=%s", shareID[:8], entityID)
		logging.LogSecurityEventWithEntityID(
			logging.EventInvalidDownloadToken,
			entityID,
			map[string]interface{}{
				"endpoint":        "download_share_chunk",
				"share_id_prefix": shareID[:min(8, len(shareID))],
				"chunk_index":     chunkIndex,
				"credential":      "token",
			},
		)
		if recordErr := recordFailedAttempt(shareID, entityID); recordErr != nil {
			logging.ErrorLogger.Printf("Failed to record invalid token attempt: %v", recordErr)
		}
		return echo.NewHTTPError(http.StatusForbidden, "Invalid download token")
	}
	return nil
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
	} else if request.Reason != "manual" && request.Reason != "owner_request" && request.Reason != "abuse" {
		// Restrict revoked_reason block to preset list of enums to prevent arbitrary string/PII injections
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid revocation reason")
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
	logging.InfoLogger.Printf("Share revoked: %s", shareID)

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
		// Notify enumeration guard with full share ID for accurate uniqueness tracking
		NotifyShareNotFound(entityID, shareID)
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

	baseURL, err := publicShareBaseURL(c)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to construct share URLs for user %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Share URL configuration error")
	}

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
		// Notify enumeration guard with full share ID for accurate uniqueness tracking
		NotifyShareNotFound(entityID, shareID)
		return echo.NewHTTPError(http.StatusNotFound, "Share not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error accessing share %s: %v", shareID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Check if share has expired
	if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
		return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
	}

	// Check if share has been revoked.
	// To prevent sensitive owner-supplied comments from leaking to anonymous clients,
	// we only leak standard machine-parsable system-wide categories if they are 'time' or 'exhausted'.
	// Any other reason gets redacted to a generic "Share has been revoked" message.
	if share.RevokedAt != nil {
		reason := "Share has been revoked"
		if share.RevokedReason.Valid && (share.RevokedReason.String == "time" || share.RevokedReason.String == "exhausted") {
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

	// The per-chunk download credential (X-Share-Ticket preferred, X-Download-Token
	// fallback) is validated below via validateShareDownloadCredential after the
	// share state is loaded.

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

	// Check if share has been revoked.
	// To prevent sensitive owner-supplied comments from leaking to anonymous clients,
	// we only leak standard machine-parsable system-wide categories if they are 'time' or 'exhausted'.
	// Any other reason gets redacted to a generic "Share has been revoked" message.
	if share.RevokedAt != nil {
		reason := "Share has been revoked"
		if share.RevokedReason.Valid && (share.RevokedReason.String == "time" || share.RevokedReason.String == "exhausted") {
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

	// Validate the per-chunk download credential: short-lived entity-bound
	// X-Share-Ticket preferred, static X-Download-Token fallback. A failed
	// check records a per-share-ID rate-limit attempt and 403s.
	if err := validateShareDownloadCredential(c, shareID, share.DownloadTokenHash, chunkIndex); err != nil {
		return err
	}

	// Check if max accesses limit has been reached (only block NEW downloads on chunk 0)
	// This check is a second-layer defense; the primary increment and check happen atomically below.
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

	// Calculate byte range for this chunk.
	// chunks are uniform
	// [nonce (12)][ciphertext][tag (16)] = chunk_size_bytes + 28. There is
	// no chunk-0 envelope-header prefix in the chunk stream; the FEK
	// envelope lives in file_metadata.encrypted_fek separately. Final
	// chunk range is bounded by sizeBytes (encrypted-stream length), not
	// padded_size, so padding is never returned as decryptable chunk data.
	gcmOverhead := int64(arkcrypto.AesGcmOverhead()) // nonce (12) + tag (16) = 28
	encChunkSize := gcmOverhead + chunkSizeBytes

	startByte := chunkIndex * encChunkSize
	endByte := startByte + encChunkSize - 1

	// Bound the final chunk by the encrypted-stream length.
	if endByte >= sizeBytes {
		endByte = sizeBytes - 1
	}

	// Calculate actual chunk size
	actualChunkSize := endByte - startByte + 1
	if actualChunkSize <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk range")
	}

	// Increment access count atomically on first chunk download.
	// To prevent concurrent double-spend race conditions (TOCTOU), we execute an UPDATE
	// statement with a conditional WHERE clause ensuring that the access_count is strictly less
	// than max_accesses (if configured). We check RowsAffected to confirm the atomic update succeeded.
	if chunkIndex == 0 {
		result, err := database.DB.Exec(`
			UPDATE file_share_keys 
			SET access_count = access_count + 1 
			WHERE share_id = ?
			  AND (max_accesses IS NULL OR access_count < max_accesses)
		`, shareID)

		if err != nil {
			logging.ErrorLogger.Printf("Database error in atomic increment of access count: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			logging.ErrorLogger.Printf("Error checking RowsAffected for atomic increment: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
		}

		if rowsAffected == 0 {
			logging.WarningLogger.Printf("Atomic access increment rejected (limit reached or concurrently exhausted): share_id=%s", shareID[:8])
			return echo.NewHTTPError(http.StatusForbidden, "Download limit reached")
		}

		// Log if this was the last allowed download
		if share.MaxAccesses.Valid && int64(share.AccessCount)+1 >= int64(share.MaxAccesses.Float64) {
			logging.InfoLogger.Printf("Share exhausted (max downloads reached): share_id=%s", shareID[:8])
		}
	}

	// Get the chunk from storage
	reader, _, err := storage.Registry.GetObjectChunkWithFallback(c.Request().Context(), storageID, startByte, actualChunkSize)
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
