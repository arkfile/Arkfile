// export.go - Handlers for .arkbackup bundle export
// Streams encrypted file data from S3 as self-contained bundles for offline decryption.
// See docs/wip/arkbackup-export.md for the bundle format specification.

package handlers

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// arkbackupMagic is the 4-byte magic header for .arkbackup bundles
var arkbackupMagic = []byte{'A', 'R', 'K', 'B'}

// arkbackupVersion is the current bundle format version
const arkbackupVersion uint16 = 1

// ExportTokenClaims holds claims for short-lived export download tokens
type ExportTokenClaims struct {
	Username string `json:"username"`
	FileID   string `json:"file_id"`
	Action   string `json:"action"`
	jwt.RegisteredClaims
}

// bundleMetadata is the JSON metadata embedded in the .arkbackup bundle header
type bundleMetadata struct {
	Version            int    `json:"version"`
	FileID             string `json:"file_id"`
	EncryptedFEK       string `json:"encrypted_fek"`
	PasswordType       string `json:"password_type"`
	SizeBytes          int64  `json:"size_bytes"`
	PaddedSize         int64  `json:"padded_size"`
	EncryptedFilename  string `json:"encrypted_filename"`
	FilenameNonce      string `json:"filename_nonce"`
	EncryptedSHA256Sum string `json:"encrypted_sha256sum"`
	SHA256SumNonce     string `json:"sha256sum_nonce"`
	ChunkSizeBytes     int64  `json:"chunk_size_bytes"`
	ChunkCount         int64  `json:"chunk_count"`
	EnvelopeVersion    int    `json:"envelope_version"`
	CreatedAt          string `json:"created_at"`
}

// ExportFile handles GET /api/files/:fileId/export
// Streams a .arkbackup bundle for the authenticated user's own file.
// Authentication: JWT + TOTP (via totpProtectedGroup middleware)
// Also accepts ?token= query param for browser downloads (short-lived export token).
func ExportFile(c echo.Context) error {
	fileID := c.Param("fileId")

	// Determine username from JWT or export token
	username, err := resolveExportAuth(c, fileID)
	if err != nil {
		return err
	}

	// Fetch file metadata
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during export: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Verify ownership
	if file.OwnerUsername != username {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	return streamExportBundle(c, file)
}

// AdminExportFile handles GET /api/admin/files/:fileId/export
// Streams a .arkbackup bundle for any user's file (admin only).
// Authentication: JWT + Admin middleware
func AdminExportFile(c echo.Context) error {
	fileID := c.Param("fileId")

	// Fetch file metadata (admin can export any file)
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during admin export: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	adminUsername := auth.GetUsernameFromToken(c)
	logging.InfoLogger.Printf("Admin export: file_id=%s owner=%s exported_by=%s", fileID, file.OwnerUsername, adminUsername)

	return streamExportBundle(c, file)
}

// CreateExportToken handles POST /api/files/:fileId/export-token
// Returns a short-lived JWT scoped to a single file export.
// Used by the browser frontend to trigger native downloads without memory buffering.
func CreateExportToken(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	// Verify file exists and is owned by user
	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during export token creation: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	if file.OwnerUsername != username {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	// Create short-lived export token (60 seconds)
	expiresAt := time.Now().Add(60 * time.Second)
	claims := &ExportTokenClaims{
		Username: username,
		FileID:   fileID,
		Action:   "export",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",
			Audience:  []string{"arkfile-export"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(auth.GetJWTPrivateKey())
	if err != nil {
		logging.ErrorLogger.Printf("Failed to sign export token: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create export token")
	}

	return JSONResponse(c, http.StatusOK, "Export token created", map[string]interface{}{
		"token":      tokenString,
		"expires_in": 60,
	})
}

// resolveExportAuth determines the username for an export request.
// This endpoint is on the public router (no JWT middleware) to support both:
//   - CLI clients: send Authorization: Bearer <jwt> header
//   - Browser downloads: send ?token=<export-token> query param
func resolveExportAuth(c echo.Context, fileID string) (string, error) {
	tokenStr := c.QueryParam("token")
	if tokenStr == "" {
		// No export token -- try Authorization: Bearer header (CLI flow)
		return resolveExportAuthFromHeader(c)
	}

	// Parse and validate export token
	token, err := jwt.ParseWithClaims(tokenStr, &ExportTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return auth.GetJWTPublicKey(), nil
	})
	if err != nil {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired export token")
	}

	claims, ok := token.Claims.(*ExportTokenClaims)
	if !ok || !token.Valid {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Invalid export token")
	}

	// Verify token is scoped to export action and correct file
	if claims.Action != "export" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Token not authorized for export")
	}
	if claims.FileID != fileID {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Token not authorized for this file")
	}

	return claims.Username, nil
}

// resolveExportAuthFromHeader parses the JWT from the Authorization: Bearer header.
// Used when the export endpoint is on the public router (no JWT middleware).
// This handles CLI clients that send standard Bearer token auth.
func resolveExportAuthFromHeader(c echo.Context) (string, error) {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	// Expect "Bearer <token>"
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || authHeader[:len(prefix)] != prefix {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}
	tokenStr := authHeader[len(prefix):]

	// Parse and validate the standard Arkfile JWT
	token, err := jwt.ParseWithClaims(tokenStr, &auth.Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return auth.GetJWTPublicKey(), nil
	})
	if err != nil {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	claims, ok := token.Claims.(*auth.Claims)
	if !ok || !token.Valid || claims.Username == "" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
	}

	return claims.Username, nil
}

// streamExportBundle writes the .arkbackup binary bundle to the HTTP response.
// Memory usage is O(1): only the JSON metadata header is buffered; the S3 blob is streamed.
func streamExportBundle(c echo.Context, file *models.File) error {
	// Build JSON metadata
	meta := buildBundleMetadata(file)
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to marshal export metadata: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build export metadata")
	}

	// Determine blob size to stream (padded size if available, otherwise size_bytes)
	blobSize := file.SizeBytes
	if file.PaddedSize.Valid && file.PaddedSize.Int64 > 0 {
		blobSize = file.PaddedSize.Int64
	}

	// Calculate total bundle size: 4 (magic) + 2 (version) + 4 (header length) + len(JSON) + blob
	fixedHeaderSize := int64(10)
	totalSize := fixedHeaderSize + int64(len(metaJSON)) + blobSize

	// Open S3 object for streaming
	s3Object, _, err := storage.Registry.GetObjectWithFallback(c.Request().Context(), file.StorageID, storage.GetObjectOptions{})
	if err != nil {
		logging.ErrorLogger.Printf("Failed to open S3 object for export: file_id=%s storage_id=%s err=%v", file.FileID, file.StorageID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file from storage")
	}
	defer s3Object.Close()

	// Set response headers
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.arkbackup"`, file.FileID))
	c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", totalSize))
	c.Response().WriteHeader(http.StatusOK)

	writer := c.Response().Writer

	// Write 4-byte magic: "ARKB"
	if _, err := writer.Write(arkbackupMagic); err != nil {
		logging.ErrorLogger.Printf("Export write error (magic): %v", err)
		return nil // Headers already sent
	}

	// Write 2-byte version (big-endian)
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, arkbackupVersion)
	if _, err := writer.Write(versionBytes); err != nil {
		logging.ErrorLogger.Printf("Export write error (version): %v", err)
		return nil
	}

	// Write 4-byte header length (big-endian)
	headerLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLenBytes, uint32(len(metaJSON)))
	if _, err := writer.Write(headerLenBytes); err != nil {
		logging.ErrorLogger.Printf("Export write error (header length): %v", err)
		return nil
	}

	// Write JSON metadata
	if _, err := writer.Write(metaJSON); err != nil {
		logging.ErrorLogger.Printf("Export write error (metadata): %v", err)
		return nil
	}

	// Stream S3 object to response
	if _, err := io.Copy(writer, s3Object); err != nil {
		logging.ErrorLogger.Printf("Export stream error (S3 blob): file_id=%s err=%v", file.FileID, err)
		return nil // Headers already sent, cannot change status
	}

	logging.InfoLogger.Printf("Export complete: file_id=%s bundle_size=%d", file.FileID, totalSize)
	return nil
}

// buildBundleMetadata constructs the JSON metadata from a file record
func buildBundleMetadata(file *models.File) *bundleMetadata {
	paddedSize := file.SizeBytes
	if file.PaddedSize.Valid && file.PaddedSize.Int64 > 0 {
		paddedSize = file.PaddedSize.Int64
	}

	// Parse envelope version from first byte of encrypted FEK (if available)
	envelopeVersion := 1

	return &bundleMetadata{
		Version:            1,
		FileID:             file.FileID,
		EncryptedFEK:       file.EncryptedFEK,
		PasswordType:       file.PasswordType,
		SizeBytes:          file.SizeBytes,
		PaddedSize:         paddedSize,
		EncryptedFilename:  file.EncryptedFilename,
		FilenameNonce:      file.FilenameNonce,
		EncryptedSHA256Sum: file.EncryptedSha256sum,
		SHA256SumNonce:     file.Sha256sumNonce,
		ChunkSizeBytes:     file.ChunkSizeBytes,
		ChunkCount:         file.ChunkCount,
		EnvelopeVersion:    envelopeVersion,
		CreatedAt:          file.UploadDate.UTC().Format(time.RFC3339),
	}
}
