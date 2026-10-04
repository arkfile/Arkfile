// export.go - Handlers for .arkbackup bundle export
// Streams encrypted file data from S3 as self-contained bundles for offline decryption.
// Bundle layout: magic ARKB, version, JSON metadata length + metadata, then
// encrypted ciphertext matching the on-server object (see docs/api.md Backup Export).

package handlers

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/storage"
	"github.com/labstack/echo/v4"
)

// arkbackupMagic is the 4-byte magic header for .arkbackup bundles
var arkbackupMagic = []byte{'A', 'R', 'K', 'B'}

// arkbackupVersion is the current bundle format version
const arkbackupVersion uint16 = 2

// bundleMetadata is the JSON metadata embedded in the .arkbackup bundle header.
//
// bundles are self-describing. OwnerUsername is required so
// the offline decrypter can rebuild metadata-field AAD (filename, sha256)
// without any external state. file_id is required for FEK-envelope AAD and
// chunk AAD. The schema matches `bundleMeta` in
// cmd/arkfile-client/offline_decrypt.go field for field.
type bundleMetadata struct {
	Version               int    `json:"version"`
	FileID                string `json:"file_id"`
	OwnerUsername         string `json:"owner_username"`
	AccountKDFSalt        string `json:"account_kdf_salt"`
	AccountKDFProfile     int    `json:"account_kdf_profile"`
	EncryptedFEK          string `json:"encrypted_fek"`
	PasswordType          string `json:"password_type"`
	SizeBytes             int64  `json:"size_bytes"`
	PaddedSize            int64  `json:"padded_size"`
	EncryptedFilename     string `json:"encrypted_filename"`
	FilenameNonce         string `json:"filename_nonce"`
	EncryptedSHA256Sum    string `json:"encrypted_sha256sum"`
	SHA256SumNonce        string `json:"sha256sum_nonce"`
	EncryptedTags         string `json:"encrypted_tags,omitempty"`
	TagsNonce             string `json:"tags_nonce,omitempty"`
	EncryptedPasswordHint string `json:"encrypted_password_hint,omitempty"`
	PasswordHintNonce     string `json:"password_hint_nonce,omitempty"`
	ChunkSizeBytes        int64  `json:"chunk_size_bytes"`
	ChunkCount            int64  `json:"chunk_count"`
	EnvelopeVersion       int    `json:"envelope_version"`
	CreatedAt             string `json:"created_at"`
}

// ExportFile handles GET /api/files/:fileId/export
// Streams a .arkbackup bundle for the authenticated user's own file.
// Authentication: the standard mfaProtectedGroup stack, which accepts a CLI
// Bearer session or the browser session cookie.
func ExportFile(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("Database error during export: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

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

// streamExportBundle writes the .arkbackup binary bundle to the HTTP response.
// Memory usage is O(1): only the JSON metadata header is buffered; the S3 blob is streamed.
func streamExportBundle(c echo.Context, file *models.File) error {
	accountKDFSalt, accountKDFProfile, err := models.GetAccountCryptoMetadata(database.DB, file.OwnerUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to load account crypto metadata for export: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build export metadata")
	}
	// Build JSON metadata
	meta := buildBundleMetadata(file, accountKDFSalt, accountKDFProfile)
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
func buildBundleMetadata(file *models.File, accountKDFSalt string, accountKDFProfile int) *bundleMetadata {
	paddedSize := file.SizeBytes
	if file.PaddedSize.Valid && file.PaddedSize.Int64 > 0 {
		paddedSize = file.PaddedSize.Int64
	}

	envelopeVersion := int(crypto.OwnerEnvelopeVersion())

	meta := &bundleMetadata{
		Version:            2,
		FileID:             file.FileID,
		OwnerUsername:      file.OwnerUsername,
		AccountKDFSalt:     accountKDFSalt,
		AccountKDFProfile:  accountKDFProfile,
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
	if file.EncryptedTags != "" && file.TagsNonce != "" {
		meta.EncryptedTags = file.EncryptedTags
		meta.TagsNonce = file.TagsNonce
	}
	// Opaque Account Key ciphertext copied verbatim; the server never decrypts it.
	if file.EncryptedPasswordHint != "" && file.PasswordHintNonce != "" {
		meta.EncryptedPasswordHint = file.EncryptedPasswordHint
		meta.PasswordHintNonce = file.PasswordHintNonce
	}
	return meta
}
