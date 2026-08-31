package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// UpdateFileTags replaces opaque owner tags for a file under optimistic concurrency.
// Official clients mutate one tag at a time; the server only validates ownership,
// field pairing, encoded size, and tags_revision.
func UpdateFileTags(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authentication token")
	}
	fileID := c.Param("fileId")
	if fileID == "" {
		return JSONErrorCode(c, http.StatusBadRequest, "invalid_request", "fileId is required")
	}

	var request struct {
		EncryptedTags    string `json:"encrypted_tags"`
		TagsNonce        string `json:"tags_nonce"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if err := c.Bind(&request); err != nil {
		return JSONErrorCode(c, http.StatusBadRequest, "invalid_request", "Invalid JSON request: "+err.Error())
	}
	if request.ExpectedRevision < 0 {
		return JSONErrorCode(c, http.StatusBadRequest, "invalid_tags", "expected_revision must be non-negative")
	}
	if err := validateOpaqueTagsPair(request.EncryptedTags, request.TagsNonce, true); err != nil {
		return JSONErrorCode(c, http.StatusBadRequest, "invalid_tags", err.Error())
	}

	file, err := models.GetFileByFileID(database.DB, fileID)
	if err != nil {
		if err.Error() == "file not found" {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		logging.ErrorLogger.Printf("UpdateFileTags: lookup failed for file_id=%s: %v", fileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}
	if file.OwnerUsername != username {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	newRevision, err := models.UpdateFileTagsConditionally(
		database.DB,
		fileID,
		username,
		request.EncryptedTags,
		request.TagsNonce,
		request.ExpectedRevision,
	)
	if err != nil {
		if errors.Is(err, models.ErrTagsRevisionConflict) {
			return JSONErrorCode(c, http.StatusConflict, "tags_revision_conflict",
				"tags were updated elsewhere; reload and retry")
		}
		logging.ErrorLogger.Printf("UpdateFileTags: update failed for file_id=%s: %v", fileID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update tags")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"file_id":       fileID,
		"tags_revision": newRevision,
	})
}

// validateOpaqueTagsPair enforces the locked pair/size contract for encrypted tags.
// allowEmptyPair permits both fields as empty strings (final one-by-one removal on PUT).
func validateOpaqueTagsPair(encryptedTags, tagsNonce string, allowEmptyPair bool) error {
	return validateOpaqueGCMPair(encryptedTags, tagsNonce, "encrypted_tags", "tags_nonce", allowEmptyPair)
}

// validateOpaqueGCMPair rejects plaintext-looking owner metadata. Ciphertext and
// nonce must both be present or both omitted, decode as canonical standard
// base64, use a 12-byte nonce, and carry at least an AES-GCM tag. This cannot
// prove the client encrypted, but it refuses to persist obvious plaintext.
func validateOpaqueGCMPair(cipherB64, nonceB64, cipherField, nonceField string, allowEmptyPair bool) error {
	hasCipher := cipherB64 != ""
	hasNonce := nonceB64 != ""
	if hasCipher != hasNonce {
		return fmt.Errorf("%s and %s must both be present or both omitted", cipherField, nonceField)
	}
	if !hasCipher && !hasNonce {
		return nil
	}
	if allowEmptyPair && cipherB64 == "" && nonceB64 == "" {
		return nil
	}
	if looksLikeHexDigest(cipherB64) {
		return fmt.Errorf("%s looks like a hex digest, not opaque ciphertext", cipherField)
	}
	if len(cipherB64) > crypto.MaxEncryptedTagsBase64Len {
		return fmt.Errorf("%s exceeds maximum encoded length", cipherField)
	}
	rawCipher, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil || base64.StdEncoding.EncodeToString(rawCipher) != cipherB64 {
		return fmt.Errorf("%s must be canonical standard base64", cipherField)
	}
	if len(rawCipher) < crypto.AesGcmTagSize() {
		return fmt.Errorf("%s ciphertext is shorter than an AES-GCM tag", cipherField)
	}
	rawNonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || base64.StdEncoding.EncodeToString(rawNonce) != nonceB64 {
		return fmt.Errorf("%s must be canonical standard base64", nonceField)
	}
	if len(rawNonce) != crypto.TagsNonceRawBytes {
		return fmt.Errorf("%s must decode to exactly 12 bytes", nonceField)
	}
	return nil
}

// looksLikeHexDigest reports SHA-256-sized (and nearby) hex strings. Those
// values are valid standard base64, so the decode checks below would
// otherwise persist a plaintext content hash as "encrypted" metadata.
func looksLikeHexDigest(s string) bool {
	n := len(s)
	if n != 32 && n != 64 && n != 128 {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
