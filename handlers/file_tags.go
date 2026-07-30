package handlers

import (
	"encoding/base64"
	"errors"
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
	hasCipher := encryptedTags != ""
	hasNonce := tagsNonce != ""
	if hasCipher != hasNonce {
		return errors.New("encrypted_tags and tags_nonce must both be present or both omitted")
	}
	if !hasCipher && !hasNonce {
		return nil
	}
	if allowEmptyPair && encryptedTags == "" && tagsNonce == "" {
		return nil
	}
	if len(encryptedTags) > crypto.MaxEncryptedTagsBase64Len {
		return errors.New("encrypted_tags exceeds maximum encoded length")
	}
	rawCipher, err := base64.StdEncoding.DecodeString(encryptedTags)
	if err != nil {
		return errors.New("encrypted_tags must be valid base64")
	}
	if len(rawCipher) == 0 {
		return errors.New("encrypted_tags ciphertext is empty")
	}
	rawNonce, err := base64.StdEncoding.DecodeString(tagsNonce)
	if err != nil {
		return errors.New("tags_nonce must be valid base64")
	}
	if len(rawNonce) != crypto.TagsNonceRawBytes {
		return errors.New("tags_nonce must decode to exactly 12 bytes")
	}
	return nil
}
