package handlers

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arkfile/Arkfile/crypto"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOpaqueTagsPair(t *testing.T) {
	require.NoError(t, validateOpaqueTagsPair("", "", false))
	require.Error(t, validateOpaqueTagsPair("abc", "", false))
	require.Error(t, validateOpaqueTagsPair("", "abc", false))

	nonce := base64.StdEncoding.EncodeToString(make([]byte, crypto.TagsNonceRawBytes))
	cipher := base64.StdEncoding.EncodeToString([]byte("ciphertext-and-tag-bytes"))
	require.NoError(t, validateOpaqueTagsPair(cipher, nonce, false))

	require.Error(t, validateOpaqueTagsPair(strings.Repeat("A", 1025), nonce, false))
	badNonce := base64.StdEncoding.EncodeToString(make([]byte, 8))
	require.Error(t, validateOpaqueTagsPair(cipher, badNonce, false))
	require.NoError(t, validateOpaqueTagsPair("", "", true))
}

func TestValidateOpaqueGCMPair_RejectsPlaintext(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(make([]byte, crypto.TagsNonceRawBytes))
	cipher := base64.StdEncoding.EncodeToString(make([]byte, 16))

	require.NoError(t, validateOpaqueGCMPair(cipher, nonce, "encrypted_filename", "filename_nonce", false))
	require.Error(t, validateOpaqueGCMPair("vacation-photos.pdf", nonce, "encrypted_filename", "filename_nonce", false))
	require.Error(t, validateOpaqueGCMPair(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		nonce,
		"encrypted_sha256sum",
		"sha256sum_nonce",
		false,
	))
	require.Error(t, validateOpaqueGCMPair(cipher, base64.StdEncoding.EncodeToString(make([]byte, 8)), "encrypted_filename", "filename_nonce", false))
	require.Error(t, validateOpaqueGCMPair(cipher, "", "encrypted_password_hint", "password_hint_nonce", false))
	require.NoError(t, validateOpaqueGCMPair("", "", "encrypted_password_hint", "password_hint_nonce", false))
}

func TestUpdateFileTags_RequiresAuthUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut, "/api/files/x/tags", strings.NewReader(`{"encrypted_tags":"","tags_nonce":"","expected_revision":0}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("fileId")
	c.SetParamValues("11111111-1111-4111-8111-111111111111")

	err := UpdateFileTags(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}
