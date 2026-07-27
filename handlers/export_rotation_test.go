package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBundleMetadataIncludesAccountKDFMetadata(t *testing.T) {
	file := &models.File{
		FileID:         "00112233-4455-6677-8899-aabbccddeeff",
		OwnerUsername:  "export-owner",
		PasswordType:   "account",
		EncryptedFEK:   "encrypted-fek",
		SizeBytes:      1024,
		PaddedSize:     sql.NullInt64{Int64: 2048, Valid: true},
		ChunkCount:     1,
		ChunkSizeBytes: int64(crypto.PlaintextChunkSize()),
	}
	salt := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	metadata := buildBundleMetadata(file, salt, int(crypto.OwnerEnvelopeKDFProfile()))
	assert.Equal(t, 2, metadata.Version)
	assert.Equal(t, salt, metadata.AccountKDFSalt)
	assert.Equal(t, int(crypto.OwnerEnvelopeKDFProfile()), metadata.AccountKDFProfile)
	assert.Equal(t, int(crypto.OwnerEnvelopeVersion()), metadata.EnvelopeVersion)
	assert.Equal(t, file.OwnerUsername, metadata.OwnerUsername)
}

// TestResolveExportAuth_QueryTokenAcrossRotation verifies that a browser
// export token (signed with the full-tier key, aud=arkfile-export) issued
// before a JWT signing-key rotation still resolves during the overlap window.
func TestResolveExportAuth_QueryTokenAcrossRotation(t *testing.T) {
	const username = "export-overlap-user"
	const fileID = "file-123"

	claims := &ExportTokenClaims{
		Username: username,
		FileID:   fileID,
		Action:   "export",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",
			Audience:  []string{"arkfile-export"},
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(auth.GetJWTFullPrivateKey())
	require.NoError(t, err)

	_, err = auth.RotateJWTSigningKeys()
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?token="+signed, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	got, err := resolveExportAuth(c, fileID)
	require.NoError(t, err)
	assert.Equal(t, username, got)
}

// TestResolveExportAuthFromHeader_BearerAcrossRotation verifies the CLI export
// path (full-tier Bearer token) still validates after a rotation.
func TestResolveExportAuthFromHeader_BearerAcrossRotation(t *testing.T) {
	const username = "export-header-overlap-user"

	token, _, err := auth.GenerateFullAccessToken(username)
	require.NoError(t, err)

	_, err = auth.RotateJWTSigningKeys()
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	got, err := resolveExportAuthFromHeader(c)
	require.NoError(t, err)
	assert.Equal(t, username, got)
}
