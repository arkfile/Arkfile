package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
