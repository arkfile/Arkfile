package handlers

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/84adam/Arkfile/auth"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebAuthnAuthBegin_RejectsNonMFAToken(t *testing.T) {
	body := bytes.NewReader([]byte(`{}`))
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/webauthn/auth/begin", body)

	claims := &auth.Claims{
		Username:    "webauthn-user",
		RequiresMFA: false,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{auth.AudienceFull},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := WebAuthnAuthBegin(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWebAuthnRegisterFinish_InvalidPayload(t *testing.T) {
	body := bytes.NewReader([]byte(`{}`))
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/webauthn/register/finish", body)

	claims := &auth.Claims{
		Username:    "webauthn-user",
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{auth.AudienceMFA},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := WebAuthnRegisterFinish(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWebAuthnAuthFinish_InvalidPayload(t *testing.T) {
	body := bytes.NewReader([]byte(`{}`))
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/webauthn/auth/finish", body)

	claims := &auth.Claims{
		Username:    "webauthn-user",
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{auth.AudienceMFA},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := WebAuthnAuthFinish(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
