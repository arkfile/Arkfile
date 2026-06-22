package auth

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/84adam/Arkfile/config" // Import config
	"github.com/84adam/Arkfile/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

// TestMain sets up necessary environment variables for config loading before running tests
// and cleans them up afterwards.
func TestMain(m *testing.M) {
	// Test Config Setup
	config.ResetConfigForTest()

	// Setup in-memory SQLite DB for KeyManager
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		fmt.Printf("FATAL: Failed to open in-memory DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create system_keys table. Mirrors the production schema in
	// database/unified_schema.sql so that auth.ValidateBootstrapToken
	// (which reads consumed_at) works under the test binary.
	_, err = db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			consumed_at TIMESTAMP
		);
	`)
	if err != nil {
		fmt.Printf("FATAL: Failed to create system_keys table: %v\n", err)
		os.Exit(1)
	}

	// Set Master Key for KeyManager
	// 32 bytes hex encoded = 64 chars
	masterKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	os.Setenv("ARKFILE_MASTER_KEY", masterKey)

	// Initialize KeyManager
	if err := crypto.InitKeyManager(db); err != nil {
		fmt.Printf("FATAL: Failed to initialize KeyManager: %v\n", err)
		os.Exit(1)
	}

	// Store original env vars and set test values
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"STORAGE_PROVIDER_1":         "generic-s3",
		"STORAGE_1_ENDPOINT":         "http://localhost:9332",
		"STORAGE_1_ACCESS_KEY":       "test-user-auth",
		"STORAGE_1_SECRET_KEY":       "test-password-auth",
		"STORAGE_1_BUCKET":           "test-bucket-auth",
		"LOCAL_STORAGE_PATH":         "/tmp/test-storage-auth",
		"JWT_TOKEN_LIFETIME_MINUTES": "1440", // Set to 24 hours for tests
	}

	for key, testValue := range testEnv {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, testValue)
	}

	// Load config with test env vars
	_, err = config.LoadConfig()
	if err != nil {
		fmt.Printf("FATAL: Failed to load config for auth tests: %v\n", err)
		os.Exit(1)
	}

	// Reset keys for test
	ResetKeysForTest()

	// Run tests
	exitCode := m.Run()

	// Cleanup
	os.Unsetenv("ARKFILE_MASTER_KEY")
	for key, originalValue := range originalEnv {
		if originalValue == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, originalValue)
		}
	}
	config.ResetConfigForTest()

	os.Exit(exitCode)
}

func TestGenerateFullAccessToken(t *testing.T) {
	testCases := []struct {
		name     string
		username string
	}{
		{"Valid username", "test.user.123"},
		{"Admin username", "admin.user.test"},
		{"Empty username", ""}, // Test edge case
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, _, err := GenerateFullAccessToken(tc.username)

			assert.NoError(t, err)
			assert.NotEmpty(t, tokenString)

			// Full tokens must validate against the full-tier public key,
			// not the temp-tier public key.
			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return GetJWTFullPublicKey(), nil
			})

			assert.NoError(t, err)
			assert.True(t, token.Valid, "Token should be valid")

			claims, ok := token.Claims.(*Claims)
			assert.True(t, ok, "Claims should be of type *Claims")
			assert.Equal(t, tc.username, claims.Username, "Username claim should match")
			assert.Equal(t, "arkfile-auth", claims.Issuer, "Issuer claim should be correct")
			assert.Contains(t, claims.Audience, AudienceAPI, "Audience claim should contain 'arkfile-api'")
			assert.NotContains(t, claims.Audience, AudienceMFA, "Full token must NOT carry the temp audience")
			assert.False(t, claims.RequiresMFA, "Full token must have requires_mfa=false")
			assert.NotEmpty(t, claims.ID, "ID (jti) claim should not be empty")

			expectedExpiry := time.Now().Add(24 * time.Hour)
			assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 5*time.Second, "Expiry time should be around 24 hours")
			assert.True(t, claims.IssuedAt.Time.Before(time.Now().Add(time.Second)), "Issue time should be in the past")
			assert.True(t, claims.NotBefore.Time.Before(time.Now().Add(time.Second)), "NotBefore time should be in the past")
		})
	}
}

// TestGenerateTemporaryMFAToken_ClaimsAndKey verifies the temp-tier token
// is signed with the temp-tier key and carries requires_mfa=true plus the
// arkfile-mfa audience.
func TestGenerateTemporaryMFAToken_ClaimsAndKey(t *testing.T) {
	tokenString, _, err := GenerateTemporaryMFAToken("alice")
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Should validate with the TEMP public key.
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return GetJWTTempPublicKey(), nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims := token.Claims.(*Claims)
	assert.Equal(t, "alice", claims.Username)
	assert.Contains(t, claims.Audience, AudienceMFA)
	assert.NotContains(t, claims.Audience, AudienceAPI, "Temp token must NOT carry the full audience")
	assert.True(t, claims.RequiresMFA, "Temp token must have requires_mfa=true")

	// Should FAIL to validate against the FULL public key (different key).
	_, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return GetJWTFullPublicKey(), nil
	})
	assert.Error(t, err, "Temp token must not validate against the full-tier public key")
}

func TestGetUsernameFromToken(t *testing.T) {
	// Setup: Create a valid token for testing
	testUsername := "test.user.2024"
	claims := &Claims{
		Username: testUsername,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), // Valid expiry
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Note: No need to sign it as we're manually setting it in the context

	// Setup: Create an Echo context
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Setup: Set the *jwt.Token in the context (emulates middleware)
	c.Set("user", token)

	// Execute
	extractedUsername := GetUsernameFromToken(c)

	// Assert
	assert.Equal(t, testUsername, extractedUsername, "Extracted username should match the one in the token")
}

// mintFullToken creates a valid full-tier JWT signed with the full-tier key,
// carrying aud=arkfile-api, requires_mfa=false, and the standard claims.
func mintFullToken(t *testing.T, username string, expiry time.Duration) string {
	t.Helper()
	tokenString, _, err := GenerateFullAccessToken(username)
	_ = expiry // expiry is controlled by config; helper kept for future variants
	assert.NoError(t, err)
	return tokenString
}

// mintCustomToken creates a JWT with caller-controlled claims and signer.
// Used by negative tests to forge audience/key combinations the production
// code paths cannot produce.
func mintCustomToken(t *testing.T, claims *Claims, signer ed25519.PrivateKey) string {
	t.Helper()
	if claims.Issuer == "" {
		claims.Issuer = Issuer
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	}
	if claims.ID == "" {
		claims.ID = "test-token-id"
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(signer)
	assert.NoError(t, err)
	return tokenString
}

func TestJWTMiddleware(t *testing.T) {
	e := echo.New()
	mockHandler := func(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*Claims)
		assert.Equal(t, "test.user.2024", claims.Username)
		return c.String(http.StatusOK, "test passed")
	}

	middlewareFunc := JWTMiddleware()
	handlerWithMiddleware := middlewareFunc(mockHandler)

	testCases := []struct {
		name           string
		tokenFunc      func() string
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid Full Token",
			tokenFunc: func() string {
				return mintFullToken(t, "test.user.2024", time.Hour)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Expired Full Token",
			tokenFunc: func() string {
				return mintCustomToken(t, &Claims{
					Username: "test.user.expired",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
						Audience:  []string{AudienceAPI},
					},
				}, GetJWTFullPrivateKey())
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name: "Signed with Attacker Key",
			tokenFunc: func() string {
				_, wrong, _ := ed25519.GenerateKey(nil)
				return mintCustomToken(t, &Claims{
					Username: "test.user.invalid",
					RegisteredClaims: jwt.RegisteredClaims{
						Audience: []string{AudienceAPI},
					},
				}, wrong)
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name: "No Token",
			tokenFunc: func() string {
				return ""
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name: "Malformed Token",
			tokenFunc: func() string {
				return "this.is.not.a.jwt"
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tokenString := tc.tokenFunc()
			if tokenString != "" {
				req.Header.Set(echo.HeaderAuthorization, "Bearer "+tokenString)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handlerWithMiddleware(c)

			if tc.expectError {
				assert.Error(t, err)
				httpErr, ok := err.(*echo.HTTPError)
				assert.True(t, ok)
				assert.Equal(t, tc.expectedStatus, httpErr.Code)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedStatus, rec.Code)
			}
		})
	}
}

// TestJWTMiddleware_RejectsTempAudience verifies that JWTMiddleware (which
// expects aud=arkfile-api) refuses a temp-tier token. This verifies that
// completing OPAQUE alone must not yield access to full-protected routes.
func TestJWTMiddleware_RejectsTempAudience(t *testing.T) {
	e := echo.New()
	handler := JWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach here")
	})

	tempToken, _, err := GenerateTemporaryMFAToken("alice")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+tempToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = handler(c)
	assert.Error(t, err, "temp-tier token must be rejected at full-tier validator")
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

// TestMFAJWTMiddleware_RejectsFullAudience verifies that MFAJWTMiddleware
// (which expects aud=arkfile-mfa) refuses a full-tier token. A full token
// must not be replayable at /api/mfa/{setup,verify,auth}.
func TestMFAJWTMiddleware_RejectsFullAudience(t *testing.T) {
	e := echo.New()
	handler := MFAJWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach here")
	})

	fullToken := mintFullToken(t, "alice", time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/api/mfa/setup", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+fullToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	assert.Error(t, err, "full-tier token must be rejected at temp-tier validator")
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

// TestJWTMiddleware_RejectsTempSignedWithFullKey verifies that even if an
// attacker hand-crafts a token with aud=arkfile-mfa and signs it with the
// FULL-tier key (i.e., an internal-policy violation), JWTMiddleware still
// refuses it because the audience does not match its expected value.
func TestJWTMiddleware_RejectsTempSignedWithFullKey(t *testing.T) {
	e := echo.New()
	handler := JWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach here")
	})

	// Token signed with the full-tier private key but carrying the TEMP
	// audience. JWTMiddleware expects AudienceAPI, so this must fail.
	crafted := mintCustomToken(t, &Claims{
		Username:    "mallory",
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: []string{AudienceMFA},
		},
	}, GetJWTFullPrivateKey())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+crafted)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	assert.Error(t, err, "audience check must reject even correctly-signed tokens")
}

// TestJWTMiddleware_RejectsForgedAudience verifies that signature
// verification still does its job: an attacker-crafted token with the
// correct audience but signed with an attacker key is rejected.
func TestJWTMiddleware_RejectsForgedAudience(t *testing.T) {
	e := echo.New()
	handler := JWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach here")
	})

	_, attackerKey, _ := ed25519.GenerateKey(nil)
	crafted := mintCustomToken(t, &Claims{
		Username: "mallory",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: []string{AudienceAPI},
		},
	}, attackerKey)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+crafted)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	assert.Error(t, err, "signature verification must reject attacker-signed tokens")
}

// TestRequireFullJWT_RejectsRequiresMFATrue verifies that even if a token
// somehow makes it past JWTMiddleware (e.g., hand-crafted with the full key
// but requires_mfa=true), RequireFullJWT catches it as defense in depth.
func TestRequireFullJWT_RejectsRequiresMFATrue(t *testing.T) {
	e := echo.New()

	// Compose the same stack as production protected groups:
	// JWTMiddleware -> RequireFullJWT -> handler
	handler := JWTMiddleware()(RequireFullJWT(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach here")
	}))

	// A token signed with the full key, carrying the correct audience, but
	// with requires_mfa=true. JWTMiddleware will accept this (signature OK,
	// audience OK); RequireFullJWT must reject it.
	crafted := mintCustomToken(t, &Claims{
		Username:    "alice",
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: []string{AudienceAPI},
		},
	}, GetJWTFullPrivateKey())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+crafted)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code, "RequireFullJWT must return 403 for requires_mfa=true")
}

// TestRequiresMFAFromToken_HandlesMissingClaims verifies that
// RequiresMFAFromToken must return false (not panic) when the context has
// no user, a nil user, or a non-Claims user value.
func TestRequiresMFAFromToken_HandlesMissingClaims(t *testing.T) {
	e := echo.New()

	t.Run("nil user", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		// Do not set "user" at all
		assert.NotPanics(t, func() {
			result := RequiresMFAFromToken(c)
			assert.False(t, result)
		})
	})

	t.Run("user set to nil pointer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		var nilToken *jwt.Token
		c.Set("user", nilToken)
		assert.NotPanics(t, func() {
			result := RequiresMFAFromToken(c)
			assert.False(t, result)
		})
	})

	t.Run("user with non-Claims claim type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		// Standard jwt.MapClaims instead of our *Claims
		tok := &jwt.Token{Claims: jwt.MapClaims{"username": "bob"}}
		c.Set("user", tok)
		assert.NotPanics(t, func() {
			result := RequiresMFAFromToken(c)
			assert.False(t, result)
		})
	})

	t.Run("user with valid *Claims requires_mfa=true", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		tok := &jwt.Token{Claims: &Claims{RequiresMFA: true}}
		c.Set("user", tok)
		assert.True(t, RequiresMFAFromToken(c))
	})

	t.Run("user with valid *Claims requires_mfa=false", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		tok := &jwt.Token{Claims: &Claims{RequiresMFA: false}}
		c.Set("user", tok)
		assert.False(t, RequiresMFAFromToken(c))
	})
}

func TestResetJWTMiddleware_AcceptsResetAudience(t *testing.T) {
	e := echo.New()
	handler := ResetJWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	resetToken, _, err := GenerateTemporaryResetToken("alice")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/mfa/reset", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+resetToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = handler(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestResetJWTMiddleware_RejectsMFAAudience(t *testing.T) {
	e := echo.New()
	handler := ResetJWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach")
	})

	mfaToken, _, err := GenerateTemporaryMFAToken("alice")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/mfa/reset", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+mfaToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = handler(c)
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestReregistrationJWTMiddleware_AcceptsReregistrationAudience(t *testing.T) {
	e := echo.New()
	handler := ReregistrationJWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	token, _, err := GenerateReregistrationToken("alice12345")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/opaque/reregister/response", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	assert.NoError(t, handler(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestReregistrationJWTMiddleware_RejectsOtherAudiences(t *testing.T) {
	e := echo.New()
	handler := ReregistrationJWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach")
	})

	// A reset-tier token (different audience, same signing key) must be rejected.
	resetToken, _, err := GenerateTemporaryResetToken("alice12345")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/opaque/reregister/response", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+resetToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = handler(c)
	assert.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestGenerateReregistrationToken_ClaimsShape(t *testing.T) {
	token, expiresAt, err := GenerateReregistrationToken("alice12345")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	// 15-minute lifetime, within a generous tolerance.
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), expiresAt, time.Minute)
}

func TestMFAResetJWTMiddleware_AcceptsResetAndFullTokens(t *testing.T) {
	e := echo.New()
	handler := MFAResetJWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	t.Run("reset-tier", func(t *testing.T) {
		resetToken, _, err := GenerateTemporaryResetToken("alice")
		assert.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/mfa/reset", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+resetToken)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		assert.NoError(t, handler(c))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("full-tier", func(t *testing.T) {
		fullToken := mintFullToken(t, "alice", time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/api/mfa/reset", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+fullToken)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		assert.NoError(t, handler(c))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestMFAResetJWTMiddleware_RejectsTempMFAAudience(t *testing.T) {
	e := echo.New()
	handler := MFAResetJWTMiddleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach")
	})

	mfaToken, _, err := GenerateTemporaryMFAToken("alice")
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/mfa/reset", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+mfaToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = handler(c)
	assert.Error(t, err)
}
