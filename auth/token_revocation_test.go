package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3" // SQLite driver for token revocation tests
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB creates an in-memory SQLite database for revocation tests
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to open in-memory SQLite DB")

	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	require.NoError(t, err)

	schema := `
	CREATE TABLE revoked_tokens (
		token_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		reason TEXT,
		revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE user_jwt_revocations (
		username TEXT PRIMARY KEY,
		revoked_at TIMESTAMP NOT NULL,
		reason TEXT
	);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err, "Failed to create tables")

	// Reset both caches for each test setup
	resetCache()
	resetUserRevocationCache()

	return db
}

// resetUserRevocationCache clears the user-wide revocation cache.
func resetUserRevocationCache() {
	userRevocationCacheMutex.Lock()
	userRevocationCache = make(map[string]userRevocationEntry)
	userRevocationCacheMutex.Unlock()
}

// resetCache clears the global revocation cache and resets its state.
func resetCache() {
	cacheMutex.Lock()
	revokedTokensCache = make(map[string]bool)
	cacheInitialized = false
	cacheMutex.Unlock()
}

// createTestToken generates a full-tier JWT string for testing revocation.
// Signed with the full-tier Ed25519 private key, audience=arkfile-api.
func createTestToken(t *testing.T, username, tokenID string, expiry time.Time) string {
	return createTestTokenWithTier(t, username, tokenID, expiry, false /* tempTier */)
}

// createTestTokenWithTier generates a JWT for revocation tests, choosing
// either the temp-tier or full-tier signing key. Used to exercise the
// two-tier revocation path (parseEitherTierToken).
func createTestTokenWithTier(t *testing.T, username, tokenID string, expiry time.Time, tempTier bool) string {
	audience := AudienceAPI
	requiresTOTP := false
	if tempTier {
		audience = AudienceMFA
		requiresTOTP = true
	}
	claims := &Claims{
		Username:     username,
		RequiresMFA: requiresTOTP,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			ID:        tokenID,
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Audience:  []string{audience},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	var signer interface{}
	if tempTier {
		signer = GetJWTTempPrivateKey()
	} else {
		signer = GetJWTFullPrivateKey()
	}
	tokenString, err := token.SignedString(signer)
	require.NoError(t, err)
	return tokenString
}

func TestRevokeToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tokenID := "test-jti-1"
	username := "revoke_user"
	expiry := time.Now().Add(1 * time.Hour)
	tokenString := createTestToken(t, username, tokenID, expiry)

	// Execute RevokeToken
	err := RevokeToken(db, tokenString, "User logout")

	// Assert: No error during revocation
	assert.NoError(t, err)

	// Assert: Token ID should be in the database
	var dbTokenID string
	var dbUsername string
	err = db.QueryRow("SELECT token_id, username FROM revoked_tokens WHERE token_id = ?", tokenID).Scan(&dbTokenID, &dbUsername)
	assert.NoError(t, err, "Token should exist in DB after revocation")
	assert.Equal(t, tokenID, dbTokenID)
	assert.Equal(t, username, dbUsername)

	// Assert: Token ID should be in the cache
	cacheMutex.RLock()
	_, existsInCache := revokedTokensCache[tokenID]
	cacheMutex.RUnlock()
	assert.True(t, existsInCache, "Token should exist in cache after revocation")

	// Test case: Token without JTI
	claimsNoJTI := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			Audience:  []string{AudienceAPI},
		}, // No ID
	}
	tokenNoJTI := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claimsNoJTI)
	tokenStringNoJTI, _ := tokenNoJTI.SignedString(GetJWTFullPrivateKey())
	err = RevokeToken(db, tokenStringNoJTI, "test")
	assert.Error(t, err, "Should error when token has no JTI")
	assert.Contains(t, err.Error(), "token has no ID", "Error message should mention missing JTI")
}

// TestRevokeToken_BothTiers verifies that RevokeToken accepts both temp-tier
// and full-tier tokens. This is required so logout / force-revoke works for
// users at any session stage.
func TestRevokeToken_BothTiers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	username := "twotier_user"
	expiry := time.Now().Add(1 * time.Hour)

	tempTokenID := "temp-jti"
	fullTokenID := "full-jti"

	tempToken := createTestTokenWithTier(t, username, tempTokenID, expiry, true)
	fullToken := createTestTokenWithTier(t, username, fullTokenID, expiry, false)

	// Both must revoke successfully.
	assert.NoError(t, RevokeToken(db, tempToken, "logout temp"))
	assert.NoError(t, RevokeToken(db, fullToken, "logout full"))

	// Both must appear independently in the revoked_tokens table.
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE username = ?", username).Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 2, count, "both tiers' jti must be revoked independently")

	// Cross-tier negative: revoking a temp jti must NOT affect a full jti.
	revokedFull, err := IsRevoked(db, fullTokenID)
	assert.NoError(t, err)
	assert.True(t, revokedFull, "full jti is revoked")

	revokedTemp, err := IsRevoked(db, tempTokenID)
	assert.NoError(t, err)
	assert.True(t, revokedTemp, "temp jti is revoked")

	// A fresh jti not in the table must remain unrevoked.
	revokedUnknown, err := IsRevoked(db, "fresh-jti")
	assert.NoError(t, err)
	assert.False(t, revokedUnknown)
}

func TestIsRevoked(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	revokedTokenID := "revoked-jti"
	validTokenID := "valid-jti"
	username := "isrevoked_user"
	expiry := time.Now().Add(1 * time.Hour)
	revokedTokenString := createTestToken(t, username, revokedTokenID, expiry)

	// Revoke one token directly via function
	err := RevokeToken(db, revokedTokenString, "test revoking")
	require.NoError(t, err)

	// Test cases
	testCases := []struct {
		name          string
		tokenID       string
		expectRevoked bool
		setupCache    func() // Optional setup for cache state
	}{
		{
			name:          "Token is revoked (check DB + Cache Update)",
			tokenID:       revokedTokenID,
			expectRevoked: true,
		},
		{
			name:          "Token is not revoked",
			tokenID:       validTokenID,
			expectRevoked: false,
		},
		{
			name:          "Token revoked (check Cache first)",
			tokenID:       revokedTokenID,
			expectRevoked: true,
			setupCache: func() {
				// Ensure cache is pre-populated for this test case
				cacheMutex.Lock()
				revokedTokensCache[revokedTokenID] = true
				cacheInitialized = true
				cacheMutex.Unlock()
			},
		},
		{
			name:          "Token not revoked (check Cache first)",
			tokenID:       validTokenID,
			expectRevoked: false,
			setupCache: func() {
				// Ensure cache is initialized but doesn't contain the token
				cacheMutex.Lock()
				// revokedTokensCache[revokedTokenID] = true // Ensure validTokenID is NOT here
				cacheInitialized = true
				cacheMutex.Unlock()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupCache != nil {
				resetCache() // Reset before specific setup
				tc.setupCache()
			} else {
				resetCache() // Ensure clean cache state if no specific setup
			}

			// Execute IsRevoked
			isRevoked, err := IsRevoked(db, tc.tokenID)

			// Assert
			assert.NoError(t, err)
			assert.Equal(t, tc.expectRevoked, isRevoked)

			// Assert cache state after check
			cacheMutex.RLock()
			_, existsInCache := revokedTokensCache[tc.tokenID]
			cacheMutex.RUnlock()
			assert.Equal(t, tc.expectRevoked, existsInCache, "Cache state should reflect revocation status after check")
			assert.True(t, cacheInitialized, "Cache should be initialized after check")
		})
	}
}

func TestInitializeCache(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Add some tokens to DB: one expired, one active
	expiredTokenID := "expired-jti"
	activeTokenID := "active-jti"
	_, err := db.Exec("INSERT INTO revoked_tokens (token_id, username, expires_at) VALUES (?, ?, ?)",
		expiredTokenID, "test_username", time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO revoked_tokens (token_id, username, expires_at) VALUES (?, ?, ?)",
		activeTokenID, "test_username", time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	// Execute initializeCache
	err = initializeCache(db)
	assert.NoError(t, err)
	assert.True(t, cacheInitialized, "Cache should be marked as initialized")

	// Assert cache contents
	cacheMutex.RLock()
	_, existsExpired := revokedTokensCache[expiredTokenID]
	_, existsActive := revokedTokensCache[activeTokenID]
	cacheMutex.RUnlock()

	assert.False(t, existsExpired, "Expired token should not be loaded into cache")
	assert.True(t, existsActive, "Active token should be loaded into cache")
}

func TestCleanupExpiredTokens(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Add expired and active tokens
	expiredTokenID := "expired-to-clean-jti"
	activeTokenID := "active-to-keep-jti"
	_, err := db.Exec("INSERT INTO revoked_tokens (token_id, username, expires_at) VALUES (?, ?, ?)",
		expiredTokenID, "test_username", time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO revoked_tokens (token_id, username, expires_at) VALUES (?, ?, ?)",
		activeTokenID, "test_username", time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	// Populate cache (to test cache reset)
	err = initializeCache(db)
	require.NoError(t, err)

	// Execute CleanupExpiredTokens
	err = CleanupExpiredTokens(db)
	assert.NoError(t, err)

	// Assert DB state
	var countExpired, countActive int
	err = db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE token_id = ?", expiredTokenID).Scan(&countExpired)
	assert.NoError(t, err)
	assert.Equal(t, 0, countExpired, "Expired token should be deleted from DB")

	err = db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE token_id = ?", activeTokenID).Scan(&countActive)
	assert.NoError(t, err)
	assert.Equal(t, 1, countActive, "Active token should remain in DB")

	// Assert Cache state (should be reset)
	cacheMutex.RLock()
	assert.False(t, cacheInitialized, "Cache should be marked as not initialized after cleanup")
	assert.Empty(t, revokedTokensCache, "Cache map should be empty after cleanup")
	cacheMutex.RUnlock()
}

func TestTokenRevocationMiddleware(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Setup Echo and mock handler
	e := echo.New()
	mockHandler := func(c echo.Context) error {
		return c.String(http.StatusOK, "passed middleware")
	}
	middleware := TokenRevocationMiddleware(db)
	handlerWithMiddleware := middleware(mockHandler)

	// Tokens
	validTokenID := "valid-for-middleware"
	revokedTokenID := "revoked-for-middleware"
	username := "middleware_user"
	expiry := time.Now().Add(1 * time.Hour)

	validTokenString := createTestToken(t, username, validTokenID, expiry)
	revokedTokenString := createTestToken(t, username, revokedTokenID, expiry)
	// Token without JTI (ID claim) -- uses Ed25519 to match production
	claimsNoJTI := &Claims{Username: username, RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiry),
		Audience:  []string{AudienceAPI},
	}}
	tokenNoJTI := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claimsNoJTI)
	tokenStringNoJTI, _ := tokenNoJTI.SignedString(GetJWTFullPrivateKey())

	// Revoke the specific token
	err := RevokeToken(db, revokedTokenString, "testing middleware")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		tokenToProvide *jwt.Token // We set *jwt.Token directly in context for middleware tests
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid, non-revoked token",
			tokenToProvide: func() *jwt.Token {
				token, _, _ := new(jwt.Parser).ParseUnverified(validTokenString, &Claims{})
				return token
			}(),
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Revoked token",
			tokenToProvide: func() *jwt.Token {
				token, _, _ := new(jwt.Parser).ParseUnverified(revokedTokenString, &Claims{})
				return token
			}(),
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name:           "No token in context",
			tokenToProvide: nil,           // Simulate no token set by previous middleware
			expectedStatus: http.StatusOK, // Middleware should pass if no token is present
			expectError:    false,
		},
		{
			name: "Token without JTI claim",
			tokenToProvide: func() *jwt.Token {
				token, _, _ := new(jwt.Parser).ParseUnverified(tokenStringNoJTI, &Claims{})
				return token
			}(),
			expectedStatus: http.StatusUnauthorized, // Should fail closed if no JTI
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Set token in context (or not)
			if tc.tokenToProvide != nil {
				c.Set("user", tc.tokenToProvide)
			}

			// Execute middleware + handler
			err := handlerWithMiddleware(c)

			// Assert
			if tc.expectError {
				assert.Error(t, err)
				httpErr, ok := err.(*echo.HTTPError)
				assert.True(t, ok, "Expected echo.HTTPError for %s", tc.name)
				assert.Equal(t, tc.expectedStatus, httpErr.Code, "Status code mismatch for %s", tc.name)
			} else {
				assert.NoError(t, err, "Unexpected error for %s", tc.name)
				assert.Equal(t, tc.expectedStatus, rec.Code, "Status code mismatch for %s", tc.name)
				if tc.expectedStatus == http.StatusOK {
					assert.Equal(t, "passed middleware", rec.Body.String(), "Handler body mismatch for %s", tc.name)
				}
			}
		})
	}
}

// TestTokenRevocationMiddleware_UserWideRevocation verifies that user-wide revocation is enforced:
// after RevokeAllUserJWTs is written, a subsequent request with a JWT issued
// before the revocation is rejected without waiting for the JWT TTL to expire.
func TestTokenRevocationMiddleware_UserWideRevocation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	username := "user_wide_revoke_test"
	expiry := time.Now().Add(10 * time.Minute)
	issuedAt := time.Now()

	// Create a valid full-tier JWT.
	claims := &Claims{
		Username:     username,
		RequiresMFA: false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ID:        "user-wide-jti-1",
			Issuer:    Issuer,
			Audience:  []string{AudienceAPI},
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := jwtToken.SignedString(GetJWTFullPrivateKey())
	require.NoError(t, err)

	// Insert a user_jwt_revocations row for a time AFTER the JWT was issued.
	revokedAt := issuedAt.Add(1 * time.Second)
	_, err = db.Exec(
		`INSERT INTO user_jwt_revocations (username, revoked_at, reason) VALUES (?, ?, ?)`,
		username, revokedAt.Format(time.RFC3339), "test force-logout",
	)
	require.NoError(t, err)

	// Invalidate cache so the middleware reads fresh from DB.
	invalidateUserRevocationCache(username)

	// Set up middleware.
	e := echo.New()
	mockHandler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
	middleware := TokenRevocationMiddleware(db)
	handlerWithMiddleware := middleware(mockHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Inject the parsed (unverified for context-injection) token.
	parsedToken, _, _ := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	c.Set("user", parsedToken)

	err = handlerWithMiddleware(c)
	require.Error(t, err, "user-wide revocation should reject the JWT immediately")
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

// TestTokenRevocationMiddleware_JWTIssuedAfterRevocation verifies that a JWT
// issued AFTER a user-wide revocation is NOT blocked by it.
func TestTokenRevocationMiddleware_JWTIssuedAfterRevocation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	username := "after_revoke_user"
	expiry := time.Now().Add(10 * time.Minute)

	// Write a revocation that happened 5 seconds ago.
	revokedAt := time.Now().Add(-5 * time.Second)
	_, err := db.Exec(
		`INSERT INTO user_jwt_revocations (username, revoked_at, reason) VALUES (?, ?, ?)`,
		username, revokedAt.Format(time.RFC3339), "old revocation",
	)
	require.NoError(t, err)
	invalidateUserRevocationCache(username)

	// Issue a JWT with issuedAt = now (after the revocation).
	claims := &Claims{
		Username:     username,
		RequiresMFA: false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "post-revoke-jti",
			Issuer:    Issuer,
			Audience:  []string{AudienceAPI},
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := jwtToken.SignedString(GetJWTFullPrivateKey())
	require.NoError(t, err)

	e := echo.New()
	mockHandler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
	handlerWithMiddleware := TokenRevocationMiddleware(db)(mockHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	parsedToken, _, _ := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	c.Set("user", parsedToken)

	err = handlerWithMiddleware(c)
	assert.NoError(t, err, "JWT issued after revocation should not be blocked")
	assert.Equal(t, http.StatusOK, rec.Code)
}
