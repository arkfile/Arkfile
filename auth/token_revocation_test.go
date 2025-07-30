package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
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
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to open in-memory SQLite DB")

	// Enable foreign key support if needed by your schema, though not strictly required for this table
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	require.NoError(t, err)

	// Create revoked_tokens table
	schema := `
	CREATE TABLE revoked_tokens (
		token_id TEXT PRIMARY KEY,
		user_email TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		reason TEXT,
		revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err, "Failed to create revoked_tokens table")

	// Reset cache for each test setup
	resetCache()

	return db
}

// resetCache clears the global revocation cache and resets its state.
func resetCache() {
	cacheMutex.Lock()
	revokedTokensCache = make(map[string]bool)
	cacheInitialized = false
	cacheMutex.Unlock()
}

// createTestToken generates a JWT string for testing revocation.
func createTestToken(t *testing.T, email, tokenID string, expiry time.Time) string {
	claims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			ID:        tokenID,
			Issuer:    "arkfile-auth",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := []byte(os.Getenv("JWT_SECRET")) // Assumes JWT_SECRET is set, needs setup
	tokenString, err := token.SignedString(secret)
	require.NoError(t, err)
	return tokenString
}

func TestRevokeToken(t *testing.T) {
	// Setup DB and JWT secret
	db := setupTestDB(t)
	defer db.Close()
	originalSecret := os.Getenv("JWT_SECRET")
	os.Setenv("JWT_SECRET", "test-revocation-secret")
	defer os.Setenv("JWT_SECRET", originalSecret)

	tokenID := "test-jti-1"
	email := "revoke@example.com"
	expiry := time.Now().Add(1 * time.Hour)
	tokenString := createTestToken(t, email, tokenID, expiry)

	// Execute RevokeToken
	err := RevokeToken(db, tokenString, "User logout")

	// Assert: No error during revocation
	assert.NoError(t, err)

	// Assert: Token ID should be in the database
	var dbTokenID string
	var dbUserEmail string
	err = db.QueryRow("SELECT token_id, user_email FROM revoked_tokens WHERE token_id = ?", tokenID).Scan(&dbTokenID, &dbUserEmail)
	assert.NoError(t, err, "Token should exist in DB after revocation")
	assert.Equal(t, tokenID, dbTokenID)
	assert.Equal(t, email, dbUserEmail)

	// Assert: Token ID should be in the cache
	cacheMutex.RLock()
	_, existsInCache := revokedTokensCache[tokenID]
	cacheMutex.RUnlock()
	assert.True(t, existsInCache, "Token should exist in cache after revocation")

	// Test case: Token without JTI
	claimsNoJTI := &Claims{
		Email:            email,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiry)}, // No ID
	}
	tokenNoJTI := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsNoJTI)
	tokenStringNoJTI, _ := tokenNoJTI.SignedString([]byte("test-revocation-secret"))
	err = RevokeToken(db, tokenStringNoJTI, "test")
	assert.Error(t, err, "Should error when token has no JTI")
	assert.Contains(t, err.Error(), "token has no ID", "Error message should mention missing JTI")
}

func TestIsRevoked(t *testing.T) {
	// Setup DB and JWT secret
	db := setupTestDB(t)
	defer db.Close()
	originalSecret := os.Getenv("JWT_SECRET")
	os.Setenv("JWT_SECRET", "test-revocation-secret")
	defer os.Setenv("JWT_SECRET", originalSecret)

	revokedTokenID := "revoked-jti"
	validTokenID := "valid-jti"
	email := "isrevoked@example.com"
	expiry := time.Now().Add(1 * time.Hour)
	revokedTokenString := createTestToken(t, email, revokedTokenID, expiry)

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
	_, err := db.Exec("INSERT INTO revoked_tokens (token_id, user_email, expires_at) VALUES (?, ?, ?)",
		expiredTokenID, "test@example.com", time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO revoked_tokens (token_id, user_email, expires_at) VALUES (?, ?, ?)",
		activeTokenID, "test@example.com", time.Now().Add(1*time.Hour))
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
	_, err := db.Exec("INSERT INTO revoked_tokens (token_id, user_email, expires_at) VALUES (?, ?, ?)",
		expiredTokenID, "test@example.com", time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO revoked_tokens (token_id, user_email, expires_at) VALUES (?, ?, ?)",
		activeTokenID, "test@example.com", time.Now().Add(1*time.Hour))
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
	// Setup DB and JWT secret
	db := setupTestDB(t)
	defer db.Close()
	originalSecret := os.Getenv("JWT_SECRET")
	os.Setenv("JWT_SECRET", "test-middleware-secret")
	defer os.Setenv("JWT_SECRET", originalSecret)

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
	// tokenNoJTI_ID := "token-without-jti" // Unused variable removed
	email := "middleware@example.com"
	expiry := time.Now().Add(1 * time.Hour)

	validTokenString := createTestToken(t, email, validTokenID, expiry)
	revokedTokenString := createTestToken(t, email, revokedTokenID, expiry)
	// Token without JTI (ID claim)
	claimsNoJTI := &Claims{Email: email, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiry)}}
	tokenNoJTI := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsNoJTI)
	tokenStringNoJTI, _ := tokenNoJTI.SignedString([]byte("test-middleware-secret"))

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
			expectedStatus: http.StatusOK, // Should proceed if no JTI
			expectError:    false,
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
