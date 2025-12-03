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
	// --- Test Config Setup ---
	config.ResetConfigForTest()

	// Setup in-memory SQLite DB for KeyManager
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		fmt.Printf("FATAL: Failed to open in-memory DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create system_keys table
	_, err = db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
		"STORAGE_PROVIDER":           "local",          // Set storage provider to local (supports MinIO)
		"MINIO_ROOT_USER":            "test-user-auth", // Provide dummy values for all required fields
		"MINIO_ROOT_PASSWORD":        "test-password-auth",
		"LOCAL_STORAGE_PATH":         "/tmp/test-storage-auth", // Required for local storage
		"JWT_TOKEN_LIFETIME_MINUTES": "1440",                   // Set to 24 hours for tests
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

	// --- Cleanup ---
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

func TestGenerateToken(t *testing.T) {
	// Config with JWT_SECRET is loaded in TestMain

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
			// Execute
			tokenString, _, err := GenerateToken(tc.username)

			// Assert: Check for errors and non-empty token
			assert.NoError(t, err)
			assert.NotEmpty(t, tokenString)

			// Assert: Verify token structure and claims
			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				// Validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
					return nil, jwt.ErrSignatureInvalid // Use standard error
				}
				// Validate using the Ed25519 public key
				return GetJWTPublicKey(), nil
			})

			assert.NoError(t, err)
			assert.True(t, token.Valid, "Token should be valid")

			claims, ok := token.Claims.(*Claims)
			assert.True(t, ok, "Claims should be of type *Claims")
			assert.Equal(t, tc.username, claims.Username, "Username claim should match")
			assert.Equal(t, "arkfile-auth", claims.Issuer, "Issuer claim should be correct")
			assert.Contains(t, claims.Audience, "arkfile-api", "Audience claim should contain 'arkfile-api'")
			assert.NotEmpty(t, claims.ID, "ID (jti) claim should not be empty")

			// Assert: Verify expiry time is approximately correct
			expectedExpiry := time.Now().Add(24 * time.Hour)
			// Allow a small delta (e.g., 5 seconds) for timing differences
			assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 5*time.Second, "Expiry time should be around 24 hours")
			assert.True(t, claims.IssuedAt.Time.Before(time.Now().Add(time.Second)), "Issue time should be in the past")
			assert.True(t, claims.NotBefore.Time.Before(time.Now().Add(time.Second)), "NotBefore time should be in the past")
		})
	}
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

func TestJWTMiddleware(t *testing.T) {
	// Config with JWT_SECRET is loaded in TestMain

	// Setup: Create Echo instance and test handler
	e := echo.New()
	mockHandler := func(c echo.Context) error {
		// We can verify the claims are set correctly by the middleware
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*Claims)
		assert.Equal(t, "test.user.2024", claims.Username)
		return c.String(http.StatusOK, "test passed")
	}

	// Setup: Get the middleware function
	middlewareFunc := JWTMiddleware()
	handlerWithMiddleware := middlewareFunc(mockHandler)

	// Test cases
	testCases := []struct {
		name           string
		tokenFunc      func() string // Function to generate token for the test
		expectedStatus int
		expectBody     string
		expectError    bool
	}{
		{
			name: "Valid Token",
			tokenFunc: func() string {
				claims := &Claims{
					Username: "test.user.2024",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
						ID:        "valid-token-id",
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
				// Sign with the Ed25519 private key
				tokenString, _ := token.SignedString(GetJWTPrivateKey())
				return tokenString
			},
			expectedStatus: http.StatusOK,
			expectBody:     "test passed",
			expectError:    false,
		},
		{
			name: "Expired Token",
			tokenFunc: func() string {
				claims := &Claims{
					Username: "test.user.expired",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
						ID:        "expired-token-id",
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
				// Sign with the Ed25519 private key
				tokenString, _ := token.SignedString(GetJWTPrivateKey())
				return tokenString
			},
			expectedStatus: http.StatusUnauthorized,
			expectBody:     "",
			expectError:    true, // Middleware should return an error
		},
		{
			name: "Invalid Signature",
			tokenFunc: func() string {
				// Generate a different Ed25519 key pair for wrong signature
				_, wrongPrivateKey, _ := ed25519.GenerateKey(nil)
				claims := &Claims{
					Username: "test.user.invalid",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
				tokenString, _ := token.SignedString(wrongPrivateKey) // Sign with wrong key
				return tokenString
			},
			expectedStatus: http.StatusUnauthorized,
			expectBody:     "",
			expectError:    true,
		},
		{
			name: "No Token",
			tokenFunc: func() string {
				return "" // No token provided
			},
			expectedStatus: http.StatusUnauthorized, // Assuming default behavior if no token
			expectBody:     "",
			expectError:    true, // Middleware should error if no token but expected
		},
		{
			name: "Malformed Token",
			tokenFunc: func() string {
				return "this.is.not.a.jwt"
			},
			expectedStatus: http.StatusUnauthorized,
			expectBody:     "",
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup request and recorder for this test case
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tokenString := tc.tokenFunc()
			if tokenString != "" {
				req.Header.Set(echo.HeaderAuthorization, "Bearer "+tokenString)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Execute the handler with middleware
			err := handlerWithMiddleware(c)

			// Assert: Check error expectation
			if tc.expectError {
				assert.Error(t, err, "Expected an error for "+tc.name)
				// Check if it's an HTTPError and the status code matches
				httpErr, ok := err.(*echo.HTTPError)
				assert.True(t, ok, "Error should be an echo.HTTPError")
				assert.Equal(t, tc.expectedStatus, httpErr.Code, "HTTP status code should match expected")
			} else {
				assert.NoError(t, err, "Did not expect an error for "+tc.name)
				assert.Equal(t, tc.expectedStatus, rec.Code, "HTTP status code should match expected")
				if tc.expectBody != "" {
					assert.Equal(t, tc.expectBody, rec.Body.String(), "Response body should match expected")
				}
			}
		})
	}
}
