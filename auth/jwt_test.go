package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/84adam/Arkfile/config" // Import config
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// createTestJWTKeys creates Ed25519 keys for testing
func createTestJWTKeys() error {
	// Create test key directory
	keyDir := "/tmp/test-arkfile-keys/jwt/current"
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create test key directory: %w", err)
	}

	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// Marshal private key to PKCS8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Marshal public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create PEM blocks
	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Write private key
	privateKeyFile := filepath.Join(keyDir, "signing.key")
	privateFile, err := os.Create(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateFile.Close()

	if err := pem.Encode(privateFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key PEM: %w", err)
	}

	// Write public key
	publicKeyFile := filepath.Join(keyDir, "public.key")
	publicFile, err := os.Create(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicFile.Close()

	if err := pem.Encode(publicFile, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to encode public key PEM: %w", err)
	}

	// Set environment variables to point to test keys
	os.Setenv("JWT_PRIVATE_KEY_PATH", privateKeyFile)
	os.Setenv("JWT_PUBLIC_KEY_PATH", publicKeyFile)

	return nil
}

// cleanupTestJWTKeys removes test keys and directories
func cleanupTestJWTKeys() {
	os.RemoveAll("/tmp/test-arkfile-keys")
	os.Unsetenv("JWT_PRIVATE_KEY_PATH")
	os.Unsetenv("JWT_PUBLIC_KEY_PATH")
}

// TestMain sets up necessary environment variables for config loading before running tests
// and cleans them up afterwards.
func TestMain(m *testing.M) {
	// --- Test Config Setup ---
	config.ResetConfigForTest()

	// Store original env vars and set test values
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"STORAGE_PROVIDER":           "local",          // Set storage provider to local (supports MinIO)
		"MINIO_ROOT_USER":            "test-user-auth", // Provide dummy values for all required fields
		"MINIO_ROOT_PASSWORD":        "test-password-auth",
		"LOCAL_STORAGE_PATH":         "/tmp/test-storage-auth", // Required for local storage
		"JWT_TOKEN_LIFETIME_MINUTES": "1440",                   // Set to 24 hours for tests
		// JWT keys will use default paths for test keys (created below)
	}

	for key, testValue := range testEnv {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, testValue)
	}

	// Create test Ed25519 keys for testing
	err := createTestJWTKeys()
	if err != nil {
		fmt.Printf("FATAL: Failed to create test JWT keys: %v\n", err)
		os.Exit(1)
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
	cleanupTestJWTKeys()
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
			tokenString, err := GenerateToken(tc.username)

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
