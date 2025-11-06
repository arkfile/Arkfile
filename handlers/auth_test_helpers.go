package handlers

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/84adam/Arkfile/storage"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
)

// setupTestEnv creates a test environment with Echo context, response recorder, mock DB, and mock storage
func setupTestEnv(t *testing.T, method, path string, body io.Reader) (echo.Context, *httptest.ResponseRecorder, sqlmock.Sqlmock, *storage.MockObjectStorageProvider) {
	e := echo.New()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create mock storage
	mockStorage := &storage.MockObjectStorageProvider{}

	return c, rec, mock, mockStorage
}

// TestOPAQUEProvider implements auth.OPAQUEProvider for testing
// This allows us to test OPAQUE handler logic without requiring CGO libraries
type TestOPAQUEProvider struct {
	available  bool
	serverKeys *TestServerKeys
}

// TestServerKeys holds mock server key material for testing
type TestServerKeys struct {
	publicKey  []byte // 32 bytes
	privateKey []byte // 32 bytes
}

// NewTestOPAQUEProvider creates a new test OPAQUE provider
func NewTestOPAQUEProvider() *TestOPAQUEProvider {
	return &TestOPAQUEProvider{
		available:  true,
		serverKeys: generateTestServerKeys(),
	}
}

// generateTestServerKeys creates deterministic but realistic server keys
func generateTestServerKeys() *TestServerKeys {
	// Use deterministic keys for test consistency
	// In real implementation, these would be generated securely
	publicKey := make([]byte, 32)
	privateKey := make([]byte, 32)

	// Generate deterministic keys based on fixed seed
	seed := "test-opaque-server-keys-for-arkfile-tests"
	hash := sha256.Sum256([]byte(seed))
	copy(privateKey, hash[:])

	// Derive public key from private key (simplified for testing)
	pubHash := sha256.Sum256(append(hash[:], []byte("public")...))
	copy(publicKey, pubHash[:])

	return &TestServerKeys{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// RegisterUser implements auth.OPAQUEProvider.RegisterUser for testing
func (t *TestOPAQUEProvider) RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
	if !t.available {
		return nil, nil, fmt.Errorf("test OPAQUE provider not available")
	}

	// Generate deterministic but realistic user record and export key
	userRecord := generateTestUserRecord(password)
	exportKey := generateTestExportKey(password)

	return userRecord, exportKey, nil
}

// AuthenticateUser implements auth.OPAQUEProvider.AuthenticateUser for testing
func (t *TestOPAQUEProvider) AuthenticateUser(password []byte, userRecord []byte) ([]byte, error) {
	if !t.available {
		return nil, fmt.Errorf("test OPAQUE provider not available")
	}

	// Validate that the user record matches what we would have generated
	expectedRecord := generateTestUserRecord(password)
	if len(userRecord) != len(expectedRecord) {
		return nil, fmt.Errorf("invalid user record format")
	}

	// Generate export key that matches registration
	exportKey := generateTestExportKey(password)

	return exportKey, nil
}

// IsAvailable implements auth.OPAQUEProvider.IsAvailable for testing
func (t *TestOPAQUEProvider) IsAvailable() bool {
	return t.available
}

// GetServerKeys implements auth.OPAQUEProvider.GetServerKeys for testing
func (t *TestOPAQUEProvider) GetServerKeys() ([]byte, []byte, error) {
	if !t.available {
		return nil, nil, fmt.Errorf("test OPAQUE provider not available")
	}

	if t.serverKeys == nil {
		return nil, nil, fmt.Errorf("server keys not initialized")
	}

	return t.serverKeys.publicKey, t.serverKeys.privateKey, nil
}

// generateTestUserRecord creates a deterministic user record for testing
func generateTestUserRecord(password []byte) []byte {
	// In real OPAQUE, this would be the output of the registration protocol
	// For testing, we create a deterministic record based on the password
	hash := sha256.Sum256(append([]byte("user-record:"), password...))
	record := make([]byte, 192) // Typical OPAQUE record size
	copy(record, hash[:])
	return record
}

// generateTestExportKey creates a deterministic export key for testing
func generateTestExportKey(password []byte) []byte {
	// In real OPAQUE, this would be derived during the protocol
	// For testing, we create a deterministic key based on the password
	hash := sha256.Sum256(append([]byte("export-key:"), password...))
	return hash[:]
}
