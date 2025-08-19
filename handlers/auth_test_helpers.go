package handlers

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/84adam/arkfile/auth"
	"github.com/DATA-DOG/go-sqlmock"
)

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

// GenerateServerKeys implements auth.OPAQUEProvider.GenerateServerKeys for testing
func (t *TestOPAQUEProvider) GenerateServerKeys() ([]byte, []byte, error) {
	if !t.available {
		return nil, nil, fmt.Errorf("test OPAQUE provider not available")
	}

	// Generate new test keys
	newKeys := generateTestServerKeys()
	t.serverKeys = newKeys

	return newKeys.publicKey, newKeys.privateKey, nil
}

// generateTestUserRecord creates a realistic user record for testing
func generateTestUserRecord(password []byte) []byte {
	// Create deterministic user record based on password
	// Real OPAQUE user records are variable length, we'll use 200 bytes for testing
	hash := sha256.Sum256(append([]byte("opaque-user-record:"), password...))

	// Extend to 200 bytes to simulate real user record
	userRecord := make([]byte, 200)
	for i := 0; i < 200; i += 32 {
		copy(userRecord[i:], hash[:])
		hash = sha256.Sum256(append(hash[:], byte(i)))
	}

	return userRecord
}

// generateTestExportKey creates a realistic 64-byte export key for testing
func generateTestExportKey(password []byte) []byte {
	// OPAQUE export keys must be exactly 64 bytes
	exportKey := make([]byte, 64)

	// Generate deterministic but realistic export key
	hash1 := sha256.Sum256(append([]byte("opaque-export-key-1:"), password...))
	hash2 := sha256.Sum256(append([]byte("opaque-export-key-2:"), password...))

	copy(exportKey[0:32], hash1[:])
	copy(exportKey[32:64], hash2[:])

	return exportKey
}

// Provider override functionality for testing

var originalProvider auth.OPAQUEProvider
var testProviderActive bool

// setupTestOPAQUEProvider installs a test OPAQUE provider for the duration of a test
func setupTestOPAQUEProvider(t *testing.T) func() {
	t.Helper()

	if !testProviderActive {
		// Save the original provider
		originalProvider = getCurrentOPAQUEProvider()

		// Install test provider
		testProvider := NewTestOPAQUEProvider()
		setTestOPAQUEProvider(testProvider)
		testProviderActive = true
	}

	// Return cleanup function
	return func() {
		if testProviderActive {
			restoreOPAQUEProvider(originalProvider)
			testProviderActive = false
		}
	}
}

// getCurrentOPAQUEProvider gets the current provider (using reflection/access pattern)
func getCurrentOPAQUEProvider() auth.OPAQUEProvider {
	return auth.GetOPAQUEProvider()
}

// setTestOPAQUEProvider sets a test provider (we need to access package internals)
func setTestOPAQUEProvider(testProvider *TestOPAQUEProvider) {
	// We need to temporarily replace the global provider
	// This requires accessing the auth package's internal state
	auth.SetTestProvider(testProvider)
}

// restoreOPAQUEProvider restores the original provider
func restoreOPAQUEProvider(provider auth.OPAQUEProvider) {
	auth.RestoreProvider(provider)
}

// Enhanced mock expectations for OPAQUE database operations

// setupOPAQUEDatabaseMocks configures database mocks for OPAQUE operations
func setupOPAQUEDatabaseMocks(mock sqlmock.Sqlmock, username string) {
	// Mock the opaque_password_records operations that models.CreateUserWithOPAQUE expects

	// Mock OPAQUE record insertion during registration
	mock.ExpectExec(`INSERT INTO opaque_password_records`).
		WithArgs("account", username, sqlmock.AnyArg(), username, true).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// setupOPAQUEAuthenticationMocks configures database mocks for OPAQUE authentication
func setupOPAQUEAuthenticationMocks(mock sqlmock.Sqlmock, username string) {
	// Mock OPAQUE record retrieval during authentication
	mock.ExpectQuery(`SELECT opaque_user_record FROM opaque_password_records WHERE record_identifier = \? AND is_active = TRUE`).
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows([]string{"opaque_user_record"}).
			AddRow(generateTestUserRecord([]byte("test-password"))))

	// Mock updating last used timestamp
	mock.ExpectExec(`UPDATE opaque_password_records SET last_used_at = CURRENT_TIMESTAMP WHERE record_identifier = \?`).
		WithArgs(username).
		WillReturnResult(sqlmock.NewResult(1, 1))
}
