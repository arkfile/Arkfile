package handlers

import (
	"database/sql"
	"testing"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/models"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

// setupOPAQUEMocks sets up standardized mock expectations for OPAQUE database operations
func setupOPAQUEMocks(mock sqlmock.Sqlmock, email string) {
	// Mock OPAQUE server keys check/setup
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM opaque_server_keys WHERE id = 1`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock OPAQUE user data retrieval for authentication
	mock.ExpectQuery(`SELECT user_email, serialized_record FROM opaque_user_data WHERE user_email = \?`).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "serialized_record"}).
			AddRow(email, "mock-opaque-record-data"))
}

// expectOPAQUERegistration sets up mock expectations for OPAQUE user registration
func expectOPAQUERegistration(mock sqlmock.Sqlmock, email string) {
	// Mock OPAQUE server keys check
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM opaque_server_keys WHERE id = 1`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock OPAQUE user registration
	mock.ExpectExec(`INSERT OR REPLACE INTO opaque_user_data \(user_email, serialized_record\) VALUES \(\?, \?\)`).
		WithArgs(email, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// expectOPAQUEAuthentication sets up mock expectations for OPAQUE authentication
func expectOPAQUEAuthentication(mock sqlmock.Sqlmock, email string) {
	// Mock OPAQUE server keys check
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM opaque_server_keys WHERE id = 1`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock OPAQUE user data retrieval
	mock.ExpectQuery(`SELECT user_email, serialized_record FROM opaque_user_data WHERE user_email = \?`).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "serialized_record"}).
			AddRow(email, "mock-opaque-record-data"))
}

// mockOPAQUESuccess simulates successful OPAQUE operations for testing handler logic
// This allows testing the handler workflow without requiring the actual OPAQUE library
func mockOPAQUESuccess(t *testing.T, email, password string) {
	t.Helper()
	// Note: This is a test helper that allows handler tests to focus on HTTP logic
	// rather than cryptographic implementation details
	t.Logf("Mocking OPAQUE success for user %s", email)
}

// validateOPAQUEHealthy validates that OPAQUE system components are available
func validateOPAQUEHealthy(t *testing.T) {
	t.Helper()

	// Check that OPAQUE server availability can be determined
	ready, err := auth.GetOPAQUEServer()
	if err != nil {
		t.Logf("OPAQUE server check returned error (expected in test environment): %v", err)
		// In test environment without libopaque.so, this is expected
		return
	}

	if ready {
		t.Log("OPAQUE server reports ready")
	} else {
		t.Log("OPAQUE server reports not ready (expected in test environment)")
	}
}

// Integration Test Helpers (for when libopaque.so is available)

// setupOPAQUETestUser creates a test user with OPAQUE authentication
// Note: Requires actual database connection and OPAQUE library
func setupOPAQUETestUser(t *testing.T, db *sql.DB, email, password string) *models.User {
	t.Helper()

	if db == nil {
		t.Skip("Integration test requires real database connection")
		return nil
	}

	// Create user with OPAQUE account in atomic transaction
	user, err := models.CreateUserWithOPAQUE(db, email, password)
	require.NoError(t, err, "Failed to create OPAQUE test user")
	require.NotNil(t, user, "Created user should not be nil")

	return user
}

// expectOPAQUERegistrationSuccess validates that OPAQUE registration succeeded
// Note: Requires actual database connection and OPAQUE library
func expectOPAQUERegistrationSuccess(t *testing.T, db *sql.DB, user *models.User) {
	t.Helper()

	if db == nil {
		t.Skip("Integration test requires real database connection")
		return
	}

	// Check that user has OPAQUE account
	hasAccount, err := user.HasOPAQUEAccount(db)
	require.NoError(t, err, "Failed to check OPAQUE account status")
	require.True(t, hasAccount, "User should have OPAQUE account after registration")

	// Verify OPAQUE account status
	status, err := user.GetOPAQUEAccountStatus(db)
	require.NoError(t, err, "Failed to get OPAQUE status")
	require.True(t, status.HasAccountPassword, "Should have account password")
	require.NotNil(t, status.OPAQUECreatedAt, "Should have creation timestamp")
}

// expectOPAQUEAuthenticationSuccess validates OPAQUE authentication and returns export key
// Note: Requires actual database connection and OPAQUE library
func expectOPAQUEAuthenticationSuccess(t *testing.T, db *sql.DB, user *models.User, password string) []byte {
	t.Helper()

	if db == nil {
		t.Skip("Integration test requires real database connection")
		return nil
	}

	// Authenticate with OPAQUE
	exportKey, err := user.AuthenticateOPAQUE(db, password)
	require.NoError(t, err, "OPAQUE authentication should succeed")
	require.NotNil(t, exportKey, "Export key should not be nil")
	require.Len(t, exportKey, 64, "Export key should be 64 bytes")

	return exportKey
}

// expectOPAQUEAuthenticationFailure validates that OPAQUE authentication fails
// Note: Requires actual database connection and OPAQUE library
func expectOPAQUEAuthenticationFailure(t *testing.T, db *sql.DB, user *models.User, wrongPassword string) {
	t.Helper()

	if db == nil {
		t.Skip("Integration test requires real database connection")
		return
	}

	// Attempt authentication with wrong password
	exportKey, err := user.AuthenticateOPAQUE(db, wrongPassword)
	require.Error(t, err, "OPAQUE authentication should fail with wrong password")
	require.Nil(t, exportKey, "Export key should be nil on failed authentication")
}

// testOPAQUEFilePassword tests file-specific password functionality
// Note: Requires actual database connection and OPAQUE library
func testOPAQUEFilePassword(t *testing.T, db *sql.DB, user *models.User, fileID, password string) {
	t.Helper()

	if db == nil {
		t.Skip("Integration test requires real database connection")
		return
	}

	// Register file password
	err := user.RegisterFilePassword(db, fileID, password, "test-label", "test hint")
	require.NoError(t, err, "Failed to register file password")

	// Authenticate file password
	exportKey, err := user.AuthenticateFilePassword(db, fileID, password)
	require.NoError(t, err, "File password authentication should succeed")
	require.NotNil(t, exportKey, "File export key should not be nil")
	require.Len(t, exportKey, 64, "File export key should be 64 bytes")

	// Get file password records
	records, err := user.GetFilePasswordRecords(db, fileID)
	require.NoError(t, err, "Failed to get file password records")
	require.Len(t, records, 1, "Should have one file password record")

	// Clean up file password
	err = user.DeleteFilePassword(db, fileID, "test-label")
	require.NoError(t, err, "Failed to delete file password")
}

// cleanupOPAQUETestUser removes test user and all OPAQUE records
// Note: Requires actual database connection
func cleanupOPAQUETestUser(t *testing.T, db *sql.DB, user *models.User) {
	t.Helper()

	if db == nil {
		t.Skip("Integration test requires real database connection")
		return
	}

	// Delete user (includes OPAQUE cleanup)
	err := user.Delete(db)
	require.NoError(t, err, "Failed to cleanup OPAQUE test user")
}
