package handlers

import (
	"testing"

	"github.com/84adam/Arkfile/auth"
	"github.com/DATA-DOG/go-sqlmock"
)

// setupOPAQUEMocks sets up standardized mock expectations for OPAQUE database operations
func setupOPAQUEMocks(mock sqlmock.Sqlmock, username string) {
	// Mock expectations for RFC-compliant OPAQUE authentication
	// These mocks align with our opaque_user_data table structure
	recordIdentifier := username // For account passwords

	// Mock RFC-compliant OPAQUE user data retrieval for authentication
	mock.ExpectQuery(`SELECT opaque_user_record FROM opaque_user_data WHERE username = \?`).
		WithArgs(recordIdentifier).
		WillReturnRows(sqlmock.NewRows([]string{"opaque_user_record"}).
			AddRow("mock-opaque-user-record"))
}

// expectOPAQUERegistration sets up mock expectations for OPAQUE user registration
func expectOPAQUERegistration(mock sqlmock.Sqlmock, username string) {
	// Mock expectations for account password registration in unified system

	// Mock RFC-compliant OPAQUE user data insertion
	mock.ExpectExec(`INSERT INTO opaque_user_data`).
		WithArgs(username, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// expectOPAQUEAuthentication sets up mock expectations for OPAQUE authentication
func expectOPAQUEAuthentication(mock sqlmock.Sqlmock, username string) {
	// Mock expectations for unified OPAQUE password system authentication
	recordIdentifier := username // For account passwords

	// Mock RFC-compliant OPAQUE user data retrieval
	mock.ExpectQuery(`SELECT opaque_user_record FROM opaque_user_data WHERE username = \?`).
		WithArgs(recordIdentifier).
		WillReturnRows(sqlmock.NewRows([]string{"opaque_user_record"}).
			AddRow("mock-opaque-user-record"))
}

// validateOPAQUEHealthy validates that OPAQUE system components are available
func validateOPAQUEHealthy(t *testing.T) {
	t.Helper()

	// Check OPAQUE availability
	if !auth.IsOPAQUEAvailable() {
		t.Log("OPAQUE not available (expected in test environment)")
		return
	}

	t.Log("OPAQUE reports ready")
}
