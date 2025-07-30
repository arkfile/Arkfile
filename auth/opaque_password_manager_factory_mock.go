//go:build mock
// +build mock

package auth

import (
	"database/sql"
)

// GetOPAQUEPasswordManager returns the mock password manager implementation for testing
func GetOPAQUEPasswordManager() OPAQUEPasswordManagerInterface {
	return NewMockOPAQUEPasswordManager()
}

// GetOPAQUEPasswordManagerWithDB returns the mock password manager implementation for testing
// Note: The mock implementation ignores the database parameter and uses in-memory storage
func GetOPAQUEPasswordManagerWithDB(db *sql.DB) OPAQUEPasswordManagerInterface {
	return NewMockOPAQUEPasswordManager()
}
