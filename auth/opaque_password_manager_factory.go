//go:build !mock
// +build !mock

package auth

import (
	"database/sql"
)

// GetOPAQUEPasswordManager returns the real password manager implementation
func GetOPAQUEPasswordManager() OPAQUEPasswordManagerInterface {
	return NewOPAQUEPasswordManager()
}

// GetOPAQUEPasswordManagerWithDB returns the real password manager implementation with database
func GetOPAQUEPasswordManagerWithDB(db *sql.DB) OPAQUEPasswordManagerInterface {
	return NewOPAQUEPasswordManagerWithDB(db)
}
