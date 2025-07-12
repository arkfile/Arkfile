//go:build js && wasm

package auth

import (
	"database/sql"
	"fmt"
)

// WASM stub implementations for OPAQUE functions

// GetOPAQUEServer returns a stub for WASM builds
func GetOPAQUEServer() (bool, error) {
	return false, fmt.Errorf("OPAQUE not supported in WASM builds")
}

// ValidateOPAQUESetup returns a stub for WASM builds
func ValidateOPAQUESetup(db *sql.DB) error {
	return fmt.Errorf("OPAQUE not supported in WASM builds")
}

// RegisterUser returns a stub for WASM builds
func RegisterUser(db *sql.DB, email, password string) error {
	return fmt.Errorf("OPAQUE not supported in WASM builds")
}

// AuthenticateUser returns a stub for WASM builds
func AuthenticateUser(db *sql.DB, email, password string) ([]byte, error) {
	return nil, fmt.Errorf("OPAQUE not supported in WASM builds")
}

// SetupServerKeys returns a stub for WASM builds
func SetupServerKeys(db *sql.DB) error {
	return fmt.Errorf("OPAQUE not supported in WASM builds")
}
