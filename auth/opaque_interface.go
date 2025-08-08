package auth

import (
	"os"
)

// OPAQUEProvider defines the interface for OPAQUE authentication operations.
// This abstraction allows for both real OPAQUE implementations (using libopaque.so)
// and mock implementations for testing without external dependencies.
type OPAQUEProvider interface {
	// RegisterUser performs OPAQUE user registration, creating a new user record
	// from a password and server private key. Returns the user record and export key.
	RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error)

	// AuthenticateUser performs OPAQUE authentication using a password and stored
	// user record. Returns the export key on successful authentication.
	AuthenticateUser(password []byte, userRecord []byte) ([]byte, error)

	// IsAvailable returns true if the OPAQUE provider is ready for operations.
	// For real OPAQUE, this checks if libopaque.so is loaded. For mocks, always true.
	IsAvailable() bool

	// GetServerKeys returns the server's public and private keys for OPAQUE operations.
	// These are used for user registration and server-side authentication.
	GetServerKeys() ([]byte, []byte, error)

	// GenerateServerKeys creates new server keys for OPAQUE operations.
	// This is typically called once during initial setup.
	GenerateServerKeys() ([]byte, []byte, error)
}

// OPAQUEProviderType represents the type of OPAQUE provider in use
type OPAQUEProviderType string

const (
	OPAQUEProviderReal OPAQUEProviderType = "real"
	OPAQUEProviderMock OPAQUEProviderType = "mock"
)

// Global provider instance - can be switched between real and mock implementations
var provider OPAQUEProvider

// SetOPAQUEProvider sets the global OPAQUE provider implementation.
// This allows switching between real OPAQUE (for production) and mock (for testing).
func SetOPAQUEProvider(p OPAQUEProvider) {
	provider = p
}

// GetOPAQUEProvider returns the current global OPAQUE provider.
// If no provider is set, it initializes based on environment (mock vs real).
func GetOPAQUEProvider() OPAQUEProvider {
	if provider == nil {
		// Check environment variable for mock mode (used in tests)
		if os.Getenv("OPAQUE_MOCK_MODE") == "true" {
			provider = NewMockOPAQUEProvider()
		} else {
			// Use real OPAQUE provider for production
			provider = NewRealOPAQUEProvider()
		}
	}
	return provider
}

// IsOPAQUEAvailable is a convenience function that checks if OPAQUE operations
// are available through the current provider.
func IsOPAQUEAvailable() bool {
	return GetOPAQUEProvider().IsAvailable()
}
