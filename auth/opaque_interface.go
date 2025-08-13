package auth

// OPAQUEProvider defines the interface for OPAQUE authentication operations.
// Static linking eliminates the need for mock implementations.
type OPAQUEProvider interface {
	// RegisterUser performs OPAQUE user registration, creating a new user record
	// from a password and server private key. Returns the user record and export key.
	RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error)

	// AuthenticateUser performs OPAQUE authentication using a password and stored
	// user record. Returns the export key on successful authentication.
	AuthenticateUser(password []byte, userRecord []byte) ([]byte, error)

	// IsAvailable returns true if the OPAQUE provider is ready for operations.
	IsAvailable() bool

	// GetServerKeys returns the server's public and private keys for OPAQUE operations.
	// These are used for user registration and server-side authentication.
	GetServerKeys() ([]byte, []byte, error)

	// GenerateServerKeys creates new server keys for OPAQUE operations.
	// This is typically called once during initial setup.
	GenerateServerKeys() ([]byte, []byte, error)
}

// Global provider instance - always uses real implementation with static linking
var provider OPAQUEProvider

// GetOPAQUEProvider returns the static OPAQUE provider.
func GetOPAQUEProvider() OPAQUEProvider {
	if provider == nil {
		provider = NewRealOPAQUEProvider()
	}
	return provider
}

// IsOPAQUEAvailable is a convenience function that checks if OPAQUE operations
// are available through the current provider.
func IsOPAQUEAvailable() bool {
	return GetOPAQUEProvider().IsAvailable()
}
