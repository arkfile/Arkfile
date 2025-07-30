//go:build !mock
// +build !mock

package auth

import (
	"fmt"
)

// RealOPAQUEProvider wraps the existing OPAQUE implementation to match the interface
type RealOPAQUEProvider struct{}

// NewRealOPAQUEProvider creates a new real OPAQUE provider
func NewRealOPAQUEProvider() *RealOPAQUEProvider {
	return &RealOPAQUEProvider{}
}

// RegisterUser implements the OPAQUEProvider interface using real OPAQUE
func (r *RealOPAQUEProvider) RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
	// Use low-level libopaque registration function directly
	userRecord, exportKey, err := libopaqueRegisterUser(password, serverPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("OPAQUE registration failed: %v", err)
	}
	return userRecord, exportKey, nil
}

// AuthenticateUser implements the OPAQUEProvider interface using real OPAQUE
func (r *RealOPAQUEProvider) AuthenticateUser(password []byte, userRecord []byte) ([]byte, error) {
	// Use low-level libopaque authentication function directly
	exportKey, err := libopaqueAuthenticateUser(password, userRecord)
	if err != nil {
		return nil, fmt.Errorf("OPAQUE authentication failed: %v", err)
	}
	return exportKey, nil
}

// IsAvailable implements the OPAQUEProvider interface
func (r *RealOPAQUEProvider) IsAvailable() bool {
	// Check if OPAQUE is available (simple availability check)
	available, _ := GetOPAQUEServer()
	return available
}

// GetServerKeys implements the OPAQUEProvider interface
func (r *RealOPAQUEProvider) GetServerKeys() ([]byte, []byte, error) {
	// Check if server keys are loaded
	if serverKeys == nil {
		return nil, nil, fmt.Errorf("server keys not loaded")
	}
	return serverKeys.ServerPublicKey, serverKeys.ServerPrivateKey, nil
}

// GenerateServerKeys implements the OPAQUEProvider interface
func (r *RealOPAQUEProvider) GenerateServerKeys() ([]byte, []byte, error) {
	// Generate new server keys
	newKeys, err := generateOPAQUEServerKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server keys: %v", err)
	}
	return newKeys.ServerPublicKey, newKeys.ServerPrivateKey, nil
}
