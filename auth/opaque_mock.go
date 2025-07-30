package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// MockOPAQUEProvider provides a predictable, testable OPAQUE implementation
// that doesn't require libopaque.so. It generates deterministic outputs
// for testing while maintaining realistic data sizes and behavior patterns.
type MockOPAQUEProvider struct {
	mu                 sync.RWMutex
	serverPublicKey    []byte
	serverPrivateKey   []byte
	registrations      map[string][]byte // email -> userRecord
	configuredFailures map[string]error  // operation -> error to return
	callHistory        []MockOPAQUECall  // track calls for verification
}

// MockOPAQUECall represents a tracked function call for test verification
type MockOPAQUECall struct {
	Operation string
	Email     string
	Success   bool
	Error     error
}

// NewMockOPAQUEProvider creates a new mock OPAQUE provider for testing
func NewMockOPAQUEProvider() *MockOPAQUEProvider {
	mock := &MockOPAQUEProvider{
		registrations:      make(map[string][]byte),
		configuredFailures: make(map[string]error),
		callHistory:        make([]MockOPAQUECall, 0),
	}

	// Generate deterministic server keys for testing
	mock.generateTestServerKeys()

	return mock
}

// generateTestServerKeys creates predictable server keys for testing
func (m *MockOPAQUEProvider) generateTestServerKeys() {
	// Generate deterministic keys for testing (32 bytes each)
	// In real implementation, these would be cryptographically random
	m.serverPrivateKey = make([]byte, 32)
	m.serverPublicKey = make([]byte, 32)

	// Use SHA256 to generate deterministic but realistic-looking keys
	privHash := sha256.Sum256([]byte("mock-opaque-private-key"))
	pubHash := sha256.Sum256([]byte("mock-opaque-public-key"))

	copy(m.serverPrivateKey, privHash[:])
	copy(m.serverPublicKey, pubHash[:])
}

// RegisterUser implements the OPAQUEProvider interface with mock behavior
func (m *MockOPAQUEProvider) RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for configured failures
	if err, exists := m.configuredFailures["RegisterUser"]; exists {
		call := MockOPAQUECall{
			Operation: "RegisterUser",
			Success:   false,
			Error:     err,
		}
		m.callHistory = append(m.callHistory, call)
		return nil, nil, err
	}

	// Mock password strength validation
	if len(password) < 12 {
		err := fmt.Errorf("password too weak: must be at least 12 characters")
		call := MockOPAQUECall{
			Operation: "RegisterUser",
			Success:   false,
			Error:     err,
		}
		m.callHistory = append(m.callHistory, call)
		return nil, nil, err
	}

	// Generate deterministic user record based on password
	// In real OPAQUE, this would contain encrypted envelope and salt
	passwordHash := sha256.Sum256(password)
	userRecord := make([]byte, 96) // Realistic size for OPAQUE user record

	// Fill user record with deterministic but realistic data
	copy(userRecord[0:32], passwordHash[:])
	copy(userRecord[32:64], m.serverPublicKey)
	copy(userRecord[64:96], serverPrivateKey)

	// Generate deterministic export key (64 bytes as per OPAQUE spec)
	exportKey := make([]byte, 64)
	exportHash1 := sha256.Sum256(append(password, []byte("export-key-part-1")...))
	exportHash2 := sha256.Sum256(append(password, []byte("export-key-part-2")...))
	copy(exportKey[0:32], exportHash1[:])
	copy(exportKey[32:64], exportHash2[:])

	// Track successful call
	call := MockOPAQUECall{
		Operation: "RegisterUser",
		Success:   true,
		Error:     nil,
	}
	m.callHistory = append(m.callHistory, call)

	return userRecord, exportKey, nil
}

// AuthenticateUser implements the OPAQUEProvider interface with mock behavior
func (m *MockOPAQUEProvider) AuthenticateUser(password []byte, userRecord []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for configured failures
	if err, exists := m.configuredFailures["AuthenticateUser"]; exists {
		call := MockOPAQUECall{
			Operation: "AuthenticateUser",
			Success:   false,
			Error:     err,
		}
		m.callHistory = append(m.callHistory, call)
		return nil, err
	}

	// Validate user record format
	if len(userRecord) != 96 {
		err := fmt.Errorf("invalid user record format")
		call := MockOPAQUECall{
			Operation: "AuthenticateUser",
			Success:   false,
			Error:     err,
		}
		m.callHistory = append(m.callHistory, call)
		return nil, err
	}

	// Extract password hash from user record (first 32 bytes)
	storedPasswordHash := userRecord[0:32]
	providedPasswordHash := sha256.Sum256(password)

	// Verify password matches
	if !compareBytes(storedPasswordHash, providedPasswordHash[:]) {
		err := fmt.Errorf("authentication failed: invalid password")
		call := MockOPAQUECall{
			Operation: "AuthenticateUser",
			Success:   false,
			Error:     err,
		}
		m.callHistory = append(m.callHistory, call)
		return nil, err
	}

	// Generate same export key as registration
	exportKey := make([]byte, 64)
	exportHash1 := sha256.Sum256(append(password, []byte("export-key-part-1")...))
	exportHash2 := sha256.Sum256(append(password, []byte("export-key-part-2")...))
	copy(exportKey[0:32], exportHash1[:])
	copy(exportKey[32:64], exportHash2[:])

	// Track successful call
	call := MockOPAQUECall{
		Operation: "AuthenticateUser",
		Success:   true,
		Error:     nil,
	}
	m.callHistory = append(m.callHistory, call)

	return exportKey, nil
}

// IsAvailable implements the OPAQUEProvider interface
func (m *MockOPAQUEProvider) IsAvailable() bool {
	// Mock provider is always available
	return true
}

// GetServerKeys implements the OPAQUEProvider interface
func (m *MockOPAQUEProvider) GetServerKeys() ([]byte, []byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for configured failures
	if err, exists := m.configuredFailures["GetServerKeys"]; exists {
		return nil, nil, err
	}

	return m.serverPublicKey, m.serverPrivateKey, nil
}

// GenerateServerKeys implements the OPAQUEProvider interface
func (m *MockOPAQUEProvider) GenerateServerKeys() ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for configured failures
	if err, exists := m.configuredFailures["GenerateServerKeys"]; exists {
		return nil, nil, err
	}

	// Generate new random keys
	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)

	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Derive public key from private key (simplified for mock)
	pubHash := sha256.Sum256(append(privateKey, []byte("public-key-derivation")...))
	copy(publicKey, pubHash[:])

	// Update stored keys
	m.serverPrivateKey = privateKey
	m.serverPublicKey = publicKey

	return publicKey, privateKey, nil
}

// Test helper methods for mock configuration and verification

// ConfigureFailure sets up the mock to return a specific error for an operation
func (m *MockOPAQUEProvider) ConfigureFailure(operation string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configuredFailures[operation] = err
}

// ClearFailures removes all configured failures
func (m *MockOPAQUEProvider) ClearFailures() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configuredFailures = make(map[string]error)
}

// GetCallHistory returns the history of calls made to the mock provider
func (m *MockOPAQUEProvider) GetCallHistory() []MockOPAQUECall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid race conditions
	history := make([]MockOPAQUECall, len(m.callHistory))
	copy(history, m.callHistory)
	return history
}

// ClearCallHistory resets the call history
func (m *MockOPAQUEProvider) ClearCallHistory() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callHistory = make([]MockOPAQUECall, 0)
}

// GetLastCall returns the most recent call made to the mock provider
func (m *MockOPAQUEProvider) GetLastCall() *MockOPAQUECall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.callHistory) == 0 {
		return nil
	}

	lastCall := m.callHistory[len(m.callHistory)-1]
	return &lastCall
}

// Utility functions

// compareBytes performs constant-time comparison of byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// IsMockMode returns true if the environment is configured for mock OPAQUE testing
func IsMockMode() bool {
	return strings.ToLower(os.Getenv("OPAQUE_MOCK_MODE")) == "true"
}

// NewMockOPAQUEProviderForTesting creates and configures a mock provider for tests
// This is the recommended way to create mock providers in test functions
func NewMockOPAQUEProviderForTesting() *MockOPAQUEProvider {
	mock := NewMockOPAQUEProvider()

	// Set as global provider for testing
	SetOPAQUEProvider(mock)

	return mock
}

// PrintMockStatus outputs mock provider status for debugging
func (m *MockOPAQUEProvider) PrintMockStatus() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fmt.Printf("=== Mock OPAQUE Provider Status ===\n")
	fmt.Printf("Server Public Key: %s\n", hex.EncodeToString(m.serverPublicKey))
	fmt.Printf("Configured Failures: %d\n", len(m.configuredFailures))
	fmt.Printf("Call History: %d calls\n", len(m.callHistory))

	for i, call := range m.callHistory {
		status := "SUCCESS"
		if !call.Success {
			status = "FAILED"
		}
		fmt.Printf("  %d. %s: %s\n", i+1, call.Operation, status)
	}
	fmt.Printf("===================================\n")
}
