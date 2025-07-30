package auth

import (
	"testing"
)

func TestMockOPAQUEProvider(t *testing.T) {
	// Set up mock provider for testing
	mock := NewMockOPAQUEProviderForTesting()
	defer mock.ClearCallHistory()

	// Test that provider is available
	if !mock.IsAvailable() {
		t.Fatal("Mock provider should always be available")
	}

	// Test server key generation
	pubKey, privKey, err := mock.GenerateServerKeys()
	if err != nil {
		t.Fatalf("GenerateServerKeys failed: %v", err)
	}

	if len(pubKey) != 32 {
		t.Errorf("Expected public key length 32, got %d", len(pubKey))
	}

	if len(privKey) != 32 {
		t.Errorf("Expected private key length 32, got %d", len(privKey))
	}

	// Test user registration
	password := []byte("test-password-123456")
	userRecord, exportKey, err := mock.RegisterUser(password, privKey)
	if err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}

	if len(userRecord) != 96 {
		t.Errorf("Expected user record length 96, got %d", len(userRecord))
	}

	if len(exportKey) != 64 {
		t.Errorf("Expected export key length 64, got %d", len(exportKey))
	}

	// Test user authentication
	authExportKey, err := mock.AuthenticateUser(password, userRecord)
	if err != nil {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}

	if len(authExportKey) != 64 {
		t.Errorf("Expected auth export key length 64, got %d", len(authExportKey))
	}

	// Verify export keys match (deterministic behavior)
	for i := 0; i < 64; i++ {
		if exportKey[i] != authExportKey[i] {
			t.Error("Export keys from registration and authentication should match")
			break
		}
	}

	// Test wrong password fails
	wrongPassword := []byte("wrong-password-123456")
	_, err = mock.AuthenticateUser(wrongPassword, userRecord)
	if err == nil {
		t.Error("Authentication with wrong password should fail")
	}

	// Test call history tracking
	history := mock.GetCallHistory()
	t.Logf("Call history: %d calls", len(history))
	for i, call := range history {
		t.Logf("  %d. %s: success=%v, error=%v", i+1, call.Operation, call.Success, call.Error)
	}

	expectedCalls := 3 // RegisterUser, AuthenticateUser (success), AuthenticateUser (failure) - GenerateServerKeys doesn't track calls
	if len(history) != expectedCalls {
		t.Errorf("Expected %d calls in history, got %d", expectedCalls, len(history))
	}

	// Verify last call was the failed authentication
	lastCall := mock.GetLastCall()
	if lastCall == nil {
		t.Fatal("Expected last call to be recorded")
	}

	if lastCall.Operation != "AuthenticateUser" || lastCall.Success {
		t.Error("Last call should be failed AuthenticateUser")
	}
}

func TestMockOPAQUEProviderFailures(t *testing.T) {
	mock := NewMockOPAQUEProvider()

	// Configure a registration failure
	mock.ConfigureFailure("RegisterUser", ErrOPAQUEMockConfiguredFailure)

	password := []byte("test-password-123456")
	serverKey := make([]byte, 32)

	_, _, err := mock.RegisterUser(password, serverKey)
	if err != ErrOPAQUEMockConfiguredFailure {
		t.Errorf("Expected configured failure, got: %v", err)
	}

	// Clear failures and try again
	mock.ClearFailures()

	_, _, err = mock.RegisterUser(password, serverKey)
	if err != nil {
		t.Errorf("After clearing failures, registration should succeed: %v", err)
	}
}

func TestProviderSwitching(t *testing.T) {
	// Test that we can switch providers
	originalProvider := GetOPAQUEProvider()

	mock := NewMockOPAQUEProvider()
	SetOPAQUEProvider(mock)

	currentProvider := GetOPAQUEProvider()
	if currentProvider != mock {
		t.Error("Provider switching failed")
	}

	// Test that the provider works
	if !currentProvider.IsAvailable() {
		t.Error("Switched provider should be available")
	}

	// Restore original provider
	SetOPAQUEProvider(originalProvider)
}

// Common mock error for testing
var ErrOPAQUEMockConfiguredFailure = NewMockError("configured mock failure")

// NewMockError creates a mock error for testing
func NewMockError(message string) error {
	return &MockError{message: message}
}

// MockError implements error interface for testing
type MockError struct {
	message string
}

func (e *MockError) Error() string {
	return e.message
}
