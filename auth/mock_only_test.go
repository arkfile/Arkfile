package auth

import (
	"testing"
)

func TestMockOnlyProvider(t *testing.T) {
	// Create mock provider directly (no interface dependency)
	mock := NewMockOPAQUEProvider()

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

	t.Logf("Mock OPAQUE provider test completed successfully")
}
