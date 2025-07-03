package auth

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/84adam/arkfile/crypto"
	_ "github.com/mattn/go-sqlite3" // SQLite driver for tests
)

// Define device capabilities locally to avoid import cycles
type DeviceCapability int

const (
	DeviceMinimal DeviceCapability = iota
	DeviceInteractive
	DeviceBalanced
	DeviceMaximum
)

func (d DeviceCapability) String() string {
	switch d {
	case DeviceMinimal:
		return "minimal"
	case DeviceInteractive:
		return "interactive"
	case DeviceBalanced:
		return "balanced"
	case DeviceMaximum:
		return "maximum"
	default:
		return "interactive"
	}
}

func setupOPAQUETestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Create OPAQUE tables
	if err := createOPAQUETables(db); err != nil {
		t.Fatalf("Failed to create OPAQUE tables: %v", err)
	}

	return db
}

func createOPAQUETables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS opaque_server_keys (
			id INTEGER PRIMARY KEY,
			server_secret_key BLOB NOT NULL,
			server_public_key BLOB NOT NULL,
			oprf_seed BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS opaque_user_data (
			user_email TEXT PRIMARY KEY,
			client_argon_salt BLOB NOT NULL,
			server_argon_salt BLOB NOT NULL,
			hardened_envelope BLOB NOT NULL,
			device_profile TEXT NOT NULL,
			created_at DATETIME NOT NULL
		)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}

	return nil
}

func TestInitializeOPAQUEServer(t *testing.T) {
	// Reset global server for clean test
	globalOPAQUEServer = nil

	server, err := GetOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	if !server.initialized {
		t.Error("Server should be initialized")
	}

	if server.configuration.OPRF != server.configuration.AKE {
		t.Error("OPRF and AKE should use the same group")
	}

	// Test singleton behavior
	server2, err := GetOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to get OPAQUE server second time: %v", err)
	}

	if server != server2 {
		t.Error("Should return same server instance")
	}
}

func TestSetupServerKeys(t *testing.T) {
	db := setupOPAQUETestDB(t)
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// First setup should create new keys
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Verify keys were stored
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count server keys: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 server key record, got %d", count)
	}

	// Second setup should load existing keys
	globalOPAQUEServer = nil // Reset to test loading
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys second time: %v", err)
	}

	// Should still be only one record
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count server keys: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 server key record after reload, got %d", count)
	}
}

func TestRegisterUser(t *testing.T) {
	db := setupOPAQUETestDB(t)
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// Setup server keys first
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test user registration
	email := "test@example.com"
	password := "securepassword123"
	deviceCapability := crypto.DeviceBalanced

	err = RegisterUser(db, email, password, deviceCapability)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Verify user data was stored
	userData, err := loadOPAQUEUserData(db, email)
	if err != nil {
		t.Fatalf("Failed to load user data: %v", err)
	}

	if userData.UserEmail != email {
		t.Errorf("Expected email %s, got %s", email, userData.UserEmail)
	}

	if userData.DeviceProfile != deviceCapability.String() {
		t.Errorf("Expected device profile %s, got %s", deviceCapability.String(), userData.DeviceProfile)
	}

	if len(userData.ClientArgonSalt) != 32 {
		t.Errorf("Expected client salt length 32, got %d", len(userData.ClientArgonSalt))
	}

	if len(userData.ServerArgonSalt) != 32 {
		t.Errorf("Expected server salt length 32, got %d", len(userData.ServerArgonSalt))
	}

	if len(userData.HardenedEnvelope) == 0 {
		t.Error("Hardened envelope should not be empty")
	}

	// Test duplicate registration (should fail)
	err = RegisterUser(db, email, password, deviceCapability)
	if err == nil {
		t.Error("Expected error for duplicate user registration")
	}
}

func TestAuthenticateUser(t *testing.T) {
	db := setupOPAQUETestDB(t)
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// Setup server keys first
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Register a test user
	email := "test@example.com"
	password := "securepassword123"
	deviceCapability := crypto.DeviceBalanced

	err = RegisterUser(db, email, password, deviceCapability)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Test successful authentication
	sessionKey, err := AuthenticateUser(db, email, password)
	if err != nil {
		t.Fatalf("Failed to authenticate user: %v", err)
	}

	if len(sessionKey) == 0 {
		t.Error("Session key should not be empty")
	}

	// Test authentication with wrong password
	_, err = AuthenticateUser(db, email, "wrongpassword")
	if err == nil {
		t.Error("Expected error for wrong password")
	}

	// Test authentication with non-existent user
	_, err = AuthenticateUser(db, "nonexistent@example.com", password)
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}

func TestDeviceCapabilityParsing(t *testing.T) {
	tests := []struct {
		profile  string
		expected crypto.DeviceCapability
	}{
		{"minimal", crypto.DeviceMinimal},
		{"interactive", crypto.DeviceInteractive},
		{"balanced", crypto.DeviceBalanced},
		{"maximum", crypto.DeviceMaximum},
		{"unknown", crypto.DeviceInteractive}, // Default
		{"", crypto.DeviceInteractive},        // Default
	}

	for _, test := range tests {
		result := parseDeviceCapability(test.profile)
		if result != test.expected {
			t.Errorf("For profile %s, expected %v, got %v", test.profile, test.expected, result)
		}
	}
}

func TestValidateOPAQUESetup(t *testing.T) {
	db := setupOPAQUETestDB(t)
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// Should fail without server keys
	err := ValidateOPAQUESetup(db)
	if err == nil {
		t.Error("Expected error when validating setup without server keys")
	}

	// Setup server keys
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Should succeed with server keys
	err = ValidateOPAQUESetup(db)
	if err != nil {
		t.Errorf("Validation should succeed with proper setup: %v", err)
	}
}

func TestOPAQUEUserDataStorage(t *testing.T) {
	db := setupOPAQUETestDB(t)
	defer db.Close()

	userData := OPAQUEUserData{
		UserEmail:        "test@example.com",
		ClientArgonSalt:  make([]byte, 32),
		ServerArgonSalt:  make([]byte, 32),
		HardenedEnvelope: []byte("test_envelope"),
		DeviceProfile:    "balanced",
		CreatedAt:        time.Now(),
	}

	// Fill salts with test data
	for i := range userData.ClientArgonSalt {
		userData.ClientArgonSalt[i] = byte(i)
	}
	for i := range userData.ServerArgonSalt {
		userData.ServerArgonSalt[i] = byte(i + 32)
	}

	// Test storing user data
	err := storeOPAQUEUserData(db, userData)
	if err != nil {
		t.Fatalf("Failed to store user data: %v", err)
	}

	// Test loading user data
	loadedData, err := loadOPAQUEUserData(db, userData.UserEmail)
	if err != nil {
		t.Fatalf("Failed to load user data: %v", err)
	}

	// Verify data integrity
	if loadedData.UserEmail != userData.UserEmail {
		t.Errorf("Email mismatch: expected %s, got %s", userData.UserEmail, loadedData.UserEmail)
	}

	if len(loadedData.ClientArgonSalt) != len(userData.ClientArgonSalt) {
		t.Errorf("Client salt length mismatch: expected %d, got %d", len(userData.ClientArgonSalt), len(loadedData.ClientArgonSalt))
	}

	for i := range userData.ClientArgonSalt {
		if loadedData.ClientArgonSalt[i] != userData.ClientArgonSalt[i] {
			t.Errorf("Client salt byte %d mismatch: expected %d, got %d", i, userData.ClientArgonSalt[i], loadedData.ClientArgonSalt[i])
		}
	}

	if loadedData.DeviceProfile != userData.DeviceProfile {
		t.Errorf("Device profile mismatch: expected %s, got %s", userData.DeviceProfile, loadedData.DeviceProfile)
	}
}

func TestMultipleDeviceRegistrations(t *testing.T) {
	db := setupOPAQUETestDB(t)
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// Setup server keys first
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test registration with different device capabilities
	devices := []crypto.DeviceCapability{
		crypto.DeviceMinimal,
		crypto.DeviceInteractive,
		crypto.DeviceBalanced,
		crypto.DeviceMaximum,
	}

	password := "testpassword123"

	for i, device := range devices {
		email := fmt.Sprintf("user%d@example.com", i)

		err := RegisterUser(db, email, password, device)
		if err != nil {
			t.Fatalf("Failed to register user with device %v: %v", device, err)
		}

		// Verify the device profile was stored correctly
		userData, err := loadOPAQUEUserData(db, email)
		if err != nil {
			t.Fatalf("Failed to load user data for %s: %v", email, err)
		}

		if userData.DeviceProfile != device.String() {
			t.Errorf("Device profile mismatch for %s: expected %s, got %s", email, device.String(), userData.DeviceProfile)
		}

		// Test authentication with the correct device profile
		sessionKey, err := AuthenticateUser(db, email, password)
		if err != nil {
			t.Fatalf("Failed to authenticate user %s: %v", email, err)
		}

		if len(sessionKey) == 0 {
			t.Errorf("Session key should not be empty for user %s", email)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	db := setupOPAQUETestDB(t)
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// Setup server keys first
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test concurrent server initialization
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, err := GetOPAQUEServer()
			if err != nil {
				t.Errorf("Failed to get OPAQUE server: %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify we still have only one server instance
	if globalOPAQUEServer == nil {
		t.Error("Global OPAQUE server should be initialized")
	}
}

func BenchmarkRegisterUser(b *testing.B) {
	db := setupOPAQUETestDB(&testing.T{})
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// Setup server keys first
	err := SetupServerKeys(db)
	if err != nil {
		b.Fatalf("Failed to setup server keys: %v", err)
	}

	password := "benchmarkpassword123"
	deviceCapability := crypto.DeviceBalanced

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		email := fmt.Sprintf("bench%d@example.com", i)
		err := RegisterUser(db, email, password, deviceCapability)
		if err != nil {
			b.Fatalf("Failed to register user: %v", err)
		}
	}
}

func BenchmarkAuthenticateUser(b *testing.B) {
	db := setupOPAQUETestDB(&testing.T{})
	defer db.Close()

	// Reset global server for clean test
	globalOPAQUEServer = nil

	// Setup server keys first
	err := SetupServerKeys(db)
	if err != nil {
		b.Fatalf("Failed to setup server keys: %v", err)
	}

	// Register a test user
	email := "bench@example.com"
	password := "benchmarkpassword123"
	deviceCapability := crypto.DeviceBalanced

	err = RegisterUser(db, email, password, deviceCapability)
	if err != nil {
		b.Fatalf("Failed to register user: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := AuthenticateUser(db, email, password)
		if err != nil {
			b.Fatalf("Failed to authenticate user: %v", err)
		}
	}
}
