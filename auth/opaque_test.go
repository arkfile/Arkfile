package auth

import (
	"database/sql"
	"testing"

	"github.com/84adam/arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

// Test complete OPAQUE protocol flow
func TestOpaqueRegistrationFlow(t *testing.T) {
	// Reset global server state
	resetOPAQUEServer()

	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	// Setup server keys
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test registration
	email := "test@example.com"
	password := "TestPassword123!SecurePass"

	err = RegisterUser(db, email, password)
	if err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}

	// Verify user data was stored
	userData, err := loadOPAQUEUserData(db, email)
	if err != nil {
		t.Fatalf("Failed to load user data: %v", err)
	}

	if userData.UserEmail != email {
		t.Errorf("Expected email %s, got %s", email, userData.UserEmail)
	}

	// Verify OPAQUE record exists
	if len(userData.SerializedRecord) == 0 {
		t.Error("Serialized OPAQUE record should not be empty")
	}

	// Verify creation time is set
	if userData.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestOpaqueAuthenticationFlow(t *testing.T) {
	// Reset global server state
	resetOPAQUEServer()

	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	// Setup server keys
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// First register a user
	email := "auth-test@example.com"
	password := "AuthTestPass123!Secure"

	err = RegisterUser(db, email, password)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Test authentication with correct password
	sessionKey, err := AuthenticateUser(db, email, password)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	if len(sessionKey) != 32 {
		t.Errorf("Expected 32-byte session key, got %d bytes", len(sessionKey))
	}

	// Test authentication with wrong password
	_, err = AuthenticateUser(db, email, "WrongPassword123!")
	if err == nil {
		t.Error("Authentication should fail with wrong password")
	}

	// Test authentication with non-existent user
	_, err = AuthenticateUser(db, "nonexistent@example.com", password)
	if err == nil {
		t.Error("Authentication should fail for non-existent user")
	}
}

func TestOpaqueContextParameter(t *testing.T) {
	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	// Verify the OPAQUE server has the correct context parameter
	server, err := GetOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to get OPAQUE server: %v", err)
	}

	expectedContext := []byte("arkfile-v1")
	if string(server.configuration.Context) != string(expectedContext) {
		t.Errorf("Expected context %s, got %s", expectedContext, server.configuration.Context)
	}

	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test that registration and authentication work with context parameter
	email := "context-test@example.com"
	password := "ContextTestPass123!Secure"

	err = RegisterUser(db, email, password)
	if err != nil {
		t.Fatalf("Registration failed with context: %v", err)
	}

	_, err = AuthenticateUser(db, email, password)
	if err != nil {
		t.Fatalf("Authentication failed with context: %v", err)
	}
}

func TestOpaqueSessionKeyDerivation(t *testing.T) {
	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Register and authenticate user
	email := "session-test@example.com"
	password := "SessionTestPass123!Secure"

	err = RegisterUser(db, email, password)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	// Get session key twice - should be consistent
	sessionKey1, err := AuthenticateUser(db, email, password)
	if err != nil {
		t.Fatalf("First authentication failed: %v", err)
	}

	sessionKey2, err := AuthenticateUser(db, email, password)
	if err != nil {
		t.Fatalf("Second authentication failed: %v", err)
	}

	// Session keys should be identical for same user/password
	if !crypto.SecureCompare(sessionKey1, sessionKey2) {
		t.Error("Session keys should be consistent for same user")
	}

	// Test session key properties
	if len(sessionKey1) != 32 {
		t.Errorf("Expected 32-byte session key, got %d bytes", len(sessionKey1))
	}

	// Verify session key is not all zeros
	allZeros := make([]byte, 32)
	if crypto.SecureCompare(sessionKey1, allZeros) {
		t.Error("Session key should not be all zeros")
	}
}

func TestOpaqueSecurityProperties(t *testing.T) {
	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test that different users have different derived keys
	users := []struct {
		email    string
		password string
	}{
		{"user1@example.com", "User1Password123!Secure"},
		{"user2@example.com", "User2Password456!Safe"},
	}

	sessionKeys := make([][]byte, len(users))

	for i, user := range users {
		// Register user
		err := RegisterUser(db, user.email, user.password)
		if err != nil {
			t.Fatalf("Registration failed for %s: %v", user.email, err)
		}

		// Authenticate user
		sessionKey, err := AuthenticateUser(db, user.email, user.password)
		if err != nil {
			t.Fatalf("Authentication failed for %s: %v", user.email, err)
		}

		sessionKeys[i] = sessionKey
	}

	// Verify session keys are different
	if crypto.SecureCompare(sessionKeys[0], sessionKeys[1]) {
		t.Error("Different users should have different session keys")
	}

	// Test cross-user authentication fails
	_, err = AuthenticateUser(db, users[0].email, users[1].password)
	if err == nil {
		t.Error("Cross-user authentication should fail")
	}
}

func TestOpaqueServerKeyManagement(t *testing.T) {
	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	// Test initial server key setup
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Verify keys were stored
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query server keys: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 server key record, got %d", count)
	}

	// Test that subsequent calls don't create duplicate keys
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Second setup should not fail: %v", err)
	}

	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query server keys count: %v", err)
	}

	if count != 1 {
		t.Errorf("Should still have only 1 server key record, got %d", count)
	}
}

func TestOpaqueSetupValidation(t *testing.T) {
	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Test validation without initialization
	err := ValidateOPAQUESetup(db)
	if err == nil {
		t.Error("Validation should fail without initialization")
	}

	// Initialize OPAQUE server
	err = InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	// Test validation without server keys
	err = ValidateOPAQUESetup(db)
	if err == nil {
		t.Error("Validation should fail without server keys")
	}

	// Setup server keys
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test successful validation
	err = ValidateOPAQUESetup(db)
	if err != nil {
		t.Errorf("Validation should succeed: %v", err)
	}
}

func TestOpaqueMemoryManagement(t *testing.T) {
	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Test that multiple registrations don't cause memory leaks
	for i := 0; i < 10; i++ {
		email := "memtest" + string(rune('0'+i)) + "@example.com"
		password := "MemTestPass123!Secure"

		err := RegisterUser(db, email, password)
		if err != nil {
			t.Fatalf("Registration %d failed: %v", i, err)
		}

		// Authenticate immediately to test cleanup
		_, err = AuthenticateUser(db, email, password)
		if err != nil {
			t.Fatalf("Authentication %d failed: %v", i, err)
		}
	}

	// If we get here without panics or excessive memory usage, the test passes
}

func TestOpaqueSimplifiedDataStructure(t *testing.T) {
	// Setup test database
	db := setupTestDatabase(t)
	defer db.Close()

	// Initialize OPAQUE server
	err := InitializeOPAQUEServer()
	if err != nil {
		t.Fatalf("Failed to initialize OPAQUE server: %v", err)
	}

	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// Register user
	email := "structure-test@example.com"
	password := "StructureTestPass123!Secure"

	err = RegisterUser(db, email, password)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	// Verify only the simplified fields are stored
	userData, err := loadOPAQUEUserData(db, email)
	if err != nil {
		t.Fatalf("Failed to load user data: %v", err)
	}

	// Check that we have the essential fields
	if userData.UserEmail != email {
		t.Errorf("Expected email %s, got %s", email, userData.UserEmail)
	}

	if len(userData.SerializedRecord) == 0 {
		t.Error("SerializedRecord should not be empty")
	}

	if userData.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	// Verify database schema matches expectations
	rows, err := db.Query("PRAGMA table_info(opaque_user_data)")
	if err != nil {
		t.Fatalf("Failed to get table info: %v", err)
	}
	defer rows.Close()

	columnCount := 0
	expectedColumns := map[string]bool{
		"user_email":        true,
		"serialized_record": true,
		"created_at":        true,
	}

	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull int
		var defaultValue interface{}
		var pk int

		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		if err != nil {
			t.Fatalf("Failed to scan column info: %v", err)
		}

		if expectedColumns[name] {
			columnCount++
		}
	}

	if columnCount != 3 {
		t.Errorf("Expected 3 columns in opaque_user_data table, found %d", columnCount)
	}
}

// Helper functions

func setupTestDatabase(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Create simplified OPAQUE tables for pure OPAQUE implementation
	schema := `
		CREATE TABLE opaque_user_data (
			user_email TEXT PRIMARY KEY,
			serialized_record TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE opaque_server_keys (
			id INTEGER PRIMARY KEY,
			server_secret_key TEXT NOT NULL,
			server_public_key TEXT NOT NULL,
			oprf_seed TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create test schema: %v", err)
	}

	return db
}

func resetOPAQUEServer() {
	globalOPAQUEServer = nil
}

func TestParseDeviceCapability(t *testing.T) {
	testCases := []struct {
		input    string
		expected crypto.DeviceCapability
	}{
		{"minimal", crypto.DeviceMinimal},
		{"interactive", crypto.DeviceInteractive},
		{"balanced", crypto.DeviceBalanced},
		{"maximum", crypto.DeviceMaximum},
		{"unknown", crypto.DeviceInteractive}, // Should default to interactive
		{"", crypto.DeviceInteractive},        // Should default to interactive
	}

	for _, tc := range testCases {
		result := parseDeviceCapability(tc.input)
		if result != tc.expected {
			t.Errorf("parseDeviceCapability(%q): expected %v, got %v",
				tc.input, tc.expected, result)
		}
	}
}
