package auth

import (
	"database/sql"
	"os"
	"testing"

	"github.com/84adam/arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

const testDBPath = "./test_opaque.db"

func setupTestDatabase(t *testing.T) *sql.DB {
	// Clean up any previous test database
	os.Remove(testDBPath)

	db, err := sql.Open("sqlite3", testDBPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Create OPAQUE tables
	schema := `
		CREATE TABLE opaque_user_data (
			username TEXT PRIMARY KEY,
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

func cleanupTestDatabase() {
	os.Remove(testDBPath)
}

// Test complete OPAQUE protocol flow from registration to authentication.
func TestOpaqueRegistrationAndAuthentication(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() {
		db.Close()
		cleanupTestDatabase()
	}()

	// 1. Setup server keys
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// 2. Test registration
	username := "test.user.2024"
	password := "TestPassword123!SecurePass"

	err = RegisterUser(db, username, password)
	if err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}

	// 3. Verify user data was stored
	userData, err := loadOPAQUEUserData(db, username)
	if err != nil {
		t.Fatalf("Failed to load user data: %v", err)
	}
	if userData.Username != username {
		t.Errorf("Expected username %s, got %s", username, userData.Username)
	}
	if len(userData.SerializedRecord) == 0 {
		t.Error("Serialized OPAQUE record should not be empty")
	}

	// Verify record has expected libopaque size
	if len(userData.SerializedRecord) != OPAQUE_USER_RECORD_LEN {
		t.Errorf("Expected user record length %d, got %d", OPAQUE_USER_RECORD_LEN, len(userData.SerializedRecord))
	}

	// 4. Test authentication with the correct password
	sessionKey, err := AuthenticateUser(db, username, password)
	if err != nil {
		t.Fatalf("Authentication failed with correct password: %v", err)
	}
	if len(sessionKey) == 0 {
		t.Error("Expected a non-empty session key")
	}

	// Verify session key has expected libopaque size
	if len(sessionKey) != OPAQUE_SHARED_SECRETBYTES {
		t.Errorf("Expected session key length %d, got %d", OPAQUE_SHARED_SECRETBYTES, len(sessionKey))
	}

	// 5. Test authentication with an incorrect password
	_, err = AuthenticateUser(db, username, "WrongPassword")
	if err == nil {
		t.Error("Authentication should have failed with an incorrect password")
	}

	// 6. Test authentication with empty password
	_, err = AuthenticateUser(db, username, "")
	if err == nil {
		t.Error("Authentication should have failed with empty password")
	}

	// 7. Test authentication for non-existent user
	_, err = AuthenticateUser(db, "nonexistent.user", password)
	if err == nil {
		t.Error("Authentication should have failed for non-existent user")
	}
}

// Test security properties of the OPAQUE implementation.
func TestOpaqueSecurityProperties(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() {
		db.Close()
		cleanupTestDatabase()
	}()

	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// 1. Register two different users
	users := []struct {
		username string
		password string
	}{
		{"user1.secure.2024", "User1Password123!Secure"},
		{"user2.safe.2024", "User2Password456!Safe"},
	}

	for _, user := range users {
		err := RegisterUser(db, user.username, user.password)
		if err != nil {
			t.Fatalf("Registration failed for %s: %v", user.username, err)
		}
	}

	// 2. Authenticate both users and get their session keys
	sessionKey1, err := AuthenticateUser(db, users[0].username, users[0].password)
	if err != nil {
		t.Fatalf("Authentication failed for %s: %v", users[0].username, err)
	}

	sessionKey2, err := AuthenticateUser(db, users[1].username, users[1].password)
	if err != nil {
		t.Fatalf("Authentication failed for %s: %v", users[1].username, err)
	}

	// 3. Verify that the session keys are different
	if crypto.SecureCompare(sessionKey1, sessionKey2) {
		t.Error("Session keys for different users should not be the same")
	}

	// 4. Test that cross-authentication fails
	_, err = AuthenticateUser(db, users[0].username, users[1].password)
	if err == nil {
		t.Error("Cross-user authentication should fail")
	}

	// 5. Test same user authentication - OPAQUE should generate different session keys each time for security
	sessionKey1Again, err := AuthenticateUser(db, users[0].username, users[0].password)
	if err != nil {
		t.Fatalf("Second authentication failed for %s: %v", users[0].username, err)
	}

	// Session keys should be different each time for security (OPAQUE protocol feature)
	if crypto.SecureCompare(sessionKey1, sessionKey1Again) {
		t.Error("Session keys should be different each authentication for security (OPAQUE protocol)")
	}

	// But both session keys should have the correct length
	if len(sessionKey1Again) != OPAQUE_SHARED_SECRETBYTES {
		t.Errorf("Expected session key length %d, got %d", OPAQUE_SHARED_SECRETBYTES, len(sessionKey1Again))
	}
}

// Test key management, ensuring keys are created once and loaded correctly.
func TestOpaqueServerKeyManagement(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() {
		db.Close()
		cleanupTestDatabase()
	}()

	// 1. Initial server key setup
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys on first call: %v", err)
	}
	firstServerPrivateKey := make([]byte, len(serverKeys.ServerPrivateKey))
	copy(firstServerPrivateKey, serverKeys.ServerPrivateKey)

	// 2. Verify keys are stored in the database
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query server keys: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 server key record, got %d", count)
	}

	// 3. Subsequent calls to SetupServerKeys should not generate new keys
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Second call to SetupServerKeys should not fail: %v", err)
	}

	// 4. Verify that the server private key loaded on the second call is the same as the first
	if !crypto.SecureCompare(firstServerPrivateKey, serverKeys.ServerPrivateKey) {
		t.Error("Server private key should be consistent across loads")
	}

	// 5. Verify server keys have expected values
	if len(serverKeys.ServerPrivateKey) != 32 {
		t.Errorf("Expected ServerPrivateKey length 32, got %d", len(serverKeys.ServerPrivateKey))
	}
	if len(serverKeys.ServerPublicKey) != 32 {
		t.Errorf("Expected ServerPublicKey length 32, got %d", len(serverKeys.ServerPublicKey))
	}
	if len(serverKeys.OPRFSeed) != 32 {
		t.Errorf("Expected OPRFSeed length 32, got %d", len(serverKeys.OPRFSeed))
	}
}

// Test OPAQUE validation functions.
func TestOpaqueValidation(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() {
		db.Close()
		cleanupTestDatabase()
	}()

	// 1. Test GetOPAQUEServer
	ready, err := GetOPAQUEServer()
	if err != nil {
		t.Fatalf("GetOPAQUEServer failed: %v", err)
	}
	if !ready {
		t.Error("OPAQUE server should be ready with libopaque CGO")
	}

	// 2. Test ValidateOPAQUESetup without keys - should setup keys automatically
	serverKeys = nil // Ensure clean state
	err = ValidateOPAQUESetup(db)
	if err != nil {
		t.Fatalf("ValidateOPAQUESetup should automatically setup keys when none exist: %v", err)
	}

	// 3. Test ValidateOPAQUESetup with keys already loaded
	err = ValidateOPAQUESetup(db)
	if err != nil {
		t.Fatalf("ValidateOPAQUESetup should succeed when keys already exist: %v", err)
	}

	// 4. Verify serverKeys are properly loaded
	if serverKeys == nil {
		t.Error("serverKeys should be loaded after ValidateOPAQUESetup")
	}
	if serverKeys != nil {
		if len(serverKeys.ServerPrivateKey) != 32 {
			t.Errorf("Expected ServerPrivateKey length 32, got %d", len(serverKeys.ServerPrivateKey))
		}
		if len(serverKeys.ServerPublicKey) != 32 {
			t.Errorf("Expected ServerPublicKey length 32, got %d", len(serverKeys.ServerPublicKey))
		}
		if len(serverKeys.OPRFSeed) != 32 {
			t.Errorf("Expected OPRFSeed length 32, got %d", len(serverKeys.OPRFSeed))
		}
	}
}

// Test edge cases and error conditions.
func TestOpaqueEdgeCases(t *testing.T) {
	db := setupTestDatabase(t)
	defer func() {
		db.Close()
		cleanupTestDatabase()
	}()

	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// 1. Test registration with empty username
	err = RegisterUser(db, "", "password123")
	if err == nil {
		t.Error("Registration should fail with empty username")
	}

	// 2. Test registration with empty password
	err = RegisterUser(db, "test.user.name", "")
	if err == nil {
		t.Error("Registration should fail with empty password")
	}

	// 3. Test duplicate registration
	username := "duplicate.user.2024"
	password := "TestPassword123"

	err = RegisterUser(db, username, password)
	if err != nil {
		t.Fatalf("First registration failed: %v", err)
	}

	err = RegisterUser(db, username, password+"different")
	if err != nil {
		t.Logf("Duplicate registration handled (expected): %v", err)
		// This should update the existing record due to our UPSERT logic
	}

	// 4. Test authentication without server keys
	serverKeys = nil
	_, err = AuthenticateUser(db, username, password)
	if err == nil {
		t.Error("Authentication should fail without server keys loaded")
	}

	// Restore server keys for cleanup
	err = SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to restore server keys: %v", err)
	}
}

// Test libopaque-specific constants and sizes.
func TestLibopaqueConstants(t *testing.T) {
	// Test that our constants match expected libopaque values
	if OPAQUE_USER_RECORD_LEN != 256 {
		t.Errorf("Expected OPAQUE_USER_RECORD_LEN=256, got %d", OPAQUE_USER_RECORD_LEN)
	}

	if OPAQUE_SHARED_SECRETBYTES != 64 {
		t.Errorf("Expected OPAQUE_SHARED_SECRETBYTES=64, got %d", OPAQUE_SHARED_SECRETBYTES)
	}

	if OPAQUE_REGISTRATION_RECORD_LEN != 192 {
		t.Errorf("Expected OPAQUE_REGISTRATION_RECORD_LEN=192, got %d", OPAQUE_REGISTRATION_RECORD_LEN)
	}
}
