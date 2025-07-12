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

func cleanupTestDatabase() {
	os.Remove(testDBPath)
}

// Test complete OPAQUE protocol flow from registration to authentication.
func TestOpaqueRegistrationAndAuthentication(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()

	// 1. Setup server keys
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// 2. Test registration
	email := "test@example.com"
	password := "TestPassword123!SecurePass"

	err = RegisterUser(db, email, password)
	if err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}

	// 3. Verify user data was stored
	userData, err := loadOPAQUEUserData(db, email)
	if err != nil {
		t.Fatalf("Failed to load user data: %v", err)
	}
	if userData.UserEmail != email {
		t.Errorf("Expected email %s, got %s", email, userData.UserEmail)
	}
	if len(userData.SerializedRecord) == 0 {
		t.Error("Serialized OPAQUE record should not be empty")
	}

	// 4. Test authentication with the correct password
	sessionKey, err := AuthenticateUser(db, email, password)
	if err != nil {
		t.Fatalf("Authentication failed with correct password: %v", err)
	}
	if len(sessionKey) == 0 {
		t.Error("Expected a non-empty session key")
	}

	// 5. Test authentication with an incorrect password
	_, err = AuthenticateUser(db, email, "WrongPassword")
	if err == nil {
		t.Error("Authentication should have failed with an incorrect password")
	}
}

// Test security properties of the OPAQUE implementation.
func TestOpaqueSecurityProperties(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()

	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys: %v", err)
	}

	// 1. Register two different users
	users := []struct {
		email    string
		password string
	}{
		{"user1@example.com", "User1Password123!Secure"},
		{"user2@example.com", "User2Password456!Safe"},
	}

	for _, user := range users {
		err := RegisterUser(db, user.email, user.password)
		if err != nil {
			t.Fatalf("Registration failed for %s: %v", user.email, err)
		}
	}

	// 2. Authenticate both users and get their session keys
	sessionKey1, err := AuthenticateUser(db, users[0].email, users[0].password)
	if err != nil {
		t.Fatalf("Authentication failed for %s: %v", users[0].email, err)
	}

	sessionKey2, err := AuthenticateUser(db, users[1].email, users[1].password)
	if err != nil {
		t.Fatalf("Authentication failed for %s: %v", users[1].email, err)
	}

	// 3. Verify that the session keys are different
	if crypto.SecureCompare(sessionKey1, sessionKey2) {
		t.Error("Session keys for different users should not be the same")
	}

	// 4. Test that cross-authentication fails
	_, err = AuthenticateUser(db, users[0].email, users[1].password)
	if err == nil {
		t.Error("Cross-user authentication should fail")
	}
}

// Test key management, ensuring keys are created once and loaded correctly.
func TestOpaqueServerKeyManagement(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()

	// 1. Initial server key setup
	err := SetupServerKeys(db)
	if err != nil {
		t.Fatalf("Failed to setup server keys on first call: %v", err)
	}
	firstKeys := serverKeys

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
	secondKeys := serverKeys

	// 4. Verify that the keys loaded on the second call are the same as the first
	if !crypto.SecureCompare(firstKeys.ServerSecretKey, secondKeys.ServerSecretKey) {
		t.Error("Server secret key should be consistent across loads")
	}
	if !crypto.SecureCompare(firstKeys.ServerPublicKey, secondKeys.ServerPublicKey) {
		t.Error("Server public key should be consistent across loads")
	}
	if !crypto.SecureCompare(firstKeys.OPRFSeed, secondKeys.OPRFSeed) {
		t.Error("OPRF seed should be consistent across loads")
	}
}
