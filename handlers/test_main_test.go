package handlers

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
	_ "github.com/mattn/go-sqlite3"
)

// TestMain initializes JWT Ed25519 keys (both tiers), TOTP master key, and config
// so that handler tests can call auth.GenerateFullAccessToken(),
// auth.GenerateTemporaryTOTPToken(), auth.ValidateTOTPCode(), etc. This follows
// the same pattern as auth/jwt_test.go TestMain.
func TestMain(m *testing.M) {
	// Reset config state
	config.ResetConfigForTest()

	// Initialize console-only loggers so handlers that call
	// logging.InfoLogger / logging.ErrorLogger don't panic on nil
	// loggers under the test binary. Matches the production startup.
	logging.InitFallbackConsoleLogging()

	// Setup in-memory SQLite DB for KeyManager (JWT key storage)
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to open in-memory DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create system_keys table (required by crypto.InitKeyManager).
	// Mirrors the production schema in database/unified_schema.sql so that
	// tests exercising bootstrap-token consumption (A-13) see the same
	// consumed_at column the production code writes to.
	_, err = db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			consumed_at TIMESTAMP
		);
	`)
	if err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to create system_keys table: %v\n", err)
		os.Exit(1)
	}

	// Set Master Key for KeyManager (same test key as auth/jwt_test.go)
	masterKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	os.Setenv("ARKFILE_MASTER_KEY", masterKey)

	// Initialize KeyManager (enables JWT key generation/storage)
	if err := crypto.InitKeyManager(db); err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to initialize KeyManager: %v\n", err)
		os.Exit(1)
	}

	// Initialize TOTP master key (uses KeyManager, not file-based keys)
	if err := crypto.InitializeTOTPMasterKey(); err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to initialize TOTP master key: %v\n", err)
		os.Exit(1)
	}

	// Set env vars for config.LoadConfig()
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"STORAGE_PROVIDER_1":         "generic-s3",
		"STORAGE_1_ENDPOINT":         "http://localhost:9332",
		"STORAGE_1_ACCESS_KEY":       "test-user-handlers",
		"STORAGE_1_SECRET_KEY":       "test-password-handlers",
		"STORAGE_1_BUCKET":           "test-bucket-handlers",
		"LOCAL_STORAGE_PATH":         "/tmp/test-storage-handlers",
		"JWT_TOKEN_LIFETIME_MINUTES": "1440",
		"DEBUG_MODE":                 "true",
	}

	for key, testValue := range testEnv {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, testValue)
	}

	// Load config
	if _, err := config.LoadConfig(); err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Reset JWT signing keys (generates fresh Ed25519 keypair)
	auth.ResetKeysForTest()

	// Run all tests
	exitCode := m.Run()

	// Cleanup
	os.Unsetenv("ARKFILE_MASTER_KEY")
	for key, originalValue := range originalEnv {
		if originalValue == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, originalValue)
		}
	}
	config.ResetConfigForTest()

	os.Exit(exitCode)
}
