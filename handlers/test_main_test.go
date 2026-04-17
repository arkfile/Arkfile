package handlers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

// TestMain initializes JWT Ed25519 keys, TOTP master key, and config
// so that handler tests can call auth.GenerateToken(), auth.GenerateFullAccessToken(),
// auth.ValidateTOTPCode(), etc. This follows the same pattern as auth/jwt_test.go TestMain.
func TestMain(m *testing.M) {
	// Reset config state
	config.ResetConfigForTest()

	// Setup in-memory SQLite DB for KeyManager (JWT key storage)
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to open in-memory DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create system_keys table (required by crypto.InitKeyManager)
	_, err = db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

	// Setup TOTP master key
	tempDir, err := os.MkdirTemp("", "handlers-test-totp-*")
	if err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	keyPath := filepath.Join(tempDir, "totp_master.key")
	os.Setenv("TOTP_MASTER_KEY_PATH", keyPath)

	if err := crypto.InitializeTOTPMasterKey(); err != nil {
		fmt.Printf("FATAL: handlers TestMain: Failed to initialize TOTP master key: %v\n", err)
		os.Exit(1)
	}

	// Set env vars for config.LoadConfig()
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"STORAGE_PROVIDER":           "generic-s3",
		"S3_ENDPOINT":                "http://localhost:9332",
		"S3_ACCESS_KEY":              "test-user-handlers",
		"S3_SECRET_KEY":              "test-password-handlers",
		"S3_BUCKET":                  "test-bucket-handlers",
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
	os.Unsetenv("TOTP_MASTER_KEY_PATH")
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
