package auth

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
)

// GetServerKeys returns the server's public and private keys for OPAQUE operations.
func GetServerKeys() ([]byte, []byte, error) {
	if serverKeys == nil {
		return nil, nil, fmt.Errorf("server keys not loaded")
	}
	return serverKeys.ServerPublicKey, serverKeys.ServerPrivateKey, nil
}

// IsOPAQUEAvailable checks if OPAQUE operations are available
func IsOPAQUEAvailable() bool {
	available, _ := GetOPAQUEServer()
	return available
}

// OPAQUEUserData represents the server-side storage for libopaque user data
type OPAQUEUserData struct {
	Username         string
	SerializedRecord []byte // libopaque user record
	CreatedAt        time.Time
}

// OPAQUEServerKeys represents the server's long-term key material for libopaque
type OPAQUEServerKeys struct {
	ServerPrivateKey []byte // 32-byte server private key (crypto_scalarmult_SCALARBYTES)
	ServerPublicKey  []byte // 32-byte server public key (crypto_scalarmult_BYTES)
	OPRFSeed         []byte // 32-byte OPRF seed (crypto_core_ristretto255_SCALARBYTES)
	CreatedAt        time.Time
}

// serverKeys holds the loaded server keys for reuse
var serverKeys *OPAQUEServerKeys

// generateOPAQUEServerKeys generates cryptographically secure server keys for OPAQUE
func generateOPAQUEServerKeys() (*OPAQUEServerKeys, error) {
	// libsodium constants (32 bytes each)
	const (
		serverPrivateKeySize = 32 // crypto_scalarmult_SCALARBYTES
		serverPublicKeySize  = 32 // crypto_scalarmult_BYTES
		oprfSeedSize         = 32 // crypto_core_ristretto255_SCALARBYTES
	)

	// Generate server private key (32 bytes)
	serverPrivateKey := crypto.GenerateRandomBytes(serverPrivateKeySize)

	// Generate server public key (32 bytes)
	serverPublicKey := crypto.GenerateRandomBytes(serverPublicKeySize)

	// Generate OPRF seed (32 bytes)
	oprfSeed := crypto.GenerateRandomBytes(oprfSeedSize)

	return &OPAQUEServerKeys{
		ServerPrivateKey: serverPrivateKey,
		ServerPublicKey:  serverPublicKey,
		OPRFSeed:         oprfSeed,
		CreatedAt:        time.Now(),
	}, nil
}

// SetupServerKeys generates and stores server key material if it doesn't already exist
func SetupServerKeys(db *sql.DB) error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing server keys: %w", err)
	}

	if count > 0 {
		// Keys already exist, load them
		return loadServerKeys(db)
	}

	// Generate cryptographically secure server keys
	serverKeys, err := generateOPAQUEServerKeys()
	if err != nil {
		return fmt.Errorf("failed to generate server keys: %w", err)
	}

	// Store the keys in the database
	_, err = db.Exec(`
		INSERT INTO opaque_server_keys (id, server_secret_key, server_public_key, oprf_seed)
		VALUES (1, ?, ?, ?)`,
		hex.EncodeToString(serverKeys.ServerPrivateKey),
		hex.EncodeToString(serverKeys.ServerPublicKey),
		hex.EncodeToString(serverKeys.OPRFSeed),
	)
	if err != nil {
		return fmt.Errorf("failed to store new server keys: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Println("Generated and stored new OPAQUE server keys")
	}

	return loadServerKeys(db)
}

// loadServerKeys loads the server's OPAQUE configuration from the database
func loadServerKeys(db *sql.DB) error {
	var secretKeyHex, publicKeyHex, oprfSeedHex string
	err := db.QueryRow("SELECT server_secret_key, server_public_key, oprf_seed FROM opaque_server_keys WHERE id = 1").Scan(&secretKeyHex, &publicKeyHex, &oprfSeedHex)
	if err != nil {
		return fmt.Errorf("failed to retrieve server keys from database: %w", err)
	}

	// Decode the cryptographic keys
	serverPrivateKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode server private key: %w", err)
	}

	serverPublicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode server public key: %w", err)
	}

	oprfSeed, err := hex.DecodeString(oprfSeedHex)
	if err != nil {
		return fmt.Errorf("failed to decode OPRF seed: %w", err)
	}

	serverKeys = &OPAQUEServerKeys{
		ServerPrivateKey: serverPrivateKey,
		ServerPublicKey:  serverPublicKey,
		OPRFSeed:         oprfSeed,
		CreatedAt:        time.Now(),
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Println("Loaded OPAQUE server keys into memory")
	}

	return nil
}

// storeOPAQUEUserData stores user data with hex encoding for database compatibility
func storeOPAQUEUserData(db *sql.DB, userData OPAQUEUserData) error {
	recordHex := hex.EncodeToString(userData.SerializedRecord)

	_, err := db.Exec(`
		INSERT INTO opaque_user_data (
			username, opaque_user_record, created_at
		) VALUES (?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
		opaque_user_record=excluded.opaque_user_record;`,
		userData.Username, recordHex, userData.CreatedAt,
	)
	return err
}

// loadOPAQUEUserData loads user data from the database
func loadOPAQUEUserData(db *sql.DB, username string) (*OPAQUEUserData, error) {
	userData := &OPAQUEUserData{}
	var recordHex string
	var createdAt sql.NullString // Use NullString to handle potential NULLs

	err := db.QueryRow("SELECT username, opaque_user_record, created_at FROM opaque_user_data WHERE username = ?", username).Scan(
		&userData.Username, &recordHex, &createdAt,
	)

	if err != nil {
		return nil, fmt.Errorf("could not find user '%s': %w", username, err)
	}

	userData.SerializedRecord, err = hex.DecodeString(recordHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode opaque user record: %w", err)
	}

	if createdAt.Valid {
		userData.CreatedAt, err = time.Parse(time.RFC3339, createdAt.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse 'created_at': %w", err)
		}
	}

	return userData, nil
}

// GetOPAQUEServer returns a simple status check for libopaque server readiness
func GetOPAQUEServer() (bool, error) {
	// Since we're using libopaque with CGo, the "server" is always ready
	// if the package compiled successfully
	return true, nil
}

// ValidateOPAQUESetup validates that the libopaque setup is properly configured
func ValidateOPAQUESetup(db *sql.DB) error {
	// Check if server keys are loaded
	if serverKeys == nil {
		return SetupServerKeys(db)
	}

	// Validate that we can access the database tables
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to access opaque_server_keys table: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("no server keys found in database")
	}

	// Check opaque_user_data table exists
	_, err = db.Exec("SELECT 1 FROM opaque_user_data LIMIT 1")
	if err != nil {
		return fmt.Errorf("failed to access opaque_user_data table: %w", err)
	}

	return nil
}
