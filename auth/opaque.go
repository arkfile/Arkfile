package auth

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
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
var (
	serverKeys     *OPAQUEServerKeys
	opaqueKeysOnce sync.Once
	opaqueKeysErr  error
)

// SetupServerKeys generates and stores server key material if it doesn't already exist.
// This function is safe for multi-instance deployments - it uses sync.Once to ensure
// only one goroutine per instance attempts key generation, and handles INSERT conflicts
// gracefully when multiple instances race to create keys.
func SetupServerKeys(db *sql.DB) error {
	opaqueKeysOnce.Do(func() {
		km, err := crypto.GetKeyManager()
		if err != nil {
			opaqueKeysErr = fmt.Errorf("failed to get KeyManager: %w", err)
			return
		}

		// libsodium constants (32 bytes each)
		const (
			serverPrivateKeySize = 32 // crypto_scalarmult_SCALARBYTES
			serverPublicKeySize  = 32 // crypto_scalarmult_BYTES
			oprfSeedSize         = 32 // crypto_core_ristretto255_SCALARBYTES
		)

		// Get or generate keys using KeyManager
		// Note: In a real OPAQUE implementation, public key should be derived from private key.
		// However, preserving existing behavior of independent generation for now.

		serverPrivateKey, err := km.GetOrGenerateKey("opaque_server_private_key", "opaque", serverPrivateKeySize)
		if err != nil {
			opaqueKeysErr = fmt.Errorf("failed to get/generate opaque server private key: %w", err)
			return
		}

		serverPublicKey, err := km.GetOrGenerateKey("opaque_server_public_key", "opaque", serverPublicKeySize)
		if err != nil {
			opaqueKeysErr = fmt.Errorf("failed to get/generate opaque server public key: %w", err)
			return
		}

		oprfSeed, err := km.GetOrGenerateKey("opaque_oprf_seed", "opaque", oprfSeedSize)
		if err != nil {
			opaqueKeysErr = fmt.Errorf("failed to get/generate opaque oprf seed: %w", err)
			return
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
	})

	return opaqueKeysErr
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

	// Check opaque_user_data table exists
	_, err := db.Exec("SELECT 1 FROM opaque_user_data LIMIT 1")
	if err != nil {
		return fmt.Errorf("failed to access opaque_user_data table: %w", err)
	}

	return nil
}
