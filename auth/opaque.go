package auth

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/logging"
)

// OPAQUEProvider defines the interface for OPAQUE authentication operations.
// Static linking eliminates the need for mock implementations.
type OPAQUEProvider interface {
	// RegisterUser performs OPAQUE user registration, creating a new user record
	// from a password and server private key. Returns the user record and export key.
	RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error)

	// AuthenticateUser performs OPAQUE authentication using a password and stored
	// user record. Returns the export key on successful authentication.
	AuthenticateUser(password []byte, userRecord []byte) ([]byte, error)

	// IsAvailable returns true if the OPAQUE provider is ready for operations.
	IsAvailable() bool

	// GetServerKeys returns the server's public and private keys for OPAQUE operations.
	// These are used for user registration and server-side authentication.
	GetServerKeys() ([]byte, []byte, error)

	// GenerateServerKeys creates new server keys for OPAQUE operations.
	// This is typically called once during initial setup.
	GenerateServerKeys() ([]byte, []byte, error)
}

// Global provider instance - always uses real implementation with static linking
var provider OPAQUEProvider

// GetOPAQUEProvider returns the static OPAQUE provider.
func GetOPAQUEProvider() OPAQUEProvider {
	if provider == nil {
		provider = NewRealOPAQUEProvider()
	}
	return provider
}

// IsOPAQUEAvailable is a convenience function that checks if OPAQUE operations
// are available through the current provider.
func IsOPAQUEAvailable() bool {
	return GetOPAQUEProvider().IsAvailable()
}

// RealOPAQUEProvider wraps the existing OPAQUE implementation to match the interface
type RealOPAQUEProvider struct{}

// NewRealOPAQUEProvider creates a new real OPAQUE provider
func NewRealOPAQUEProvider() *RealOPAQUEProvider {
	return &RealOPAQUEProvider{}
}

// RegisterUser implements the OPAQUEProvider interface using real OPAQUE
func (r *RealOPAQUEProvider) RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
	// Use low-level libopaque registration function directly
	userRecord, exportKey, err := libopaqueRegisterUser(password, serverPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("OPAQUE registration failed: %v", err)
	}
	return userRecord, exportKey, nil
}

// AuthenticateUser implements the OPAQUEProvider interface using real OPAQUE
func (r *RealOPAQUEProvider) AuthenticateUser(password []byte, userRecord []byte) ([]byte, error) {
	// Use low-level libopaque authentication function directly
	exportKey, err := libopaqueAuthenticateUser(password, userRecord)
	if err != nil {
		return nil, fmt.Errorf("OPAQUE authentication failed: %v", err)
	}
	return exportKey, nil
}

// IsAvailable implements the OPAQUEProvider interface
func (r *RealOPAQUEProvider) IsAvailable() bool {
	// Check if OPAQUE is available (simple availability check)
	available, _ := GetOPAQUEServer()
	return available
}

// GetServerKeys implements the OPAQUEProvider interface
func (r *RealOPAQUEProvider) GetServerKeys() ([]byte, []byte, error) {
	// Check if server keys are loaded
	if serverKeys == nil {
		return nil, nil, fmt.Errorf("server keys not loaded")
	}
	return serverKeys.ServerPublicKey, serverKeys.ServerPrivateKey, nil
}

// GenerateServerKeys implements the OPAQUEProvider interface
func (r *RealOPAQUEProvider) GenerateServerKeys() ([]byte, []byte, error) {
	// Generate new server keys
	newKeys, err := generateOPAQUEServerKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server keys: %v", err)
	}
	return newKeys.ServerPublicKey, newKeys.ServerPrivateKey, nil
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

// RegisterUser performs the libopaque registration flow using the one-step method
func RegisterUser(db *sql.DB, username, password string) error {
	if serverKeys == nil {
		return fmt.Errorf("server keys not loaded")
	}

	// Validate inputs
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	passwordBytes := []byte(password)

	// Use libopaque's one-step registration with server private key
	userRecord, exportKey, err := libopaqueRegisterUser(passwordBytes, serverKeys.ServerPrivateKey)
	if err != nil {
		return fmt.Errorf("libopaque registration failed: %w", err)
	}

	// Clear the export key for security (we don't store it)
	crypto.SecureZeroBytes(exportKey)

	// Store the user record in the database
	userData := OPAQUEUserData{
		Username:         username,
		SerializedRecord: userRecord,
		CreatedAt:        time.Now(),
	}

	return storeOPAQUEUserData(db, userData)
}

// AuthenticateUser performs the libopaque authentication flow using the one-step method
func AuthenticateUser(db *sql.DB, username, password string) ([]byte, error) {
	if serverKeys == nil {
		return nil, fmt.Errorf("server keys not loaded")
	}

	userData, err := loadOPAQUEUserData(db, username)
	if err != nil {
		return nil, fmt.Errorf("failed to load user data: %w", err)
	}

	passwordBytes := []byte(password)

	// Use libopaque's one-step authentication
	sessionKey, err := libopaqueAuthenticateUser(passwordBytes, userData.SerializedRecord)
	if err != nil {
		return nil, fmt.Errorf("libopaque authentication failed: %w", err)
	}

	return sessionKey, nil
}

// storeOPAQUEUserData stores user data with hex encoding for database compatibility
func storeOPAQUEUserData(db *sql.DB, userData OPAQUEUserData) error {
	recordHex := hex.EncodeToString(userData.SerializedRecord)

	_, err := db.Exec(`
		INSERT INTO opaque_user_data (
			username, serialized_record, created_at
		) VALUES (?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
		serialized_record=excluded.serialized_record;`,
		userData.Username, recordHex, userData.CreatedAt,
	)
	return err
}

// loadOPAQUEUserData loads user data from the database
func loadOPAQUEUserData(db *sql.DB, username string) (*OPAQUEUserData, error) {
	userData := &OPAQUEUserData{}
	var recordHex string
	var createdAt sql.NullString // Use NullString to handle potential NULLs

	err := db.QueryRow("SELECT username, serialized_record, created_at FROM opaque_user_data WHERE username = ?", username).Scan(
		&userData.Username, &recordHex, &createdAt,
	)

	if err != nil {
		return nil, fmt.Errorf("could not find user '%s': %w", username, err)
	}

	userData.SerializedRecord, err = hex.DecodeString(recordHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode serialized record: %w", err)
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
