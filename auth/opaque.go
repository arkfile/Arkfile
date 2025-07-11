package auth

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/logging"
	"github.com/bytemare/opaque"
)

// OPAQUEServer holds the OPAQUE server instance and configuration
type OPAQUEServer struct {
	server        *opaque.Server
	configuration *opaque.Configuration
	initialized   bool
}

// OPAQUEUserData represents the server-side storage for pure OPAQUE user data
type OPAQUEUserData struct {
	UserEmail        string
	SerializedRecord []byte // Serialized OPAQUE RegistrationRecord
	CreatedAt        time.Time
}

// OPAQUEServerKeys represents the server's long-term key material
type OPAQUEServerKeys struct {
	ServerSecretKey []byte
	ServerPublicKey []byte
	OPRFSeed        []byte
	CreatedAt       time.Time
}

// Global OPAQUE server instance
var globalOPAQUEServer *OPAQUEServer

// InitializeOPAQUEServer initializes the global OPAQUE server with RistrettoSha512
func InitializeOPAQUEServer() error {
	if globalOPAQUEServer != nil && globalOPAQUEServer.initialized {
		return nil // Already initialized
	}

	config := opaque.DefaultConfiguration()
	config.Context = []byte("arkfile-v1") // Add domain separation
	config.OPRF = opaque.RistrettoSha512
	config.AKE = opaque.RistrettoSha512

	server, err := config.Server()
	if err != nil {
		return fmt.Errorf("failed to create OPAQUE server: %w", err)
	}

	globalOPAQUEServer = &OPAQUEServer{
		server:        server,
		configuration: config,
		initialized:   true,
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("OPAQUE server initialized with RistrettoSha512")
	}
	return nil
}

// GetOPAQUEServer returns the global OPAQUE server instance
func GetOPAQUEServer() (*OPAQUEServer, error) {
	if globalOPAQUEServer == nil || !globalOPAQUEServer.initialized {
		if err := InitializeOPAQUEServer(); err != nil {
			return nil, err
		}
	}
	return globalOPAQUEServer, nil
}

// SetupServerKeys generates and stores server key material if not exists
func SetupServerKeys(db *sql.DB) error {
	server, err := GetOPAQUEServer()
	if err != nil {
		return err
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing server keys: %w", err)
	}

	if count > 0 {
		return loadServerKeys(db, server)
	}

	serverSecret, serverPublic := server.configuration.KeyGen()
	oprfSeed := server.configuration.GenerateOPRFSeed()

	_, err = db.Exec(`
		INSERT INTO opaque_server_keys (id, server_secret_key, server_public_key, oprf_seed)
		VALUES (1, ?, ?, ?)`,
		hex.EncodeToString(serverSecret), hex.EncodeToString(serverPublic), hex.EncodeToString(oprfSeed),
	)
	if err != nil {
		return fmt.Errorf("failed to store server keys: %w", err)
	}

	err = server.server.SetKeyMaterial(nil, serverSecret, serverPublic, oprfSeed)
	if err != nil {
		return fmt.Errorf("failed to set server key material: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("Generated and stored new OPAQUE server keys")
	}
	return nil
}

// loadServerKeys loads existing server keys from database
func loadServerKeys(db *sql.DB, server *OPAQUEServer) error {
	var serverSecretStr, serverPublicStr, oprfSeedStr string

	err := db.QueryRow(`
		SELECT server_secret_key, server_public_key, oprf_seed
		FROM opaque_server_keys WHERE id = 1
	`).Scan(&serverSecretStr, &serverPublicStr, &oprfSeedStr)
	if err != nil {
		return fmt.Errorf("failed to load server keys: %w", err)
	}

	serverSecret, err := hex.DecodeString(serverSecretStr)
	if err != nil {
		return fmt.Errorf("failed to decode server secret key: %w", err)
	}

	serverPublic, err := hex.DecodeString(serverPublicStr)
	if err != nil {
		return fmt.Errorf("failed to decode server public key: %w", err)
	}

	oprfSeed, err := hex.DecodeString(oprfSeedStr)
	if err != nil {
		return fmt.Errorf("failed to decode OPRF seed: %w", err)
	}

	err = server.server.SetKeyMaterial(nil, serverSecret, serverPublic, oprfSeed)
	if err != nil {
		return fmt.Errorf("failed to set loaded key material: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("Loaded existing OPAQUE server keys")
	}
	return nil
}

// RegisterUser performs pure OPAQUE registration using stateless approach
func RegisterUser(db *sql.DB, email, password string) error {
	// Create fresh configuration for this registration session
	config := opaque.DefaultConfiguration()
	config.Context = []byte("arkfile-v1")
	config.OPRF = opaque.RistrettoSha512
	config.AKE = opaque.RistrettoSha512

	// Create fresh client and server instances for registration
	client, err := config.Client()
	if err != nil {
		return err
	}

	server, err := config.Server()
	if err != nil {
		return err
	}

	// Load server keys from database
	var serverSecretStr, serverPublicStr, oprfSeedStr string
	err = db.QueryRow(`
		SELECT server_secret_key, server_public_key, oprf_seed
		FROM opaque_server_keys WHERE id = 1
	`).Scan(&serverSecretStr, &serverPublicStr, &oprfSeedStr)
	if err != nil {
		return fmt.Errorf("failed to load server keys for registration: %w", err)
	}

	serverSecret, err := hex.DecodeString(serverSecretStr)
	if err != nil {
		return fmt.Errorf("failed to decode server secret key: %w", err)
	}

	serverPublic, err := hex.DecodeString(serverPublicStr)
	if err != nil {
		return fmt.Errorf("failed to decode server public key: %w", err)
	}

	oprfSeed, err := hex.DecodeString(oprfSeedStr)
	if err != nil {
		return fmt.Errorf("failed to decode OPRF seed: %w", err)
	}

	// Set server key material with proper server identity
	err = server.SetKeyMaterial([]byte("arkfile-server"), serverSecret, serverPublic, oprfSeed)
	if err != nil {
		return fmt.Errorf("failed to set server key material: %w", err)
	}

	// Start registration process
	req := client.RegistrationInit([]byte(password))

	deserializer, err := config.Deserializer()
	if err != nil {
		return err
	}

	serverPub, err := deserializer.DecodeAkePublicKey(serverPublic)
	if err != nil {
		return err
	}

	resp := server.RegistrationResponse(req, serverPub, []byte(email), oprfSeed)

	record, exportKey := client.RegistrationFinalize(resp, opaque.ClientRegistrationFinalizeOptions{
		ClientIdentity: []byte(email),
		ServerIdentity: []byte("arkfile-server"),
	})

	serializedRecord := record.Serialize()

	userData := OPAQUEUserData{
		UserEmail:        email,
		SerializedRecord: serializedRecord,
		CreatedAt:        time.Now(),
	}

	err = storeOPAQUEUserData(db, userData)
	if err != nil {
		crypto.SecureZeroBytes(exportKey)
		return err
	}

	// Secure cleanup
	crypto.SecureZeroBytes(exportKey)
	return nil
}

// AuthenticateUser performs pure OPAQUE authentication using stateless approach
func AuthenticateUser(db *sql.DB, email, password string) ([]byte, error) {
	userData, err := loadOPAQUEUserData(db, email)
	if err != nil {
		return nil, err
	}

	// Create fresh configuration for this authentication session to avoid state conflicts
	config := opaque.DefaultConfiguration()
	config.Context = []byte("arkfile-v1")
	config.OPRF = opaque.RistrettoSha512
	config.AKE = opaque.RistrettoSha512

	// Create fresh client and server instances
	client, err := config.Client()
	if err != nil {
		return nil, err
	}

	server, err := config.Server()
	if err != nil {
		return nil, err
	}

	// Load server keys from database
	var serverSecretStr, serverPublicStr, oprfSeedStr string
	err = db.QueryRow(`
		SELECT server_secret_key, server_public_key, oprf_seed
		FROM opaque_server_keys WHERE id = 1
	`).Scan(&serverSecretStr, &serverPublicStr, &oprfSeedStr)
	if err != nil {
		return nil, fmt.Errorf("failed to load server keys: %w", err)
	}

	serverSecret, err := hex.DecodeString(serverSecretStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server secret key: %w", err)
	}

	serverPublic, err := hex.DecodeString(serverPublicStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server public key: %w", err)
	}

	oprfSeed, err := hex.DecodeString(oprfSeedStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode OPRF seed: %w", err)
	}

	// Set server key material with proper server identity
	err = server.SetKeyMaterial([]byte("arkfile-server"), serverSecret, serverPublic, oprfSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to set server key material: %w", err)
	}

	// Start login process
	ke1 := client.LoginInit([]byte(password))

	deserializer, err := config.Deserializer()
	if err != nil {
		return nil, err
	}

	registrationRecord, err := deserializer.RegistrationRecord(userData.SerializedRecord)
	if err != nil {
		return nil, err
	}

	clientRecord := &opaque.ClientRecord{
		RegistrationRecord:   registrationRecord,
		CredentialIdentifier: []byte(email),
	}

	ke2, err := server.LoginInit(ke1, clientRecord)
	if err != nil {
		return nil, err
	}

	ke3, exportKey, err := client.LoginFinish(ke2, opaque.ClientLoginFinishOptions{
		ClientIdentity: []byte(email),
		ServerIdentity: []byte("arkfile-server"),
	})
	if err != nil {
		return nil, err
	}

	err = server.LoginFinish(ke3)
	if err != nil {
		return nil, err
	}

	clientSessionKey := client.SessionKey()
	serverSessionKey := server.SessionKey()

	// Verify session keys match
	if !crypto.SecureCompare(clientSessionKey, serverSessionKey) {
		crypto.SecureZeroBytes(exportKey)
		return nil, fmt.Errorf("session key mismatch")
	}

	crypto.SecureZeroBytes(exportKey)
	return clientSessionKey, nil
}

// storeOPAQUEUserData stores user data with hex encoding
func storeOPAQUEUserData(db *sql.DB, userData OPAQUEUserData) error {
	recordHex := hex.EncodeToString(userData.SerializedRecord)

	_, err := db.Exec(`
		INSERT INTO opaque_user_data (
			user_email, serialized_record, created_at
		) VALUES (?, ?, ?)`,
		userData.UserEmail, recordHex, userData.CreatedAt,
	)
	return err
}

// loadOPAQUEUserData loads user data from DB
func loadOPAQUEUserData(db *sql.DB, email string) (*OPAQUEUserData, error) {
	userData := &OPAQUEUserData{}

	var recordStr, createdAtStr string

	err := db.QueryRow(`
		SELECT user_email, serialized_record, created_at
		FROM opaque_user_data WHERE user_email = ?`,
		email,
	).Scan(
		&userData.UserEmail, &recordStr, &createdAtStr,
	)

	if err != nil {
		return nil, err
	}

	userData.SerializedRecord, err = hex.DecodeString(recordStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode serialized record: %w", err)
	}

	userData.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	return userData, nil
}

// loadServerKeysForInstance loads server keys for a specific server instance
func loadServerKeysForInstance(db *sql.DB, server *opaque.Server) error {
	var serverSecretStr, serverPublicStr, oprfSeedStr string

	err := db.QueryRow(`
		SELECT server_secret_key, server_public_key, oprf_seed
		FROM opaque_server_keys WHERE id = 1
	`).Scan(&serverSecretStr, &serverPublicStr, &oprfSeedStr)
	if err != nil {
		return fmt.Errorf("failed to load server keys: %w", err)
	}

	serverSecret, err := hex.DecodeString(serverSecretStr)
	if err != nil {
		return fmt.Errorf("failed to decode server secret key: %w", err)
	}

	serverPublic, err := hex.DecodeString(serverPublicStr)
	if err != nil {
		return fmt.Errorf("failed to decode server public key: %w", err)
	}

	oprfSeed, err := hex.DecodeString(oprfSeedStr)
	if err != nil {
		return fmt.Errorf("failed to decode OPRF seed: %w", err)
	}

	err = server.SetKeyMaterial(nil, serverSecret, serverPublic, oprfSeed)
	if err != nil {
		return fmt.Errorf("failed to set loaded key material: %w", err)
	}

	return nil
}

// parseDeviceCapability parses string to DeviceCapability
func parseDeviceCapability(profile string) crypto.DeviceCapability {
	switch profile {
	case "minimal":
		return crypto.DeviceMinimal
	case "interactive":
		return crypto.DeviceInteractive
	case "balanced":
		return crypto.DeviceBalanced
	case "maximum":
		return crypto.DeviceMaximum
	default:
		return crypto.DeviceInteractive
	}
}

// ValidateOPAQUESetup verifies that OPAQUE is properly configured
func ValidateOPAQUESetup(db *sql.DB) error {
	server, err := GetOPAQUEServer()
	if err != nil {
		return fmt.Errorf("OPAQUE server not initialized: %w", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check server keys: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("OPAQUE server keys not found")
	}

	if server.configuration.OPRF != opaque.RistrettoSha512 {
		return fmt.Errorf("unexpected OPRF configuration")
	}

	if server.configuration.AKE != opaque.RistrettoSha512 {
		return fmt.Errorf("unexpected AKE configuration")
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("OPAQUE setup validation successful")
	}
	return nil
}
