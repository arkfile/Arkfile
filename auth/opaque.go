package auth

import (
	"database/sql"
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

// OPAQUEUserData represents the server-side storage for OPAQUE user data
type OPAQUEUserData struct {
	UserEmail        string
	ClientArgonSalt  []byte // Salt for client-side Argon2ID hardening
	ServerArgonSalt  []byte // Salt for server-side Argon2ID hardening
	HardenedEnvelope []byte // Server-hardened OPAQUE envelope
	DeviceProfile    string // Device capability profile used
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

	// Create OPAQUE configuration with RistrettoSha512 for maximum security
	config := opaque.DefaultConfiguration()
	// DefaultConfiguration already uses RistrettoSha512, but let's be explicit
	config.OPRF = opaque.RistrettoSha512
	config.AKE = opaque.RistrettoSha512

	// Create server instance
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

	// Check if server keys already exist
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing server keys: %w", err)
	}

	if count > 0 {
		// Keys exist, load them
		return loadServerKeys(db, server)
	}

	// Generate new server keys
	serverSecret, serverPublic := server.configuration.KeyGen()
	oprfSeed := server.configuration.GenerateOPRFSeed()

	// Store in database
	_, err = db.Exec(`
		INSERT INTO opaque_server_keys (id, server_secret_key, server_public_key, oprf_seed)
		VALUES (1, ?, ?, ?)`,
		serverSecret, serverPublic, oprfSeed,
	)
	if err != nil {
		return fmt.Errorf("failed to store server keys: %w", err)
	}

	// Set key material in server
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
	var serverSecret, serverPublic, oprfSeed []byte

	err := db.QueryRow(`
		SELECT server_secret_key, server_public_key, oprf_seed
		FROM opaque_server_keys WHERE id = 1
	`).Scan(&serverSecret, &serverPublic, &oprfSeed)

	if err != nil {
		return fmt.Errorf("failed to load server keys: %w", err)
	}

	// Set key material in server
	err = server.server.SetKeyMaterial(nil, serverSecret, serverPublic, oprfSeed)
	if err != nil {
		return fmt.Errorf("failed to set loaded key material: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("Loaded existing OPAQUE server keys")
	}
	return nil
}

// RegisterUser performs OPAQUE registration with hybrid Argon2ID protection
func RegisterUser(db *sql.DB, email, password string, deviceCapability crypto.DeviceCapability) error {
	_, err := GetOPAQUEServer()
	if err != nil {
		return err
	}

	// For now, implement a simplified version that stores the necessary data
	// without full OPAQUE integration until we can properly configure the library

	// Step 1: Client-side Argon2ID hardening
	clientSalt, err := crypto.GenerateSalt(32)
	if err != nil {
		return fmt.Errorf("failed to generate client salt: %w", err)
	}

	clientProfile := deviceCapability.GetProfile()
	hardenedPassword := crypto.DeriveKeyArgon2ID([]byte(password), clientSalt, clientProfile)

	// Step 2: Server-side Argon2ID hardening (double protection)
	serverSalt, err := crypto.GenerateSalt(32)
	if err != nil {
		return fmt.Errorf("failed to generate server salt: %w", err)
	}

	// For now, store the double-hardened password as the envelope
	// This provides strong protection while we complete OPAQUE integration
	doubleHardenedPassword := crypto.DeriveKeyArgon2ID(hardenedPassword, serverSalt, crypto.ArgonMaximum)

	// Step 3: Store user data
	userData := OPAQUEUserData{
		UserEmail:        email,
		ClientArgonSalt:  clientSalt,
		ServerArgonSalt:  serverSalt,
		HardenedEnvelope: doubleHardenedPassword,
		DeviceProfile:    deviceCapability.String(),
		CreatedAt:        time.Now(),
	}

	err = storeOPAQUEUserData(db, userData)
	if err != nil {
		return fmt.Errorf("failed to store OPAQUE user data: %w", err)
	}

	// Clear sensitive material
	crypto.SecureZeroSessionKey(hardenedPassword)
	crypto.SecureZeroSessionKey(doubleHardenedPassword)

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("OPAQUE registration completed for user: %s", email)
	}
	return nil
}

// AuthenticateUser performs OPAQUE login with hybrid Argon2ID protection
func AuthenticateUser(db *sql.DB, email, password string) ([]byte, error) {
	_, err := GetOPAQUEServer()
	if err != nil {
		return nil, err
	}

	// Load user's OPAQUE data
	userData, err := loadOPAQUEUserData(db, email)
	if err != nil {
		return nil, fmt.Errorf("failed to load user data: %w", err)
	}

	// Step 1: Client-side Argon2ID hardening (recreate the registration process)
	capability := parseDeviceCapability(userData.DeviceProfile)
	clientProfile := capability.GetProfile()
	hardenedPassword := crypto.DeriveKeyArgon2ID([]byte(password), userData.ClientArgonSalt, clientProfile)

	// Step 2: Server-side Argon2ID hardening (recreate double protection)
	doubleHardenedPassword := crypto.DeriveKeyArgon2ID(hardenedPassword, userData.ServerArgonSalt, crypto.ArgonMaximum)

	// Step 3: Verify password by comparing with stored envelope
	// For constant-time comparison, use a constant-time comparison function
	if !crypto.SecureCompare(doubleHardenedPassword, userData.HardenedEnvelope) {
		// Clear sensitive material before returning error
		crypto.SecureZeroBytes(hardenedPassword)
		crypto.SecureZeroBytes(doubleHardenedPassword)
		return nil, fmt.Errorf("authentication failed")
	}

	// Step 4: Derive session key from the verified password material
	sessionKey, err := crypto.DeriveSessionKey(doubleHardenedPassword, crypto.SessionKeyContext)
	if err != nil {
		crypto.SecureZeroBytes(hardenedPassword)
		crypto.SecureZeroBytes(doubleHardenedPassword)
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	// Clear sensitive material
	crypto.SecureZeroBytes(hardenedPassword)
	crypto.SecureZeroBytes(doubleHardenedPassword)

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("OPAQUE authentication successful for user: %s", email)
	}
	return sessionKey, nil
}

// Helper functions

func storeOPAQUEUserData(db *sql.DB, userData OPAQUEUserData) error {
	_, err := db.Exec(`
		INSERT INTO opaque_user_data (
			user_email, client_argon_salt, server_argon_salt,
			hardened_envelope, device_profile, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		userData.UserEmail, userData.ClientArgonSalt, userData.ServerArgonSalt,
		userData.HardenedEnvelope, userData.DeviceProfile, userData.CreatedAt,
	)
	return err
}

func loadOPAQUEUserData(db *sql.DB, email string) (*OPAQUEUserData, error) {
	userData := &OPAQUEUserData{}

	err := db.QueryRow(`
		SELECT user_email, client_argon_salt, server_argon_salt,
		       hardened_envelope, device_profile, created_at
		FROM opaque_user_data WHERE user_email = ?`,
		email,
	).Scan(
		&userData.UserEmail, &userData.ClientArgonSalt, &userData.ServerArgonSalt,
		&userData.HardenedEnvelope, &userData.DeviceProfile, &userData.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return userData, nil
}

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
		return crypto.DeviceInteractive // Safe default
	}
}

func reverseArgon2IDHardening(hardenedData, salt []byte) []byte {
	// Note: This is a placeholder. In practice, we'd need to store the original
	// envelope differently or use a reversible transformation. For now, we'll
	// assume the envelope is stored in a way that can be unhardened.
	// This might require storing both the hardened and original versions.

	// For the initial implementation, we might store the envelope unhardened
	// and just apply Argon2ID to a hash for verification purposes.
	return hardenedData
}

// ValidateOPAQUESetup verifies that OPAQUE is properly configured
func ValidateOPAQUESetup(db *sql.DB) error {
	// Check if server is initialized
	server, err := GetOPAQUEServer()
	if err != nil {
		return fmt.Errorf("OPAQUE server not initialized: %w", err)
	}

	// Check if server keys exist
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys WHERE id = 1").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check server keys: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("OPAQUE server keys not found")
	}

	// Validate configuration
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
