package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
)

// DefaultOpaqueServerID is the OPAQUE server identity (idS) used when no
// deployment domain is resolved. Config normally always sets Server.Domain
// (ARKFILE_DOMAIN, else BASE_URL host, else "localhost"), so this is a
// defensive fallback that matches the config-level "localhost" default to keep
// local and dev deployments authenticating deterministically.
const DefaultOpaqueServerID = "localhost"

// OpaqueServerID returns the OPAQUE server identity (idS) bound into the
// protocol transcript. It is the deployment domain when configured, otherwise
// DefaultOpaqueServerID. All OPAQUE participants (server, browser, CLI) must
// use the exact same value, so the browser and CLI fetch it from the server
// via GET /api/config/opaque rather than hardcoding it.
func OpaqueServerID() string {
	if cfg, err := config.LoadConfig(); err == nil {
		if d := strings.TrimSpace(cfg.Server.Domain); d != "" {
			return d
		}
	}
	return DefaultOpaqueServerID
}

// DeriveFakeUserRecord deterministically generates a fake 256-byte OPAQUE user record for a non-existent username
func DeriveFakeUserRecord(username string) ([]byte, error) {
	if serverKeys == nil || len(serverKeys.OPRFSeed) == 0 {
		return nil, fmt.Errorf("opaque server keys not loaded")
	}

	info := []byte("arkfile-fake-user-record:" + username)
	reader := hkdf.Expand(sha256.New, serverKeys.OPRFSeed, info)

	fakeRecord := make([]byte, OPAQUE_USER_RECORD_LEN)
	if _, err := io.ReadFull(reader, fakeRecord); err != nil {
		return nil, fmt.Errorf("failed to expand fake user record: %w", err)
	}

	return fakeRecord, nil
}

// GetServerPrivateKey returns the server's OPAQUE private key. libopaque derives
// the matching public key from this private key during the protocol, so there is
// no separate stored public key.
func GetServerPrivateKey() ([]byte, error) {
	if serverKeys == nil {
		return nil, fmt.Errorf("server keys not loaded")
	}
	return serverKeys.ServerPrivateKey, nil
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
			oprfSeedSize         = 32 // crypto_core_ristretto255_SCALARBYTES
		)

		// Only the private key and OPRF seed are persisted. libopaque derives
		// the server public key from the private key during the protocol, so
		// there is no separate public key to generate or store.
		serverPrivateKey, err := km.GetOrGenerateKey("opaque_server_private_key", "opaque", serverPrivateKeySize)
		if err != nil {
			opaqueKeysErr = fmt.Errorf("failed to get/generate opaque server private key: %w", err)
			return
		}

		oprfSeed, err := km.GetOrGenerateKey("opaque_oprf_seed", "opaque", oprfSeedSize)
		if err != nil {
			opaqueKeysErr = fmt.Errorf("failed to get/generate opaque oprf seed: %w", err)
			return
		}

		serverKeys = &OPAQUEServerKeys{
			ServerPrivateKey: serverPrivateKey,
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
