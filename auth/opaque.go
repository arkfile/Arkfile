//go:build !js && !wasm

package auth

/*
#cgo CFLAGS: -I../vendor/aldenml/ecc/src -I../vendor/aldenml/ecc/build/libsodium/include
#cgo LDFLAGS: -L../vendor/aldenml/ecc/build -L../vendor/aldenml/ecc/build/libsodium/lib -lecc_static -lsodium
#include <stdlib.h>
#include "../vendor/aldenml/ecc/src/opaque.h"
*/
import "C"

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
	"unsafe"

	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/logging"
)

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

// serverKeys holds the loaded server keys for reuse.
var serverKeys *OPAQUEServerKeys

// SetupServerKeys generates and stores server key material if it doesn't already exist.
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

	// Keys don't exist, so generate, store, and load them
	privateKey := make([]byte, C.ecc_opaque_ristretto255_sha512_Nsk)
	publicKey := make([]byte, C.ecc_opaque_ristretto255_sha512_Npk)
	oprfSeed := crypto.GenerateRandomBytes(C.ecc_opaque_ristretto255_sha512_Nh)

	C.ecc_opaque_ristretto255_sha512_GenerateAuthKeyPair(
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)

	_, err = db.Exec(`
		INSERT INTO opaque_server_keys (id, server_secret_key, server_public_key, oprf_seed)
		VALUES (1, ?, ?, ?)`,
		hex.EncodeToString(privateKey), hex.EncodeToString(publicKey), hex.EncodeToString(oprfSeed),
	)
	if err != nil {
		return fmt.Errorf("failed to store new server keys: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Println("Generated and stored new OPAQUE server keys")
	}

	// After storing, load the keys into the global variable
	return loadServerKeys(db)
}

// loadServerKeys loads the server's OPAQUE keys from the database into memory.
func loadServerKeys(db *sql.DB) error {
	var secretKeyHex, publicKeyHex, oprfSeedHex string
	err := db.QueryRow("SELECT server_secret_key, server_public_key, oprf_seed FROM opaque_server_keys WHERE id = 1").Scan(&secretKeyHex, &publicKeyHex, &oprfSeedHex)
	if err != nil {
		return fmt.Errorf("failed to retrieve server keys from database: %w", err)
	}

	secretKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode server secret key: %w", err)
	}

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode server public key: %w", err)
	}

	oprfSeed, err := hex.DecodeString(oprfSeedHex)
	if err != nil {
		return fmt.Errorf("failed to decode OPRF seed: %w", err)
	}

	serverKeys = &OPAQUEServerKeys{
		ServerSecretKey: secretKey,
		ServerPublicKey: publicKey,
		OPRFSeed:        oprfSeed,
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Println("Loaded OPAQUE server keys into memory")
	}

	return nil
}

// RegisterUser performs the OPAQUE registration flow.
func RegisterUser(db *sql.DB, email, password string) error {
	if serverKeys == nil {
		return fmt.Errorf("server keys not loaded")
	}

	// Client-side registration simulation
	// In a real application, this would be on the client device.
	passwordBytes := []byte(password)
	blind := make([]byte, C.ecc_opaque_ristretto255_sha512_Ns)
	request := make([]byte, C.ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE)

	cPassword := C.CBytes(passwordBytes)
	defer C.free(cPassword)

	C.ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
		(*C.uchar)(unsafe.Pointer(&request[0])),
		(*C.uchar)(unsafe.Pointer(&blind[0])),
		(*C.uchar)(cPassword),
		C.int(len(passwordBytes)),
	)

	// Server-side registration
	response := make([]byte, C.ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE)
	cEmail := C.CBytes([]byte(email))
	defer C.free(cEmail)

	C.ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
		(*C.uchar)(unsafe.Pointer(&response[0])),
		(*C.uchar)(unsafe.Pointer(&request[0])),
		(*C.uchar)(unsafe.Pointer(&serverKeys.ServerPublicKey[0])),
		(*C.uchar)(cEmail),
		C.int(len(email)),
		(*C.uchar)(unsafe.Pointer(&serverKeys.OPRFSeed[0])),
	)

	// Client-side finalization
	record := make([]byte, C.ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE)
	exportKey := make([]byte, C.ecc_opaque_ristretto255_sha512_Nh)
	serverIdentity := []byte("arkfile-server")
	cServerIdentity := C.CBytes(serverIdentity)
	defer C.free(cServerIdentity)

	C.ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest(
		(*C.uchar)(unsafe.Pointer(&record[0])),
		(*C.uchar)(unsafe.Pointer(&exportKey[0])),
		(*C.uchar)(cPassword),
		C.int(len(passwordBytes)),
		(*C.uchar)(unsafe.Pointer(&blind[0])),
		(*C.uchar)(unsafe.Pointer(&response[0])),
		(*C.uchar)(cServerIdentity),
		C.int(len(serverIdentity)),
		(*C.uchar)(cEmail),
		C.int(len(email)),
		C.ecc_opaque_ristretto255_sha512_MHF_SCRYPT, // Using Scrypt as specified
		nil,
		0,
	)

	crypto.SecureZeroBytes(exportKey)

	// Store the registration record in the database
	userData := OPAQUEUserData{
		UserEmail:        email,
		SerializedRecord: record,
		CreatedAt:        time.Now(),
	}

	return storeOPAQUEUserData(db, userData)
}

// AuthenticateUser performs the OPAQUE authentication flow.
func AuthenticateUser(db *sql.DB, email, password string) ([]byte, error) {
	if serverKeys == nil {
		return nil, fmt.Errorf("server keys not loaded")
	}

	userData, err := loadOPAQUEUserData(db, email)
	if err != nil {
		return nil, fmt.Errorf("failed to load user data: %w", err)
	}

	// Client-side authentication simulation (KE1 generation)
	passwordBytes := []byte(password)
	cPassword := C.CBytes(passwordBytes)
	defer C.free(cPassword)
	clientState := make([]byte, C.ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE)
	ke1 := make([]byte, C.ecc_opaque_ristretto255_sha512_KE1SIZE)
	C.ecc_opaque_ristretto255_sha512_GenerateKE1(
		(*C.uchar)(unsafe.Pointer(&ke1[0])),
		(*C.uchar)(unsafe.Pointer(&clientState[0])),
		(*C.uchar)(cPassword),
		C.int(len(passwordBytes)),
	)

	// Server-side (KE2 generation)
	ke2 := make([]byte, C.ecc_opaque_ristretto255_sha512_KE2SIZE)
	serverState := make([]byte, C.ecc_opaque_ristretto255_sha512_SERVERSTATESIZE)
	cEmail := C.CBytes([]byte(email))
	defer C.free(cEmail)
	serverIdentity := []byte("arkfile-server")
	cServerIdentity := C.CBytes(serverIdentity)
	defer C.free(cServerIdentity)

	C.ecc_opaque_ristretto255_sha512_GenerateKE2(
		(*C.uchar)(unsafe.Pointer(&ke2[0])),
		(*C.uchar)(unsafe.Pointer(&serverState[0])),
		(*C.uchar)(cServerIdentity),
		C.int(len(serverIdentity)),
		(*C.uchar)(unsafe.Pointer(&serverKeys.ServerSecretKey[0])),
		(*C.uchar)(unsafe.Pointer(&serverKeys.ServerPublicKey[0])),
		(*C.uchar)(unsafe.Pointer(&userData.SerializedRecord[0])),
		(*C.uchar)(cEmail),
		C.int(len(email)),
		(*C.uchar)(unsafe.Pointer(&serverKeys.OPRFSeed[0])),
		(*C.uchar)(unsafe.Pointer(&ke1[0])),
		(*C.uchar)(cEmail),
		C.int(len(email)),
		nil, 0, // No extra context
	)

	// Client-side finalization (KE3 generation)
	ke3 := make([]byte, C.ecc_opaque_ristretto255_sha512_KE3SIZE)
	sessionKey := make([]byte, C.ecc_opaque_ristretto255_sha512_Nm)
	exportKey := make([]byte, C.ecc_opaque_ristretto255_sha512_Nh)

	result := C.ecc_opaque_ristretto255_sha512_GenerateKE3(
		(*C.uchar)(unsafe.Pointer(&ke3[0])),
		(*C.uchar)(unsafe.Pointer(&sessionKey[0])),
		(*C.uchar)(unsafe.Pointer(&exportKey[0])),
		(*C.uchar)(unsafe.Pointer(&clientState[0])),
		(*C.uchar)(cEmail),
		C.int(len(email)),
		(*C.uchar)(cServerIdentity),
		C.int(len(serverIdentity)),
		(*C.uchar)(unsafe.Pointer(&ke2[0])),
		C.ecc_opaque_ristretto255_sha512_MHF_SCRYPT,
		nil, 0,
		nil, 0,
	)

	crypto.SecureZeroBytes(exportKey)

	if result != 0 {
		return nil, fmt.Errorf("client-side authentication failed")
	}

	// Server-side validation
	serverSessionKey := make([]byte, C.ecc_opaque_ristretto255_sha512_Nm)
	result = C.ecc_opaque_ristretto255_sha512_ServerFinish(
		(*C.uchar)(unsafe.Pointer(&serverSessionKey[0])),
		(*C.uchar)(unsafe.Pointer(&serverState[0])),
		(*C.uchar)(unsafe.Pointer(&ke3[0])),
	)

	if result != 0 {
		return nil, fmt.Errorf("server-side authentication failed")
	}

	// Final check
	if !crypto.SecureCompare(sessionKey, serverSessionKey) {
		return nil, fmt.Errorf("session key mismatch")
	}

	return sessionKey, nil
}

// storeOPAQUEUserData stores user data with hex encoding for database compatibility.
func storeOPAQUEUserData(db *sql.DB, userData OPAQUEUserData) error {
	recordHex := hex.EncodeToString(userData.SerializedRecord)

	_, err := db.Exec(`
		INSERT INTO opaque_user_data (
			user_email, serialized_record, created_at
		) VALUES (?, ?, ?)
		ON CONFLICT(user_email) DO UPDATE SET
		serialized_record=excluded.serialized_record;`,
		userData.UserEmail, recordHex, userData.CreatedAt,
	)
	return err
}

// loadOPAQUEUserData loads user data from the database.
func loadOPAQUEUserData(db *sql.DB, email string) (*OPAQUEUserData, error) {
	userData := &OPAQUEUserData{}
	var recordHex string
	var createdAt sql.NullString // Use NullString to handle potential NULLs

	err := db.QueryRow("SELECT user_email, serialized_record, created_at FROM opaque_user_data WHERE user_email = ?", email).Scan(
		&userData.UserEmail, &recordHex, &createdAt,
	)

	if err != nil {
		return nil, fmt.Errorf("could not find user '%s': %w", email, err)
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

// GetOPAQUEServer returns a simple status check for OPAQUE server readiness
func GetOPAQUEServer() (bool, error) {
	// Since we're using pure OPAQUE with CGo, the "server" is always ready
	// if the package compiled successfully
	return true, nil
}

// ValidateOPAQUESetup validates that the OPAQUE setup is properly configured
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
