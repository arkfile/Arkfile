package auth

/*
#cgo CFLAGS: -I../vendor/stef/libopaque/src -I../vendor/stef/liboprf/src
#cgo LDFLAGS: -L../vendor/stef/libopaque/src -L../vendor/stef/liboprf/src -lopaque -loprf -static
#cgo pkg-config: libsodium
#include "opaque_wrapper.h"
#include <stdlib.h>
*/
import "C"
import (
	"database/sql"
	"fmt"
	"time"
	"unsafe"

	"github.com/google/uuid"
)

// Multi-step OPAQUE registration flow

// CreateRegistrationResponse handles server-side step of registration
// Takes client's registration request (M) and returns server response (rpub) and secret (rsec)
func CreateRegistrationResponse(requestData []byte) ([]byte, []byte, error) {
	if len(requestData) != OPAQUE_REGISTER_PUBLIC_LEN {
		return nil, nil, fmt.Errorf("invalid registration request length: expected %d, got %d",
			OPAQUE_REGISTER_PUBLIC_LEN, len(requestData))
	}

	// Get server private key
	_, serverPrivateKey, err := GetServerKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get server keys: %w", err)
	}

	// Allocate buffers for server response
	responseSecret := make([]byte, OPAQUE_REGISTER_SECRET_LEN)
	responsePublic := make([]byte, OPAQUE_REGISTER_PUBLIC_LEN)

	// Convert Go slices to C pointers
	cRequestData := C.CBytes(requestData)
	defer C.free(cRequestData)

	cServerPrivateKey := C.CBytes(serverPrivateKey)
	defer C.free(cServerPrivateKey)

	// Call C function
	ret := C.wrap_opaque_create_registration_response(
		(*C.uint8_t)(cRequestData),
		(*C.uint8_t)(cServerPrivateKey),
		(*C.uint8_t)(&responseSecret[0]),
		(*C.uint8_t)(&responsePublic[0]),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("registration response creation failed: error code %d", ret)
	}

	// Return both the public response (sent to client) and secret (kept by server)
	return responsePublic, responseSecret, nil
}

// StoreUserRecord finalizes registration by storing the user record
// Takes the server secret and client's finalized registration record, returns complete user record
func StoreUserRecord(rsec []byte, rrec []byte) ([]byte, error) {
	if len(rsec) != OPAQUE_REGISTER_SECRET_LEN {
		return nil, fmt.Errorf("invalid server secret length: expected %d, got %d",
			OPAQUE_REGISTER_SECRET_LEN, len(rsec))
	}

	if len(rrec) != OPAQUE_REGISTRATION_RECORD_LEN {
		return nil, fmt.Errorf("invalid registration record length: expected %d, got %d",
			OPAQUE_REGISTRATION_RECORD_LEN, len(rrec))
	}

	// Allocate buffer for final user record
	userRecord := make([]byte, OPAQUE_USER_RECORD_LEN)

	// Convert Go slices to C pointers
	cServerSecret := C.CBytes(rsec)
	defer C.free(cServerSecret)

	cClientRecord := C.CBytes(rrec)
	defer C.free(cClientRecord)

	cUserRecord := C.CBytes(userRecord)
	defer C.free(cUserRecord)

	// Call libopaque's StoreUserRecord function
	ret := C.wrap_opaque_store_user_record(
		(*C.uint8_t)(cServerSecret),
		(*C.uint8_t)(cClientRecord),
		(*C.uint8_t)(cUserRecord),
	)

	if ret != 0 {
		return nil, fmt.Errorf("user record storage failed: error code %d", ret)
	}

	// Copy the result back to our slice
	copy(userRecord, C.GoBytes(unsafe.Pointer(cUserRecord), C.int(OPAQUE_USER_RECORD_LEN)))

	return userRecord, nil
}

// Multi-step OPAQUE authentication flow

// CreateCredentialResponse handles server-side step of authentication
// Takes client's credential request and user record, returns server response
func CreateCredentialResponse(requestData []byte, userRecord []byte) ([]byte, []byte, error) {
	if len(requestData) != OPAQUE_USER_SESSION_PUBLIC_LEN {
		return nil, nil, fmt.Errorf("invalid credential request length: expected %d, got %d",
			OPAQUE_USER_SESSION_PUBLIC_LEN, len(requestData))
	}

	if len(userRecord) != OPAQUE_USER_RECORD_LEN {
		return nil, nil, fmt.Errorf("invalid user record length: expected %d, got %d",
			OPAQUE_USER_RECORD_LEN, len(userRecord))
	}

	// Allocate buffers for server response
	resp := make([]byte, OPAQUE_SERVER_SESSION_LEN)
	sk := make([]byte, OPAQUE_SHARED_SECRETBYTES)
	authU := make([]byte, 64) // crypto_auth_hmacsha512_BYTES

	// Prepare Opaque_Ids structure
	ids := make([]byte, 20) // sizeof(Opaque_Ids) = 4 + 8 + 2 + 8 = 22 bytes, but we'll use 20 for safety
	ids[0] = 4              // idU_len
	ids[2] = 'u'
	ids[3] = 's'
	ids[4] = 'e'
	ids[5] = 'r'
	ids[6] = 6 // idS_len
	ids[8] = 's'
	ids[9] = 'e'
	ids[10] = 'r'
	ids[11] = 'v'
	ids[12] = 'e'
	ids[13] = 'r'

	// Prepare context
	context := []byte("arkfile_auth")
	contextLen := uint16(len(context))

	// Convert Go slices to C pointers
	cRequestData := C.CBytes(requestData)
	defer C.free(cRequestData)

	cUserRecord := C.CBytes(userRecord)
	defer C.free(cUserRecord)

	cIds := C.CBytes(ids)
	defer C.free(cIds)

	cContext := C.CBytes(context)
	defer C.free(cContext)

	// Call C function with correct parameters
	ret := C.wrap_opaque_create_credential_response(
		(*C.uint8_t)(cRequestData),
		(*C.uint8_t)(cUserRecord),
		(*C.uint8_t)(cIds),
		(*C.uint8_t)(cContext),
		C.uint16_t(contextLen),
		(*C.uint8_t)(unsafe.Pointer(&resp[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&authU[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("credential response creation failed: error code %d", ret)
	}

	// Return resp (sent to client) and authU (stored for verification)
	// sk is server-side session key, not used in our implementation
	return resp, authU, nil
}

// UserAuth validates the client's authentication token
// Takes server's authU and client's authU, returns true if they match
func UserAuth(authUServer []byte, authUClient []byte) error {
	if len(authUServer) != 64 || len(authUClient) != 64 {
		return fmt.Errorf("invalid authU length: expected 64 bytes")
	}

	// Convert Go slices to C pointers
	cAuthUServer := C.CBytes(authUServer)
	defer C.free(cAuthUServer)

	cAuthUClient := C.CBytes(authUClient)
	defer C.free(cAuthUClient)

	// Call C function
	ret := C.wrap_opaque_user_auth(
		(*C.uint8_t)(cAuthUServer),
		(*C.uint8_t)(cAuthUClient),
	)

	if ret != 0 {
		return fmt.Errorf("authentication failed: authU mismatch")
	}

	return nil
}

// Session Management Functions

// CreateAuthSession creates a new authentication session for multi-step protocol
func CreateAuthSession(db *sql.DB, username string, flowType string, serverPublicKey []byte) (string, error) {
	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(15 * time.Minute)

	query := "INSERT INTO opaque_auth_sessions (session_id, username, flow_type, server_public_key, expires_at) VALUES (?, ?, ?, ?, ?)"

	_, err := db.Exec(query, sessionID, username, flowType, serverPublicKey, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	return sessionID, nil
}

// ValidateAuthSession validates and retrieves session data
func ValidateAuthSession(db *sql.DB, sessionID string, expectedFlowType string) (username string, serverPk []byte, err error) {
	query := "SELECT username, server_public_key FROM opaque_auth_sessions WHERE session_id = ? AND flow_type = ? AND expires_at > CURRENT_TIMESTAMP"

	err = db.QueryRow(query, sessionID, expectedFlowType).Scan(&username, &serverPk)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil, fmt.Errorf("invalid or expired session")
		}
		return "", nil, fmt.Errorf("session validation failed: %w", err)
	}

	return username, serverPk, nil
}

// DeleteAuthSession removes a session after use
func DeleteAuthSession(db *sql.DB, sessionID string) error {
	query := "DELETE FROM opaque_auth_sessions WHERE session_id = ?"
	_, err := db.Exec(query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// CleanupExpiredSessions removes all expired sessions
func CleanupExpiredSessions(db *sql.DB) error {
	query := "DELETE FROM opaque_auth_sessions WHERE expires_at < CURRENT_TIMESTAMP"
	result, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Printf("Cleaned up %d expired OPAQUE sessions\n", rowsAffected)
	}

	return nil
}
