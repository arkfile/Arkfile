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
	"fmt"
	"unsafe"
)

// Multi-step OPAQUE registration flow

// CreateRegistrationResponse handles server-side step of registration
// Takes client's registration request (M) and returns server response (rpub)
func CreateRegistrationResponse(requestData []byte) ([]byte, error) {
	if len(requestData) != OPAQUE_REGISTER_PUBLIC_LEN {
		return nil, fmt.Errorf("invalid registration request length: expected %d, got %d",
			OPAQUE_REGISTER_PUBLIC_LEN, len(requestData))
	}

	// Get server private key
	_, serverPrivateKey, err := GetServerKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get server keys: %w", err)
	}

	// Allocate buffers for server response
	rsec := make([]byte, OPAQUE_REGISTER_SECRET_LEN)
	rpub := make([]byte, OPAQUE_REGISTER_PUBLIC_LEN)

	// Convert Go slices to C pointers
	cRequestData := C.CBytes(requestData)
	defer C.free(cRequestData)

	cServerPrivateKey := C.CBytes(serverPrivateKey)
	defer C.free(cServerPrivateKey)

	// Call C function
	ret := C.arkfile_opaque_create_registration_response(
		(*C.uint8_t)(cRequestData),
		(*C.uint8_t)(cServerPrivateKey),
		(*C.uint8_t)(unsafe.Pointer(&rsec[0])),
		(*C.uint8_t)(unsafe.Pointer(&rpub[0])),
	)

	if ret != 0 {
		return nil, fmt.Errorf("registration response creation failed: error code %d", ret)
	}

	// Note: rsec is server-side secret, not returned to client
	// Only rpub is sent to client
	return rpub, nil
}

// StoreUserRecord finalizes registration by storing the user record
// Takes the finalized registration record from client and stores it
func StoreUserRecord(rrec []byte) ([]byte, error) {
	if len(rrec) != OPAQUE_REGISTRATION_RECORD_LEN {
		return nil, fmt.Errorf("invalid registration record length: expected %d, got %d",
			OPAQUE_REGISTRATION_RECORD_LEN, len(rrec))
	}

	// For libopaque, the registration record IS the user record
	// No additional processing needed - just validate and return
	userRecord := make([]byte, OPAQUE_USER_RECORD_LEN)

	// The rrec from client contains the full user record
	// Copy it to our buffer (validation happens in C library)
	copy(userRecord, rrec)

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

	// Convert Go slices to C pointers
	cRequestData := C.CBytes(requestData)
	defer C.free(cRequestData)

	cUserRecord := C.CBytes(userRecord)
	defer C.free(cUserRecord)

	// Call C function
	ret := C.arkfile_opaque_create_credential_response(
		(*C.uint8_t)(cRequestData),
		(*C.uint8_t)(cUserRecord),
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
	ret := C.arkfile_opaque_user_auth(
		(*C.uint8_t)(cAuthUServer),
		(*C.uint8_t)(cAuthUClient),
	)

	if ret != 0 {
		return fmt.Errorf("authentication failed: authU mismatch")
	}

	return nil
}
