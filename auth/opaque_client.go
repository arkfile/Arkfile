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

// Client-side OPAQUE operations for CLI tools
// These functions implement the client-side of the OPAQUE protocol
// and maintain zero-knowledge properties by never sending passwords to the server

// Registration Flow - Client Side

// ClientCreateRegistrationRequest creates the initial registration request
// This is Step 1 of the registration flow (client-side)
// Input: password (user's password)
// Output: usrCtx (client context to store), M (registration request to send to server)
func ClientCreateRegistrationRequest(password []byte) ([]byte, []byte, error) {
	if len(password) == 0 {
		return nil, nil, fmt.Errorf("password cannot be empty")
	}

	// Allocate buffers - usrCtx must be OPAQUE_REGISTER_USER_SEC_LEN + password length
	usrCtx := make([]byte, OPAQUE_REGISTER_USER_SEC_LEN+len(password))
	M := make([]byte, OPAQUE_REGISTER_PUBLIC_LEN)

	// Convert Go slices to C pointers
	cPassword := C.CBytes(password)
	defer C.free(cPassword)

	// Call C function
	ret := C.wrap_opaque_create_registration_request(
		(*C.uint8_t)(cPassword),
		C.uint16_t(len(password)),
		(*C.uint8_t)(unsafe.Pointer(&usrCtx[0])),
		(*C.uint8_t)(unsafe.Pointer(&M[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("registration request creation failed: error code %d", ret)
	}

	return usrCtx, M, nil
}

// ClientFinalizeRegistration finalizes the registration process
// This is Step 3 of the registration flow (client-side)
// Input: usrCtx (client context from step 1), serverResponse (rpub from server), username
// Output: rrec (registration record to send to server), exportKey (client export key)
func ClientFinalizeRegistration(usrCtx []byte, serverResponse []byte, username string) ([]byte, []byte, error) {
	// usrCtx length should be at least OPAQUE_REGISTER_USER_SEC_LEN (may be larger due to password)
	if len(usrCtx) < OPAQUE_REGISTER_USER_SEC_LEN {
		return nil, nil, fmt.Errorf("invalid user context length: expected at least %d, got %d",
			OPAQUE_REGISTER_USER_SEC_LEN, len(usrCtx))
	}

	if len(serverResponse) != OPAQUE_REGISTER_PUBLIC_LEN {
		return nil, nil, fmt.Errorf("invalid server response length: expected %d, got %d",
			OPAQUE_REGISTER_PUBLIC_LEN, len(serverResponse))
	}

	// Allocate buffers
	rrec := make([]byte, OPAQUE_REGISTRATION_RECORD_LEN)
	exportKey := make([]byte, 32) // crypto_hash_sha256_BYTES

	// Prepare IDs
	idU := []byte(username)
	idULen := uint16(len(idU))

	// Use default server ID "server" for now
	idS := []byte("server")
	idSLen := uint16(len(idS))

	// Convert Go slices to C pointers
	cUsrCtx := C.CBytes(usrCtx)
	defer C.free(cUsrCtx)

	cServerResponse := C.CBytes(serverResponse)
	defer C.free(cServerResponse)

	cIdU := C.CBytes(idU)
	defer C.free(cIdU)

	cIdS := C.CBytes(idS)
	defer C.free(cIdS)

	// Call C function
	ret := C.wrap_opaque_finalize_request(
		(*C.uint8_t)(cUsrCtx),
		(*C.uint8_t)(cServerResponse),
		(*C.uint8_t)(cIdU),
		C.uint16_t(idULen),
		(*C.uint8_t)(cIdS),
		C.uint16_t(idSLen),
		(*C.uint8_t)(unsafe.Pointer(&rrec[0])),
		(*C.uint8_t)(unsafe.Pointer(&exportKey[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("registration finalization failed: error code %d", ret)
	}

	return rrec, exportKey, nil
}

// Authentication Flow - Client Side

// ClientCreateCredentialRequest creates the initial authentication request
// This is Step 1 of the authentication flow (client-side)
// Input: password (user's password)
// Output: sec (client secret to store), pub (credential request to send to server)
func ClientCreateCredentialRequest(password []byte) ([]byte, []byte, error) {
	if len(password) == 0 {
		return nil, nil, fmt.Errorf("password cannot be empty")
	}

	// Allocate buffers - sec must be OPAQUE_USER_SESSION_SECRET_LEN + password length
	sec := make([]byte, OPAQUE_USER_SESSION_SECRET_LEN+len(password))
	pub := make([]byte, OPAQUE_USER_SESSION_PUBLIC_LEN)

	// Convert Go slices to C pointers
	cPassword := C.CBytes(password)
	defer C.free(cPassword)

	// Call C function
	ret := C.wrap_opaque_create_credential_request(
		(*C.uint8_t)(cPassword),
		C.uint16_t(len(password)),
		(*C.uint8_t)(unsafe.Pointer(&sec[0])),
		(*C.uint8_t)(unsafe.Pointer(&pub[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("credential request creation failed: error code %d", ret)
	}

	return sec, pub, nil
}

// ClientRecoverCredentials recovers credentials from server response
// This is Step 3 of the authentication flow (client-side)
// Input: sec (client secret from step 1), serverResponse (credential response from server), username
// Output: sk (session key), authU (authentication token to send to server), exportKey (client export key)
func ClientRecoverCredentials(sec []byte, serverResponse []byte, username string) ([]byte, []byte, []byte, error) {
	// sec length should be at least OPAQUE_USER_SESSION_SECRET_LEN (may be larger due to password)
	if len(sec) < OPAQUE_USER_SESSION_SECRET_LEN {
		return nil, nil, nil, fmt.Errorf("invalid client secret length: expected at least %d, got %d",
			OPAQUE_USER_SESSION_SECRET_LEN, len(sec))
	}

	if len(serverResponse) != OPAQUE_SERVER_SESSION_LEN {
		return nil, nil, nil, fmt.Errorf("invalid server response length: expected %d, got %d",
			OPAQUE_SERVER_SESSION_LEN, len(serverResponse))
	}

	// Allocate buffers
	sk := make([]byte, OPAQUE_SHARED_SECRETBYTES)
	authU := make([]byte, 64)     // crypto_auth_hmacsha512_BYTES
	exportKey := make([]byte, 32) // crypto_hash_sha256_BYTES

	// Prepare IDs
	idU := []byte(username)
	idULen := uint16(len(idU))

	// Use default server ID "server" for now
	idS := []byte("server")
	idSLen := uint16(len(idS))

	// Prepare context
	context := []byte("arkfile_auth")
	contextLen := uint16(len(context))

	// Convert Go slices to C pointers
	cSec := C.CBytes(sec)
	defer C.free(cSec)

	cServerResponse := C.CBytes(serverResponse)
	defer C.free(cServerResponse)

	cIdU := C.CBytes(idU)
	defer C.free(cIdU)

	cIdS := C.CBytes(idS)
	defer C.free(cIdS)

	cContext := C.CBytes(context)
	defer C.free(cContext)

	// Call C function
	ret := C.wrap_opaque_recover_credentials(
		(*C.uint8_t)(cServerResponse),
		(*C.uint8_t)(cSec),
		(*C.uint8_t)(cContext),
		C.uint16_t(contextLen),
		(*C.uint8_t)(cIdU),
		C.uint16_t(idULen),
		(*C.uint8_t)(cIdS),
		C.uint16_t(idSLen),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&authU[0])),
		(*C.uint8_t)(unsafe.Pointer(&exportKey[0])),
	)

	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("credential recovery failed: error code %d", ret)
	}

	return sk, authU, exportKey, nil
}
