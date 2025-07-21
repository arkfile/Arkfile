//go:build !js && !wasm

package auth

/*
#cgo CFLAGS: -I../vendor/stef/libopaque/src -I../vendor/stef/liboprf/src -I../vendor/stef/liboprf/src/noise_xk
#cgo LDFLAGS: -L../vendor/stef/libopaque/src -L../vendor/stef/liboprf/src -L../vendor/stef/liboprf/src/noise_xk
#cgo LDFLAGS: -lopaque -loprf -loprf-noiseXK -lsodium
#include "opaque_wrapper.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// LibOPAQUE constants (from opaque.h)
const (
	OPAQUE_USER_RECORD_LEN         = 256
	OPAQUE_SHARED_SECRETBYTES      = 64
	OPAQUE_REGISTRATION_RECORD_LEN = 192
	OPAQUE_USER_SESSION_PUBLIC_LEN = 96
	OPAQUE_USER_SESSION_SECRET_LEN = 226
	OPAQUE_SERVER_SESSION_LEN      = 320
)

// libopaqueRegisterUser is a Go wrapper for the one-step registration
func libopaqueRegisterUser(password []byte) ([]byte, []byte, error) {
	userRecord := make([]byte, OPAQUE_USER_RECORD_LEN)
	exportKey := make([]byte, OPAQUE_SHARED_SECRETBYTES)

	cPassword := C.CBytes(password)
	defer C.free(cPassword)

	ret := C.arkfile_opaque_register_user(
		(*C.uint8_t)(cPassword),
		C.uint16_t(len(password)),
		(*C.uint8_t)(unsafe.Pointer(&userRecord[0])),
		(*C.uint8_t)(unsafe.Pointer(&exportKey[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("libopaque registration failed: error code %d", ret)
	}

	return userRecord, exportKey, nil
}

// libopaqueAuthenticateUser is a Go wrapper for the one-step authentication
func libopaqueAuthenticateUser(password []byte, userRecord []byte) ([]byte, error) {
	sessionKey := make([]byte, OPAQUE_SHARED_SECRETBYTES)

	cPassword := C.CBytes(password)
	defer C.free(cPassword)

	ret := C.arkfile_opaque_authenticate_user(
		(*C.uint8_t)(cPassword),
		C.uint16_t(len(password)),
		(*C.uint8_t)(unsafe.Pointer(&userRecord[0])),
		(*C.uint8_t)(unsafe.Pointer(&sessionKey[0])),
	)

	if ret != 0 {
		return nil, fmt.Errorf("libopaque authentication failed: error code %d", ret)
	}

	return sessionKey, nil
}

// Error handling helper
func libopaqueError(code C.int, operation string) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("libopaque %s failed: error code %d", operation, code)
}
