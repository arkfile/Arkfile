//go:build !mock
// +build !mock

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

// libopaqueRegisterUser is a Go wrapper for the one-step registration
func libopaqueRegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
	userRecord := make([]byte, OPAQUE_USER_RECORD_LEN)
	exportKey := make([]byte, OPAQUE_SHARED_SECRETBYTES)

	cPassword := C.CBytes(password)
	defer C.free(cPassword)

	cServerPrivateKey := C.CBytes(serverPrivateKey)
	defer C.free(cServerPrivateKey)

	ret := C.arkfile_opaque_register_user(
		(*C.uint8_t)(cPassword),
		C.uint16_t(len(password)),
		(*C.uint8_t)(cServerPrivateKey),
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
