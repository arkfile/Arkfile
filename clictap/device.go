package clictap

/*
#cgo CFLAGS: -I${SRCDIR}
#include "fido_wrapper.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

var initOnce sync.Once
var initErr error

func ensureInit() error {
	initOnce.Do(func() {
		if C.wrap_fido_init() != 0 {
			initErr = fmt.Errorf("libfido2 init failed")
		}
	})
	return initErr
}

// cAllocBytes copies a Go byte slice into C heap memory (required for Go 1.23+ cgo).
func cAllocBytes(data []byte) (*C.uchar, unsafe.Pointer, error) {
	if len(data) == 0 {
		return nil, nil, nil
	}
	p := C.calloc(1, C.size_t(len(data)))
	if p == nil {
		return nil, nil, fmt.Errorf("calloc failed")
	}
	C.memcpy(p, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	return (*C.uchar)(p), unsafe.Pointer(p), nil
}

func cFree(p unsafe.Pointer) {
	if p != nil {
		C.free(p)
	}
}

// ListDevices returns hidraw paths for connected FIDO devices.
func ListDevices() ([]string, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}

	var cPaths **C.char
	var count C.size_t
	if C.wrap_fido_list_devices(&cPaths, &count) != 0 {
		return nil, fmt.Errorf("failed to list security key devices")
	}
	defer C.wrap_fido_free_paths(cPaths, count)

	n := int(count)
	if n == 0 {
		return nil, fmt.Errorf("no security key devices found")
	}

	paths := make([]string, n)
	cPathArr := (*[1 << 20]*C.char)(unsafe.Pointer(cPaths))[:n:n]
	for i := 0; i < n; i++ {
		paths[i] = C.GoString(cPathArr[i])
	}
	return paths, nil
}

// Attestation holds raw outputs from MakeCredential.
type Attestation struct {
	AuthData     []byte
	CredentialID []byte
}

// Assertion holds raw outputs from GetAssertion.
type Assertion struct {
	AuthData     []byte
	Signature    []byte
	CredentialID []byte
}

// MakeCredentialOptions configures security-key enrollment.
type MakeCredentialOptions struct {
	ClientDataHash   []byte
	RPID             string
	RPName           string
	UserID           []byte
	UserName         string
	UserDisplayName  string
	ResidentKey      int
	UserVerification int
}

// AssertOptions configures security-key authentication.
type AssertOptions struct {
	ClientDataHash     []byte
	RPID               string
	AllowCredentialIDs [][]byte
	UserVerification   int
}

// MakeCredential runs authenticatorMakeCredential on the given device path.
func MakeCredential(devicePath string, opts MakeCredentialOptions) (*Attestation, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	if len(opts.ClientDataHash) == 0 || opts.RPID == "" || len(opts.UserID) == 0 {
		return nil, fmt.Errorf("invalid make-credential parameters")
	}

	cPath := C.CString(devicePath)
	defer cFree(unsafe.Pointer(cPath))

	cRPID := C.CString(opts.RPID)
	defer cFree(unsafe.Pointer(cRPID))

	var cRPName *C.char
	if opts.RPName != "" {
		cRPName = C.CString(opts.RPName)
		defer cFree(unsafe.Pointer(cRPName))
	}

	cUserName := C.CString(opts.UserName)
	defer cFree(unsafe.Pointer(cUserName))

	cDisplayName := C.CString(opts.UserDisplayName)
	defer cFree(unsafe.Pointer(cDisplayName))

	cHash, hashAlloc, err := cAllocBytes(opts.ClientDataHash)
	if err != nil {
		return nil, err
	}
	defer cFree(hashAlloc)

	cUserID, userIDAlloc, err := cAllocBytes(opts.UserID)
	if err != nil {
		return nil, err
	}
	defer cFree(userIDAlloc)

	cReq := (*C.wrap_fido_make_cred_req)(C.calloc(1, C.size_t(unsafe.Sizeof(C.wrap_fido_make_cred_req{}))))
	if cReq == nil {
		return nil, fmt.Errorf("calloc failed")
	}
	defer cFree(unsafe.Pointer(cReq))

	cReq.client_data_hash = cHash
	cReq.client_data_hash_len = C.size_t(len(opts.ClientDataHash))
	cReq.rp_id = cRPID
	cReq.rp_name = cRPName
	cReq.user_id = cUserID
	cReq.user_id_len = C.size_t(len(opts.UserID))
	cReq.user_name = cUserName
	cReq.user_display_name = cDisplayName
	cReq.cred_type = C.WRAP_FIDO_CRED_ES256
	cReq.resident_key = C.int(opts.ResidentKey)
	cReq.user_verification = C.int(opts.UserVerification)

	cOut := (*C.wrap_fido_attestation)(C.calloc(1, C.size_t(unsafe.Sizeof(C.wrap_fido_attestation{}))))
	if cOut == nil {
		return nil, fmt.Errorf("calloc failed")
	}
	defer func() {
		C.wrap_fido_attestation_free(cOut)
		cFree(unsafe.Pointer(cOut))
	}()

	if C.wrap_fido_make_credential(cPath, cReq, cOut) != 0 {
		return nil, fmt.Errorf("security key enrollment failed (touch the key when prompted)")
	}

	att := &Attestation{}
	if cOut.auth_data_len > 0 {
		att.AuthData = C.GoBytes(unsafe.Pointer(cOut.auth_data), C.int(cOut.auth_data_len))
	}
	if cOut.credential_id_len > 0 {
		att.CredentialID = C.GoBytes(unsafe.Pointer(cOut.credential_id), C.int(cOut.credential_id_len))
	}
	return att, nil
}

// GetAssertion runs authenticatorGetAssertion on the given device path.
func GetAssertion(devicePath string, opts AssertOptions) (*Assertion, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	if len(opts.ClientDataHash) == 0 || opts.RPID == "" {
		return nil, fmt.Errorf("invalid assertion parameters")
	}

	cPath := C.CString(devicePath)
	defer cFree(unsafe.Pointer(cPath))

	cRPID := C.CString(opts.RPID)
	defer cFree(unsafe.Pointer(cRPID))

	cHash, hashAlloc, err := cAllocBytes(opts.ClientDataHash)
	if err != nil {
		return nil, err
	}
	defer cFree(hashAlloc)

	n := len(opts.AllowCredentialIDs)
	var credAllocs []unsafe.Pointer
	var cIDPtrs **C.uchar
	var cLens *C.size_t

	if n > 0 {
		cIDPtrs = (**C.uchar)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(uintptr(0)))))
		if cIDPtrs == nil {
			return nil, fmt.Errorf("calloc failed")
		}
		cLens = (*C.size_t)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.size_t(0)))))
		if cLens == nil {
			cFree(unsafe.Pointer(cIDPtrs))
			return nil, fmt.Errorf("calloc failed")
		}

		ptrArr := (*[1 << 20]*C.uchar)(unsafe.Pointer(cIDPtrs))[:n:n]
		lenArr := (*[1 << 20]C.size_t)(unsafe.Pointer(cLens))[:n:n]

		for i, id := range opts.AllowCredentialIDs {
			if len(id) == 0 {
				for _, p := range credAllocs {
					cFree(p)
				}
				cFree(unsafe.Pointer(cIDPtrs))
				cFree(unsafe.Pointer(cLens))
				return nil, fmt.Errorf("empty allowed credential id")
			}
			cid, raw, allocErr := cAllocBytes(id)
			if allocErr != nil {
				for _, p := range credAllocs {
					cFree(p)
				}
				cFree(unsafe.Pointer(cIDPtrs))
				cFree(unsafe.Pointer(cLens))
				return nil, allocErr
			}
			credAllocs = append(credAllocs, raw)
			ptrArr[i] = cid
			lenArr[i] = C.size_t(len(id))
		}
	}
	defer func() {
		for _, p := range credAllocs {
			cFree(p)
		}
		cFree(unsafe.Pointer(cIDPtrs))
		cFree(unsafe.Pointer(cLens))
	}()

	cReq := (*C.wrap_fido_assert_req)(C.calloc(1, C.size_t(unsafe.Sizeof(C.wrap_fido_assert_req{}))))
	if cReq == nil {
		return nil, fmt.Errorf("calloc failed")
	}
	defer cFree(unsafe.Pointer(cReq))

	cReq.client_data_hash = cHash
	cReq.client_data_hash_len = C.size_t(len(opts.ClientDataHash))
	cReq.rp_id = cRPID
	cReq.allow_cred_ids = cIDPtrs
	cReq.allow_cred_lens = cLens
	cReq.allow_cred_count = C.size_t(n)
	cReq.user_verification = C.int(opts.UserVerification)

	cOut := (*C.wrap_fido_assertion)(C.calloc(1, C.size_t(unsafe.Sizeof(C.wrap_fido_assertion{}))))
	if cOut == nil {
		return nil, fmt.Errorf("calloc failed")
	}
	defer func() {
		C.wrap_fido_assertion_free(cOut)
		cFree(unsafe.Pointer(cOut))
	}()

	if C.wrap_fido_get_assertion(cPath, cReq, cOut) != 0 {
		return nil, fmt.Errorf("security key authentication failed (touch the key when prompted)")
	}

	a := &Assertion{}
	if cOut.auth_data_len > 0 {
		a.AuthData = C.GoBytes(unsafe.Pointer(cOut.auth_data), C.int(cOut.auth_data_len))
	}
	if cOut.signature_len > 0 {
		a.Signature = C.GoBytes(unsafe.Pointer(cOut.signature), C.int(cOut.signature_len))
	}
	if cOut.credential_id_len > 0 {
		a.CredentialID = C.GoBytes(unsafe.Pointer(cOut.credential_id), C.int(cOut.credential_id_len))
	}
	return a, nil
}

// SelectDevice returns the first listed device path (single-key v1).
func SelectDevice() (string, error) {
	paths, err := ListDevices()
	if err != nil {
		return "", err
	}
	return paths[0], nil
}

const (
	OptOmit  = int(C.WRAP_FIDO_OPT_OMIT)
	OptFalse = int(C.WRAP_FIDO_OPT_FALSE)
	OptTrue  = int(C.WRAP_FIDO_OPT_TRUE)
)
