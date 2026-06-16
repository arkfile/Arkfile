package clictap

/*
#cgo CFLAGS: -I${SRCDIR}
#include "fido_wrapper.h"
#include <stdlib.h>
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
	AuthData      []byte
	CredentialID  []byte
	AttestationFmt string
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
	ClientDataHash   []byte
	RPID             string
	AllowCredentialIDs [][]byte
	UserVerification int
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
	defer C.free(unsafe.Pointer(cPath))

	cRPID := C.CString(opts.RPID)
	defer C.free(unsafe.Pointer(cRPID))

	var cRPName *C.char
	if opts.RPName != "" {
		cRPName = C.CString(opts.RPName)
		defer C.free(unsafe.Pointer(cRPName))
	}

	cUserName := C.CString(opts.UserName)
	defer C.free(unsafe.Pointer(cUserName))

	cDisplayName := C.CString(opts.UserDisplayName)
	defer C.free(unsafe.Pointer(cDisplayName))

	req := C.wrap_fido_make_cred_req{
		client_data_hash:     (*C.uchar)(unsafe.Pointer(&opts.ClientDataHash[0])),
		client_data_hash_len: C.size_t(len(opts.ClientDataHash)),
		rp_id:                cRPID,
		rp_name:              cRPName,
		user_id:              (*C.uchar)(unsafe.Pointer(&opts.UserID[0])),
		user_id_len:          C.size_t(len(opts.UserID)),
		user_name:            cUserName,
		user_display_name:    cDisplayName,
		cred_type:            C.WRAP_FIDO_CRED_ES256,
		resident_key:         C.int(opts.ResidentKey),
		user_verification:    C.int(opts.UserVerification),
	}

	var out C.wrap_fido_attestation
	defer C.wrap_fido_attestation_free(&out)

	if C.wrap_fido_make_credential(cPath, &req, &out) != 0 {
		return nil, fmt.Errorf("security key enrollment failed (touch the key when prompted)")
	}

	att := &Attestation{
		AttestationFmt: C.GoString(out.attestation_fmt),
	}
	if out.auth_data_len > 0 {
		att.AuthData = C.GoBytes(unsafe.Pointer(out.auth_data), C.int(out.auth_data_len))
	}
	if out.credential_id_len > 0 {
		att.CredentialID = C.GoBytes(unsafe.Pointer(out.credential_id), C.int(out.credential_id_len))
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
	defer C.free(unsafe.Pointer(cPath))

	cRPID := C.CString(opts.RPID)
	defer C.free(unsafe.Pointer(cRPID))

	idPtrs := make([]*C.uchar, len(opts.AllowCredentialIDs))
	idLens := make([]C.size_t, len(opts.AllowCredentialIDs))
	for i, id := range opts.AllowCredentialIDs {
		if len(id) == 0 {
			return nil, fmt.Errorf("empty allowed credential id")
		}
		idPtrs[i] = (*C.uchar)(unsafe.Pointer(&id[0]))
		idLens[i] = C.size_t(len(id))
	}

	var cIDPtrs **C.uchar
	if len(idPtrs) > 0 {
		cIDPtrs = (**C.uchar)(unsafe.Pointer(&idPtrs[0]))
	}

	req := C.wrap_fido_assert_req{
		client_data_hash:     (*C.uchar)(unsafe.Pointer(&opts.ClientDataHash[0])),
		client_data_hash_len: C.size_t(len(opts.ClientDataHash)),
		rp_id:                cRPID,
		allow_cred_ids:       cIDPtrs,
		allow_cred_lens:      (*C.size_t)(unsafe.Pointer(&idLens[0])),
		allow_cred_count:     C.size_t(len(idLens)),
		user_verification:    C.int(opts.UserVerification),
	}

	var out C.wrap_fido_assertion
	defer C.wrap_fido_assertion_free(&out)

	if C.wrap_fido_get_assertion(cPath, &req, &out) != 0 {
		return nil, fmt.Errorf("security key authentication failed (touch the key when prompted)")
	}

	a := &Assertion{}
	if out.auth_data_len > 0 {
		a.AuthData = C.GoBytes(unsafe.Pointer(out.auth_data), C.int(out.auth_data_len))
	}
	if out.signature_len > 0 {
		a.Signature = C.GoBytes(unsafe.Pointer(out.signature), C.int(out.signature_len))
	}
	if out.credential_id_len > 0 {
		a.CredentialID = C.GoBytes(unsafe.Pointer(out.credential_id), C.int(out.credential_id_len))
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
