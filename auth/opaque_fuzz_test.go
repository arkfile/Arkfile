package auth

import (
	"testing"
)

func opaqueFuzzMaterial(f *testing.F) (userRecord, validM, validPub []byte) {
	f.Helper()
	ResetOpaqueServerKeysForTest()
	if err := SetupServerKeys(nil); err != nil {
		f.Fatal(err)
	}
	f.Cleanup(ResetOpaqueServerKeysForTest)

	password := []byte("OpaqueFuzzPassword-2026!")
	username := "opaque.fuzz.user"
	usrCtx, m, err := ClientCreateRegistrationRequest(password)
	if err != nil {
		f.Fatal(err)
	}
	rpub, rsec, err := CreateRegistrationResponse(m)
	if err != nil {
		f.Fatal(err)
	}
	rrec, _, err := ClientFinalizeRegistration(usrCtx, rpub, username, OpaqueServerID())
	if err != nil {
		f.Fatal(err)
	}
	record, err := StoreUserRecord(rsec, rrec)
	if err != nil {
		f.Fatal(err)
	}
	_, pub, err := ClientCreateCredentialRequest(password)
	if err != nil {
		f.Fatal(err)
	}
	return record, m, pub
}

func FuzzCreateRegistrationResponse(f *testing.F) {
	_, validM, _ := opaqueFuzzMaterial(f)
	f.Add(validM)
	f.Add([]byte{})
	f.Add(validM[:len(validM)-1])
	oversize := make([]byte, len(validM)+1)
	copy(oversize, validM)
	f.Add(oversize)

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _, _ = CreateRegistrationResponse(input)

		padded := make([]byte, OPAQUE_REGISTER_REQUEST_LEN)
		copy(padded, input)
		resp, secret, err := CreateRegistrationResponse(padded)
		if err == nil {
			if len(resp) != OPAQUE_REGISTER_PUBLIC_LEN || len(secret) != OPAQUE_REGISTER_SECRET_LEN {
				t.Fatal("CreateRegistrationResponse succeeded with unexpected buffer lengths")
			}
		}
	})
}

func FuzzCreateCredentialResponse(f *testing.F) {
	userRecord, _, validPub := opaqueFuzzMaterial(f)
	f.Add(validPub)
	f.Add([]byte{})
	f.Add(validPub[:len(validPub)-1])
	oversize := make([]byte, len(validPub)+1)
	copy(oversize, validPub)
	f.Add(oversize)

	const username = "opaque.fuzz.user"
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _, _ = CreateCredentialResponse(input, userRecord, username)

		padded := make([]byte, OPAQUE_USER_SESSION_PUBLIC_LEN)
		copy(padded, input)
		resp, authU, err := CreateCredentialResponse(padded, userRecord, username)
		if err == nil {
			if len(resp) != OPAQUE_SERVER_SESSION_LEN || len(authU) != 64 {
				t.Fatal("CreateCredentialResponse succeeded with unexpected buffer lengths")
			}
		}
	})
}
