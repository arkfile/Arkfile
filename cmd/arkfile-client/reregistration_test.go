package main

import (
	"testing"

	"github.com/84adam/Arkfile/crypto"
)

// buildVerifierResponse encrypts a filename sample under the Account Key derived
// from (password, owner) and packages it as the server's 409 re-registration
// payload, mirroring respondAccountRequiresReregistration on the server.
func buildVerifierResponse(t *testing.T, password, owner string) *Response {
	t.Helper()
	accountKey := crypto.DeriveAccountPasswordKey([]byte(password), owner)
	encFn, fnNonce, _, _, err := encryptMetadata("quarterly-report.pdf", "deadbeef", accountKey, testFileID, owner)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}
	return &Response{
		Data: map[string]interface{}{
			"file_count": float64(1),
			"verifier": map[string]interface{}{
				"file_id":            testFileID,
				"owner_username":     owner,
				"encrypted_filename": encFn,
				"filename_nonce":     fnNonce,
			},
		},
	}
}

func TestVerifyReregistrationPassword_CorrectPassword(t *testing.T) {
	const password = "Correct-Account-Password-2026!"
	const owner = testOwner
	resp := buildVerifierResponse(t, password, owner)

	if err := verifyReregistrationPassword([]byte(password), owner, resp); err != nil {
		t.Fatalf("expected correct password to verify, got: %v", err)
	}
}

func TestVerifyReregistrationPassword_WrongPassword(t *testing.T) {
	const owner = testOwner
	resp := buildVerifierResponse(t, "Correct-Account-Password-2026!", owner)

	if err := verifyReregistrationPassword([]byte("Wrong-Password-2026!Nope"), owner, resp); err == nil {
		t.Fatal("expected wrong password to fail verification")
	}
}

func TestVerifyReregistrationPassword_MissingVerifierFailsSafe(t *testing.T) {
	resp := &Response{Data: map[string]interface{}{"file_count": float64(1)}}
	if err := verifyReregistrationPassword([]byte("anything"), testOwner, resp); err == nil {
		t.Fatal("missing verifier sample must fail safe (refuse to proceed)")
	}
}

func TestVerifyReregistrationPassword_IncompleteVerifierFailsSafe(t *testing.T) {
	resp := &Response{Data: map[string]interface{}{
		"file_count": float64(1),
		"verifier": map[string]interface{}{
			"file_id":        testFileID,
			"owner_username": testOwner,
			// encrypted_filename / filename_nonce intentionally omitted
		},
	}}
	if err := verifyReregistrationPassword([]byte("anything"), testOwner, resp); err == nil {
		t.Fatal("incomplete verifier sample must fail safe")
	}
}
