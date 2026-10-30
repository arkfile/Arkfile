package main

import (
	"fmt"

	"github.com/arkfile/Arkfile/cli/reregistration"
)

// reregistrationRequiredCode is the stable error code the server returns (with
// HTTP 409) when an account has been flagged for a one-time OPAQUE
// re-registration following an operator-initiated credential rotation.
const reregistrationRequiredCode = "account_requires_reregistration"

// performReregistration runs the one-time OPAQUE re-registration ceremony for a
// flagged account. It is invoked from the login flow when the login response
// step returns account_requires_reregistration. The password is still required
// after this returns (to derive the Account Key), so it is NOT zeroized here.
//
// When the user owns files, the entered password is confirmed against an
// account-key-encrypted metadata sample BEFORE the OPAQUE record is replaced, so
// a mismatched password can never be bound to the account and lock the user out
// of their own files. On success this returns the finalize response, which has
// the same MFA-pending shape as a normal login finalize.
func (c *HTTPClient) performReregistration(username string, password []byte, reregResp *Response) (*Response, error) {
	fmt.Println("This account needs a one-time security re-registration after an OPAQUE server key update.")
	fmt.Println("Your files, shares, and settings are preserved. Reconnecting with your existing password...")

	serverID, err := c.fetchOpaqueServerID()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OPAQUE server identity: %w", err)
	}
	finalData, err := reregistration.Perform(
		func(method, path string, body map[string]string, token string) (map[string]interface{}, error) {
			resp, reqErr := c.makeRequest(method, path, body, token)
			if resp == nil {
				return nil, reqErr
			}
			return resp.Data, reqErr
		},
		"/api/opaque/reregister/response",
		"/api/opaque/reregister/finalize",
		username,
		password,
		reregResp.Data,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Re-registration complete for %s.\n", username)
	loginResp := &Response{Success: true, Data: finalData}
	// The ceremony returns the same nested MFA-pending payload as login
	// finalize. Login reads RequiresMFA and TempToken, not only Data.
	applyResponseDataFields(loginResp)
	return loginResp, nil
}

// verifyReregistrationPassword confirms the entered password derives the Account
// Key that wraps the user's existing files, using the account-key-encrypted
// verifier sample the server returned with the 409. A decryption failure means
// the password does not match the existing files; the ceremony is aborted with
// no server-side change so the user is never locked out.
func verifyReregistrationPassword(password []byte, username string, reregResp *Response) error {
	return reregistration.VerifyPassword(password, username, reregResp.Data)
}
