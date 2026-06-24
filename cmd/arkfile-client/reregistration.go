package main

import (
	"fmt"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
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
	handoffToken, _ := reregResp.Data["reregistration_token"].(string)
	if handoffToken == "" {
		return nil, fmt.Errorf("re-registration required but the server did not provide a handoff token")
	}

	fileCountF, _ := reregResp.Data["file_count"].(float64)
	fileCount := int(fileCountF)

	fmt.Println("This account needs a one-time security re-registration after an OPAQUE server key update.")
	fmt.Println("Your files, shares, and settings are preserved. Reconnecting with your existing password...")

	if fileCount > 0 {
		if err := verifyReregistrationPassword(password, username, reregResp); err != nil {
			return nil, err
		}
		logVerbose("Password confirmed against existing file metadata; proceeding with re-registration")
	}

	clientSecret, registrationRequest, err := auth.ClientCreateRegistrationRequest(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create re-registration request: %w", err)
	}

	respResp, err := c.makeRequest("POST", "/api/opaque/reregister/response", map[string]string{
		"registration_request": encodeBase64(registrationRequest),
	}, handoffToken)
	if err != nil {
		return nil, fmt.Errorf("re-registration response failed: %w", err)
	}

	registrationResponseB64, ok := respResp.Data["registration_response"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid server response: missing registration_response")
	}
	sessionID, ok := respResp.Data["session_id"].(string)
	if !ok || sessionID == "" {
		sessionID = respResp.SessionID
	}
	if sessionID == "" {
		return nil, fmt.Errorf("invalid server response: missing session_id")
	}

	registrationResponse, err := decodeBase64(registrationResponseB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %w", err)
	}

	serverID, err := c.fetchOpaqueServerID()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OPAQUE server identity: %w", err)
	}

	registrationRecord, _, err := auth.ClientFinalizeRegistration(clientSecret, registrationResponse, username, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize re-registration: %w", err)
	}

	finalizeResp, err := c.makeRequest("POST", "/api/opaque/reregister/finalize", map[string]string{
		"session_id":          sessionID,
		"registration_record": encodeBase64(registrationRecord),
	}, handoffToken)
	if err != nil {
		return nil, fmt.Errorf("re-registration finalization failed: %w", err)
	}

	fmt.Printf("Re-registration complete for %s.\n", username)
	return finalizeResp, nil
}

// verifyReregistrationPassword confirms the entered password derives the Account
// Key that wraps the user's existing files, using the account-key-encrypted
// verifier sample the server returned with the 409. A decryption failure means
// the password does not match the existing files; the ceremony is aborted with
// no server-side change so the user is never locked out.
func verifyReregistrationPassword(password []byte, username string, reregResp *Response) error {
	verifierRaw, ok := reregResp.Data["verifier"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("the server reported existing files but provided no verifier sample; aborting re-registration to protect your files")
	}

	fileID, _ := verifierRaw["file_id"].(string)
	owner, _ := verifierRaw["owner_username"].(string)
	encFilename, _ := verifierRaw["encrypted_filename"].(string)
	filenameNonce, _ := verifierRaw["filename_nonce"].(string)
	if fileID == "" || encFilename == "" || filenameNonce == "" {
		return fmt.Errorf("the server verifier sample is incomplete; aborting re-registration to protect your files")
	}
	if owner == "" {
		owner = username
	}

	accountKey := crypto.DeriveAccountPasswordKey(password, username)
	defer clearBytes(accountKey)

	if _, err := decryptMetadataField(encFilename, filenameNonce, accountKey, fileID, crypto.AADFieldFilename, owner); err != nil {
		return fmt.Errorf("the password you entered does not match this account's existing files; re-registration aborted (no changes were made)")
	}
	return nil
}
