package reregistration

import (
	"encoding/base64"
	"fmt"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
)

const RequiredCode = "account_requires_reregistration"

// Poster sends one authenticated API call and returns the response data map.
type Poster func(method, path string, body map[string]string, token string) (map[string]interface{}, error)

// Perform replaces the OPAQUE password record for a flagged account.
// responsePath and finalizePath select the normal or admin ceremony routes.
// When the account owns files, password must decrypt the verifier sample first.
func Perform(post Poster, responsePath, finalizePath, username string, password []byte, payload map[string]interface{}, serverID string) (map[string]interface{}, error) {
	handoffToken, _ := payload["reregistration_token"].(string)
	if handoffToken == "" {
		return nil, fmt.Errorf("re-registration required but the server did not provide a handoff token")
	}

	fileCountF, _ := payload["file_count"].(float64)
	if int(fileCountF) > 0 {
		if err := VerifyPassword(password, username, payload); err != nil {
			return nil, err
		}
	}

	clientSecret, registrationRequest, err := auth.ClientCreateRegistrationRequest(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create re-registration request: %w", err)
	}
	respData, err := post("POST", responsePath, map[string]string{
		"registration_request": base64.StdEncoding.EncodeToString(registrationRequest),
	}, handoffToken)
	if err != nil {
		return nil, fmt.Errorf("re-registration response failed: %w", err)
	}

	registrationResponseB64, _ := respData["registration_response"].(string)
	sessionID, _ := respData["session_id"].(string)
	if registrationResponseB64 == "" || sessionID == "" {
		return nil, fmt.Errorf("invalid server response: missing re-registration session")
	}
	registrationResponse, err := base64.StdEncoding.DecodeString(registrationResponseB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %w", err)
	}
	registrationRecord, _, err := auth.ClientFinalizeRegistration(clientSecret, registrationResponse, username, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize re-registration: %w", err)
	}
	finalData, err := post("POST", finalizePath, map[string]string{
		"session_id":          sessionID,
		"registration_record": base64.StdEncoding.EncodeToString(registrationRecord),
	}, handoffToken)
	if err != nil {
		return nil, fmt.Errorf("re-registration finalization failed: %w", err)
	}
	return finalData, nil
}

func VerifyPassword(password []byte, username string, payload map[string]interface{}) error {
	verifierRaw, ok := payload["verifier"].(map[string]interface{})
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
	saltB64, _ := payload["account_kdf_salt"].(string)
	profile, _ := payload["account_kdf_profile"].(float64)
	if saltB64 == "" || int(profile) != int(crypto.OwnerEnvelopeKDFProfile()) {
		return fmt.Errorf("the server did not provide valid Account Key metadata; aborting re-registration")
	}
	accountSalt, err := crypto.DecodeBase64(saltB64)
	if err != nil {
		return fmt.Errorf("the server provided an invalid Account Key salt; aborting re-registration")
	}
	accountKey, err := crypto.DeriveAccountPasswordKey(password, accountSalt)
	if err != nil {
		return fmt.Errorf("failed to derive Account Key: %w", err)
	}
	defer crypto.SecureZeroMFAKey(accountKey)

	nonce, err := base64.StdEncoding.DecodeString(filenameNonce)
	if err != nil {
		return fmt.Errorf("failed to decode verifier nonce: %w", err)
	}
	encData, err := base64.StdEncoding.DecodeString(encFilename)
	if err != nil {
		return fmt.Errorf("failed to decode verifier filename: %w", err)
	}
	combined := append(append([]byte{}, nonce...), encData...)
	aad := crypto.BuildMetadataFieldAAD(fileID, crypto.AADFieldFilename, owner)
	if _, err := crypto.DecryptGCMWithAAD(combined, accountKey, aad); err != nil {
		return fmt.Errorf("the password you entered does not match this account's existing files; re-registration aborted (no changes were made)")
	}
	return nil
}
