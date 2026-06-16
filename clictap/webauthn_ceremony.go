package clictap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

func b64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

type creationOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	} `json:"pubKeyCredParams"`
	AuthenticatorSelection *struct {
		RequireResidentKey *bool  `json:"requireResidentKey"`
		ResidentKey        string `json:"residentKey"`
		UserVerification   string `json:"userVerification"`
	} `json:"authenticatorSelection"`
}

type requestOptions struct {
	Challenge          string   `json:"challenge"`
	RPID               string   `json:"rpId"`
	AllowCredentials   []credDescriptor `json:"allowCredentials"`
	UserVerification   string   `json:"userVerification"`
}

type credDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func mapUserVerification(uv string) int {
	switch strings.ToLower(strings.TrimSpace(uv)) {
	case "required":
		return OptTrue
	default:
		// Arkfile policy: touch-only (discouraged). Treat missing, preferred, and
		// unknown values as discouraged — never omit UV and let the key default to PIN.
		return OptFalse
	}
}

func mapResidentKey(sel *creationOptions) int {
	if sel == nil || sel.AuthenticatorSelection == nil {
		return OptFalse
	}
	rk := sel.AuthenticatorSelection.ResidentKey
	if rk == "required" || rk == "preferred" {
		return OptTrue
	}
	if sel.AuthenticatorSelection.RequireResidentKey != nil && *sel.AuthenticatorSelection.RequireResidentKey {
		return OptTrue
	}
	return OptFalse
}

func clientDataHash(clientDataJSON []byte) []byte {
	sum := sha256.Sum256(clientDataJSON)
	return sum[:]
}

func buildClientDataCreate(challengeB64, origin string) []byte {
	payload := map[string]string{
		"type":      "webauthn.create",
		"challenge": challengeB64,
		"origin":    origin,
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func buildClientDataGet(challengeB64, origin string) []byte {
	payload := map[string]string{
		"type":      "webauthn.get",
		"challenge": challengeB64,
		"origin":    origin,
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func buildAttestationObject(fmtName string, authData []byte) ([]byte, error) {
	if fmtName == "" {
		fmtName = "none"
	}
	obj := map[string]interface{}{
		"fmt":      fmtName,
		"authData": authData,
		"attStmt":  map[string]interface{}{},
	}
	return cbor.Marshal(obj)
}

// RegisterFromOptions performs CTAP enrollment and returns PublicKeyCredential JSON for the server finish endpoint.
func RegisterFromOptions(optionsJSON []byte, origin string) (json.RawMessage, error) {
	var opts creationOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("parse registration options: %w", err)
	}
	if opts.Challenge == "" || opts.RP.ID == "" || opts.User.ID == "" {
		return nil, fmt.Errorf("registration options missing required fields")
	}

	// EncodeUserIDAsString: user.id is the username as a plain UTF-8 string.
	userID := []byte(opts.User.ID)
	if len(userID) == 0 && opts.User.Name != "" {
		userID = []byte(opts.User.Name)
	}
	if len(userID) == 0 {
		return nil, fmt.Errorf("registration options missing user id")
	}

	clientDataJSON := buildClientDataCreate(opts.Challenge, origin)
	hash := clientDataHash(clientDataJSON)

	devicePath, err := SelectDevice()
	if err != nil {
		return nil, err
	}

	displayName := opts.User.DisplayName
	if displayName == "" {
		displayName = opts.User.Name
	}

	att, err := MakeCredential(devicePath, MakeCredentialOptions{
		ClientDataHash:   hash,
		RPID:             opts.RP.ID,
		RPName:           opts.RP.Name,
		UserID:           userID,
		UserName:         opts.User.Name,
		UserDisplayName:  displayName,
		ResidentKey:      mapResidentKey(&opts),
		UserVerification: mapUserVerification(uvFromCreation(opts)),
	})
	if err != nil {
		return nil, err
	}

	attObj, err := buildAttestationObject(att.AttestationFmt, att.AuthData)
	if err != nil {
		return nil, err
	}

	credID := att.CredentialID
	cred := map[string]interface{}{
		"id":    b64URL(credID),
		"rawId": b64URL(credID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    b64URL(clientDataJSON),
			"attestationObject": b64URL(attObj),
		},
	}
	return json.Marshal(cred)
}

func uvFromCreation(opts creationOptions) string {
	if opts.AuthenticatorSelection == nil {
		return "discouraged"
	}
	uv := strings.TrimSpace(opts.AuthenticatorSelection.UserVerification)
	if uv == "" {
		return "discouraged"
	}
	return uv
}

// AuthenticateFromOptions performs CTAP authentication and returns PublicKeyCredential JSON.
func AuthenticateFromOptions(optionsJSON []byte, origin string) (json.RawMessage, error) {
	var opts requestOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("parse authentication options: %w", err)
	}
	if opts.Challenge == "" || opts.RPID == "" {
		return nil, fmt.Errorf("authentication options missing required fields")
	}

	clientDataJSON := buildClientDataGet(opts.Challenge, origin)
	hash := clientDataHash(clientDataJSON)

	allowIDs := make([][]byte, 0, len(opts.AllowCredentials))
	for _, c := range opts.AllowCredentials {
		if c.Type != "" && c.Type != "public-key" {
			continue
		}
		id, err := decodeB64URL(c.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid allowCredentials id: %w", err)
		}
		allowIDs = append(allowIDs, id)
	}

	devicePath, err := SelectDevice()
	if err != nil {
		return nil, err
	}

	assertion, err := GetAssertion(devicePath, AssertOptions{
		ClientDataHash:       hash,
		RPID:                 opts.RPID,
		AllowCredentialIDs: allowIDs,
		UserVerification:   mapUserVerification(opts.UserVerification),
	})
	if err != nil {
		return nil, err
	}

	credID := assertion.CredentialID
	resp := map[string]interface{}{
		"id":    b64URL(credID),
		"rawId": b64URL(credID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    b64URL(clientDataJSON),
			"authenticatorData": b64URL(assertion.AuthData),
			"signature":         b64URL(assertion.Signature),
		},
	}
	return json.Marshal(resp)
}

// OriginFromServerURL derives the WebAuthn origin from the CLI server base URL.
func OriginFromServerURL(serverURL string) string {
	return strings.TrimRight(strings.TrimSpace(serverURL), "/")
}
