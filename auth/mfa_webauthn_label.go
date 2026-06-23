package auth

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	MaxWebAuthnUserLabelLen = 64
	webAuthnBlobVersion     = 1
)

type webAuthnStoredBlob struct {
	Version   int                  `json:"v,omitempty"`
	Pending   bool                 `json:"pending,omitempty"`
	Credential *webauthn.Credential `json:"credential,omitempty"`
	UserLabel string               `json:"user_label,omitempty"`
}

// ValidateWebAuthnUserLabel checks optional user-private security key labels.
func ValidateWebAuthnUserLabel(label string) error {
	label = strings.TrimSpace(label)
	if label == "" {
		return nil
	}
	if len(label) > MaxWebAuthnUserLabelLen {
		return fmt.Errorf("label must be at most %d characters", MaxWebAuthnUserLabelLen)
	}
	for i := 0; i < len(label); i++ {
		if label[i] < 0x20 || label[i] > 0x7E {
			return fmt.Errorf("label must contain ASCII printable characters only")
		}
	}
	return nil
}

func normalizeWebAuthnUserLabel(label string) string {
	return strings.TrimSpace(label)
}

func marshalWebAuthnStoredBlob(blob webAuthnStoredBlob) ([]byte, error) {
	raw, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("marshal webauthn blob: %w", err)
	}
	return raw, nil
}

func parseWebAuthnStoredBlob(plaintext []byte) (webAuthnStoredBlob, error) {
	if bytesEqual(plaintext, webAuthnPendingBlob) {
		return webAuthnStoredBlob{Pending: true}, nil
	}

	var blob webAuthnStoredBlob
	if err := json.Unmarshal(plaintext, &blob); err == nil {
		if blob.Pending || blob.Credential != nil || blob.Version > 0 {
			return blob, nil
		}
	}

	var cred webauthn.Credential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return webAuthnStoredBlob{}, fmt.Errorf("parse webauthn credential blob: %w", err)
	}
	return webAuthnStoredBlob{
		Version:    webAuthnBlobVersion,
		Credential: &cred,
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func extractWebAuthnUserLabel(username string, encrypted []byte) (string, error) {
	plaintext, err := decryptWebAuthnBlob(username, encrypted)
	if err != nil {
		return "", err
	}
	blob, err := parseWebAuthnStoredBlob(plaintext)
	if err != nil {
		return "", err
	}
	return blob.UserLabel, nil
}

func loadWebAuthnCredentialFromRow(username string, encrypted []byte) (*webauthn.Credential, error) {
	plaintext, err := decryptWebAuthnBlob(username, encrypted)
	if err != nil {
		return nil, err
	}
	blob, err := parseWebAuthnStoredBlob(plaintext)
	if err != nil {
		return nil, err
	}
	if blob.Pending || bytesEqual(plaintext, webAuthnPendingBlob) {
		return nil, fmt.Errorf("webauthn enrollment still pending")
	}
	if blob.Credential == nil {
		return nil, fmt.Errorf("webauthn credential missing from blob")
	}
	return blob.Credential, nil
}

func encodeWebAuthnCredentialBlob(username string, cred *webauthn.Credential, userLabel string) ([]byte, error) {
	label := normalizeWebAuthnUserLabel(userLabel)
	if err := ValidateWebAuthnUserLabel(label); err != nil {
		return nil, err
	}
	blob := webAuthnStoredBlob{
		Version:    webAuthnBlobVersion,
		Credential: cred,
		UserLabel:  label,
	}
	raw, err := marshalWebAuthnStoredBlob(blob)
	if err != nil {
		return nil, err
	}
	return encryptWebAuthnBlob(username, raw)
}

func updateWebAuthnUserLabel(username string, encrypted []byte, newLabel string) ([]byte, error) {
	label := normalizeWebAuthnUserLabel(newLabel)
	if err := ValidateWebAuthnUserLabel(label); err != nil {
		return nil, err
	}
	plaintext, err := decryptWebAuthnBlob(username, encrypted)
	if err != nil {
		return nil, err
	}
	blob, err := parseWebAuthnStoredBlob(plaintext)
	if err != nil {
		return nil, err
	}
	if blob.Pending || blob.Credential == nil {
		return nil, fmt.Errorf("cannot set label on pending webauthn enrollment")
	}
	blob.Version = webAuthnBlobVersion
	blob.UserLabel = label
	raw, err := marshalWebAuthnStoredBlob(blob)
	if err != nil {
		return nil, err
	}
	return encryptWebAuthnBlob(username, raw)
}
