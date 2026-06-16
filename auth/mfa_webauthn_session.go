package auth

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const webAuthnSessionTTL = 5 * time.Minute

type webAuthnSessionKind string

const (
	webAuthnSessionRegister webAuthnSessionKind = "register"
	webAuthnSessionAuth     webAuthnSessionKind = "auth"
)

type webAuthnSessionEntry struct {
	data      webauthn.SessionData
	expiresAt time.Time
}

var (
	webAuthnSessionMu sync.Mutex
	webAuthnSessions  = map[string]webAuthnSessionEntry{}
)

func webAuthnSessionKey(username string, kind webAuthnSessionKind) string {
	return username + ":" + string(kind)
}

// SaveWebAuthnSession stores ceremony state between begin and finish.
func SaveWebAuthnSession(username string, kind webAuthnSessionKind, data *webauthn.SessionData) error {
	if data == nil {
		return fmt.Errorf("session data is nil")
	}
	if data.Expires.IsZero() {
		data.Expires = time.Now().UTC().Add(webAuthnSessionTTL)
	}

	webAuthnSessionMu.Lock()
	defer webAuthnSessionMu.Unlock()
	webAuthnSessions[webAuthnSessionKey(username, kind)] = webAuthnSessionEntry{
		data:      *data,
		expiresAt: data.Expires,
	}
	return nil
}

// LoadWebAuthnSession returns stored ceremony state and removes it (one-time use).
func LoadWebAuthnSession(username string, kind webAuthnSessionKind) (webauthn.SessionData, error) {
	key := webAuthnSessionKey(username, kind)

	webAuthnSessionMu.Lock()
	defer webAuthnSessionMu.Unlock()

	entry, ok := webAuthnSessions[key]
	if !ok {
		return webauthn.SessionData{}, fmt.Errorf("webauthn session not found")
	}
	delete(webAuthnSessions, key)

	if time.Now().UTC().After(entry.expiresAt) {
		return webAuthn.SessionData{}, fmt.Errorf("webauthn session expired")
	}

	return entry.data, nil
}

// ClearWebAuthnSessionsForUser removes any in-flight ceremony state for a user.
func ClearWebAuthnSessionsForUser(username string) {
	webAuthnSessionMu.Lock()
	defer webAuthnSessionMu.Unlock()
	delete(webAuthnSessions, webAuthnSessionKey(username, webAuthnSessionRegister))
	delete(webAuthnSessions, webAuthnSessionKey(username, webAuthnSessionAuth))
}

// MarshalWebAuthnOptions JSON-encodes protocol options for API responses.
func MarshalWebAuthnOptions(v interface{}) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}
