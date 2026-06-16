package auth

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// webAuthnUser adapts an Arkfile account to the go-webauthn User interface.
type webAuthnUser struct {
	username    string
	credentials []webauthn.Credential
}

func newWebAuthnUser(username string, credentials []webauthn.Credential) *webAuthnUser {
	return &webAuthnUser{
		username:    username,
		credentials: credentials,
	}
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return []byte(u.username)
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.username
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.username
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	if u.credentials == nil {
		return []webauthn.Credential{}
	}
	return u.credentials
}
