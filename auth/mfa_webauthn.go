package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/go-webauthn/webauthn/protocol"
)

// WebAuthnRegisterBegin starts security-key enrollment for a user.
func WebAuthnRegisterBegin(db *sql.DB, username string) (options json.RawMessage, backupCodes []string, err error) {
	enabled, err := IsUserMFAEnabled(db, username)
	if err != nil {
		return nil, nil, err
	}
	if enabled {
		return nil, nil, fmt.Errorf("MFA already enabled")
	}

	w, err := GetWebAuthn()
	if err != nil {
		return nil, nil, err
	}

	pendingMethod, err := GetPendingMFAMethodType(db, username)
	if err != nil {
		return nil, nil, err
	}

	var codes []string
	if pendingMethod == MFAMethodWebAuthn {
		// Resume pending enrollment: backup codes were already issued at first begin.
		codes = nil
	} else {
		codes, err = generateBackupCodesResilient(BackupCodeCount)
		if err != nil {
			return nil, nil, fmt.Errorf("generate backup codes: %w", err)
		}
		if err := StoreWebAuthnPendingSetup(db, username, codes); err != nil {
			return nil, nil, err
		}
	}

	user := newWebAuthnUser(username, nil)
	creation, session, err := w.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementDiscouraged),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("begin registration: %w", err)
	}

	if err := SaveWebAuthnSession(username, webAuthnSessionRegister, session); err != nil {
		return nil, nil, err
	}

	opts, err := MarshalWebAuthnOptions(creation.Response)
	if err != nil {
		return nil, nil, err
	}

	return opts, codes, nil
}

// WebAuthnRegisterFinish completes security-key enrollment.
func WebAuthnRegisterFinish(db *sql.DB, username string, credentialJSON []byte) error {
	now := time.Now().UTC()
	if err := checkMFALockout(db, username, now); err != nil {
		return err
	}

	w, err := GetWebAuthn()
	if err != nil {
		return err
	}

	session, err := LoadWebAuthnSession(username, webAuthnSessionRegister)
	if err != nil {
		return err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credentialJSON))
	if err != nil {
		recordMFAFailureAndEmit(db, username, now)
		return fmt.Errorf("parse registration response: %w", err)
	}

	user := newWebAuthnUser(username, nil)
	cred, err := w.CreateCredential(user, session, parsed)
	if err != nil {
		recordMFAFailureAndEmit(db, username, now)
		return fmt.Errorf("verify registration: %w", err)
	}

	if err := saveWebAuthnCredential(db, username, cred, true, true); err != nil {
		return err
	}

	if err := clearMFAFailures(db, username); err != nil {
		return err
	}

	ClearWebAuthnSessionsForUser(username)
	return nil
}

// WebAuthnAuthBegin starts a security-key authentication ceremony.
func WebAuthnAuthBegin(db *sql.DB, username string) (json.RawMessage, error) {
	now := time.Now().UTC()
	if err := checkMFALockout(db, username, now); err != nil {
		return nil, err
	}

	method, err := GetUserMFAMethodType(db, username)
	if err != nil {
		return nil, err
	}
	if method != MFAMethodWebAuthn {
		return nil, fmt.Errorf("user is not enrolled with a security key")
	}

	stored, err := loadWebAuthnCredential(db, username)
	if err != nil {
		return nil, err
	}

	w, err := GetWebAuthn()
	if err != nil {
		return nil, err
	}

	user := newWebAuthnUser(username, []webauthn.Credential{*stored})
	assertion, session, err := w.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("begin login: %w", err)
	}

	if err := SaveWebAuthnSession(username, webAuthnSessionAuth, session); err != nil {
		return nil, err
	}

	return MarshalWebAuthnOptions(assertion.Response)
}

// WebAuthnAuthFinish verifies a security-key assertion and persists the updated sign counter.
func WebAuthnAuthFinish(db *sql.DB, username string, credentialJSON []byte) error {
	now := time.Now().UTC()
	lockState, err := getMFALockoutState(db, username)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lockout state: %w", err)
	}
	if err := checkMFALockout(db, username, now); err != nil {
		return err
	}

	w, err := GetWebAuthn()
	if err != nil {
		return err
	}

	session, err := LoadWebAuthnSession(username, webAuthnSessionAuth)
	if err != nil {
		return err
	}

	stored, err := loadWebAuthnCredential(db, username)
	if err != nil {
		return err
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credentialJSON))
	if err != nil {
		recordMFAFailureAndEmit(db, username, now)
		return fmt.Errorf("parse assertion response: %w", err)
	}

	user := newWebAuthnUser(username, []webauthn.Credential{*stored})
	updated, err := w.ValidateLogin(user, session, parsed)
	if err != nil {
		recordMFAFailureAndEmit(db, username, now)
		return fmt.Errorf("verify assertion: %w", err)
	}

	if err := saveWebAuthnCredential(db, username, updated, true, true); err != nil {
		return err
	}

	clearMFAFailuresIfLocked(db, username, lockState)

	_, err = db.Exec("UPDATE user_mfa_credentials SET last_used = ? WHERE username = ?",
		time.Now().UTC(), username)
	if err != nil {
		return fmt.Errorf("update last_used: %w", err)
	}

	ClearWebAuthnSessionsForUser(username)
	return nil
}
