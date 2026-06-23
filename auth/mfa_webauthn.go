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
func WebAuthnRegisterBegin(db *sql.DB, username string) (options json.RawMessage, backupCodes []string, credentialID string, err error) {
	w, err := GetWebAuthn()
	if err != nil {
		return nil, nil, "", err
	}

	issueCodes, err := ShouldIssueBackupCodes(db, username)
	if err != nil {
		return nil, nil, "", err
	}

	pendingMethod, err := GetPendingMFAMethodType(db, username)
	if err != nil {
		return nil, nil, "", err
	}

	var codes []string
	if pendingMethod == MFAMethodWebAuthn {
		credentialID, err = getPendingWebAuthnCredentialID(db, username)
		if err != nil {
			return nil, nil, "", err
		}
		codes = nil
	} else {
		if err := CanAddMFAMethod(db, username, MFAMethodWebAuthn); err != nil {
			return nil, nil, "", err
		}
		if issueCodes {
			codes, err = generateBackupCodesResilient(BackupCodeCount)
			if err != nil {
				return nil, nil, "", fmt.Errorf("generate backup codes: %w", err)
			}
		}
		credentialID, err = StoreWebAuthnPendingSetup(db, username, codes, issueCodes)
		if err != nil {
			return nil, nil, "", err
		}
	}

	user := newWebAuthnUser(username, nil)
	creation, session, err := w.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementDiscouraged),
	)
	if err != nil {
		return nil, nil, "", fmt.Errorf("begin registration: %w", err)
	}

	if err := SaveWebAuthnSession(username, webAuthnSessionRegister, session); err != nil {
		return nil, nil, "", err
	}

	opts, err := MarshalWebAuthnOptions(creation.Response)
	if err != nil {
		return nil, nil, "", err
	}

	return opts, codes, credentialID, nil
}

// WebAuthnRegisterFinish completes security-key enrollment.
func WebAuthnRegisterFinish(db *sql.DB, username, credentialID, userLabel string, credentialJSON []byte) error {
	now := time.Now().UTC()
	if err := checkMFALockout(db, username, now); err != nil {
		return err
	}

	if err := ValidateWebAuthnUserLabel(userLabel); err != nil {
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

	pendingID, err := getPendingWebAuthnCredentialID(db, username)
	if err != nil {
		return err
	}
	if credentialID != "" && credentialID != pendingID {
		return fmt.Errorf("credential id mismatch for pending enrollment")
	}
	credentialID = pendingID

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

	if err := saveWebAuthnCredential(db, username, credentialID, cred, userLabel, true, true); err != nil {
		return err
	}

	if err := clearMFAFailures(db, username); err != nil {
		return err
	}

	ClearWebAuthnSessionsForUser(username)
	return nil
}

// WebAuthnAuthBegin starts a security-key authentication ceremony for one credential.
func WebAuthnAuthBegin(db *sql.DB, username, credentialID string) (json.RawMessage, error) {
	now := time.Now().UTC()
	if err := checkMFALockout(db, username, now); err != nil {
		return nil, err
	}

	if credentialID == "" {
		var err error
		_, credentialID, err = loadWebAuthnCredentialByMethod(db, username)
		if err != nil {
			return nil, err
		}
	}

	stored, err := loadWebAuthnCredential(db, username, credentialID)
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
	if err := SaveWebAuthnAuthCredentialID(username, credentialID); err != nil {
		return nil, err
	}

	return MarshalWebAuthnOptions(assertion.Response)
}

// WebAuthnAuthFinish verifies a security-key assertion and persists the updated sign counter.
func WebAuthnAuthFinish(db *sql.DB, username, credentialID string, credentialJSON []byte) error {
	now := time.Now().UTC()
	lockState, err := getMFALockoutState(db, username)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lockout state: %w", err)
	}
	if err := checkMFALockout(db, username, now); err != nil {
		return err
	}

	if credentialID == "" {
		credentialID, _ = LoadWebAuthnAuthCredentialID(username)
	}
	if credentialID == "" {
		var loadErr error
		_, credentialID, loadErr = loadWebAuthnCredentialByMethod(db, username)
		if loadErr != nil {
			return loadErr
		}
	}

	row, err := GetCredentialByID(db, username, credentialID)
	if err != nil {
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

	stored, err := loadWebAuthnCredential(db, username, credentialID)
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

	label, _ := extractWebAuthnUserLabel(username, row.CredentialData)
	if err := saveWebAuthnCredential(db, username, credentialID, updated, label, true, true); err != nil {
		return err
	}

	clearMFAFailuresIfLocked(db, username, lockState)
	updateCredentialLastUsed(db, username, credentialID)

	ClearWebAuthnSessionsForUser(username)
	return nil
}

// UpdateWebAuthnUserLabel updates the encrypted user-private label on a security key credential.
func UpdateWebAuthnUserLabel(db *sql.DB, username, credentialID, label string) error {
	row, err := GetCredentialByID(db, username, credentialID)
	if err != nil {
		return err
	}
	if row.MethodType != MFAMethodWebAuthn {
		return fmt.Errorf("labels are supported for security keys only")
	}
	if !row.SetupCompleted {
		return fmt.Errorf("cannot update label on incomplete enrollment")
	}

	encrypted, err := updateWebAuthnUserLabel(username, row.CredentialData, label)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE user_mfa_credentials SET credential_data = ?
		WHERE username = ? AND credential_id = ?`,
		encrypted, username, credentialID,
	)
	return err
}
