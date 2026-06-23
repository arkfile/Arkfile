package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthnPendingBlob = []byte(`{"pending":true}`)

func encryptWebAuthnBlob(username string, plaintext []byte) ([]byte, error) {
	mfaKey, err := crypto.DeriveMFAUserKey(username)
	if err != nil {
		return nil, fmt.Errorf("derive MFA key: %w", err)
	}
	defer crypto.SecureZeroMFAKey(mfaKey)

	encrypted, err := crypto.EncryptGCM(plaintext, mfaKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt credential blob: %w", err)
	}
	return encrypted, nil
}

func decryptWebAuthnBlob(username string, encrypted []byte) ([]byte, error) {
	if decoded, err := decodeBase64IfNeeded(encrypted); err == nil {
		encrypted = decoded
	}

	mfaKey, err := crypto.DeriveMFAUserKey(username)
	if err != nil {
		return nil, fmt.Errorf("derive MFA key: %w", err)
	}
	defer crypto.SecureZeroMFAKey(mfaKey)

	plaintext, err := crypto.DecryptGCM(encrypted, mfaKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt credential blob: %w", err)
	}
	return plaintext, nil
}

func loadWebAuthnCredential(db *sql.DB, username, credentialID string) (*webauthn.Credential, error) {
	row, err := GetCredentialByID(db, username, credentialID)
	if err != nil {
		return nil, err
	}
	if row.MethodType != MFAMethodWebAuthn {
		return nil, fmt.Errorf("credential is not a security key enrollment")
	}
	return loadWebAuthnCredentialFromRow(username, row.CredentialData)
}

func loadWebAuthnCredentialByMethod(db *sql.DB, username string) (*webauthn.Credential, string, error) {
	row, err := GetCredentialByMethod(db, username, MFAMethodWebAuthn)
	if err != nil {
		return nil, "", err
	}
	cred, err := loadWebAuthnCredentialFromRow(username, row.CredentialData)
	if err != nil {
		return nil, "", err
	}
	return cred, row.CredentialID, nil
}

func saveWebAuthnCredential(db *sql.DB, username, credentialID string, cred *webauthn.Credential, userLabel string, enabled, setupCompleted bool) error {
	encrypted, err := encodeWebAuthnCredentialBlob(username, cred, userLabel)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE user_mfa_credentials
		SET credential_data = ?, enabled = ?, setup_completed = ?
		WHERE username = ? AND credential_id = ?`,
		encrypted, enabled, setupCompleted, username, credentialID,
	)
	if err != nil {
		return fmt.Errorf("update webauthn credential: %w", err)
	}
	return nil
}

// StoreWebAuthnPendingSetup creates a pending webauthn enrollment row.
func StoreWebAuthnPendingSetup(db *sql.DB, username string, backupCodes []string, issueBackupCodes bool) (string, error) {
	if err := CanAddMFAMethod(db, username, MFAMethodWebAuthn); err != nil {
		return "", err
	}

	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	encrypted, err := encryptWebAuthnBlob(username, webAuthnPendingBlob)
	if err != nil {
		return "", err
	}

	credentialID := newCredentialID()
	_, err = tx.Exec(`
		INSERT INTO user_mfa_credentials (
			credential_id, username, method_type, credential_data,
			enabled, setup_completed, created_at
		) VALUES (?, ?, 'webauthn', ?, ?, ?, ?)`,
		credentialID, username, encrypted,
		false, false, time.Now().UTC(),
	)
	if err != nil {
		return "", fmt.Errorf("store pending webauthn row: %w", err)
	}

	if issueBackupCodes && len(backupCodes) > 0 {
		if err := storeBackupCodesTx(tx, username, backupCodes, true); err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	return credentialID, nil
}

func getPendingWebAuthnCredentialID(db *sql.DB, username string) (string, error) {
	row, err := GetCredentialByMethod(db, username, MFAMethodWebAuthn)
	if err != nil {
		return "", err
	}
	if row.SetupCompleted {
		return "", fmt.Errorf("webauthn already completed")
	}
	return row.CredentialID, nil
}

func marshalCredentialForDebug(cred *webauthn.Credential) ([]byte, error) {
	return json.Marshal(cred)
}
