package auth

import (
	"bytes"
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

func loadWebAuthnCredential(db *sql.DB, username string) (*webauthn.Credential, error) {
	mfaData, err := getMFAData(db, username)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptWebAuthnBlob(username, mfaData.SecretEncrypted)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(plaintext, webAuthnPendingBlob) {
		return nil, fmt.Errorf("webauthn enrollment still pending")
	}

	var cred webauthn.Credential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("parse webauthn credential: %w", err)
	}
	return &cred, nil
}

func saveWebAuthnCredential(db *sql.DB, username string, cred *webauthn.Credential, enabled, setupCompleted bool) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("marshal webauthn credential: %w", err)
	}

	encrypted, err := encryptWebAuthnBlob(username, raw)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE user_mfa_credentials
		SET credential_data = ?, enabled = ?, setup_completed = ?, method_type = ?
		WHERE username = ?`,
		encrypted, enabled, setupCompleted, MFAMethodWebAuthn, username,
	)
	if err != nil {
		return fmt.Errorf("update webauthn credential: %w", err)
	}
	return nil
}

// StoreWebAuthnPendingSetup creates a pending webauthn enrollment row with backup codes.
func StoreWebAuthnPendingSetup(db *sql.DB, username string, backupCodes []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	encrypted, err := encryptWebAuthnBlob(username, webAuthnPendingBlob)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO user_mfa_credentials (
			username, method_type, credential_data,
			enabled, setup_completed, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		username, MFAMethodWebAuthn, encrypted,
		false, false, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("store pending webauthn row: %w", err)
	}

	_, _ = tx.Exec("DELETE FROM user_mfa_backup_codes WHERE username = ?", username)
	for i, code := range backupCodes {
		salt := deriveBackupCodeSalt(username, i)
		hash, err := crypto.DeriveArgon2IDKey(
			[]byte(code),
			salt,
			crypto.UnifiedArgonSecure.KeyLen,
			crypto.UnifiedArgonSecure.Memory,
			crypto.UnifiedArgonSecure.Time,
			crypto.UnifiedArgonSecure.Threads,
		)
		if err != nil {
			return fmt.Errorf("hash backup code: %w", err)
		}

		_, err = tx.Exec(`
			INSERT INTO user_mfa_backup_codes (username, code_index, code_hash) VALUES (?, ?, ?)`,
			username, i, hash,
		)
		if err != nil {
			return fmt.Errorf("store backup code: %w", err)
		}
	}

	return tx.Commit()
}
