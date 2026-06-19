package crypto

import (
	"database/sql"
	"encoding/base64"
	"fmt"
)

// ReencryptMFACredentialData decrypts credential_data under oldMaster and re-encrypts under newMaster.
func ReencryptMFACredentialData(oldMaster, newMaster []byte, username string, encrypted []byte) ([]byte, error) {
	if decoded, err := decodeBase64CiphertextIfNeeded(encrypted); err == nil {
		encrypted = decoded
	}

	oldKey, err := DeriveMFAUserKeyFromMaster(oldMaster, username)
	if err != nil {
		return nil, err
	}
	defer SecureZeroMFAKey(oldKey)

	plaintext, err := DecryptGCM(encrypted, oldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt MFA credential for %s: %w", username, err)
	}

	newKey, err := DeriveMFAUserKeyFromMaster(newMaster, username)
	if err != nil {
		return nil, err
	}
	defer SecureZeroMFAKey(newKey)

	reencrypted, err := EncryptGCM(plaintext, newKey)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encrypt MFA credential for %s: %w", username, err)
	}
	return reencrypted, nil
}

// ReencryptContactInfo decrypts contact info under oldMaster and re-encrypts under newMaster.
func ReencryptContactInfo(oldMaster, newMaster []byte, dataB64, nonceB64 string) (newDataB64, newNonceB64 string, err error) {
	oldKey, err := DeriveUserSecretSubkeyFromMaster(oldMaster, []byte("contact_info"))
	if err != nil {
		return "", "", err
	}
	defer SecureClear(oldKey)

	newKey, err := DeriveUserSecretSubkeyFromMaster(newMaster, []byte("contact_info"))
	if err != nil {
		return "", "", err
	}
	defer SecureClear(newKey)

	ciphertext, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode contact info ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode contact info nonce: %w", err)
	}

	encrypted := append(nonce, ciphertext...)
	plaintext, err := DecryptGCM(encrypted, oldKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt contact info: %w", err)
	}

	reencrypted, err := EncryptGCM(plaintext, newKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to re-encrypt contact info: %w", err)
	}

	nonceSize := AesGcmNonceSize()
	if len(reencrypted) < nonceSize {
		return "", "", fmt.Errorf("re-encrypted contact info too short")
	}
	return base64.StdEncoding.EncodeToString(reencrypted[nonceSize:]),
		base64.StdEncoding.EncodeToString(reencrypted[:nonceSize]),
		nil
}

// UserSecretRotationStats reports how many rows were re-encrypted.
type UserSecretRotationStats struct {
	MFACredentials int
	ContactInfo    int
}

// ReencryptAllUserSecretWrappedRows re-encrypts MFA credentials and contact info in a single transaction.
func ReencryptAllUserSecretWrappedRows(db *sql.DB, oldMaster, newMaster []byte) (UserSecretRotationStats, error) {
	var stats UserSecretRotationStats

	tx, err := db.Begin()
	if err != nil {
		return stats, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT username, credential_data FROM user_mfa_credentials`)
	if err != nil {
		return stats, fmt.Errorf("failed to list MFA credentials: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var credentialData []byte
		if err := rows.Scan(&username, &credentialData); err != nil {
			return stats, err
		}
		reencrypted, err := ReencryptMFACredentialData(oldMaster, newMaster, username, credentialData)
		if err != nil {
			return stats, err
		}
		if _, err := tx.Exec(
			`UPDATE user_mfa_credentials SET credential_data = ? WHERE username = ?`,
			reencrypted, username,
		); err != nil {
			return stats, fmt.Errorf("failed to update MFA credential for %s: %w", username, err)
		}
		stats.MFACredentials++
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	contactRows, err := tx.Query(`SELECT username, encrypted_data, nonce FROM user_contact_info`)
	if err != nil {
		return stats, fmt.Errorf("failed to list contact info rows: %w", err)
	}
	defer contactRows.Close()

	for contactRows.Next() {
		var username, dataB64, nonceB64 string
		if err := contactRows.Scan(&username, &dataB64, &nonceB64); err != nil {
			return stats, err
		}
		newData, newNonce, err := ReencryptContactInfo(oldMaster, newMaster, dataB64, nonceB64)
		if err != nil {
			return stats, fmt.Errorf("contact info for %s: %w", username, err)
		}
		if _, err := tx.Exec(
			`UPDATE user_contact_info SET encrypted_data = ?, nonce = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
			newData, newNonce, username,
		); err != nil {
			return stats, fmt.Errorf("failed to update contact info for %s: %w", username, err)
		}
		stats.ContactInfo++
	}
	if err := contactRows.Err(); err != nil {
		return stats, err
	}

	if err := tx.Commit(); err != nil {
		return stats, fmt.Errorf("failed to commit user-secret re-encryption transaction: %w", err)
	}
	return stats, nil
}

func decodeBase64CiphertextIfNeeded(data []byte) ([]byte, error) {
	if len(data) > 60 && len(data)%4 == 0 {
		isBase64 := true
		for _, b := range data {
			if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
				(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=') {
				isBase64 = false
				break
			}
		}
		if isBase64 {
			decoded, err := base64.StdEncoding.DecodeString(string(data))
			if err == nil {
				return decoded, nil
			}
		}
	}
	return data, nil
}
