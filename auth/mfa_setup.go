package auth

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// GenerateMFASetup creates new TOTP enrollment material for a user.
func GenerateMFASetup(username string) (*MFASetup, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secretB32 := base32.StdEncoding.EncodeToString(secret)
	secretB32 = strings.TrimRight(secretB32, "=")

	qrURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		TOTPIssuer, username, secretB32, TOTPIssuer, TOTPDigits, TOTPPeriod)

	backupCodes, err := generateBackupCodesResilient(BackupCodeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	qrImage, err := generateQRCodeDataURI(qrURL)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to generate QR code image: %v", err)
		}
		qrImage = ""
	}

	return &MFASetup{
		Secret:      secretB32,
		QRCodeURL:   qrURL,
		QRCodeImage: qrImage,
		BackupCodes: backupCodes,
		ManualEntry: formatManualEntry(secretB32),
	}, nil
}

// GetPendingMFASetup retrieves an existing pending (unverified) TOTP setup for a user.
func GetPendingMFASetup(db *sql.DB, username string) (*MFASetup, error) {
	row, err := GetCredentialByMethod(db, username, MFAMethodTOTP)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query pending MFA setup: %w", err)
	}

	if row.SetupCompleted {
		return nil, nil
	}

	secret, err := decryptTOTPSecret(row.CredentialData, username)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt pending TOTP secret: %w", err)
	}

	var backupCodes []string
	issueCodes, err := ShouldIssueBackupCodes(db, username)
	if err != nil {
		return nil, err
	}
	if issueCodes {
		backupCodes, err = generateBackupCodesResilient(BackupCodeCount)
		if err != nil {
			return nil, fmt.Errorf("failed to generate fresh backup codes for pending setup: %w", err)
		}
		if err := storeBackupCodes(db, username, backupCodes, true); err != nil {
			return nil, err
		}
	}

	qrURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		TOTPIssuer, username, secret, TOTPIssuer, TOTPDigits, TOTPPeriod)

	qrImage, err := generateQRCodeDataURI(qrURL)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to regenerate QR code image for pending setup: %v", err)
		}
		qrImage = ""
	}

	return &MFASetup{
		Secret:      secret,
		QRCodeURL:   qrURL,
		QRCodeImage: qrImage,
		BackupCodes: backupCodes,
		ManualEntry: formatManualEntry(secret),
	}, nil
}

// StoreMFASetup stores TOTP enrollment data with optional backup code issuance.
func StoreMFASetup(db *sql.DB, username string, setup *MFASetup) error {
	return StoreMFASetupWithPolicy(db, username, setup, true)
}

// StoreMFASetupWithPolicy stores TOTP enrollment and optionally persists backup codes.
func StoreMFASetupWithPolicy(db *sql.DB, username string, setup *MFASetup, issueBackupCodes bool) error {
	if err := CanAddMFAMethod(db, username, MFAMethodTOTP); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	mfaKey, err := crypto.DeriveMFAUserKey(username)
	if err != nil {
		return fmt.Errorf("failed to derive MFA user key: %w", err)
	}
	defer crypto.SecureZeroMFAKey(mfaKey)

	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), mfaKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	_, err = tx.Exec(`
		INSERT INTO user_mfa_credentials (
			credential_id, username, method_type, credential_data,
			enabled, setup_completed, created_at
		) VALUES (?, ?, 'totp', ?, ?, ?, ?)`,
		newCredentialID(), username, secretEncrypted,
		false, false, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to store MFA config: %w", err)
	}

	if issueBackupCodes && len(setup.BackupCodes) > 0 {
		if err := storeBackupCodesTx(tx, username, setup.BackupCodes, true); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit MFA setup transaction: %w", err)
	}

	return nil
}

// CompleteMFASetup validates a test code and enables TOTP for the user.
func CompleteMFASetup(db *sql.DB, username, testCode string) error {
	mfaData, err := getMFADataByMethod(db, username, MFAMethodTOTP)
	if err != nil {
		return fmt.Errorf("failed to get MFA data: %w", err)
	}

	if mfaData.SetupCompleted {
		return fmt.Errorf("MFA setup already completed")
	}

	secret, err := decryptTOTPSecret(mfaData.SecretEncrypted, username)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	if !validateTOTPCodeInternal(secret, testCode) {
		return fmt.Errorf("invalid TOTP code")
	}

	_, err = db.Exec(`
		UPDATE user_mfa_credentials
		SET enabled = true, setup_completed = true
		WHERE username = ? AND method_type = 'totp'`,
		username,
	)
	if err != nil {
		return fmt.Errorf("failed to complete MFA setup: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("MFA setup completed for user: %s", username)
	}

	return nil
}

// ResetMFA stages a new TOTP secret and fresh backup codes for path B recovery.
func ResetMFA(db *sql.DB, username, backupCode string) (*MFASetup, error) {
	return ResetMFAMethod(db, username, MFAMethodTOTP, backupCode)
}

// ResetMFAMethod replaces one MFA method type during recovery.
func ResetMFAMethod(db *sql.DB, username, methodType, backupCode string) (*MFASetup, error) {
	if backupCode != "" {
		if err := ValidateBackupCode(db, username, backupCode); err != nil {
			return nil, fmt.Errorf("invalid backup code: %w", err)
		}
	}

	switch methodType {
	case MFAMethodTOTP:
		return resetTOTPMethod(db, username)
	case MFAMethodWebAuthn:
		return resetWebAuthnMethod(db, username)
	default:
		return nil, fmt.Errorf("unsupported MFA method type for reset")
	}
}

func resetTOTPMethod(db *sql.DB, username string) (*MFASetup, error) {
	setup, err := GenerateMFASetup(username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new MFA setup: %w", err)
	}

	mfaKey, err := crypto.DeriveMFAUserKey(username)
	if err != nil {
		return nil, fmt.Errorf("failed to derive MFA user key: %w", err)
	}
	defer crypto.SecureZeroMFAKey(mfaKey)

	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), mfaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		DELETE FROM user_mfa_credentials WHERE username = ? AND method_type = 'totp'`,
		username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to clear existing TOTP credential: %w", err)
	}

	_, err = tx.Exec(`
		INSERT INTO user_mfa_credentials (
			credential_id, username, method_type, credential_data,
			enabled, setup_completed, created_at
		) VALUES (?, ?, 'totp', ?, ?, ?, ?)`,
		newCredentialID(), username, secretEncrypted, false, false, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store reset TOTP credential: %w", err)
	}

	if err := storeBackupCodesTx(tx, username, setup.BackupCodes, true); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit reset transaction: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("SECURITY: MFA TOTP reset for user: %s", username)
	}

	return setup, nil
}

func resetWebAuthnMethod(db *sql.DB, username string) (*MFASetup, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`DELETE FROM user_mfa_credentials WHERE username = ? AND method_type = 'webauthn'`, username)
	if err != nil {
		return nil, fmt.Errorf("failed to clear webauthn credential: %w", err)
	}

	encrypted, err := encryptWebAuthnBlob(username, webAuthnPendingBlob)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(`
		INSERT INTO user_mfa_credentials (
			credential_id, username, method_type, credential_data,
			enabled, setup_completed, created_at
		) VALUES (?, ?, 'webauthn', ?, ?, ?, ?)`,
		newCredentialID(), username, encrypted, false, false, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store pending webauthn reset row: %w", err)
	}

	codes, err := generateBackupCodesResilient(BackupCodeCount)
	if err != nil {
		return nil, err
	}
	if err := storeBackupCodesTx(tx, username, codes, true); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("SECURITY: MFA WebAuthn reset for user: %s", username)
	}

	return &MFASetup{BackupCodes: codes}, nil
}

func generateQRCodeDataURI(content string) (string, error) {
	qrCode, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("failed to encode QR code: %w", err)
	}

	qrCode, err = barcode.Scale(qrCode, 200, 200)
	if err != nil {
		return "", fmt.Errorf("failed to scale QR code: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, qrCode); err != nil {
		return "", fmt.Errorf("failed to encode PNG: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return "data:image/png;base64," + b64, nil
}

func formatManualEntry(secret string) string {
	formatted := ""
	for i, char := range secret {
		if i > 0 && i%4 == 0 {
			formatted += " "
		}
		formatted += string(char)
	}
	return formatted
}

// RemoveUserCredential deletes one credential and clears backup codes if none remain completed.
func RemoveUserCredential(db *sql.DB, username, credentialID string) (bool, error) {
	row, err := GetCredentialByID(db, username, credentialID)
	if err != nil {
		return false, err
	}

	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM user_mfa_credentials WHERE username = ? AND credential_id = ?`, username, credentialID); err != nil {
		return false, err
	}

	var remaining int
	if err := tx.QueryRow(`
		SELECT COUNT(*) FROM user_mfa_credentials
		WHERE username = ? AND enabled = 1 AND setup_completed = 1`,
		username,
	).Scan(&remaining); err != nil {
		return false, err
	}

	clearAllBackupCodes := remaining == 0
	if clearAllBackupCodes {
		if _, err := tx.Exec(`DELETE FROM user_mfa_backup_codes WHERE username = ?`, username); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}

	_ = row
	return clearAllBackupCodes, nil
}
