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
	var secretEncrypted []byte
	var setupCompleted bool

	err := db.QueryRow(`
		SELECT credential_data, setup_completed
		FROM user_mfa_credentials
		WHERE username = ?`,
		username,
	).Scan(&secretEncrypted, &setupCompleted)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query pending MFA setup: %w", err)
	}

	if setupCompleted {
		return nil, nil
	}

	if decoded, err := decodeBase64IfNeeded(secretEncrypted); err == nil {
		secretEncrypted = decoded
	}

	secret, err := decryptTOTPSecret(secretEncrypted, username)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt pending TOTP secret: %w", err)
	}

	backupCodes, err := generateBackupCodesResilient(BackupCodeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate fresh backup codes for pending setup: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

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
			return nil, err
		}
		_, err = tx.Exec(
			`INSERT INTO user_mfa_backup_codes (username, code_index, code_hash) VALUES (?, ?, ?)`,
			username, i, hash,
		)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
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

// StoreMFASetup stores enrollment data with user-secret master encryption and hashed backup codes.
func StoreMFASetup(db *sql.DB, username string, setup *MFASetup) error {
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
		INSERT OR REPLACE INTO user_mfa_credentials (
			username, method_type, credential_data,
			enabled, setup_completed, created_at
		) VALUES (?, 'totp', ?, ?, ?, ?)`,
		username, secretEncrypted,
		false, false, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to store MFA config: %w", err)
	}

	_, _ = tx.Exec("DELETE FROM user_mfa_backup_codes WHERE username = ?", username)
	for i, code := range setup.BackupCodes {
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
			return fmt.Errorf("failed to hash backup code: %w", err)
		}

		_, err = tx.Exec(`
			INSERT INTO user_mfa_backup_codes (username, code_index, code_hash) VALUES (?, ?, ?)`,
			username, i, hash,
		)
		if err != nil {
			return fmt.Errorf("failed to save hashed backup code: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit MFA setup transaction: %w", err)
	}

	return nil
}

// CompleteMFASetup validates a test code and enables MFA for the user.
func CompleteMFASetup(db *sql.DB, username, testCode string) error {
	mfaData, err := getMFAData(db, username)
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
		WHERE username = ?`,
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

// ResetMFA stages a new TOTP secret and fresh backup codes; verify must complete before MFA is active.
func ResetMFA(db *sql.DB, username, backupCode string) (*MFASetup, error) {
	if backupCode != "" {
		if err := ValidateBackupCode(db, username, backupCode); err != nil {
			return nil, fmt.Errorf("invalid backup code: %w", err)
		}
	}

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
		UPDATE user_mfa_credentials 
		SET credential_data = ?, created_at = ?, enabled = false, setup_completed = false
		WHERE username = ?`,
		secretEncrypted, time.Now().UTC(), username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update MFA data: %w", err)
	}

	_, _ = tx.Exec("DELETE FROM user_mfa_backup_codes WHERE username = ?", username)
	for i, code := range setup.BackupCodes {
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
			return nil, fmt.Errorf("failed to hash backup code during reset: %w", err)
		}

		_, err = tx.Exec(`
			INSERT INTO user_mfa_backup_codes (username, code_index, code_hash) VALUES (?, ?, ?)`,
			username, i, hash,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert fresh reset backup code: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit reset transaction: %w", err)
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("SECURITY: MFA reset for user: %s", username)
	}

	return setup, nil
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
