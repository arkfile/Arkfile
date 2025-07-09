package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/logging"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	TOTPIssuer       = "ArkFile"
	TOTPDigits       = 6
	TOTPPeriod       = 30
	TOTPSkew         = 1 // Allow ±1 window (90 seconds total)
	BackupCodeLength = 10
	BackupCodeCount  = 10
)

// Human-friendly backup code character set (excludes B/8, O/0, I/1, S/5, Z/2)
const BackupCodeCharset = "ACDEFGHJKLMNPQRTUVWXY34679"

// TOTPSetup represents the data needed for TOTP setup
type TOTPSetup struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qrCodeUrl"`
	BackupCodes []string `json:"backupCodes"`
	ManualEntry string   `json:"manualEntry"`
}

// TOTPData represents the stored TOTP data for a user
type TOTPData struct {
	SecretEncrypted      []byte `json:"secret_encrypted"`
	BackupCodesEncrypted []byte `json:"backup_codes_encrypted"`
	Enabled              bool   `json:"enabled"`
	SetupCompleted       bool   `json:"setup_completed"`
	CreatedAt            time.Time
	LastUsed             *time.Time
}

// GenerateTOTPSetup creates a new TOTP setup for a user
func GenerateTOTPSetup(userEmail string, sessionKey []byte) (*TOTPSetup, error) {
	// Generate 32-byte secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Encode as base32 for TOTP compatibility
	secretB32 := base32.StdEncoding.EncodeToString(secret)

	// Remove padding for cleaner display
	secretB32 = trimPadding(secretB32)

	// Generate QR code URL
	qrURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		TOTPIssuer, userEmail, secretB32, TOTPIssuer, TOTPDigits, TOTPPeriod)

	// Generate backup codes
	backupCodes := generateBackupCodes(BackupCodeCount)

	return &TOTPSetup{
		Secret:      secretB32,
		QRCodeURL:   qrURL,
		BackupCodes: backupCodes,
		ManualEntry: formatManualEntry(secretB32),
	}, nil
}

// StoreTOTPSetup stores the TOTP setup data in the database (encrypted)
func StoreTOTPSetup(db *sql.DB, userEmail string, setup *TOTPSetup, sessionKey []byte) error {
	// Derive TOTP-specific encryption key
	totpKey, err := crypto.DeriveSessionKey(sessionKey, crypto.TOTPEncryptionContext)
	if err != nil {
		return fmt.Errorf("failed to derive TOTP key: %w", err)
	}
	defer crypto.SecureZeroSessionKey(totpKey)

	// Encrypt the TOTP secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Encrypt backup codes as JSON
	backupCodesJSON, err := json.Marshal(setup.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt backup codes: %w", err)
	}

	// Store in database
	_, err = db.Exec(`
		INSERT OR REPLACE INTO user_totp (
			user_email, secret_encrypted, backup_codes_encrypted, 
			enabled, setup_completed, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		userEmail, secretEncrypted, backupCodesEncrypted,
		false, false, time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to store TOTP setup: %w", err)
	}

	return nil
}

// CompleteTOTPSetup validates a test code and enables TOTP for the user
func CompleteTOTPSetup(db *sql.DB, userEmail, testCode string, sessionKey []byte) error {
	// Get stored TOTP data
	totpData, err := getTOTPData(db, userEmail)
	if err != nil {
		return fmt.Errorf("failed to get TOTP data: %w", err)
	}

	if totpData.SetupCompleted {
		return fmt.Errorf("TOTP setup already completed")
	}

	// Decrypt secret
	secret, err := decryptTOTPSecret(totpData.SecretEncrypted, sessionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Validate the test code
	if !validateTOTPCodeInternal(secret, testCode) {
		return fmt.Errorf("invalid TOTP code")
	}

	// Enable TOTP and mark setup as completed
	_, err = db.Exec(`
		UPDATE user_totp 
		SET enabled = true, setup_completed = true 
		WHERE user_email = ?`,
		userEmail,
	)

	if err != nil {
		return fmt.Errorf("failed to complete TOTP setup: %w", err)
	}

	// Log successful TOTP setup
	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("TOTP setup completed for user: %s", userEmail)
	}

	return nil
}

// ValidateTOTPCode validates a TOTP code with replay protection
func ValidateTOTPCode(db *sql.DB, userEmail, code string, sessionKey []byte) error {
	// Get user's TOTP data
	totpData, err := getTOTPData(db, userEmail)
	if err != nil {
		return fmt.Errorf("failed to get TOTP data: %w", err)
	}

	if !totpData.Enabled || !totpData.SetupCompleted {
		return fmt.Errorf("TOTP not enabled for user")
	}

	// Decrypt secret
	secret, err := decryptTOTPSecret(totpData.SecretEncrypted, sessionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Validate code with time windows (90-second tolerance)
	now := time.Now()
	for i := -TOTPSkew; i <= TOTPSkew; i++ {
		testTime := now.Add(time.Duration(i) * time.Duration(TOTPPeriod) * time.Second)

		expectedCode, err := totp.GenerateCodeCustom(secret, testTime, totp.ValidateOpts{
			Period:    TOTPPeriod,
			Skew:      0, // We handle skew manually
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})

		if err != nil {
			continue
		}

		if expectedCode == code {
			// Check for replay attack
			if err := checkTOTPReplay(db, userEmail, code, testTime); err != nil {
				return fmt.Errorf("replay attack detected: %w", err)
			}

			// Log usage
			if err := logTOTPUsage(db, userEmail, code, testTime); err != nil {
				return fmt.Errorf("failed to log TOTP usage: %w", err)
			}

			// Update last used timestamp
			_, err = db.Exec("UPDATE user_totp SET last_used = ? WHERE user_email = ?",
				time.Now(), userEmail)
			if err != nil {
				// Log but don't fail
				if logging.ErrorLogger != nil {
					logging.ErrorLogger.Printf("Failed to update TOTP last_used: %v", err)
				}
			}

			return nil // Valid code
		}
	}

	return fmt.Errorf("invalid TOTP code")
}

// ValidateBackupCode validates and consumes a backup code
func ValidateBackupCode(db *sql.DB, userEmail, code string, sessionKey []byte) error {
	// Get user's TOTP data
	totpData, err := getTOTPData(db, userEmail)
	if err != nil {
		return fmt.Errorf("failed to get TOTP data: %w", err)
	}

	if !totpData.Enabled || !totpData.SetupCompleted {
		return fmt.Errorf("TOTP not enabled for user")
	}

	// Decrypt backup codes
	var backupCodes []string
	if err := decryptJSON(totpData.BackupCodesEncrypted, sessionKey, &backupCodes); err != nil {
		return fmt.Errorf("failed to decrypt backup codes: %w", err)
	}

	// Check if code exists and not used
	codeHash := hashString(code)
	if err := checkBackupCodeReplay(db, userEmail, codeHash); err != nil {
		return fmt.Errorf("backup code already used: %w", err)
	}

	// Find and validate code
	codeFound := false
	for _, validCode := range backupCodes {
		if validCode == code {
			codeFound = true
			break
		}
	}

	if !codeFound {
		return fmt.Errorf("invalid backup code")
	}

	// Mark as used
	if err := logBackupCodeUsage(db, userEmail, codeHash); err != nil {
		return fmt.Errorf("failed to log backup code usage: %w", err)
	}

	// Update last used timestamp
	_, err = db.Exec("UPDATE user_totp SET last_used = ? WHERE user_email = ?",
		time.Now(), userEmail)
	if err != nil {
		// Log but don't fail
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to update TOTP last_used after backup code: %v", err)
		}
	}

	return nil
}

// IsUserTOTPEnabled checks if TOTP is enabled for a user
func IsUserTOTPEnabled(db *sql.DB, userEmail string) (bool, error) {
	var enabled bool
	var setupCompleted bool

	err := db.QueryRow(`
		SELECT enabled, setup_completed 
		FROM user_totp 
		WHERE user_email = ?`,
		userEmail,
	).Scan(&enabled, &setupCompleted)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check TOTP status: %w", err)
	}

	return enabled && setupCompleted, nil
}

// DisableTOTP disables TOTP for a user (requires current TOTP code)
func DisableTOTP(db *sql.DB, userEmail, currentCode string, sessionKey []byte) error {
	// Validate current code first
	if err := ValidateTOTPCode(db, userEmail, currentCode, sessionKey); err != nil {
		return fmt.Errorf("invalid current TOTP code: %w", err)
	}

	// Disable TOTP
	_, err := db.Exec("DELETE FROM user_totp WHERE user_email = ?", userEmail)
	if err != nil {
		return fmt.Errorf("failed to disable TOTP: %w", err)
	}

	// Log the action
	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("TOTP disabled for user: %s", userEmail)
	}

	return nil
}

// CleanupTOTPLogs removes old TOTP usage logs
func CleanupTOTPLogs(db *sql.DB) error {
	cutoff := time.Now().Add(-2 * time.Minute) // Clean logs older than 2 minutes

	// Clean TOTP usage logs
	_, err := db.Exec("DELETE FROM totp_usage_log WHERE used_at < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to clean TOTP usage logs: %w", err)
	}

	// Clean backup code usage logs (keep for longer - 30 days)
	backupCutoff := time.Now().Add(-30 * 24 * time.Hour)
	_, err = db.Exec("DELETE FROM totp_backup_usage WHERE used_at < ?", backupCutoff)
	if err != nil {
		return fmt.Errorf("failed to clean backup code usage logs: %w", err)
	}

	return nil
}

// Helper functions

func generateBackupCodes(count int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		codes[i] = generateSingleBackupCode()
	}
	return codes
}

func generateSingleBackupCode() string {
	code := make([]byte, BackupCodeLength)
	charsetLen := len(BackupCodeCharset)

	for i := 0; i < BackupCodeLength; i++ {
		// Use crypto/rand for cryptographically secure random selection
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			panic(fmt.Sprintf("Failed to generate random bytes: %v", err))
		}

		// Use modulo to select character from charset
		code[i] = BackupCodeCharset[int(randomBytes[0])%charsetLen]
	}
	return string(code)
}

func formatManualEntry(secret string) string {
	// Format as groups of 4 characters for easier manual entry
	formatted := ""
	for i, char := range secret {
		if i > 0 && i%4 == 0 {
			formatted += " "
		}
		formatted += string(char)
	}
	return formatted
}

func trimPadding(s string) string {
	return s[:len(s)-len(s)%8+len(s)%8]
}

func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func validateTOTPCodeInternal(secret, code string) bool {
	return totp.Validate(code, secret)
}

func checkTOTPReplay(db *sql.DB, userEmail, code string, testTime time.Time) error {
	codeHash := hashString(code)
	windowStart := testTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM totp_usage_log 
		WHERE user_email = ? AND code_hash = ? AND window_start = ?`,
		userEmail, codeHash, windowStart,
	).Scan(&count)

	if err != nil {
		return fmt.Errorf("failed to check replay: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("code already used")
	}

	return nil
}

func logTOTPUsage(db *sql.DB, userEmail, code string, testTime time.Time) error {
	codeHash := hashString(code)
	windowStart := testTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	_, err := db.Exec(`
		INSERT INTO totp_usage_log (user_email, code_hash, window_start) 
		VALUES (?, ?, ?)`,
		userEmail, codeHash, windowStart,
	)

	return err
}

func checkBackupCodeReplay(db *sql.DB, userEmail, codeHash string) error {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM totp_backup_usage 
		WHERE user_email = ? AND code_hash = ?`,
		userEmail, codeHash,
	).Scan(&count)

	if err != nil {
		return fmt.Errorf("failed to check backup code replay: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("backup code already used")
	}

	return nil
}

func logBackupCodeUsage(db *sql.DB, userEmail, codeHash string) error {
	_, err := db.Exec(`
		INSERT INTO totp_backup_usage (user_email, code_hash) 
		VALUES (?, ?)`,
		userEmail, codeHash,
	)
	return err
}

func getTOTPData(db *sql.DB, userEmail string) (*TOTPData, error) {
	var data TOTPData
	var createdAtStr string
	var lastUsedStr sql.NullString

	err := db.QueryRow(`
		SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used
		FROM user_totp 
		WHERE user_email = ?`,
		userEmail,
	).Scan(&data.SecretEncrypted, &data.BackupCodesEncrypted, &data.Enabled, &data.SetupCompleted, &createdAtStr, &lastUsedStr)

	if err != nil {
		return nil, err
	}

	// Parse timestamps
	if createdAtStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr); parseErr == nil {
			data.CreatedAt = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			data.CreatedAt = parsedTime
		}
	}

	if lastUsedStr.Valid && lastUsedStr.String != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", lastUsedStr.String); parseErr == nil {
			data.LastUsed = &parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, lastUsedStr.String); parseErr == nil {
			data.LastUsed = &parsedTime
		}
	}

	return &data, nil
}

func decryptTOTPSecret(encrypted []byte, sessionKey []byte) (string, error) {
	// Derive TOTP-specific key
	totpKey, err := crypto.DeriveSessionKey(sessionKey, crypto.TOTPEncryptionContext)
	if err != nil {
		return "", err
	}
	defer crypto.SecureZeroSessionKey(totpKey)

	// Decrypt using AES-GCM
	decrypted, err := crypto.DecryptGCM(encrypted, totpKey)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func decryptJSON(encrypted []byte, sessionKey []byte, target interface{}) error {
	totpKey, err := crypto.DeriveSessionKey(sessionKey, crypto.TOTPEncryptionContext)
	if err != nil {
		return err
	}
	defer crypto.SecureZeroSessionKey(totpKey)

	decrypted, err := crypto.DecryptGCM(encrypted, totpKey)
	if err != nil {
		return err
	}

	return json.Unmarshal(decrypted, target)
}
