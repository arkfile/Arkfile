package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
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
func GenerateTOTPSetup(username string, sessionKey []byte) (*TOTPSetup, error) {
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
		TOTPIssuer, username, secretB32, TOTPIssuer, TOTPDigits, TOTPPeriod)

	// Generate backup codes
	backupCodes := generateBackupCodes(BackupCodeCount)

	return &TOTPSetup{
		Secret:      secretB32,
		QRCodeURL:   qrURL,
		BackupCodes: backupCodes,
		ManualEntry: formatManualEntry(secretB32),
	}, nil
}

// StoreTOTPSetup stores the TOTP setup data in the database (temporarily encrypted during setup)
func StoreTOTPSetup(db *sql.DB, username string, setup *TOTPSetup, sessionKey []byte) error {
	// During setup, use a temporary encryption key derivable from session key
	// This allows us to decrypt during verification, then re-encrypt with production key

	// Derive temporary TOTP setup key (different from production key)
	const TOTPSetupTempContext = "ARKFILE_TOTP_SETUP_TEMP"
	tempTotpKey, err := crypto.DeriveSessionKey(sessionKey, TOTPSetupTempContext)
	if err != nil {
		return fmt.Errorf("failed to derive temporary TOTP key: %w", err)
	}
	defer crypto.SecureZeroSessionKey(tempTotpKey)

	// Encrypt the TOTP secret with temporary key
	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), tempTotpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Convert backup codes to JSON and encrypt
	backupCodesJSON, err := json.Marshal(setup.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, tempTotpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt backup codes: %w", err)
	}

	// Store in database with temporarily encrypted data during setup
	_, err = db.Exec(`
		INSERT OR REPLACE INTO user_totp (
			username, secret_encrypted, backup_codes_encrypted, 
			enabled, setup_completed, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		username, secretEncrypted, backupCodesEncrypted,
		false, false, time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to store TOTP setup: %w", err)
	}

	return nil
}

// CompleteTOTPSetup validates a test code and enables TOTP for the user
func CompleteTOTPSetup(db *sql.DB, username, testCode string, sessionKey []byte) error {
	// Get stored TOTP data
	totpData, err := getTOTPData(db, username)
	if err != nil {
		return fmt.Errorf("failed to get TOTP data: %w", err)
	}

	if totpData.SetupCompleted {
		return fmt.Errorf("TOTP setup already completed")
	}

	// During setup, the secret is encrypted with temporary key
	// Decrypt using the same temporary key from setup
	const TOTPSetupTempContext = "ARKFILE_TOTP_SETUP_TEMP"
	tempTotpKey, err := crypto.DeriveSessionKey(sessionKey, TOTPSetupTempContext)
	if err != nil {
		return fmt.Errorf("failed to derive temporary TOTP key: %w", err)
	}
	defer crypto.SecureZeroSessionKey(tempTotpKey)

	// Decrypt the secret from temporary encryption
	secretBytes, err := crypto.DecryptGCM(totpData.SecretEncrypted, tempTotpKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt temporary TOTP secret: %w", err)
	}
	secret := string(secretBytes)

	// Validate the test code
	if !validateTOTPCodeInternal(secret, testCode) {
		return fmt.Errorf("invalid TOTP code")
	}

	// Now encrypt the secret for production use with user-specific persistent key
	totpKey, err := deriveUserTOTPKey(sessionKey)
	if err != nil {
		return fmt.Errorf("failed to derive user TOTP key: %w", err)
	}
	defer crypto.SecureZeroSessionKey(totpKey)

	// Encrypt the TOTP secret with user-specific persistent key
	secretEncrypted, err := crypto.EncryptGCM([]byte(secret), totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Decrypt backup codes from temporary encryption
	backupCodesBytes, err := crypto.DecryptGCM(totpData.BackupCodesEncrypted, tempTotpKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt temporary backup codes: %w", err)
	}

	var backupCodes []string
	if err := json.Unmarshal(backupCodesBytes, &backupCodes); err != nil {
		return fmt.Errorf("failed to unmarshal backup codes: %w", err)
	}

	// Re-encrypt backup codes with user-specific persistent key
	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt backup codes: %w", err)
	}

	// Update with encrypted data and enable TOTP
	_, err = db.Exec(`
		UPDATE user_totp 
		SET secret_encrypted = ?, backup_codes_encrypted = ?, enabled = true, setup_completed = true 
		WHERE username = ?`,
		secretEncrypted, backupCodesEncrypted, username,
	)

	if err != nil {
		return fmt.Errorf("failed to complete TOTP setup: %w", err)
	}

	// Log successful TOTP setup
	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("TOTP setup completed for user: %s", username)
	}

	return nil
}

// ValidateTOTPCode validates a TOTP code with replay protection
func ValidateTOTPCode(db *sql.DB, username, code string, sessionKey []byte) error {
	// Get user's TOTP data
	totpData, err := getTOTPData(db, username)
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

	// Validate code
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    TOTPPeriod,
		Skew:      uint(TOTPSkew),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		return fmt.Errorf("TOTP validation error: %w", err)
	}

	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	// TODO: Re-implement replay attack protection.
	// The new validation method does not provide the timestamp of the matched code,
	// so the previous replay protection mechanism needs to be re-evaluated.

	// Update last used timestamp
	_, err = db.Exec("UPDATE user_totp SET last_used = ? WHERE username = ?",
		time.Now(), username)
	if err != nil {
		// Log but don't fail
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to update TOTP last_used: %v", err)
		}
	}

	return nil // Valid code
}

// ValidateBackupCode validates and consumes a backup code
func ValidateBackupCode(db *sql.DB, username, code string, sessionKey []byte) error {
	// Get user's TOTP data
	totpData, err := getTOTPData(db, username)
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
	if err := checkBackupCodeReplay(db, username, codeHash); err != nil {
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
	if err := logBackupCodeUsage(db, username, codeHash); err != nil {
		return fmt.Errorf("failed to log backup code usage: %w", err)
	}

	// Update last used timestamp
	_, err = db.Exec("UPDATE user_totp SET last_used = ? WHERE username = ?",
		time.Now(), username)
	if err != nil {
		// Log but don't fail
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to update TOTP last_used after backup code: %v", err)
		}
	}

	return nil
}

// IsUserTOTPEnabled checks if TOTP is enabled for a user
func IsUserTOTPEnabled(db *sql.DB, username string) (bool, error) {
	var enabled bool
	var setupCompleted bool

	err := db.QueryRow(`
		SELECT enabled, setup_completed 
		FROM user_totp 
		WHERE username = ?`,
		username,
	).Scan(&enabled, &setupCompleted)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // No entry means TOTP is not enabled, not an error
		}
		return false, fmt.Errorf("failed to check TOTP status: %w", err)
	}

	return enabled && setupCompleted, nil
}

// DisableTOTP disables TOTP for a user (requires current TOTP code)
func DisableTOTP(db *sql.DB, username, currentCode string, sessionKey []byte) error {
	// Validate current code first
	if err := ValidateTOTPCode(db, username, currentCode, sessionKey); err != nil {
		return fmt.Errorf("invalid current TOTP code: %w", err)
	}

	// Disable TOTP
	_, err := db.Exec("DELETE FROM user_totp WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("failed to disable TOTP: %w", err)
	}

	// Log the action
	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("TOTP disabled for user: %s", username)
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
	// Remove trailing '=' padding characters from base32 string
	return strings.TrimRight(s, "=")
}

func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func validateTOTPCodeInternal(secret, code string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    TOTPPeriod,
		Skew:      uint(TOTPSkew),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return valid
}

func checkTOTPReplay(db *sql.DB, username, code string, testTime time.Time) error {
	codeHash := hashString(code)
	windowStart := testTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM totp_usage_log 
		WHERE username = ? AND code_hash = ? AND window_start = ?`,
		username, codeHash, windowStart,
	).Scan(&count)

	if err != nil {
		return fmt.Errorf("failed to check replay: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("code already used")
	}

	return nil
}

func logTOTPUsage(db *sql.DB, username, code string, testTime time.Time) error {
	codeHash := hashString(code)
	windowStart := testTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	_, err := db.Exec(`
		INSERT INTO totp_usage_log (username, code_hash, window_start) 
		VALUES (?, ?, ?)`,
		username, codeHash, windowStart,
	)

	return err
}

func checkBackupCodeReplay(db *sql.DB, username, codeHash string) error {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM totp_backup_usage 
		WHERE username = ? AND code_hash = ?`,
		username, codeHash,
	).Scan(&count)

	if err != nil {
		return fmt.Errorf("failed to check backup code replay: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("backup code already used")
	}

	return nil
}

func logBackupCodeUsage(db *sql.DB, username, codeHash string) error {
	_, err := db.Exec(`
		INSERT INTO totp_backup_usage (username, code_hash) 
		VALUES (?, ?)`,
		username, codeHash,
	)
	return err
}

func getTOTPData(db *sql.DB, username string) (*TOTPData, error) {
	var data TOTPData
	var createdAtStr string
	var lastUsedStr sql.NullString

	err := db.QueryRow(`
		SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used
		FROM user_totp 
		WHERE username = ?`,
		username,
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
	// Use user-specific persistent key derived from user's OPAQUE record
	// This ensures the same key is used regardless of session
	totpKey, err := deriveUserTOTPKey(sessionKey)
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
	totpKey, err := deriveUserTOTPKey(sessionKey)
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

// deriveUserTOTPKey derives a consistent user-specific key for TOTP encryption
// This key is derived from the user's OPAQUE export key and remains the same
// across different login sessions, unlike session-specific keys
func deriveUserTOTPKey(sessionKey []byte) ([]byte, error) {
	// Use a specific context for user TOTP encryption that's distinct from session keys
	const UserTOTPContext = "ARKFILE_USER_TOTP_PERSISTENT"
	return crypto.DeriveSessionKey(sessionKey, UserTOTPContext)
}
