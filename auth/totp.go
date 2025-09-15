package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	TOTPIssuer       = "Arkfile"
	TOTPDigits       = 6
	TOTPPeriod       = 30
	TOTPSkew         = 0 // Allow ±0 window (60 seconds total: current + prev/next 30s windows = ±25s tolerance)
	BackupCodeLength = 10
	BackupCodeCount  = 10
)

// Human-friendly backup code character set (excludes B/8, O/0, I/1, S/5, Z/2)
const BackupCodeCharset = "ACDEFGHJKLMNPQRTUVWXY34679"

// TOTPSetup represents the data needed for TOTP setup
type TOTPSetup struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
	ManualEntry string   `json:"manual_entry"`
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
func GenerateTOTPSetup(username string) (*TOTPSetup, error) {
	// Generate 20-byte secret (160 bits) for standard 32-character Base32 output
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Encode as base32 for TOTP compatibility
	secretB32 := base32.StdEncoding.EncodeToString(secret)

	// Remove padding to get clean 32-character Base32 string (consistent with admin secret)
	secretB32 = strings.TrimRight(secretB32, "=")

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

// StoreTOTPSetup stores the TOTP setup data in the database with server-side encryption
func StoreTOTPSetup(db *sql.DB, username string, setup *TOTPSetup) error {
	// Derive user-specific TOTP encryption key from server master key
	totpKey, err := crypto.DeriveTOTPUserKey(username)
	if err != nil {
		return fmt.Errorf("failed to derive TOTP user key: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Encrypt the TOTP secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Convert backup codes to JSON and encrypt
	backupCodesJSON, err := json.Marshal(setup.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt backup codes: %w", err)
	}

	// Store in database (not enabled until setup completion)
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
func CompleteTOTPSetup(db *sql.DB, username, testCode string) error {
	// Get stored TOTP data
	totpData, err := getTOTPData(db, username)
	if err != nil {
		return fmt.Errorf("failed to get TOTP data: %w", err)
	}

	if totpData.SetupCompleted {
		return fmt.Errorf("TOTP setup already completed")
	}

	// Decrypt and validate the test code
	secret, err := decryptTOTPSecret(totpData.SecretEncrypted, username)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Validate the test code
	if !validateTOTPCodeInternal(secret, testCode) {
		return fmt.Errorf("invalid TOTP code")
	}

	// Enable TOTP
	_, err = db.Exec(`
		UPDATE user_totp 
		SET enabled = true, setup_completed = true 
		WHERE username = ?`,
		username,
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
func ValidateTOTPCode(db *sql.DB, username, code string) error {
	// Get user's TOTP data
	totpData, err := getTOTPData(db, username)
	if err != nil {
		return fmt.Errorf("failed to get TOTP data: %w", err)
	}

	if !totpData.Enabled || !totpData.SetupCompleted {
		return fmt.Errorf("TOTP not enabled for user")
	}

	// Decrypt TOTP secret using server-side key management
	secret, err := decryptTOTPSecret(totpData.SecretEncrypted, username)
	if err != nil {
		// Debug logging for decrypt failures (no secret exposure)
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP decrypt failed for user: %s", username)
		}
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Validate code
	currentTime := time.Now().UTC()
	windowStart := currentTime.Truncate(time.Duration(TOTPPeriod) * time.Second).Unix()

	valid, err := totp.ValidateCustom(code, secret, currentTime, totp.ValidateOpts{
		Period:    TOTPPeriod,
		Skew:      uint(TOTPSkew),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		return fmt.Errorf("TOTP validation error: %w", err)
	}

	if !valid {
		// Debug logging for code mismatch (with window metadata)
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP code mismatch for user: %s, window_start: %d, skew: %d",
				username, windowStart, TOTPSkew)
		}
		return fmt.Errorf("invalid TOTP code")
	}

	// Check for replay attack
	if err := checkTOTPReplay(db, username, code, currentTime); err != nil {
		// Debug logging for replay detection
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP replay detected for user: %s", username)
		}
		return fmt.Errorf("replay attack detected: %w", err)
	}

	// Log TOTP usage
	if err := logTOTPUsage(db, username, code, currentTime); err != nil {
		// Log but don't fail
		logging.ErrorLogger.Printf("Failed to log TOTP usage: %v", err)
	}

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
func ValidateBackupCode(db *sql.DB, username, code string) error {
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
	if err := decryptJSON(totpData.BackupCodesEncrypted, username, &backupCodes); err != nil {
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
func DisableTOTP(db *sql.DB, username, currentCode string) error {
	// Validate current code first
	if err := ValidateTOTPCode(db, username, currentCode); err != nil {
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

	// CRITICAL FIX: rqlite driver returns BLOB data as base64-encoded strings
	// We need to decode them back to binary data for proper GCM decryption
	if isDebugMode() {
		fmt.Printf("getTOTPData: Raw data lengths - secret=%d, backup_codes=%d\n",
			len(data.SecretEncrypted), len(data.BackupCodesEncrypted))
	}

	// Detect and decode base64-encoded data
	if decodedSecret, err := decodeBase64IfNeeded(data.SecretEncrypted); err == nil {
		if isDebugMode() && len(decodedSecret) != len(data.SecretEncrypted) {
			fmt.Printf("TOTP: Decoded secret from %d to %d bytes (was base64)\n",
				len(data.SecretEncrypted), len(decodedSecret))
		}
		data.SecretEncrypted = decodedSecret
	}

	if decodedBackup, err := decodeBase64IfNeeded(data.BackupCodesEncrypted); err == nil {
		if isDebugMode() && len(decodedBackup) != len(data.BackupCodesEncrypted) {
			fmt.Printf("TOTP: Decoded backup codes from %d to %d bytes (was base64)\n",
				len(data.BackupCodesEncrypted), len(decodedBackup))
		}
		data.BackupCodesEncrypted = decodedBackup
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

func decryptTOTPSecret(encrypted []byte, username string) (string, error) {
	// Debug logging for TOTP decryption attempts
	if isDebugMode() && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("TOTP decrypt attempt for user: %s, encrypted_data_len: %d",
			username, len(encrypted))
		if len(encrypted) > 0 {
			logging.ErrorLogger.Printf("TOTP decrypt data preview: first_8_bytes=%x, last_8_bytes=%x",
				encrypted[:min(8, len(encrypted))],
				encrypted[max(0, len(encrypted)-8):])
		}
	}

	// Use user-specific persistent key derived from server TOTP master key
	totpKey, err := crypto.DeriveTOTPUserKey(username)
	if err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP key derivation failed for user: %s, error: %v", username, err)
		}
		return "", err
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Debug logging for derived key validation
	if isDebugMode() && logging.ErrorLogger != nil {
		if len(totpKey) == 32 {
			// Log key hash for debugging (never log actual key)
			keyHash := hashString(string(totpKey))
			logging.ErrorLogger.Printf("TOTP key derived successfully for user: %s, key_hash: %s",
				username, keyHash[:16])
		} else {
			logging.ErrorLogger.Printf("TOTP key derivation issue for user: %s, unexpected key length: %d",
				username, len(totpKey))
		}
	}

	// Decrypt using AES-GCM
	decrypted, err := crypto.DecryptGCM(encrypted, totpKey)
	if err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP GCM decryption failed for user: %s, error: %v", username, err)
			logging.ErrorLogger.Printf("TOTP GCM decrypt context: key_len=%d, data_len=%d",
				len(totpKey), len(encrypted))
		}
		return "", err
	}

	// Debug logging for successful decryption
	if isDebugMode() && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("TOTP decrypt successful for user: %s, decrypted_len: %d",
			username, len(decrypted))
	}

	return string(decrypted), nil
}

func decryptJSON(encrypted []byte, username string, target interface{}) error {
	totpKey, err := crypto.DeriveTOTPUserKey(username)
	if err != nil {
		return err
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	decrypted, err := crypto.DecryptGCM(encrypted, totpKey)
	if err != nil {
		return err
	}

	return json.Unmarshal(decrypted, target)
}

// Helper functions for safe array slicing
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// isDebugMode checks if debug mode is enabled
func isDebugMode() bool {
	debug := strings.ToLower(os.Getenv("DEBUG_MODE"))
	return debug == "true" || debug == "1"
}

// CanDecryptTOTPSecret checks if a user's TOTP secret can be decrypted (dev diagnostic helper)
// This is exported for use by dev-only diagnostic endpoints
func CanDecryptTOTPSecret(db *sql.DB, username string) (present bool, decryptable bool, enabled bool, setupCompleted bool, err error) {
	// Enhanced debug logging for CanDecryptTOTPSecret function
	if isDebugMode() {
		fmt.Printf("=== CanDecryptTOTPSecret DEBUG START for user: %s ===\n", username)
	}

	// Get stored TOTP data
	totpData, err := getTOTPData(db, username)
	if err != nil {
		if err == sql.ErrNoRows {
			if isDebugMode() {
				fmt.Printf("CanDecryptTOTPSecret: No TOTP data found for user: %s\n", username)
			}
			return false, false, false, false, nil // User has no TOTP data
		}
		if isDebugMode() {
			fmt.Printf("CanDecryptTOTPSecret: Database error for user %s: %v\n", username, err)
		}
		return false, false, false, false, err
	}

	present = true
	enabled = totpData.Enabled
	setupCompleted = totpData.SetupCompleted

	if isDebugMode() {
		fmt.Printf("CanDecryptTOTPSecret: TOTP data found - enabled=%t, setupCompleted=%t, encrypted_len=%d\n",
			enabled, setupCompleted, len(totpData.SecretEncrypted))
	}

	// Try to decrypt the secret with enhanced debug logging
	decryptedSecret, decryptErr := decryptTOTPSecret(totpData.SecretEncrypted, username)
	decryptable = (decryptErr == nil)

	if isDebugMode() {
		if decryptErr != nil {
			fmt.Printf("CanDecryptTOTPSecret: Decryption FAILED for user %s: %v\n", username, decryptErr)
		} else {
			fmt.Printf("CanDecryptTOTPSecret: Decryption SUCCESS for user %s, secret_len=%d\n", username, len(decryptedSecret))
		}
		fmt.Printf("=== CanDecryptTOTPSecret DEBUG END for user: %s ===\n", username)
	}

	return present, decryptable, enabled, setupCompleted, nil
}

// decodeBase64IfNeeded attempts to detect and decode base64-encoded data
// If the input is not valid base64, it returns the original data unchanged
func decodeBase64IfNeeded(data []byte) ([]byte, error) {
	// If data looks like base64 (length is multiple of 4, contains only base64 chars)
	// and is longer than what we expect for raw binary, try to decode it
	if len(data) > 60 && len(data)%4 == 0 {
		// Check if all characters are valid base64
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

	// Return original data if not base64 or decoding failed
	return data, nil
}

// decodeBase64 decodes base64 data
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
