package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/png"
	"os"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	TOTPIssuer       = "Arkfile"
	TOTPDigits       = 6
	TOTPPeriod       = 30
	TOTPSkew         = 1 // Allow ±1 window (accepts current, previous, and next 30s windows)
	BackupCodeLength = 10
	BackupCodeCount  = 10

	// Lockout policy constants
	totpSoftLockoutThreshold = 10 // failures before exponential backoff begins
	totpHardCapThreshold     = 30 // failures before hard 24h cap
	totpWindowDuration       = 24 * time.Hour
	totpBackoffCapMinutes    = 60
)

// Human-friendly backup code character set (excludes B/8, O/0, I/1, S/5, Z/2)
const BackupCodeCharset = "ACDEFGHJKLMNPQRTUVWXY34679"

// TOTPSetup represents the data needed for TOTP setup
type TOTPSetup struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	QRCodeImage string   `json:"qr_code_image"` // Base64 data URI for QR code PNG
	BackupCodes []string `json:"backup_codes"`
	ManualEntry string   `json:"manual_entry"`
}

// TOTPData represents the stored TOTP data for a user
type TOTPData struct {
	SecretEncrypted []byte `json:"credential_data"`
	Enabled         bool   `json:"enabled"`
	SetupCompleted  bool   `json:"setup_completed"`
	CreatedAt       time.Time
	LastUsed        *time.Time
}

// GenerateTOTPSetup creates a new TOTP setup for a user
func GenerateMFASetup(username string) (*TOTPSetup, error) {
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

	// Generate backup codes (utilizing cryptographically secure rejection sampling)
	backupCodes, err := generateBackupCodesResilient(BackupCodeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Generate QR code image as base64 data URI
	qrImage, err := generateQRCodeDataURI(qrURL)
	if err != nil {
		// Log but don't fail - QR URL is still available for manual entry
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to generate QR code image: %v", err)
		}
		qrImage = "" // Empty string signals frontend to use fallback
	}

	return &TOTPSetup{
		Secret:      secretB32,
		QRCodeURL:   qrURL,
		QRCodeImage: qrImage,
		BackupCodes: backupCodes,
		ManualEntry: formatManualEntry(secretB32),
	}, nil
}

// GetPendingTOTPSetup retrieves an existing pending (unverified) TOTP setup for a user.
// Returns the decrypted setup data if a pending setup exists, nil if not.
func GetPendingMFASetup(db *sql.DB, username string) (*TOTPSetup, error) {
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
			return nil, nil // No existing setup
		}
		return nil, fmt.Errorf("failed to query pending TOTP setup: %w", err)
	}

	// If setup is already completed, this isn't a pending setup
	if setupCompleted {
		return nil, nil
	}

	// Decode base64 if needed (rqlite driver quirk)
	if decoded, err := decodeBase64IfNeeded(secretEncrypted); err == nil {
		secretEncrypted = decoded
	}

	// Decrypt secret
	secret, err := decryptTOTPSecret(secretEncrypted, username)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt pending TOTP secret: %w", err)
	}

	// Retrieve pending backup codes (they aren't GCM-encrypted in separate blobs anymore, we reconstruct them or query hashes)
	// Since hashes are one-way, we cannot re-show plaintext backup codes for a pending setup.
	// We generate and store fresh ones if they ask, OR we simply re-setup. To preserve safety, GetPendingTOTPSetup
	// will generate fresh backup codes securely for the user and save them in DB during this call.
	backupCodes, err := generateBackupCodesResilient(BackupCodeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate fresh backup codes for pending setup: %w", err)
	}

	// Re-save backup codes
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

	// Rebuild QR code URL and image from the existing secret
	qrURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		TOTPIssuer, username, secret, TOTPIssuer, TOTPDigits, TOTPPeriod)

	qrImage, err := generateQRCodeDataURI(qrURL)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to regenerate QR code image for pending setup: %v", err)
		}
		qrImage = ""
	}

	return &TOTPSetup{
		Secret:      secret,
		QRCodeURL:   qrURL,
		QRCodeImage: qrImage,
		BackupCodes: backupCodes,
		ManualEntry: formatManualEntry(secret),
	}, nil
}

// StoreTOTPSetup stores the TOTP setup data in the database with server-side encryption and hashed backup codes
func StoreMFASetup(db *sql.DB, username string, setup *TOTPSetup) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Derive user-specific TOTP encryption key from Tier-3 user core key
	totpKey, err := crypto.DeriveTOTPUserKey(username)
	if err != nil {
		return fmt.Errorf("failed to derive TOTP user key in Tier-3: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Encrypt the TOTP secret using AES-GCM
	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Store core row (with backup_codes_encrypted column completely eliminated)
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO user_mfa_credentials (
			username, method_type, credential_data,
			enabled, setup_completed, created_at
		) VALUES (?, 'totp', ?, ?, ?, ?)`,
		username, secretEncrypted,
		false, false, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to store TOTP config: %w", err)
	}

	// Store hashed backup codes on user_mfa_backup_codes table (reuses global Argon2id floor parameters)
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
		return fmt.Errorf("failed to commit TOTP setup transaction: %w", err)
	}

	return nil
}

// CompleteTOTPSetup validates a test code and enables TOTP for the user
func CompleteMFASetup(db *sql.DB, username, testCode string) error {
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
		UPDATE user_mfa_credentials 
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

// TOTPLockoutError is returned when a TOTP attempt is rejected due to failure-rate lockout.
// RetryAfter is the duration the caller must wait before retrying (zero for hard-cap).
type TOTPLockoutError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *TOTPLockoutError) Error() string {
	return e.Reason
}

// totpLockoutState holds the three columns read from user_mfa_credentials for lockout computation.
type totpLockoutState struct {
	failedAttempts int
	windowStarted  *time.Time
	lastFailed     *time.Time
}

// computeLockoutState is a pure function that decides whether another TOTP attempt is
// allowed given the current failure state and the current time. It has no side effects.
func computeLockoutState(s totpLockoutState, now time.Time) (allowed bool, retryAfter time.Duration, reason string) {
	// No window open yet, or window has expired: always allowed.
	if s.windowStarted == nil || now.Sub(*s.windowStarted) >= totpWindowDuration {
		return true, 0, ""
	}

	// Hard daily cap: 30 or more failures in the current window.
	if s.failedAttempts >= totpHardCapThreshold {
		windowEnds := s.windowStarted.Add(totpWindowDuration)
		wait := windowEnds.Sub(now)
		if wait < 0 {
			wait = 0
		}
		return false, wait, "too many failed attempts; try again later"
	}

	// Soft exponential backoff: 10 or more failures.
	if s.failedAttempts >= totpSoftLockoutThreshold && s.lastFailed != nil {
		backoffExp := s.failedAttempts - totpSoftLockoutThreshold
		backoffMinutes := 1 << backoffExp // 2^(attempts-10) minutes
		if backoffMinutes > totpBackoffCapMinutes {
			backoffMinutes = totpBackoffCapMinutes
		}
		backoff := time.Duration(backoffMinutes) * time.Minute
		retryAt := s.lastFailed.Add(backoff)
		if now.Before(retryAt) {
			return false, retryAt.Sub(now), "too many failed attempts; try again later"
		}
	}

	return true, 0, ""
}

// getTOTPLockoutState reads the three lockout columns from user_mfa_credentials for the given user.
func getTOTPLockoutState(db *sql.DB, username string) (totpLockoutState, error) {
	var s totpLockoutState
	var failedAttempts int
	var windowStartedStr sql.NullString
	var lastFailedStr sql.NullString

	err := db.QueryRow(`
		SELECT failed_attempts_in_window, window_started_at, last_failed_attempt_at
		FROM user_mfa_credentials
		WHERE username = ?`, username,
	).Scan(&failedAttempts, &windowStartedStr, &lastFailedStr)

	if err != nil {
		return s, err
	}

	s.failedAttempts = failedAttempts

	parseTS := func(raw sql.NullString) *time.Time {
		if !raw.Valid || raw.String == "" {
			return nil
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, raw.String); err == nil {
				return &t
			}
		}
		return nil
	}

	s.windowStarted = parseTS(windowStartedStr)
	s.lastFailed = parseTS(lastFailedStr)
	return s, nil
}

// recordTOTPFailure increments the failure counter for a user and persists it.
func recordTOTPFailure(db *sql.DB, username string, now time.Time) (totpLockoutState, error) {
	cur, err := getTOTPLockoutState(db, username)
	if err != nil {
		return cur, err
	}

	var newAttempts int
	var newWindowStart time.Time

	// Reset window if it has expired or hasn't started.
	if cur.windowStarted == nil || now.Sub(*cur.windowStarted) >= totpWindowDuration {
		newAttempts = 1
		newWindowStart = now
	} else {
		newAttempts = cur.failedAttempts + 1
		newWindowStart = *cur.windowStarted
	}

	_, err = db.Exec(`
		UPDATE user_mfa_credentials
		SET failed_attempts_in_window = ?,
		    window_started_at = ?,
		    last_failed_attempt_at = ?
		WHERE username = ?`,
		newAttempts, newWindowStart, now, username,
	)
	if err != nil {
		return cur, err
	}

	updated := totpLockoutState{
		failedAttempts: newAttempts,
		windowStarted:  &newWindowStart,
		lastFailed:     &now,
	}
	return updated, nil
}

// clearTOTPFailures resets all lockout state on a successful verification.
func clearTOTPFailures(db *sql.DB, username string) error {
	_, err := db.Exec(`
		UPDATE user_mfa_credentials
		SET failed_attempts_in_window = 0,
		    window_started_at = NULL,
		    last_failed_attempt_at = NULL
		WHERE username = ?`, username,
	)
	return err
}

// emitTOTPLockoutEvent logs a TOTP lockout state transition.
func emitTOTPLockoutEvent(_ *sql.DB, username, eventType, detail string) {
	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("SECURITY: %s for user: %s (%s)", eventType, username, detail)
	}
}

// ValidateTOTPCode validates a TOTP code with replay protection and failure-rate lockout.
func ValidateTOTPCode(db *sql.DB, username, code string) error {
	// Check lockout state before doing any crypto work.
	lockState, err := getTOTPLockoutState(db, username)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check TOTP lockout state: %w", err)
	}

	now := time.Now().UTC()
	allowed, retryAfter, reason := computeLockoutState(lockState, now)
	if !allowed {
		return &TOTPLockoutError{Reason: reason, RetryAfter: retryAfter}
	}

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
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP code mismatch for user: %s, window_start: %d, skew: %d",
				username, windowStart, TOTPSkew)
		}
		// Record the failure and check for lockout transitions.
		updated, recErr := recordTOTPFailure(db, username, now)
		if recErr != nil && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to record TOTP failure for user %s: %v", username, recErr)
		}
		// Emit security events on lockout threshold crossings.
		if updated.failedAttempts == totpSoftLockoutThreshold+1 {
			emitTOTPLockoutEvent(db, username, "TOTPSoftLockout",
				fmt.Sprintf("failure count reached %d", updated.failedAttempts))
		} else if updated.failedAttempts == totpHardCapThreshold+1 {
			emitTOTPLockoutEvent(db, username, "TOTPHardCap",
				fmt.Sprintf("failure count reached %d; locked for 24h", updated.failedAttempts))
		}
		return fmt.Errorf("invalid TOTP code")
	}

	// Check for replay attack
	if err := checkTOTPReplay(db, username, code, currentTime); err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP replay detected for user: %s", username)
		}
		return fmt.Errorf("replay attack detected: %w", err)
	}

	// Success: clear lockout state and emit recovery event if recovering from lockout.
	wasLocked := lockState.failedAttempts >= totpSoftLockoutThreshold
	if clearErr := clearTOTPFailures(db, username); clearErr != nil && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("Failed to clear TOTP failures for user %s: %v", username, clearErr)
	}
	if wasLocked {
		emitTOTPLockoutEvent(db, username, "TOTPLockoutCleared", "successful verification after lockout")
	}

	// Log TOTP usage
	if err := logTOTPUsage(db, username, code, currentTime); err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to log TOTP usage: %v", err)
		}
	}

	// Update last used timestamp
	_, err = db.Exec("UPDATE user_mfa_credentials SET last_used = ? WHERE username = ?",
		time.Now(), username)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to update TOTP last_used: %v", err)
		}
	}

	return nil
}

// ValidateBackupCode validates and consumes a hashed backup code securely (O(1)-avg verification with race hardening).
func ValidateBackupCode(db *sql.DB, username, code string) error {
	// Check lockout state before doing any crypto work.
	lockState, err := getTOTPLockoutState(db, username)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check TOTP lockout state: %w", err)
	}

	now := time.Now().UTC()
	allowed, retryAfter, reason := computeLockoutState(lockState, now)
	if !allowed {
		return &TOTPLockoutError{Reason: reason, RetryAfter: retryAfter}
	}

	// Parse provided code to verify constraints
	if len(code) != BackupCodeLength {
		return fmt.Errorf("invalid backup code length")
	}

	// Permute verification indices randomly to defeat timing-based index inference
	perm := make([]int, BackupCodeCount)
	for i := range perm {
		perm[i] = i
	}
	// Simple durand-buxom/Fisher-Yates shuffle locally using crypto/rand to avoid timing leakage
	shuffleIndices(perm)

	var matchedIndex = -1
	var matchedHash []byte

	// Calculate candidates
	for _, codeIndex := range perm {
		salt := deriveBackupCodeSalt(username, codeIndex)
		candHash, err := crypto.DeriveArgon2IDKey(
			[]byte(code),
			salt,
			crypto.UnifiedArgonSecure.KeyLen,
			crypto.UnifiedArgonSecure.Memory,
			crypto.UnifiedArgonSecure.Time,
			crypto.UnifiedArgonSecure.Threads,
		)
		if err != nil {
			continue
		}

		// Check if DB stores a non-used matching hash for this index
		var storedHash []byte
		var usedAt sql.NullString
		err = db.QueryRow(`
			SELECT code_hash, used_at FROM user_mfa_backup_codes 
			WHERE username = ? AND code_index = ? AND code_hash = ?`,
			username, codeIndex, candHash,
		).Scan(&storedHash, &usedAt)

		if err == nil && (!usedAt.Valid || usedAt.String == "") {
			// Found unused matching backup code!
			matchedIndex = codeIndex
			matchedHash = candHash
			break
		}
	}

	if matchedIndex == -1 {
		// Log failure and apply lockout backoffs
		updated, recErr := recordTOTPFailure(db, username, now)
		if recErr != nil && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to record TOTP failure for user %s: %v", username, recErr)
		}
		if updated.failedAttempts == totpSoftLockoutThreshold+1 {
			emitTOTPLockoutEvent(db, username, "TOTPSoftLockout",
				fmt.Sprintf("failure count reached %d", updated.failedAttempts))
		} else if updated.failedAttempts == totpHardCapThreshold+1 {
			emitTOTPLockoutEvent(db, username, "TOTPHardCap",
				fmt.Sprintf("failure count reached %d; locked for 24h", updated.failedAttempts))
		}
		return fmt.Errorf("invalid backup code")
	}

	// Optimistic transaction-gated update to resolve race conditions double-spend
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		UPDATE user_mfa_backup_codes 
		SET used_at = ? 
		WHERE username = ? AND code_index = ? AND code_hash = ? AND used_at IS NULL`,
		time.Now().UTC(), username, matchedIndex, matchedHash,
	)
	if err != nil {
		return fmt.Errorf("failed to consume backup code: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("race condition: backup code already consumed by concurrent request")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit consumed backup code transaction: %w", err)
	}

	// Clear lockout states on success
	wasLocked := lockState.failedAttempts >= totpSoftLockoutThreshold
	if clearErr := clearTOTPFailures(db, username); clearErr != nil && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("Failed to clear TOTP failures for user %s: %v", username, clearErr)
	}
	if wasLocked {
		emitTOTPLockoutEvent(db, username, "TOTPLockoutCleared", "successful backup code after lockout")
	}

	// Log backup code usage
	if err := logBackupCodeUsage(db, username, hex.EncodeToString(matchedHash)); err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to log backup code usage: %v", err)
		}
	}

	// Update last used timestamp
	_, err = db.Exec("UPDATE user_mfa_credentials SET last_used = ? WHERE username = ?",
		time.Now().UTC(), username)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("Failed to update TOTP last_used after backup code: %v", err)
		}
	}

	return nil
}

// IsUserMFAEnabled checks if TOTP is enabled for a user
func IsUserMFAEnabled(db *sql.DB, username string) (bool, error) {
	var enabled bool
	var setupCompleted bool

	err := db.QueryRow(`
		SELECT enabled, setup_completed 
		FROM user_mfa_credentials 
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

// ResetTOTP resets TOTP for a user (requires valid backup code or pre-validated reset JWT auth).
// This generates a new TOTP secret and new backup codes while keeping TOTP enabled.
func ResetTOTP(db *sql.DB, username, backupCode string) (*TOTPSetup, error) {
	// Validate backup code first if provided (some flows validate beforehand via the recovery token)
	if backupCode != "" {
		if err := ValidateBackupCode(db, username, backupCode); err != nil {
			return nil, fmt.Errorf("invalid backup code: %w", err)
		}
	}

	// Generate new TOTP setup
	setup, err := GenerateMFASetup(username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new TOTP setup: %w", err)
	}

	// Derive user-specific TOTP encryption key from Tier-3 master
	totpKey, err := crypto.DeriveTOTPUserKey(username)
	if err != nil {
		return nil, fmt.Errorf("failed to derive TOTP user key in Tier-3: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Encrypt the new TOTP secret using GCM
	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), totpKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Update database with new encrypted data (keep enabled=true, setup_completed=true)
	_, err = tx.Exec(`
		UPDATE user_mfa_credentials 
		SET credential_data = ?, created_at = ?
		WHERE username = ?`,
		secretEncrypted, time.Now().UTC(), username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update TOTP data: %w", err)
	}

	// Insert fresh hashed backup codes
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

	// Log the security event
	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("SECURITY: TOTP reset for user: %s", username)
	}

	return setup, nil
}

// CleanupTOTPLogs removes old TOTP usage logs
func CleanupTOTPLogs(db *sql.DB) error {
	cutoff := time.Now().Add(-2 * time.Minute) // Clean logs older than 2 minutes

	// Clean TOTP usage logs
	_, err := db.Exec("DELETE FROM mfa_usage_log WHERE used_at < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to clean TOTP usage logs: %w", err)
	}

	// Clean backup code usage logs (keep for longer - 30 days)
	backupCutoff := time.Now().Add(-30 * 24 * time.Hour)
	_, err = db.Exec("DELETE FROM mfa_backup_usage WHERE used_at < ?", backupCutoff)
	if err != nil {
		return fmt.Errorf("failed to clean backup code usage logs: %w", err)
	}

	return nil
}

// Helper functions

func deriveBackupCodeSalt(username string, index int) []byte {
	salt := sha256.Sum256([]byte(fmt.Sprintf("arkfile-backup-code-salt:%s:%d", username, index)))
	return salt[:]
}

func generateBackupCodesResilient(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := generateSingleBackupCodeResilient()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func generateSingleBackupCodeResilient() (string, error) {
	code := make([]byte, BackupCodeLength)
	charsetLen := len(BackupCodeCharset)

	for i := 0; i < BackupCodeLength; {
		// Use crypto/rand rejection sampling to eliminate modulo bias
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("secure random failed: %w", err)
		}

		// Rejection pool: 256 - (256 % charsetLen)
		limit := 256 - (256 % charsetLen)
		val := int(randomBytes[0])
		if val < limit {
			code[i] = BackupCodeCharset[val%charsetLen]
			i++
		}
	}
	return string(code), nil
}

func shuffleIndices(slice []int) {
	n := len(slice)
	for i := n - 1; i > 0; i-- {
		b := make([]byte, 1)
		_, _ = rand.Read(b)
		j := int(b[0]) % (i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// generateQRCodeDataURI creates a QR code PNG and returns it as a base64 data URI
func generateQRCodeDataURI(content string) (string, error) {
	// Create QR code
	qrCode, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("failed to encode QR code: %w", err)
	}

	// Scale to 200x200 pixels for good visibility
	qrCode, err = barcode.Scale(qrCode, 200, 200)
	if err != nil {
		return "", fmt.Errorf("failed to scale QR code: %w", err)
	}

	// Encode as PNG to buffer
	var buf bytes.Buffer
	if err := png.Encode(&buf, qrCode); err != nil {
		return "", fmt.Errorf("failed to encode PNG: %w", err)
	}

	// Convert to base64 data URI
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return "data:image/png;base64," + b64, nil
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
		FROM mfa_usage_log 
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
		INSERT INTO mfa_usage_log (username, code_hash, window_start) 
		VALUES (?, ?, ?)`,
		username, codeHash, windowStart,
	)

	return err
}

func checkBackupCodeReplay(db *sql.DB, username, codeHash string) error {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM mfa_backup_usage 
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
		INSERT INTO mfa_backup_usage (username, code_hash) 
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
		SELECT credential_data, enabled, setup_completed, created_at, last_used
		FROM user_mfa_credentials 
		WHERE username = ?`,
		username,
	).Scan(&data.SecretEncrypted, &data.Enabled, &data.SetupCompleted, &createdAtStr, &lastUsedStr)

	if err != nil {
		return nil, err
	}

	// CRITICAL FIX: rqlite driver returns BLOB data as base64-encoded strings
	// We need to decode them back to binary data for proper GCM decryption
	// Detect and decode base64-encoded data
	if decodedSecret, err := decodeBase64IfNeeded(data.SecretEncrypted); err == nil {
		data.SecretEncrypted = decodedSecret
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
	// Use user-specific persistent key derived from server TOTP master key
	totpKey, err := crypto.DeriveTOTPUserKey(username)
	if err != nil {
		if isDebugMode() && logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("TOTP key derivation failed for user: %s, error: %v", username, err)
		}
		return "", err
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Decrypt using AES-GCM
	decrypted, err := crypto.DecryptGCM(encrypted, totpKey)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// isDebugMode checks if debug mode is enabled
func isDebugMode() bool {
	debug := strings.ToLower(os.Getenv("DEBUG_MODE"))
	return debug == "true" || debug == "1"
}

// CanDecryptTOTPSecret checks if a user's TOTP secret can be decrypted (dev diagnostic helper)
// This is exported for use by dev-only diagnostic endpoints
func CanDecryptTOTPSecret(db *sql.DB, username string) (present bool, decryptable bool, enabled bool, setupCompleted bool, err error) {
	// Get stored TOTP data
	totpData, err := getTOTPData(db, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, false, false, false, nil // User has no TOTP data
		}
		return false, false, false, false, err
	}

	present = true
	enabled = totpData.Enabled
	setupCompleted = totpData.SetupCompleted

	// Try to decrypt the secret
	_, decryptErr := decryptTOTPSecret(totpData.SecretEncrypted, username)
	decryptable = (decryptErr == nil)

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
