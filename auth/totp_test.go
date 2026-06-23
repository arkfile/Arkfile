package auth

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/pquerna/otp/totp"
)

// setupTOTPTestEnvironment sets up the test environment for TOTP tests
func setupTOTPTestEnvironment(t *testing.T) {
	os.Setenv("DEBUG_MODE", "true") // Enable debug mode for testing

	// Write / load temporary user-secret master key for testing
	crypto.SetUserSecretMasterForTest(make([]byte, 32))
}

func setupTOTPTestDB(t *testing.T) *sql.DB {
	// Use in-memory SQLite for testing
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	schema := MFATestSchemaDDL

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create test schema: %v", err)
	}

	return db
}

func TestServerSideTOTPKeyManagement(t *testing.T) {
	setupTOTPTestEnvironment(t)

	username := "testuser"

	// Test key derivation consistency
	key1, err := crypto.DeriveMFAUserKey(username)
	if err != nil {
		t.Fatalf("Failed to derive TOTP key 1: %v", err)
	}
	defer crypto.SecureZeroMFAKey(key1)

	key2, err := crypto.DeriveMFAUserKey(username)
	if err != nil {
		t.Fatalf("Failed to derive TOTP key 2: %v", err)
	}
	defer crypto.SecureZeroMFAKey(key2)

	// Keys should be identical for the same user
	if len(key1) != len(key2) {
		t.Fatal("TOTP keys have different lengths")
	}

	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatal("TOTP keys are not identical")
		}
	}

	// Test that different users get different keys
	key3, err := crypto.DeriveMFAUserKey("different_user")
	if err != nil {
		t.Fatalf("Failed to derive TOTP key 3: %v", err)
	}
	defer crypto.SecureZeroMFAKey(key3)

	// Keys should be different for different users
	identical := true
	for i := range key1 {
		if key1[i] != key3[i] {
			identical = false
			break
		}
	}
	if identical {
		t.Fatal("TOTP keys for different users are identical")
	}
}

func TestMFASetup(t *testing.T) {
	setupTOTPTestEnvironment(t)

	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "testuser"

	// Test TOTP setup generation
	setup, err := GenerateMFASetup(username)
	if err != nil {
		t.Fatalf("Failed to generate TOTP setup: %v", err)
	}

	// Validate setup structure
	if setup.Secret == "" {
		t.Fatal("TOTP secret is empty")
	}
	if setup.QRCodeURL == "" {
		t.Fatal("TOTP QR code URL is empty")
	}
	if len(setup.BackupCodes) != BackupCodeCount {
		t.Fatalf("Expected %d backup codes, got %d", BackupCodeCount, len(setup.BackupCodes))
	}
	if setup.ManualEntry == "" {
		t.Fatal("TOTP manual entry is empty")
	}

	// Store the TOTP setup
	if err := StoreMFASetup(db, username, setup); err != nil {
		t.Fatalf("Failed to store TOTP setup: %v", err)
	}

	// Verify setup was stored correctly
	totpData, err := getMFAData(db, username)
	if err != nil {
		t.Fatalf("Failed to retrieve TOTP data: %v", err)
	}

	if totpData.Enabled {
		t.Fatal("TOTP should not be enabled before completion")
	}
	if totpData.SetupCompleted {
		t.Fatal("TOTP setup should not be completed yet")
	}

	// Test that we can decrypt the stored secret
	decryptedSecret, err := decryptTOTPSecret(totpData.SecretEncrypted, username)
	if err != nil {
		t.Fatalf("Failed to decrypt TOTP secret: %v", err)
	}

	if decryptedSecret != setup.Secret {
		t.Fatal("Decrypted TOTP secret does not match original")
	}
}

func TestTOTPCompletion(t *testing.T) {
	setupTOTPTestEnvironment(t)

	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "testuser"

	// Generate and store TOTP setup
	setup, err := GenerateMFASetup(username)
	if err != nil {
		t.Fatalf("Failed to generate TOTP setup: %v", err)
	}

	if err := StoreMFASetup(db, username, setup); err != nil {
		t.Fatalf("Failed to store TOTP setup: %v", err)
	}

	// Generate a valid TOTP code
	currentCode, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	// Complete TOTP setup
	if err := CompleteMFASetup(db, username, currentCode); err != nil {
		t.Fatalf("Failed to complete TOTP setup: %v", err)
	}

	// Verify TOTP is now enabled
	enabled, err := IsUserMFAEnabled(db, username)
	if err != nil {
		t.Fatalf("Failed to check TOTP status: %v", err)
	}
	if !enabled {
		t.Fatal("TOTP should be enabled after completion")
	}

	// Test invalid code during setup completion
	setup2, err := GenerateMFASetup("testuser2")
	if err != nil {
		t.Fatalf("Failed to generate second TOTP setup: %v", err)
	}

	if err := StoreMFASetup(db, "testuser2", setup2); err != nil {
		t.Fatalf("Failed to store second TOTP setup: %v", err)
	}

	// Try to complete with invalid code
	if err := CompleteMFASetup(db, "testuser2", "000000"); err == nil {
		t.Fatal("TOTP setup completion should fail with invalid code")
	}
}

func TestTOTPValidation(t *testing.T) {
	setupTOTPTestEnvironment(t)

	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "testuser"

	// Set up and complete TOTP
	setup, err := GenerateMFASetup(username)
	if err != nil {
		t.Fatalf("Failed to generate TOTP setup: %v", err)
	}

	if err := StoreMFASetup(db, username, setup); err != nil {
		t.Fatalf("Failed to store TOTP setup: %v", err)
	}

	currentCode, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	if err := CompleteMFASetup(db, username, currentCode); err != nil {
		t.Fatalf("Failed to complete TOTP setup: %v", err)
	}

	// Test valid TOTP code validation
	testTime := time.Now().UTC()
	validCode, err := totp.GenerateCode(setup.Secret, testTime)
	if err != nil {
		t.Fatalf("Failed to generate valid TOTP code: %v", err)
	}

	if err := ValidateTOTPCode(db, username, validCode); err != nil {
		t.Fatalf("Valid TOTP code should be accepted: %v", err)
	}

	// Test invalid TOTP code
	if err := ValidateTOTPCode(db, username, "000000"); err == nil {
		t.Fatal("Invalid TOTP code should be rejected")
	}

	// Test replay attack prevention
	if err := ValidateTOTPCode(db, username, validCode); err == nil {
		t.Fatal("TOTP code replay should be prevented")
	}
}

func TestBackupCodeValidation(t *testing.T) {
	setupTOTPTestEnvironment(t)

	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "testuser"

	// Set up and complete TOTP
	setup, err := GenerateMFASetup(username)
	if err != nil {
		t.Fatalf("Failed to generate TOTP setup: %v", err)
	}

	if err := StoreMFASetup(db, username, setup); err != nil {
		t.Fatalf("Failed to store TOTP setup: %v", err)
	}

	currentCode, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	if err := CompleteMFASetup(db, username, currentCode); err != nil {
		t.Fatalf("Failed to complete TOTP setup: %v", err)
	}

	// Test valid backup code
	firstBackupCode := setup.BackupCodes[0]
	if err := ValidateBackupCode(db, username, firstBackupCode); err != nil {
		t.Fatalf("Valid backup code should be accepted: %v", err)
	}

	// Test backup code replay prevention
	if err := ValidateBackupCode(db, username, firstBackupCode); err == nil {
		t.Fatal("Backup code replay should be prevented")
	}

	// Test invalid backup code
	if err := ValidateBackupCode(db, username, "INVALIDCODE"); err == nil {
		t.Fatal("Invalid backup code should be rejected")
	}
}

func TestTOTPCleanup(t *testing.T) {
	setupTOTPTestEnvironment(t)

	db := setupTOTPTestDB(t)
	defer db.Close()

	// Test cleanup function doesn't error
	if err := CleanupMFALogs(db); err != nil {
		t.Fatalf("TOTP cleanup failed: %v", err)
	}
}

func TestMFAReset(t *testing.T) {
	setupTOTPTestEnvironment(t)

	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "testuser"

	// Set up and complete TOTP
	setup, err := GenerateMFASetup(username)
	if err != nil {
		t.Fatalf("Failed to generate TOTP setup: %v", err)
	}

	if err := StoreMFASetup(db, username, setup); err != nil {
		t.Fatalf("Failed to store TOTP setup: %v", err)
	}

	currentCode, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	if err := CompleteMFASetup(db, username, currentCode); err != nil {
		t.Fatalf("Failed to complete TOTP setup: %v", err)
	}

	// Verify TOTP is enabled
	enabled, err := IsUserMFAEnabled(db, username)
	if err != nil {
		t.Fatalf("Failed to check TOTP status: %v", err)
	}
	if !enabled {
		t.Fatal("TOTP should be enabled")
	}

	// Get a backup code for reset
	backupCode := setup.BackupCodes[0]

	// Reset TOTP with backup code
	newSetup, err := ResetMFA(db, username, backupCode)
	if err != nil {
		t.Fatalf("Failed to reset TOTP: %v", err)
	}

	// Verify new setup is different from old setup
	if newSetup.Secret == setup.Secret {
		t.Fatal("New TOTP secret should be different from old secret")
	}

	// Reset stages a new secret; MFA is inactive until verify completes.
	enabled, err = IsUserMFAEnabled(db, username)
	if err != nil {
		t.Fatalf("Failed to check TOTP status after reset: %v", err)
	}
	if enabled {
		t.Fatal("TOTP should not be enabled until verify completes after reset")
	}

	// Verify old TOTP code no longer works
	oldCode, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to generate old TOTP code: %v", err)
	}
	if err := ValidateTOTPCode(db, username, oldCode); err == nil {
		t.Fatal("Old TOTP code should not work after reset")
	}

	newCode, err := totp.GenerateCode(newSetup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to generate new TOTP code: %v", err)
	}
	if err := CompleteMFASetup(db, username, newCode); err != nil {
		t.Fatalf("Failed to complete TOTP setup after reset: %v", err)
	}

	enabled, err = IsUserMFAEnabled(db, username)
	if err != nil {
		t.Fatalf("Failed to check TOTP status after reset verify: %v", err)
	}
	if !enabled {
		t.Fatal("TOTP should be enabled after reset verify")
	}
	if err := ValidateTOTPCode(db, username, newCode); err != nil {
		t.Fatalf("New TOTP code should work after reset verify: %v", err)
	}

	// Test invalid backup code for reset
	setup2, err := GenerateMFASetup("testuser2")
	if err != nil {
		t.Fatalf("Failed to generate second TOTP setup: %v", err)
	}

	if err := StoreMFASetup(db, "testuser2", setup2); err != nil {
		t.Fatalf("Failed to store second TOTP setup: %v", err)
	}

	currentCode2, err := totp.GenerateCode(setup2.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	if err := CompleteMFASetup(db, "testuser2", currentCode2); err != nil {
		t.Fatalf("Failed to complete TOTP setup: %v", err)
	}

	// Try to reset with invalid backup code
	if _, err := ResetMFA(db, "testuser2", "INVALIDCODE"); err == nil {
		t.Fatal("TOTP reset should fail with invalid backup code")
	}
}

// setupFullTOTP is a helper that creates a fully enrolled TOTP user in the given db.
func setupFullTOTP(t *testing.T, db *sql.DB, username string) *MFASetup {
	t.Helper()
	setup, err := GenerateMFASetup(username)
	if err != nil {
		t.Fatalf("GenerateTOTPSetup: %v", err)
	}
	if err := StoreMFASetup(db, username, setup); err != nil {
		t.Fatalf("StoreTOTPSetup: %v", err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := CompleteMFASetup(db, username, code); err != nil {
		t.Fatalf("CompleteTOTPSetup: %v", err)
	}
	return setup
}

// driveFailures submits n invalid TOTP codes for username and returns the last error.
// It sets last_failed_attempt_at to pastTime so backoff windows are not blocking
// unless the caller explicitly wants them to be.
func driveFailures(t *testing.T, db *sql.DB, username string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := ValidateTOTPCode(db, username, "000000")
		if err == nil {
			t.Fatalf("attempt %d: expected failure but got nil", i+1)
		}
		// After each failure, back-date last_failed_attempt_at so the soft backoff
		// does not block subsequent attempts in this loop.
		_, dbErr := db.Exec(
			`UPDATE user_mfa_lockout SET last_failed_attempt_at = ? WHERE username = ?`,
			time.Now().Add(-2*time.Hour), username,
		)
		if dbErr != nil {
			t.Fatalf("failed to back-date last_failed_at: %v", dbErr)
		}
	}
}

// TestComputeLockoutState_NoWindow verifies that a fresh state (no window) is always allowed.
func TestComputeLockoutState_NoWindow(t *testing.T) {
	s := mfaLockoutState{}
	allowed, retryAfter, _ := computeLockoutState(s, time.Now())
	if !allowed {
		t.Fatal("expected allowed with no window")
	}
	if retryAfter != 0 {
		t.Fatalf("expected zero retryAfter, got %v", retryAfter)
	}
}

// TestComputeLockoutState_ExpiredWindow verifies that an expired window resets to allowed.
func TestComputeLockoutState_ExpiredWindow(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(-25 * time.Hour) // 25h ago, beyond the 24h window
	attempts := 50
	s := mfaLockoutState{
		failedAttempts: attempts,
		windowStarted:  &windowStart,
		lastFailed:     &windowStart,
	}
	allowed, _, _ := computeLockoutState(s, now)
	if !allowed {
		t.Fatal("expected allowed for expired window regardless of attempt count")
	}
}

// TestComputeLockoutState_SoftBackoff verifies exponential backoff triggers at threshold+1.
func TestComputeLockoutState_SoftBackoff(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(-1 * time.Hour)
	lastFailed := now.Add(-30 * time.Second) // failed 30s ago

	// At exactly mfaSoftLockoutThreshold failures, next attempt is still allowed
	// (backoff starts at threshold+1 in the record path, but computeLockoutState
	// checks >= threshold with the recorded count).
	// At threshold failures + 30s backoff window of 2^0=1 minute, not yet expired.
	s := mfaLockoutState{
		failedAttempts: mfaSoftLockoutThreshold,
		windowStarted:  &windowStart,
		lastFailed:     &lastFailed,
	}
	allowed, retryAfter, _ := computeLockoutState(s, now)
	if allowed {
		t.Fatal("expected blocked at soft lockout threshold with recent failure")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retryAfter, got %v", retryAfter)
	}
}

// TestComputeLockoutState_BackoffDoubles verifies that retryAfter doubles between consecutive attempts.
func TestComputeLockoutState_BackoffDoubles(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(-1 * time.Hour)
	lastFailed := now.Add(-5 * time.Second) // very recent failure

	var prevRetry time.Duration
	for attempts := mfaSoftLockoutThreshold; attempts < mfaSoftLockoutThreshold+5; attempts++ {
		s := mfaLockoutState{
			failedAttempts: attempts,
			windowStarted:  &windowStart,
			lastFailed:     &lastFailed,
		}
		_, retryAfter, _ := computeLockoutState(s, now)
		if attempts > mfaSoftLockoutThreshold && retryAfter <= prevRetry {
			t.Fatalf("at attempt %d retryAfter=%v did not increase from previous %v",
				attempts, retryAfter, prevRetry)
		}
		prevRetry = retryAfter
	}
}

// TestComputeLockoutState_HardCap verifies the hard daily cap blocks all attempts.
func TestComputeLockoutState_HardCap(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(-1 * time.Hour)
	lastFailed := now.Add(-1 * time.Second)

	s := mfaLockoutState{
		failedAttempts: mfaHardCapThreshold,
		windowStarted:  &windowStart,
		lastFailed:     &lastFailed,
	}
	allowed, retryAfter, _ := computeLockoutState(s, now)
	if allowed {
		t.Fatal("expected blocked at hard cap threshold")
	}
	// retryAfter should be approximately 23h (window expires in ~23h)
	if retryAfter < 22*time.Hour || retryAfter > 24*time.Hour {
		t.Fatalf("expected retryAfter near 23h, got %v", retryAfter)
	}
}

// TestComputeLockoutState_BackoffCap verifies that backoff is capped at mfaBackoffCapMinutes.
func TestComputeLockoutState_BackoffCap(t *testing.T) {
	now := time.Now()
	windowStart := now.Add(-1 * time.Hour)
	lastFailed := now.Add(-1 * time.Second)

	// At 20 failures (10 above soft threshold), backoff would be 2^10=1024min uncapped.
	s := mfaLockoutState{
		failedAttempts: mfaSoftLockoutThreshold + 10,
		windowStarted:  &windowStart,
		lastFailed:     &lastFailed,
	}
	_, retryAfter, _ := computeLockoutState(s, now)
	maxExpected := time.Duration(mfaBackoffCapMinutes)*time.Minute + 5*time.Second
	if retryAfter > maxExpected {
		t.Fatalf("retryAfter %v exceeds cap of %d minutes", retryAfter, mfaBackoffCapMinutes)
	}
}

// TestTOTPLockout_SoftBackoffEntry verifies that after threshold failures the next
// ValidateTOTPCode call returns a MFALockoutError.
// Strategy: drive (threshold - 1) back-dated failures so they don't self-block, then
// drive 1 recent failure (no back-dating) so the recorded last_failed_at is NOW.
// The very next attempt sees failed_attempts == threshold with a recent last_failed_at
// and must be blocked by computeLockoutState before any crypto.
func TestTOTPLockout_SoftBackoffEntry(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "lockout-soft-user"
	setupFullTOTP(t, db, username)

	// Drive (threshold - 1) back-dated failures.
	driveFailures(t, db, username, mfaSoftLockoutThreshold-1)

	// Drive exactly 1 more failure WITHOUT back-dating, so last_failed_at = now.
	err := ValidateTOTPCode(db, username, "000000")
	if err == nil {
		t.Fatal("expected error for invalid code on final failure")
	}
	// This attempt is invalid code, not lockout-blocked yet.
	if _, ok := err.(*MFALockoutError); ok {
		t.Fatalf("should not be locked out yet at attempt %d, got %T", mfaSoftLockoutThreshold, err)
	}

	// Now the next attempt: failed_attempts == threshold, last_failed_at == recent.
	// computeLockoutState must block it before the crypto check.
	err = ValidateTOTPCode(db, username, "000000")
	if err == nil {
		t.Fatal("expected lockout error after exceeding soft threshold")
	}
	lockoutErr, ok := err.(*MFALockoutError)
	if !ok {
		t.Fatalf("expected *MFALockoutError, got %T: %v", err, err)
	}
	if lockoutErr.RetryAfter <= 0 {
		t.Fatalf("expected positive RetryAfter, got %v", lockoutErr.RetryAfter)
	}
}

// TestTOTPLockout_HardDailyCapEntry verifies that at mfaHardCapThreshold failures
// the account is fully locked until the window expires.
func TestTOTPLockout_HardDailyCapEntry(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "lockout-hard-user"
	setupFullTOTP(t, db, username)

	// Drive mfaHardCapThreshold failures (back-dating between each).
	driveFailures(t, db, username, mfaHardCapThreshold)

	// One more attempt: must return MFALockoutError with retryAfter near window end.
	err := ValidateTOTPCode(db, username, "000000")
	if err == nil {
		t.Fatal("expected lockout error after hard cap")
	}
	lockoutErr, ok := err.(*MFALockoutError)
	if !ok {
		t.Fatalf("expected *MFALockoutError, got %T: %v", err, err)
	}
	if lockoutErr.RetryAfter <= 0 {
		t.Fatalf("expected positive RetryAfter for hard cap, got %v", lockoutErr.RetryAfter)
	}
}

// TestTOTPLockout_ClearOnSuccess verifies that a successful TOTP code clears all lockout state.
func TestTOTPLockout_ClearOnSuccess(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "lockout-clear-user"
	setup := setupFullTOTP(t, db, username)

	// Drive some failures.
	driveFailures(t, db, username, mfaSoftLockoutThreshold-1)

	// Submit a valid code (back-date last_failed first so backoff doesn't block).
	_, dbErr := db.Exec(
		`UPDATE user_mfa_lockout SET last_failed_attempt_at = ? WHERE username = ?`,
		time.Now().Add(-2*time.Hour), username,
	)
	if dbErr != nil {
		t.Fatalf("failed to back-date: %v", dbErr)
	}

	validCode, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := ValidateTOTPCode(db, username, validCode); err != nil {
		t.Fatalf("valid code should succeed: %v", err)
	}

	// Verify lockout row is cleared (successful auth deletes the row).
	var lockoutCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM user_mfa_lockout WHERE username = ?`, username).Scan(&lockoutCount)
	if err != nil {
		t.Fatalf("query lockout state: %v", err)
	}
	if lockoutCount != 0 {
		t.Fatalf("expected lockout row removed after success, got count=%d", lockoutCount)
	}
}

// TestTOTPLockout_WindowResetAfter24h verifies that failures older than 24h do not block.
func TestTOTPLockout_WindowResetAfter24h(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "lockout-expired-user"
	setupFullTOTP(t, db, username)

	// Manually set a window that started 25 hours ago with hard-cap failures.
	staleWindow := time.Now().Add(-25 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO user_mfa_lockout (username, failed_attempts_in_window, window_started_at, last_failed_attempt_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			failed_attempts_in_window = excluded.failed_attempts_in_window,
			window_started_at = excluded.window_started_at,
			last_failed_attempt_at = excluded.last_failed_attempt_at`,
		username, mfaHardCapThreshold+5, staleWindow, staleWindow,
	)
	if err != nil {
		t.Fatalf("setup stale window: %v", err)
	}

	// A new failure should reset the window (not be blocked).
	err = ValidateTOTPCode(db, username, "000000")
	if err == nil {
		t.Fatal("expected error for invalid code (but not a lockout error)")
	}
	if _, ok := err.(*MFALockoutError); ok {
		t.Fatal("stale window should not produce lockout error; window should have been reset")
	}
}

// TestTOTPSkew_AcceptsPreviousWindow verifies that a code from the previous 30s window
// is accepted.
func TestTOTPSkew_AcceptsPreviousWindow(t *testing.T) {
	setupTOTPTestEnvironment(t)
	db := setupTOTPTestDB(t)
	defer db.Close()

	username := "skew-user"
	setup := setupFullTOTP(t, db, username)

	// Generate a code for 35 seconds ago (previous 30s window).
	prevWindow := time.Now().UTC().Add(-35 * time.Second)
	prevCode, err := totp.GenerateCode(setup.Secret, prevWindow)
	if err != nil {
		t.Fatalf("GenerateCode for previous window: %v", err)
	}

	if err := ValidateTOTPCode(db, username, prevCode); err != nil {
		t.Fatalf("code from previous window should be accepted: %v", err)
	}
}
