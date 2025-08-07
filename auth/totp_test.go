package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"testing"
	"time"

	"github.com/84adam/arkfile/crypto"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants
const (
	testUsername         = "test_username"
	testPassword         = "TestPassword123!"
	testSecretB32        = "JBSWY3DPEHPK3PXP" // Test secret for reproducible tests
	TOTPSetupTempContext = "ARKFILE_TOTP_SETUP_TEMP"
)

// Helper function to generate test session key
func generateTestSessionKey(t *testing.T) []byte {
	t.Helper()
	// Generate a deterministic session key for testing
	opaqueExportKey := make([]byte, 32)
	copy(opaqueExportKey, []byte("test-opaque-export-key-for-testing"))

	sessionKey, err := crypto.DeriveSessionKey(opaqueExportKey, crypto.SessionKeyContext)
	require.NoError(t, err)
	return sessionKey
}

// Helper function to generate valid TOTP code for testing
func generateTestTOTPCode(t *testing.T, secret string, testTime time.Time) string {
	t.Helper()
	// NOTE: totp.GenerateCodeCustom expects the raw secret bytes, not the base32 string.
	// But our validation functions now use the base32 string. For the test to pass,
	// we must generate the code from the base32 string, just like an authenticator app would.
	code, err := totp.GenerateCode(secret, testTime)
	require.NoError(t, err)
	return code
}

// Helper function to generate valid TOTP code for benchmarking
func generateTestTOTPCodeBench(b *testing.B, secret string, testTime time.Time) string {
	b.Helper()
	// This appears to be unused now. Let's keep it but fix it.
	code, err := totp.GenerateCode(secret, testTime)
	if err != nil {
		b.Fatal(err)
	}
	return code
}

// Helper function to create test database with mocks
func setupTOTPTestDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	return db, mock
}

// Test TOTP Setup Generation
func TestGenerateTOTPSetup_Success(t *testing.T) {
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	setup, err := GenerateTOTPSetup(testUsername, sessionKey)
	require.NoError(t, err)
	assert.NotNil(t, setup)

	// Verify secret is base32 encoded (add padding if needed)
	secretPadded := setup.Secret
	if len(setup.Secret)%8 != 0 {
		padding := 8 - (len(setup.Secret) % 8)
		for i := 0; i < padding; i++ {
			secretPadded += "="
		}
	}
	secretBytes, err := base32.StdEncoding.DecodeString(secretPadded)
	require.NoError(t, err)
	assert.Equal(t, 32, len(secretBytes)) // 32 bytes = 256 bits

	// Verify QR code URL format
	expectedPrefix := "otpauth://totp/ArkFile:" + testUsername + "?secret="
	assert.Contains(t, setup.QRCodeURL, expectedPrefix)
	assert.Contains(t, setup.QRCodeURL, "&issuer=ArkFile")
	assert.Contains(t, setup.QRCodeURL, "&digits=6")
	assert.Contains(t, setup.QRCodeURL, "&period=30")

	// Verify backup codes
	assert.Len(t, setup.BackupCodes, BackupCodeCount)
	for _, code := range setup.BackupCodes {
		assert.Len(t, code, BackupCodeLength)
		// Verify codes only contain allowed characters
		for _, char := range code {
			assert.Contains(t, BackupCodeCharset, string(char))
		}
	}

	// Verify manual entry format
	assert.NotEmpty(t, setup.ManualEntry)
	assert.Contains(t, setup.ManualEntry, " ") // Should contain spaces for formatting
}

// Test TOTP Setup Storage
func TestStoreTOTPSetup_Success(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	setup, err := GenerateTOTPSetup(testUsername, sessionKey)
	require.NoError(t, err)

	// Mock database insert
	mock.ExpectExec(`INSERT OR REPLACE INTO user_totp`).
		WithArgs(testUsername, sqlmock.AnyArg(), sqlmock.AnyArg(), false, false, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = StoreTOTPSetup(db, testUsername, setup, sessionKey)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Setup Completion
func TestCompleteTOTPSetup_Success(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Encrypt the test secret with TEMPORARY key (like during setup)
	tempTotpKey, err := crypto.DeriveSessionKey(sessionKey, TOTPSetupTempContext)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(tempTotpKey)

	secretEncrypted, err := crypto.EncryptGCM([]byte(testSecretB32), tempTotpKey)
	require.NoError(t, err)

	// Create some mock backup codes
	backupCodes := []string{"TEST123456", "TEST234567"}
	backupCodesJSON, err := json.Marshal(backupCodes)
	require.NoError(t, err)

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, tempTotpKey)
	require.NoError(t, err)

	// Mock database queries
	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
			AddRow(secretEncrypted, backupCodesEncrypted, false, false, time.Now(), nil))

	// Mock update query with production encryption
	mock.ExpectExec(`UPDATE user_totp SET secret_encrypted = \?, backup_codes_encrypted = \?, enabled = true, setup_completed = true WHERE username = \?`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), testUsername).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Generate valid TOTP code
	testTime := time.Now()
	validCode := generateTestTOTPCode(t, testSecretB32, testTime)

	err = CompleteTOTPSetup(db, testUsername, validCode, sessionKey)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Setup Completion with Invalid Code
func TestCompleteTOTPSetup_InvalidCode(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Encrypt the test secret with TEMPORARY key (like during setup)
	tempTotpKey, err := crypto.DeriveSessionKey(sessionKey, TOTPSetupTempContext)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(tempTotpKey)

	secretEncrypted, err := crypto.EncryptGCM([]byte(testSecretB32), tempTotpKey)
	require.NoError(t, err)

	// Create some mock backup codes
	backupCodes := []string{"TEST123456", "TEST234567"}
	backupCodesJSON, err := json.Marshal(backupCodes)
	require.NoError(t, err)

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, tempTotpKey)
	require.NoError(t, err)

	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
			AddRow(secretEncrypted, backupCodesEncrypted, false, false, time.Now(), nil))

	// Use invalid code
	err = CompleteTOTPSetup(db, testUsername, "000000", sessionKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Code Validation
func TestValidateTOTPCode_Success(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Setup encrypted secret
	totpKey, err := deriveUserTOTPKey(sessionKey)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(totpKey)

	secretEncrypted, err := crypto.EncryptGCM([]byte(testSecretB32), totpKey)
	require.NoError(t, err)

	// Mock getting TOTP data
	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
			AddRow(secretEncrypted, []byte("encrypted-backup-codes"), true, true, time.Now(), nil))

	// Replay protection is temporarily disabled
	// TODO: Re-enable replay protection tests when the feature is re-implemented

	// Mock updating last used
	mock.ExpectExec(`UPDATE user_totp SET last_used = \? WHERE username = \?`).
		WithArgs(sqlmock.AnyArg(), testUsername).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Generate valid code
	testTime := time.Now()
	validCode := generateTestTOTPCode(t, testSecretB32, testTime)

	err = ValidateTOTPCode(db, testUsername, validCode, sessionKey)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TODO: Re-implement this test when replay protection is re-enabled
// // Test TOTP Code Validation with Replay Attack
// func TestValidateTOTPCode_ReplayAttack(t *testing.T) {
// 	db, mock := setupTOTPTestDB(t)
// 	sessionKey := generateTestSessionKey(t)
// 	defer crypto.SecureZeroSessionKey(sessionKey)

// 	// Setup encrypted secret
// 	totpKey, err := deriveUserTOTPKey(sessionKey)
// 	require.NoError(t, err)
// 	defer crypto.SecureZeroSessionKey(totpKey)

// 	secretEncrypted, err := crypto.EncryptGCM([]byte(testSecretB32), totpKey)
// 	require.NoError(t, err)

// 	// Mock getting TOTP data
// 	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
// 		WithArgs(testUsername).
// 		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
//			AddRow(secretEncrypted, []byte("encrypted-backup-codes"), true, true, time.Now(), nil))

// 	// Mock replay check - code already used
// 	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM totp_usage_log WHERE username = \? AND code_hash = \? AND window_start = \?`).
// 		WithArgs(testUsername, sqlmock.AnyArg(), sqlmock.AnyArg()).
// 		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1)) // Code already used

// 	// Generate valid code
// 	testTime := time.Now()
// 	validCode := generateTestTOTPCode(t, testSecretB32, testTime)

// 	err = ValidateTOTPCode(db, testUsername, validCode, sessionKey)
// 	require.Error(t, err)
// 	assert.Contains(t, err.Error(), "replay attack detected")

// 	assert.NoError(t, mock.ExpectationsWereMet())
// }

// Test Backup Code Validation
func TestValidateBackupCode_Success(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Setup test backup codes
	backupCodes := []string{"TEST123456", "TEST234567", "TEST345678"}
	backupCodesJSON, err := json.Marshal(backupCodes)
	require.NoError(t, err)

	// Encrypt backup codes
	totpKey, err := deriveUserTOTPKey(sessionKey)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(totpKey)

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	require.NoError(t, err)

	// Mock getting TOTP data
	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
			AddRow([]byte("encrypted-secret"), backupCodesEncrypted, true, true, time.Now(), nil))

	// Mock backup code replay check
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM totp_backup_usage WHERE username = \? AND code_hash = \?`).
		WithArgs(testUsername, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Mock logging backup code usage
	mock.ExpectExec(`INSERT INTO totp_backup_usage \(username, code_hash\) VALUES \(\?, \?\)`).
		WithArgs(testUsername, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock updating last used
	mock.ExpectExec(`UPDATE user_totp SET last_used = \? WHERE username = \?`).
		WithArgs(sqlmock.AnyArg(), testUsername).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Use valid backup code
	testCode := backupCodes[0]

	err = ValidateBackupCode(db, testUsername, testCode, sessionKey)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test Backup Code Validation with Already Used Code
func TestValidateBackupCode_AlreadyUsed(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Setup test backup codes
	backupCodes := []string{"TEST123456", "TEST234567", "TEST345678"}
	backupCodesJSON, err := json.Marshal(backupCodes)
	require.NoError(t, err)

	// Encrypt backup codes
	totpKey, err := deriveUserTOTPKey(sessionKey)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(totpKey)

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	require.NoError(t, err)

	// Mock getting TOTP data
	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
			AddRow([]byte("encrypted-secret"), backupCodesEncrypted, true, true, time.Now(), nil))

	// Mock backup code replay check - code already used
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM totp_backup_usage WHERE username = \? AND code_hash = \?`).
		WithArgs(testUsername, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1)) // Code already used

	// Use backup code that's already been used
	testCode := backupCodes[0]

	err = ValidateBackupCode(db, testUsername, testCode, sessionKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backup code already used")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Status Check
func TestIsUserTOTPEnabled_Success(t *testing.T) {
	db, mock := setupTOTPTestDB(t)

	// Mock enabled TOTP
	mock.ExpectQuery(`SELECT enabled, setup_completed FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"enabled", "setup_completed"}).
			AddRow(true, true))

	enabled, err := IsUserTOTPEnabled(db, testUsername)
	require.NoError(t, err)
	assert.True(t, enabled)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Status Check for Non-Existent User
func TestIsUserTOTPEnabled_UserNotFound(t *testing.T) {
	db, mock := setupTOTPTestDB(t)

	// Mock no TOTP record
	mock.ExpectQuery(`SELECT enabled, setup_completed FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnError(sql.ErrNoRows)

	enabled, err := IsUserTOTPEnabled(db, testUsername)
	require.NoError(t, err)
	assert.False(t, enabled)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Disable
func TestDisableTOTP_Success(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Setup encrypted secret for validation
	totpKey, err := deriveUserTOTPKey(sessionKey)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(totpKey)

	secretEncrypted, err := crypto.EncryptGCM([]byte(testSecretB32), totpKey)
	require.NoError(t, err)

	// Mock getting TOTP data for validation
	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
			AddRow(secretEncrypted, []byte("encrypted-backup-codes"), true, true, time.Now(), nil))

	// Replay protection is temporarily disabled
	// TODO: Re-enable replay protection tests when the feature is re-implemented

	// Mock updating last used for validation
	mock.ExpectExec(`UPDATE user_totp SET last_used = \? WHERE username = \?`).
		WithArgs(sqlmock.AnyArg(), testUsername).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock disabling TOTP
	mock.ExpectExec(`DELETE FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Generate valid code for disable
	testTime := time.Now()
	validCode := generateTestTOTPCode(t, testSecretB32, testTime)

	err = DisableTOTP(db, testUsername, validCode, sessionKey)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Cleanup
func TestCleanupTOTPLogs_Success(t *testing.T) {
	db, mock := setupTOTPTestDB(t)

	// Mock cleanup of TOTP usage logs
	mock.ExpectExec(`DELETE FROM totp_usage_log WHERE used_at < \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 5)) // 5 rows deleted

	// Mock cleanup of backup code usage logs
	mock.ExpectExec(`DELETE FROM totp_backup_usage WHERE used_at < \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 2)) // 2 rows deleted

	err := CleanupTOTPLogs(db)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test TOTP Helper Functions
func TestGenerateSingleBackupCode(t *testing.T) {
	code := generateSingleBackupCode()

	assert.Len(t, code, BackupCodeLength)

	// Verify all characters are from allowed charset
	for _, char := range code {
		assert.Contains(t, BackupCodeCharset, string(char))
	}
}

func TestFormatManualEntry(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	formatted := formatManualEntry(secret)

	assert.Contains(t, formatted, " ")                           // Should contain spaces
	assert.Equal(t, len(secret)+len(secret)/4-1, len(formatted)) // Original + spaces, -1 for no trailing space
}

func TestHashString(t *testing.T) {
	input := "test-string"
	hash1 := hashString(input)
	hash2 := hashString(input)

	assert.Equal(t, hash1, hash2) // Same input should produce same hash
	assert.Len(t, hash1, 64)      // SHA-256 produces 64 character hex string

	// Different inputs should produce different hashes
	hash3 := hashString("different-string")
	assert.NotEqual(t, hash1, hash3)
}

// Test Clock Skew Tolerance
func TestValidateTOTPCode_ClockSkewTolerance(t *testing.T) {
	db, mock := setupTOTPTestDB(t)
	sessionKey := generateTestSessionKey(t)
	defer crypto.SecureZeroSessionKey(sessionKey)

	// Setup encrypted secret
	totpKey, err := deriveUserTOTPKey(sessionKey)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(totpKey)

	secretEncrypted, err := crypto.EncryptGCM([]byte(testSecretB32), totpKey)
	require.NoError(t, err)

	// Test with code from previous window (should work due to skew tolerance)
	testTime := time.Now().Add(-TOTPPeriod * time.Second) // Previous window
	validCode := generateTestTOTPCode(t, testSecretB32, testTime)

	// Mock getting TOTP data
	mock.ExpectQuery(`SELECT secret_encrypted, backup_codes_encrypted, enabled, setup_completed, created_at, last_used FROM user_totp WHERE username = \?`).
		WithArgs(testUsername).
		WillReturnRows(sqlmock.NewRows([]string{"secret_encrypted", "backup_codes_encrypted", "enabled", "setup_completed", "created_at", "last_used"}).
			AddRow(secretEncrypted, []byte("encrypted-backup-codes"), true, true, time.Now(), nil))

	// Replay protection is temporarily disabled
	// TODO: Re-enable replay protection tests when the feature is re-implemented

	// Mock updating last used
	mock.ExpectExec(`UPDATE user_totp SET last_used = \? WHERE username = \?`).
		WithArgs(sqlmock.AnyArg(), testUsername).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = ValidateTOTPCode(db, testUsername, validCode, sessionKey)
	require.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Test Session Key Security
func TestTOTPSecuritySessionKeyIsolation(t *testing.T) {
	sessionKey1 := generateTestSessionKey(t)
	sessionKey2 := make([]byte, 32)
	copy(sessionKey2, []byte("different-session-key-for-test"))

	defer func() {
		crypto.SecureZeroSessionKey(sessionKey1)
		crypto.SecureZeroSessionKey(sessionKey2)
	}()

	// Generate setup with first session key
	setup, err := GenerateTOTPSetup(testUsername, sessionKey1)
	require.NoError(t, err)

	// Encrypt with first key
	totpKey1, err := deriveUserTOTPKey(sessionKey1)
	require.NoError(t, err)
	defer crypto.SecureZeroSessionKey(totpKey1)

	secretEncrypted, err := crypto.EncryptGCM([]byte(setup.Secret), totpKey1)
	require.NoError(t, err)

	// Try to decrypt with second key (should fail)
	_, err = decryptTOTPSecret(secretEncrypted, sessionKey2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cipher: message authentication failed")
}

// Benchmark TOTP Operations
func BenchmarkGenerateTOTPSetup(b *testing.B) {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	defer crypto.SecureZeroSessionKey(sessionKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateTOTPSetup(testUsername, sessionKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateTOTPCode(b *testing.B) {
	// This would require more complex mocking for benchmarking
	// For now, just benchmark the internal validation
	secret := testSecretB32
	testTime := time.Now()
	validCode := generateTestTOTPCodeBench(b, secret, testTime)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := validateTOTPCodeInternal(secret, validCode)
		if !valid {
			b.Fatal("Code validation failed")
		}
	}
}
