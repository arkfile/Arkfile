package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/utils"
	"github.com/pquerna/otp/totp"
)

// CreateDevAdminWithOPAQUE creates a dev admin user with OPAQUE registration
// This function simulates the complete client-server OPAQUE registration flow
// internally to create a dev admin user with known credentials for testing.
//
// CRITICAL SECURITY: This function has triple-layer protection:
// 1. Production environment check
// 2. Exact username validation (only "arkfile-dev-admin")
// 3. ADMIN_USERNAMES environment variable verification
func CreateDevAdminWithOPAQUE(db *sql.DB, username, password string) (*models.User, error) {
	// SECURITY LAYER 1: Block in production environment
	if utils.IsProductionEnvironment() {
		logging.ErrorLogger.Printf("CRITICAL SECURITY: Dev admin creation blocked in production")
		return nil, fmt.Errorf("SECURITY: Dev admin creation blocked in production environment")
	}

	// SECURITY LAYER 2: Only allow exact admin username
	if username != "arkfile-dev-admin" {
		logging.ErrorLogger.Printf("SECURITY: Attempted to auto-create non-admin user: %s", username)
		return nil, fmt.Errorf("SECURITY: Only arkfile-dev-admin can be auto-created")
	}

	// SECURITY LAYER 3: Verify in ADMIN_USERNAMES env var
	adminUsernames := os.Getenv("ADMIN_USERNAMES")
	if !strings.Contains(adminUsernames, username) {
		logging.ErrorLogger.Printf("SECURITY: Username %s not in ADMIN_USERNAMES", username)
		return nil, fmt.Errorf("SECURITY: Username not in ADMIN_USERNAMES")
	}

	log.Printf("Creating dev admin user with OPAQUE protocol: %s", username)

	// Step 1: Client creates registration request
	usrCtx, M, err := ClientCreateRegistrationRequest([]byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}

	// Step 2: Server creates registration response
	rpub, rsec, err := CreateRegistrationResponse(M)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration response: %w", err)
	}

	// Step 3: Client finalizes registration
	rrec, exportKey, err := ClientFinalizeRegistration(usrCtx, rpub, username)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize registration: %w", err)
	}

	// Step 4: Server stores user record
	userRecord, err := StoreUserRecord(rsec, rrec)
	if err != nil {
		return nil, fmt.Errorf("failed to store user record: %w", err)
	}

	// Store OPAQUE user data in database
	opaqueUserData := OPAQUEUserData{
		Username:         username,
		SerializedRecord: userRecord,
		CreatedAt:        time.Now(),
	}

	if err := storeOPAQUEUserData(db, opaqueUserData); err != nil {
		return nil, fmt.Errorf("failed to store OPAQUE user data: %w", err)
	}

	log.Printf("OPAQUE registration completed for dev admin, export_key_length=%d", len(exportKey))

	// Create user record in database
	user := &models.User{
		Username:   username,
		IsApproved: true, // Auto-approve admin
		IsAdmin:    true, // Set admin privileges
		CreatedAt:  time.Now(),
	}

	// Insert user into database
	result, err := db.Exec(`
		INSERT INTO users (username, is_approved, is_admin, created_at)
		VALUES (?, ?, ?, ?)`,
		user.Username, user.IsApproved, user.IsAdmin, user.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user record: %w", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}
	user.ID = userID

	log.Printf("Dev admin user created successfully: %s (ID: %d)", username, user.ID)

	return user, nil
}

// SetupDevAdminTOTP sets up TOTP for the dev admin user with a fixed secret
// This allows predictable TOTP codes for testing purposes.
//
// SECURITY: This function is protected by production environment checks
func SetupDevAdminTOTP(db *sql.DB, user *models.User, totpSecret string) error {
	// SECURITY CHECK: Double-check production environment (defense in depth)
	if utils.IsProductionEnvironment() {
		logging.ErrorLogger.Printf("CRITICAL SECURITY: Dev admin TOTP setup blocked in production")
		return fmt.Errorf("SECURITY: Dev admin TOTP setup blocked in production environment")
	}

	log.Printf("Setting up TOTP for dev admin '%s' with fixed secret", user.Username)

	// Generate backup codes
	backupCodes := generateDevAdminBackupCodes(10)

	// Derive user-specific TOTP key from server master key
	totpKey, err := crypto.DeriveTOTPUserKey(user.Username)
	if err != nil {
		return fmt.Errorf("failed to derive TOTP user key: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Encrypt TOTP secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(totpSecret), totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Encrypt backup codes
	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt backup codes: %w", err)
	}

	// Store TOTP data in database
	_, err = db.Exec(`
		INSERT OR REPLACE INTO user_totp (
			username, secret_encrypted, backup_codes_encrypted, 
			enabled, setup_completed, created_at, last_used
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.Username, secretEncrypted, backupCodesEncrypted,
		true, true, time.Now(), nil,
	)

	if err != nil {
		return fmt.Errorf("failed to store TOTP setup: %w", err)
	}

	log.Printf("TOTP setup completed for dev admin '%s'", user.Username)
	log.Printf("SECURITY: TOTP configured with fixed secret for development/testing only!")

	return nil
}

// validateTOTPMasterKeyIntegrity performs an end-to-end test of TOTP master key
func validateTOTPMasterKeyIntegrity() error {
	testUsername := "totp-integrity-test-user"
	testData := []byte("TOTP_INTEGRITY_TEST_DATA_2025")

	// Test 1: Derive a user key
	userKey, err := crypto.DeriveTOTPUserKey(testUsername)
	if err != nil {
		return fmt.Errorf("failed to derive test user key: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(userKey)

	if len(userKey) != 32 {
		return fmt.Errorf("derived key has wrong length: expected 32, got %d", len(userKey))
	}

	// Test 2: Encrypt test data
	encrypted, err := crypto.EncryptGCM(testData, userKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt test data: %w", err)
	}

	if len(encrypted) == 0 {
		return fmt.Errorf("encrypted data is empty")
	}

	// Test 3: Decrypt test data
	decrypted, err := crypto.DecryptGCM(encrypted, userKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt test data: %w", err)
	}

	// Test 4: Verify data integrity
	if string(decrypted) != string(testData) {
		return fmt.Errorf("data integrity check failed: decrypted data doesn't match original")
	}

	log.Printf("TOTP master key integrity test passed")
	return nil
}

// ValidateDevAdminTOTPWorkflow performs complete end-to-end TOTP validation
func ValidateDevAdminTOTPWorkflow(db *sql.DB, user *models.User, totpSecret string) error {
	// Check if TOTP is enabled
	enabled, err := IsUserTOTPEnabled(db, user.Username)
	if err != nil {
		return fmt.Errorf("failed to check TOTP enabled status: %w", err)
	}

	if !enabled {
		return fmt.Errorf("TOTP not enabled after setup")
	}

	// Test TOTP decryption workflow
	present, decryptable, totpEnabled, setupCompleted, err := CanDecryptTOTPSecret(db, user.Username)
	if err != nil {
		return fmt.Errorf("TOTP decryption test failed: %w", err)
	}

	if !present || !decryptable || !totpEnabled || !setupCompleted {
		return fmt.Errorf("TOTP validation failed: present=%t, decryptable=%t, enabled=%t, setup=%t",
			present, decryptable, totpEnabled, setupCompleted)
	}

	// Generate and validate TOTP code
	currentCode, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		return fmt.Errorf("failed to generate test TOTP code: %w", err)
	}

	// Test TOTP validation
	if err := ValidateTOTPCode(db, user.Username, currentCode); err != nil {
		return fmt.Errorf("TOTP code validation failed: %w", err)
	}

	log.Printf("Complete TOTP workflow validation passed for '%s'", user.Username)
	return nil
}

// generateDevAdminBackupCodes generates backup codes for dev admin
// SECURITY: Even for dev/testing, backup codes MUST be cryptographically random
// to prevent predictable patterns that could be exploited
func generateDevAdminBackupCodes(count int) []string {
	// Use the same secure random generation as production
	// This ensures dev environment matches production behavior
	return generateBackupCodes(count)
}

// waitForNextTOTPWindow calculates minimum time to wait for next TOTP window
// This ensures we don't trigger replay detection when validating TOTP multiple times
func waitForNextTOTPWindow() time.Duration {
	now := time.Now().UTC()
	currentWindowStart := now.Truncate(30 * time.Second)
	nextWindowStart := currentWindowStart.Add(30 * time.Second)
	waitDuration := nextWindowStart.Sub(now)

	// Add 100ms buffer to ensure we're solidly in new window
	return waitDuration + (100 * time.Millisecond)
}

// ValidateDevAdminAuthentication performs complete end-to-end validation of dev admin authentication
// This function simulates the entire OPAQUE authentication flow internally to ensure
// the dev admin registration was successful and the system is working properly
func ValidateDevAdminAuthentication(db *sql.DB, username, password, totpSecret string) error {
	// Simulate client credential request
	sec, pub, err := ClientCreateCredentialRequest([]byte(password))
	if err != nil {
		return fmt.Errorf("credential request failed: %w", err)
	}

	// Get user record and create server response
	userRecord, err := loadOPAQUEUserData(db, username)
	if err != nil {
		return fmt.Errorf("failed to load user record: %w", err)
	}

	credentialResponse, authUServer, err := CreateCredentialResponse(pub, userRecord.SerializedRecord, username)
	if err != nil {
		return fmt.Errorf("server credential response failed: %w", err)
	}

	// Create auth session to test database serialization (round-trip test)
	sessionID, err := CreateAuthSession(db, username, "dev_admin_validation", authUServer)
	if err != nil {
		return fmt.Errorf("failed to create validation session: %w", err)
	}

	// Retrieve auth session to verify database storage/retrieval
	retrievedUsername, retrievedAuthUServer, err := ValidateAuthSession(db, sessionID, "dev_admin_validation")
	if err != nil {
		return fmt.Errorf("failed to validate validation session: %w", err)
	}

	if retrievedUsername != username {
		return fmt.Errorf("username mismatch in validation session")
	}

	// Clean up session
	if err := DeleteAuthSession(db, sessionID); err != nil {
		log.Printf("Warning: failed to cleanup validation session: %v", err)
	}

	// Client recovers credentials
	_, authUClient, _, err := ClientRecoverCredentials(sec, credentialResponse, username)
	if err != nil {
		return fmt.Errorf("client credential recovery failed: %w", err)
	}

	// Verify authentication tokens match using the RETRIEVED server token
	// This ensures the token survived the database round-trip intact
	if err := UserAuth(retrievedAuthUServer, authUClient); err != nil {
		return fmt.Errorf("authentication token verification failed (db round-trip): %w", err)
	}

	// Smart wait for next TOTP window to avoid replay detection
	waitDuration := waitForNextTOTPWindow()
	log.Printf("[DEV-ADMIN] Waiting %v for next TOTP window...", waitDuration.Round(time.Millisecond))
	time.Sleep(waitDuration)

	// Validate TOTP in new window
	// Generate TOTP code for current time (now in new window)
	currentTime := time.Now()
	currentCode, err := totp.GenerateCode(totpSecret, currentTime)
	if err != nil {
		return fmt.Errorf("TOTP code generation failed: %w", err)
	}

	if err := ValidateTOTPCode(db, username, currentCode); err != nil {
		return fmt.Errorf("TOTP validation failed: %w", err)
	}

	// Validate Refresh Token Lifecycle
	// This ensures the token database schema and logic are correct
	log.Printf("[DEV-ADMIN] Validating refresh token lifecycle...")

	// 1. Create Token
	token, err := models.CreateRefreshToken(db, username)
	if err != nil {
		return fmt.Errorf("failed to create test refresh token: %w", err)
	}

	// 2. Validate Token
	valUser, err := models.ValidateRefreshToken(db, token)
	if err != nil {
		return fmt.Errorf("failed to validate test refresh token: %w", err)
	}
	if valUser != username {
		return fmt.Errorf("refresh token validation returned wrong user: expected %s, got %s", username, valUser)
	}

	// 3. Revoke Token
	if err := models.RevokeRefreshToken(db, token); err != nil {
		return fmt.Errorf("failed to revoke test refresh token: %w", err)
	}

	// 4. Verify Revocation
	_, err = models.ValidateRefreshToken(db, token)
	if err != models.ErrRefreshTokenNotFound {
		return fmt.Errorf("revoked token should be invalid, got error: %v", err)
	}

	log.Printf("[DEV-ADMIN] Refresh token lifecycle validation passed")

	return nil
}
