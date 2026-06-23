package auth

import (
	"database/sql"
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

	// Step 3: Client finalizes registration. Runs in-process, so it reads the
	// server identity directly from config (same value /api/config/opaque serves).
	rrec, exportKey, err := ClientFinalizeRegistration(usrCtx, rpub, username, OpaqueServerID())
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
	folded := utils.FoldUsername(user.Username)
	result, err := db.Exec(`
		INSERT INTO users (username, username_folded, is_approved, is_admin, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		user.Username, folded, user.IsApproved, user.IsAdmin, user.CreatedAt,
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
	mfaKey, err := crypto.DeriveMFAUserKey(user.Username)
	if err != nil {
		return fmt.Errorf("failed to derive MFA user key: %w", err)
	}
	defer crypto.SecureZeroMFAKey(mfaKey)

	// Encrypt TOTP secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(totpSecret), mfaKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Store TOTP data in database (schema has no backup_codes_encrypted column)
	_, err = db.Exec(`
		INSERT INTO user_mfa_credentials (
			credential_id, username, method_type, credential_data,
			enabled, setup_completed, created_at, last_used
		) VALUES (?, ?, 'totp', ?, ?, ?, ?, ?)`,
		newCredentialID(), user.Username, secretEncrypted,
		true, true, time.Now().UTC(), nil,
	)

	if err != nil {
		return fmt.Errorf("failed to store dev admin TOTP setup: %w", err)
	}

	// Store hashed backup codes on user_mfa_backup_codes table (reuses global Argon2id floor parameters)
	_, _ = db.Exec("DELETE FROM user_mfa_backup_codes WHERE username = ?", user.Username)
	for i, code := range backupCodes {
		salt := deriveBackupCodeSalt(user.Username, i)
		hash, err := crypto.DeriveArgon2IDKey(
			[]byte(code),
			salt,
			crypto.UnifiedArgonSecure.KeyLen,
			crypto.UnifiedArgonSecure.Memory,
			crypto.UnifiedArgonSecure.Time,
			crypto.UnifiedArgonSecure.Threads,
		)
		if err != nil {
			return fmt.Errorf("failed to hash dev admin backup code: %w", err)
		}

		_, err = db.Exec(`
			INSERT OR REPLACE INTO user_mfa_backup_codes (username, code_index, code_hash) VALUES (?, ?, ?)`,
			user.Username, i, hash,
		)
		if err != nil {
			return fmt.Errorf("failed to store dev admin backup code: %w", err)
		}
	}

	log.Printf("TOTP setup completed for dev admin '%s' and backup codes generated", user.Username)
	log.Printf("SECURITY: TOTP configured with fixed secret for development/testing only!")

	return nil
}

// ValidateDevAdminTOTPWorkflow performs end-to-end TOTP validation for dev admin bootstrap.
// It verifies that the TOTP secret was stored correctly and can be decrypted, but does NOT
// generate or validate an actual TOTP code. This avoids "burning" a TOTP window during
// server startup, which would cause replay-detection failures if an admin login attempt
// happens within the same 30-second window (e.g., during e2e testing).
func ValidateDevAdminTOTPWorkflow(db *sql.DB, user *models.User, totpSecret string) error {
	// Check if TOTP is enabled
	enabled, err := IsUserMFAEnabled(db, user.Username)
	if err != nil {
		return fmt.Errorf("failed to check TOTP enabled status: %w", err)
	}

	if !enabled {
		return fmt.Errorf("TOTP not enabled after setup")
	}

	// Test TOTP decryption workflow — this proves the master key derivation,
	// encryption, and database storage are all working correctly without
	// consuming a TOTP code window in the replay log.
	present, decryptable, totpEnabled, setupCompleted, err := CanDecryptMFASecret(db, user.Username)
	if err != nil {
		return fmt.Errorf("TOTP decryption test failed: %w", err)
	}

	if !present || !decryptable || !totpEnabled || !setupCompleted {
		return fmt.Errorf("TOTP validation failed: present=%t, decryptable=%t, enabled=%t, setup=%t",
			present, decryptable, totpEnabled, setupCompleted)
	}

	log.Printf("TOTP workflow validation passed for '%s' (decrypt-only, no code burned)", user.Username)
	return nil
}

// generateDevAdminBackupCodes generates backup codes for dev admin
// SECURITY: Even for dev/testing, backup codes MUST be cryptographically random
// to prevent predictable patterns that could be exploited
func generateDevAdminBackupCodes(count int) []string {
	// Use the same secure random generation as production
	// This ensures dev environment matches production behavior
	codes, err := generateBackupCodesResilient(count)
	if err != nil {
		panic(err)
	}
	return codes
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

	// Client recovers credentials (in-process; idS from config)
	_, authUClient, _, err := ClientRecoverCredentials(sec, credentialResponse, username, OpaqueServerID())
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

	// 2. Validate Token (returns username, newRotatedToken, error)
	valUser, _, err := models.ValidateRefreshToken(db, token)
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
	_, _, err = models.ValidateRefreshToken(db, token)
	if err != models.ErrRefreshTokenNotFound {
		return fmt.Errorf("revoked token should be invalid, got error: %v", err)
	}

	log.Printf("[DEV-ADMIN] Refresh token lifecycle validation passed")

	return nil
}
