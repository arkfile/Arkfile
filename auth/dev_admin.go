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
	rrec, exportKey, err := ClientFinalizeRegistration(usrCtx, rpub)
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

	// Enhanced debug logging
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	isDebug := debugMode == "true" || debugMode == "1"

	if isDebug {
		log.Printf("=== DEV ADMIN TOTP SETUP START ===")
		log.Printf("Setting up TOTP for user: %s", user.Username)

		// Check TOTP master key status
		masterKeyReady, keyLen := crypto.GetTOTPMasterKeyStatus()
		log.Printf("TOTP master key status: ready=%t, length=%d", masterKeyReady, keyLen)

		if !masterKeyReady {
			log.Printf("ERROR: TOTP master key not ready - BLOCKING setup")
			return fmt.Errorf("TOTP master key not ready for admin setup")
		}

		// Test master key integrity
		if err := validateTOTPMasterKeyIntegrity(); err != nil {
			log.Printf("ERROR: TOTP master key integrity validation failed: %v", err)
			return fmt.Errorf("TOTP master key integrity validation failed: %w", err)
		}
		log.Printf("TOTP master key integrity validation passed")
	}

	log.Printf("Setting up TOTP for dev admin '%s' with fixed secret", user.Username)

	// Generate backup codes
	backupCodes := generateDevAdminBackupCodes(10)

	if isDebug {
		log.Printf("Generated %d backup codes for dev admin", len(backupCodes))

		// Log backup codes for testing/debugging TOTP reset functionality
		log.Printf("Backup codes:")
		for i, code := range backupCodes {
			log.Printf("- %d: %s", i+1, code)
		}

	}

	// Derive user-specific TOTP key from server master key
	totpKey, err := crypto.DeriveTOTPUserKey(user.Username)
	if err != nil {
		if isDebug {
			log.Printf("ERROR: Failed to derive TOTP user key: %v", err)
		}
		return fmt.Errorf("failed to derive TOTP user key: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	if isDebug {
		log.Printf("Successfully derived TOTP user key, key_length=%d", len(totpKey))
	}

	// Encrypt TOTP secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(totpSecret), totpKey)
	if err != nil {
		if isDebug {
			log.Printf("ERROR: Failed to encrypt TOTP secret: %v", err)
		}
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	if isDebug {
		log.Printf("TOTP secret encrypted successfully, encrypted_length=%d", len(secretEncrypted))
	}

	// Encrypt backup codes
	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	if err != nil {
		if isDebug {
			log.Printf("ERROR: Failed to encrypt backup codes: %v", err)
		}
		return fmt.Errorf("failed to encrypt backup codes: %w", err)
	}

	if isDebug {
		log.Printf("Backup codes encrypted successfully, encrypted_length=%d", len(backupCodesEncrypted))
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
		if isDebug {
			log.Printf("ERROR: Failed to store TOTP in database: %v", err)
		}
		return fmt.Errorf("failed to store TOTP setup: %w", err)
	}

	if isDebug {
		log.Printf("TOTP data stored successfully in database")

		// Test decryption immediately
		log.Printf("Testing TOTP decryption immediately after setup...")
		testDecrypted, testErr := crypto.DecryptGCM(secretEncrypted, totpKey)
		if testErr != nil {
			log.Printf("ERROR: Immediate TOTP decryption test failed: %v", testErr)
		} else {
			log.Printf("SUCCESS: Immediate TOTP decryption test passed, decrypted_length=%d", len(testDecrypted))
		}

		log.Printf("=== DEV ADMIN TOTP SETUP END ===")
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
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	isDebug := debugMode == "true" || debugMode == "1"

	if isDebug {
		log.Printf("=== DEV ADMIN TOTP WORKFLOW VALIDATION START ===")
		log.Printf("Testing complete TOTP workflow for: %s", user.Username)
	}

	// Step 1: Check if TOTP is enabled
	enabled, err := IsUserTOTPEnabled(db, user.Username)
	if err != nil {
		return fmt.Errorf("failed to check TOTP enabled status: %w", err)
	}

	if !enabled {
		return fmt.Errorf("TOTP not enabled after setup")
	}

	if isDebug {
		log.Printf("Step 1: TOTP is enabled")
	}

	// Step 2: Test TOTP decryption workflow
	present, decryptable, totpEnabled, setupCompleted, err := CanDecryptTOTPSecret(db, user.Username)
	if err != nil {
		return fmt.Errorf("TOTP decryption test failed: %w", err)
	}

	if !present || !decryptable || !totpEnabled || !setupCompleted {
		return fmt.Errorf("TOTP validation failed: present=%t, decryptable=%t, enabled=%t, setup=%t",
			present, decryptable, totpEnabled, setupCompleted)
	}

	if isDebug {
		log.Printf("Step 2: TOTP decryption workflow validated")
	}

	// Step 3: Generate and validate TOTP code
	currentCode, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		return fmt.Errorf("failed to generate test TOTP code: %w", err)
	}

	if isDebug {
		log.Printf("Step 3: Generated test TOTP code: %s", currentCode)
	}

	// Step 4: Test TOTP validation
	if err := ValidateTOTPCode(db, user.Username, currentCode); err != nil {
		if isDebug {
			log.Printf("FAILED: TOTP code validation failed: %v", err)
		}
		return fmt.Errorf("TOTP code validation failed: %w", err)
	}

	if isDebug {
		log.Printf("SUCCESS: TOTP code validation passed")
		log.Printf("=== DEV ADMIN TOTP WORKFLOW VALIDATION COMPLETE ===")
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
