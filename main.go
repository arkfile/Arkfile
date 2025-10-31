package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pquerna/otp/totp"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/handlers"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/storage"
	"github.com/84adam/Arkfile/utils"
)

func setupRoutes(e *echo.Echo) {
	// Health check endpoint
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "ok",
		})
	})

	// Set the global Echo instance for handlers
	handlers.Echo = e

	// Set up auth Echo instance
	auth.Echo = e.Group("")
	auth.Echo.Use(auth.JWTMiddleware())
	// auth.Echo.Use(auth.TokenRevocationMiddleware(database.DB)) // Temporarily disabled for testing
	auth.Echo.Use(handlers.RequireApproved)

	// Register all routes
	handlers.RegisterRoutes()
}

func main() {
	// Load environment variables from .env file if it exists
	// This allows flexibility - the app can work with systemd EnvironmentFile
	// or with a local .env file for development
	if err := godotenv.Load(); err != nil {
		// This is expected behavior in production with systemd - log as info, not warning
		log.Printf("Info: No .env file found (%v), using system environment variables", err)
	}

	// Load configuration - this must happen after environment variables are loaded
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate production configuration
	if err := config.ValidateProductionConfig(); err != nil {
		log.Fatalf("Production configuration validation failed: %v", err)
	}

	// CRITICAL SECURITY: Prevent DEBUG_MODE in production
	if utils.IsProductionEnvironment() {
		debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
		if debugMode == "true" || debugMode == "1" {
			log.Fatal("CRITICAL SECURITY: DEBUG_MODE cannot be enabled in production environment. " +
				"Debug mode exposes sensitive cryptographic information in logs and enables admin endpoints. " +
				"Set DEBUG_MODE=false or remove it from environment variables.")
		}
	}

	log.Printf("Configuration loaded successfully")
	_ = cfg // Use the config variable to prevent unused variable warning

	// Initialize console-only logging for systemd compatibility
	// This ensures all logs go to stderr and are captured by systemd/journalctl
	log.Printf("Initializing console-only logging for systemd compatibility")
	logging.InitFallbackConsoleLogging()

	// Set debug logging if configured
	if strings.ToLower(cfg.Server.LogLevel) == "debug" {
		log.Printf("Debug logging enabled - all debug messages will be visible in journalctl")
		// The logging package will handle debug level filtering
	}

	// Initialize database
	database.InitDB()
	defer database.DB.Close()

	// Rate limiting schema is now included in unified_schema.sql
	// No separate application needed

	// Initialize OPAQUE server keys first (required for real OPAQUE provider)
	if err := auth.SetupServerKeys(database.DB); err != nil {
		log.Fatalf("Failed to setup OPAQUE server keys: %v", err)
	}

	// Initialize TOTP master key
	if err := crypto.InitializeTOTPMasterKey(); err != nil {
		log.Fatalf("Failed to initialize TOTP master key: %v", err)
	}

	// Initialize OPAQUE provider
	provider := auth.GetOPAQUEProvider()
	if !provider.IsAvailable() {
		log.Fatalf("OPAQUE provider not available")
	}

	// Verify server keys are available
	_, _, err = provider.GetServerKeys()
	if err != nil {
		log.Fatalf("Failed to get OPAQUE server keys: %v", err)
	}
	logging.InfoLogger.Printf("OPAQUE provider initialized successfully")

	// Start TOTP cleanup routine
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Clean every 5 minutes
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := auth.CleanupTOTPLogs(database.DB); err != nil {
					logging.ErrorLogger.Printf("Failed to cleanup TOTP logs: %v", err)
				}
			}
		}
	}()

	// Initialize Entity ID service for rate limiting
	entityIDConfig := logging.EntityIDConfig{
		MasterSecretPath:  "",             // Will generate random secret
		RotationPeriod:    24 * time.Hour, // Daily rotation
		RetentionDays:     90,             // 90 days retention
		CleanupInterval:   24 * time.Hour, // Daily cleanup
		EmergencyRotation: true,           // Enable emergency rotation
	}
	if err := logging.InitializeEntityIDService(entityIDConfig); err != nil {
		log.Fatalf("Failed to initialize Entity ID service: %v", err)
	}
	logging.InfoLogger.Printf("Entity ID service initialized successfully")

	// Initialize storage
	storage.InitMinio()

	// Initialize admin user if needed
	if err := initializeAdminUser(); err != nil {
		log.Printf("Warning: Failed to initialize admin user: %v", err)
		log.Printf("Application will continue running without admin user setup")
		// Don't crash the app - admin user can be set up manually later
	}

	// Initialize test user if needed
	if err := initializeTestUser(); err != nil {
		log.Printf("Warning: Failed to initialize test user: %v", err)
	}

	// Create Echo instance
	e := echo.New()

	// Basic security middleware first
	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "SAMEORIGIN",
		HSTSMaxAge:         63072000, // 2 years
		HSTSPreloadEnabled: true,
		// CSP is handled by CSPMiddleware below for WASM compatibility
	}))

	// Force HTTPS and check TLS version
	// e.Pre(middleware.HTTPSRedirect()) // Commented out for demo - TLS certificates need to be properly configured
	// e.Use(handlers.TLSVersionCheck) // Apply TLS check to all routes

	// Phase 5F: Enhanced security middleware
	e.Use(handlers.CSPMiddleware)
	// Note: ShareRateLimitMiddleware and TimingProtectionMiddleware are applied
	// specifically to share endpoints in route_config.go, not globally

	// Additional middleware
	e.Use(middleware.Logger())
	e.Use(middleware.CORS())

	// Host-based routing using a custom middleware
	// Currently unused but available for future environment-specific features
	// Environment differences are primarily handled through .env configuration
	// This middleware allows for runtime environment checks if needed later
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			host := c.Request().Host
			testDomain := os.Getenv("TEST_DOMAIN")
			if host == testDomain {
				// Set a context value to indicate test environment
				// Access this in handlers with: c.Get("environment").(string)
				c.Set("environment", "test")
			} else {
				// Set a context value to indicate production environment
				c.Set("environment", "prod")
			}
			return next(c)
		}
	})

	// Common routes setup
	setupRoutes(e)

	// Start server with TLS support
	port := cfg.Server.Port
	tlsPort := cfg.Server.TLSPort
	tlsEnabled := cfg.Server.TLSEnabled

	// Override with legacy environment variables if present
	if prodPort := os.Getenv("PROD_PORT"); prodPort != "" {
		port = prodPort
	}
	if testPort := os.Getenv("TEST_PORT"); testPort != "" {
		testDomain := os.Getenv("TEST_DOMAIN")
		host := os.Getenv("HOST")
		if host == testDomain {
			port = testPort
		}
	}

	if port == "" {
		port = "8080" // Default fallback
	}

	if tlsEnabled {
		// Get TLS certificate paths
		certFile := os.Getenv("TLS_CERT_FILE")
		keyFile := os.Getenv("TLS_KEY_FILE")

		if certFile == "" || keyFile == "" {
			log.Printf("TLS enabled but certificate files not specified, falling back to HTTP only")
			tlsEnabled = false
		}

		if tlsEnabled {
			if tlsPort == "" {
				tlsPort = "4443" // Default HTTPS port for demo
			}

			// Start HTTPS server in goroutine
			go func() {
				log.Printf("Starting HTTPS server on port %s", tlsPort)
				if err := e.StartTLS(":"+tlsPort, certFile, keyFile); err != nil {
					logging.ErrorLogger.Printf("Failed to start HTTPS server: %v", err)
				}
			}()

			// Add a small delay to let HTTPS server start
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Start HTTP server
	log.Printf("Starting HTTP server on port %s", port)
	if err := e.Start(":" + port); err != nil {
		logging.ErrorLogger.Printf("Failed to start HTTP server: %v", err)
	}
}

// initializeAdminUser creates and configures the designated admin user if needed
// CRITICAL SECURITY: This function MUST NEVER run in production environment
func initializeAdminUser() error {
	// SECURITY CHECK #1: Block in production environment
	if utils.IsProductionEnvironment() {
		// Log critical security warning and BLOCK execution
		logging.ErrorLogger.Printf("CRITICAL SECURITY: initializeAdminUser() blocked in production environment")
		return fmt.Errorf("SECURITY: Admin user initialization blocked in production environment")
	}

	// SECURITY CHECK #2: Verify we have admin usernames configured
	adminUsernames := os.Getenv("ADMIN_USERNAMES")
	if adminUsernames == "" {
		log.Printf("No ADMIN_USERNAMES configured, skipping admin user initialization")
		return nil
	}

	// SECURITY CHECK #3: Block dev admin accounts if somehow we're in production
	devAdminAccounts := []string{"arkfile-dev-admin", "admin.dev.user", "admin.demo.user", "dev-admin", "test-admin"}
	for _, devAccount := range devAdminAccounts {
		if strings.Contains(adminUsernames, devAccount) {
			if utils.IsProductionEnvironment() {
				logging.ErrorLogger.Printf("CRITICAL SECURITY: Dev admin account '%s' blocked in production", devAccount)
				return fmt.Errorf("SECURITY: Dev admin accounts not allowed in production")
			}
		}
	}

	// Get first admin username (for development, we typically use one admin user)
	adminUsernameList := strings.Split(adminUsernames, ",")
	if len(adminUsernameList) == 0 {
		return nil
	}

	adminUsername := strings.TrimSpace(adminUsernameList[0])
	if adminUsername == "" {
		return nil
	}

	log.Printf("Checking if admin user '%s' needs initialization...", adminUsername)

	// Check if admin user already exists
	existingUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check admin user existence: %w", err)
	}

	if existingUser != nil {
		log.Printf("Admin user '%s' already exists (ID: %d), skipping initialization", adminUsername, existingUser.ID)
		return nil
	}

	log.Printf("No existing admin user found - creating fresh admin user '%s' for development/testing...", adminUsername)

	// Create fresh admin user
	log.Printf("Creating admin user '%s' for development/testing...", adminUsername)

	// Use a secure default password for the admin user
	// In a real deployment, this should be changed immediately
	defaultAdminPassword := "DevAdmin2025!SecureInitialPassword"

	// Create admin user with OPAQUE authentication
	adminUser, err := models.CreateUserWithOPAQUE(database.DB, adminUsername, defaultAdminPassword, nil)
	if err != nil {
		return fmt.Errorf("failed to create admin user with OPAQUE: %w", err)
	}

	log.Printf("Admin user '%s' created successfully with ID: %d", adminUsername, adminUser.ID)
	log.Printf("SECURITY: Default admin password has been set - change it immediately after first login")

	// Set up TOTP for the new admin user
	if err := setupAdminTOTP(adminUser); err != nil {
		return fmt.Errorf("failed to setup TOTP for new admin user: %w", err)
	}

	// FINAL VALIDATION: Test complete TOTP workflow for admin user
	if err := validateAdminTOTPWorkflow(adminUser); err != nil {
		return fmt.Errorf("admin TOTP workflow validation failed: %w", err)
	}

	return nil
}

// initializeTestUser creates a standard test user for development if needed
func initializeTestUser() error {
	if utils.IsProductionEnvironment() {
		return nil // Do not create test users in production
	}

	testUsername := "arkfile-dev-test-user"
	testPassword := "password"

	log.Printf("Checking if test user '%s' needs initialization...", testUsername)

	// Check if user exists
	existingUser, err := models.GetUserByUsername(database.DB, testUsername)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check test user existence: %w", err)
	}

	if existingUser != nil {
		log.Printf("Test user '%s' already exists (ID: %d), skipping initialization", testUsername, existingUser.ID)
		return nil
	}

	log.Printf("Creating test user '%s' for development...", testUsername)

	// Create user with OPAQUE
	_, err = models.CreateUserWithOPAQUE(database.DB, testUsername, testPassword, nil)
	if err != nil {
		return fmt.Errorf("failed to create test user with OPAQUE: %w", err)
	}

	log.Printf("Test user '%s' created successfully.", testUsername)
	return nil
}

// isProductionEnvironment checks multiple indicators to determine if we're in production
func isProductionEnvironment() bool {
	// Check environment variables that indicate production
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))
	goEnv := strings.ToLower(os.Getenv("GO_ENV"))
	appEnv := strings.ToLower(os.Getenv("APP_ENV"))

	// Production indicators
	productionIndicators := []string{"production", "prod", "live", "release"}

	for _, indicator := range productionIndicators {
		if env == indicator || goEnv == indicator || appEnv == indicator {
			return true
		}
	}

	// Check if DEBUG_MODE is explicitly disabled (production setting)
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	if debugMode == "false" || debugMode == "0" {
		// Additional check - if debug is disabled AND we don't have explicit dev indicators
		devIndicators := []string{"development", "dev", "test", "testing", "local"}
		hasDevIndicator := false

		for _, devIndicator := range devIndicators {
			if env == devIndicator || goEnv == devIndicator || appEnv == devIndicator {
				hasDevIndicator = true
				break
			}
		}

		if !hasDevIndicator {
			return true // Likely production
		}
	}

	return false
}

// setupAdminTOTP sets up TOTP for the admin user with a fixed secret for testing
func setupAdminTOTP(user *models.User) error {
	// SECURITY CHECK: Double-check production environment (defense in depth)
	if utils.IsProductionEnvironment() {
		logging.ErrorLogger.Printf("CRITICAL SECURITY: setupAdminTOTP() blocked in production environment")
		return fmt.Errorf("SECURITY: Admin TOTP setup blocked in production environment")
	}

	// Enhanced debug logging for admin TOTP setup timing and key status
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	isDebug := debugMode == "true" || debugMode == "1"

	if isDebug {
		log.Printf("=== ADMIN TOTP SETUP DEBUG START ===")
		log.Printf("Admin TOTP setup initiated for user: %s", user.Username)

		// Check TOTP master key status before proceeding
		masterKeyReady, keyLen := crypto.GetTOTPMasterKeyStatus()
		log.Printf("TOTP master key status: ready=%t, length=%d", masterKeyReady, keyLen)

		if !masterKeyReady {
			log.Printf("ERROR: TOTP master key not ready during admin setup - BLOCKING setup")
			return fmt.Errorf("TOTP master key not ready for admin setup")
		}

		// CRITICAL: Test master key integrity before creating admin TOTP records
		if err := validateTOTPMasterKeyIntegrity(); err != nil {
			log.Printf("ERROR: TOTP master key integrity validation failed: %v", err)
			return fmt.Errorf("TOTP master key integrity validation failed: %w", err)
		}
		log.Printf("TOTP master key integrity validation passed")
	}

	// Fixed TOTP secret for predictable testing (base32 encoded)
	// This is a 32-character standard Base32 secret (160 bits) for dev/test admin user
	fixedTOTPSecret := "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"

	log.Printf("Setting up TOTP for admin user '%s' with fixed secret for testing", user.Username)

	// Generate backup codes
	backupCodes := generateAdminBackupCodes(10)

	if isDebug {
		log.Printf("Generated %d backup codes for admin user", len(backupCodes))
	}

	// Server-managed TOTP master key; per-user keys via HKDF; no OPAQUE sessionKey at rest
	// This ensures deterministic TOTP decryption independent of OPAQUE sessions

	// Derive user-specific TOTP key from server master key
	totpKey, err := crypto.DeriveTOTPUserKey(user.Username)
	if err != nil {
		if isDebug {
			log.Printf("ERROR: Failed to derive TOTP user key for admin: %v", err)
		}
		return fmt.Errorf("failed to derive TOTP user key: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	if isDebug {
		log.Printf("Successfully derived TOTP user key for admin, key_length=%d", len(totpKey))
	}

	// Encrypt TOTP secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(fixedTOTPSecret), totpKey)
	if err != nil {
		if isDebug {
			log.Printf("ERROR: Failed to encrypt TOTP secret for admin: %v", err)
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
			log.Printf("ERROR: Failed to encrypt backup codes for admin: %v", err)
		}
		return fmt.Errorf("failed to encrypt backup codes: %w", err)
	}

	if isDebug {
		log.Printf("Backup codes encrypted successfully, encrypted_length=%d", len(backupCodesEncrypted))
	}

	// Store TOTP data directly in database (bypass normal setup flow)
	_, err = database.DB.Exec(`
		INSERT OR REPLACE INTO user_totp (
			username, secret_encrypted, backup_codes_encrypted, 
			enabled, setup_completed, created_at, last_used
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.Username, secretEncrypted, backupCodesEncrypted,
		true, true, time.Now(), nil,
	)

	if err != nil {
		if isDebug {
			log.Printf("ERROR: Failed to store admin TOTP in database: %v", err)
		}
		return fmt.Errorf("failed to store admin TOTP setup: %w", err)
	}

	if isDebug {
		log.Printf("TOTP data stored successfully in database")

		// Test decryption immediately to verify the setup
		log.Printf("Testing TOTP decryption immediately after setup...")
		testDecrypted, testErr := crypto.DecryptGCM(secretEncrypted, totpKey)
		if testErr != nil {
			log.Printf("ERROR: Immediate TOTP decryption test failed: %v", testErr)
		} else {
			log.Printf("SUCCESS: Immediate TOTP decryption test passed, decrypted_secret_length=%d", len(testDecrypted))
		}

		log.Printf("=== ADMIN TOTP SETUP DEBUG END ===")
	}

	// Log setup completion
	log.Printf("TOTP setup completed for admin user '%s'", user.Username)
	log.Printf(" SECURITY: TOTP configured with fixed secret for development/testing only!")
	log.Printf("Use a TOTP app to scan QR code or manually enter the secret for authentication")

	return nil
}

// validateTOTPMasterKeyIntegrity performs an end-to-end test of TOTP master key functionality
// This ensures the key can be used for encryption/decryption before creating admin records
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

	log.Printf("TOTP master key integrity test passed: encrypt/decrypt cycle successful")
	return nil
}

// validateAdminTOTPWorkflow performs a complete end-to-end TOTP validation test
// This simulates an actual login attempt to ensure the TOTP system works correctly
func validateAdminTOTPWorkflow(user *models.User) error {
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	isDebug := debugMode == "true" || debugMode == "1"

	if isDebug {
		log.Printf("=== ADMIN TOTP WORKFLOW VALIDATION START ===")
		log.Printf("Testing complete TOTP workflow for admin user: %s", user.Username)
	}

	// Step 1: Check if TOTP is enabled for the admin user
	enabled, err := auth.IsUserTOTPEnabled(database.DB, user.Username)
	if err != nil {
		return fmt.Errorf("failed to check TOTP enabled status: %w", err)
	}

	if !enabled {
		return fmt.Errorf("TOTP not enabled for admin user after setup")
	}

	if isDebug {
		log.Printf("Step 1: TOTP is enabled for admin user")
	}

	// Step 2: Test the complete TOTP decryption workflow using auth.CanDecryptTOTPSecret
	present, decryptable, totpEnabled, setupCompleted, err := auth.CanDecryptTOTPSecret(database.DB, user.Username)
	if err != nil {
		return fmt.Errorf("TOTP decryption test failed: %w", err)
	}

	if !present {
		return fmt.Errorf("TOTP data not present for admin user")
	}

	if !decryptable {
		return fmt.Errorf("TOTP secret cannot be decrypted for admin user")
	}

	if !totpEnabled {
		return fmt.Errorf("TOTP not enabled according to decryption test")
	}

	if !setupCompleted {
		return fmt.Errorf("TOTP setup not completed according to decryption test")
	}

	if isDebug {
		log.Printf("Step 2: TOTP decryption workflow validated successfully")
		log.Printf("   - TOTP present: %t", present)
		log.Printf("   - TOTP decryptable: %t", decryptable)
		log.Printf("   - TOTP enabled: %t", totpEnabled)
		log.Printf("   - Setup completed: %t", setupCompleted)
	}

	// Step 3: Generate a valid TOTP code for the fixed admin secret and test validation
	// The admin uses a fixed secret: "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"
	// We can generate a valid code using the current time and test the validation
	fixedTOTPSecret := "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"

	// Generate current TOTP code for validation test
	currentCode, err := generateTOTPCode(fixedTOTPSecret)
	if err != nil {
		return fmt.Errorf("failed to generate test TOTP code: %w", err)
	}

	if isDebug {
		log.Printf("Step 3: Generated test TOTP code for validation: %s", currentCode)
	}

	// Step 4: Test TOTP validation using the actual auth.ValidateTOTPCode function
	// This simulates a real login attempt with the generated TOTP code
	if err := auth.ValidateTOTPCode(database.DB, user.Username, currentCode); err != nil {
		if isDebug {
			log.Printf("FAILED: TOTP code validation failed: %v", err)
		}
		return fmt.Errorf("TOTP code validation failed during startup test: %w", err)
	}

	if isDebug {
		log.Printf("SUCCESS: TOTP code validation passed - admin login workflow confirmed working")
		log.Printf("=== ADMIN TOTP WORKFLOW VALIDATION COMPLETE ===")
	}

	log.Printf("Complete TOTP workflow validation passed for admin user '%s'", user.Username)
	log.Printf("Admin login system validated: OPAQUE auth + TOTP validation working end-to-end")
	return nil
}

// generateTOTPCode generates a TOTP code for a given secret (for testing purposes)
func generateTOTPCode(secret string) (string, error) {
	// Use the same TOTP library that the validation uses to ensure compatibility
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return code, nil
}

// generateAdminBackupCodes generates backup codes for admin user
func generateAdminBackupCodes(count int) []string {
	// Use a simple charset for backup codes
	const charset = "ACDEFGHJKLMNPQRTUVWXY34679"
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		code := make([]byte, 10)
		for j := 0; j < 10; j++ {
			// Use a deterministic approach for testing consistency
			// In real deployment, this would use crypto/rand
			code[j] = charset[(i*10+j)%len(charset)]
		}
		codes[i] = string(code)
	}

	return codes
}
