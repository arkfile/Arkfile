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

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/config"
	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/handlers"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
	"github.com/84adam/arkfile/utils"
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

	// Serve WebAssembly files
	e.File("/wasm_exec.js", "client/wasm_exec.js")
	e.File("/main.wasm", "client/main.wasm")
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

	log.Printf("Configuration loaded successfully")
	_ = cfg // Use the config variable to prevent unused variable warning

	// Initialize logging with error handling
	loggingConfig := &logging.LogConfig{
		LogDir:     "/opt/arkfile/var/log", // Use absolute path for production deployment
		MaxSize:    10 * 1024 * 1024,       // 10MB
		MaxBackups: 5,
		LogLevel:   logging.INFO,
	}
	if err := logging.InitLogging(loggingConfig); err != nil {
		log.Printf("Warning: Failed to initialize file logging, using console only: %v", err)
		// Initialize fallback console loggers to prevent nil pointer panics
		logging.InitFallbackConsoleLogging()
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

	// Fixed TOTP secret for predictable testing (base32 encoded)
	// This is "Hello!" encoded in base32 - easy to remember and generates predictable codes
	fixedTOTPSecret := "JBSWY3DPEHPK3PXP"

	log.Printf("Setting up TOTP for admin user '%s' with fixed secret for testing", user.Username)

	// Generate backup codes
	backupCodes := generateAdminBackupCodes(10)

	// Use server-side TOTP key management
	// This decouples TOTP from OPAQUE sessions for better reliability

	// Derive user-specific TOTP key from server master key
	totpKey, err := crypto.DeriveTOTPUserKey(user.Username)
	if err != nil {
		return fmt.Errorf("failed to derive TOTP user key: %w", err)
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Encrypt TOTP secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(fixedTOTPSecret), totpKey)
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
		return fmt.Errorf("failed to store admin TOTP setup: %w", err)
	}

	// Log setup completion
	log.Printf("✅ TOTP setup completed for admin user '%s'", user.Username)
	log.Printf("⚠️  SECURITY: TOTP configured with fixed secret for development/testing only!")
	log.Printf("� Use a TOTP app to scan QR code or manually enter the secret for authentication")

	return nil
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

// formatTOTPManualEntry formats TOTP secret for manual entry
func formatTOTPManualEntry(secret string) string {
	formatted := ""
	for i, char := range secret {
		if i > 0 && i%4 == 0 {
			formatted += " "
		}
		formatted += string(char)
	}
	return formatted
}
