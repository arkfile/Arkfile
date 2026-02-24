package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

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
	// Liveness probe: is the process alive?
	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "alive",
		})
	})

	// Readiness probe: can we serve traffic? Checks all dependencies.
	e.GET("/readyz", func(c echo.Context) error {
		checks := map[string]string{}
		allReady := true

		// Check rqlite connectivity
		if err := database.DB.Ping(); err != nil {
			checks["rqlite"] = fmt.Sprintf("not ready: %v", err)
			allReady = false
		} else {
			checks["rqlite"] = "ok"
		}

		// Check storage connectivity
		if storage.Provider == nil {
			checks["storage"] = "not initialized"
			allReady = false
		} else {
			checks["storage"] = "ok"
		}

		checks["status"] = "ready"
		if !allReady {
			checks["status"] = "not ready"
			return c.JSON(http.StatusServiceUnavailable, checks)
		}
		return c.JSON(http.StatusOK, checks)
	})

	// Set the global Echo instance for handlers
	handlers.Echo = e

	// Set up auth Echo instance
	auth.Echo = e.Group("")
	auth.Echo.Use(auth.JWTMiddleware())
	auth.Echo.Use(auth.TokenRevocationMiddleware(database.DB))
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

	// Initialize KeyManager (required for all system secrets)
	if err := crypto.InitKeyManager(database.DB); err != nil {
		log.Fatalf("Failed to initialize KeyManager: %v", err)
	}

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

	// Verify OPAQUE is available
	if !auth.IsOPAQUEAvailable() {
		log.Fatalf("OPAQUE not available")
	}
	logging.InfoLogger.Printf("OPAQUE initialized successfully")

	// Start session cleanup goroutine
	go func() {
		// Perform initial cleanup on startup
		if err := auth.CleanupExpiredSessions(database.DB); err != nil {
			logging.ErrorLogger.Printf("Failed to perform initial session cleanup: %v", err)
		}

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := auth.CleanupExpiredSessions(database.DB); err != nil {
				logging.ErrorLogger.Printf("Failed to cleanup expired sessions: %v", err)
			}
		}
	}()

	// Start TOTP cleanup routine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := auth.CleanupTOTPLogs(database.DB); err != nil {
				logging.ErrorLogger.Printf("Failed to cleanup TOTP logs: %v", err)
			}
		}
	}()

	// Initialize Entity ID service for rate limiting
	entityIDConfig := logging.EntityIDConfig{
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
	if err := storage.InitS3(); err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Check for bootstrap condition (Zero Users)
	if err := auth.CheckAndGenerateBootstrapToken(database.DB); err != nil {
		log.Fatalf("Failed to check/generate bootstrap token: %v", err)
	}

	// Initialize admin user if needed (Dev/Test only)
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
		// CSP is handled by CSPMiddleware below
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
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     cfg.Server.AllowedOrigins,
		AllowMethods:     []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "X-Requested-With"},
		AllowCredentials: true,
		MaxAge:           300, // 5 minutes
	}))

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
				tlsPort = "8443" // Default HTTPS port for demo
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

	// Fixed dev admin credentials for testing
	const devAdminUsername = "arkfile-dev-admin"
	const devAdminPassword = "DevAdmin2025!SecureInitialPassword"
	const devAdminTOTPSecret = "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"

	// SECURITY CHECK #3: Only auto-create if arkfile-dev-admin is in ADMIN_USERNAMES
	if !strings.Contains(adminUsernames, devAdminUsername) {
		log.Printf("Dev admin username '%s' not in ADMIN_USERNAMES, skipping auto-creation", devAdminUsername)
		return nil
	}

	log.Printf("Checking if dev admin user '%s' needs initialization...", devAdminUsername)

	// Check if admin user already exists
	existingUser, err := models.GetUserByUsername(database.DB, devAdminUsername)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check admin user existence: %w", err)
	}

	if existingUser != nil {
		log.Printf("Dev admin user '%s' already exists (ID: %d), skipping initialization", devAdminUsername, existingUser.ID)
		return nil
	}

	// Create dev admin user with OPAQUE protocol
	log.Printf("Creating dev admin user with OPAQUE registration...")
	user, err := auth.CreateDevAdminWithOPAQUE(database.DB, devAdminUsername, devAdminPassword)
	if err != nil {
		return fmt.Errorf("failed to create dev admin user: %w", err)
	}

	log.Printf("Dev admin user created successfully: %s (ID: %d)", user.Username, user.ID)

	// Setup TOTP with fixed secret
	log.Printf("Setting up TOTP for dev admin user...")
	if err := auth.SetupDevAdminTOTP(database.DB, user, devAdminTOTPSecret); err != nil {
		return fmt.Errorf("failed to setup dev admin TOTP: %w", err)
	}

	log.Printf("Dev admin TOTP setup completed successfully")

	// Validate the complete TOTP workflow
	log.Printf("Validating dev admin TOTP workflow...")
	if err := auth.ValidateDevAdminTOTPWorkflow(database.DB, user, devAdminTOTPSecret); err != nil {
		log.Printf("Warning: Dev admin TOTP workflow validation failed: %v", err)
		// Don't fail - allow server to start even if validation fails
	} else {
		log.Printf("Dev admin TOTP workflow validation passed")
	}

	// NEW: Validate complete authentication flow (OPAQUE + TOTP)
	log.Printf("Validating complete dev admin authentication flow...")
	if err := auth.ValidateDevAdminAuthentication(database.DB, devAdminUsername, devAdminPassword, devAdminTOTPSecret); err != nil {
		log.Printf("CRITICAL: Dev admin authentication validation failed: %v", err)
		// This is critical - if authentication doesn't work, the system is broken
		return fmt.Errorf("dev admin authentication validation failed: %w", err)
	}

	log.Printf("SUCCESS: Full OPAQUE Auth + TOTP validation complete for '%s' user.", devAdminUsername)

	return nil
}
