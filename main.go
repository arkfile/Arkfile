package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/config"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/handlers"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/storage"
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
		// Log the error but don't fail - environment variables might be
		// provided by systemd or other means
		log.Printf("Warning: Could not load .env file: %v", err)
		log.Printf("Continuing with environment variables from system/systemd")
	}

	// Load configuration - this must happen after environment variables are loaded
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Printf("Configuration loaded successfully")
	_ = cfg // Use the config variable to prevent unused variable warning

	// Initialize logging with error handling
	loggingConfig := &logging.LogConfig{
		LogDir:     "var/log",        // Use the var/log directory that's properly set up
		MaxSize:    10 * 1024 * 1024, // 10MB
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

	// Initialize OPAQUE server keys
	if err := auth.SetupServerKeys(database.DB); err != nil {
		log.Fatalf("Failed to setup OPAQUE server keys: %v", err)
	}
	logging.InfoLogger.Printf("OPAQUE server keys initialized successfully")

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

	// Initialize storage
	storage.InitMinio()

	// Create Echo instance
	e := echo.New()

	// Basic security middleware first
	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            63072000, // 2 years
		HSTSPreloadEnabled:    true,
		ContentSecurityPolicy: "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
	}))

	// Force HTTPS and check TLS version
	// e.Pre(middleware.HTTPSRedirect()) // Commented out for demo - TLS certificates need to be properly configured
	// e.Use(handlers.TLSVersionCheck) // Apply TLS check to all routes

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
