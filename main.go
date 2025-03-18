package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/84adam/arkfile/auth"
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
	auth.Echo.Use(handlers.RequireApproved)
	
	// Register all routes
	handlers.RegisterRoutes()
	
	// Serve WebAssembly files
	e.File("/wasm_exec.js", "client/wasm_exec.js")
	e.File("/main.wasm", "client/main.wasm")
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize logging
	loggingConfig := &logging.LogConfig{
		LogDir:     "logs",
		MaxSize:    10 * 1024 * 1024, // 10MB
		MaxBackups: 5,
		LogLevel:   logging.INFO,
	}
	logging.InitLogging(loggingConfig)

	// Initialize database
	database.InitDB()
	defer database.DB.Close()

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
		ContentSecurityPolicy: "default-src 'self'",
	}))

	// Force HTTPS and check TLS version
	e.Pre(middleware.HTTPSRedirect())
	e.Use(handlers.TLSVersionCheck) // Apply TLS check to all routes

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

	// Start server
	port := os.Getenv("PROD_PORT")
	testDomain := os.Getenv("TEST_DOMAIN")
	host := os.Getenv("HOST")

	if host == testDomain {
		port = os.Getenv("TEST_PORT")
	}

	if port == "" {
		port = "8080" // Default fallback
	}

	if err := e.Start(":" + port); err != nil {
		logging.ErrorLogger.Printf("Failed to start server: %v", err)
	}
}
