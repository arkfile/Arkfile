package main

import (
    "log"
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
    // Serve static files for the web client
    e.Static("/", "client/static")

    // Serve WebAssembly files
    e.File("/wasm_exec.js", "client/wasm_exec.js")
    e.File("/main.wasm", "client/main.wasm")

    // Auth routes
    e.POST("/register", handlers.Register)
    e.POST("/login", handlers.Login)

    // File routes (protected)
    fileGroup := e.Group("/api")
    fileGroup.Use(auth.JWTMiddleware())
    fileGroup.POST("/upload", handlers.UploadFile)
    fileGroup.GET("/download/:filename", handlers.DownloadFile)
}

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Fatal("Error loading .env file")
    }

    // Initialize logging
    loggingConfig := &logging.LogConfig{
        LogDir:        "logs",
        MaxSize:       10 * 1024 * 1024,  // 10MB
        MaxBackups:    5,
        LogLevel:      logging.INFO,
    }
    logging.InitLogging(loggingConfig)

    // Initialize database
    database.InitDB()
    defer database.DB.Close()

    // Initialize storage
    storage.InitMinio()

    // Create Echo instance
    e := echo.New()

    // Middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    e.Use(middleware.CORS())
    e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
        XSSProtection:            "1; mode=block",
        ContentTypeNosniff:       "nosniff",
        XFrameOptions:            "SAMEORIGIN",
        HSTSMaxAge:               31536000,
        ContentSecurityPolicy:    "default-src 'self'",
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

    // Start server
    port := os.Getenv("PROD_PORT")
    testDomain := os.Getenv("TEST_DOMAIN")
    host := os.Getenv("HOST")

    if host == testDomain {
        port = os.Getenv("TEST_PORT")
    }

    if port == "" {
        port = "8080"  // Default fallback
    }

    if err := e.Start(":" + port); err != nil {
        logging.ErrorLogger.Printf("Failed to start server: %v", err)
    }
}
