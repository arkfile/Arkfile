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

func setupRoutes(g *echo.Group) {
    // Auth routes
    g.POST("/register", handlers.Register)
    g.POST("/login", handlers.Login)

    // File routes (protected)
    fileGroup := g.Group("/api")
    fileGroup.Use(auth.JWTMiddleware())
    fileGroup.POST("/upload", handlers.UploadFile)
    fileGroup.GET("/download/:filename", handlers.DownloadFile)

    // Static and WASM files
    g.Static("/", "client/static")
    g.File("/wasm_exec.js", "client/wasm_exec.js")
    g.File("/main.wasm", "client/main.wasm")
}

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Fatal("Error loading .env file")
    }

    // Initialize logging
    logging.InitLogging()

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
        XSSProtection:         "1; mode=block",
        ContentTypeNosniff:    "nosniff",
        XFrameOptions:         "SAMEORIGIN",
        HSTSMaxAge:            31536000,
        ContentSecurityPolicy: "default-src 'self'",
    }))

    // Production routes
    prod := e.Group("", middleware.HostWithConfig(middleware.HostConfig{
        Host: os.Getenv("PROD_DOMAIN"),
    }))
    setupRoutes(prod)

    // Test routes
    test := e.Group("", middleware.HostWithConfig(middleware.HostConfig{
        Host: os.Getenv("TEST_DOMAIN"),
    }))
    setupRoutes(test)

    // Get port based on domain
    port := os.Getenv("PROD_PORT")
    testDomain := os.Getenv("TEST_DOMAIN")
    host := os.Getenv("HOST")
    if host == testDomain {
       port = os.Getenv("TEST_PORT")
    }
    if port == "" {
       port = "8080" // Default fallback
    }

    // Start server
    if err := e.Start(":" + port); err != nil {
        logging.ErrorLogger.Printf("Failed to start server: %v", err)
    }
}
