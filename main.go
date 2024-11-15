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
        HSTSMaxAge:           31536000,
        ContentSecurityPolicy: "default-src 'self'",
    }))

    // Serve static files for the web client
    e.Static("/", "client/static")

    // Serve WebAssembly files
    e.File("/wasm_exec.js", "client/wasm_exec.js")
    e.File("/main.wasm", "client/main.wasm")

    // Routes
    // Auth routes
    e.POST("/register", handlers.Register)
    e.POST("/login", handlers.Login)

    // File routes (protected)
    fileGroup := e.Group("/api")
    fileGroup.Use(auth.JWTMiddleware())
    fileGroup.POST("/upload", handlers.UploadFile)
    fileGroup.GET("/download/:filename", handlers.DownloadFile)

    // Start server
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    if err := e.Start(":" + port); err != nil {
        logging.ErrorLogger.Printf("Failed to start server: %v", err)
    }
}
