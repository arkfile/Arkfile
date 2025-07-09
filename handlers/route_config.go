package handlers

import (
	"github.com/84adam/arkfile/auth"
	"github.com/labstack/echo/v4"
)

// RegisterRoutes initializes all routes for the application
func RegisterRoutes() {
	// Explicitly serve index.html at root
	Echo.GET("/", func(c echo.Context) error {
		return c.File("static/index.html")
	})

	// Static files
	Echo.Static("/", "static")

	// OPAQUE Authentication (Only)
	Echo.POST("/api/opaque/register", OpaqueRegister)
	Echo.POST("/api/opaque/login", OpaqueLogin)
	Echo.POST("/api/opaque/capability", DetectDeviceCapability)
	Echo.GET("/api/opaque/health", OpaqueHealthCheck)

	// TOTP Authentication - requires authentication
	auth.Echo.POST("/api/totp/setup", TOTPSetup)
	auth.Echo.POST("/api/totp/verify", TOTPVerify)
	auth.Echo.GET("/api/totp/status", TOTPStatus)
	auth.Echo.POST("/api/totp/disable", TOTPDisable)

	// TOTP Authentication completion - requires temporary TOTP token
	totpGroup := Echo.Group("/api/totp")
	totpGroup.Use(auth.TOTPJWTMiddleware())
	totpGroup.POST("/auth", TOTPAuth)

	// Admin contacts (public - no auth required)
	Echo.GET("/api/admin-contacts", AdminContactsHandler)

	// Session management (OPAQUE sessions)
	Echo.POST("/api/refresh", RefreshToken)
	Echo.POST("/api/logout", Logout)
	auth.Echo.POST("/api/revoke-token", RevokeToken)
	auth.Echo.POST("/api/revoke-all", RevokeAllTokens)

	// Files - require authentication
	auth.Echo.GET("/api/files", ListFiles)
	auth.Echo.POST("/api/upload", UploadFile)
	auth.Echo.GET("/api/download/:filename", DownloadFile)
	auth.Echo.DELETE("/api/files/:filename", DeleteFile)

	// Chunked uploads
	auth.Echo.POST("/api/uploads/init", CreateUploadSession)
	auth.Echo.POST("/api/uploads/:sessionId/chunks/:chunkNumber", UploadChunk)
	auth.Echo.POST("/api/uploads/:sessionId/complete", CompleteUpload)
	auth.Echo.GET("/api/uploads/:sessionId/status", GetUploadStatus)
	auth.Echo.DELETE("/api/uploads/:sessionId", CancelUpload)

	// Share file
	auth.Echo.POST("/api/share", ShareFile) // Create a share link (changed from CreateShareLink)
	auth.Echo.GET("/api/user/shares", ListShares)
	auth.Echo.DELETE("/api/share/:id", DeleteShare)

	// Access shared file
	Echo.GET("/shared/:id", GetSharedFile)
	Echo.POST("/shared/:id/auth", AuthenticateShare)
	Echo.GET("/shared/:id/download", DownloadSharedFile)
	// API endpoint for accessing shared file
	Echo.GET("/api/shared/:shareId", GetSharedFileByShareID)
	// Additional API endpoints for shared.html
	Echo.POST("/api/shared/:shareId/auth", AuthenticateShare)
	Echo.GET("/api/shared/:shareId/download", DownloadSharedFile)

	// File encryption key management
	auth.Echo.POST("/api/files/:filename/update-encryption", UpdateEncryption)
	auth.Echo.GET("/api/files/:filename/keys", ListKeys)
	auth.Echo.DELETE("/api/files/:filename/keys/:keyId", DeleteKey)
	auth.Echo.PATCH("/api/files/:filename/keys/:keyId", UpdateKey)
	auth.Echo.POST("/api/files/:filename/keys/:keyId/set-primary", SetPrimaryKey)

	// User management (admin only)
	auth.Echo.GET("/api/admin/users", ListUsers)
	auth.Echo.PATCH("/api/admin/users/:email", UpdateUser)
	auth.Echo.DELETE("/api/admin/users/:email", DeleteUser)

	// System statistics (admin only)
	auth.Echo.GET("/api/admin/stats", GetSystemStats)
	auth.Echo.GET("/api/admin/activity", GetActivityLogs)
}
