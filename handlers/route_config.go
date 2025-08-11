package handlers

import (
	"os"
	"strings"

	"github.com/84adam/arkfile/auth"
	"github.com/labstack/echo/v4"
)

// RegisterRoutes initializes all routes for the application
func RegisterRoutes() {
	// Explicitly serve index.html at root with HEAD support
	Echo.GET("/", func(c echo.Context) error {
		return c.File("client/static/index.html")
	})
	Echo.HEAD("/", func(c echo.Context) error {
		return c.File("client/static/index.html")
	})

	// Static assets with HEAD support
	Echo.Static("/js/dist", "client/static/js/dist")
	Echo.Static("/css", "client/static/css")
	Echo.Static("/wasm", "client/static/wasm")
	Echo.Static("/errors", "client/static/errors")

	// Individual static files needed by frontend with HEAD support
	Echo.File("/wasm_exec.js", "client/wasm_exec.js")
	Echo.HEAD("/wasm_exec.js", func(c echo.Context) error {
		return c.File("client/wasm_exec.js")
	})
	Echo.File("/main.wasm", "client/main.wasm")
	Echo.HEAD("/main.wasm", func(c echo.Context) error {
		return c.File("client/main.wasm")
	})

	// OPAQUE Authentication (Only) - with rate limiting protection
	Echo.POST("/api/opaque/register", RegisterRateLimitMiddleware(OpaqueRegister))
	Echo.POST("/api/opaque/login", LoginRateLimitMiddleware(OpaqueLogin))
	Echo.GET("/api/opaque/health", OpaqueHealthCheck)

	// TOTP Authentication - requires authentication with rate limiting protection
	auth.Echo.POST("/api/totp/setup", TOTPSetup)
	auth.Echo.POST("/api/totp/verify", TOTPRateLimitMiddleware("totp_verify")(TOTPVerify))
	auth.Echo.GET("/api/totp/status", TOTPStatus)
	auth.Echo.POST("/api/totp/disable", TOTPDisable)

	// TOTP Authentication completion - requires temporary TOTP token with rate limiting
	totpGroup := Echo.Group("/api/totp")
	totpGroup.Use(auth.TOTPJWTMiddleware())
	totpGroup.POST("/auth", TOTPRateLimitMiddleware("totp_auth")(TOTPAuth))

	// Admin contacts (public - no auth required)
	Echo.GET("/api/admin-contacts", AdminContactsHandler)

	// Session management (OPAQUE sessions)
	Echo.POST("/api/refresh", RefreshToken)
	Echo.POST("/api/logout", Logout)

	// Create TOTP-protected group for all sensitive operations
	totpProtectedGroup := auth.Echo.Group("")
	totpProtectedGroup.Use(RequireTOTP)

	// Token revocation - require TOTP
	totpProtectedGroup.POST("/api/revoke-token", RevokeToken)
	totpProtectedGroup.POST("/api/revoke-all", RevokeAllTokens)

	// Files - require authentication AND TOTP

	totpProtectedGroup.GET("/api/files", ListFiles)
	totpProtectedGroup.POST("/api/upload", UploadFile)
	totpProtectedGroup.GET("/api/download/:filename", DownloadFile)
	totpProtectedGroup.DELETE("/api/files/:filename", DeleteFile)

	// Chunked uploads - require TOTP
	totpProtectedGroup.POST("/api/uploads/init", CreateUploadSession)
	totpProtectedGroup.POST("/api/uploads/:sessionId/chunks/:chunkNumber", UploadChunk)
	totpProtectedGroup.POST("/api/uploads/:sessionId/complete", CompleteUpload)
	totpProtectedGroup.GET("/api/uploads/:sessionId/status", GetUploadStatus)
	totpProtectedGroup.DELETE("/api/uploads/:sessionId", CancelUpload)

	// File sharing - require TOTP for creation, anonymous access for usage
	totpProtectedGroup.POST("/api/files/:fileId/share", CreateFileShare) // Create Argon2id-based anonymous share
	totpProtectedGroup.GET("/api/user/shares", ListShares)               // List user's shares
	totpProtectedGroup.DELETE("/api/share/:id", DeleteShare)             // Delete a share

	// Anonymous share access (no authentication required) - with rate limiting and timing protection
	shareGroup := Echo.Group("")
	shareGroup.Use(ShareRateLimitMiddleware)                       // Apply rate limiting FIRST (fail fast for abusers)
	shareGroup.Use(TimingProtectionMiddleware)                     // Then timing protection (for valid requests)
	shareGroup.GET("/shared/:id", GetSharedFile)                   // Share access page
	shareGroup.GET("/api/share/:id", GetShareInfo)                 // Get share metadata (no password required)
	shareGroup.GET("/api/shared/:id", GetShareInfo)                // Alternative route for frontend compatibility
	shareGroup.POST("/api/share/:id", AccessSharedFile)            // Anonymous share access with password
	shareGroup.POST("/api/shared/:id", AccessSharedFile)           // Alternative route for frontend compatibility
	shareGroup.GET("/api/share/:id/download", DownloadSharedFile)  // Download shared file
	shareGroup.GET("/api/shared/:id/download", DownloadSharedFile) // Alternative route for frontend compatibility

	// File encryption key management - require TOTP
	totpProtectedGroup.POST("/api/files/:filename/update-encryption", UpdateEncryption)
	totpProtectedGroup.GET("/api/files/:filename/keys", ListKeys)
	totpProtectedGroup.DELETE("/api/files/:filename/keys/:keyId", DeleteKey)
	totpProtectedGroup.PATCH("/api/files/:filename/keys/:keyId", UpdateKey)
	totpProtectedGroup.POST("/api/files/:filename/keys/:keyId/set-primary", SetPrimaryKey)

	// Admin API endpoints - structured for future expansion
	// Production admin endpoints (reserved for future legitimate admin operations)
	adminGroup := Echo.Group("/api/admin")
	adminGroup.Use(AdminMiddleware)
	// Future production admin endpoints will go here
	// Examples: adminGroup.GET("/system/health", AdminSystemHealth)
	//          adminGroup.GET("/users/pending", AdminPendingUsers)

	// Development/Testing admin endpoints (gated by ADMIN_DEV_TEST_API_ENABLED)
	// SECURITY: These endpoints are ONLY for development and testing
	if isDevTestAdminAPIEnabled() {
		devTestAdminGroup := Echo.Group("/api/admin/dev-test")
		devTestAdminGroup.Use(auth.JWTMiddleware()) // Add JWT middleware first
		devTestAdminGroup.Use(AdminMiddleware)      // Then admin middleware
		devTestAdminGroup.POST("/user/cleanup", AdminCleanupTestUser)
		devTestAdminGroup.POST("/user/:username/approve", AdminApproveUser)
		devTestAdminGroup.GET("/user/:username/status", AdminGetUserStatus)
	}

	// User management (admin only) - require TOTP (commented out until implemented)
	// totpProtectedGroup.GET("/api/admin/users", RequireAdmin(ListUsers))
	// totpProtectedGroup.PATCH("/api/admin/users/:username", RequireAdmin(UpdateUser))
	// totpProtectedGroup.DELETE("/api/admin/users/:username", RequireAdmin(DeleteUser))

	// System statistics (admin only) - require TOTP (commented out until implemented)
	// totpProtectedGroup.GET("/api/admin/stats", RequireAdmin(GetSystemStats))
	// totpProtectedGroup.GET("/api/admin/activity", RequireAdmin(GetActivityLogs))
}

// isDevTestAdminAPIEnabled checks if development/testing admin API endpoints should be enabled
// SECURITY: This MUST return false in production environments
func isDevTestAdminAPIEnabled() bool {
	// Check environment variable
	enabled := strings.ToLower(os.Getenv("ADMIN_DEV_TEST_API_ENABLED"))
	if enabled == "true" || enabled == "1" || enabled == "yes" {
		return true
	}

	// Default to false for security
	return false
}
