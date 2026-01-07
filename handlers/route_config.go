package handlers

import (
	"os"
	"strings"

	"github.com/84adam/Arkfile/auth"
	"github.com/labstack/echo/v4"
)

// Import other handler packages for routing
// This allows routing to use functions from the separated handlers

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
	Echo.Static("/errors", "client/static/errors")

	// Individual static files needed by frontend with HEAD support
	Echo.File("/favicon.ico", "client/static/favicon.ico")
	Echo.HEAD("/favicon.ico", func(c echo.Context) error {
		return c.File("client/static/favicon.ico")
	})

	// Configuration endpoints (public - needed for client-side crypto)
	Echo.GET("/api/config/argon2", GetArgon2Config)
	Echo.GET("/api/config/password-requirements", GetPasswordRequirements)

	// OPAQUE Authentication (Multi-Step Protocol) - with rate limiting protection
	Echo.POST("/api/opaque/register/response", RegisterRateLimitMiddleware(OpaqueRegisterResponse))
	Echo.POST("/api/opaque/register/finalize", RegisterRateLimitMiddleware(OpaqueRegisterFinalize))
	Echo.POST("/api/opaque/login/response", LoginRateLimitMiddleware(OpaqueAuthResponse))
	Echo.POST("/api/opaque/login/finalize", LoginRateLimitMiddleware(OpaqueAuthFinalize))
	Echo.GET("/api/opaque/health", OpaqueHealthCheck)

	// Admin OPAQUE Authentication (Multi-Step Protocol) - separate endpoints with admin verification
	Echo.POST("/api/admin/login/response", LoginRateLimitMiddleware(AdminOpaqueAuthResponse))
	Echo.POST("/api/admin/login/finalize", LoginRateLimitMiddleware(AdminOpaqueAuthFinalize))

	// Bootstrap Registration (OPAQUE) - Initial Admin Setup
	Echo.POST("/api/bootstrap/register/response", RegisterRateLimitMiddleware(BootstrapRegisterResponse))
	Echo.POST("/api/bootstrap/register/finalize", RegisterRateLimitMiddleware(BootstrapRegisterFinalize))

	// TOTP Authentication - requires authentication with rate limiting protection
	auth.Echo.POST("/api/totp/setup", TOTPSetup)
	auth.Echo.POST("/api/totp/verify", TOTPRateLimitMiddleware("totp_verify")(TOTPVerify))
	auth.Echo.GET("/api/totp/status", TOTPStatus)
	auth.Echo.POST("/api/totp/reset", TOTPReset)

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
	totpProtectedGroup.POST("/api/revoke-all", RevokeAllRefreshTokens)

	// Files - require authentication AND TOTP

	totpProtectedGroup.GET("/api/files", ListFiles)
	totpProtectedGroup.POST("/api/upload", UploadFile)
	totpProtectedGroup.GET("/api/files/:fileId/meta", GetFileMeta)
	totpProtectedGroup.GET("/api/files/:fileId", DownloadFile)
	totpProtectedGroup.DELETE("/api/files/:fileId", DeleteFile)

	// Chunked uploads - require TOTP
	totpProtectedGroup.POST("/api/uploads/init", CreateUploadSession)
	totpProtectedGroup.POST("/api/uploads/:sessionId/chunks/:chunkNumber", UploadChunk)
	totpProtectedGroup.POST("/api/uploads/:sessionId/complete", CompleteUpload)
	totpProtectedGroup.GET("/api/uploads/:sessionId/status", GetUploadStatus)
	totpProtectedGroup.DELETE("/api/uploads/:fileId", CancelUpload)

	// File sharing - require TOTP for creation, anonymous access for usage
	totpProtectedGroup.GET("/api/files/:fileId/envelope", GetFileEnvelope) // Get file envelope for share creation
	totpProtectedGroup.POST("/api/files/:fileId/share", CreateFileShare)   // Create Argon2id-based anonymous share
	totpProtectedGroup.GET("/api/users/shares", ListShares)                // List user's shares
	totpProtectedGroup.DELETE("/api/share/:id", DeleteShare)               // Delete a share
	totpProtectedGroup.POST("/api/share/:id/revoke", RevokeShare)          // Revoke a share

	// Anonymous share access (no authentication required) - with rate limiting and timing protection
	shareGroup := Echo.Group("/api")
	shareGroup.Use(ShareRateLimitMiddleware)                   // Apply rate limiting FIRST (fail fast for abusers)
	shareGroup.Use(TimingProtectionMiddleware)                 // Then timing protection (for valid requests)
	shareGroup.GET("/shares/:id", GetSharedFile)               // Share access page
	shareGroup.GET("/shares/:id/envelope", GetShareEnvelope)   // Get share envelope for client-side decryption
	shareGroup.GET("/shares/:id/download", DownloadSharedFile) // Download shared file

	// File encryption key management - require TOTP
	totpProtectedGroup.POST("/api/files/:fileId/update-encryption", UpdateEncryption)
	totpProtectedGroup.GET("/api/files/:fileId/keys", ListKeys)
	totpProtectedGroup.DELETE("/api/files/:fileId/keys/:keyId", DeleteKey)
	totpProtectedGroup.PATCH("/api/files/:fileId/keys/:keyId", UpdateKey)
	totpProtectedGroup.POST("/api/files/:fileId/keys/:keyId/set-primary", SetPrimaryKey)
	totpProtectedGroup.POST("/api/files/:fileId/get-decryption-key", GetFileDecryptionKey) // To be refactored for Argon2ID based encryption key management

	// Credits system - user endpoints (require TOTP)
	totpProtectedGroup.GET("/api/credits", GetUserCredits)

	// Admin API endpoints - structured for future expansion
	// Production admin endpoints (require JWT authentication + admin privileges)
	adminGroup := Echo.Group("/api/admin")
	adminGroup.Use(auth.JWTMiddleware()) // Add JWT middleware first
	adminGroup.Use(AdminMiddleware)      // Then admin middleware

	// Credits system - admin endpoints (require admin privileges)
	adminGroup.GET("/credits", AdminGetAllCredits)
	adminGroup.GET("/credits/:username", AdminGetUserCredits)
	adminGroup.POST("/credits/:username", AdminAdjustCredits)
	adminGroup.PUT("/credits/:username", AdminSetCredits)

	// User management - admin endpoints (migrated from dev/test to production)
	adminGroup.POST("/users/:username/approve", AdminApproveUser)
	adminGroup.GET("/users/:username/status", AdminGetUserStatus)

	// System monitoring - admin endpoints (Phase 2: Bridge existing monitoring infrastructure)
	adminGroup.GET("/system/health", AdminSystemHealth)
	adminGroup.GET("/security/events", AdminSecurityEvents)

	// Future production admin endpoints will go here
	//          adminGroup.GET("/users/pending", AdminPendingUsers)

	// Development/Testing admin endpoints (gated by ADMIN_DEV_TEST_API_ENABLED)
	// SECURITY: These endpoints are ONLY for development and testing
	if isDevTestAdminAPIEnabled() {
		devTestAdminGroup := Echo.Group("/api/admin/dev-test")
		devTestAdminGroup.Use(auth.JWTMiddleware()) // Add JWT middleware first
		devTestAdminGroup.Use(AdminMiddleware)      // Then admin middleware
		devTestAdminGroup.POST("/users/cleanup", AdminCleanupTestUser)
		devTestAdminGroup.GET("/totp/decrypt-check/:username", AdminTOTPDecryptCheck) // TOTP diagnostic endpoint
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
