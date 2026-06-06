package handlers

import (
	"net/http"
	"os"
	"strings"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/labstack/echo/v4"
)

// RegisterRoutes initializes all routes for the application
func RegisterRoutes() {
	// CookieTokenMiddleware extracts the JWT from the session cookie (if present)
	// and injects it as an Authorization header so the JWT validators see it
	// regardless of whether the client is a browser or a non-browser caller.
	Echo.Use(CookieTokenMiddleware)

	// CSRFMiddleware enforces the double-submit cookie pattern for browser sessions.
	// Requests without an Arkfile session cookie are not affected.
	Echo.Use(CSRFMiddleware)

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

	// Serve libopaque.js for OPAQUE authentication
	Echo.File("/js/libopaque.js", "client/static/js/libopaque.js")

	// Serve shared-init.js for share page initialization (CSP-compliant external script)
	Echo.File("/js/shared-init.js", "client/static/js/shared-init.js")

	// Serve the streaming-download Service Worker at top-level so its default
	// scope covers '/'. The SW intercepts /sw-download/<uuid> requests from
	// pages and responds with a streaming Response carrying the decrypted
	// byte stream. See client/static/js/src/sw-download.ts.
	Echo.File("/sw-download.js", "client/static/js/sw-download.js")

	// Defense-in-depth: if the SW is not active for any reason, /sw-download/<uuid>
	// requests fall through to the server. Return 404 immediately so the page's
	// anchor click fails fast rather than being misinterpreted as a real route.
	Echo.GET("/sw-download/*", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusNotFound, "Service Worker not active")
	})

	// Individual static files needed by frontend with HEAD support
	Echo.File("/favicon.ico", "client/static/favicon.ico")
	Echo.HEAD("/favicon.ico", func(c echo.Context) error {
		return c.File("client/static/favicon.ico")
	})

	// Configuration endpoints (public - needed for client-side crypto)
	Echo.GET("/api/config/argon2", GetArgon2Config)
	Echo.GET("/api/config/password-requirements", GetPasswordRequirements)
	Echo.GET("/api/config/chunking", GetChunkingConfig)
	// OPAQUE server identity (idS); browser + CLI fetch this so all OPAQUE
	// participants bind the same server identity into the protocol transcript.
	Echo.GET("/api/config/opaque", GetOpaqueConfig)

	// Version endpoint (public)
	Echo.GET("/api/version", GetVersion)

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

	// TOTP Status and Reset - requires full authentication (standard JWT)
	auth.Echo.GET("/api/totp/status", TOTPStatus)
	auth.Echo.POST("/api/totp/reset", TOTPReset)

	// TOTP Setup/Verify/Auth - requires temporary TOTP token (arkfile-totp audience)
	totpGroup := Echo.Group("/api/totp")
	totpGroup.POST("/recover-with-backup-code", RecoverWithBackupCode) // public recovery trigger
	totpGroup.POST("/setup", TOTPSetup, auth.TOTPJWTMiddleware())
	totpGroup.POST("/verify", TOTPRateLimitMiddleware("totp_verify")(TOTPVerify), auth.TOTPJWTMiddleware())
	totpGroup.POST("/auth", TOTPRateLimitMiddleware("totp_auth")(TOTPAuth), auth.TOTPJWTMiddleware())

	// Admin contacts (public - no auth required)
	Echo.GET("/api/admin-contacts", AdminContactsHandler)

	// Session management (OPAQUE sessions)
	Echo.POST("/api/refresh", RefreshToken)
	// Logout requires authentication (A-33) to prevent remote DoS or session manipulation.
	// It is registered under auth.Echo which applies JWTMiddleware + TokenRevocationMiddleware.
	auth.Echo.POST("/api/logout", Logout)

	// Create TOTP-protected group for all sensitive operations.
	// Stack inherited from auth.Echo: JWTMiddleware + TokenRevocationMiddleware + RequireApproved.
	// Adds: RequireFullJWT (rejects requires_totp=true and audience drift) + RequireTOTP.
	totpProtectedGroup := auth.Echo.Group("")
	totpProtectedGroup.Use(auth.RequireFullJWT)
	totpProtectedGroup.Use(RequireTOTP)

	// Token revocation - require TOTP
	totpProtectedGroup.POST("/api/revoke-token", RevokeToken)
	totpProtectedGroup.POST("/api/auth/revoke-all", RevokeAllTokens)

	// Files - require authentication AND TOTP

	totpProtectedGroup.GET("/api/files", ListFiles)
	totpProtectedGroup.GET("/api/files/metadata", ListRecentFileMetadata)
	totpProtectedGroup.POST("/api/files/metadata/batch", GetFileMetadataBatch)
	totpProtectedGroup.GET("/api/files/:fileId/meta", GetFileMeta)
	totpProtectedGroup.DELETE("/api/files/:fileId", DeleteFile)

	// Chunked downloads - require TOTP
	totpProtectedGroup.GET("/api/files/:fileId/chunks/:chunkIndex", DownloadFileChunk)

	// Chunked uploads - require TOTP
	totpProtectedGroup.POST("/api/uploads/init", CreateUploadSession)
	totpProtectedGroup.POST("/api/uploads/:sessionId/chunks/:chunkNumber", UploadChunk)
	totpProtectedGroup.POST("/api/uploads/:sessionId/complete", CompleteUpload)
	totpProtectedGroup.GET("/api/uploads/:sessionId/status", GetUploadStatus)
	totpProtectedGroup.DELETE("/api/uploads/:sessionId", CancelUpload)

	// File sharing - authenticated endpoints (require TOTP)
	totpProtectedGroup.GET("/api/files/:fileId/envelope", GetFileEnvelope) // Get file envelope for share creation
	totpProtectedGroup.POST("/api/shares", CreateFileShare)                // Create anonymous share (file_id in body)
	totpProtectedGroup.GET("/api/shares", ListShares)                      // List user's shares
	totpProtectedGroup.POST("/api/shares/:id/revoke", RevokeShare)         // Revoke a share

	// Anonymous share access (no authentication required) - separate namespace with rate limiting
	// Using /api/public/shares to avoid conflicts with authenticated /api/shares routes
	publicShareGroup := Echo.Group("/api/public/shares")
	publicShareGroup.Use(ShareEnumerationMiddleware) // Entity-global enumeration protection FIRST
	publicShareGroup.Use(ShareRateLimitMiddleware)   // Then per-share-ID rate limiting (fail fast for abusers)
	publicShareGroup.Use(TimingProtectionMiddleware) // Then timing protection (for valid requests)
	publicShareGroup.GET("/:id", GetSharedFile)      // Share access page

	// Share page (serves shared.html for /shared/:id URLs - no authentication required).
	// To prevent URL enumeration sweeps and timing-attack mapping on this legacy path,
	// we protect it with the exact same middleware group (D-05).
	Echo.GET("/shared/:id", ShareEnumerationMiddleware(ShareRateLimitMiddleware(TimingProtectionMiddleware(GetSharedFile))))
	publicShareGroup.GET("/:id/envelope", GetShareEnvelope)             // Get share envelope for client-side decryption
	publicShareGroup.GET("/:id/metadata", GetShareDownloadMetadata)     // Get metadata for shared file download
	publicShareGroup.GET("/:id/chunks/:chunkIndex", DownloadShareChunk) // Download chunk of shared file

	// File export token - requires TOTP (creates short-lived download token)
	totpProtectedGroup.POST("/api/files/:fileId/export-token", CreateExportToken)

	// File export download - registered on public router because browser downloads
	// use ?token= query param (no Authorization header). The handler validates
	// auth internally via resolveExportAuth() which checks either JWT or token.
	Echo.GET("/api/files/:fileId/export", ExportFile)

	// Contact information - user endpoints.
	// These are intentionally NOT in totpProtectedGroup (which inherits RequireApproved)
	// so that pending users can set their contact info while awaiting approval.
	// Stack: JWT + TokenRevocation + RequireFullJWT + RequireTOTP (no RequireApproved).
	pendingAllowedGroup := Echo.Group("")
	pendingAllowedGroup.Use(auth.JWTMiddleware())
	pendingAllowedGroup.Use(auth.TokenRevocationMiddleware(database.DB))
	pendingAllowedGroup.Use(auth.RequireFullJWT)
	pendingAllowedGroup.Use(RequireTOTP)
	pendingAllowedGroup.GET("/api/user/contact-info", GetContactInfo)
	pendingAllowedGroup.PUT("/api/user/contact-info", PutContactInfo)
	pendingAllowedGroup.DELETE("/api/user/contact-info", DeleteContactInfo)

	// Current user identity - used by browser clients to get username/role
	// since the full JWT is HttpOnly and not readable by JavaScript.
	totpProtectedGroup.GET("/api/auth/me", GetCurrentUser)

	// Credits system - user endpoints (require TOTP)
	totpProtectedGroup.GET("/api/credits", GetUserCredits)

	// Admin API endpoints - structured for future expansion.
	// Stack: JWTMiddleware (validates aud=arkfile-api, rejects temp tokens at signature/audience)
	//      + RequireFullJWT (defense in depth: rejects requires_totp=true)
	//      + RequireTOTP (asserts the user has TOTP enrolled; E-01 fix)
	//      + AdminMiddleware (loopback gate, rate limit, admin-flag check, audit log).
	adminGroup := Echo.Group("/api/admin")
	adminGroup.Use(auth.JWTMiddleware())
	adminGroup.Use(auth.RequireFullJWT)
	adminGroup.Use(RequireTOTP)
	adminGroup.Use(AdminMiddleware)

	// Credits system - admin endpoints (require admin privileges).
	// Read-only views; positive admin-initiated balance changes go through the
	// /api/admin/billing/gift endpoint (typed transaction = 'gift'), and negative
	// changes are produced exclusively by the daily storage settlement sweep.
	adminGroup.GET("/credits", AdminGetAllCredits)
	adminGroup.GET("/credits/:username", AdminGetUserCredits)

	// User management - admin endpoints
	adminGroup.GET("/users", ListUsers)
	adminGroup.POST("/users/:username/approve", ApproveUser)
	adminGroup.GET("/users/:username/status", AdminGetUserStatus)
	adminGroup.PUT("/users/:username/storage", UpdateUserStorageLimit)
	adminGroup.POST("/users/:username/revoke", AdminRevokeUser)
	adminGroup.DELETE("/users/:username", DeleteUser)
	adminGroup.PUT("/users/:username", UpdateUser)
	adminGroup.POST("/users/:username/force-logout", AdminForceLogout)

	// Admin inspection of user files and shares
	adminGroup.GET("/users/:username/files", AdminListUserFiles)
	adminGroup.GET("/users/:username/shares", AdminListUserShares)

	// Contact information - admin endpoints (view any user's contact info)
	adminGroup.GET("/users/:username/contact-info", AdminGetContactInfo)

	// Admin file/share management
	adminGroup.DELETE("/files/:fileId", AdminDeleteFile)
	adminGroup.POST("/shares/:shareId/revoke", AdminRevokeShare)

	// File export - admin endpoints (for disaster recovery)
	adminGroup.GET("/files/:fileId/export", AdminExportFile)

	// System monitoring - admin endpoints
	adminGroup.GET("/system/status", AdminSystemStatus)
	adminGroup.GET("/system/health", AdminSystemHealth)
	adminGroup.GET("/security/events", AdminSecurityEvents)

	// Storage management - admin endpoints (multi-backend)
	adminGroup.GET("/storage/status", AdminStorageStatus)
	adminGroup.GET("/storage/sync-status", AdminSyncStatus)
	adminGroup.POST("/storage/copy-all", AdminCopyAll)
	adminGroup.POST("/storage/copy-user-files", AdminCopyUserFiles)
	adminGroup.POST("/storage/copy-file", AdminCopyFile)
	adminGroup.GET("/storage/tasks", AdminListTasks)
	adminGroup.POST("/storage/cancel-all-tasks", AdminCancelAllTasks)
	adminGroup.GET("/storage/task/:taskId", AdminTaskStatus)
	adminGroup.POST("/storage/cancel-task/:taskId", AdminCancelTask)
	adminGroup.POST("/storage/set-primary", AdminSetPrimary)
	adminGroup.POST("/storage/set-secondary", AdminSetSecondary)
	adminGroup.POST("/storage/set-tertiary", AdminSetTertiary)
	adminGroup.POST("/storage/swap-providers", AdminSwapProviders)
	adminGroup.POST("/storage/verify-storage", AdminVerifyStorage)
	adminGroup.POST("/storage/set-cost", AdminSetCost)
	adminGroup.POST("/storage/verify-all", AdminVerifyAll)
	adminGroup.GET("/alerts/summary", AdminAlertsSummary)

	// Billing - admin endpoints (storage credits / usage metering).
	// See handlers/admin_billing.go for the handler implementations.
	adminGroup.GET("/billing/price", AdminGetBillingPrice)
	adminGroup.POST("/billing/set-price", AdminSetBillingPrice)
	adminGroup.GET("/billing/sweep-summary", AdminGetBillingSweepSummary)
	adminGroup.GET("/billing/overdrawn", AdminGetBillingOverdrawn)
	adminGroup.POST("/billing/gift", AdminBillingGift)

	// Development/Testing admin endpoints (gated by ADMIN_DEV_TEST_API_ENABLED)
	// SECURITY: These endpoints are ONLY for development and testing
	if isDevTestAdminAPIEnabled() {
		// Same stack as adminGroup; dev-test endpoints must not skip any layer.
		devTestAdminGroup := Echo.Group("/api/admin/dev-test")
		devTestAdminGroup.Use(auth.JWTMiddleware())
		devTestAdminGroup.Use(auth.RequireFullJWT)
		devTestAdminGroup.Use(RequireTOTP)
		devTestAdminGroup.Use(AdminMiddleware)
		devTestAdminGroup.POST("/users/cleanup", AdminCleanupTestUser)
		devTestAdminGroup.GET("/totp/decrypt-check/:username", AdminTOTPDecryptCheck) // TOTP diagnostic endpoint

		// Billing tick-now: forces an immediate tick (and optional sweep).
		// Lives under /dev-test so it is physically not registered as a
		// route in production-flavored deployments. Used by the e2e billing
		// test in scripts/testing/e2e-test.sh.
		devTestAdminGroup.POST("/billing/tick-now", AdminBillingTickNow)
	}
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
