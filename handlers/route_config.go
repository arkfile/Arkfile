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

	Echo.File("/faq.html", "client/static/faq.html")
	Echo.HEAD("/faq.html", func(c echo.Context) error {
		return c.File("client/static/faq.html")
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

	// OPAQUE re-registration ceremony - reached when an account flagged for
	// OPAQUE credential rotation signs in. Gated by the short-lived
	// re-registration handoff token (aud=arkfile-reregistration).
	Echo.POST("/api/opaque/reregister/response", RegisterRateLimitMiddleware(ReregisterResponse), auth.ReregistrationJWTMiddleware())
	Echo.POST("/api/opaque/reregister/finalize", RegisterRateLimitMiddleware(ReregisterFinalize), auth.ReregistrationJWTMiddleware())

	// Admin OPAQUE Authentication (Multi-Step Protocol) - separate endpoints with admin verification
	Echo.POST("/api/admin/login/response", LoginRateLimitMiddleware(AdminOpaqueAuthResponse))
	Echo.POST("/api/admin/login/finalize", LoginRateLimitMiddleware(AdminOpaqueAuthFinalize))

	// Bootstrap Registration (OPAQUE) - Initial Admin Setup
	Echo.POST("/api/bootstrap/register/response", RegisterRateLimitMiddleware(BootstrapRegisterResponse))
	Echo.POST("/api/bootstrap/register/finalize", RegisterRateLimitMiddleware(BootstrapRegisterFinalize))

	// MFA Status - requires full authentication (standard JWT)
	auth.Echo.GET("/api/mfa/status", MFAStatus)

	// MFA Setup/Verify/Auth/Recovery/Reset - temp or dual-tier JWT depending on route
	mfaGroup := Echo.Group("/api/mfa")
	mfaGroup.POST("/recover-with-backup-code", RecoverWithBackupCode, auth.MFAJWTMiddleware())
	mfaGroup.POST("/reset", MFAReset, auth.MFAResetJWTMiddleware())
	mfaGroup.POST("/setup", MFASetup, auth.MFAJWTMiddleware())
	mfaGroup.POST("/verify", MFARateLimitMiddleware("mfa_verify")(MFAVerify), auth.MFAJWTMiddleware())
	mfaGroup.POST("/auth", MFARateLimitMiddleware("mfa_auth")(MFAAuth), auth.MFAJWTMiddleware())
	mfaGroup.POST("/webauthn/register/begin", WebAuthnRegisterBegin, auth.MFAJWTMiddleware())
	mfaGroup.POST("/webauthn/register/finish", MFARateLimitMiddleware("mfa_verify")(WebAuthnRegisterFinish), auth.MFAJWTMiddleware())
	mfaGroup.POST("/webauthn/auth/begin", WebAuthnAuthBegin, auth.MFAJWTMiddleware())
	mfaGroup.POST("/webauthn/auth/finish", MFARateLimitMiddleware("mfa_auth")(WebAuthnAuthFinish), auth.MFAJWTMiddleware())

	// Admin contacts (public - no auth required)
	Echo.GET("/api/admin-contacts", AdminContactsHandler)

	// Session management (OPAQUE sessions)
	Echo.POST("/api/refresh", RefreshToken)
	// Logout requires authentication to prevent remote DoS or session manipulation.
	// It is registered under auth.Echo which applies JWTMiddleware + TokenRevocationMiddleware.
	auth.Echo.POST("/api/logout", Logout)

	// Create MFA-protected group for all sensitive operations.
	// Stack inherited from auth.Echo: JWTMiddleware + TokenRevocationMiddleware + RequireApproved.
	// Adds: RequireFullJWT (rejects requires_mfa=true and audience drift) + RequireMFA.
	mfaProtectedGroup := auth.Echo.Group("")
	mfaProtectedGroup.Use(auth.RequireFullJWT)
	mfaProtectedGroup.Use(RequireMFA)

	// MFA credential management (full session required)
	mfaProtectedGroup.GET("/api/mfa/credentials", ListMFACredentials)
	mfaProtectedGroup.DELETE("/api/mfa/credentials/:credential_id", DeleteMFACredential)
	mfaProtectedGroup.PATCH("/api/mfa/credentials/:credential_id/label", UpdateMFACredentialLabel)
	mfaProtectedGroup.POST("/api/mfa/backup-codes/regenerate", RegenerateMFABackupCodes)
	mfaProtectedGroup.POST("/api/mfa/credentials/totp/add", MFASetup)
	mfaProtectedGroup.POST("/api/mfa/credentials/webauthn/register/begin", WebAuthnRegisterBegin)
	mfaProtectedGroup.POST("/api/mfa/credentials/webauthn/register/finish", MFARateLimitMiddleware("mfa_verify")(WebAuthnRegisterFinish))

	// Token revocation - require MFA
	mfaProtectedGroup.POST("/api/revoke-token", RevokeToken)
	mfaProtectedGroup.POST("/api/auth/revoke-all", RevokeAllTokens)

	// Files - require authentication and MFA

	mfaProtectedGroup.GET("/api/files", ListFiles)
	mfaProtectedGroup.GET("/api/files/metadata", ListRecentFileMetadata)
	mfaProtectedGroup.POST("/api/files/metadata/batch", GetFileMetadataBatch)
	mfaProtectedGroup.GET("/api/files/:fileId/meta", GetFileMeta)
	mfaProtectedGroup.DELETE("/api/files/:fileId", DeleteFile)

	// Chunked downloads - require MFA
	mfaProtectedGroup.GET("/api/files/:fileId/chunks/:chunkIndex", DownloadFileChunk)

	// Chunked uploads - require MFA
	mfaProtectedGroup.POST("/api/uploads/init", CreateUploadSession)
	mfaProtectedGroup.POST("/api/uploads/:sessionId/chunks/:chunkNumber", UploadChunk)
	mfaProtectedGroup.POST("/api/uploads/:sessionId/complete", CompleteUpload)
	mfaProtectedGroup.GET("/api/uploads/:sessionId/status", GetUploadStatus)
	mfaProtectedGroup.DELETE("/api/uploads/:sessionId", CancelUpload)

	// File sharing - authenticated endpoints (require MFA)
	mfaProtectedGroup.GET("/api/files/:fileId/envelope", GetFileEnvelope) // Get file envelope for share creation
	mfaProtectedGroup.POST("/api/shares", CreateFileShare)                // Create anonymous share (file_id in body)
	mfaProtectedGroup.GET("/api/shares", ListShares)                      // List user's shares
	mfaProtectedGroup.POST("/api/shares/:id/revoke", RevokeShare)         // Revoke a share

	// Anonymous share access (no authentication required) - separate namespace with rate limiting
	// Using /api/public/shares to avoid conflicts with authenticated /api/shares routes
	publicShareGroup := Echo.Group("/api/public/shares")
	publicShareGroup.Use(ShareEnumerationMiddleware) // Entity-global enumeration protection FIRST
	publicShareGroup.Use(ShareRateLimitMiddleware)   // Then per-share-ID rate limiting (fail fast for abusers)
	publicShareGroup.Use(TimingProtectionMiddleware) // Then timing protection (for valid requests)
	publicShareGroup.GET("/:id", GetSharedFile)      // Share access page

	// Share page (serves shared.html for /shared/:id URLs - no authentication required).
	// To prevent URL enumeration sweeps and timing-attack mapping on this legacy path,
	// we protect it with the exact same middleware group.
	Echo.GET("/shared/:id", ShareEnumerationMiddleware(ShareRateLimitMiddleware(TimingProtectionMiddleware(GetSharedFile))))
	publicShareGroup.GET("/:id/envelope", GetShareEnvelope)             // Get share envelope for client-side decryption
	publicShareGroup.GET("/:id/metadata", GetShareDownloadMetadata)     // Get metadata for shared file download
	publicShareGroup.GET("/:id/chunks/:chunkIndex", DownloadShareChunk) // Download chunk of shared file

	// File export token - requires TOTP (creates short-lived download token)
	mfaProtectedGroup.POST("/api/files/:fileId/export-token", CreateExportToken)

	// File export download - registered on public router because browser downloads
	// use ?token= query param (no Authorization header). The handler validates
	// auth internally via resolveExportAuth() which checks either JWT or token.
	Echo.GET("/api/files/:fileId/export", ExportFile)

	// Contact information - user endpoints.
	// These are intentionally NOT in mfaProtectedGroup (which inherits RequireApproved)
	// so that pending users can set their contact info while awaiting approval.
	// Stack: JWT + TokenRevocation + RequireFullJWT + RequireMFA (no RequireApproved).
	pendingAllowedGroup := Echo.Group("")
	pendingAllowedGroup.Use(auth.JWTMiddleware())
	pendingAllowedGroup.Use(auth.TokenRevocationMiddleware(database.DB))
	pendingAllowedGroup.Use(auth.RequireFullJWT)
	pendingAllowedGroup.Use(RequireMFA)
	pendingAllowedGroup.GET("/api/user/contact-info", GetContactInfo)
	pendingAllowedGroup.PUT("/api/user/contact-info", PutContactInfo)
	pendingAllowedGroup.DELETE("/api/user/contact-info", DeleteContactInfo)

	// Current user identity - used by browser clients to get username/role
	// since the full JWT is HttpOnly and not readable by JavaScript.
	mfaProtectedGroup.GET("/api/auth/me", GetCurrentUser)

	// Credits system - user endpoints (require MFA)
	mfaProtectedGroup.GET("/api/credits", GetUserCredits)

	// Payments integration - user endpoints
	mfaProtectedGroup.POST("/api/billing/invoice", CreateInvoiceHandler)
	mfaProtectedGroup.GET("/api/billing/invoice/:invoice_id", GetInvoiceStatusHandler)

	// Webhook endpoint (public, unauthenticated)
	Echo.POST("/api/webhooks/btcpay", BTCPayWebhookHandler)

	// Admin API endpoints - structured for future expansion.
	// Stack: JWTMiddleware (validates aud=arkfile-api, rejects temp tokens at signature/audience)
	//      + RequireFullJWT (defense in depth: rejects requires_mfa=true)
	//      + RequireMFA (asserts the user has MFA enrolled)
	//      + AdminMiddleware (loopback gate, rate limit, admin-flag check, audit log).
	adminGroup := Echo.Group("/api/admin")
	adminGroup.Use(auth.JWTMiddleware())
	adminGroup.Use(auth.RequireFullJWT)
	adminGroup.Use(RequireMFA)
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
	adminGroup.POST("/users/:username/reset-mfa", AdminResetUserMFA)
	adminGroup.GET("/users/:username/mfa-credentials", AdminListUserMFACredentials)

	// OPAQUE credential rotation: flag account(s) for one-time re-registration.
	// The all-users route is registered before the parameterized route so it is
	// not shadowed by :username.
	adminGroup.POST("/users/flag-reregistration-all", AdminFlagAllUsersReregistration)
	adminGroup.POST("/users/:username/flag-reregistration", AdminFlagUserReregistration)

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
	adminGroup.POST("/system/prepare-user-secret-master-rotation", AdminPrepareUserSecretMasterRotation)
	adminGroup.POST("/system/prepare-envelope-master-rotation", AdminPrepareEnvelopeMasterRotation)
	adminGroup.POST("/system/rotate-jwt-keys", AdminRotateJWTKeys)
	adminGroup.POST("/system/retire-jwt-key-version", AdminRetireJWTKeyVersion)
	adminGroup.POST("/system/rotate-opaque-keys", AdminRotateOpaqueKeys)
	adminGroup.POST("/system/replace-opaque-keys", AdminReplaceOpaqueKeys)
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

	// Payments integration - admin endpoints
	adminGroup.GET("/payments/invoice/:invoice_id", AdminGetInvoiceHandler)
	adminGroup.GET("/payments/invoices", AdminListInvoicesHandler)
	adminGroup.POST("/payments/invoice/:invoice_id/sync", AdminSyncInvoiceHandler)
	adminGroup.POST("/payments/reconcile", AdminReconcilePaymentsHandler)

	// Development/Testing admin endpoints (gated by ADMIN_DEV_TEST_API_ENABLED)
	// SECURITY: These endpoints are ONLY for development and testing
	if isDevTestAdminAPIEnabled() {
		// Same stack as adminGroup; dev-test endpoints must not skip any layer.
		devTestAdminGroup := Echo.Group("/api/admin/dev-test")
		devTestAdminGroup.Use(auth.JWTMiddleware())
		devTestAdminGroup.Use(auth.RequireFullJWT)
		devTestAdminGroup.Use(RequireMFA)
		devTestAdminGroup.Use(AdminMiddleware)
		devTestAdminGroup.POST("/users/cleanup", AdminCleanupTestUser)
		devTestAdminGroup.GET("/mfa/decrypt-check/:username", AdminMFADecryptCheck)

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
