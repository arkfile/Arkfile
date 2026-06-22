package handlers

import (
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/utils"
)

// parseIPAddress safely converts IP string to net.IP
func parseIPAddress(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Fallback to localhost for invalid IPs
		return net.ParseIP("127.0.0.1")
	}
	return ip
}

// peerAddrIsLoopback returns true only if the kernel-reported transport peer
// address is loopback. This is the ONLY correct primitive for localhost-only
// authorization decisions (AdminMiddleware, BootstrapRegister*).
//
// It MUST NOT consult c.RealIP(), X-Forwarded-For, or X-Real-IP. Those values
// are client-controllable (set by any HTTP client) and Echo's default IP
// extractor walks them.
//
// main.go pins e.IPExtractor = echo.ExtractIPDirect() which makes c.RealIP()
// also safe today, but this helper documents the intent at the call site so
// a future regression to e.IPExtractor cannot silently reopen the hole.
func peerAddrIsLoopback(c echo.Context) bool {
	remote := c.Request().RemoteAddr
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		// RemoteAddr might be a bare address without a port in some
		// httptest-style setups; treat the whole string as the host.
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// publicClientIP returns the public-facing client IP for non-authorization
// purposes (EntityID HMAC binning, rate-limit keying, audit logging).
//
// Production topology: Caddy terminates TLS on the same host and reverse-
// proxies over loopback. The kernel transport peer Arkfile sees is therefore
// 127.0.0.1 from Caddy. The real public client IP is propagated by Caddy in
// the X-Arkfile-Peer header (set via `header_up X-Arkfile-Peer
// {http.request.remote.host}` in the Caddyfile). Caddy strips any incoming
// X-Forwarded-For / X-Real-IP / Forwarded headers before reverse-proxying, so
// X-Arkfile-Peer cannot be spoofed by a remote client.
//
// Dev-without-Caddy topology (dev-reset.sh): X-Arkfile-Peer is absent; we
// fall back to c.RealIP() which (with e.IPExtractor = ExtractIPDirect)
// returns the kernel peer, which is the real local client.
//
// This value is ALWAYS HMAC'd through logging/entity_id.go before any
// persistence; the raw IP never enters logs or DB rows.
func publicClientIP(c echo.Context) net.IP {
	if header := c.Request().Header.Get("X-Arkfile-Peer"); header != "" {
		if ip := net.ParseIP(strings.TrimSpace(header)); ip != nil {
			return ip
		}
	}
	return parseIPAddress(c.RealIP())
}

// PrivacyRequestLogger is an Echo middleware that logs HTTP requests without
// exposing raw IP addresses. It uses the entity ID system to replace the
// client IP with a privacy-preserving HMAC-based identifier.
func PrivacyRequestLogger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()

		// Process request
		err := next(c)

		// Compute entity ID (privacy-preserving, replaces raw IP)
		entityID := logging.GetOrCreateEntityID(c)

		// Log request with entity ID instead of IP
		latency := time.Since(start)
		req := c.Request()
		res := c.Response()

		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}

		logging.InfoLogger.Printf("Request: entity=%s method=%s uri=%s status=%d latency=%s bytes_out=%d error=%q",
			entityID,
			req.Method,
			req.RequestURI,
			res.Status,
			latency.String(),
			res.Size,
			errMsg,
		)

		return err
	}
}

// RateLimitState represents the current rate limiting state for an entity
type RateLimitState struct {
	EntityID       string     `json:"entity_id"`
	TimeWindow     string     `json:"time_window"`
	Endpoint       string     `json:"endpoint"`
	RequestCount   int        `json:"request_count"`
	LastRequest    time.Time  `json:"last_request"`
	ViolationCount int        `json:"violation_count"`
	PenaltyUntil   *time.Time `json:"penalty_until"`
}

// RateLimitManager manages rate limiting state with privacy-preserving entity IDs
type RateLimitManager struct {
	db     *sql.DB
	config config.RateLimitConfig
	cache  map[string]*RateLimitState
	mutex  sync.RWMutex
}

// NewRateLimitManager creates a new rate limit manager
func NewRateLimitManager(db *sql.DB, rateLimitConfig config.RateLimitConfig) *RateLimitManager {
	manager := &RateLimitManager{
		db:     db,
		config: rateLimitConfig,
		cache:  make(map[string]*RateLimitState),
	}

	// Start cleanup routine
	go manager.cleanupRoutine()

	return manager
}

// Global rate limit manager instance
var DefaultRateLimitManager *RateLimitManager

// InitializeRateLimitManager initializes the global rate limit manager
func InitializeRateLimitManager(rateLimitConfig config.RateLimitConfig) error {
	if database.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	DefaultRateLimitManager = NewRateLimitManager(database.DB, rateLimitConfig)
	logging.InfoLogger.Printf("Rate limit manager initialized")
	return nil
}

// CheckRateLimit checks if a request should be rate limited
func (rlm *RateLimitManager) CheckRateLimit(entityID, endpoint string, limit int, windowSize time.Duration) (bool, error) {
	if !rlm.config.EnableRateLimit {
		return false, nil // Rate limiting disabled
	}

	timeWindow := logging.DefaultEntityIDService.GetCurrentTimeWindow()
	key := fmt.Sprintf("%s:%s:%s", entityID, timeWindow, endpoint)

	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()

	// Get current state
	state, exists := rlm.cache[key]
	if !exists {
		// Load from database or create new
		state = &RateLimitState{
			EntityID:     entityID,
			TimeWindow:   timeWindow,
			Endpoint:     endpoint,
			RequestCount: 0,
			LastRequest:  time.Now().UTC(),
		}
		rlm.loadStateFromDB(state)
		rlm.cache[key] = state
	}

	// Check if currently under penalty
	if state.PenaltyUntil != nil && time.Now().UTC().Before(*state.PenaltyUntil) {
		return true, nil // Still under penalty
	}

	// Increment request count
	state.RequestCount++
	state.LastRequest = time.Now().UTC()

	// Check if limit exceeded
	if state.RequestCount > limit {
		// Apply progressive penalty
		state.ViolationCount++
		penaltyDuration := rlm.calculatePenalty(state.ViolationCount)
		penaltyUntil := time.Now().UTC().Add(penaltyDuration)
		state.PenaltyUntil = &penaltyUntil

		// Save to database
		rlm.saveStateToDB(state)

		// Log security event
		logging.LogSecurityEvent(
			logging.EventRateLimitViolation,
			nil, // No IP in logs - using entity ID
			nil,
			nil,
			map[string]interface{}{
				"endpoint":        endpoint,
				"request_count":   state.RequestCount,
				"limit":           limit,
				"violation_count": state.ViolationCount,
				"penalty_until":   penaltyUntil,
			},
		)

		return true, nil // Rate limited
	}

	// Save updated state
	rlm.saveStateToDB(state)

	return false, nil // Not rate limited
}

// calculatePenalty calculates progressive penalty duration
func (rlm *RateLimitManager) calculatePenalty(violationCount int) time.Duration {
	if violationCount > rlm.config.MaxViolations {
		return rlm.config.MaxPenaltyDelay
	}

	// Progressive penalty: base delay * (penalty multiplier ^ violation count)
	baseDelay := 30 * time.Second
	for i := 1; i < violationCount; i++ {
		baseDelay = time.Duration(float64(baseDelay) * rlm.config.ViolationPenalty)
		if baseDelay > rlm.config.MaxPenaltyDelay {
			return rlm.config.MaxPenaltyDelay
		}
	}

	return baseDelay
}

// loadStateFromDB loads rate limit state from database
func (rlm *RateLimitManager) loadStateFromDB(state *RateLimitState) {
	query := `SELECT request_count, last_request, violation_count, penalty_until 
              FROM rate_limit_state 
              WHERE entity_id = ? AND time_window = ? AND endpoint = ?`

	var penaltyUntil sql.NullTime
	err := rlm.db.QueryRow(query, state.EntityID, state.TimeWindow, state.Endpoint).Scan(
		&state.RequestCount,
		&state.LastRequest,
		&state.ViolationCount,
		&penaltyUntil,
	)

	if err != nil && err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("Failed to load rate limit state: %v", err)
	}

	if penaltyUntil.Valid {
		state.PenaltyUntil = &penaltyUntil.Time
	}
}

// saveStateToDB saves rate limit state to database
func (rlm *RateLimitManager) saveStateToDB(state *RateLimitState) {
	query := `INSERT OR REPLACE INTO rate_limit_state 
              (entity_id, time_window, endpoint, request_count, last_request, violation_count, penalty_until, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	var penaltyUntil interface{}
	if state.PenaltyUntil != nil {
		penaltyUntil = *state.PenaltyUntil
	}

	_, err := rlm.db.Exec(query,
		state.EntityID,
		state.TimeWindow,
		state.Endpoint,
		state.RequestCount,
		state.LastRequest,
		state.ViolationCount,
		penaltyUntil,
		time.Now().UTC(),
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to save rate limit state: %v", err)
	}
}

// cleanupRoutine periodically cleans up old rate limit data
func (rlm *RateLimitManager) cleanupRoutine() {
	ticker := time.NewTicker(rlm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rlm.cleanup()
	}
}

// cleanup removes old rate limit data
func (rlm *RateLimitManager) cleanup() {
	cutoffDate := time.Now().UTC().AddDate(0, 0, -rlm.config.RetentionDays)
	cutoffWindow := logging.DefaultEntityIDService.GetTimeWindowForTime(cutoffDate)

	// Clean database
	_, err := rlm.db.Exec("DELETE FROM rate_limit_state WHERE time_window < ?", cutoffWindow)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to cleanup old rate limit data: %v", err)
		return
	}

	// Clean cache
	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()

	for key, state := range rlm.cache {
		if state.TimeWindow < cutoffWindow {
			delete(rlm.cache, key)
		}
	}

	logging.InfoLogger.Printf("Cleaned up rate limit data older than %s", cutoffWindow)
}

// RateLimitMiddleware creates rate limiting middleware for specific endpoints
func RateLimitMiddleware(endpointConfig config.EndpointConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if DefaultRateLimitManager == nil {
				return next(c) // Rate limiting not initialized
			}

			if !endpointConfig.Enabled {
				return next(c) // Rate limiting disabled for this endpoint
			}

			// Get composite entity ID (privacy-preserving, NAT-aware).
			// publicClientIP prefers the Caddy-set X-Arkfile-Peer header so
			// rate-limit buckets reflect the real public client rather than
			// the loopback peer Caddy presents. Never used for authorization.
			clientIP := publicClientIP(c)
			entityID := logging.GetCompositeEntityIDForRequest(clientIP, c.Request())

			// Check rate limit
			rateLimited, err := DefaultRateLimitManager.CheckRateLimit(
				entityID,
				endpointConfig.Path,
				endpointConfig.Limit,
				endpointConfig.WindowSize,
			)

			if err != nil {
				logging.ErrorLogger.Printf("Rate limit check failed: %v", err)
				return JSONError(c, http.StatusServiceUnavailable, "Rate limiter unavailable")
			}

			if rateLimited {
				// Log rate limit violation
				logging.LogSecurityEvent(
					logging.EventRateLimitViolation,
					clientIP,
					nil,
					nil,
					map[string]interface{}{
						"endpoint":    endpointConfig.Path,
						"method":      endpointConfig.Method,
						"limit":       endpointConfig.Limit,
						"window_type": endpointConfig.WindowType,
						"description": endpointConfig.Description,
					},
				)

				// Unified rate-limit response shape: stable machine-readable
				// code "rate_limited" in the top-level error field; per-endpoint
				// path is exposed via data.endpoint. The Retry-After HTTP
				// header would be the authoritative retry signal but this
				// site does not have a real next-allowed timestamp available,
				// so we omit retry_after_seconds rather than emit a misleading
				// value. Callers should fall back to general backoff guidance.
				return JSONErrorCodeData(c, http.StatusTooManyRequests, "rate_limited",
					fmt.Sprintf("Too many requests to %s. Please try again later.", endpointConfig.Path),
					map[string]interface{}{
						"endpoint": endpointConfig.Path,
					})
			}

			return next(c)
		}
	}
}

// paymentProviderFrameOrigin returns scheme://host for BTCPay checkout iframe embedding.
func paymentProviderFrameOrigin(serverURL string) string {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimSuffix(serverURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// buildContentSecurityPolicy assembles the CSP header, optionally allowing the
// configured BTCPay Server origin for checkout iframe embedding.
func buildContentSecurityPolicy() string {
	frameSrc := "'self'"
	if cfg := config.GetConfig(); cfg.Payments.Enabled {
		if origin := paymentProviderFrameOrigin(cfg.Payments.BTCPayServerURL); origin != "" {
			frameSrc += " " + origin
		}
	}

	// Note: 'wasm-unsafe-eval' is required for OPAQUE WebAssembly authentication.
	// frame-src includes the BTCPay Server origin when payments are enabled so
	// the billing top-up modal can embed the provider checkout page.
	return "default-src 'self'; " +
		"script-src 'self' 'wasm-unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"connect-src 'self' data: blob:; " +
		"font-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-src " + frameSrc + "; " +
		"frame-ancestors 'none'; " +
		"worker-src 'self'; " +
		"require-trusted-types-for 'script'; " +
		"trusted-types default; " +
		"upgrade-insecure-requests"
}

// CSPMiddleware adds Content Security Policy headers with strict security
func CSPMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		csp := buildContentSecurityPolicy()

		c.Response().Header().Set("Content-Security-Policy", csp)

		// Additional security headers
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		c.Response().Header().Set("X-Frame-Options", "DENY")
		c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
		c.Response().Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		return next(c)
	}
}

// CookieTokenMiddleware extracts the JWT from an Arkfile session cookie when
// one is present, and injects it as an Authorization header so the downstream
// JWT validators (JWTMiddleware, MFAJWTMiddleware) work without modification.
//
// Priority rules (no UA sniffing):
//  1. Full-tier cookie present: inject as bearer; ignore any existing header.
//  2. Temp-tier cookie present: inject as bearer; ignore any existing header.
//  3. Bearer header only (no cookie): pass through unchanged.
//  4. Neither: pass through; downstream middleware handles unauthenticated.
func CookieTokenMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()

		// Check for full-tier cookie first, then temp-tier.
		var cookieJWT string
		if ck, err := req.Cookie(CookieFullToken); err == nil && ck.Value != "" {
			cookieJWT = ck.Value
		} else if ck, err := req.Cookie(CookieTempToken); err == nil && ck.Value != "" {
			cookieJWT = ck.Value
		}

		if cookieJWT != "" {
			// Browser path: inject token into Authorization header so existing
			// JWTMiddleware/MFAJWTMiddleware validate it without any changes.
			req.Header.Set("Authorization", "Bearer "+cookieJWT)
		}
		// CLI path (no cookie): Authorization header already set by client — nothing to do.

		return next(c)
	}
}

// csrfExemptPaths are anonymous pre-authentication endpoints. They establish a
// brand-new session, so the double-submit CSRF check (which protects existing
// authenticated sessions) does not apply. Exempting them also ensures a stale
// or attacker-planted session cookie left in the browser cannot block the
// register/login flow.
var csrfExemptPaths = map[string]struct{}{
	"/api/opaque/register/response":    {},
	"/api/opaque/register/finalize":    {},
	"/api/opaque/login/response":       {},
	"/api/opaque/login/finalize":       {},
	"/api/admin/login/response":        {},
	"/api/admin/login/finalize":        {},
	"/api/bootstrap/register/response": {},
	"/api/bootstrap/register/finalize": {},
}

func isCSRFExemptPath(path string) bool {
	_, ok := csrfExemptPaths[path]
	return ok
}

// CSRFMiddleware enforces the double-submit CSRF pattern for browser requests.
// Applied only when a full-tier Arkfile cookie is present on the request.
// Safe (GET/HEAD/OPTIONS) methods are exempt.
// CLI requests (no Arkfile cookie) bypass this middleware entirely.
func CSRFMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Anonymous pre-authentication endpoints establish a new session and
		// must never be gated by CSRF (a stale cookie must not block them).
		if isCSRFExemptPath(c.Path()) {
			return next(c)
		}

		// Only enforce CSRF for browser sessions (full-tier cookie present).
		// Temp-tier-only sessions are during TOTP handoff; POST to /api/mfa/*
		// is safe here because TOTP endpoints are protected by MFAJWTMiddleware
		// (audience=arkfile-mfa) and are not state-changing in a sensitive way
		// that an attacker can exploit — the temp token itself is the credential.
		ck, err := c.Request().Cookie(CookieFullToken)
		if err != nil || ck.Value == "" {
			// No full-tier cookie: CLI path or unauthenticated — no CSRF check.
			return next(c)
		}

		// Exempt safe methods.
		method := c.Request().Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return next(c)
		}

		// Compare X-CSRF-Token header to __Host-arkfile-csrf cookie value.
		csrfHeader := c.Request().Header.Get("X-CSRF-Token")
		csrfCookie, cookieErr := c.Request().Cookie(CookieCSRF)
		if cookieErr != nil || csrfCookie.Value == "" || csrfHeader == "" {
			return echo.NewHTTPError(http.StatusForbidden, "CSRF token missing")
		}

		// Constant-time comparison to prevent timing attacks.
		if subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(csrfCookie.Value)) != 1 {
			logging.LogSecurityEvent(
				logging.EventUnauthorizedAccess,
				publicClientIP(c),
				nil,
				nil,
				map[string]interface{}{
					"reason":   "CSRF token mismatch",
					"endpoint": c.Request().URL.Path,
					"method":   method,
				},
			)
			return echo.NewHTTPError(http.StatusForbidden, "CSRF token invalid")
		}

		return next(c)
	}
}

// TimingProtectionMiddleware enforces 1-second minimum response time for anonymous endpoints
func TimingProtectionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Only apply to share access endpoints (anonymous access)
		path := c.Request().URL.Path
		if !requiresTimingProtection(path) {
			return next(c)
		}

		startTime := time.Now()

		// Process the request
		err := next(c)

		// Calculate elapsed time
		elapsed := time.Since(startTime)
		minDelay := 1 * time.Second // 1-second minimum for good UX + security balance

		// If response was faster than minimum, add delay
		if elapsed < minDelay {
			remainingDelay := minDelay - elapsed
			time.Sleep(remainingDelay)

			logging.InfoLogger.Printf("Timing protection applied: %v delay added to %s",
				remainingDelay, path)
		}

		return err
	}
}

// requiresTimingProtection checks if an endpoint requires timing protection
func requiresTimingProtection(path string) bool {
	protectedEndpoints := []string{
		"/api/share/", // Share envelope access (no auth required, client-side decryption)
		"/shared/",    // Share page access
	}

	for _, endpoint := range protectedEndpoints {
		if len(path) >= len(endpoint) && path[:len(endpoint)] == endpoint {
			return true
		}
	}

	// Also check for exact matches and patterns that should be protected
	if path == "/api/share" ||
		path == "/shared" ||
		(len(path) > len("/api/share/") && path[:len("/api/share/")] == "/api/share/") ||
		(len(path) > len("/shared/") && path[:len("/shared/")] == "/shared/") {
		return true
	}

	return false
}

// TLSVersionCheck middleware adds TLS version information to response headers
// and logs TLS version usage for analytics
func TLSVersionCheck(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Ensure HTTPS
		if c.Request().TLS == nil {
			return echo.NewHTTPError(http.StatusForbidden,
				"HTTPS required for this operation")
		}

		// Get TLS version string (TLS 1.3 only)
		var versionStr string
		switch c.Request().TLS.Version {
		case tls.VersionTLS13:
			versionStr = "1.3"
		default:
			versionStr = fmt.Sprintf("unexpected (%d)", c.Request().TLS.Version)
		}

		// Add TLS version to response headers for client detection
		c.Response().Header().Set("X-TLS-Version", versionStr)

		// Log TLS version and cipher suite for analytics (entity ID, not raw IP)
		entityID := logging.GetOrCreateEntityID(c)
		logging.InfoLogger.Printf("TLS Connection: version=%s cipher=%s entity=%s path=%s",
			versionStr,
			tls.CipherSuiteName(c.Request().TLS.CipherSuite),
			entityID,
			c.Request().URL.Path,
		)

		return next(c)
	}
}

// RequireApproved ensures the user is approved before allowing access.
// Applied to auth.Echo so all routes in that group inherit it.
// Contact-info endpoints are intentionally placed in a separate group
// (pendingAllowedGroup in route_config.go) that omits this middleware,
// allowing pending users to manage their contact information.
func RequireApproved(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := auth.GetUsernameFromToken(c)

		// Get user details
		user, err := models.GetUserByUsername(database.DB, username)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Check if user is approved or is an admin
		if !user.IsApproved && !user.HasAdminPrivileges() {
			return echo.NewHTTPError(http.StatusForbidden, "Account pending approval")
		}

		return next(c)
	}
}

// RequireAdmin ensures the user has admin privileges before allowing access
func RequireAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := auth.GetUsernameFromToken(c)

		// Get user details
		user, err := models.GetUserByUsername(database.DB, username)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Check if user has admin privileges
		if !user.HasAdminPrivileges() {
			return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
		}

		return next(c)
	}
}

// RequireMFA ensures the user has TOTP enabled before allowing access to protected resources.
// Note: /api/mfa/setup and /api/mfa/verify are on a separate route group using MFAJWTMiddleware
// and never reach this middleware, so no path-based bypass is needed here.
func RequireMFA(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := auth.GetUsernameFromToken(c)

		// Check if user has TOTP enabled
		totpEnabled, err := auth.IsUserMFAEnabled(database.DB, username)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to check TOTP status for %s: %v", username, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify TOTP status")
		}

		if !totpEnabled {
			// Log security event for TOTP bypass attempt.
			// publicClientIP returns the real public client IP (HMAC'd through
			// EntityID before persistence -- raw IP never reaches logs/DB).
			logging.LogSecurityEvent(
				logging.EventUnauthorizedAccess,
				publicClientIP(c),
				&username,
				nil,
				map[string]interface{}{
					"reason":   "TOTP not enabled",
					"endpoint": c.Request().URL.Path,
					"method":   c.Request().Method,
				},
			)

			return echo.NewHTTPError(http.StatusForbidden, "Two-factor authentication is required. Please complete TOTP setup.")
		}

		return next(c)
	}
}

// isLocalhostIP checks if an IP address is localhost without storing or logging it.
//
// DEPRECATED for authorization decisions. Use peerAddrIsLoopback(c) instead.
// This helper takes a net.IP that callers usually obtained from c.RealIP(),
// which walks X-Forwarded-For under Echo's default extractor and is therefore
// spoofable. See peerAddrIsLoopback for the correct
// primitive for "is this request coming from loopback?" authz gates.
func isLocalhostIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.ParseIP("::1"))
}

// AdminMiddleware enforces multi-layer security for admin endpoints
func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// 1. Localhost validation. We MUST use the kernel-reported transport
		// peer here, not c.RealIP(), so a remote attacker cannot pass
		// X-Forwarded-For: 127.0.0.1 and slip past the gate.
		if !peerAddrIsLoopback(c) {
			return echo.NewHTTPError(http.StatusForbidden, "Admin endpoints only available from localhost")
		}

		// 2. For rate limiting and audit logging, use composite EntityID
		// system keyed on the real public client IP (read from the Caddy-
		// set X-Arkfile-Peer header via publicClientIP). The raw IP never
		// reaches logs or DB rows -- EntityID HMAC is the privacy boundary.
		clientIP := publicClientIP(c)
		entityID := logging.GetCompositeEntityIDForRequest(clientIP, c.Request())

		// 3. Check rate limit using existing EntityID system
		if DefaultRateLimitManager != nil {
			rateLimited, err := DefaultRateLimitManager.CheckRateLimit(
				entityID,
				"/api/admin",
				10, // 10 requests per minute
				time.Minute,
			)
			if err != nil {
				logging.ErrorLogger.Printf("Admin rate limit check failed: %v", err)
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate request")
			}
			if rateLimited {
				// Log rate limit violation using existing system
				logging.LogSecurityEvent(
					logging.EventRateLimitViolation,
					nil, // No IP in logs - privacy preserving
					nil,
					nil,
					map[string]interface{}{
						"endpoint":    "/api/admin",
						"description": "Admin API rate limit exceeded",
					},
				)
				return echo.NewHTTPError(http.StatusTooManyRequests, "Admin rate limit exceeded")
			}
		}

		// 4. Valid admin JWT
		username := auth.GetUsernameFromToken(c)
		if username == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Admin authentication required")
		}

		// 5. Admin privileges
		user, err := models.GetUserByUsername(database.DB, username)
		if err != nil || !user.HasAdminPrivileges() {
			return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
		}

		// 6. Block dev admin accounts in production
		if utils.IsProductionEnvironment() && utils.IsDevAdminAccount(username) {
			logging.ErrorLogger.Printf("SECURITY: Blocked dev admin account '%s' in production", username)
			return echo.NewHTTPError(http.StatusForbidden, "Dev admin accounts blocked in production")
		}

		// 7. Audit log using existing security event system (no IP stored)
		logging.LogSecurityEvent(
			logging.EventAdminAccess, // Will need to add this event type to logging package
			nil,                      // No IP in logs - privacy preserving
			&username,
			nil,
			map[string]interface{}{
				"endpoint": c.Request().URL.Path,
				"method":   c.Request().Method,
			},
		)

		return next(c)
	}
}
