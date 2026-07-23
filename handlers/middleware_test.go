package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// Regression tests.
//
// These tests prove that the localhost-only authorization gate on
// AdminMiddleware ignores client-controlled headers (X-Forwarded-For,
// X-Real-IP, Forwarded) and consults ONLY the kernel-reported transport
// peer address via peerAddrIsLoopback. They also exercise publicClientIP,
// which is the separate helper used for non-authz client-identity
// purposes (EntityID HMAC binning, rate-limit keying).

// newTestEchoWithIPExtractor builds an *echo.Echo wired the same way main.go
// wires the production process: e.IPExtractor pinned to ExtractIPDirect.
// Tests that exercise c.RealIP() must use this constructor so the test
// environment matches the runtime authorization posture.
func newTestEchoWithIPExtractor() *echo.Echo {
	e := echo.New()
	e.IPExtractor = echo.ExtractIPDirect()
	return e
}

// makeRequest builds an Echo context with explicit RemoteAddr + optional
// X-Forwarded-For header. Mimics what an HTTP client + Caddy would produce.
func makeRequest(e *echo.Echo, remoteAddr, xff, arkfilePeer string) echo.Context {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if arkfilePeer != "" {
		req.Header.Set("X-Arkfile-Peer", arkfilePeer)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

// TestPeerAddrIsLoopback_RejectsForgedXFF
//
// Scenario: an internet host sends a request with X-Forwarded-For: 127.0.0.1
// (the forged value) but its real TCP peer is a public IP. The helper MUST
// return false because the kernel-reported transport peer is what matters.
func TestPeerAddrIsLoopback_RejectsForgedXFF(t *testing.T) {
	e := newTestEchoWithIPExtractor()

	cases := []struct {
		name       string
		remoteAddr string
		xff        string
	}{
		{"public_ipv4_with_forged_xff_127", "203.0.113.7:55555", "127.0.0.1"},
		{"public_ipv4_with_forged_xff_v6", "203.0.113.7:55555", "::1"},
		{"public_ipv4_no_xff", "203.0.113.7:55555", ""},
		{"public_ipv6_with_forged_xff", "[2001:db8::1]:55555", "127.0.0.1"},
		{"rfc1918_with_forged_xff", "10.0.0.5:33333", "127.0.0.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := makeRequest(e, tc.remoteAddr, tc.xff, "")
			if peerAddrIsLoopback(c) {
				t.Fatalf("peerAddrIsLoopback returned true for non-loopback peer %q (XFF=%q). "+
					"The gate must consult the kernel "+
					"transport peer, not the X-Forwarded-For header.", tc.remoteAddr, tc.xff)
			}
		})
	}
}

// TestPeerAddrIsLoopback_AcceptsActualLoopback proves the gate still opens
// for legitimate loopback peers (the production case where Caddy on the
// same host reverse-proxies to Arkfile on 127.0.0.1).
func TestPeerAddrIsLoopback_AcceptsActualLoopback(t *testing.T) {
	e := newTestEchoWithIPExtractor()

	cases := []struct {
		name       string
		remoteAddr string
	}{
		{"ipv4_loopback_with_port", "127.0.0.1:55555"},
		{"ipv4_loopback_no_port", "127.0.0.1"},
		{"ipv6_loopback_with_port", "[::1]:55555"},
		{"ipv6_loopback_no_port", "::1"},
		{"loopback_range_127_x", "127.42.0.9:1234"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := makeRequest(e, tc.remoteAddr, "", "")
			if !peerAddrIsLoopback(c) {
				t.Fatalf("peerAddrIsLoopback returned false for loopback peer %q -- "+
					"this would break Caddy -> Arkfile on the same host.", tc.remoteAddr)
			}
		})
	}
}

// TestPeerAddrIsLoopback_RejectsInvalidRemoteAddr proves the helper does
// not fall back to "true" when RemoteAddr is unparseable. Failing closed
// is the right posture for an authz gate.
func TestPeerAddrIsLoopback_RejectsInvalidRemoteAddr(t *testing.T) {
	e := newTestEchoWithIPExtractor()
	c := makeRequest(e, "not-an-ip-address-at-all", "127.0.0.1", "")
	if peerAddrIsLoopback(c) {
		t.Fatalf("peerAddrIsLoopback returned true for unparseable RemoteAddr -- " +
			"must fail closed for authz decisions.")
	}
}

// TestAdminMiddleware_RejectsForgedXFF is the end-to-end regression
// test against the actual middleware. The middleware must return 403 and
// MUST NOT call the wrapped handler when the kernel peer is non-loopback,
// regardless of what X-Forwarded-For says.
func TestAdminMiddleware_RejectsForgedXFF(t *testing.T) {
	e := newTestEchoWithIPExtractor()

	called := false
	wrapped := AdminMiddleware(func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	c := makeRequest(e, "203.0.113.7:55555", "127.0.0.1", "")
	err := wrapped(c)

	if called {
		t.Fatalf("REGRESSION: AdminMiddleware invoked the inner handler for a " +
			"remote request that spoofed X-Forwarded-For: 127.0.0.1. The localhost " +
			"gate must reject this request.")
	}
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("AdminMiddleware returned %T (%v); expected *echo.HTTPError with code 403", err, err)
	}
	if httpErr.Code != http.StatusForbidden {
		t.Fatalf("AdminMiddleware returned status %d; expected %d (Forbidden) for a non-loopback peer",
			httpErr.Code, http.StatusForbidden)
	}
}

// TestPublicClientIP_PrefersArkfilePeerHeader proves that for non-authz
// purposes (EntityID HMAC binning, rate-limit keying) we honour the
// Caddy-controlled X-Arkfile-Peer header. The header is safe to trust
// because Caddy is the only entity allowed to set it: the Caddyfile uses
// `header_up X-Arkfile-Peer {http.request.remote.host}` which overwrites
// any incoming value, and strips X-Forwarded-For / X-Real-IP / Forwarded.
func TestPublicClientIP_PrefersArkfilePeerHeader(t *testing.T) {
	e := newTestEchoWithIPExtractor()

	c := makeRequest(e, "127.0.0.1:55555", "", "198.51.100.42")
	got := publicClientIP(c)
	if got == nil {
		t.Fatalf("publicClientIP returned nil")
	}
	if got.String() != "198.51.100.42" {
		t.Fatalf("publicClientIP = %v; want 198.51.100.42 (from X-Arkfile-Peer header)", got)
	}
}

// TestPublicClientIP_FallsBackToRemoteAddr proves the helper still works
// in the dev-without-Caddy topology (dev-reset.sh): no X-Arkfile-Peer
// header is set, and we should read the kernel transport peer.
func TestPublicClientIP_FallsBackToRemoteAddr(t *testing.T) {
	e := newTestEchoWithIPExtractor()

	c := makeRequest(e, "10.0.0.5:33333", "", "")
	got := publicClientIP(c)
	if got == nil {
		t.Fatalf("publicClientIP returned nil")
	}
	if got.String() != "10.0.0.5" {
		t.Fatalf("publicClientIP = %v; want 10.0.0.5 (from RemoteAddr)", got)
	}
}

// TestPublicClientIP_IgnoresForgedXFF proves that even if a remote client
// puts a forged value in X-Forwarded-For, publicClientIP must NOT use it.
// With e.IPExtractor = ExtractIPDirect and Caddy stripping XFF, c.RealIP()
// returns the kernel peer; publicClientIP returns that, not the XFF value.
func TestPublicClientIP_IgnoresForgedXFF(t *testing.T) {
	e := newTestEchoWithIPExtractor()

	c := makeRequest(e, "203.0.113.7:55555", "127.0.0.1", "")
	got := publicClientIP(c)
	if got == nil {
		t.Fatalf("publicClientIP returned nil")
	}
	if got.String() != "203.0.113.7" {
		t.Fatalf("publicClientIP = %v; want 203.0.113.7. regression: "+
			"publicClientIP must not honour X-Forwarded-For (which is what "+
			"e.IPExtractor = ExtractIPDirect prevents).", got)
	}
}

// TestPublicClientIP_IgnoresMalformedHeader proves we fall back gracefully
// to RemoteAddr if the X-Arkfile-Peer header is present but unparseable.
func TestPublicClientIP_IgnoresMalformedHeader(t *testing.T) {
	e := newTestEchoWithIPExtractor()

	c := makeRequest(e, "10.0.0.5:33333", "", "not-a-real-ip")
	got := publicClientIP(c)
	if got == nil {
		t.Fatalf("publicClientIP returned nil")
	}
	if got.String() != "10.0.0.5" {
		t.Fatalf("publicClientIP = %v; want fallback to 10.0.0.5 when X-Arkfile-Peer is malformed", got)
	}
}

// CookieTokenMiddleware tests

// TestCookieTokenMiddleware_NoCookie verifies that when no Arkfile cookie is
// present the Authorization header is left untouched (CLI path passthrough).
func TestCookieTokenMiddleware_NoCookie(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer cli-token-abc")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	capturedAuth := ""
	handler := CookieTokenMiddleware(func(c echo.Context) error {
		capturedAuth = c.Request().Header.Get("Authorization")
		return c.String(http.StatusOK, "ok")
	})
	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedAuth != "Bearer cli-token-abc" {
		t.Errorf("Authorization header modified when no cookie present; got %q want %q",
			capturedAuth, "Bearer cli-token-abc")
	}
}

// TestCookieTokenMiddleware_FullTokenCookie verifies that the full-tier cookie
// JWT is injected as the Authorization header and replaces any existing bearer.
func TestCookieTokenMiddleware_FullTokenCookie(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.AddCookie(&http.Cookie{Name: CookieFullToken, Value: "full-jwt-xyz"})
	req.Header.Set("Authorization", "Bearer should-be-replaced")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	capturedAuth := ""
	handler := CookieTokenMiddleware(func(c echo.Context) error {
		capturedAuth = c.Request().Header.Get("Authorization")
		return c.String(http.StatusOK, "ok")
	})
	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedAuth != "Bearer full-jwt-xyz" {
		t.Errorf("Authorization header = %q; want %q", capturedAuth, "Bearer full-jwt-xyz")
	}
}

// TestCookieTokenMiddleware_TempTokenCookie verifies that the temp-tier cookie
// JWT is injected when only the temp cookie is present.
func TestCookieTokenMiddleware_TempTokenCookie(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/auth", nil)
	req.AddCookie(&http.Cookie{Name: CookieTempToken, Value: "temp-jwt-abc"})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	capturedAuth := ""
	handler := CookieTokenMiddleware(func(c echo.Context) error {
		capturedAuth = c.Request().Header.Get("Authorization")
		return c.String(http.StatusOK, "ok")
	})
	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedAuth != "Bearer temp-jwt-abc" {
		t.Errorf("Authorization header = %q; want %q", capturedAuth, "Bearer temp-jwt-abc")
	}
}

// CSRFMiddleware tests

// TestCSRFMiddleware_NoCookie_PassesThrough verifies that when no full-tier
// cookie is present (CLI path) the middleware is a no-op.
func TestCSRFMiddleware_NoCookie_PassesThrough(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer cli-token")
	// No X-CSRF-Token, no cookie — CLI path.
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	handler := CSRFMiddleware(func(c echo.Context) error {
		called = true
		return c.String(http.StatusOK, "ok")
	})
	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

// TestCSRFMiddleware_SafeMethod_PassesThrough verifies that GET requests with
// a full-tier cookie are NOT subject to the CSRF header check.
func TestCSRFMiddleware_SafeMethod_PassesThrough(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.AddCookie(&http.Cookie{Name: CookieFullToken, Value: "full-jwt"})
	// No X-CSRF-Token — GET is exempt.
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	handler := CSRFMiddleware(func(c echo.Context) error {
		called = true
		return c.String(http.StatusOK, "ok")
	})
	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("next handler was not called on GET")
	}
}

// TestCSRFMiddleware_MissingHeader_Returns403 verifies that a POST with a
// full-tier cookie but no X-CSRF-Token header returns 403.
func TestCSRFMiddleware_MissingHeader_Returns403(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/uploads/init", nil)
	req.AddCookie(&http.Cookie{Name: CookieFullToken, Value: "full-jwt"})
	req.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "csrf-token-value"})
	// No X-CSRF-Token header.
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := CSRFMiddleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach")
	})
	err := handler(c)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected HTTPError, got %T: %v", err, err)
	}
	if he.Code != http.StatusForbidden {
		t.Errorf("status = %d; want %d", he.Code, http.StatusForbidden)
	}
}

// TestCSRFMiddleware_MismatchedTokens_Returns403 verifies that a POST with a
// full-tier cookie and a mismatched X-CSRF-Token header returns 403.
func TestCSRFMiddleware_MismatchedTokens_Returns403(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/files/delete", nil)
	req.AddCookie(&http.Cookie{Name: CookieFullToken, Value: "full-jwt"})
	req.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "correct-csrf"})
	req.Header.Set("X-CSRF-Token", "wrong-csrf")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := CSRFMiddleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach")
	})
	err := handler(c)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected HTTPError, got %T: %v", err, err)
	}
	if he.Code != http.StatusForbidden {
		t.Errorf("status = %d; want %d", he.Code, http.StatusForbidden)
	}
}

// TestCSRFMiddleware_ValidTokens_Passes verifies that a POST with matching
// X-CSRF-Token header and __Host-arkfile-csrf cookie is allowed through.
func TestCSRFMiddleware_ValidTokens_Passes(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/shares", nil)
	req.AddCookie(&http.Cookie{Name: CookieFullToken, Value: "full-jwt"})
	req.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "matching-csrf-value"})
	req.Header.Set("X-CSRF-Token", "matching-csrf-value")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	handler := CSRFMiddleware(func(c echo.Context) error {
		called = true
		return c.String(http.StatusOK, "ok")
	})
	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

// TestRequiresTimingProtection_PublicShareRoutes is a regression guard against
// the route-namespace drift where timing protection matched /api/share/ but the
// real anonymous share endpoints live under /api/public/shares/. Every path the
// publicShareGroup and the /shared/:id page route serve MUST be covered, or a
// fast 404/200 leaks share-ID existence at line rate.
func TestRequiresTimingProtection_PublicShareRoutes(t *testing.T) {
	protected := []string{
		"/api/public/shares/abc123/envelope",
		"/api/public/shares/abc123/metadata",
		"/api/public/shares/abc123/chunks/0",
		"/api/public/shares/abc123/chunks/42",
		"/api/public/shares/abc123/ticket",
		"/shared/abc123",
	}
	for _, p := range protected {
		if !requiresTimingProtection(p) {
			t.Errorf("requiresTimingProtection(%q) = false; want true (public share route must be padded)", p)
		}
	}
}

// TestRequiresTimingProtection_NonShareRoutesNotPadded confirms the floor does
// not silently widen to authenticated or unrelated paths, which would add
// avoidable latency to non-anonymous endpoints.
func TestRequiresTimingProtection_NonShareRoutesNotPadded(t *testing.T) {
	unprotected := []string{
		"/api/share", // legacy prefix root, not a registered route
		"/api/shares",
		"/api/files/abc/envelope",
		"/api/uploads/abc/chunks/0",
		"/api/auth/login",
		"/",
		"/api/admin/users",
	}
	for _, p := range unprotected {
		if requiresTimingProtection(p) {
			t.Errorf("requiresTimingProtection(%q) = true; want false (non-public-share route should not be padded)", p)
		}
	}
}

// TestTimingProtectionMiddleware_AppliesMinimumFloor verifies the middleware
// pads a sub-floor response up to the 1-second minimum on a protected path, and
// does not pad an unprotected path.
func TestTimingProtectionMiddleware_AppliesMinimumFloor(t *testing.T) {
	e := echo.New()

	// Protected path: handler returns instantly; middleware must pad to >= 1s.
	req := httptest.NewRequest(http.MethodGet, "/api/public/shares/abc/envelope", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	fastHandler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
	start := time.Now()
	if err := TimingProtectionMiddleware(fastHandler)(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < time.Second-50*time.Millisecond {
		t.Errorf("protected path not padded: elapsed=%v, want >= ~1s", elapsed)
	}

	// Unprotected path: handler returns instantly; no padding expected.
	req2 := httptest.NewRequest(http.MethodGet, "/api/files/abc/envelope", nil)
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)
	start2 := time.Now()
	if err := TimingProtectionMiddleware(fastHandler)(c2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	elapsed2 := time.Since(start2)
	if elapsed2 >= time.Second {
		t.Errorf("unprotected path was padded: elapsed=%v, want < 1s", elapsed2)
	}
}
