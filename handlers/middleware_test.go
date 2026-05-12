package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// F-01 regression tests.
//
// These tests prove that the localhost-only authorization gate on
// AdminMiddleware ignores client-controlled headers (X-Forwarded-For,
// X-Real-IP, Forwarded) and consults ONLY the kernel-reported transport
// peer address via peerAddrIsLoopback. They also exercise publicClientIP,
// which is the separate helper used for non-authz client-identity
// purposes (EntityID HMAC binning, rate-limit keying).
//
// See: docs/wip/review/00-executive-summary.md (F-01).

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

// TestPeerAddrIsLoopback_RejectsForgedXFF proves the F-01 fix.
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
					"This is the F-01 bug -- the gate must consult the kernel "+
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

// TestAdminMiddleware_RejectsForgedXFF is the end-to-end F-01 regression
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
		t.Fatalf("F-01 REGRESSION: AdminMiddleware invoked the inner handler for a " +
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
		t.Fatalf("publicClientIP = %v; want 203.0.113.7. F-01 regression: "+
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
