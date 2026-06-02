package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// Regression tests for the bootstrap endpoints.
//
// BootstrapRegisterResponse and BootstrapRegisterFinalize are the two
// privileged endpoints that allow the first admin to be seeded against a
// fresh deployment. They are gated by:
//   (1) the bootstrap token (issued at first startup to the operator), AND
//   (2) a localhost-only check on the request peer.
//
// Layer (2) MUST consult the kernel-reported transport peer, NOT c.RealIP()
// / X-Forwarded-For. The tests below prove that a remote attacker who sends
// X-Forwarded-For: 127.0.0.1 cannot reach the bootstrap logic.

// makeBootstrapRequest constructs an Echo context with a JSON body that
// would normally drive the bootstrap handler. The token / username values
// do not matter because the localhost gate runs BEFORE token validation;
// if the test reaches a 401 (invalid token) instead of 403 (non-local
// peer), the gate has already failed.
func makeBootstrapRequest(e *echo.Echo, remoteAddr, xff string, body []byte) echo.Context {
	req := httptest.NewRequest(http.MethodPost, "/api/bootstrap/register/response", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

// TestBootstrapRegisterResponse_RejectsForgedXFF proves that the localhost
// gate on the bootstrap-response endpoint rejects a remote request even
// when X-Forwarded-For is set to 127.0.0.1.
func TestBootstrapRegisterResponse_RejectsForgedXFF(t *testing.T) {
	e := echo.New()
	e.IPExtractor = echo.ExtractIPDirect()

	// Minimal valid-shape JSON body. The handler never gets this far if
	// the gate works correctly; if it does, we'd see a 400/401 rather
	// than a 403, which would be the F-01 regression we are testing for.
	body := []byte(`{"bootstrap_token":"fake","username":"alice","registration_request":"AAAA"}`)

	c := makeBootstrapRequest(e, "203.0.113.7:55555", "127.0.0.1", body)
	err := BootstrapRegisterResponse(c)

	// The handler returns a JSON error via JSONError (not echo.NewHTTPError),
	// so the HTTP status appears on the response recorder, and err is nil.
	rec := c.Response().Writer.(*httptest.ResponseRecorder)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("REGRESSION: BootstrapRegisterResponse returned status %d for a remote "+
			"request that spoofed X-Forwarded-For: 127.0.0.1. Expected %d (Forbidden). err=%v body=%s",
			rec.Code, http.StatusForbidden, err, rec.Body.String())
	}
}

// TestBootstrapRegisterFinalize_RejectsForgedXFF mirrors the above for the
// finalize endpoint (which is the one that actually creates the admin
// user, so it is the higher-impact half of the bootstrap flow).
func TestBootstrapRegisterFinalize_RejectsForgedXFF(t *testing.T) {
	e := echo.New()
	e.IPExtractor = echo.ExtractIPDirect()

	body := []byte(`{"bootstrap_token":"fake","session_id":"fake","username":"alice","registration_record":"AAAA"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/bootstrap/register/finalize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:55555"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := BootstrapRegisterFinalize(c)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("REGRESSION: BootstrapRegisterFinalize returned status %d for a remote "+
			"request that spoofed X-Forwarded-For: 127.0.0.1. Expected %d (Forbidden). err=%v body=%s",
			rec.Code, http.StatusForbidden, err, rec.Body.String())
	}
}

// TestBootstrapRegisterResponse_AcceptsLoopbackPeer proves that the gate
// itself doesn't block legitimate loopback callers. We can only verify
// the gate passes (the handler will then fail with 400/401 on the fake
// JSON body / invalid token, which is correct downstream behaviour).
func TestBootstrapRegisterResponse_AcceptsLoopbackPeer(t *testing.T) {
	e := echo.New()
	e.IPExtractor = echo.ExtractIPDirect()

	body := []byte(`{"bootstrap_token":"fake","username":"alice","registration_request":"AAAA"}`)

	c := makeBootstrapRequest(e, "127.0.0.1:55555", "", body)
	_ = BootstrapRegisterResponse(c)

	rec := c.Response().Writer.(*httptest.ResponseRecorder)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("BootstrapRegisterResponse returned 403 for a legitimate loopback peer "+
			"(RemoteAddr=127.0.0.1). The localhost gate should accept this request and "+
			"only fail later on token/body validation. body=%s", rec.Body.String())
	}
	// We accept any non-403 status here (typically 401 invalid bootstrap
	// token, or 500 if no system_keys row exists in the test DB) because
	// the goal of this test is the GATE, not the rest of the handler.
}
