package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// Regression tests at the handler-package level.
//
// These tests prove that the middleware chain protecting the admin group
// (and totp/pending groups) rejects:
//   1. temp-tier tokens (aud=arkfile-mfa) at JWTMiddleware
//   2. full-tier tokens with requires_mfa=true (hand-crafted) at RequireFullJWT
// These rejections happen BEFORE any DB lookup in AdminMiddleware /
// RequireMFA, so the tests do not need a populated users table.

// adminStackHeadOfChain mimics the production middleware composition for
// /api/admin/*: JWTMiddleware first, then RequireFullJWT. The downstream
// layers (RequireMFA, AdminMiddleware) execute only if these two pass.
// "the request never reaches RequireMFA" is the assertion we care about.
func adminStackHeadOfChain(h echo.HandlerFunc) echo.HandlerFunc {
	return auth.JWTMiddleware()(auth.RequireFullJWT(h))
}

// totpProtectedStackHead mimics the head of mfaProtectedGroup composition.
// Same composition as adminStackHeadOfChain by design -- both groups gate
// on JWTMiddleware + RequireFullJWT before reaching their role-specific
// downstream middlewares.
func totpProtectedStackHead(h echo.HandlerFunc) echo.HandlerFunc {
	return auth.JWTMiddleware()(auth.RequireFullJWT(h))
}

// TestAdminStackHead_RejectsTempToken_Before_DB verifies that a temp
// post-OPAQUE token (aud=arkfile-mfa) MUST be rejected by JWTMiddleware
// before the request gets anywhere near AdminMiddleware. Without the fix,
// the same Ed25519 key signed both tiers and this token would have reached
// the inner handler.
func TestAdminStackHead_RejectsTempToken_Before_DB(t *testing.T) {
	e := echo.New()

	innerCalled := false
	stack := adminStackHeadOfChain(func(c echo.Context) error {
		innerCalled = true
		return c.String(http.StatusOK, "should not reach here")
	})

	tempToken, _, err := auth.GenerateTemporaryMFAToken("alice")
	if err != nil {
		t.Fatalf("GenerateTemporaryMFAToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+tempToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = stack(c)
	if innerCalled {
		t.Fatalf("REGRESSION: admin middleware chain invoked the inner handler " +
			"for a temp-tier token. JWTMiddleware must reject aud=arkfile-mfa before " +
			"AdminMiddleware/RequireMFA can run.")
	}
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for temp token at admin stack head, got %d", httpErr.Code)
	}
}

// TestAdminStackHead_RejectsFullTokenWithRequiresMFATrue verifies that
// even if an internal-policy violation produced a full-tier-signed token
// carrying aud=arkfile-api but requires_mfa=true, RequireFullJWT catches
// it. This is the defense-in-depth layer behind JWTMiddleware's audience
// check.
func TestAdminStackHead_RejectsFullTokenWithRequiresMFATrue(t *testing.T) {
	e := echo.New()

	innerCalled := false
	stack := adminStackHeadOfChain(func(c echo.Context) error {
		innerCalled = true
		return c.String(http.StatusOK, "should not reach here")
	})

	// Hand-craft a token: full-tier key, full audience, but requires_mfa=true.
	claims := &auth.Claims{
		Username:     "alice",
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    auth.Issuer,
			Audience:  []string{auth.AudienceAPI},
			ID:        "crafted-token",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	crafted, err := tok.SignedString(auth.GetJWTFullPrivateKey())
	if err != nil {
		t.Fatalf("sign crafted token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+crafted)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = stack(c)
	if innerCalled {
		t.Fatalf("RequireFullJWT REGRESSION: a token with requires_mfa=true " +
			"reached the inner handler. RequireFullJWT must block this.")
	}
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for requires_mfa=true token, got %d", httpErr.Code)
	}
}

// TestTOTPProtectedStackHead_RejectsTempToken verifies the same
// rejection at the mfaProtectedGroup head: a temp token never reaches
// any of the /api/files, /api/uploads, /api/shares handlers.
func TestTOTPProtectedStackHead_RejectsTempToken(t *testing.T) {
	e := echo.New()

	innerCalled := false
	stack := totpProtectedStackHead(func(c echo.Context) error {
		innerCalled = true
		return c.String(http.StatusOK, "should not reach here")
	})

	tempToken, _, err := auth.GenerateTemporaryMFAToken("alice")
	if err != nil {
		t.Fatalf("GenerateTemporaryMFAToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+tempToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = stack(c)
	if innerCalled {
		t.Fatalf("REGRESSION: mfaProtectedGroup chain invoked inner handler " +
			"for a temp token.")
	}
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", httpErr.Code)
	}
}

// TestAdminStackHead_AcceptsValidFullToken verifies the positive case:
// a properly-issued full-tier token (post-OPAQUE+TOTP) passes the head
// of the admin chain. Whether the downstream RequireMFA / AdminMiddleware
// then approve the request depends on DB state (is_admin, TOTP enabled),
// which is tested separately at the e2e level.
func TestAdminStackHead_AcceptsValidFullToken(t *testing.T) {
	e := echo.New()

	innerCalled := false
	stack := adminStackHeadOfChain(func(c echo.Context) error {
		innerCalled = true
		return c.NoContent(http.StatusOK)
	})

	fullToken, _, err := auth.GenerateFullAccessToken("alice")
	if err != nil {
		t.Fatalf("GenerateFullAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+fullToken)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := stack(c); err != nil {
		t.Fatalf("valid full token rejected by admin stack head: %v", err)
	}
	if !innerCalled {
		t.Fatalf("valid full token did not reach inner handler at admin stack head")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
}
