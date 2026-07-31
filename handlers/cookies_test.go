package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestIssueTempCookie_ExpiresFullSessionCookies(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/register/finalize", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	issueTempCookie(c, "temp-jwt-value")

	setCookies := rec.Result().Header["Set-Cookie"]
	if len(setCookies) == 0 {
		t.Fatal("expected Set-Cookie headers")
	}

	joined := strings.Join(setCookies, "\n")
	for _, name := range []string{CookieFullToken, CookieRefresh, CookieCSRF} {
		foundExpire := false
		for _, sc := range setCookies {
			if strings.HasPrefix(sc, name+"=") && (strings.Contains(sc, "Max-Age=0") || strings.Contains(sc, "Max-Age=-1")) {
				foundExpire = true
				break
			}
		}
		if !foundExpire {
			t.Fatalf("expected expired Set-Cookie for %s; got:\n%s", name, joined)
		}
	}

	foundTemp := false
	for _, sc := range setCookies {
		if strings.HasPrefix(sc, CookieTempToken+"=temp-jwt-value") && strings.Contains(sc, "Max-Age=1200") {
			foundTemp = true
			break
		}
	}
	if !foundTemp {
		t.Fatalf("expected temp cookie with value; got:\n%s", joined)
	}
}

func TestCookieTokenMiddleware_FullCookieShadowsTemp(t *testing.T) {
	// Documents why issueTempCookie must expire the full cookie: middleware
	// prefers __Host-arkfile-token when both are present.
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/webauthn/register/begin", nil)
	req.AddCookie(&http.Cookie{Name: CookieFullToken, Value: "full-jwt"})
	req.AddCookie(&http.Cookie{Name: CookieTempToken, Value: "temp-jwt"})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	captured := ""
	handler := CookieTokenMiddleware(func(c echo.Context) error {
		captured = c.Request().Header.Get("Authorization")
		return c.NoContent(http.StatusOK)
	})
	if err := handler(c); err != nil {
		t.Fatal(err)
	}
	if captured != "Bearer full-jwt" {
		t.Fatalf("Authorization = %q; want Bearer full-jwt (full takes precedence)", captured)
	}
}
