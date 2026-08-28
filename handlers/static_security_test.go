package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticHandlerRejectsEncodedPathSeparatorBypass(t *testing.T) {
	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "admin")
	require.NoError(t, os.MkdirAll(privateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(privateDir, "private.txt"), []byte("private"), 0o600))

	e := echo.New()
	e.GET("/admin/*", func(c echo.Context) error {
		return c.NoContent(http.StatusForbidden)
	})
	e.Static("/", publicDir)

	for _, requestPath := range []string{
		"/admin%2Fprivate.txt",
		"/admin%2fprivate.txt",
		"/admin%5Cprivate.txt",
		"/admin%5cprivate.txt",
	} {
		t.Run(requestPath, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, requestPath, nil)
			rec := httptest.NewRecorder()

			e.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.NotContains(t, rec.Body.String(), "private")
		})
	}
}
