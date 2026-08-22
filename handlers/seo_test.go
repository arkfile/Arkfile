package handlers

import (
	"image"
	_ "image/jpeg"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkfile/Arkfile/config"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServePublicPageInjectsConfiguredBaseURL(t *testing.T) {
	cfg, err := config.LoadConfig()
	require.NoError(t, err)
	originalBaseURL := cfg.Server.BaseURL
	cfg.Server.BaseURL = "https://arkfile.example/"
	t.Cleanup(func() { cfg.Server.BaseURL = originalBaseURL })

	filename := filepath.Join(t.TempDir(), "page.html")
	require.NoError(t, os.WriteFile(filename, []byte(
		`<link rel="canonical" href="{{ARKFILE_BASE_URL}}/"><meta property="og:image" content="{{ARKFILE_BASE_URL}}/og-image.jpg">`,
	), 0o600))

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "https://evil.example/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	require.NoError(t, servePublicPage(c, filename))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `href="https://arkfile.example/"`)
	assert.Contains(t, rec.Body.String(), `content="https://arkfile.example/og-image.jpg"`)
	assert.NotContains(t, rec.Body.String(), publicBaseURLPlaceholder)
	assert.NotContains(t, rec.Body.String(), "evil.example")
}

func TestSEOIndexFilesContainExpectedMetadata(t *testing.T) {
	index, err := os.ReadFile("../client/static/index.html")
	require.NoError(t, err)
	indexHTML := string(index)

	description := "Private online storage and secure file sharing. Arkfile encrypts files on your device before upload, so only you and the people you choose can open them."
	assert.Contains(t, indexHTML, `<meta name="description" content="`+description+`">`)
	assert.Contains(t, indexHTML, `<meta property="og:image" content="{{ARKFILE_BASE_URL}}/og-image.jpg">`)
	assert.Contains(t, indexHTML, `<meta name="twitter:card" content="summary_large_image">`)
	assert.Contains(t, indexHTML, `id="app-container" data-nosnippet`)

	shared, err := os.ReadFile("../client/static/shared.html")
	require.NoError(t, err)
	assert.Contains(t, string(shared), `<meta name="robots" content="noindex, nofollow">`)

	imageFile, err := os.Open("../client/static/noahsark-painting.jpeg")
	require.NoError(t, err)
	defer imageFile.Close()
	imageConfig, _, err := image.DecodeConfig(imageFile)
	require.NoError(t, err)
	assert.Equal(t, 1200, imageConfig.Width)
	assert.Equal(t, 630, imageConfig.Height)
}

func TestServeRobotsAndSitemapUseConfiguredBaseURL(t *testing.T) {
	cfg, err := config.LoadConfig()
	require.NoError(t, err)
	originalBaseURL := cfg.Server.BaseURL
	cfg.Server.BaseURL = "https://arkfile.example/"
	t.Cleanup(func() { cfg.Server.BaseURL = originalBaseURL })

	t.Run("robots", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		require.NoError(t, ServeRobots(c))
		assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get(echo.HeaderContentType))
		assert.Contains(t, rec.Body.String(), "Disallow: /shared/")
		assert.Contains(t, rec.Body.String(), "Sitemap: https://arkfile.example/sitemap.xml")
	})

	t.Run("sitemap", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		require.NoError(t, ServeSitemap(c))
		assert.Equal(t, "application/xml; charset=utf-8", rec.Header().Get(echo.HeaderContentType))
		assert.Contains(t, rec.Body.String(), "<loc>https://arkfile.example/</loc>")
		assert.Contains(t, rec.Body.String(), "<loc>https://arkfile.example/faq.html</loc>")
		assert.NotContains(t, rec.Body.String(), "/shared/")
	})
}
