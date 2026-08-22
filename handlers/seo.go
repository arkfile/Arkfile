package handlers

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

const publicBaseURLPlaceholder = "{{ARKFILE_BASE_URL}}"

func servePublicPage(c echo.Context, filename string) error {
	baseURL, err := publicShareBaseURL(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Public URL configuration error")
	}

	page, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	rendered := strings.ReplaceAll(string(page), publicBaseURLPlaceholder, html.EscapeString(baseURL))
	return c.HTMLBlob(http.StatusOK, []byte(rendered))
}

// ServeRobots publishes crawl rules for the two public informational pages.
func ServeRobots(c echo.Context) error {
	baseURL, err := publicShareBaseURL(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Public URL configuration error")
	}

	body := fmt.Sprintf(`User-agent: *
Allow: /
Disallow: /api/
Disallow: /shared/
Disallow: /errors/
Disallow: /healthz
Disallow: /readyz

Sitemap: %s/sitemap.xml
`, baseURL)

	return c.Blob(http.StatusOK, "text/plain; charset=utf-8", []byte(body))
}

// ServeSitemap lists the public pages that are useful to search engines.
func ServeSitemap(c echo.Context) error {
	baseURL, err := publicShareBaseURL(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Public URL configuration error")
	}
	baseURL = html.EscapeString(baseURL)

	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>%s/</loc></url>
  <url><loc>%s/faq.html</loc></url>
</urlset>
`, baseURL, baseURL)

	return c.Blob(http.StatusOK, "application/xml; charset=utf-8", []byte(body))
}
