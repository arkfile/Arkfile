package handlers

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"strings"

	"github.com/arkfile/Arkfile/config"
	"github.com/labstack/echo/v4"
)

const (
	publicBaseURLPlaceholder     = "{{ARKFILE_BASE_URL}}"
	publicDomainPlaceholder      = "{{ARKFILE_DOMAIN}}"
	legalOperatorPlaceholder     = "{{ARKFILE_LEGAL_OPERATOR}}"
	legalAdminContactPlaceholder = "{{ARKFILE_ADMIN_CONTACT_BLOCK}}"
)

func servePublicPage(c echo.Context, filename string) error {
	baseURL, err := publicShareBaseURL(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Public URL configuration error")
	}

	page, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	cfg := config.GetConfig()
	domain := strings.TrimSpace(cfg.Server.Domain)
	if domain == "" {
		domain = "localhost"
	}

	legalOperator := strings.TrimSpace(cfg.Deployment.LegalEntityName)
	if legalOperator == "" {
		legalOperator = "the operator of " + domain
	}

	adminContactBlock := ""
	if adminContact := strings.TrimSpace(cfg.Deployment.AdminContact); adminContact != "" {
		adminContactBlock = "<p>Administrator contact: " + html.EscapeString(adminContact) + "</p>"
	}

	rendered := string(page)
	replacements := map[string]string{
		publicBaseURLPlaceholder:     html.EscapeString(baseURL),
		publicDomainPlaceholder:      html.EscapeString(domain),
		legalOperatorPlaceholder:     html.EscapeString(legalOperator),
		legalAdminContactPlaceholder: adminContactBlock,
	}
	for placeholder, value := range replacements {
		rendered = strings.ReplaceAll(rendered, placeholder, value)
	}
	return c.HTMLBlob(http.StatusOK, []byte(rendered))
}

// ServeRobots publishes crawl rules for the public informational pages.
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
  <url><loc>%s/terms.html</loc></url>
  <url><loc>%s/privacy.html</loc></url>
</urlset>
`, baseURL, baseURL, baseURL, baseURL)

	return c.Blob(http.StatusOK, "application/xml; charset=utf-8", []byte(body))
}
