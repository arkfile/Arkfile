package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
)

// Cached error page contents (read once at first use)
var (
	page404Content string
	page429Content string
	pageOnce404    sync.Once
	pageOnce429    sync.Once
)

// read404Page returns the 404.html content, caching it after the first read
func read404Page() string {
	pageOnce404.Do(func() {
		data, err := os.ReadFile("client/static/errors/404.html")
		if err != nil {
			page404Content = "<html><body><h1>404 - Not Found</h1></body></html>"
			return
		}
		page404Content = string(data)
	})
	return page404Content
}

// read429Page returns the 429.html content, caching it after the first read
func read429Page() string {
	pageOnce429.Do(func() {
		data, err := os.ReadFile("client/static/errors/429.html")
		if err != nil {
			page429Content = "<html><body><h1>429 - Too Many Requests</h1><p>Please wait before trying again.</p></body></html>"
			return
		}
		page429Content = string(data)
	})
	return page429Content
}

// isBrowserRequest checks if the request is from a browser (Accept header contains text/html)
func isBrowserRequest(c echo.Context) bool {
	accept := c.Request().Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}

// ServeRateLimitPage returns the 429 error page with appropriate format
// (HTML for browsers, JSON for API clients)
func ServeRateLimitPage(c echo.Context, retryAfter int, message string) error {
	c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	if isBrowserRequest(c) {
		return c.HTML(http.StatusTooManyRequests, read429Page())
	}
	return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
		"success":    false,
		"error":      "rate_limited",
		"retryAfter": retryAfter,
		"message":    message,
	})
}
