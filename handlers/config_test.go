package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
)

// TestGetOpaqueConfig verifies the public /api/config/opaque endpoint returns
// the OPAQUE server identity in the exact {"server_id": "..."} shape that the
// browser and CLI clients parse. A drift here would silently break login.
func TestGetOpaqueConfig(t *testing.T) {
	// Minimal storage env so config.LoadConfig() (used by auth.OpaqueServerID)
	// passes validation.
	envKeys := []string{
		"ARKFILE_DOMAIN",
		"STORAGE_PROVIDER_1",
		"STORAGE_1_ENDPOINT",
		"STORAGE_1_ACCESS_KEY",
		"STORAGE_1_SECRET_KEY",
		"STORAGE_1_BUCKET",
	}
	originalEnv := make(map[string]string)
	for _, k := range envKeys {
		originalEnv[k] = os.Getenv(k)
	}
	defer func() {
		for _, k := range envKeys {
			if originalEnv[k] == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, originalEnv[k])
			}
		}
		// Leave a loaded (non-nil) config behind: other handler tests call
		// config.GetConfig(), which panics on a nil singleton. We reset to pick
		// up the restored env, then reload so the singleton is valid again.
		config.ResetConfigForTest()
		_, _ = config.LoadConfig()
	}()

	os.Setenv("STORAGE_PROVIDER_1", "generic-s3")
	os.Setenv("STORAGE_1_ENDPOINT", "http://localhost:9332")
	os.Setenv("STORAGE_1_ACCESS_KEY", "test")
	os.Setenv("STORAGE_1_SECRET_KEY", "test")
	os.Setenv("STORAGE_1_BUCKET", "test")

	t.Run("default server identity", func(t *testing.T) {
		config.ResetConfigForTest()
		os.Unsetenv("ARKFILE_DOMAIN")

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/config/opaque", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if assert.NoError(t, GetOpaqueConfig(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)

			var body map[string]string
			assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			// Exactly one key, matching the wire contract clients parse.
			assert.Equal(t, map[string]string{"server_id": auth.DefaultOpaqueServerID}, body)
		}
	})

	t.Run("configured FQDN server identity", func(t *testing.T) {
		config.ResetConfigForTest()
		os.Setenv("ARKFILE_DOMAIN", "test.arkfile.net")

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/config/opaque", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if assert.NoError(t, GetOpaqueConfig(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)

			var body map[string]string
			assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, map[string]string{"server_id": "test.arkfile.net"}, body)
		}
	})
}
