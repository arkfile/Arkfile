package auth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/arkfile/Arkfile/config"
)

// TestOpaqueServerID verifies the single source of truth for the OPAQUE server
// identity (idS). All OPAQUE participants (server, browser, CLI) must agree on
// this value, so the default and configured-override behavior are guarded here.
func TestOpaqueServerID(t *testing.T) {
	// Minimal storage env so config.LoadConfig() passes validation, since
	// OpaqueServerID() loads config to read Server.Domain.
	baseEnv := map[string]string{
		"STORAGE_PROVIDER_1":   "generic-s3",
		"STORAGE_1_ENDPOINT":   "http://localhost:9332",
		"STORAGE_1_ACCESS_KEY": "test",
		"STORAGE_1_SECRET_KEY": "test",
		"STORAGE_1_BUCKET":     "test",
	}

	cases := []struct {
		name        string
		domainValue string // "" means unset
		want        string
	}{
		{name: "unset falls back to default", domainValue: "", want: DefaultOpaqueServerID},
		{name: "configured FQDN is used", domainValue: "test.arkfile.net", want: "test.arkfile.net"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config.ResetConfigForTest()

			keys := []string{"ARKFILE_DOMAIN"}
			for k := range baseEnv {
				keys = append(keys, k)
			}
			originalEnv := make(map[string]string)
			for _, k := range keys {
				originalEnv[k] = os.Getenv(k)
			}
			defer func() {
				for _, k := range keys {
					if originalEnv[k] == "" {
						os.Unsetenv(k)
					} else {
						os.Setenv(k, originalEnv[k])
					}
				}
				config.ResetConfigForTest()
			}()

			for k, v := range baseEnv {
				os.Setenv(k, v)
			}
			if tc.domainValue == "" {
				os.Unsetenv("ARKFILE_DOMAIN")
			} else {
				os.Setenv("ARKFILE_DOMAIN", tc.domainValue)
			}

			assert.Equal(t, tc.want, OpaqueServerID())
		})
	}
}
