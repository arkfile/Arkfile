package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAWSS3ConfigValidation tests AWS S3 configuration validation
func TestAWSS3ConfigValidation(t *testing.T) {
	testCases := []struct {
		name        string
		envVars     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid AWS S3 configuration",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "aws-s3",
				"STORAGE_1_REGION":     "us-west-2",
				"STORAGE_1_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
				"STORAGE_1_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"STORAGE_1_BUCKET":     "arkfile-test-bucket",
			},
			expectError: false,
		},
		{
			name: "AWS S3 with default region",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "aws-s3",
				"STORAGE_1_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
				"STORAGE_1_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"STORAGE_1_BUCKET":     "arkfile-test-bucket",
				// STORAGE_1_REGION not set - should default to us-east-1
			},
			expectError: false,
		},
		{
			name: "AWS S3 missing access key",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "aws-s3",
				"STORAGE_1_REGION":     "us-west-2",
				"STORAGE_1_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"STORAGE_1_BUCKET":     "arkfile-test-bucket",
				// STORAGE_1_ACCESS_KEY missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires",
		},
		{
			name: "AWS S3 missing secret key",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "aws-s3",
				"STORAGE_1_REGION":     "us-west-2",
				"STORAGE_1_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
				"STORAGE_1_BUCKET":     "arkfile-test-bucket",
				// STORAGE_1_SECRET_KEY missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires",
		},
		{
			name: "AWS S3 missing bucket name",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "aws-s3",
				"STORAGE_1_REGION":     "us-west-2",
				"STORAGE_1_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
				"STORAGE_1_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				// STORAGE_1_BUCKET missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset config for clean test
			ResetConfigForTest()

			// Store original environment and set test values
			originalEnv := make(map[string]string)
			for key, value := range tc.envVars {
				originalEnv[key] = os.Getenv(key)
				os.Setenv(key, value)
			}

			// Defer cleanup
			defer func() {
				for key, originalValue := range originalEnv {
					if originalValue == "" {
						os.Unsetenv(key)
					} else {
						os.Setenv(key, originalValue)
					}
				}
				ResetConfigForTest()
			}()

			// Test config loading
			cfg, err := LoadConfig()

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)

				// Validate AWS S3 specific configuration
				if assert.NotNil(t, cfg) {
					assert.Equal(t, "aws-s3", cfg.Storage.Provider)
					assert.Equal(t, tc.envVars["STORAGE_1_ACCESS_KEY"], cfg.Storage.AccessKeyID)
					assert.Equal(t, tc.envVars["STORAGE_1_SECRET_KEY"], cfg.Storage.SecretAccessKey)
					assert.Equal(t, tc.envVars["STORAGE_1_BUCKET"], cfg.Storage.BucketName)
					assert.True(t, cfg.Storage.UseSSL)
				}

				// Check region defaulting
				expectedRegion := tc.envVars["STORAGE_1_REGION"]
				if expectedRegion == "" {
					expectedRegion = "us-east-1"
				}
				assert.Equal(t, expectedRegion, cfg.Storage.Region)
			}
		})
	}
}

// TestServerDomainConfig verifies the resolution precedence for the OPAQUE
// server identity (idS) domain: ARKFILE_DOMAIN wins; else the BASE_URL host
// (scheme/path/port stripped); else "localhost". All OPAQUE participants must
// agree on this value, so it must be deterministic.
func TestServerDomainConfig(t *testing.T) {
	// Minimal storage env so LoadConfig() passes validation.
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
		baseURL     string // "" means unset
		wantDomain  string
	}{
		{name: "both unset falls back to localhost", domainValue: "", baseURL: "", wantDomain: "localhost"},
		{name: "ARKFILE_DOMAIN wins over BASE_URL", domainValue: "id.arkfile.net", baseURL: "https://other.example.com", wantDomain: "id.arkfile.net"},
		{name: "derives host from BASE_URL when domain unset", domainValue: "", baseURL: "https://test.arkfile.net", wantDomain: "test.arkfile.net"},
		{name: "strips port from BASE_URL host", domainValue: "", baseURL: "https://test.arkfile.net:8443", wantDomain: "test.arkfile.net"},
		{name: "configured FQDN is used verbatim", domainValue: "test.arkfile.net", baseURL: "", wantDomain: "test.arkfile.net"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetConfigForTest()

			keys := []string{"ARKFILE_DOMAIN", "BASE_URL"}
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
				ResetConfigForTest()
			}()

			for k, v := range baseEnv {
				os.Setenv(k, v)
			}
			if tc.domainValue == "" {
				os.Unsetenv("ARKFILE_DOMAIN")
			} else {
				os.Setenv("ARKFILE_DOMAIN", tc.domainValue)
			}
			if tc.baseURL == "" {
				os.Unsetenv("BASE_URL")
			} else {
				os.Setenv("BASE_URL", tc.baseURL)
			}

			cfg, err := LoadConfig()
			assert.NoError(t, err)
			assert.NotNil(t, cfg)
			assert.Equal(t, tc.wantDomain, cfg.Server.Domain)
		})
	}
}

// TestStorageProviderSupport tests that aws-s3 is recognized as a supported provider
func TestStorageProviderSupport(t *testing.T) {
	ResetConfigForTest()

	// Set up minimal valid config for each supported provider
	providers := []struct {
		name    string
		envVars map[string]string
	}{
		{
			name: "aws-s3",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "aws-s3",
				"STORAGE_1_ACCESS_KEY": "test-key",
				"STORAGE_1_SECRET_KEY": "test-secret",
				"STORAGE_1_BUCKET":     "test-bucket",
			},
		},
		{
			name: "backblaze",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "backblaze",
				"STORAGE_1_ENDPOINT":   "https://s3.us-west-002.backblazeb2.com",
				"STORAGE_1_ACCESS_KEY": "test-key",
				"STORAGE_1_SECRET_KEY": "test-secret",
				"STORAGE_1_BUCKET":     "test-bucket",
			},
		},
		{
			name: "wasabi",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "wasabi",
				"STORAGE_1_REGION":     "us-east-1",
				"STORAGE_1_ACCESS_KEY": "test-key",
				"STORAGE_1_SECRET_KEY": "test-secret",
				"STORAGE_1_BUCKET":     "test-bucket",
			},
		},
		{
			name: "vultr",
			envVars: map[string]string{
				"JWT_SECRET":           "test-jwt-secret",
				"STORAGE_PROVIDER_1":   "vultr",
				"STORAGE_1_REGION":     "ewr",
				"STORAGE_1_ACCESS_KEY": "test-key",
				"STORAGE_1_SECRET_KEY": "test-secret",
				"STORAGE_1_BUCKET":     "test-bucket",
			},
		},
	}

	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			// Reset for each test
			ResetConfigForTest()

			// Set environment variables
			originalEnv := make(map[string]string)
			for key, value := range provider.envVars {
				originalEnv[key] = os.Getenv(key)
				os.Setenv(key, value)
			}

			defer func() {
				for key, originalValue := range originalEnv {
					if originalValue == "" {
						os.Unsetenv(key)
					} else {
						os.Setenv(key, originalValue)
					}
				}
				ResetConfigForTest()
			}()

			// Load config and verify it's valid
			cfg, err := LoadConfig()
			assert.NoError(t, err, "Provider %s should be supported", provider.name)
			assert.NotNil(t, cfg)
			assert.Equal(t, provider.name, cfg.Storage.Provider)
		})
	}
}

// TestValidateProductionConfig_RejectsDevTestAPIInProduction proves A-14:
// the server must refuse to start when ENVIRONMENT=production AND
// ADMIN_DEV_TEST_API_ENABLED is truthy. ValidateProductionConfig is called
// from main.go BEFORE any handler registration, so the dev/test route group
// in handlers/route_config.go can never be wired under this combination.
func TestValidateProductionConfig_RejectsDevTestAPIInProduction(t *testing.T) {
	// Save and restore the env vars we touch so this test doesn't bleed
	// into the rest of the package.
	envKeys := []string{
		"ENVIRONMENT",
		"NODE_ENV",
		"GO_ENV",
		"ENV",
		"ADMIN_DEV_TEST_API_ENABLED",
		"ADMIN_USERNAMES",
		"ARKFILE_DOMAIN",
		// Storage envs that LoadConfig requires:
		"STORAGE_PROVIDER_1",
		"STORAGE_1_ENDPOINT",
		"STORAGE_1_ACCESS_KEY",
		"STORAGE_1_SECRET_KEY",
		"STORAGE_1_BUCKET",
	}
	originalEnv := map[string]string{}
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
		ResetConfigForTest()
	}()

	// Seed minimum-viable storage so LoadConfig() doesn't fail first.
	os.Setenv("STORAGE_PROVIDER_1", "generic-s3")
	os.Setenv("STORAGE_1_ENDPOINT", "http://localhost:9332")
	os.Setenv("STORAGE_1_ACCESS_KEY", "test")
	os.Setenv("STORAGE_1_SECRET_KEY", "test")
	os.Setenv("STORAGE_1_BUCKET", "test")
	// Use a non-dev admin username so the dev-admin check doesn't fire first.
	os.Setenv("ADMIN_USERNAMES", "real-admin")
	// Provide a real FQDN so the production domain guard passes for the
	// "allowed" cases; the dedicated domain-guard test below exercises the
	// missing/localhost paths separately.
	os.Setenv("ARKFILE_DOMAIN", "prod.arkfile.net")

	cases := []struct {
		name         string
		environment  string
		devTestValue string
		wantErrSub   string
	}{
		{
			name:         "production + dev-test API true => blocked",
			environment:  "production",
			devTestValue: "true",
			wantErrSub:   "ADMIN_DEV_TEST_API_ENABLED",
		},
		{
			name:         "production + dev-test API 1 => blocked",
			environment:  "production",
			devTestValue: "1",
			wantErrSub:   "ADMIN_DEV_TEST_API_ENABLED",
		},
		{
			name:         "production + dev-test API yes => blocked",
			environment:  "production",
			devTestValue: "yes",
			wantErrSub:   "ADMIN_DEV_TEST_API_ENABLED",
		},
		{
			name:         "production + dev-test API false => allowed",
			environment:  "production",
			devTestValue: "false",
			wantErrSub:   "", // no error expected from the A-14 path
		},
		{
			name:         "production + dev-test API unset => allowed",
			environment:  "production",
			devTestValue: "",
			wantErrSub:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset config singleton so LoadConfig sees fresh env each time.
			ResetConfigForTest()

			os.Setenv("ENVIRONMENT", tc.environment)
			if tc.devTestValue == "" {
				os.Unsetenv("ADMIN_DEV_TEST_API_ENABLED")
			} else {
				os.Setenv("ADMIN_DEV_TEST_API_ENABLED", tc.devTestValue)
			}

			err := ValidateProductionConfig()

			if tc.wantErrSub == "" {
				assert.NoError(t, err, "ValidateProductionConfig should accept env=%q devTest=%q",
					tc.environment, tc.devTestValue)
			} else {
				if err == nil {
					t.Fatalf("A-14 REGRESSION: ValidateProductionConfig accepted env=%q devTest=%q; want error containing %q",
						tc.environment, tc.devTestValue, tc.wantErrSub)
				}
				assert.Contains(t, err.Error(), tc.wantErrSub,
					"error should mention the offending env var")
			}
		})
	}
}

// TestValidateProductionConfig_RequiresDomain proves the OPAQUE idS guard:
// production must refuse to start when the resolved domain is empty or
// "localhost" (i.e. neither ARKFILE_DOMAIN nor BASE_URL was set to a real
// FQDN), and must accept a real FQDN.
func TestValidateProductionConfig_RequiresDomain(t *testing.T) {
	envKeys := []string{
		"ENVIRONMENT",
		"ADMIN_DEV_TEST_API_ENABLED",
		"ADMIN_USERNAMES",
		"ARKFILE_DOMAIN",
		"BASE_URL",
		"STORAGE_PROVIDER_1",
		"STORAGE_1_ENDPOINT",
		"STORAGE_1_ACCESS_KEY",
		"STORAGE_1_SECRET_KEY",
		"STORAGE_1_BUCKET",
	}
	originalEnv := map[string]string{}
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
		ResetConfigForTest()
	}()

	os.Setenv("ENVIRONMENT", "production")
	os.Setenv("ADMIN_DEV_TEST_API_ENABLED", "false")
	os.Setenv("ADMIN_USERNAMES", "real-admin")
	os.Setenv("STORAGE_PROVIDER_1", "generic-s3")
	os.Setenv("STORAGE_1_ENDPOINT", "http://localhost:9332")
	os.Setenv("STORAGE_1_ACCESS_KEY", "test")
	os.Setenv("STORAGE_1_SECRET_KEY", "test")
	os.Setenv("STORAGE_1_BUCKET", "test")

	cases := []struct {
		name      string
		domain    string // "" means unset
		baseURL   string // "" means unset
		wantBlock bool
	}{
		{name: "no domain or base url => blocked (localhost fallback)", domain: "", baseURL: "", wantBlock: true},
		{name: "explicit localhost => blocked", domain: "localhost", baseURL: "", wantBlock: true},
		{name: "real ARKFILE_DOMAIN => allowed", domain: "prod.arkfile.net", baseURL: "", wantBlock: false},
		{name: "real BASE_URL host => allowed", domain: "", baseURL: "https://prod.arkfile.net", wantBlock: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetConfigForTest()
			if tc.domain == "" {
				os.Unsetenv("ARKFILE_DOMAIN")
			} else {
				os.Setenv("ARKFILE_DOMAIN", tc.domain)
			}
			if tc.baseURL == "" {
				os.Unsetenv("BASE_URL")
			} else {
				os.Setenv("BASE_URL", tc.baseURL)
			}

			err := ValidateProductionConfig()
			if tc.wantBlock {
				if err == nil {
					t.Fatalf("expected production to be blocked for domain=%q baseURL=%q", tc.domain, tc.baseURL)
				}
				assert.Contains(t, err.Error(), "ARKFILE_DOMAIN")
			} else {
				assert.NoError(t, err, "production should be allowed for domain=%q baseURL=%q", tc.domain, tc.baseURL)
			}
		})
	}
}

func TestPaymentsConfigFromEnv(t *testing.T) {
	baseEnv := map[string]string{
		"JWT_SECRET":           "test-jwt-secret",
		"STORAGE_PROVIDER_1":   "generic-s3",
		"STORAGE_1_ENDPOINT":   "http://localhost:9332",
		"STORAGE_1_ACCESS_KEY": "test",
		"STORAGE_1_SECRET_KEY": "test",
		"STORAGE_1_BUCKET":     "test-bucket",
		"ARKFILE_PAYMENTS_ENABLED":       "true",
		"ARKFILE_BTCPAY_SERVER_URL":      "https://btcpay.example.com",
		"ARKFILE_BTCPAY_STORE_ID":        "store-abc",
		"ARKFILE_BTCPAY_API_KEY":         "key-xyz",
		"ARKFILE_BTCPAY_WEBHOOK_SECRET":  "whsec-test",
		"ARKFILE_MIN_TOP_UP_USD":         "1.25",
		"ARKFILE_MAX_TOP_UP_USD":         "500.00",
	}
	originalEnv := map[string]string{}
	for key := range baseEnv {
		originalEnv[key] = os.Getenv(key)
	}
	defer func() {
		for key, val := range originalEnv {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
		ResetConfigForTest()
	}()

	ResetConfigForTest()
	for key, val := range baseEnv {
		os.Setenv(key, val)
	}

	cfg, err := LoadConfig()
	assert.NoError(t, err)
	assert.True(t, cfg.Payments.Enabled)
	assert.Equal(t, "https://btcpay.example.com", cfg.Payments.BTCPayServerURL)
	assert.Equal(t, "store-abc", cfg.Payments.BTCPayStoreID)
	assert.Equal(t, "key-xyz", cfg.Payments.BTCPayAPIKey)
	assert.Equal(t, "whsec-test", cfg.Payments.BTCPayWebhookSecret)
	assert.Equal(t, "1.25", cfg.Payments.MinTopUpUSD)
	assert.Equal(t, "500.00", cfg.Payments.MaxTopUpUSD)
}
