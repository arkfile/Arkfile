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
				"JWT_SECRET":            "test-jwt-secret",
				"STORAGE_PROVIDER":      "aws-s3",
				"AWS_REGION":            "us-west-2",
				"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
				"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"AWS_S3_BUCKET_NAME":    "arkfile-test-bucket",
			},
			expectError: false,
		},
		{
			name: "AWS S3 with default region",
			envVars: map[string]string{
				"JWT_SECRET":            "test-jwt-secret",
				"STORAGE_PROVIDER":      "aws-s3",
				"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
				"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"AWS_S3_BUCKET_NAME":    "arkfile-test-bucket",
				// AWS_REGION not set - should default to us-east-1
			},
			expectError: false,
		},
		{
			name: "AWS S3 missing access key",
			envVars: map[string]string{
				"JWT_SECRET":            "test-jwt-secret",
				"STORAGE_PROVIDER":      "aws-s3",
				"AWS_REGION":            "us-west-2",
				"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"AWS_S3_BUCKET_NAME":    "arkfile-test-bucket",
				// AWS_ACCESS_KEY_ID missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_S3_BUCKET_NAME",
		},
		{
			name: "AWS S3 missing secret key",
			envVars: map[string]string{
				"JWT_SECRET":         "test-jwt-secret",
				"STORAGE_PROVIDER":   "aws-s3",
				"AWS_REGION":         "us-west-2",
				"AWS_ACCESS_KEY_ID":  "AKIAIOSFODNN7EXAMPLE",
				"AWS_S3_BUCKET_NAME": "arkfile-test-bucket",
				// AWS_SECRET_ACCESS_KEY missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_S3_BUCKET_NAME",
		},
		{
			name: "AWS S3 missing bucket name",
			envVars: map[string]string{
				"JWT_SECRET":            "test-jwt-secret",
				"STORAGE_PROVIDER":      "aws-s3",
				"AWS_REGION":            "us-west-2",
				"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
				"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				// AWS_S3_BUCKET_NAME missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_S3_BUCKET_NAME",
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
				assert.Equal(t, "aws-s3", cfg.Storage.Provider)
				assert.Equal(t, tc.envVars["AWS_ACCESS_KEY_ID"], cfg.Storage.AccessKeyID)
				assert.Equal(t, tc.envVars["AWS_SECRET_ACCESS_KEY"], cfg.Storage.SecretAccessKey)
				assert.Equal(t, tc.envVars["AWS_S3_BUCKET_NAME"], cfg.Storage.BucketName)
				assert.True(t, cfg.Storage.UseSSL)

				// Check region defaulting
				expectedRegion := tc.envVars["AWS_REGION"]
				if expectedRegion == "" {
					expectedRegion = "us-east-1"
				}
				assert.Equal(t, expectedRegion, cfg.Storage.Region)
			}
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
				"JWT_SECRET":            "test-jwt-secret",
				"STORAGE_PROVIDER":      "aws-s3",
				"AWS_ACCESS_KEY_ID":     "test-key",
				"AWS_SECRET_ACCESS_KEY": "test-secret",
				"AWS_S3_BUCKET_NAME":    "test-bucket",
			},
		},
		{
			name: "backblaze",
			envVars: map[string]string{
				"JWT_SECRET":                "test-jwt-secret",
				"STORAGE_PROVIDER":          "backblaze",
				"BACKBLAZE_ENDPOINT":        "s3.us-west-002.backblazeb2.com",
				"BACKBLAZE_KEY_ID":          "test-key",
				"BACKBLAZE_APPLICATION_KEY": "test-secret",
				"BACKBLAZE_BUCKET_NAME":     "test-bucket",
			},
		},
		{
			name: "wasabi",
			envVars: map[string]string{
				"JWT_SECRET":               "test-jwt-secret",
				"STORAGE_PROVIDER":         "wasabi",
				"WASABI_REGION":            "us-east-1",
				"WASABI_ACCESS_KEY_ID":     "test-key",
				"WASABI_SECRET_ACCESS_KEY": "test-secret",
				"WASABI_BUCKET_NAME":       "test-bucket",
			},
		},
		{
			name: "vultr",
			envVars: map[string]string{
				"JWT_SECRET":              "test-jwt-secret",
				"STORAGE_PROVIDER":        "vultr",
				"VULTR_REGION":            "ewr",
				"VULTR_ACCESS_KEY_ID":     "test-key",
				"VULTR_SECRET_ACCESS_KEY": "test-secret",
				"VULTR_BUCKET_NAME":       "test-bucket",
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
