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
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "aws-s3",
				"S3_REGION":        "us-west-2",
				"S3_ACCESS_KEY":    "AKIAIOSFODNN7EXAMPLE",
				"S3_SECRET_KEY":    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"S3_BUCKET":        "arkfile-test-bucket",
			},
			expectError: false,
		},
		{
			name: "AWS S3 with default region",
			envVars: map[string]string{
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "aws-s3",
				"S3_ACCESS_KEY":    "AKIAIOSFODNN7EXAMPLE",
				"S3_SECRET_KEY":    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"S3_BUCKET":        "arkfile-test-bucket",
				// S3_REGION not set - should default to us-east-1
			},
			expectError: false,
		},
		{
			name: "AWS S3 missing access key",
			envVars: map[string]string{
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "aws-s3",
				"S3_REGION":        "us-west-2",
				"S3_SECRET_KEY":    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"S3_BUCKET":        "arkfile-test-bucket",
				// S3_ACCESS_KEY missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires",
		},
		{
			name: "AWS S3 missing secret key",
			envVars: map[string]string{
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "aws-s3",
				"S3_REGION":        "us-west-2",
				"S3_ACCESS_KEY":    "AKIAIOSFODNN7EXAMPLE",
				"S3_BUCKET":        "arkfile-test-bucket",
				// S3_SECRET_KEY missing
			},
			expectError: true,
			errorMsg:    "AWS S3 storage requires",
		},
		{
			name: "AWS S3 missing bucket name",
			envVars: map[string]string{
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "aws-s3",
				"S3_REGION":        "us-west-2",
				"S3_ACCESS_KEY":    "AKIAIOSFODNN7EXAMPLE",
				"S3_SECRET_KEY":    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				// S3_BUCKET missing
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
				assert.Equal(t, "aws-s3", cfg.Storage.Provider)
				assert.Equal(t, tc.envVars["S3_ACCESS_KEY"], cfg.Storage.AccessKeyID)
				assert.Equal(t, tc.envVars["S3_SECRET_KEY"], cfg.Storage.SecretAccessKey)
				assert.Equal(t, tc.envVars["S3_BUCKET"], cfg.Storage.BucketName)
				assert.True(t, cfg.Storage.UseSSL)

				// Check region defaulting
				expectedRegion := tc.envVars["S3_REGION"]
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
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "aws-s3",
				"S3_ACCESS_KEY":    "test-key",
				"S3_SECRET_KEY":    "test-secret",
				"S3_BUCKET":        "test-bucket",
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
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "wasabi",
				"S3_REGION":        "us-east-1",
				"S3_ACCESS_KEY":    "test-key",
				"S3_SECRET_KEY":    "test-secret",
				"S3_BUCKET":        "test-bucket",
			},
		},
		{
			name: "vultr",
			envVars: map[string]string{
				"JWT_SECRET":       "test-jwt-secret",
				"STORAGE_PROVIDER": "vultr",
				"S3_REGION":        "ewr",
				"S3_ACCESS_KEY":    "test-key",
				"S3_SECRET_KEY":    "test-secret",
				"S3_BUCKET":        "test-bucket",
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
