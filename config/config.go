package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"

	"github.com/84adam/Arkfile/utils"
)

var (
	config     *Config
	configOnce sync.Once
)

type Config struct {
	Server struct {
		Port           string   `json:"port"`
		TLSPort        string   `json:"tls_port"`
		Host           string   `json:"host"`
		BaseURL        string   `json:"base_url"`
		LogLevel       string   `json:"log_level"`
		TLSEnabled     bool     `json:"tls_enabled"`
		AllowedOrigins []string `json:"allowed_origins"`
	} `json:"server"`

	Database struct {
		Path string `json:"path"`
	} `json:"database"`

	Storage struct {
		Provider        string `json:"provider"` // "generic-s3", "backblaze", "wasabi", "vultr", "aws-s3"
		Endpoint        string `json:"endpoint"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		BucketName      string `json:"bucket_name"`
		Region          string `json:"region"`
		UseSSL          bool   `json:"use_ssl"`
		ForcePathStyle  bool   `json:"force_path_style"` // Required for many self-hosted S3 (MinIO, SeaweedFS, Ceph)
	} `json:"storage"`

	Security struct {
		JWTPrivateKeyPath       string        `json:"jwt_private_key_path"`
		JWTPublicKeyPath        string        `json:"jwt_public_key_path"`
		JWTExpiryHours          int           `json:"jwt_expiry_hours"`
		RefreshTokenDuration    time.Duration `json:"refresh_token_duration"`
		RefreshTokenCookieName  string        `json:"refresh_token_cookie_name"`
		RevokeUsedRefreshTokens bool          `json:"revoke_used_refresh_tokens"`

		// Argon2ID configuration removed - using OPAQUE-only authentication
	} `json:"security"`

	Logging struct {
		Directory  string `json:"directory"`
		MaxSize    int64  `json:"max_size"`
		MaxBackups int    `json:"max_backups"`
	} `json:"logging"`

	KeyManagement struct {
		KeyDirectory     string `json:"key_directory"`
		OPAQUEKeyPath    string `json:"opaque_key_path"`
		JWTKeyPath       string `json:"jwt_key_path"`
		TLSCertPath      string `json:"tls_cert_path"`
		UseSystemdCreds  bool   `json:"use_systemd_creds"`
		BackupDirectory  string `json:"backup_directory"`
		RotationSchedule string `json:"rotation_schedule"`
	} `json:"key_management"`

	Deployment struct {
		Environment       string   `json:"environment"`
		DataDirectory     string   `json:"data_directory"`
		LogDirectory      string   `json:"log_directory"`
		AdminContact      string   `json:"admin_contact"`
		AdminUsernames    []string `json:"admin_usernames"`
		RequireApproval   bool     `json:"require_approval"`
		MaintenanceWindow string   `json:"maintenance_window"`
		BackupRetention   int      `json:"backup_retention_days"`
	} `json:"deployment"`
}

// LoadConfig loads the configuration from environment variables and optional JSON file
func LoadConfig() (*Config, error) {
	var err error
	configOnce.Do(func() {
		config = &Config{}

		// Load .env file if it exists
		godotenv.Load()

		// Load default configuration
		if err = loadDefaultConfig(config); err != nil {
			return
		}

		// Override with environment variables
		if err = loadEnvConfig(config); err != nil {
			return
		}

		// Load JSON config if specified
		configPath := os.Getenv("CONFIG_FILE")
		if configPath != "" {
			if err = loadJSONConfig(config, configPath); err != nil {
				return
			}
		}

		// Validate configuration
		if err = validateConfig(config); err != nil {
			return
		}
	})

	if err != nil {
		return nil, err
	}

	return config, nil
}

func loadDefaultConfig(cfg *Config) error {
	// Set default values
	cfg.Server.Port = "8080"
	cfg.Server.TLSPort = "8443"
	cfg.Server.Host = "localhost"
	cfg.Server.AllowedOrigins = []string{"http://localhost:8080", "https://localhost:8443"}
	cfg.Database.Path = "./arkfile.db"
	cfg.Security.JWTPrivateKeyPath = "/opt/arkfile/etc/keys/jwt/current/signing.key"
	cfg.Security.JWTPublicKeyPath = "/opt/arkfile/etc/keys/jwt/current/public.key"
	cfg.Security.JWTExpiryHours = 72
	cfg.Security.RefreshTokenDuration = 24 * 7 * time.Hour // Default to 7 days
	cfg.Security.RefreshTokenCookieName = "refreshToken"
	cfg.Security.RevokeUsedRefreshTokens = true

	// Argon2ID defaults removed - using OPAQUE-only authentication

	cfg.Logging.Directory = "logs"
	cfg.Logging.MaxSize = 10 * 1024 * 1024 // 10MB
	cfg.Logging.MaxBackups = 5

	// Key management defaults
	cfg.KeyManagement.KeyDirectory = "/opt/arkfile/etc/keys"
	cfg.KeyManagement.OPAQUEKeyPath = "opaque/server_private.key"
	cfg.KeyManagement.JWTKeyPath = "jwt/current/signing.key"
	cfg.KeyManagement.TLSCertPath = "tls/server.crt"
	cfg.KeyManagement.UseSystemdCreds = true
	cfg.KeyManagement.BackupDirectory = "/opt/arkfile/etc/keys/backups"
	cfg.KeyManagement.RotationSchedule = "30d"

	// Deployment defaults
	cfg.Deployment.Environment = "development"
	cfg.Deployment.DataDirectory = "/opt/arkfile/var/lib"
	cfg.Deployment.LogDirectory = "/opt/arkfile/var/log"
	cfg.Deployment.BackupRetention = 30

	return nil
}

func loadEnvConfig(cfg *Config) error {
	// Server configuration
	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Port = port
	}
	if tlsPort := os.Getenv("TLS_PORT"); tlsPort != "" {
		cfg.Server.TLSPort = tlsPort
	}
	if host := os.Getenv("HOST"); host != "" {
		cfg.Server.Host = host
	}
	if baseURL := os.Getenv("BASE_URL"); baseURL != "" {
		cfg.Server.BaseURL = baseURL
	}
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		cfg.Server.LogLevel = logLevel
	}
	if tlsEnabled := os.Getenv("TLS_ENABLED"); tlsEnabled != "" {
		if enabled, err := strconv.ParseBool(tlsEnabled); err == nil {
			cfg.Server.TLSEnabled = enabled
		}
	}

	if allowedOrigins := os.Getenv("CORS_ALLOWED_ORIGINS"); allowedOrigins != "" {
		// Parse comma-separated list of allowed origins
		origins := strings.Split(allowedOrigins, ",")
		cfg.Server.AllowedOrigins = make([]string, 0, len(origins))
		for _, origin := range origins {
			if trimmed := strings.TrimSpace(origin); trimmed != "" {
				cfg.Server.AllowedOrigins = append(cfg.Server.AllowedOrigins, trimmed)
			}
		}
	}

	// Storage configuration
	cfg.Storage.Provider = os.Getenv("STORAGE_PROVIDER")
	if cfg.Storage.Provider == "" {
		cfg.Storage.Provider = "generic-s3" // Default to generic S3 (works for local/cluster/etc)
	}

	// Map environment variables based on provider
	switch cfg.Storage.Provider {
	case "generic-s3":
		cfg.Storage.Endpoint = os.Getenv("S3_ENDPOINT")
		cfg.Storage.AccessKeyID = os.Getenv("S3_ACCESS_KEY")
		cfg.Storage.SecretAccessKey = os.Getenv("S3_SECRET_KEY")
		cfg.Storage.BucketName = os.Getenv("S3_BUCKET")
		cfg.Storage.Region = os.Getenv("S3_REGION")
		if cfg.Storage.Region == "" {
			cfg.Storage.Region = "us-east-1" // Default region
		}

		// Default to path style for generic S3 (safer for self-hosted)
		cfg.Storage.ForcePathStyle = true
		if forcePathStyle := os.Getenv("S3_FORCE_PATH_STYLE"); forcePathStyle != "" {
			if val, err := strconv.ParseBool(forcePathStyle); err == nil {
				cfg.Storage.ForcePathStyle = val
			}
		}

		// SSL defaults to true, but can be disabled (e.g. for local dev)
		cfg.Storage.UseSSL = true
		if useSSL := os.Getenv("S3_USE_SSL"); useSSL != "" {
			if val, err := strconv.ParseBool(useSSL); err == nil {
				cfg.Storage.UseSSL = val
			}
		}

	case "backblaze":
		cfg.Storage.Endpoint = os.Getenv("BACKBLAZE_ENDPOINT")
		cfg.Storage.AccessKeyID = os.Getenv("BACKBLAZE_KEY_ID")
		cfg.Storage.SecretAccessKey = os.Getenv("BACKBLAZE_APPLICATION_KEY")
		cfg.Storage.BucketName = os.Getenv("BACKBLAZE_BUCKET_NAME")
		cfg.Storage.UseSSL = true
	case "cloudflare-r2":
		cfg.Storage.Endpoint = os.Getenv("CLOUDFLARE_ENDPOINT")
		cfg.Storage.AccessKeyID = os.Getenv("CLOUDFLARE_ACCESS_KEY_ID")
		cfg.Storage.SecretAccessKey = os.Getenv("CLOUDFLARE_SECRET_ACCESS_KEY")
		cfg.Storage.BucketName = os.Getenv("CLOUDFLARE_BUCKET_NAME")
		cfg.Storage.UseSSL = true
	case "wasabi":
		cfg.Storage.Region = os.Getenv("WASABI_REGION")
		cfg.Storage.AccessKeyID = os.Getenv("WASABI_ACCESS_KEY_ID")
		cfg.Storage.SecretAccessKey = os.Getenv("WASABI_SECRET_ACCESS_KEY")
		cfg.Storage.BucketName = os.Getenv("WASABI_BUCKET_NAME")
		cfg.Storage.UseSSL = true
	case "vultr":
		cfg.Storage.Region = os.Getenv("VULTR_REGION")
		cfg.Storage.AccessKeyID = os.Getenv("VULTR_ACCESS_KEY_ID")
		cfg.Storage.SecretAccessKey = os.Getenv("VULTR_SECRET_ACCESS_KEY")
		cfg.Storage.BucketName = os.Getenv("VULTR_BUCKET_NAME")
		cfg.Storage.UseSSL = true
	case "aws-s3":
		cfg.Storage.Region = os.Getenv("AWS_REGION")
		cfg.Storage.AccessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
		cfg.Storage.SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		cfg.Storage.BucketName = os.Getenv("AWS_S3_BUCKET_NAME")
		cfg.Storage.UseSSL = true
		// Default to us-east-1 if no region specified
		if cfg.Storage.Region == "" {
			cfg.Storage.Region = "us-east-1"
		}
	}

	// Generic overrides (still useful for quick overrides)
	if endpoint := os.Getenv("STORAGE_ENDPOINT"); endpoint != "" {
		cfg.Storage.Endpoint = endpoint
	}
	if accessKey := os.Getenv("STORAGE_ACCESS_KEY_ID"); accessKey != "" {
		cfg.Storage.AccessKeyID = accessKey
	}
	if secretKey := os.Getenv("STORAGE_SECRET_ACCESS_KEY"); secretKey != "" {
		cfg.Storage.SecretAccessKey = secretKey
	}
	if bucketName := os.Getenv("STORAGE_BUCKET_NAME"); bucketName != "" {
		cfg.Storage.BucketName = bucketName
	}
	if region := os.Getenv("STORAGE_REGION"); region != "" {
		cfg.Storage.Region = region
	}

	// Security configuration - Ed25519 key paths can be overridden via environment
	if jwtPrivateKeyPath := os.Getenv("JWT_PRIVATE_KEY_PATH"); jwtPrivateKeyPath != "" {
		cfg.Security.JWTPrivateKeyPath = jwtPrivateKeyPath
	}
	if jwtPublicKeyPath := os.Getenv("JWT_PUBLIC_KEY_PATH"); jwtPublicKeyPath != "" {
		cfg.Security.JWTPublicKeyPath = jwtPublicKeyPath
	}
	if rtExpiryStr := os.Getenv("REFRESH_TOKEN_EXPIRY_HOURS"); rtExpiryStr != "" {
		if rtExpiryInt, err := strconv.Atoi(rtExpiryStr); err == nil {
			cfg.Security.RefreshTokenDuration = time.Duration(rtExpiryInt) * time.Hour
		}
	}
	if rtCookieName := os.Getenv("REFRESH_TOKEN_COOKIE_NAME"); rtCookieName != "" {
		cfg.Security.RefreshTokenCookieName = rtCookieName
	}
	if revokeStr := os.Getenv("REVOKE_USED_REFRESH_TOKENS"); revokeStr != "" {
		if revokeBool, err := strconv.ParseBool(revokeStr); err == nil {
			cfg.Security.RevokeUsedRefreshTokens = revokeBool
		}
	}

	// Argon2ID environment overrides removed - using OPAQUE-only authentication

	// Key management environment overrides
	if keyDir := os.Getenv("ARKFILE_KEY_DIRECTORY"); keyDir != "" {
		cfg.KeyManagement.KeyDirectory = keyDir
	}
	if useSystemdCreds := os.Getenv("ARKFILE_USE_SYSTEMD_CREDS"); useSystemdCreds != "" {
		if useCreds, err := strconv.ParseBool(useSystemdCreds); err == nil {
			cfg.KeyManagement.UseSystemdCreds = useCreds
		}
	}

	// Deployment environment overrides
	if env := os.Getenv("ARKFILE_ENV"); env != "" {
		cfg.Deployment.Environment = env
	}
	if dataDir := os.Getenv("ARKFILE_DATA_DIRECTORY"); dataDir != "" {
		cfg.Deployment.DataDirectory = dataDir
	}
	if logDir := os.Getenv("ARKFILE_LOG_DIRECTORY"); logDir != "" {
		cfg.Deployment.LogDirectory = logDir
	}
	if adminContact := os.Getenv("ARKFILE_ADMIN_CONTACT"); adminContact != "" {
		cfg.Deployment.AdminContact = adminContact
	}

	// Admin usernames configuration
	if adminUsernames := os.Getenv("ADMIN_USERNAMES"); adminUsernames != "" {
		// Parse comma-separated list of admin usernames
		usernames := strings.Split(adminUsernames, ",")
		cfg.Deployment.AdminUsernames = make([]string, 0, len(usernames))
		for _, username := range usernames {
			if trimmed := strings.TrimSpace(username); trimmed != "" {
				cfg.Deployment.AdminUsernames = append(cfg.Deployment.AdminUsernames, trimmed)
			}
		}
	}

	// Require approval configuration
	if requireApproval := os.Getenv("REQUIRE_APPROVAL"); requireApproval != "" {
		if approval, err := strconv.ParseBool(requireApproval); err == nil {
			cfg.Deployment.RequireApproval = approval
		}
	}

	return nil
}

func loadJSONConfig(cfg *Config, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}

	return nil
}

func validateConfig(cfg *Config) error {
	// Validate JWT Ed25519 key paths
	if cfg.Security.JWTPrivateKeyPath == "" {
		return fmt.Errorf("JWT_PRIVATE_KEY_PATH is required")
	}
	if cfg.Security.JWTPublicKeyPath == "" {
		return fmt.Errorf("JWT_PUBLIC_KEY_PATH is required")
	}

	// Validate storage configuration based on provider
	switch cfg.Storage.Provider {
	case "generic-s3":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("generic-s3 storage requires S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, and S3_BUCKET")
		}
	case "backblaze":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("Backblaze storage requires endpoint, access key, secret key, and bucket name")
		}
	case "cloudflare-r2":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("Cloudflare R2 storage requires endpoint, access key, secret key, and bucket name")
		}
	case "wasabi", "vultr":
		if cfg.Storage.AccessKeyID == "" || cfg.Storage.SecretAccessKey == "" ||
			cfg.Storage.BucketName == "" || cfg.Storage.Region == "" {
			return fmt.Errorf("%s storage requires access key, secret key, bucket name, and region", cfg.Storage.Provider)
		}
	case "aws-s3":
		if cfg.Storage.AccessKeyID == "" || cfg.Storage.SecretAccessKey == "" ||
			cfg.Storage.BucketName == "" {
			return fmt.Errorf("AWS S3 storage requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_S3_BUCKET_NAME")
		}
		// Region validation for AWS S3 - should have been defaulted to us-east-1 if not provided
		if cfg.Storage.Region == "" {
			return fmt.Errorf("AWS S3 storage requires a valid region")
		}
	default:
		return fmt.Errorf("unsupported storage provider: %s", cfg.Storage.Provider)
	}

	return nil
}

// ValidateProductionConfig validates that the configuration is safe for production
func ValidateProductionConfig() error {
	if utils.IsProductionEnvironment() {
		// Get admin usernames from configuration
		cfg, err := LoadConfig()
		if err != nil {
			return fmt.Errorf("failed to load config for production validation: %w", err)
		}

		// Check for dev admin accounts in configuration
		for _, adminUsername := range cfg.Deployment.AdminUsernames {
			if utils.IsDevAdminAccount(adminUsername) {
				return fmt.Errorf("FATAL: Dev admin account '%s' found in production ADMIN_USERNAMES - deployment blocked", adminUsername)
			}
		}

		// Also check environment variable directly as a backup
		adminUsernames := os.Getenv("ADMIN_USERNAMES")
		if adminUsernames != "" {
			for _, adminUsername := range strings.Split(adminUsernames, ",") {
				adminUsername = strings.TrimSpace(adminUsername)
				if utils.IsDevAdminAccount(adminUsername) {
					return fmt.Errorf("FATAL: Dev admin account '%s' found in production ADMIN_USERNAMES environment variable - deployment blocked", adminUsername)
				}
			}
		}
	}

	return nil
}

// GetConfig returns the current configuration
func GetConfig() *Config {
	if config == nil {
		panic("Configuration not loaded")
	}
	return config
}

// Testing helper - DO NOT USE IN PRODUCTION
// ResetConfigForTest resets the sync.Once and config variable for testing purposes.
// This allows LoadConfig to be called again with potentially different env vars in tests.
func ResetConfigForTest() {
	configOnce = sync.Once{}
	config = nil
}
