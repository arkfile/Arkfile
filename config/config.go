package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var (
	config     *Config
	configOnce sync.Once
)

type Config struct {
	Server struct {
		Port       string `json:"port"`
		TLSPort    string `json:"tls_port"`
		Host       string `json:"host"`
		BaseURL    string `json:"base_url"`
		LogLevel   string `json:"log_level"`
		TLSEnabled bool   `json:"tls_enabled"`
	} `json:"server"`

	Database struct {
		Path string `json:"path"`
	} `json:"database"`

	Storage struct {
		Provider        string `json:"provider"` // "local", "backblaze", "wasabi", "vultr", "cluster"
		Endpoint        string `json:"endpoint"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		BucketName      string `json:"bucket_name"`
		Region          string `json:"region"`
		UseSSL          bool   `json:"use_ssl"`
		LocalPath       string `json:"local_path"` // For local provider
	} `json:"storage"`

	Security struct {
		JWTSecret               string        `json:"jwt_secret"`
		JWTExpiryHours          int           `json:"jwt_expiry_hours"`
		RefreshTokenDuration    time.Duration `json:"refresh_token_duration"`
		RefreshTokenCookieName  string        `json:"refresh_token_cookie_name"`
		RevokeUsedRefreshTokens bool          `json:"revoke_used_refresh_tokens"`
		PasswordMinLength       int           `json:"password_min_length"`
		MaxFileSize             int64         `json:"max_file_size"`
		AllowedFileTypes        []string      `json:"allowed_file_types"`

		// Server-side Argon2ID configuration (for user authentication)
		ServerArgon2ID struct {
			Time    uint32 `json:"time"`    // iterations
			Memory  uint32 `json:"memory"`  // KB
			Threads uint8  `json:"threads"` // parallelism
		} `json:"server_argon2id"`

		// Client-side Argon2ID configuration (for file encryption)
		ClientArgon2ID struct {
			Time    uint32 `json:"time"`    // iterations
			Memory  uint32 `json:"memory"`  // KB
			Threads uint8  `json:"threads"` // parallelism
		} `json:"client_argon2id"`
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
		Environment       string `json:"environment"`
		DataDirectory     string `json:"data_directory"`
		LogDirectory      string `json:"log_directory"`
		AdminContact      string `json:"admin_contact"`
		MaintenanceWindow string `json:"maintenance_window"`
		BackupRetention   int    `json:"backup_retention_days"`
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
	cfg.Server.Host = "localhost"
	cfg.Database.Path = "./arkfile.db"
	cfg.Security.JWTExpiryHours = 72
	cfg.Security.RefreshTokenDuration = 24 * 7 * time.Hour // Default to 7 days
	cfg.Security.RefreshTokenCookieName = "refreshToken"
	cfg.Security.RevokeUsedRefreshTokens = true
	cfg.Security.PasswordMinLength = 8
	cfg.Security.MaxFileSize = 100 * 1024 * 1024 // 100MB
	cfg.Security.AllowedFileTypes = []string{".jpg", ".jpeg", ".png", ".pdf", ".iso"}

	// Server-side Argon2ID defaults (optimized for server performance)
	cfg.Security.ServerArgon2ID.Time = 4
	cfg.Security.ServerArgon2ID.Memory = 131072 // 128MB
	cfg.Security.ServerArgon2ID.Threads = 4

	// Client-side Argon2ID defaults (optimized for broad device compatibility)
	cfg.Security.ClientArgon2ID.Time = 4
	cfg.Security.ClientArgon2ID.Memory = 131072 // 128MB
	cfg.Security.ClientArgon2ID.Threads = 4

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
	if tlsEnabled := os.Getenv("TLS_ENABLED"); tlsEnabled != "" {
		if enabled, err := strconv.ParseBool(tlsEnabled); err == nil {
			cfg.Server.TLSEnabled = enabled
		}
	}

	// Storage configuration
	cfg.Storage.Provider = os.Getenv("STORAGE_PROVIDER")
	if cfg.Storage.Provider == "" {
		cfg.Storage.Provider = "local" // Default to local storage
	}

	// Map environment variables based on provider
	switch cfg.Storage.Provider {
	case "local":
		cfg.Storage.AccessKeyID = os.Getenv("MINIO_ROOT_USER")
		cfg.Storage.SecretAccessKey = os.Getenv("MINIO_ROOT_PASSWORD")
		cfg.Storage.LocalPath = os.Getenv("LOCAL_STORAGE_PATH")
		cfg.Storage.BucketName = "arkfile" // Default bucket name for local
		cfg.Storage.UseSSL = false
		cfg.Storage.Endpoint = "localhost:9000"
	case "backblaze":
		cfg.Storage.Endpoint = os.Getenv("BACKBLAZE_ENDPOINT")
		cfg.Storage.AccessKeyID = os.Getenv("BACKBLAZE_KEY_ID")
		cfg.Storage.SecretAccessKey = os.Getenv("BACKBLAZE_APPLICATION_KEY")
		cfg.Storage.BucketName = os.Getenv("BACKBLAZE_BUCKET_NAME")
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
	case "cluster":
		cfg.Storage.Endpoint = os.Getenv("MINIO_CLUSTER_NODES")
		cfg.Storage.AccessKeyID = os.Getenv("MINIO_CLUSTER_ACCESS_KEY")
		cfg.Storage.SecretAccessKey = os.Getenv("MINIO_CLUSTER_SECRET_KEY")
		cfg.Storage.BucketName = os.Getenv("MINIO_CLUSTER_BUCKET")
		cfg.Storage.UseSSL = true
	}

	// Generic overrides
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

	// Security configuration
	cfg.Security.JWTSecret = os.Getenv("JWT_SECRET")
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

	// Server-side Argon2ID overrides
	if serverTime := os.Getenv("SERVER_ARGON2ID_TIME"); serverTime != "" {
		if timeInt, err := strconv.ParseUint(serverTime, 10, 32); err == nil {
			cfg.Security.ServerArgon2ID.Time = uint32(timeInt)
		}
	}
	if serverMemory := os.Getenv("SERVER_ARGON2ID_MEMORY"); serverMemory != "" {
		if memoryInt, err := strconv.ParseUint(serverMemory, 10, 32); err == nil {
			cfg.Security.ServerArgon2ID.Memory = uint32(memoryInt)
		}
	}
	if serverThreads := os.Getenv("SERVER_ARGON2ID_THREADS"); serverThreads != "" {
		if threadsInt, err := strconv.ParseUint(serverThreads, 10, 8); err == nil {
			cfg.Security.ServerArgon2ID.Threads = uint8(threadsInt)
		}
	}

	// Client-side Argon2ID overrides
	if clientTime := os.Getenv("CLIENT_ARGON2ID_TIME"); clientTime != "" {
		if timeInt, err := strconv.ParseUint(clientTime, 10, 32); err == nil {
			cfg.Security.ClientArgon2ID.Time = uint32(timeInt)
		}
	}
	if clientMemory := os.Getenv("CLIENT_ARGON2ID_MEMORY"); clientMemory != "" {
		if memoryInt, err := strconv.ParseUint(clientMemory, 10, 32); err == nil {
			cfg.Security.ClientArgon2ID.Memory = uint32(memoryInt)
		}
	}
	if clientThreads := os.Getenv("CLIENT_ARGON2ID_THREADS"); clientThreads != "" {
		if threadsInt, err := strconv.ParseUint(clientThreads, 10, 8); err == nil {
			cfg.Security.ClientArgon2ID.Threads = uint8(threadsInt)
		}
	}

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
	if cfg.Security.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}

	// Validate storage configuration based on provider
	switch cfg.Storage.Provider {
	case "local":
		if cfg.Storage.AccessKeyID == "" || cfg.Storage.SecretAccessKey == "" {
			return fmt.Errorf("local storage requires MINIO_ROOT_USER and MINIO_ROOT_PASSWORD")
		}
		if cfg.Storage.LocalPath == "" {
			return fmt.Errorf("local storage requires LOCAL_STORAGE_PATH")
		}
	case "backblaze":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("Backblaze storage requires endpoint, access key, secret key, and bucket name")
		}
	case "wasabi", "vultr":
		if cfg.Storage.AccessKeyID == "" || cfg.Storage.SecretAccessKey == "" ||
			cfg.Storage.BucketName == "" || cfg.Storage.Region == "" {
			return fmt.Errorf("%s storage requires access key, secret key, bucket name, and region", cfg.Storage.Provider)
		}
	case "cluster":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("cluster storage requires endpoint, access key, secret key, and bucket name")
		}
	default:
		return fmt.Errorf("unsupported storage provider: %s", cfg.Storage.Provider)
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
