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
		Port     string `json:"port"`
		Host     string `json:"host"`
		BaseURL  string `json:"base_url"`
		LogLevel string `json:"log_level"`
	} `json:"server"`

	Database struct {
		Path string `json:"path"`
	} `json:"database"`

	Storage struct {
		BackblazeEndpoint string `json:"backblaze_endpoint"`
		BackblazeKeyID    string `json:"backblaze_key_id"`
		BackblazeAppKey   string `json:"backblaze_app_key"`
		BucketName        string `json:"bucket_name"`
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

	return nil
}

func loadEnvConfig(cfg *Config) error {
	// Server configuration
	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Port = port
	}
	if host := os.Getenv("HOST"); host != "" {
		cfg.Server.Host = host
	}
	if baseURL := os.Getenv("BASE_URL"); baseURL != "" {
		cfg.Server.BaseURL = baseURL
	}

	// Storage configuration
	cfg.Storage.BackblazeEndpoint = os.Getenv("BACKBLAZE_ENDPOINT")
	cfg.Storage.BackblazeKeyID = os.Getenv("BACKBLAZE_KEY_ID")
	cfg.Storage.BackblazeAppKey = os.Getenv("BACKBLAZE_APPLICATION_KEY")
	cfg.Storage.BucketName = os.Getenv("BACKBLAZE_BUCKET_NAME")

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

	if cfg.Storage.BackblazeEndpoint == "" ||
		cfg.Storage.BackblazeKeyID == "" ||
		cfg.Storage.BackblazeAppKey == "" ||
		cfg.Storage.BucketName == "" {
		return fmt.Errorf("Backblaze configuration is incomplete")
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
