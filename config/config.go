package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

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
		JWTSecret         string   `json:"jwt_secret"`
		JWTExpiryHours    int      `json:"jwt_expiry_hours"`
		PasswordMinLength int      `json:"password_min_length"`
		BcryptCost        int      `json:"bcrypt_cost"`
		MaxFileSize       int64    `json:"max_file_size"`
		AllowedFileTypes  []string `json:"allowed_file_types"`
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
	cfg.Security.PasswordMinLength = 8
	cfg.Security.BcryptCost = 12
	cfg.Security.MaxFileSize = 100 * 1024 * 1024 // 100MB
	cfg.Security.AllowedFileTypes = []string{".jpg", ".jpeg", ".png", ".pdf", ".iso"}
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
