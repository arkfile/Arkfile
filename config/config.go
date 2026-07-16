package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"

	"github.com/arkfile/Arkfile/money"
	"github.com/arkfile/Arkfile/subbridge"
	"github.com/arkfile/Arkfile/utils"
)

// hostFromBaseURL extracts the bare hostname from a BASE_URL value, stripping
// the scheme, any path, and any :port. Returns "" if no host can be parsed.
// Examples:
//
//	"https://test.arkfile.net"      -> "test.arkfile.net"
//	"https://test.arkfile.net:8443" -> "test.arkfile.net"
//	"test.arkfile.net"              -> "test.arkfile.net"
func hostFromBaseURL(baseURL string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return ""
	}
	// url.Parse only populates Host when a scheme is present; add one if needed.
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

var (
	config     *Config
	configOnce sync.Once
)

type Config struct {
	Server struct {
		Port    string `json:"port"`
		TLSPort string `json:"tls_port"`
		Host    string `json:"host"`
		BaseURL string `json:"base_url"`
		// Domain is the deployment FQDN bound into the OPAQUE server identity
		// (idS). All OPAQUE clients (browser, CLI) must use the exact same value
		// or authentication fails, so it is sourced from this single server
		// config and served to clients via /api/config/opaque. Resolved from
		// ARKFILE_DOMAIN, else the BASE_URL host, else "localhost" (see
		// loadEnvConfig). Production deployments must resolve to a real FQDN;
		// ValidateProductionConfig fails closed otherwise.
		Domain         string   `json:"domain"`
		LogLevel       string   `json:"log_level"`
		TLSEnabled     bool     `json:"tls_enabled"`
		AllowedOrigins []string `json:"allowed_origins"`
	} `json:"server"`

	Database struct {
		Path string `json:"path"`
	} `json:"database"`

	Storage struct {
		Provider                string `json:"provider"` // "generic-s3", "backblaze", "wasabi", "vultr", "aws-s3"
		Endpoint                string `json:"endpoint"`
		AccessKeyID             string `json:"access_key_id"`
		SecretAccessKey         string `json:"secret_access_key"`
		BucketName              string `json:"bucket_name"`
		Region                  string `json:"region"`
		UseSSL                  bool   `json:"use_ssl"`
		ForcePathStyle          bool   `json:"force_path_style"`          // Required for many self-hosted S3 (SeaweedFS, Ceph, MinIO)
		EnableUploadReplication bool   `json:"enable_upload_replication"` // When true and a secondary provider is configured, new uploads are auto-replicated
	} `json:"storage"`

	Security struct {
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

	Billing       BillingConfig       `json:"billing"`
	Payments      PaymentsConfig      `json:"payments"`
	Subscriptions SubscriptionsConfig `json:"subscriptions"`
}

// BillingConfig is the storage credits / usage metering configuration.
type BillingConfig struct {
	// Enabled is the master switch. When false, the billing scheduler is not
	// started; the API endpoints continue to return current/zero state.
	Enabled bool `json:"enabled"`

	// FreeBaselineBytes is the per-instance free baseline in bytes. Storage
	// usage above this threshold is billable.
	FreeBaselineBytes int64 `json:"free_baseline_bytes"`

	// CustomerPriceUSDPerTBPerMonth is the dollars-and-cents price string
	// (e.g. "10.00", "19.99") used to seed billing_settings on first startup.
	// Runtime updates go through the admin set-price endpoint and persist
	// in billing_settings; this value is only the seed.
	CustomerPriceUSDPerTBPerMonth string `json:"customer_price_usd_per_tb_per_month"`

	// GiftedCreditsUSD is the per-user-on-approval gift amount as a
	// dollars-and-cents string. Default "0.00" means no automatic gift.
	// Admins can manually gift credit at any time via `arkfile-admin billing gift`.
	GiftedCreditsUSD string `json:"gifted_credits_usd"`

	// TickInterval is the meter tick cadence. Production should leave at 1h;
	// the e2e billing test overrides to 1m for fast verification.
	TickInterval time.Duration `json:"tick_interval"`

	// SweepAtUTC is the daily settlement time as "HH:MM" UTC.
	SweepAtUTC string `json:"sweep_at_utc"`

	// IncludeAdmins controls whether admin accounts are billed. Default false
	// keeps operator self-usage out of beta usage data.
	IncludeAdmins bool `json:"include_admins"`

	// PaygNegativeBalanceLimitUSD is the dollars-and-cents pay-as-you-go
	// negative-balance cap (default "10.00"). Once a user's balance reaches
	// this far below zero, uploads are blocked; login and downloads remain
	// available so users can retrieve their data and settle up. Only enforced
	// when Enabled is true.
	PaygNegativeBalanceLimitUSD string `json:"payg_negative_balance_limit_usd"`

	// PaygEnabled gates hourly metering, daily settlement, and the negative-
	// balance upload cap. Requires Enabled=true for any PAYG behavior.
	PaygEnabled bool `json:"payg_enabled"`

	// paygNegativeBalanceLimitMicrocents is the parsed value of
	// PaygNegativeBalanceLimitUSD in microcents, populated by LoadConfig.
	paygNegativeBalanceLimitMicrocents int64
}

// PaygNegativeBalanceLimitMicrocents returns the configured pay-as-you-go
// negative-balance cap in microcents. Returns 0 (block at zero) if unset.
func (b BillingConfig) PaygNegativeBalanceLimitMicrocents() int64 {
	return b.paygNegativeBalanceLimitMicrocents
}

// SubscriptionsConfig is the Subscription Bridge consumer configuration.
type SubscriptionsConfig struct {
	Enabled           bool   `json:"enabled"`
	BridgeEnabled     bool   `json:"bridge_enabled"`
	BridgeURL         string `json:"bridge_url"`
	BridgePairingRoot string `json:"-"`
	ReturnURL         string `json:"return_url"`
	GiftDefaultDays   int    `json:"gift_default_days"`
	GiftMaxDays       int    `json:"gift_max_days"`
	PastDueGraceDays  int    `json:"past_due_grace_days"`
	SeedDevPlan       bool   `json:"seed_dev_plan"`
}

// PaymentsConfig is the BTCPay Server one-time top-up configuration.
type PaymentsConfig struct {
	Enabled             bool   `json:"enabled"`
	BTCPayServerURL     string `json:"btcpay_server_url"`
	BTCPayStoreID       string `json:"btcpay_store_id"`
	BTCPayAPIKey        string `json:"btcpay_api_key"`
	BTCPayWebhookSecret string `json:"btcpay_webhook_secret"`
	MinTopUpUSD         string `json:"min_top_up_usd"`
	MaxTopUpUSD         string `json:"max_top_up_usd"`
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

		if microcents, parseErr := money.ParseUSDToMicrocents(config.Billing.PaygNegativeBalanceLimitUSD, 2, false); parseErr == nil {
			config.Billing.paygNegativeBalanceLimitMicrocents = microcents
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

func storageSlotKey(slot int, suffix string) string {
	return fmt.Sprintf("STORAGE_%d_%s", slot, suffix)
}

func storageProviderKey(slot int) string {
	return fmt.Sprintf("STORAGE_PROVIDER_%d", slot)
}

func loadPrimaryStorageConfig(cfg *Config) {
	cfg.Storage.Provider = os.Getenv(storageProviderKey(1))
	if cfg.Storage.Provider == "" {
		cfg.Storage.Provider = "generic-s3"
	}

	cfg.Storage.Endpoint = os.Getenv(storageSlotKey(1, "ENDPOINT"))
	cfg.Storage.AccessKeyID = os.Getenv(storageSlotKey(1, "ACCESS_KEY"))
	cfg.Storage.SecretAccessKey = os.Getenv(storageSlotKey(1, "SECRET_KEY"))
	cfg.Storage.BucketName = os.Getenv(storageSlotKey(1, "BUCKET"))
	cfg.Storage.Region = os.Getenv(storageSlotKey(1, "REGION"))
	if cfg.Storage.Region == "" {
		cfg.Storage.Region = "us-east-1"
	}

	switch cfg.Storage.Provider {
	case "generic-s3":
		if cfg.Storage.Endpoint == "" {
			cfg.Storage.Endpoint = "http://localhost:9332"
		}
		cfg.Storage.ForcePathStyle = true
	case "wasabi":
		if cfg.Storage.Endpoint == "" {
			cfg.Storage.Endpoint = fmt.Sprintf("https://s3.%s.wasabisys.com", cfg.Storage.Region)
		}
		cfg.Storage.ForcePathStyle = true
		cfg.Storage.UseSSL = true
	case "vultr":
		if cfg.Storage.Endpoint == "" {
			cfg.Storage.Endpoint = fmt.Sprintf("https://%s.vultrobjects.com", cfg.Storage.Region)
		}
		cfg.Storage.UseSSL = true
	case "hetzner":
		if cfg.Storage.Endpoint == "" {
			cfg.Storage.Endpoint = fmt.Sprintf("https://%s.your-objectstorage.com", cfg.Storage.Region)
		}
		cfg.Storage.ForcePathStyle = true
		cfg.Storage.UseSSL = true
	case "backblaze", "cloudflare-r2", "aws-s3":
		cfg.Storage.UseSSL = true
	}

	if forcePathStyle := os.Getenv(storageSlotKey(1, "FORCE_PATH_STYLE")); forcePathStyle != "" {
		if val, err := strconv.ParseBool(forcePathStyle); err == nil {
			cfg.Storage.ForcePathStyle = val
		}
	}

	if useSSL := os.Getenv(storageSlotKey(1, "USE_SSL")); useSSL != "" {
		if val, err := strconv.ParseBool(useSSL); err == nil {
			cfg.Storage.UseSSL = val
		}
	} else if cfg.Storage.Endpoint != "" {
		cfg.Storage.UseSSL = strings.HasPrefix(strings.ToLower(cfg.Storage.Endpoint), "https://")
	}

	if cfg.Storage.Provider == "aws-s3" && cfg.Storage.Region == "" {
		cfg.Storage.Region = "us-east-1"
	}
}

func loadDefaultConfig(cfg *Config) error {
	// Set default values
	cfg.Server.Port = "8080"
	cfg.Server.TLSPort = "8443"
	cfg.Server.Host = "localhost"
	cfg.Server.AllowedOrigins = []string{"https://localhost:8443"}
	cfg.Database.Path = "./arkfile.db"
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
	cfg.KeyManagement.TLSCertPath = "tls/server.crt"
	cfg.KeyManagement.UseSystemdCreds = true
	cfg.KeyManagement.BackupDirectory = "/opt/arkfile/etc/keys/backups"
	cfg.KeyManagement.RotationSchedule = "30d"

	// Deployment defaults
	cfg.Deployment.Environment = "development"
	cfg.Deployment.DataDirectory = "/opt/arkfile/var/lib"
	cfg.Deployment.LogDirectory = "/opt/arkfile/var/log"
	cfg.Deployment.BackupRetention = 30

	// Billing defaults (storage credits / usage metering).
	cfg.Billing.Enabled = false
	cfg.Billing.FreeBaselineBytes = 1073741824 // 1 GiB, matches models.DefaultStorageLimit
	cfg.Billing.CustomerPriceUSDPerTBPerMonth = "10.00"
	cfg.Billing.GiftedCreditsUSD = "0.00" // no auto-gift; admins gift manually if desired
	cfg.Billing.TickInterval = time.Hour
	cfg.Billing.SweepAtUTC = "00:15"
	cfg.Billing.IncludeAdmins = false
	cfg.Billing.PaygNegativeBalanceLimitUSD = "10.00"
	cfg.Billing.PaygEnabled = false

	// Subscriptions defaults (Subscription Bridge consumer)
	cfg.Subscriptions.Enabled = false
	cfg.Subscriptions.GiftDefaultDays = 30
	cfg.Subscriptions.GiftMaxDays = 90
	cfg.Subscriptions.PastDueGraceDays = 7
	cfg.Subscriptions.SeedDevPlan = false

	// Payments defaults (BTCPay Server integration)
	cfg.Payments.Enabled = false
	cfg.Payments.MinTopUpUSD = "0.50"
	cfg.Payments.MaxTopUpUSD = "1000.00"

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
	// Resolve the OPAQUE server identity (idS) domain with this precedence:
	//   1. ARKFILE_DOMAIN env (explicit; written by deploy scripts)
	//   2. host parsed from BASE_URL (scheme/path/port stripped)
	//   3. "localhost" default (local/LAN deployments have no single FQDN)
	// All OPAQUE participants must agree on this value, so it is the single
	// source of truth served to clients via /api/config/opaque.
	if domain := strings.TrimSpace(os.Getenv("ARKFILE_DOMAIN")); domain != "" {
		cfg.Server.Domain = domain
	} else if host := hostFromBaseURL(cfg.Server.BaseURL); host != "" {
		cfg.Server.Domain = host
	} else {
		cfg.Server.Domain = "localhost"
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
	loadPrimaryStorageConfig(cfg)

	// Security configuration - Ed25519 key paths can be overridden via environment
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

	// Upload replication: when true and a secondary provider is configured,
	// newly uploaded files are automatically replicated to the secondary provider.
	if enableReplication := os.Getenv("ENABLE_UPLOAD_REPLICATION"); enableReplication != "" {
		if repl, err := strconv.ParseBool(enableReplication); err == nil {
			cfg.Storage.EnableUploadReplication = repl
		}
	}

	// Billing / usage metering envs
	if v := os.Getenv("ARKFILE_BILLING_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Billing.Enabled = parsed
		}
	}
	if v := os.Getenv("ARKFILE_FREE_STORAGE_BYTES"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
			cfg.Billing.FreeBaselineBytes = parsed
		}
	}
	if v := os.Getenv("ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH"); v != "" {
		cfg.Billing.CustomerPriceUSDPerTBPerMonth = v
	}
	if v := os.Getenv("ARKFILE_BILLING_GIFTED_CREDITS_USD"); v != "" {
		cfg.Billing.GiftedCreditsUSD = v
	}
	if v := os.Getenv("ARKFILE_BILLING_TICK_INTERVAL"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			cfg.Billing.TickInterval = parsed
		}
	}
	if v := os.Getenv("ARKFILE_BILLING_SWEEP_AT_UTC"); v != "" {
		cfg.Billing.SweepAtUTC = v
	}
	if v := os.Getenv("ARKFILE_BILLING_INCLUDE_ADMINS"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Billing.IncludeAdmins = parsed
		}
	}
	if v := os.Getenv("ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD"); v != "" {
		cfg.Billing.PaygNegativeBalanceLimitUSD = v
	}
	if v := os.Getenv("ARKFILE_BILLING_PAYG_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Billing.PaygEnabled = parsed
		}
	} else if cfg.Billing.Enabled {
		cfg.Billing.PaygEnabled = false
	}

	// Subscriptions envs
	if v := os.Getenv("ARKFILE_SUBSCRIPTIONS_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Subscriptions.Enabled = parsed
		}
	}
	if v := os.Getenv("ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Subscriptions.BridgeEnabled = parsed
		}
	}
	if v := os.Getenv("ARKFILE_SUBSCRIPTION_BRIDGE_URL"); v != "" {
		cfg.Subscriptions.BridgeURL = strings.TrimRight(strings.TrimSpace(v), "/")
	}
	if v := os.Getenv("ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT"); v != "" {
		cfg.Subscriptions.BridgePairingRoot = v
	}
	if v := os.Getenv("ARKFILE_SUBSCRIPTION_RETURN_URL"); v != "" {
		cfg.Subscriptions.ReturnURL = v
	}
	if v := os.Getenv("ARKFILE_GIFT_SUBSCRIPTION_DEFAULT_DAYS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			cfg.Subscriptions.GiftDefaultDays = parsed
		}
	}
	if v := os.Getenv("ARKFILE_GIFT_SUBSCRIPTION_MAX_DAYS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			cfg.Subscriptions.GiftMaxDays = parsed
		}
	}
	if v := os.Getenv("ARKFILE_SUBSCRIPTION_PAST_DUE_GRACE_DAYS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			cfg.Subscriptions.PastDueGraceDays = parsed
		}
	}
	if v := os.Getenv("ARKFILE_SUBSCRIPTION_SEED_DEV_PLAN"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Subscriptions.SeedDevPlan = parsed
		}
	}

	// Payments (BTCPay Server integration) envs
	if v := os.Getenv("ARKFILE_PAYMENTS_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.Payments.Enabled = parsed
		}
	}
	if v := os.Getenv("ARKFILE_BTCPAY_SERVER_URL"); v != "" {
		cfg.Payments.BTCPayServerURL = v
	}
	if v := os.Getenv("ARKFILE_BTCPAY_STORE_ID"); v != "" {
		cfg.Payments.BTCPayStoreID = v
	}
	if v := os.Getenv("ARKFILE_BTCPAY_API_KEY"); v != "" {
		cfg.Payments.BTCPayAPIKey = v
	}
	if v := os.Getenv("ARKFILE_BTCPAY_WEBHOOK_SECRET"); v != "" {
		cfg.Payments.BTCPayWebhookSecret = v
	}
	if v := os.Getenv("ARKFILE_MIN_TOP_UP_USD"); v != "" {
		cfg.Payments.MinTopUpUSD = v
	}
	if v := os.Getenv("ARKFILE_MAX_TOP_UP_USD"); v != "" {
		cfg.Payments.MaxTopUpUSD = v
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
	// Validate the PAYG negative-balance cap regardless of whether billing is
	// enabled; the default ("10.00") must always parse cleanly.
	if cfg.Billing.PaygNegativeBalanceLimitUSD != "" {
		if _, err := money.ParseUSDToMicrocents(cfg.Billing.PaygNegativeBalanceLimitUSD, 2, false); err != nil {
			return fmt.Errorf("ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD: %w", err)
		}
	}

	// Validate storage configuration based on provider
	switch cfg.Storage.Provider {
	case "generic-s3":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("generic-s3 storage requires STORAGE_1_ENDPOINT, STORAGE_1_ACCESS_KEY, STORAGE_1_SECRET_KEY, and STORAGE_1_BUCKET")
		}
	case "backblaze":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("backblaze storage requires STORAGE_1_ENDPOINT, STORAGE_1_ACCESS_KEY, STORAGE_1_SECRET_KEY, and STORAGE_1_BUCKET")
		}
	case "cloudflare-r2":
		if cfg.Storage.Endpoint == "" || cfg.Storage.AccessKeyID == "" ||
			cfg.Storage.SecretAccessKey == "" || cfg.Storage.BucketName == "" {
			return fmt.Errorf("cloudflare-r2 storage requires STORAGE_1_ENDPOINT, STORAGE_1_ACCESS_KEY, STORAGE_1_SECRET_KEY, and STORAGE_1_BUCKET")
		}
	case "wasabi", "vultr", "hetzner":
		if cfg.Storage.AccessKeyID == "" || cfg.Storage.SecretAccessKey == "" ||
			cfg.Storage.BucketName == "" || cfg.Storage.Region == "" {
			return fmt.Errorf("%s storage requires STORAGE_1_ACCESS_KEY, STORAGE_1_SECRET_KEY, STORAGE_1_BUCKET, and STORAGE_1_REGION", cfg.Storage.Provider)
		}
	case "aws-s3":
		if cfg.Storage.AccessKeyID == "" || cfg.Storage.SecretAccessKey == "" ||
			cfg.Storage.BucketName == "" {
			return fmt.Errorf("AWS S3 storage requires STORAGE_1_ACCESS_KEY, STORAGE_1_SECRET_KEY, and STORAGE_1_BUCKET")
		}
	default:
		return fmt.Errorf("unsupported storage provider: %s", cfg.Storage.Provider)
	}

	if err := validatePaymentsConfig(cfg); err != nil {
		return err
	}
	if err := validateSubscriptionsConfig(cfg); err != nil {
		return err
	}

	return nil
}

func validateSubscriptionsConfig(cfg *Config) error {
	if !cfg.Subscriptions.Enabled {
		if cfg.Subscriptions.BridgeEnabled {
			return fmt.Errorf("ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED requires ARKFILE_SUBSCRIPTIONS_ENABLED=true")
		}
		return nil
	}
	if cfg.Subscriptions.GiftDefaultDays < 1 {
		return fmt.Errorf("ARKFILE_GIFT_SUBSCRIPTION_DEFAULT_DAYS must be at least 1")
	}
	if cfg.Subscriptions.GiftMaxDays < cfg.Subscriptions.GiftDefaultDays {
		return fmt.Errorf("ARKFILE_GIFT_SUBSCRIPTION_MAX_DAYS must be >= ARKFILE_GIFT_SUBSCRIPTION_DEFAULT_DAYS")
	}
	if cfg.Subscriptions.PastDueGraceDays < 0 {
		return fmt.Errorf("ARKFILE_SUBSCRIPTION_PAST_DUE_GRACE_DAYS must be non-negative")
	}
	if !cfg.Subscriptions.BridgeEnabled {
		return nil
	}
	if strings.TrimSpace(cfg.Subscriptions.BridgeURL) == "" {
		return fmt.Errorf("ARKFILE_SUBSCRIPTION_BRIDGE_URL is required when ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED=true")
	}
	bridgeURL, err := url.Parse(cfg.Subscriptions.BridgeURL)
	if err != nil || bridgeURL.Host == "" || (bridgeURL.Scheme != "https" && bridgeURL.Scheme != "http") {
		return fmt.Errorf("ARKFILE_SUBSCRIPTION_BRIDGE_URL must be an absolute HTTP(S) URL")
	}
	if bridgeURL.User != nil || bridgeURL.Fragment != "" || bridgeURL.RawQuery != "" || (bridgeURL.Path != "" && bridgeURL.Path != "/") {
		return fmt.Errorf("ARKFILE_SUBSCRIPTION_BRIDGE_URL must be an origin URL without userinfo, query, fragment, or path")
	}
	if bridgeURL.Scheme != "https" && bridgeURL.Hostname() != "127.0.0.1" && bridgeURL.Hostname() != "localhost" && bridgeURL.Hostname() != "::1" {
		return fmt.Errorf("ARKFILE_SUBSCRIPTION_BRIDGE_URL must use HTTPS except on loopback")
	}
	if !isLowerHexSecret(cfg.Subscriptions.BridgePairingRoot, 64) {
		return fmt.Errorf("ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT must be exactly 64 lowercase hexadecimal characters")
	}
	returnURL := cfg.Subscriptions.ReturnURL
	if returnURL == "" && cfg.Server.BaseURL != "" {
		returnURL = strings.TrimRight(cfg.Server.BaseURL, "/") + "/?subscription=return"
	}
	normalized, err := subbridge.NormalizeReturnURL(returnURL)
	if err != nil || normalized != returnURL {
		return fmt.Errorf("ARKFILE_SUBSCRIPTION_RETURN_URL (or BASE_URL fallback) must be a normalized HTTPS URL; HTTP is allowed only on loopback")
	}
	return nil
}

func isLowerHexSecret(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func validatePaymentsConfig(cfg *Config) error {
	if !cfg.Payments.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.Payments.BTCPayServerURL) == "" {
		return fmt.Errorf("ARKFILE_BTCPAY_SERVER_URL is required when ARKFILE_PAYMENTS_ENABLED=true")
	}
	if strings.TrimSpace(cfg.Payments.BTCPayStoreID) == "" {
		return fmt.Errorf("ARKFILE_BTCPAY_STORE_ID is required when ARKFILE_PAYMENTS_ENABLED=true")
	}
	if strings.TrimSpace(cfg.Payments.BTCPayAPIKey) == "" {
		return fmt.Errorf("ARKFILE_BTCPAY_API_KEY is required when ARKFILE_PAYMENTS_ENABLED=true")
	}
	if strings.TrimSpace(cfg.Payments.BTCPayWebhookSecret) == "" {
		return fmt.Errorf("ARKFILE_BTCPAY_WEBHOOK_SECRET is required when ARKFILE_PAYMENTS_ENABLED=true")
	}
	production := strings.EqualFold(strings.TrimSpace(cfg.Deployment.Environment), "production") || utils.IsProductionEnvironment()
	allowLoopbackHTTP := !production && isExplicitDevelopmentOrTest(cfg.Deployment.Environment)
	if _, err := validatePaymentOrigin(cfg.Payments.BTCPayServerURL, production, allowLoopbackHTTP); err != nil {
		return fmt.Errorf("ARKFILE_BTCPAY_SERVER_URL: %w", err)
	}
	if strings.TrimSpace(cfg.Server.BaseURL) == "" {
		return fmt.Errorf("BASE_URL is required when ARKFILE_PAYMENTS_ENABLED=true")
	}
	if _, err := validatePaymentOrigin(cfg.Server.BaseURL, production, allowLoopbackHTTP); err != nil {
		return fmt.Errorf("BASE_URL: %w", err)
	}

	minMicrocents, err := parsePositiveTopUpUSD(cfg.Payments.MinTopUpUSD, "ARKFILE_MIN_TOP_UP_USD")
	if err != nil {
		return err
	}
	maxMicrocents, err := parsePositiveTopUpUSD(cfg.Payments.MaxTopUpUSD, "ARKFILE_MAX_TOP_UP_USD")
	if err != nil {
		return err
	}
	if minMicrocents >= maxMicrocents {
		return fmt.Errorf("ARKFILE_MIN_TOP_UP_USD must be less than ARKFILE_MAX_TOP_UP_USD")
	}
	return nil
}

func isExplicitDevelopmentOrTest(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "development", "dev", "test", "testing":
		return true
	default:
		return false
	}
}

func parsePositiveTopUpUSD(value, name string) (int64, error) {
	total, err := money.ParseUSDToMicrocents(value, 2, false)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid USD amount with at most two decimal places: %w", name, err)
	}
	if total <= 0 {
		return 0, fmt.Errorf("%s must be a positive USD amount", name)
	}
	return total, nil
}

func validatePaymentOrigin(raw string, production, allowLoopbackHTTP bool) (*url.URL, error) {
	if raw != strings.TrimSpace(raw) || raw == "" {
		return nil, fmt.Errorf("must be a normalized origin")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return nil, fmt.Errorf("must be an absolute HTTP(S) origin")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
		return nil, fmt.Errorf("must not contain credentials, query, fragment, or path")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("must use HTTPS")
	}
	if parsed.Scheme != strings.ToLower(parsed.Scheme) || parsed.Host != strings.ToLower(parsed.Host) {
		return nil, fmt.Errorf("must use a lowercase normalized origin")
	}
	if (parsed.Scheme == "https" && parsed.Port() == "443") || (parsed.Scheme == "http" && parsed.Port() == "80") {
		return nil, fmt.Errorf("must omit the default port")
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return nil, fmt.Errorf("must include a hostname")
	}
	loopback := hostname == "localhost" || strings.HasSuffix(hostname, ".localhost")
	ip := net.ParseIP(hostname)
	if ip != nil {
		loopback = ip.IsLoopback()
		if production && (loopback || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			return nil, fmt.Errorf("must use a public network origin in production")
		}
	}
	if production {
		if parsed.Scheme != "https" {
			return nil, fmt.Errorf("must use HTTPS in production")
		}
		if loopback {
			return nil, fmt.Errorf("must not use a loopback origin in production")
		}
		if ip == nil && (!strings.Contains(hostname, ".") || strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal")) {
			return nil, fmt.Errorf("must use a public hostname in production")
		}
	} else if parsed.Scheme == "http" && !(allowLoopbackHTTP && loopback) {
		return nil, fmt.Errorf("HTTP is allowed only for loopback development and test origins")
	}
	if parsed.String() != raw {
		return nil, fmt.Errorf("must be a normalized origin")
	}
	return parsed, nil
}

// ValidateProductionConfig validates that the configuration is safe for production
func ValidateProductionConfig() error {
	if utils.IsProductionEnvironment() {
		// ADMIN_DEV_TEST_API_ENABLED grants /api/admin/dev-test/**
		// which exposes destructive endpoints (user-cleanup, TOTP
		// decrypt-check, billing tick-now). The route group itself is
		// gated by this env var in handlers/route_config.go, so a
		// production deployment with the flag set silently exposes the
		// surface. Fail-closed at startup so the server refuses to run
		// in that combination at all.
		enabled := strings.ToLower(os.Getenv("ADMIN_DEV_TEST_API_ENABLED"))
		if enabled == "true" || enabled == "1" || enabled == "yes" {
			return fmt.Errorf("FATAL: ADMIN_DEV_TEST_API_ENABLED=%q is incompatible with production environment - deployment blocked", enabled)
		}

		// Get admin usernames from configuration
		cfg, err := LoadConfig()
		if err != nil {
			return fmt.Errorf("failed to load config for production validation: %w", err)
		}

		// The OPAQUE server identity (idS) must be bound to a real deployment
		// FQDN in production. A missing/"localhost" domain means ARKFILE_DOMAIN
		// and BASE_URL were both unset, so idS would silently fall back to the
		// local default - defeating the purpose of binding it. Fail closed.
		domain := strings.TrimSpace(cfg.Server.Domain)
		if domain == "" || domain == "localhost" {
			return fmt.Errorf("FATAL: ARKFILE_DOMAIN (or BASE_URL) must be set to the deployment FQDN in production; got %q - deployment blocked", domain)
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
	requireApprovalMu.Lock()
	requireApproval = false
	requireApprovalInitialized = false
	requireApprovalMu.Unlock()
}

// require_approval live, admin-controllable policy state.
//
// The env-loaded Deployment.RequireApproval is the seed/default. At startup
// main.go loads the persisted value from the system_settings table (if present)
// and calls SetRequireApproval; the admin set-approval-policy endpoint updates
// that table and calls SetRequireApproval to flip the policy without a restart.
// RequireApproval falls back to the env default until the first SetRequireApproval.
var (
	requireApprovalMu          sync.RWMutex
	requireApproval            bool
	requireApprovalInitialized bool
)

// SetRequireApproval sets the live auto-approval policy. require_approval=true
// means new registrations require explicit admin approval; false means they are
// auto-approved at registration time with approved_by="system".
func SetRequireApproval(enabled bool) {
	requireApprovalMu.Lock()
	requireApproval = enabled
	requireApprovalInitialized = true
	requireApprovalMu.Unlock()
}

// RequireApproval returns the live auto-approval policy. Before the first
// SetRequireApproval call it falls back to the env-loaded
// Deployment.RequireApproval so the registration path is correct even if the
// system_settings load has not yet run.
func RequireApproval() bool {
	requireApprovalMu.RLock()
	if requireApprovalInitialized {
		v := requireApproval
		requireApprovalMu.RUnlock()
		return v
	}
	requireApprovalMu.RUnlock()
	return GetConfig().Deployment.RequireApproval
}
