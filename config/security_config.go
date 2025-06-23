package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/84adam/arkfile/logging"
)

// SecurityConfig centralizes all security-related configuration
type SecurityConfig struct {
	// Entity ID configuration
	EntityID EntityIDConfig `json:"entity_id"`

	// Rate limiting configuration
	RateLimit RateLimitConfig `json:"rate_limit"`

	// Security event configuration
	SecurityEvents SecurityEventsConfig `json:"security_events"`

	// Monitoring configuration
	Monitoring MonitoringConfig `json:"monitoring"`

	// Emergency procedures configuration
	Emergency EmergencyConfig `json:"emergency"`
}

// EntityIDConfig configures privacy-preserving entity identification
type EntityIDConfig struct {
	MasterSecretPath  string        `json:"master_secret_path"`
	RotationPeriod    time.Duration `json:"rotation_period"`    // 24 * time.Hour
	RetentionDays     int           `json:"retention_days"`     // 90
	CleanupInterval   time.Duration `json:"cleanup_interval"`   // 24 * time.Hour
	EmergencyRotation bool          `json:"emergency_rotation"` // true
}

// RateLimitConfig configures rate limiting policies
type RateLimitConfig struct {
	// Authentication endpoints (per hour)
	RegisterLimit       int `json:"register_limit"`        // 5 per day
	LoginLimit          int `json:"login_limit"`           // 20 per hour
	RefreshLimit        int `json:"refresh_limit"`         // 60 per hour
	ForgotPasswordLimit int `json:"forgot_password_limit"` // 3 per day
	ResetPasswordLimit  int `json:"reset_password_limit"`  // 10 per hour

	// Account operations (per hour)
	ProfileAccessLimit int `json:"profile_access_limit"` // 100 per hour
	EmailCheckLimit    int `json:"email_check_limit"`    // 20 per hour

	// Administrative operations (per hour)
	UserManagementLimit int `json:"user_management_limit"` // 50 per hour
	SystemStatusLimit   int `json:"system_status_limit"`   // 30 per hour
	AuditLogsLimit      int `json:"audit_logs_limit"`      // 20 per hour

	// Progressive penalty configuration
	ViolationPenalty float64       `json:"violation_penalty"` // 2.0 (double delay)
	MaxPenaltyDelay  time.Duration `json:"max_penalty_delay"` // 15 minutes
	RecoveryPeriod   time.Duration `json:"recovery_period"`   // 1 hour
	MaxViolations    int           `json:"max_violations"`    // 5 before max penalty

	// Global settings
	EnableRateLimit bool          `json:"enable_rate_limit"` // true
	CleanupInterval time.Duration `json:"cleanup_interval"`  // 24 * time.Hour
	RetentionDays   int           `json:"retention_days"`    // 30
}

// SecurityEventsConfig configures security event logging
type SecurityEventsConfig struct {
	MaxRetentionDays int               `json:"max_retention_days"` // 90
	EnabledEvents    []string          `json:"enabled_events"`
	AlertThresholds  map[string]int    `json:"alert_thresholds"`
	SeverityLevels   map[string]string `json:"severity_levels"`
	AutoCleanup      bool              `json:"auto_cleanup"`     // true
	CleanupInterval  time.Duration     `json:"cleanup_interval"` // 24 * time.Hour
	LogToFile        bool              `json:"log_to_file"`      // true
	LogToDatabase    bool              `json:"log_to_database"`  // true
}

// MonitoringConfig configures key health and system monitoring
type MonitoringConfig struct {
	// Key health monitoring
	KeyHealthInterval  time.Duration `json:"key_health_interval"`  // 1 * time.Hour
	CertExpiryWarning  time.Duration `json:"cert_expiry_warning"`  // 30 * 24 * time.Hour (30 days)
	CertExpiryCritical time.Duration `json:"cert_expiry_critical"` // 7 * 24 * time.Hour (7 days)
	KeyRotationOverdue time.Duration `json:"key_rotation_overdue"` // 35 * 24 * time.Hour (35 days)
	BackupValidation   time.Duration `json:"backup_validation"`    // 7 * 24 * time.Hour (weekly)

	// System monitoring
	HealthCheckInterval time.Duration `json:"health_check_interval"` // 5 * time.Minute
	MetricsRetention    time.Duration `json:"metrics_retention"`     // 30 * 24 * time.Hour (30 days)
	AlertCooldown       time.Duration `json:"alert_cooldown"`        // 1 * time.Hour

	// Performance monitoring
	EnablePerformanceMetrics bool   `json:"enable_performance_metrics"` // true
	MetricsEndpoint          string `json:"metrics_endpoint"`           // "/metrics"

	// Database monitoring
	DatabaseHealthInterval time.Duration `json:"database_health_interval"` // 10 * time.Minute
	SlowQueryThreshold     time.Duration `json:"slow_query_threshold"`     // 1 * time.Second
}

// EmergencyConfig configures emergency response procedures
type EmergencyConfig struct {
	// Automatic responses
	AutoRotateOnBreach    bool `json:"auto_rotate_on_breach"`    // true
	AutoEscalateRateLimit bool `json:"auto_escalate_rate_limit"` // true
	AutoIsolateOnPattern  bool `json:"auto_isolate_on_pattern"`  // true

	// Emergency contacts and procedures
	EmergencyContacts    []string       `json:"emergency_contacts"`
	NotificationEndpoint string         `json:"notification_endpoint"`
	EscalationThresholds map[string]int `json:"escalation_thresholds"`

	// Emergency rate limiting
	EmergencyRateLimitMultiplier float64       `json:"emergency_rate_limit_multiplier"` // 0.1 (10x stricter)
	EmergencyDuration            time.Duration `json:"emergency_duration"`              // 1 * time.Hour

	// Recovery procedures
	RequireManualRecovery   bool     `json:"require_manual_recovery"` // true
	RecoveryValidationSteps []string `json:"recovery_validation_steps"`
}

// EndpointConfig defines rate limiting configuration for specific endpoints
type EndpointConfig struct {
	Path        string        `json:"path"`
	Method      string        `json:"method"`
	Category    string        `json:"category"`    // "auth", "account", "admin", "unrestricted"
	Limit       int           `json:"limit"`       // requests per time window
	WindowType  string        `json:"window_type"` // "hour", "day"
	WindowSize  time.Duration `json:"window_size"`
	Enabled     bool          `json:"enabled"`
	Description string        `json:"description"`
}

// GetDefaultSecurityConfig returns the default security configuration
func GetDefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		EntityID: EntityIDConfig{
			MasterSecretPath:  "/opt/arkfile/etc/keys/entity_id/master.key",
			RotationPeriod:    24 * time.Hour,
			RetentionDays:     90,
			CleanupInterval:   24 * time.Hour,
			EmergencyRotation: true,
		},
		RateLimit: RateLimitConfig{
			// Authentication limits
			RegisterLimit:       5,  // 5 per day
			LoginLimit:          20, // 20 per hour
			RefreshLimit:        60, // 60 per hour
			ForgotPasswordLimit: 3,  // 3 per day
			ResetPasswordLimit:  10, // 10 per hour

			// Account operation limits
			ProfileAccessLimit: 100, // 100 per hour
			EmailCheckLimit:    20,  // 20 per hour

			// Admin operation limits
			UserManagementLimit: 50, // 50 per hour
			SystemStatusLimit:   30, // 30 per hour
			AuditLogsLimit:      20, // 20 per hour

			// Progressive penalties
			ViolationPenalty: 2.0,
			MaxPenaltyDelay:  15 * time.Minute,
			RecoveryPeriod:   1 * time.Hour,
			MaxViolations:    5,

			// Global settings
			EnableRateLimit: true,
			CleanupInterval: 24 * time.Hour,
			RetentionDays:   30,
		},
		SecurityEvents: SecurityEventsConfig{
			MaxRetentionDays: 90,
			EnabledEvents: []string{
				"opaque_registration", "opaque_login_success", "opaque_login_failure",
				"jwt_refresh_success", "jwt_refresh_failure", "rate_limit_violation",
				"suspicious_pattern", "endpoint_abuse", "key_rotation",
			},
			AlertThresholds: map[string]int{
				"opaque_login_failure": 10, // 10 failures per hour
				"rate_limit_violation": 5,  // 5 violations per hour
				"suspicious_pattern":   3,  // 3 patterns per hour
				"endpoint_abuse":       2,  // 2 abuse events per hour
			},
			SeverityLevels: map[string]string{
				"opaque_login_failure": "WARNING",
				"rate_limit_violation": "WARNING",
				"suspicious_pattern":   "CRITICAL",
				"endpoint_abuse":       "CRITICAL",
				"emergency_procedure":  "CRITICAL",
			},
			AutoCleanup:     true,
			CleanupInterval: 24 * time.Hour,
			LogToFile:       true,
			LogToDatabase:   true,
		},
		Monitoring: MonitoringConfig{
			KeyHealthInterval:  1 * time.Hour,
			CertExpiryWarning:  30 * 24 * time.Hour,
			CertExpiryCritical: 7 * 24 * time.Hour,
			KeyRotationOverdue: 35 * 24 * time.Hour,
			BackupValidation:   7 * 24 * time.Hour,

			HealthCheckInterval: 5 * time.Minute,
			MetricsRetention:    30 * 24 * time.Hour,
			AlertCooldown:       1 * time.Hour,

			EnablePerformanceMetrics: true,
			MetricsEndpoint:          "/metrics",

			DatabaseHealthInterval: 10 * time.Minute,
			SlowQueryThreshold:     1 * time.Second,
		},
		Emergency: EmergencyConfig{
			AutoRotateOnBreach:    true,
			AutoEscalateRateLimit: true,
			AutoIsolateOnPattern:  true,

			EmergencyContacts: []string{},
			EscalationThresholds: map[string]int{
				"critical_events_per_hour": 5,
				"failed_logins_per_hour":   100,
				"rate_violations_per_hour": 50,
			},

			EmergencyRateLimitMultiplier: 0.1, // 10x stricter
			EmergencyDuration:            1 * time.Hour,

			RequireManualRecovery: true,
			RecoveryValidationSteps: []string{
				"verify_key_integrity",
				"check_database_consistency",
				"validate_security_events",
				"confirm_rate_limit_state",
			},
		},
	}
}

// GetRateLimitedEndpoints returns the configuration for rate-limited endpoints
func GetRateLimitedEndpoints() []EndpointConfig {
	return []EndpointConfig{
		{
			Path:        "/register",
			Method:      "POST",
			Category:    "auth",
			Limit:       5,
			WindowType:  "day",
			WindowSize:  24 * time.Hour,
			Enabled:     true,
			Description: "OPAQUE user registration",
		},
		{
			Path:        "/login",
			Method:      "POST",
			Category:    "auth",
			Limit:       20,
			WindowType:  "hour",
			WindowSize:  1 * time.Hour,
			Enabled:     true,
			Description: "OPAQUE authentication",
		},
		{
			Path:        "/refresh",
			Method:      "POST",
			Category:    "auth",
			Limit:       60,
			WindowType:  "hour",
			WindowSize:  1 * time.Hour,
			Enabled:     true,
			Description: "JWT token refresh",
		},
		{
			Path:        "/forgot-password",
			Method:      "POST",
			Category:    "auth",
			Limit:       3,
			WindowType:  "day",
			WindowSize:  24 * time.Hour,
			Enabled:     true,
			Description: "Password reset initiation",
		},
		{
			Path:        "/reset-password",
			Method:      "POST",
			Category:    "auth",
			Limit:       10,
			WindowType:  "hour",
			WindowSize:  1 * time.Hour,
			Enabled:     true,
			Description: "Password reset completion",
		},
		{
			Path:        "/user/profile",
			Method:      "GET",
			Category:    "account",
			Limit:       100,
			WindowType:  "hour",
			WindowSize:  1 * time.Hour,
			Enabled:     true,
			Description: "User profile access",
		},
		{
			Path:        "/check-email",
			Method:      "POST",
			Category:    "account",
			Limit:       20,
			WindowType:  "hour",
			WindowSize:  1 * time.Hour,
			Enabled:     true,
			Description: "Email existence checking",
		},
	}
}

// LoadSecurityConfig loads security configuration from file or returns defaults
func LoadSecurityConfig(configPath string) (SecurityConfig, error) {
	// Try to load from file
	if configPath != "" {
		if data, err := os.ReadFile(configPath); err == nil {
			var config SecurityConfig
			if err := json.Unmarshal(data, &config); err == nil {
				return config, nil
			}
		}
	}

	// Return default configuration
	return GetDefaultSecurityConfig(), nil
}

// SaveSecurityConfig saves security configuration to file
func SaveSecurityConfig(config SecurityConfig, configPath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal security config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write security config: %w", err)
	}

	return nil
}

// ValidateSecurityConfig validates the security configuration
func ValidateSecurityConfig(config SecurityConfig) error {
	// Validate entity ID configuration
	if config.EntityID.RotationPeriod < time.Hour {
		return fmt.Errorf("entity ID rotation period must be at least 1 hour")
	}
	if config.EntityID.RetentionDays < 1 {
		return fmt.Errorf("entity ID retention days must be at least 1")
	}

	// Validate rate limiting configuration
	if config.RateLimit.EnableRateLimit {
		if config.RateLimit.LoginLimit < 1 {
			return fmt.Errorf("login limit must be at least 1")
		}
		if config.RateLimit.RegisterLimit < 1 {
			return fmt.Errorf("register limit must be at least 1")
		}
		if config.RateLimit.ViolationPenalty < 1.0 {
			return fmt.Errorf("violation penalty must be at least 1.0")
		}
		if config.RateLimit.MaxViolations < 1 {
			return fmt.Errorf("max violations must be at least 1")
		}
	}

	// Validate security events configuration
	if config.SecurityEvents.MaxRetentionDays < 1 {
		return fmt.Errorf("security events retention days must be at least 1")
	}

	// Validate monitoring configuration
	if config.Monitoring.KeyHealthInterval < time.Minute {
		return fmt.Errorf("key health interval must be at least 1 minute")
	}
	if config.Monitoring.HealthCheckInterval < time.Minute {
		return fmt.Errorf("health check interval must be at least 1 minute")
	}

	// Validate emergency configuration
	if config.Emergency.EmergencyRateLimitMultiplier <= 0 || config.Emergency.EmergencyRateLimitMultiplier > 1 {
		return fmt.Errorf("emergency rate limit multiplier must be between 0 and 1")
	}

	return nil
}

// ApplySecurityConfig applies security configuration to the application
func ApplySecurityConfig(config SecurityConfig) error {
	// Initialize entity ID service
	if err := logging.InitializeEntityIDService(logging.EntityIDConfig{
		MasterSecretPath:  config.EntityID.MasterSecretPath,
		RotationPeriod:    config.EntityID.RotationPeriod,
		RetentionDays:     config.EntityID.RetentionDays,
		CleanupInterval:   config.EntityID.CleanupInterval,
		EmergencyRotation: config.EntityID.EmergencyRotation,
	}); err != nil {
		return fmt.Errorf("failed to initialize entity ID service: %w", err)
	}

	// Initialize security event logger
	if err := logging.InitializeSecurityEventLogger(logging.SecurityEventConfig{
		MaxRetentionDays: config.SecurityEvents.MaxRetentionDays,
		EnabledEvents:    convertToSecurityEventTypes(config.SecurityEvents.EnabledEvents),
		AlertThresholds:  convertToSecurityEventThresholds(config.SecurityEvents.AlertThresholds),
	}); err != nil {
		return fmt.Errorf("failed to initialize security event logger: %w", err)
	}

	logging.InfoLogger.Printf("Security configuration applied successfully")
	return nil
}

// Helper functions for type conversion
func convertToSecurityEventTypes(events []string) []logging.SecurityEventType {
	var result []logging.SecurityEventType
	for _, event := range events {
		result = append(result, logging.SecurityEventType(event))
	}
	return result
}

func convertToSecurityEventThresholds(thresholds map[string]int) map[logging.SecurityEventType]int {
	result := make(map[logging.SecurityEventType]int)
	for event, threshold := range thresholds {
		result[logging.SecurityEventType(event)] = threshold
	}
	return result
}
