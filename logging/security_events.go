package logging

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/84adam/arkfile/database"
)

// SecurityEventType defines the types of security events that can be logged
type SecurityEventType string

const (
	// Authentication events
	EventOpaqueRegistration SecurityEventType = "opaque_registration"
	EventOpaqueLoginSuccess SecurityEventType = "opaque_login_success"
	EventOpaqueLoginFailure SecurityEventType = "opaque_login_failure"
	EventJWTRefreshSuccess  SecurityEventType = "jwt_refresh_success"
	EventJWTRefreshFailure  SecurityEventType = "jwt_refresh_failure"

	// Rate limiting events
	EventRateLimitViolation SecurityEventType = "rate_limit_violation"
	EventRateLimitRecovery  SecurityEventType = "rate_limit_recovery"
	EventProgressivePenalty SecurityEventType = "progressive_penalty"

	// Access pattern events
	EventSuspiciousPattern  SecurityEventType = "suspicious_pattern"
	EventEndpointAbuse      SecurityEventType = "endpoint_abuse"
	EventUnauthorizedAccess SecurityEventType = "unauthorized_access"
	EventMultipleFailures   SecurityEventType = "multiple_failures"

	// Key health events
	EventKeyRotation        SecurityEventType = "key_rotation"
	EventKeyHealthCheck     SecurityEventType = "key_health_check"
	EventEmergencyProcedure SecurityEventType = "emergency_procedure"

	// System security events
	EventConfigurationChange SecurityEventType = "configuration_change"
	EventSecurityAudit       SecurityEventType = "security_audit"
	EventSystemStartup       SecurityEventType = "system_startup"
	EventSystemShutdown      SecurityEventType = "system_shutdown"
	EventAdminAccess         SecurityEventType = "admin_access"
)

// SecurityEventSeverity defines the severity levels for security events
type SecurityEventSeverity string

const (
	SeverityInfo     SecurityEventSeverity = "INFO"
	SeverityWarning  SecurityEventSeverity = "WARNING"
	SeverityCritical SecurityEventSeverity = "CRITICAL"
)

// SecurityEvent represents a security-related event with privacy-preserving entity identification
type SecurityEvent struct {
	ID            int64                  `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     SecurityEventType      `json:"event_type"`
	EntityID      string                 `json:"entity_id"`      // HMAC-based, non-reversible
	TimeWindow    string                 `json:"time_window"`    // "2025-06-20"
	Username      *string                `json:"username"`       // Only for authenticated events
	DeviceProfile *string                `json:"device_profile"` // OPAQUE export key context
	Severity      SecurityEventSeverity  `json:"severity"`
	Details       map[string]interface{} `json:"details"`
	CreatedAt     time.Time              `json:"created_at"`
}

// SecurityEventLogger handles logging of security events with privacy protection
type SecurityEventLogger struct {
	db               *sql.DB
	entityIDService  *EntityIDService
	maxRetentionDays int
}

// SecurityEventConfig configures security event logging
type SecurityEventConfig struct {
	MaxRetentionDays int                       `json:"max_retention_days"` // 90
	EnabledEvents    []SecurityEventType       `json:"enabled_events"`
	AlertThresholds  map[SecurityEventType]int `json:"alert_thresholds"`
}

// NewSecurityEventLogger creates a new security event logger
func NewSecurityEventLogger(db *sql.DB, entityIDService *EntityIDService, config SecurityEventConfig) *SecurityEventLogger {
	return &SecurityEventLogger{
		db:               db,
		entityIDService:  entityIDService,
		maxRetentionDays: config.MaxRetentionDays,
	}
}

// LogSecurityEvent logs a security event with privacy-preserving entity identification
func (sel *SecurityEventLogger) LogSecurityEvent(eventType SecurityEventType, ip net.IP, username *string, deviceProfile *string, details map[string]interface{}) error {
	// Generate privacy-preserving entity ID
	entityID := ""
	timeWindow := ""
	if sel.entityIDService != nil && ip != nil {
		entityID = sel.entityIDService.GetEntityID(ip)
		timeWindow = sel.entityIDService.GetCurrentTimeWindow()
	}

	// Determine severity based on event type
	severity := sel.getSeverityForEventType(eventType)

	// Sanitize details to ensure no sensitive information is logged
	sanitizedDetails := sel.sanitizeDetails(details)

	// Create security event
	event := SecurityEvent{
		Timestamp:     time.Now().UTC(),
		EventType:     eventType,
		EntityID:      entityID,
		TimeWindow:    timeWindow,
		Username:      username,
		DeviceProfile: deviceProfile,
		Severity:      severity,
		Details:       sanitizedDetails,
		CreatedAt:     time.Now().UTC(),
	}

	// Store in database
	if err := sel.storeSecurityEvent(event); err != nil {
		ErrorLogger.Printf("Failed to store security event: %v", err)
		return err
	}

	// Log to file based on severity
	sel.logToFile(event)

	return nil
}

// LogAuthenticationEvent logs authentication-related events
func (sel *SecurityEventLogger) LogAuthenticationEvent(eventType SecurityEventType, ip net.IP, username *string, deviceProfile *string, success bool, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["success"] = success
	details["authentication_type"] = "opaque"

	return sel.LogSecurityEvent(eventType, ip, username, deviceProfile, details)
}

// LogRateLimitEvent logs rate limiting events
func (sel *SecurityEventLogger) LogRateLimitEvent(eventType SecurityEventType, ip net.IP, endpoint string, requestCount int, limit int, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["endpoint"] = endpoint
	details["request_count"] = requestCount
	details["limit"] = limit
	details["violation_ratio"] = float64(requestCount) / float64(limit)

	return sel.LogSecurityEvent(eventType, ip, nil, nil, details)
}

// LogKeyHealthEvent logs key health and rotation events
func (sel *SecurityEventLogger) LogKeyHealthEvent(eventType SecurityEventType, component string, status string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["component"] = component
	details["status"] = status

	// Key health events don't have associated IP addresses
	return sel.LogSecurityEvent(eventType, nil, nil, nil, details)
}

// GetSecurityEvents retrieves security events with filtering options
func (sel *SecurityEventLogger) GetSecurityEvents(filters SecurityEventFilters) ([]SecurityEvent, error) {
	query := `SELECT id, timestamp, event_type, entity_id, time_window, username, device_profile, severity, details, created_at FROM security_events WHERE 1=1`
	args := []interface{}{}
	argCount := 0

	// Add filters
	if filters.EventType != "" {
		argCount++
		query += fmt.Sprintf(" AND event_type = $%d", argCount)
		args = append(args, string(filters.EventType))
	}

	if filters.EntityID != "" {
		argCount++
		query += fmt.Sprintf(" AND entity_id = $%d", argCount)
		args = append(args, filters.EntityID)
	}

	if filters.TimeWindow != "" {
		argCount++
		query += fmt.Sprintf(" AND time_window = $%d", argCount)
		args = append(args, filters.TimeWindow)
	}

	if !filters.StartTime.IsZero() {
		argCount++
		query += fmt.Sprintf(" AND timestamp >= $%d", argCount)
		args = append(args, filters.StartTime)
	}

	if !filters.EndTime.IsZero() {
		argCount++
		query += fmt.Sprintf(" AND timestamp <= $%d", argCount)
		args = append(args, filters.EndTime)
	}

	if filters.Severity != "" {
		argCount++
		query += fmt.Sprintf(" AND severity = $%d", argCount)
		args = append(args, string(filters.Severity))
	}

	// Add ordering and limit
	query += " ORDER BY timestamp DESC"
	if filters.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filters.Limit)
	}

	rows, err := sel.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query security events: %w", err)
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var event SecurityEvent
		var detailsJSON string

		err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.EventType,
			&event.EntityID,
			&event.TimeWindow,
			&event.Username,
			&event.DeviceProfile,
			&event.Severity,
			&detailsJSON,
			&event.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan security event: %w", err)
		}

		// Parse details JSON
		if detailsJSON != "" {
			if err := json.Unmarshal([]byte(detailsJSON), &event.Details); err != nil {
				event.Details = map[string]interface{}{"parse_error": detailsJSON}
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// SecurityEventFilters defines filtering options for security event queries
type SecurityEventFilters struct {
	EventType  SecurityEventType
	EntityID   string
	TimeWindow string
	StartTime  time.Time
	EndTime    time.Time
	Severity   SecurityEventSeverity
	Limit      int
}

// CleanupOldEvents removes security events older than the retention period
func (sel *SecurityEventLogger) CleanupOldEvents() error {
	cutoffDate := time.Now().UTC().AddDate(0, 0, -sel.maxRetentionDays)

	result, err := sel.db.Exec("DELETE FROM security_events WHERE created_at < ?", cutoffDate)
	if err != nil {
		return fmt.Errorf("failed to cleanup old security events: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	InfoLogger.Printf("Cleaned up %d old security events older than %s", rowsAffected, cutoffDate.Format("2006-01-02"))

	return nil
}

// storeSecurityEvent stores a security event in the database
func (sel *SecurityEventLogger) storeSecurityEvent(event SecurityEvent) error {
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	query := `INSERT INTO security_events (timestamp, event_type, entity_id, time_window, username, device_profile, severity, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = sel.db.Exec(query,
		event.Timestamp,
		string(event.EventType),
		event.EntityID,
		event.TimeWindow,
		event.Username,
		event.DeviceProfile,
		string(event.Severity),
		string(detailsJSON),
		event.CreatedAt,
	)

	return err
}

// getSeverityForEventType determines the appropriate severity level for an event type
func (sel *SecurityEventLogger) getSeverityForEventType(eventType SecurityEventType) SecurityEventSeverity {
	switch eventType {
	case EventOpaqueLoginFailure, EventJWTRefreshFailure, EventRateLimitViolation:
		return SeverityWarning
	case EventSuspiciousPattern, EventEndpointAbuse, EventUnauthorizedAccess, EventMultipleFailures, EventEmergencyProcedure:
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// sanitizeDetails removes or masks sensitive information from event details
func (sel *SecurityEventLogger) sanitizeDetails(details map[string]interface{}) map[string]interface{} {
	if details == nil {
		return make(map[string]interface{})
	}

	sanitized := make(map[string]interface{})
	sensitiveKeys := []string{"password", "token", "secret", "key", "ip", "ip_address", "client_ip"}

	for key, value := range details {
		keyLower := strings.ToLower(key)
		isSensitive := false

		// Check if key contains sensitive terms
		for _, sensitiveKey := range sensitiveKeys {
			if strings.Contains(keyLower, sensitiveKey) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			// Mask sensitive values
			sanitized[key] = "[REDACTED]"
		} else {
			// Keep non-sensitive values
			sanitized[key] = value
		}
	}

	return sanitized
}

// logToFile logs the security event to the appropriate log file based on severity
func (sel *SecurityEventLogger) logToFile(event SecurityEvent) {
	message := fmt.Sprintf("Security Event: %s | Entity: %s | Window: %s | Severity: %s",
		event.EventType, event.EntityID, event.TimeWindow, event.Severity)

	if event.Username != nil {
		message += fmt.Sprintf(" | User: %s", *event.Username)
	}

	if event.DeviceProfile != nil {
		message += fmt.Sprintf(" | Profile: %s", *event.DeviceProfile)
	}

	switch event.Severity {
	case SeverityCritical:
		ErrorLogger.Printf("%s", message)
	case SeverityWarning:
		WarningLogger.Printf("%s", message)
	default:
		InfoLogger.Printf("%s", message)
	}
}

// Global security event logger instance
var DefaultSecurityEventLogger *SecurityEventLogger

// InitializeSecurityEventLogger initializes the global security event logger
func InitializeSecurityEventLogger(config SecurityEventConfig) error {
	if database.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	if DefaultEntityIDService == nil {
		return fmt.Errorf("entity ID service not initialized")
	}

	DefaultSecurityEventLogger = NewSecurityEventLogger(database.DB, DefaultEntityIDService, config)

	InfoLogger.Printf("Security event logger initialized with %d day retention", config.MaxRetentionDays)
	return nil
}

// LogSecurityEvent is a convenience function that uses the default logger
func LogSecurityEvent(eventType SecurityEventType, ip net.IP, username *string, deviceProfile *string, details map[string]interface{}) error {
	if DefaultSecurityEventLogger == nil {
		return fmt.Errorf("security event logger not initialized")
	}
	return DefaultSecurityEventLogger.LogSecurityEvent(eventType, ip, username, deviceProfile, details)
}
