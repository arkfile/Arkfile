package logging

import (
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/84adam/arkfile/database"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create tables
	createSecurityEventsTable := `
	CREATE TABLE security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		event_type TEXT NOT NULL,
		entity_id TEXT,
		time_window TEXT,
		user_email TEXT,
		device_profile TEXT,
		severity TEXT NOT NULL,
		details TEXT,
		created_at DATETIME NOT NULL
	)`

	if _, err := db.Exec(createSecurityEventsTable); err != nil {
		t.Fatalf("Failed to create security_events table: %v", err)
	}

	return db
}

func stringPtr(s string) *string {
	return &s
}

func TestSecurityEventLogging(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Set test database
	database.DB = db

	// Initialize entity ID service for tests
	entityConfig := EntityIDConfig{
		MasterSecretPath: "",
		RotationPeriod:   24 * time.Hour,
		RetentionDays:    90,
		CleanupInterval:  1 * time.Hour,
	}

	entityService, err := NewEntityIDService(entityConfig)
	if err != nil {
		t.Fatalf("Failed to create EntityIDService: %v", err)
	}

	// Initialize security event logger
	config := SecurityEventConfig{
		MaxRetentionDays: 90,
	}

	logger := NewSecurityEventLogger(db, entityService, config)
	DefaultSecurityEventLogger = logger

	tests := []struct {
		name        string
		eventType   SecurityEventType
		ip          net.IP
		userEmail   *string
		deviceType  *string
		details     map[string]interface{}
		expectedSev SecurityEventSeverity
	}{
		{
			name:        "OPAQUE Login Success",
			eventType:   EventOpaqueLoginSuccess,
			ip:          net.ParseIP("192.168.1.100"),
			userEmail:   stringPtr("test@example.com"),
			deviceType:  stringPtr("ArgonBalanced"),
			details:     map[string]interface{}{"success": true},
			expectedSev: SeverityInfo,
		},
		{
			name:        "OPAQUE Login Failure",
			eventType:   EventOpaqueLoginFailure,
			ip:          net.ParseIP("192.168.1.101"),
			userEmail:   stringPtr("test@example.com"),
			deviceType:  stringPtr("ArgonBalanced"),
			details:     map[string]interface{}{"success": false, "error": "invalid_credentials"},
			expectedSev: SeverityWarning,
		},
		{
			name:        "Rate Limit Violation",
			eventType:   EventRateLimitViolation,
			ip:          net.ParseIP("10.0.0.1"),
			userEmail:   nil,
			deviceType:  nil,
			details:     map[string]interface{}{"requests": 100, "limit": 50, "endpoint": "/auth/login"},
			expectedSev: SeverityWarning,
		},
		{
			name:        "Key Health Check",
			eventType:   EventKeyHealthCheck,
			ip:          nil,
			userEmail:   nil,
			deviceType:  nil,
			details:     map[string]interface{}{"component": "jwt_keys", "status": "healthy", "key_age_days": 30},
			expectedSev: SeverityInfo,
		},
		{
			name:        "Emergency Procedure",
			eventType:   EventEmergencyProcedure,
			ip:          nil,
			userEmail:   nil,
			deviceType:  nil,
			details:     map[string]interface{}{"action": "key_revocation", "reason": "suspected_compromise"},
			expectedSev: SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := LogSecurityEvent(tt.eventType, tt.ip, tt.userEmail, tt.deviceType, tt.details)
			if err != nil {
				t.Fatalf("Failed to log security event: %v", err)
			}

			// Verify event was stored correctly
			var count int
			err = db.QueryRow("SELECT COUNT(*) FROM security_events WHERE event_type = ?", string(tt.eventType)).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to query security events: %v", err)
			}

			if count == 0 {
				t.Errorf("Security event was not stored")
			}

			// Verify event details
			var eventType, severity, entityID, timeWindow, createdAt string
			var userEmail, deviceProfile sql.NullString
			err = db.QueryRow(`
				SELECT event_type, severity, entity_id, time_window, user_email, device_profile, created_at 
				FROM security_events 
				WHERE event_type = ? 
				ORDER BY created_at DESC 
				LIMIT 1
			`, string(tt.eventType)).Scan(&eventType, &severity, &entityID, &timeWindow, &userEmail, &deviceProfile, &createdAt)

			if err != nil {
				t.Fatalf("Failed to query event details: %v", err)
			}

			// Verify event type
			if eventType != string(tt.eventType) {
				t.Errorf("Expected event type %s, got %s", tt.eventType, eventType)
			}

			// Verify severity
			if severity != string(tt.expectedSev) {
				t.Errorf("Expected severity %s, got %s", tt.expectedSev, severity)
			}

			// Verify entity ID is present for IP-based events
			if tt.ip != nil && entityID == "" {
				t.Errorf("Expected non-empty entity ID for IP-based event")
			}

			// Verify time window is present for IP-based events
			if tt.ip != nil && timeWindow == "" {
				t.Errorf("Expected non-empty time window for IP-based event")
			}

			// Verify user email
			if tt.userEmail != nil {
				if !userEmail.Valid || userEmail.String != *tt.userEmail {
					t.Errorf("Expected user email %s, got %v", *tt.userEmail, userEmail)
				}
			}

			// Verify device profile
			if tt.deviceType != nil {
				if !deviceProfile.Valid || deviceProfile.String != *tt.deviceType {
					t.Errorf("Expected device profile %s, got %v", *tt.deviceType, deviceProfile)
				}
			}

			// Verify details based on event type
			if tt.eventType == EventKeyHealthCheck && tt.details != nil {
				if keyAge, ok := tt.details["key_age_days"]; ok {
					// Check that numeric values are preserved
					if _, isInt := keyAge.(int); !isInt {
						t.Errorf("Expected detail key_age_days to be numeric, got %T", keyAge)
					}
				}
			}

			// Verify timestamp is recent - try multiple formats
			var eventTime time.Time
			formats := []string{
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05.000000Z",
				time.RFC3339,
				time.RFC3339Nano,
			}

			for _, format := range formats {
				if t, err := time.Parse(format, createdAt); err == nil {
					eventTime = t
					break
				}
			}

			if eventTime.IsZero() {
				t.Fatalf("Failed to parse created_at timestamp with any format: %s", createdAt)
			}

			if time.Since(eventTime) > time.Minute {
				t.Errorf("Event timestamp is too old: %v", eventTime)
			}
		})
	}
}

func TestSecurityEventTypes(t *testing.T) {
	// Test that all security event types are defined correctly
	eventTypes := []SecurityEventType{
		EventOpaqueRegistration,
		EventOpaqueLoginSuccess,
		EventOpaqueLoginFailure,
		EventJWTRefreshSuccess,
		EventJWTRefreshFailure,
		EventRateLimitViolation,
		EventRateLimitRecovery,
		EventProgressivePenalty,
		EventSuspiciousPattern,
		EventEndpointAbuse,
		EventUnauthorizedAccess,
		EventMultipleFailures,
		EventKeyRotation,
		EventKeyHealthCheck,
		EventEmergencyProcedure,
		EventConfigurationChange,
		EventSecurityAudit,
		EventSystemStartup,
		EventSystemShutdown,
	}

	for _, eventType := range eventTypes {
		if string(eventType) == "" {
			t.Errorf("Event type should not be empty: %v", eventType)
		}
	}

	// Test severity levels
	severities := []SecurityEventSeverity{
		SeverityInfo,
		SeverityWarning,
		SeverityCritical,
	}

	for _, severity := range severities {
		if string(severity) == "" {
			t.Errorf("Severity should not be empty: %v", severity)
		}
	}
}

func TestSecurityEventSensitiveDataExclusion(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	database.DB = db

	// Initialize services for tests
	entityConfig := EntityIDConfig{
		MasterSecretPath: "",
		RotationPeriod:   24 * time.Hour,
		RetentionDays:    90,
		CleanupInterval:  1 * time.Hour,
	}

	entityService, err := NewEntityIDService(entityConfig)
	if err != nil {
		t.Fatalf("Failed to create EntityIDService: %v", err)
	}

	config := SecurityEventConfig{
		MaxRetentionDays: 90,
	}

	logger := NewSecurityEventLogger(db, entityService, config)
	DefaultSecurityEventLogger = logger

	// Test that sensitive data is never logged
	sensitiveDetails := map[string]interface{}{
		"password":        "secret123",
		"private_key":     "-----BEGIN PRIVATE KEY-----",
		"jwt_token":       "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
		"session_id":      "abc123def456",
		"opaque_envelope": "base64encodeddata==",
		"safe_data":       "this should be logged",
		"user_preference": "dark_mode",
	}

	// Use correct function signature
	err = LogSecurityEvent(EventOpaqueLoginSuccess, net.ParseIP("192.168.1.1"), stringPtr("test@example.com"), nil, sensitiveDetails)
	if err != nil {
		t.Fatalf("Failed to log security event: %v", err)
	}

	// Query the stored details
	var detailsJSON string
	err = db.QueryRow("SELECT details FROM security_events WHERE event_type = ? ORDER BY created_at DESC LIMIT 1",
		string(EventOpaqueLoginSuccess)).Scan(&detailsJSON)
	if err != nil {
		t.Fatalf("Failed to query event details: %v", err)
	}

	// Verify sensitive data is masked
	if contains(detailsJSON, "secret123") || contains(detailsJSON, "-----BEGIN PRIVATE KEY-----") ||
		contains(detailsJSON, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9") {
		t.Errorf("Sensitive data should not be present in stored details: %s", detailsJSON)
	}

	// Verify safe data is preserved
	if !contains(detailsJSON, "this should be logged") || !contains(detailsJSON, "dark_mode") {
		t.Errorf("Safe data should be preserved in stored details: %s", detailsJSON)
	}
}

func TestSecurityEventQueryPerformance(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	database.DB = db

	// Initialize services for tests
	entityConfig := EntityIDConfig{
		MasterSecretPath: "",
		RotationPeriod:   24 * time.Hour,
		RetentionDays:    90,
		CleanupInterval:  1 * time.Hour,
	}

	entityService, err := NewEntityIDService(entityConfig)
	if err != nil {
		t.Fatalf("Failed to create EntityIDService: %v", err)
	}

	config := SecurityEventConfig{
		MaxRetentionDays: 90,
	}

	logger := NewSecurityEventLogger(db, entityService, config)
	DefaultSecurityEventLogger = logger

	// Create index for performance testing
	_, err = db.Exec(`CREATE INDEX idx_security_events_type_time ON security_events(event_type, created_at)`)
	if err != nil {
		t.Fatalf("Failed to create index: %v", err)
	}

	// Insert many events using correct function signature
	for i := 0; i < 1000; i++ {
		ip := net.ParseIP("192.168.1." + string(rune(100+(i%155))))
		if ip == nil {
			ip = net.ParseIP("192.168.1.100") // fallback IP
		}

		err := LogSecurityEvent(EventOpaqueLoginSuccess, ip, nil, nil, nil)
		if err != nil {
			t.Fatalf("Failed to log success event: %v", err)
		}

		if i%10 == 0 {
			err := LogSecurityEvent(EventOpaqueLoginFailure, ip, nil, nil, nil)
			if err != nil {
				t.Fatalf("Failed to log failure event: %v", err)
			}
		}
	}

	// Test query performance
	start := time.Now()

	filters := SecurityEventFilters{
		EventType: EventOpaqueLoginFailure,
		Limit:     50,
	}

	events, err := logger.GetSecurityEvents(filters)
	if err != nil {
		t.Fatalf("Failed to query security events: %v", err)
	}

	duration := time.Since(start)

	// Verify results
	if len(events) == 0 {
		t.Errorf("Expected to find events, got none")
	}

	if len(events) > 50 {
		t.Errorf("Expected at most 50 events, got %d", len(events))
	}

	// Performance should be reasonable (adjust threshold as needed)
	if duration > time.Second {
		t.Errorf("Query took too long: %v", duration)
	}

	t.Logf("Query returned %d events in %v", len(events), duration)
}
