package monitoring

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
)

// KeyHealthStatus represents the health status of a cryptographic component
type KeyHealthStatus string

const (
	HealthStatusHealthy  KeyHealthStatus = "healthy"
	HealthStatusWarning  KeyHealthStatus = "warning"
	HealthStatusCritical KeyHealthStatus = "critical"
	HealthStatusUnknown  KeyHealthStatus = "unknown"
)

// KeyComponent represents a monitored cryptographic component
type KeyComponent struct {
	Name         string                 `json:"name"`
	Type         string                 `json:"type"` // "opaque_server", "jwt_signing", "tls_cert", "entity_id"
	Path         string                 `json:"path"` // File path or identifier
	Status       KeyHealthStatus        `json:"status"`
	LastChecked  time.Time              `json:"last_checked"`
	NextCheck    time.Time              `json:"next_check"`
	Details      map[string]interface{} `json:"details"`
	AlertLevel   string                 `json:"alert_level"`
	ErrorMessage string                 `json:"error_message,omitempty"`
}

// KeyHealthMonitor monitors the health of cryptographic keys and certificates
type KeyHealthMonitor struct {
	db       *sql.DB
	config   config.MonitoringConfig
	stopChan chan bool
}

// NewKeyHealthMonitor creates a new key health monitor
func NewKeyHealthMonitor(db *sql.DB, monitoringConfig config.MonitoringConfig) *KeyHealthMonitor {
	return &KeyHealthMonitor{
		db:       db,
		config:   monitoringConfig,
		stopChan: make(chan bool),
	}
}

// Start begins the key health monitoring routine
func (khm *KeyHealthMonitor) Start() {
	logging.InfoLogger.Printf("Starting key health monitoring")

	// Perform initial health check
	khm.PerformHealthCheck()

	// Start periodic health checks
	ticker := time.NewTicker(khm.config.KeyHealthInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				khm.PerformHealthCheck()
			case <-khm.stopChan:
				return
			}
		}
	}()
}

// Stop stops the key health monitoring routine
func (khm *KeyHealthMonitor) Stop() {
	close(khm.stopChan)
	logging.InfoLogger.Printf("Key health monitoring stopped")
}

// PerformHealthCheck performs a comprehensive health check of all key components
func (khm *KeyHealthMonitor) PerformHealthCheck() {
	logging.InfoLogger.Printf("Performing key health check")

	components := []KeyComponent{
		{
			Name: "OPAQUE Server Keys",
			Type: "opaque_server",
			Path: "/opt/arkfile/etc/keys/opaque/server.key",
		},
		{
			Name: "JWT Signing Key",
			Type: "jwt_signing",
			Path: "/opt/arkfile/etc/keys/jwt/signing.key",
		},
		{
			Name: "Entity ID Master Secret",
			Type: "entity_id",
			Path: "/opt/arkfile/etc/keys/entity_id/master.key",
		},
		{
			Name: "TLS Certificate",
			Type: "tls_cert",
			Path: "/opt/arkfile/etc/tls/server.crt",
		},
		{
			Name: "MinIO TLS Certificate",
			Type: "tls_cert",
			Path: "/opt/arkfile/etc/tls/minio.crt",
		},
		{
			Name: "rqlite TLS Certificate",
			Type: "tls_cert",
			Path: "/opt/arkfile/etc/tls/rqlite.crt",
		},
	}

	for _, component := range components {
		khm.checkComponent(&component)
		khm.saveComponentStatus(component)
	}

	// Log overall health summary
	khm.logHealthSummary()
}

// checkComponent checks the health of a specific key component
func (khm *KeyHealthMonitor) checkComponent(component *KeyComponent) {
	component.LastChecked = time.Now().UTC()
	component.NextCheck = time.Now().UTC().Add(khm.config.KeyHealthInterval)
	component.Details = make(map[string]interface{})
	component.ErrorMessage = ""

	switch component.Type {
	case "opaque_server":
		khm.checkOpaqueServerKeys(component)
	case "jwt_signing":
		khm.checkJWTSigningKey(component)
	case "entity_id":
		khm.checkEntityIDKey(component)
	case "tls_cert":
		khm.checkTLSCertificate(component)
	default:
		component.Status = HealthStatusUnknown
		component.ErrorMessage = "Unknown component type"
	}

	// Log status changes
	khm.logStatusChange(component)
}

// checkOpaqueServerKeys checks OPAQUE server key health
func (khm *KeyHealthMonitor) checkOpaqueServerKeys(component *KeyComponent) {
	// Check if OPAQUE server keys exist and are accessible
	if !khm.fileExists(component.Path) {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = "OPAQUE server key file not found"
		component.Details["issue"] = "missing_file"
		return
	}

	// Check file permissions
	if !khm.checkFilePermissions(component.Path, 0600) {
		component.Status = HealthStatusWarning
		component.AlertLevel = "WARNING"
		component.ErrorMessage = "OPAQUE server key has incorrect permissions"
		component.Details["issue"] = "incorrect_permissions"
		return
	}

	// Check file age and size
	fileInfo, err := os.Stat(component.Path)
	if err != nil {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = fmt.Sprintf("Cannot access OPAQUE server key: %v", err)
		component.Details["issue"] = "access_error"
		return
	}

	component.Details["file_size"] = fileInfo.Size()
	component.Details["file_age_days"] = int(time.Since(fileInfo.ModTime()).Hours() / 24)

	// Check if key needs rotation (older than 30 days)
	if time.Since(fileInfo.ModTime()) > khm.config.KeyRotationOverdue {
		component.Status = HealthStatusWarning
		component.AlertLevel = "WARNING"
		component.ErrorMessage = "OPAQUE server key is overdue for rotation"
		component.Details["issue"] = "rotation_overdue"
		return
	}

	component.Status = HealthStatusHealthy
	component.AlertLevel = "INFO"
}

// checkJWTSigningKey checks JWT signing key health
func (khm *KeyHealthMonitor) checkJWTSigningKey(component *KeyComponent) {
	if !khm.fileExists(component.Path) {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = "JWT signing key file not found"
		component.Details["issue"] = "missing_file"
		return
	}

	if !khm.checkFilePermissions(component.Path, 0600) {
		component.Status = HealthStatusWarning
		component.AlertLevel = "WARNING"
		component.ErrorMessage = "JWT signing key has incorrect permissions"
		component.Details["issue"] = "incorrect_permissions"
		return
	}

	fileInfo, err := os.Stat(component.Path)
	if err != nil {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = fmt.Sprintf("Cannot access JWT signing key: %v", err)
		component.Details["issue"] = "access_error"
		return
	}

	component.Details["file_size"] = fileInfo.Size()
	component.Details["file_age_days"] = int(time.Since(fileInfo.ModTime()).Hours() / 24)

	// JWT keys should be rotated more frequently (weekly)
	if time.Since(fileInfo.ModTime()) > 7*24*time.Hour {
		component.Status = HealthStatusWarning
		component.AlertLevel = "WARNING"
		component.ErrorMessage = "JWT signing key should be rotated"
		component.Details["issue"] = "rotation_recommended"
		return
	}

	component.Status = HealthStatusHealthy
	component.AlertLevel = "INFO"
}

// checkEntityIDKey checks Entity ID master secret health
func (khm *KeyHealthMonitor) checkEntityIDKey(component *KeyComponent) {
	// Check Entity ID service health directly
	if logging.DefaultEntityIDService == nil {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = "Entity ID service not initialized"
		component.Details["issue"] = "service_not_initialized"
		return
	}

	// Check master secret hash
	secretHash := logging.DefaultEntityIDService.GetMasterSecretHash()
	if secretHash == "" {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = "Entity ID master secret not accessible"
		component.Details["issue"] = "secret_not_accessible"
		return
	}

	component.Details["secret_hash"] = secretHash
	component.Details["current_window"] = logging.DefaultEntityIDService.GetCurrentTimeWindow()

	component.Status = HealthStatusHealthy
	component.AlertLevel = "INFO"
}

// checkTLSCertificate checks TLS certificate health and expiry
func (khm *KeyHealthMonitor) checkTLSCertificate(component *KeyComponent) {
	if !khm.fileExists(component.Path) {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = "TLS certificate file not found"
		component.Details["issue"] = "missing_file"
		return
	}

	// Read and parse certificate
	certData, err := os.ReadFile(component.Path)
	if err != nil {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = fmt.Sprintf("Cannot read TLS certificate: %v", err)
		component.Details["issue"] = "read_error"
		return
	}

	// Calculate certificate hash for change detection
	certHash := sha256.Sum256(certData)
	component.Details["cert_hash"] = hex.EncodeToString(certHash[:8])

	// For basic health check, just verify file accessibility
	// In a full implementation, we would parse the certificate and check expiry
	fileInfo, err := os.Stat(component.Path)
	if err != nil {
		component.Status = HealthStatusCritical
		component.AlertLevel = "CRITICAL"
		component.ErrorMessage = fmt.Sprintf("Cannot access TLS certificate: %v", err)
		component.Details["issue"] = "access_error"
		return
	}

	component.Details["file_size"] = fileInfo.Size()
	component.Details["file_age_days"] = int(time.Since(fileInfo.ModTime()).Hours() / 24)

	// Warn if certificate file is very old (might indicate stale cert)
	if time.Since(fileInfo.ModTime()) > 30*24*time.Hour {
		component.Status = HealthStatusWarning
		component.AlertLevel = "WARNING"
		component.ErrorMessage = "TLS certificate file is old, check expiry"
		component.Details["issue"] = "old_certificate"
		return
	}

	component.Status = HealthStatusHealthy
	component.AlertLevel = "INFO"
}

// fileExists checks if a file exists
func (khm *KeyHealthMonitor) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// checkFilePermissions checks if a file has the correct permissions
func (khm *KeyHealthMonitor) checkFilePermissions(path string, expectedPerm os.FileMode) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.Mode().Perm() == expectedPerm
}

// saveComponentStatus saves component health status to database
func (khm *KeyHealthMonitor) saveComponentStatus(component KeyComponent) {
	query := `INSERT OR REPLACE INTO key_health_status 
              (component, status, last_checked, next_check, details, alert_level, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)`

	detailsJSON := "{}"
	if len(component.Details) > 0 {
		if data, err := json.Marshal(component.Details); err == nil {
			detailsJSON = string(data)
		}
	}

	_, err := khm.db.Exec(query,
		component.Name,
		string(component.Status),
		component.LastChecked,
		component.NextCheck,
		detailsJSON,
		component.AlertLevel,
		time.Now().UTC(),
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to save key health status for %s: %v", component.Name, err)
	}
}

// logStatusChange logs significant status changes
func (khm *KeyHealthMonitor) logStatusChange(component *KeyComponent) {
	// Get previous status from database for comparison
	var previousStatus string
	query := `SELECT status FROM key_health_status WHERE component = ?`
	err := khm.db.QueryRow(query, component.Name).Scan(&previousStatus)

	if err != nil && err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("Failed to get previous status for %s: %v", component.Name, err)
		return
	}

	// Log if status changed or if there's an issue
	if previousStatus != string(component.Status) || component.Status != HealthStatusHealthy {
		message := fmt.Sprintf("Key Health: %s status changed from %s to %s",
			component.Name, previousStatus, component.Status)

		if component.ErrorMessage != "" {
			message += fmt.Sprintf(" - %s", component.ErrorMessage)
		}

		switch component.Status {
		case HealthStatusCritical:
			logging.ErrorLogger.Printf("%s", message)
			// Log security event for critical issues
			logging.LogSecurityEvent(
				logging.EventKeyHealthCheck,
				nil,
				nil,
				nil,
				map[string]interface{}{
					"component":     component.Name,
					"status":        component.Status,
					"previous":      previousStatus,
					"error_message": component.ErrorMessage,
					"details":       component.Details,
				},
			)
		case HealthStatusWarning:
			logging.WarningLogger.Printf("%s", message)
		default:
			logging.InfoLogger.Printf("%s", message)
		}
	}
}

// logHealthSummary logs a summary of overall key health
func (khm *KeyHealthMonitor) logHealthSummary() {
	query := `SELECT status, COUNT(*) FROM key_health_status GROUP BY status`
	rows, err := khm.db.Query(query)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get health summary: %v", err)
		return
	}
	defer rows.Close()

	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			logging.ErrorLogger.Printf("Failed to scan health summary row: %v", err)
			continue
		}
		statusCounts[status] = count
	}

	// Log summary
	totalComponents := 0
	for _, count := range statusCounts {
		totalComponents += count
	}

	if totalComponents == 0 {
		logging.InfoLogger.Printf("Key Health Summary: No components monitored")
		return
	}

	summary := fmt.Sprintf("Key Health Summary: %d components total", totalComponents)
	if healthy := statusCounts["healthy"]; healthy > 0 {
		summary += fmt.Sprintf(", %d healthy", healthy)
	}
	if warning := statusCounts["warning"]; warning > 0 {
		summary += fmt.Sprintf(", %d warning", warning)
	}
	if critical := statusCounts["critical"]; critical > 0 {
		summary += fmt.Sprintf(", %d critical", critical)
	}
	if unknown := statusCounts["unknown"]; unknown > 0 {
		summary += fmt.Sprintf(", %d unknown", unknown)
	}

	logging.InfoLogger.Printf("%s", summary)

	// Escalate if there are critical issues
	if statusCounts["critical"] > 0 {
		logging.ErrorLogger.Printf("ALERT: %d critical key health issues detected", statusCounts["critical"])
		khm.escalateCriticalIssues()
	}
}

// escalateCriticalIssues handles escalation of critical key health issues
func (khm *KeyHealthMonitor) escalateCriticalIssues() {
	// Log security event for critical key health issues
	logging.LogSecurityEvent(
		logging.EventEmergencyProcedure,
		nil,
		nil,
		nil,
		map[string]interface{}{
			"reason": "critical_key_health_issues",
			"action": "escalation_triggered",
		},
	)

	// In a full implementation, this would trigger alerts, notifications, etc.
	logging.ErrorLogger.Printf("Critical key health issues require immediate attention")
}

// GetHealthStatus returns the current health status of all components
func (khm *KeyHealthMonitor) GetHealthStatus() ([]KeyComponent, error) {
	query := `SELECT component, status, last_checked, next_check, details, alert_level, updated_at 
              FROM key_health_status ORDER BY component`

	rows, err := khm.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query health status: %w", err)
	}
	defer rows.Close()

	var components []KeyComponent
	for rows.Next() {
		var component KeyComponent
		var detailsJSON string
		var updatedAt time.Time

		err := rows.Scan(
			&component.Name,
			&component.Status,
			&component.LastChecked,
			&component.NextCheck,
			&detailsJSON,
			&component.AlertLevel,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan health status row: %w", err)
		}

		// Parse details JSON
		if detailsJSON != "" {
			var details map[string]interface{}
			if err := json.Unmarshal([]byte(detailsJSON), &details); err == nil {
				component.Details = details
			}
		}

		components = append(components, component)
	}

	return components, nil
}

// Global key health monitor instance
var DefaultKeyHealthMonitor *KeyHealthMonitor

// InitializeKeyHealthMonitor initializes the global key health monitor
func InitializeKeyHealthMonitor(monitoringConfig config.MonitoringConfig) error {
	if database.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	DefaultKeyHealthMonitor = NewKeyHealthMonitor(database.DB, monitoringConfig)
	DefaultKeyHealthMonitor.Start()

	logging.InfoLogger.Printf("Key health monitor initialized and started")
	return nil
}

// StopKeyHealthMonitor stops the global key health monitor
func StopKeyHealthMonitor() {
	if DefaultKeyHealthMonitor != nil {
		DefaultKeyHealthMonitor.Stop()
	}
}
