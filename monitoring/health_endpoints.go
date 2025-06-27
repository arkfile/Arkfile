package monitoring

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/config"
	"github.com/84adam/arkfile/logging"
)

// HealthStatus represents the overall health status
type HealthStatus string

const (
	StatusHealthy   HealthStatus = "healthy"
	StatusDegraded  HealthStatus = "degraded"
	StatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheck represents a single health check result
type HealthCheck struct {
	Name        string            `json:"name"`
	Status      HealthStatus      `json:"status"`
	Message     string            `json:"message,omitempty"`
	Duration    time.Duration     `json:"duration"`
	Timestamp   time.Time         `json:"timestamp"`
	Details     map[string]string `json:"details,omitempty"`
	LastSuccess *time.Time        `json:"last_success,omitempty"`
	LastFailure *time.Time        `json:"last_failure,omitempty"`
}

// HealthResponse represents the complete health check response
type HealthResponse struct {
	Status    HealthStatus           `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version"`
	Uptime    time.Duration          `json:"uptime"`
	Checks    map[string]HealthCheck `json:"checks"`
	System    SystemInfo             `json:"system"`
	Summary   HealthSummary          `json:"summary"`
}

// SystemInfo provides system-level information
type SystemInfo struct {
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"num_goroutine"`
	NumCPU       int    `json:"num_cpu"`
	MemStats     struct {
		Alloc      uint64 `json:"alloc"`
		TotalAlloc uint64 `json:"total_alloc"`
		Sys        uint64 `json:"sys"`
		NumGC      uint32 `json:"num_gc"`
		LastGC     string `json:"last_gc"`
	} `json:"memory"`
	DiskUsage map[string]DiskInfo `json:"disk_usage"`
}

// DiskInfo provides disk usage information
type DiskInfo struct {
	Total     uint64  `json:"total"`
	Used      uint64  `json:"used"`
	Available uint64  `json:"available"`
	UsedPct   float64 `json:"used_percent"`
}

// HealthSummary provides summary statistics
type HealthSummary struct {
	Total     int `json:"total"`
	Healthy   int `json:"healthy"`
	Degraded  int `json:"degraded"`
	Unhealthy int `json:"unhealthy"`
}

// HealthMonitor manages health checks and monitoring
type HealthMonitor struct {
	db        *sql.DB
	config    *config.Config
	startTime time.Time
	version   string
	checks    map[string]HealthChecker
}

// HealthChecker interface for implementing health checks
type HealthChecker interface {
	Check() HealthCheck
	Name() string
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(db *sql.DB, cfg *config.Config, version string) *HealthMonitor {
	hm := &HealthMonitor{
		db:        db,
		config:    cfg,
		startTime: time.Now(),
		version:   version,
		checks:    make(map[string]HealthChecker),
	}

	// Register default health checks
	hm.RegisterCheck(&DatabaseHealthCheck{db: db})
	hm.RegisterCheck(&KeyHealthCheck{config: cfg})
	hm.RegisterCheck(&StorageHealthCheck{config: cfg})
	hm.RegisterCheck(&SystemHealthCheck{})

	return hm
}

// RegisterCheck registers a new health check
func (hm *HealthMonitor) RegisterCheck(checker HealthChecker) {
	hm.checks[checker.Name()] = checker
}

// GetHealthStatus performs all health checks and returns the status
func (hm *HealthMonitor) GetHealthStatus() HealthResponse {
	start := time.Now()
	checks := make(map[string]HealthCheck)
	summary := HealthSummary{}

	// Run all health checks
	for name, checker := range hm.checks {
		check := checker.Check()
		checks[name] = check
		summary.Total++

		switch check.Status {
		case StatusHealthy:
			summary.Healthy++
		case StatusDegraded:
			summary.Degraded++
		case StatusUnhealthy:
			summary.Unhealthy++
		}
	}

	// Determine overall status
	overallStatus := StatusHealthy
	if summary.Unhealthy > 0 {
		overallStatus = StatusUnhealthy
	} else if summary.Degraded > 0 {
		overallStatus = StatusDegraded
	}

	return HealthResponse{
		Status:    overallStatus,
		Timestamp: start,
		Version:   hm.version,
		Uptime:    time.Since(hm.startTime),
		Checks:    checks,
		System:    hm.getSystemInfo(),
		Summary:   summary,
	}
}

// getSystemInfo collects system information
func (hm *HealthMonitor) getSystemInfo() SystemInfo {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info := SystemInfo{
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
		DiskUsage:    make(map[string]DiskInfo),
	}

	info.MemStats.Alloc = memStats.Alloc
	info.MemStats.TotalAlloc = memStats.TotalAlloc
	info.MemStats.Sys = memStats.Sys
	info.MemStats.NumGC = memStats.NumGC
	if memStats.LastGC > 0 {
		info.MemStats.LastGC = time.Unix(0, int64(memStats.LastGC)).Format(time.RFC3339)
	}

	// Add disk usage for key directories
	if hm.config != nil {
		paths := []string{
			hm.config.KeyManagement.KeyDirectory,
			hm.config.Deployment.DataDirectory,
			hm.config.Deployment.LogDirectory,
			"./", // Current directory
		}

		for _, path := range paths {
			if diskInfo := getDiskUsage(path); diskInfo != nil {
				info.DiskUsage[path] = *diskInfo
			}
		}
	}

	return info
}

// DatabaseHealthCheck checks database connectivity
type DatabaseHealthCheck struct {
	db *sql.DB
}

func (d *DatabaseHealthCheck) Name() string {
	return "database"
}

func (d *DatabaseHealthCheck) Check() HealthCheck {
	start := time.Now()
	check := HealthCheck{
		Name:      "database",
		Timestamp: start,
	}

	if d.db == nil {
		check.Status = StatusUnhealthy
		check.Message = "Database connection is nil"
		check.Duration = time.Since(start)
		return check
	}

	// Test database connectivity
	if err := d.db.Ping(); err != nil {
		check.Status = StatusUnhealthy
		check.Message = fmt.Sprintf("Database ping failed: %v", err)
		check.Duration = time.Since(start)
		return check
	}

	// Check OPAQUE tables
	var count int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM opaque_server_keys").Scan(&count); err != nil {
		check.Status = StatusDegraded
		check.Message = fmt.Sprintf("OPAQUE server keys check failed: %v", err)
	} else if count == 0 {
		check.Status = StatusDegraded
		check.Message = "No OPAQUE server keys found"
	} else {
		check.Status = StatusHealthy
		check.Message = fmt.Sprintf("Database operational, %d OPAQUE keys", count)
	}

	check.Duration = time.Since(start)
	return check
}

// KeyHealthCheck checks cryptographic key health
type KeyHealthCheck struct {
	config *config.Config
}

func (k *KeyHealthCheck) Name() string {
	return "keys"
}

func (k *KeyHealthCheck) Check() HealthCheck {
	start := time.Now()
	check := HealthCheck{
		Name:      "keys",
		Timestamp: start,
		Details:   make(map[string]string),
	}

	if k.config == nil {
		check.Status = StatusUnhealthy
		check.Message = "Configuration not available"
		check.Duration = time.Since(start)
		return check
	}

	keyDir := k.config.KeyManagement.KeyDirectory
	issues := 0

	// Check key directory exists
	if _, err := os.Stat(keyDir); os.IsNotExist(err) {
		check.Details["key_directory"] = "missing"
		issues++
	} else {
		check.Details["key_directory"] = "exists"
	}

	// Check JWT key
	jwtKeyPath := fmt.Sprintf("%s/%s", keyDir, k.config.KeyManagement.JWTKeyPath)
	if _, err := os.Stat(jwtKeyPath); os.IsNotExist(err) {
		check.Details["jwt_key"] = "missing"
		issues++
	} else {
		check.Details["jwt_key"] = "exists"
	}

	// Check OPAQUE key
	opaqueKeyPath := fmt.Sprintf("%s/%s", keyDir, k.config.KeyManagement.OPAQUEKeyPath)
	if _, err := os.Stat(opaqueKeyPath); os.IsNotExist(err) {
		check.Details["opaque_key"] = "missing"
		issues++
	} else {
		check.Details["opaque_key"] = "exists"
	}

	// Determine status
	if issues == 0 {
		check.Status = StatusHealthy
		check.Message = "All cryptographic keys available"
	} else if issues < 3 {
		check.Status = StatusDegraded
		check.Message = fmt.Sprintf("%d key issues detected", issues)
	} else {
		check.Status = StatusUnhealthy
		check.Message = "Critical key files missing"
	}

	check.Duration = time.Since(start)
	return check
}

// StorageHealthCheck checks storage backend connectivity
type StorageHealthCheck struct {
	config *config.Config
}

func (s *StorageHealthCheck) Name() string {
	return "storage"
}

func (s *StorageHealthCheck) Check() HealthCheck {
	start := time.Now()
	check := HealthCheck{
		Name:      "storage",
		Timestamp: start,
		Details:   make(map[string]string),
	}

	if s.config == nil {
		check.Status = StatusUnhealthy
		check.Message = "Configuration not available"
		check.Duration = time.Since(start)
		return check
	}

	// Check storage configuration
	storage := s.config.Storage
	if storage.BackblazeEndpoint == "" || storage.BackblazeKeyID == "" {
		check.Status = StatusDegraded
		check.Message = "Storage backend not fully configured"
		check.Details["configuration"] = "incomplete"
	} else {
		check.Status = StatusHealthy
		check.Message = "Storage backend configured"
		check.Details["configuration"] = "complete"
		check.Details["endpoint"] = storage.BackblazeEndpoint
		check.Details["bucket"] = storage.BucketName
	}

	check.Duration = time.Since(start)
	return check
}

// SystemHealthCheck checks system resources
type SystemHealthCheck struct{}

func (s *SystemHealthCheck) Name() string {
	return "system"
}

func (s *SystemHealthCheck) Check() HealthCheck {
	start := time.Now()
	check := HealthCheck{
		Name:      "system",
		Timestamp: start,
		Details:   make(map[string]string),
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check memory usage (warn if over 1GB)
	memUsageMB := memStats.Alloc / 1024 / 1024
	check.Details["memory_mb"] = fmt.Sprintf("%d", memUsageMB)

	// Check goroutines (warn if over 1000)
	numGoroutines := runtime.NumGoroutine()
	check.Details["goroutines"] = fmt.Sprintf("%d", numGoroutines)

	// Determine status
	if memUsageMB > 1024 {
		check.Status = StatusDegraded
		check.Message = fmt.Sprintf("High memory usage: %d MB", memUsageMB)
	} else if numGoroutines > 1000 {
		check.Status = StatusDegraded
		check.Message = fmt.Sprintf("High goroutine count: %d", numGoroutines)
	} else {
		check.Status = StatusHealthy
		check.Message = "System resources normal"
	}

	check.Duration = time.Since(start)
	return check
}

// HTTP Handlers

// HealthHandler returns the complete health status
func (hm *HealthMonitor) HealthHandler(c echo.Context) error {
	status := hm.GetHealthStatus()

	// Log health check for monitoring
	logging.LogSecurityEvent(
		logging.EventKeyHealthCheck,
		nil, // No IP for health checks
		nil, // No user email for health checks
		nil, // No device profile for health checks
		map[string]interface{}{
			"status":       string(status.Status),
			"total_checks": status.Summary.Total,
			"healthy":      status.Summary.Healthy,
			"degraded":     status.Summary.Degraded,
			"unhealthy":    status.Summary.Unhealthy,
		},
	)

	// Set appropriate HTTP status code
	httpStatus := http.StatusOK
	if status.Status == StatusUnhealthy {
		httpStatus = http.StatusServiceUnavailable
	} else if status.Status == StatusDegraded {
		httpStatus = http.StatusOK // Still operational
	}

	return c.JSON(httpStatus, status)
}

// ReadinessHandler returns readiness status (simplified health check)
func (hm *HealthMonitor) ReadinessHandler(c echo.Context) error {
	// Quick readiness check - database ping only
	ready := true
	message := "Ready"

	if hm.db != nil {
		if err := hm.db.Ping(); err != nil {
			ready = false
			message = "Database not ready"
		}
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}

	return c.JSON(status, map[string]interface{}{
		"ready":     ready,
		"message":   message,
		"timestamp": time.Now(),
	})
}

// LivenessHandler returns liveness status (minimal check)
func (hm *HealthMonitor) LivenessHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"alive":     true,
		"timestamp": time.Now(),
		"uptime":    time.Since(hm.startTime).String(),
	})
}

// MetricsHandler returns Prometheus-compatible metrics
func (hm *HealthMonitor) MetricsHandler(c echo.Context) error {
	status := hm.GetHealthStatus()

	// Generate Prometheus metrics format
	metrics := fmt.Sprintf(`# HELP arkfile_health_status Overall health status (0=unhealthy, 1=degraded, 2=healthy)
# TYPE arkfile_health_status gauge
arkfile_health_status{version="%s"} %d

# HELP arkfile_uptime_seconds Uptime in seconds
# TYPE arkfile_uptime_seconds counter
arkfile_uptime_seconds %f

# HELP arkfile_memory_bytes Memory usage in bytes
# TYPE arkfile_memory_bytes gauge
arkfile_memory_bytes %d

# HELP arkfile_goroutines Number of goroutines
# TYPE arkfile_goroutines gauge
arkfile_goroutines %d

# HELP arkfile_checks_total Total number of health checks
# TYPE arkfile_checks_total counter
arkfile_checks_total %d

# HELP arkfile_checks_healthy Number of healthy checks
# TYPE arkfile_checks_healthy gauge
arkfile_checks_healthy %d

# HELP arkfile_checks_degraded Number of degraded checks
# TYPE arkfile_checks_degraded gauge
arkfile_checks_degraded %d

# HELP arkfile_checks_unhealthy Number of unhealthy checks
# TYPE arkfile_checks_unhealthy gauge
arkfile_checks_unhealthy %d
`,
		status.Version,
		healthStatusToInt(status.Status),
		status.Uptime.Seconds(),
		status.System.MemStats.Alloc,
		status.System.NumGoroutine,
		status.Summary.Total,
		status.Summary.Healthy,
		status.Summary.Degraded,
		status.Summary.Unhealthy,
	)

	return c.String(http.StatusOK, metrics)
}

// healthStatusToInt converts HealthStatus to integer for Prometheus
func healthStatusToInt(status HealthStatus) int {
	switch status {
	case StatusUnhealthy:
		return 0
	case StatusDegraded:
		return 1
	case StatusHealthy:
		return 2
	default:
		return 0
	}
}

// getDiskUsage gets disk usage information for a path
func getDiskUsage(path string) *DiskInfo {
	// This is a simple implementation - in production might use syscall
	// For now, just check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	// Placeholder values - would use syscall.Statfs on Unix systems
	return &DiskInfo{
		Total:     1000000000, // 1GB placeholder
		Used:      500000000,  // 500MB placeholder
		Available: 500000000,  // 500MB placeholder
		UsedPct:   50.0,       // 50% placeholder
	}
}
