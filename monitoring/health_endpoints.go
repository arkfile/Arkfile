package monitoring

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/arkfile/Arkfile/config"
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
	}

	info.MemStats.Alloc = memStats.Alloc
	info.MemStats.TotalAlloc = memStats.TotalAlloc
	info.MemStats.Sys = memStats.Sys
	info.MemStats.NumGC = memStats.NumGC
	if memStats.LastGC > 0 {
		info.MemStats.LastGC = time.Unix(0, int64(memStats.LastGC)).Format(time.RFC3339)
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

	userSecretMasterPath := filepath.Join(keyDir, "user-secret-master.bin")
	if _, err := os.Stat(userSecretMasterPath); os.IsNotExist(err) {
		check.Details["user_secret_master_key"] = "missing"
		issues++
	} else {
		check.Details["user_secret_master_key"] = "exists"
	}

	if issues == 0 {
		check.Status = StatusHealthy
		check.Message = "Key directory and user-secret master key present"
	} else if issues == 1 {
		check.Status = StatusDegraded
		check.Message = "Key health issue detected"
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
	if storage.Endpoint == "" || storage.AccessKeyID == "" || storage.SecretAccessKey == "" {
		check.Status = StatusDegraded
		check.Message = "Storage backend not fully configured"
		check.Details["configuration"] = "incomplete"
	} else {
		check.Status = StatusHealthy
		check.Message = fmt.Sprintf("Storage backend configured (%s)", storage.Provider)
		check.Details["configuration"] = "complete"
		check.Details["provider"] = storage.Provider
		check.Details["endpoint"] = storage.Endpoint
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

// DefaultHealthMonitor is the process-wide health monitor for admin API queries.
var DefaultHealthMonitor *HealthMonitor

// InitDefaultHealthMonitor creates and stores the singleton health monitor.
func InitDefaultHealthMonitor(db *sql.DB, cfg *config.Config, version string) {
	DefaultHealthMonitor = NewHealthMonitor(db, cfg, version)
}
