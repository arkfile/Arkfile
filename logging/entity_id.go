package logging

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// EntityIDService provides privacy-preserving entity identification
// using HMAC with daily-rotating keys derived from a master secret
type EntityIDService struct {
	masterSecret   []byte
	keyCache       map[string][]byte // Cache for derived daily keys
	cacheMutex     sync.RWMutex
	rotationPeriod time.Duration
	retentionDays  int
}

// EntityIDConfig configures the entity ID service
type EntityIDConfig struct {
	MasterSecretPath  string        `json:"master_secret_path"`
	RotationPeriod    time.Duration `json:"rotation_period"`    // 24 * time.Hour
	RetentionDays     int           `json:"retention_days"`     // 90
	CleanupInterval   time.Duration `json:"cleanup_interval"`   // 24 * time.Hour
	EmergencyRotation bool          `json:"emergency_rotation"` // true
}

// NewEntityIDService creates a new entity ID service with the given configuration
func NewEntityIDService(config EntityIDConfig) (*EntityIDService, error) {
	service := &EntityIDService{
		keyCache:       make(map[string][]byte),
		rotationPeriod: config.RotationPeriod,
		retentionDays:  config.RetentionDays,
	}

	// Generate or load master secret
	if err := service.initializeMasterSecret(config.MasterSecretPath); err != nil {
		return nil, fmt.Errorf("failed to initialize master secret: %w", err)
	}

	// Start cleanup goroutine
	go service.cleanupRoutine(config.CleanupInterval)

	return service, nil
}

// GetEntityID returns a privacy-preserving entity identifier for the given IP address
// The entity ID is consistent within the current time window (day) but changes
// with daily rotation for temporal privacy isolation
func (e *EntityIDService) GetEntityID(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}

	// Get current time window key
	timeWindow := e.GetCurrentTimeWindow()
	dailyKey := e.getDailyKey(timeWindow)

	// Generate HMAC-based entity ID
	mac := hmac.New(sha256.New, dailyKey)
	mac.Write(ip)
	entityID := hex.EncodeToString(mac.Sum(nil))

	return entityID[:16] // Use first 16 characters for readability
}

// GetCurrentTimeWindow returns the current time window identifier (YYYY-MM-DD format)
func (e *EntityIDService) GetCurrentTimeWindow() string {
	return time.Now().UTC().Format("2006-01-02")
}

// GetTimeWindowForTime returns the time window identifier for a specific time
func (e *EntityIDService) GetTimeWindowForTime(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// RotateKeys performs emergency rotation of the master secret
// This invalidates all current entity IDs and rate limiting state
func (e *EntityIDService) RotateKeys() error {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	// Generate new master secret
	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		return fmt.Errorf("failed to generate new master secret: %w", err)
	}

	// Update master secret
	e.masterSecret = newSecret

	// Clear key cache to force re-derivation
	e.keyCache = make(map[string][]byte)

	// Log emergency rotation event
	InfoLogger.Printf("Emergency entity ID key rotation completed")

	return nil
}

// CleanupOldWindows removes old time window data beyond retention period
func (e *EntityIDService) CleanupOldWindows(retentionDays int) error {
	cutoffDate := time.Now().UTC().AddDate(0, 0, -retentionDays)
	cutoffWindow := e.GetTimeWindowForTime(cutoffDate)

	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	// Remove old keys from cache
	for window := range e.keyCache {
		if window < cutoffWindow {
			delete(e.keyCache, window)
		}
	}

	InfoLogger.Printf("Cleaned up entity ID keys older than %s", cutoffWindow)
	return nil
}

// GetMasterSecretHash returns a hash of the master secret for health monitoring
// This allows verification of key accessibility without exposing the secret
func (e *EntityIDService) GetMasterSecretHash() string {
	if e.masterSecret == nil {
		return ""
	}
	hash := sha256.Sum256(e.masterSecret)
	return hex.EncodeToString(hash[:8]) // First 8 bytes for identification
}

// getDailyKey derives or retrieves the daily key for the given time window
func (e *EntityIDService) getDailyKey(timeWindow string) []byte {
	e.cacheMutex.RLock()
	if key, exists := e.keyCache[timeWindow]; exists {
		e.cacheMutex.RUnlock()
		return key
	}
	e.cacheMutex.RUnlock()

	// Derive new key
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	// Double-check after acquiring write lock
	if key, exists := e.keyCache[timeWindow]; exists {
		return key
	}

	// Derive key using HKDF-SHA256
	key := make([]byte, 32)
	info := []byte("entity_id_v1")
	salt := []byte(timeWindow)

	hkdf := hkdf.New(sha256.New, e.masterSecret, salt, info)
	if _, err := hkdf.Read(key); err != nil {
		// Fallback to direct HMAC if HKDF fails
		mac := hmac.New(sha256.New, e.masterSecret)
		mac.Write(salt)
		mac.Write(info)
		key = mac.Sum(nil)
	}

	// Cache the derived key
	e.keyCache[timeWindow] = key

	return key
}

// initializeMasterSecret loads or generates the master secret
func (e *EntityIDService) initializeMasterSecret(secretPath string) error {
	// For now, generate a random master secret
	// In production, this would load from secure storage
	masterSecret := make([]byte, 32)
	if _, err := rand.Read(masterSecret); err != nil {
		return fmt.Errorf("failed to generate master secret: %w", err)
	}

	e.masterSecret = masterSecret
	return nil
}

// cleanupRoutine runs periodic cleanup of old keys and cache entries
func (e *EntityIDService) cleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := e.CleanupOldWindows(e.retentionDays); err != nil {
			ErrorLogger.Printf("Entity ID cleanup failed: %v", err)
		}
	}
}

// ValidateEntityID checks if an entity ID has the expected format
func ValidateEntityID(entityID string) bool {
	if len(entityID) != 16 {
		return false
	}

	// Check if it's valid hex
	_, err := hex.DecodeString(entityID)
	return err == nil
}

// Global entity ID service instance
var DefaultEntityIDService *EntityIDService

// InitializeEntityIDService initializes the global entity ID service
func InitializeEntityIDService(config EntityIDConfig) error {
	var err error
	DefaultEntityIDService, err = NewEntityIDService(config)
	if err != nil {
		return fmt.Errorf("failed to initialize entity ID service: %w", err)
	}

	InfoLogger.Printf("Entity ID service initialized with daily rotation")
	return nil
}

// GetEntityIDForIP is a convenience function that uses the default service
func GetEntityIDForIP(ip net.IP) string {
	if DefaultEntityIDService == nil {
		return "uninitialized"
	}
	return DefaultEntityIDService.GetEntityID(ip)
}
