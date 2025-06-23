package handlers

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/config"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
)

// parseIPAddress safely converts IP string to net.IP
func parseIPAddress(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Fallback to localhost for invalid IPs
		return net.ParseIP("127.0.0.1")
	}
	return ip
}

// RateLimitState represents the current rate limiting state for an entity
type RateLimitState struct {
	EntityID       string     `json:"entity_id"`
	TimeWindow     string     `json:"time_window"`
	Endpoint       string     `json:"endpoint"`
	RequestCount   int        `json:"request_count"`
	LastRequest    time.Time  `json:"last_request"`
	ViolationCount int        `json:"violation_count"`
	PenaltyUntil   *time.Time `json:"penalty_until"`
}

// RateLimitManager manages rate limiting state with privacy-preserving entity IDs
type RateLimitManager struct {
	db     *sql.DB
	config config.RateLimitConfig
	cache  map[string]*RateLimitState
	mutex  sync.RWMutex
}

// NewRateLimitManager creates a new rate limit manager
func NewRateLimitManager(db *sql.DB, rateLimitConfig config.RateLimitConfig) *RateLimitManager {
	manager := &RateLimitManager{
		db:     db,
		config: rateLimitConfig,
		cache:  make(map[string]*RateLimitState),
	}

	// Start cleanup routine
	go manager.cleanupRoutine()

	return manager
}

// Global rate limit manager instance
var DefaultRateLimitManager *RateLimitManager

// InitializeRateLimitManager initializes the global rate limit manager
func InitializeRateLimitManager(rateLimitConfig config.RateLimitConfig) error {
	if database.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	DefaultRateLimitManager = NewRateLimitManager(database.DB, rateLimitConfig)
	logging.InfoLogger.Printf("Rate limit manager initialized")
	return nil
}

// CheckRateLimit checks if a request should be rate limited
func (rlm *RateLimitManager) CheckRateLimit(entityID, endpoint string, limit int, windowSize time.Duration) (bool, error) {
	if !rlm.config.EnableRateLimit {
		return false, nil // Rate limiting disabled
	}

	timeWindow := logging.DefaultEntityIDService.GetCurrentTimeWindow()
	key := fmt.Sprintf("%s:%s:%s", entityID, timeWindow, endpoint)

	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()

	// Get current state
	state, exists := rlm.cache[key]
	if !exists {
		// Load from database or create new
		state = &RateLimitState{
			EntityID:     entityID,
			TimeWindow:   timeWindow,
			Endpoint:     endpoint,
			RequestCount: 0,
			LastRequest:  time.Now().UTC(),
		}
		rlm.loadStateFromDB(state)
		rlm.cache[key] = state
	}

	// Check if currently under penalty
	if state.PenaltyUntil != nil && time.Now().UTC().Before(*state.PenaltyUntil) {
		return true, nil // Still under penalty
	}

	// Increment request count
	state.RequestCount++
	state.LastRequest = time.Now().UTC()

	// Check if limit exceeded
	if state.RequestCount > limit {
		// Apply progressive penalty
		state.ViolationCount++
		penaltyDuration := rlm.calculatePenalty(state.ViolationCount)
		penaltyUntil := time.Now().UTC().Add(penaltyDuration)
		state.PenaltyUntil = &penaltyUntil

		// Save to database
		rlm.saveStateToDB(state)

		// Log security event
		logging.LogSecurityEvent(
			logging.EventRateLimitViolation,
			nil, // No IP in logs - using entity ID
			nil,
			nil,
			map[string]interface{}{
				"endpoint":        endpoint,
				"request_count":   state.RequestCount,
				"limit":           limit,
				"violation_count": state.ViolationCount,
				"penalty_until":   penaltyUntil,
			},
		)

		return true, nil // Rate limited
	}

	// Save updated state
	rlm.saveStateToDB(state)

	return false, nil // Not rate limited
}

// calculatePenalty calculates progressive penalty duration
func (rlm *RateLimitManager) calculatePenalty(violationCount int) time.Duration {
	if violationCount > rlm.config.MaxViolations {
		return rlm.config.MaxPenaltyDelay
	}

	// Progressive penalty: base delay * (penalty multiplier ^ violation count)
	baseDelay := 30 * time.Second
	for i := 1; i < violationCount; i++ {
		baseDelay = time.Duration(float64(baseDelay) * rlm.config.ViolationPenalty)
		if baseDelay > rlm.config.MaxPenaltyDelay {
			return rlm.config.MaxPenaltyDelay
		}
	}

	return baseDelay
}

// loadStateFromDB loads rate limit state from database
func (rlm *RateLimitManager) loadStateFromDB(state *RateLimitState) {
	query := `SELECT request_count, last_request, violation_count, penalty_until 
              FROM rate_limit_state 
              WHERE entity_id = ? AND time_window = ? AND endpoint = ?`

	var penaltyUntil sql.NullTime
	err := rlm.db.QueryRow(query, state.EntityID, state.TimeWindow, state.Endpoint).Scan(
		&state.RequestCount,
		&state.LastRequest,
		&state.ViolationCount,
		&penaltyUntil,
	)

	if err != nil && err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("Failed to load rate limit state: %v", err)
	}

	if penaltyUntil.Valid {
		state.PenaltyUntil = &penaltyUntil.Time
	}
}

// saveStateToDB saves rate limit state to database
func (rlm *RateLimitManager) saveStateToDB(state *RateLimitState) {
	query := `INSERT OR REPLACE INTO rate_limit_state 
              (entity_id, time_window, endpoint, request_count, last_request, violation_count, penalty_until, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	var penaltyUntil interface{}
	if state.PenaltyUntil != nil {
		penaltyUntil = *state.PenaltyUntil
	}

	_, err := rlm.db.Exec(query,
		state.EntityID,
		state.TimeWindow,
		state.Endpoint,
		state.RequestCount,
		state.LastRequest,
		state.ViolationCount,
		penaltyUntil,
		time.Now().UTC(),
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to save rate limit state: %v", err)
	}
}

// cleanupRoutine periodically cleans up old rate limit data
func (rlm *RateLimitManager) cleanupRoutine() {
	ticker := time.NewTicker(rlm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rlm.cleanup()
	}
}

// cleanup removes old rate limit data
func (rlm *RateLimitManager) cleanup() {
	cutoffDate := time.Now().UTC().AddDate(0, 0, -rlm.config.RetentionDays)
	cutoffWindow := logging.DefaultEntityIDService.GetTimeWindowForTime(cutoffDate)

	// Clean database
	_, err := rlm.db.Exec("DELETE FROM rate_limit_state WHERE time_window < ?", cutoffWindow)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to cleanup old rate limit data: %v", err)
		return
	}

	// Clean cache
	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()

	for key, state := range rlm.cache {
		if state.TimeWindow < cutoffWindow {
			delete(rlm.cache, key)
		}
	}

	logging.InfoLogger.Printf("Cleaned up rate limit data older than %s", cutoffWindow)
}

// RateLimitMiddleware creates rate limiting middleware for specific endpoints
func RateLimitMiddleware(endpointConfig config.EndpointConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if DefaultRateLimitManager == nil {
				return next(c) // Rate limiting not initialized
			}

			if !endpointConfig.Enabled {
				return next(c) // Rate limiting disabled for this endpoint
			}

			// Get entity ID from IP address (privacy-preserving)
			clientIP := parseIPAddress(c.RealIP())
			entityID := logging.GetEntityIDForIP(clientIP)

			// Check rate limit
			rateLimited, err := DefaultRateLimitManager.CheckRateLimit(
				entityID,
				endpointConfig.Path,
				endpointConfig.Limit,
				endpointConfig.WindowSize,
			)

			if err != nil {
				logging.ErrorLogger.Printf("Rate limit check failed: %v", err)
				// Continue on error to avoid blocking legitimate requests
				return next(c)
			}

			if rateLimited {
				// Log rate limit violation
				logging.LogSecurityEvent(
					logging.EventRateLimitViolation,
					clientIP,
					nil,
					nil,
					map[string]interface{}{
						"endpoint":    endpointConfig.Path,
						"method":      endpointConfig.Method,
						"limit":       endpointConfig.Limit,
						"window_type": endpointConfig.WindowType,
						"description": endpointConfig.Description,
					},
				)

				return echo.NewHTTPError(http.StatusTooManyRequests, map[string]interface{}{
					"error":       "Rate limit exceeded",
					"message":     fmt.Sprintf("Too many requests to %s. Please try again later.", endpointConfig.Path),
					"retry_after": "Please wait before making another request",
				})
			}

			return next(c)
		}
	}
}

// TLSVersionCheck middleware adds TLS version information to response headers
// and logs TLS version usage for analytics
func TLSVersionCheck(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Ensure HTTPS
		if c.Request().TLS == nil {
			return echo.NewHTTPError(http.StatusForbidden,
				"HTTPS required for this operation")
		}

		// Get TLS version string
		var versionStr string
		switch c.Request().TLS.Version {
		case tls.VersionTLS13:
			versionStr = "1.3"
		case tls.VersionTLS12:
			versionStr = "1.2"
		default:
			versionStr = fmt.Sprintf("unknown (%d)", c.Request().TLS.Version)
		}

		// Add TLS version to response headers for client detection
		c.Response().Header().Set("X-TLS-Version", versionStr)

		// Log TLS version and cipher suite for analytics
		logging.InfoLogger.Printf("TLS Connection: version=%s cipher=%s client=%s path=%s",
			versionStr,
			tls.CipherSuiteName(c.Request().TLS.CipherSuite),
			c.RealIP(),
			c.Request().URL.Path,
		)

		return next(c)
	}
}

// RequireApproved ensures the user is approved before allowing access
func RequireApproved(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		email := auth.GetEmailFromToken(c)

		// Get user details
		user, err := models.GetUserByEmail(database.DB, email)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Check if user is approved or is an admin
		if !user.IsApproved && !user.HasAdminPrivileges() {
			return echo.NewHTTPError(http.StatusForbidden, "Account pending approval")
		}

		return next(c)
	}
}

// RequireAdmin ensures the user has admin privileges before allowing access
func RequireAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		email := auth.GetEmailFromToken(c)

		// Get user details
		user, err := models.GetUserByEmail(database.DB, email)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
		}

		// Check if user has admin privileges
		if !user.HasAdminPrivileges() {
			return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
		}

		return next(c)
	}
}
