package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
)

const (
	shareAccessAttemptRetention       = 30 * 24 * time.Hour
	shareAccessAttemptCleanupInterval = time.Hour
)

var (
	shareAccessAttemptCleanupMu     sync.Mutex
	lastShareAccessAttemptCleanupAt = time.Now()
)

// ShareRateLimitEntry represents a rate limiting entry for share access
type ShareRateLimitEntry struct {
	ShareID            string
	EntityID           string
	FailedCount        int
	LastFailedAttempt  *time.Time
	NextAllowedAttempt *time.Time
}

func pruneShareAccessAttempts(cutoff time.Time) (int64, error) {
	result, err := database.DB.Exec(`
		DELETE FROM share_access_attempts
		WHERE COALESCE(updated_at, created_at) < ?
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to prune share access attempts: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return rowsAffected, nil
}

func maybePruneShareAccessAttempts(now time.Time) {
	shareAccessAttemptCleanupMu.Lock()
	defer shareAccessAttemptCleanupMu.Unlock()

	if now.Sub(lastShareAccessAttemptCleanupAt) < shareAccessAttemptCleanupInterval {
		return
	}

	rows, err := pruneShareAccessAttempts(now.Add(-shareAccessAttemptRetention))
	if err != nil {
		logging.ErrorLogger.Printf("Share access attempt cleanup failed: %v", err)
		return
	}
	lastShareAccessAttemptCleanupAt = now
	if rows > 0 {
		logging.InfoLogger.Printf("Pruned %d expired share access attempt rows", rows)
	}
}

// calculateSharePenalty calculates the delay penalty based on failure count
func calculateSharePenalty(failureCount int) time.Duration {
	if failureCount <= 3 {
		return 0 // First 3 attempts immediate
	}

	penalties := []time.Duration{
		30 * time.Second, // 4th attempt
		60 * time.Second, // 5th attempt
		2 * time.Minute,  // 6th attempt
		4 * time.Minute,  // 7th attempt
		8 * time.Minute,  // 8th attempt
		15 * time.Minute, // 9th attempt
	}

	if failureCount-4 < len(penalties) {
		return penalties[failureCount-4]
	}
	return 30 * time.Minute // Cap at 30 minutes for 10+ attempts
}

// getOrCreateRateLimitEntry retrieves or creates a rate limiting entry
func getOrCreateRateLimitEntry(shareID, entityID string) (*ShareRateLimitEntry, error) {
	maybePruneShareAccessAttempts(time.Now())

	// First, ignore duplicates and ensure the row exists.
	_, err := database.DB.Exec(`
		INSERT OR IGNORE INTO share_access_attempts (share_id, entity_id, failed_count, created_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
	`, shareID, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure rate limit entry: %w", err)
	}

	var entry ShareRateLimitEntry
	var lastFailedAttempt, nextAllowedAttempt sql.NullTime

	err = database.DB.QueryRow(`
		SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt
		FROM share_access_attempts 
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID).Scan(
		&entry.ShareID,
		&entry.EntityID,
		&entry.FailedCount,
		&lastFailedAttempt,
		&nextAllowedAttempt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query rate limit entry: %w", err)
	}

	// Convert nullable times
	if lastFailedAttempt.Valid {
		entry.LastFailedAttempt = &lastFailedAttempt.Time
	}
	if nextAllowedAttempt.Valid {
		entry.NextAllowedAttempt = &nextAllowedAttempt.Time
	}

	return &entry, nil
}

// recordFailedAttempt records a failed share access attempt
func recordFailedAttempt(shareID, entityID string) error {
	// Ensure the row exists to avoid race/TOCTOU on checking first
	_, err := database.DB.Exec(`
		INSERT OR IGNORE INTO share_access_attempts (share_id, entity_id, failed_count, created_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
	`, shareID, entityID)
	if err != nil {
		return fmt.Errorf("failed to ensure rate limit entry for record: %w", err)
	}

	// Put inside a transaction to prevent read-then-write race
	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction for record: %w", err)
	}
	defer tx.Rollback()

	// 2. Select the current failed_count
	var currentFailureCount int
	err = tx.QueryRow(`
		SELECT failed_count FROM share_access_attempts 
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID).Scan(&currentFailureCount)
	if err != nil {
		return fmt.Errorf("failed to query current failure count: %w", err)
	}

	newFailureCount := currentFailureCount + 1
	penalty := calculateSharePenalty(newFailureCount)
	nextAllowed := time.Now().Add(penalty)

	_, err = tx.Exec(`
		UPDATE share_access_attempts 
		SET failed_count = ?, last_failed_attempt = CURRENT_TIMESTAMP, next_allowed_attempt = ?
		WHERE share_id = ? AND entity_id = ?
	`, newFailureCount, nextAllowed, shareID, entityID)
	if err != nil {
		return fmt.Errorf("failed to update rate limit entry: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logging.InfoLogger.Printf("Rate limit updated for share %s, entity %s: %d failures, next allowed: %v",
		shareID, entityID, newFailureCount, nextAllowed)

	return nil
}

// checkRateLimit checks if an access attempt is allowed
func checkRateLimit(shareID, entityID string) (bool, time.Duration, error) {
	entry, err := getOrCreateRateLimitEntry(shareID, entityID)
	if err != nil {
		return false, 0, err
	}

	// If no failures recorded, allow access
	if entry.FailedCount == 0 || entry.NextAllowedAttempt == nil {
		return true, 0, nil
	}

	// Check if enough time has passed
	now := time.Now()
	if now.Before(*entry.NextAllowedAttempt) {
		remainingDelay := entry.NextAllowedAttempt.Sub(now)
		return false, remainingDelay, nil
	}

	return true, 0, nil
}

// isEntityRateLimited checks if an entity is currently rate limited for a share
func isEntityRateLimited(shareID, entityID string) (bool, time.Time, error) {
	var nextAllowedAttempt sql.NullTime

	err := database.DB.QueryRow(`
		SELECT next_allowed_attempt 
		FROM share_access_attempts 
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID).Scan(&nextAllowedAttempt)

	if err == sql.ErrNoRows {
		// No record means not rate limited
		return false, time.Time{}, nil
	} else if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to check rate limit: %w", err)
	}

	// If no penalty time set, not rate limited
	if !nextAllowedAttempt.Valid {
		return false, time.Time{}, nil
	}

	// Check if penalty time has passed
	now := time.Now()
	if now.Before(nextAllowedAttempt.Time) {
		return true, nextAllowedAttempt.Time, nil
	}

	return false, time.Time{}, nil
}

// ShareRateLimitMiddleware provides rate limiting for share access attempts
// This middleware is designed to work WITH TimingProtectionMiddleware by not short-circuiting timing
func ShareRateLimitMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		shareID := c.Param("id")
		if shareID == "" {
			// No share ID in route - this middleware doesn't apply to this route
			// (e.g., authenticated ListShares endpoint at /api/shares without :id)
			return next(c)
		}

		// Get Entity ID for this request
		entityID := logging.GetOrCreateEntityID(c)

		// Check if currently rate limited
		isRateLimited, nextAllowed, err := isEntityRateLimited(shareID, entityID)
		if err != nil {
			logging.ErrorLogger.Printf("Rate limit check failed for share %s: %v", shareID, err)
			return next(c) // Continue on error to avoid blocking legitimate requests
		}

		if isRateLimited {
			// Calculate retry after in seconds
			retryAfter := int(time.Until(nextAllowed).Seconds())
			if retryAfter < 0 {
				retryAfter = 0
			}

			// Record this failed attempt (rate limited request)
			if err := recordFailedAttempt(shareID, entityID); err != nil {
				logging.ErrorLogger.Printf("Failed to record rate limited attempt: %v", err)
			}

			message := fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", retryAfter)
			body := APIResponse{
				Success: false,
				Error:   "rate_limited",
				Message: message,
				Data: map[string]interface{}{
					"retry_after_seconds": retryAfter,
				},
			}

			// Store rate limit response in context so timing protection can
			// still apply its delay before the body is written.
			c.Set("rate_limited_response", body)
			c.Set("rate_limited", true)

			c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			return c.JSON(http.StatusTooManyRequests, body)
		}

		return next(c)
	}
}

// General rate limiting for authentication endpoints

// AuthRateLimitEntry represents a rate limiting entry for authentication endpoints
type AuthRateLimitEntry struct {
	EndpointType       string // "login", "register", "mfa_verify", "mfa_auth"
	EntityID           string
	FailedCount        int
	LastFailedAttempt  *time.Time
	NextAllowedAttempt *time.Time
}

// calculateAuthPenalty calculates the delay penalty for authentication endpoints
func calculateAuthPenalty(failureCount int, endpointType string) time.Duration {
	if failureCount <= 3 {
		return 0 // First 3 attempts immediate
	}

	// Different penalties for different endpoint types
	var basePenalties []time.Duration

	switch endpointType {
	case "login":
		// More aggressive penalties for login attempts
		basePenalties = []time.Duration{
			60 * time.Second, // 4th attempt
			2 * time.Minute,  // 5th attempt
			5 * time.Minute,  // 6th attempt
			10 * time.Minute, // 7th attempt
			20 * time.Minute, // 8th attempt
			30 * time.Minute, // 9th attempt
		}
	case "register":
		// Moderate penalties for registration
		basePenalties = []time.Duration{
			30 * time.Second, // 4th attempt
			60 * time.Second, // 5th attempt
			2 * time.Minute,  // 6th attempt
			5 * time.Minute,  // 7th attempt
			10 * time.Minute, // 8th attempt
			15 * time.Minute, // 9th attempt
		}
	case "mfa_verify", "mfa_auth":
		// TOTP brute force protection
		basePenalties = []time.Duration{
			30 * time.Second, // 4th attempt
			60 * time.Second, // 5th attempt
			2 * time.Minute,  // 6th attempt
			4 * time.Minute,  // 7th attempt
			8 * time.Minute,  // 8th attempt
			15 * time.Minute, // 9th attempt
		}
	default:
		// Default penalties
		basePenalties = []time.Duration{
			30 * time.Second,
			60 * time.Second,
			2 * time.Minute,
			4 * time.Minute,
			8 * time.Minute,
			15 * time.Minute,
		}
	}

	if failureCount-4 < len(basePenalties) {
		return basePenalties[failureCount-4]
	}
	return 30 * time.Minute // Cap at 30 minutes for 10+ attempts
}

// LoginRateLimitMiddleware provides rate limiting for login endpoints
func LoginRateLimitMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		entityID := logging.GetOrCreateEntityID(c)

		// Check if currently rate limited for login attempts
		allowed, delay, err := checkAuthRateLimit("login", entityID)
		if err != nil {
			logging.ErrorLogger.Printf("Login rate limit check failed: %v", err)
			return JSONError(c, http.StatusServiceUnavailable, "Rate limiter unavailable")
		}

		if !allowed {
			retryAfter := int(delay.Seconds())
			c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			return JSONErrorCodeData(c, http.StatusTooManyRequests, "rate_limited",
				fmt.Sprintf("Too many login attempts. Try again in %d seconds.", retryAfter),
				map[string]interface{}{
					"retry_after_seconds": retryAfter,
					"endpoint":            "login",
				})
		}

		return next(c)
	}
}

// RegisterRateLimitMiddleware provides rate limiting for registration endpoints
func RegisterRateLimitMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		entityID := logging.GetOrCreateEntityID(c)

		allowed, delay, err := checkAuthRateLimit("register", entityID)
		if err != nil {
			logging.ErrorLogger.Printf("Register rate limit check failed: %v", err)
			return JSONError(c, http.StatusServiceUnavailable, "Rate limiter unavailable")
		}

		if !allowed {
			retryAfter := int(delay.Seconds())
			c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			return JSONErrorCodeData(c, http.StatusTooManyRequests, "rate_limited",
				fmt.Sprintf("Too many registration attempts. Try again in %d seconds.", retryAfter),
				map[string]interface{}{
					"retry_after_seconds": retryAfter,
					"endpoint":            "register",
				})
		}

		return next(c)
	}
}

// MFARateLimitMiddleware provides rate limiting for TOTP endpoints
func MFARateLimitMiddleware(endpointType string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			entityID := logging.GetOrCreateEntityID(c)

			allowed, delay, err := checkAuthRateLimit(endpointType, entityID)
			if err != nil {
				logging.ErrorLogger.Printf("TOTP rate limit check failed: %v", err)
				return JSONError(c, http.StatusServiceUnavailable, "Rate limiter unavailable")
			}

			if !allowed {
				retryAfter := int(delay.Seconds())
				c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				return JSONErrorCodeData(c, http.StatusTooManyRequests, "rate_limited",
					fmt.Sprintf("Too many TOTP attempts. Try again in %d seconds.", retryAfter),
					map[string]interface{}{
						"retry_after_seconds": retryAfter,
						"endpoint":            endpointType,
					})
			}

			return next(c)
		}
	}
}

// checkAuthRateLimit checks if an authentication attempt is allowed
func checkAuthRateLimit(endpointType, entityID string) (bool, time.Duration, error) {
	entry, err := getOrCreateAuthRateLimitEntry(endpointType, entityID)
	if err != nil {
		return false, 0, err
	}

	// If no failures recorded, allow access
	if entry.FailedCount == 0 || entry.NextAllowedAttempt == nil {
		return true, 0, nil
	}

	// Check if enough time has passed
	now := time.Now()
	if now.Before(*entry.NextAllowedAttempt) {
		remainingDelay := entry.NextAllowedAttempt.Sub(now)
		return false, remainingDelay, nil
	}

	return true, 0, nil
}

// getOrCreateAuthRateLimitEntry retrieves or creates an auth rate limiting entry
func getOrCreateAuthRateLimitEntry(endpointType, entityID string) (*AuthRateLimitEntry, error) {
	maybePruneShareAccessAttempts(time.Now())

	var entry AuthRateLimitEntry
	var lastFailedAttempt, nextAllowedAttempt sql.NullTime

	// Use a different table/approach - we'll reuse share_access_attempts with endpoint_type as share_id
	shareID := "auth_" + endpointType + "_" + entityID

	_, err := database.DB.Exec(`
		INSERT OR IGNORE INTO share_access_attempts (share_id, entity_id, failed_count, created_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
	`, shareID, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure auth rate limit entry: %w", err)
	}

	err = database.DB.QueryRow(`
		SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt
		FROM share_access_attempts 
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID).Scan(
		&entry.EndpointType,
		&entry.EntityID,
		&entry.FailedCount,
		&lastFailedAttempt,
		&nextAllowedAttempt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query auth rate limit entry: %w", err)
	}

	entry.EndpointType = endpointType

	// Convert nullable times
	if lastFailedAttempt.Valid {
		entry.LastFailedAttempt = &lastFailedAttempt.Time
	}
	if nextAllowedAttempt.Valid {
		entry.NextAllowedAttempt = &nextAllowedAttempt.Time
	}

	return &entry, nil
}

// recordAuthFailedAttempt records a failed authentication attempt
func recordAuthFailedAttempt(endpointType, entityID string) error {
	shareID := "auth_" + endpointType + "_" + entityID

	_, err := database.DB.Exec(`
		INSERT OR IGNORE INTO share_access_attempts (share_id, entity_id, failed_count, created_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
	`, shareID, entityID)
	if err != nil {
		return fmt.Errorf("failed to ensure auth rate limit entry for record: %w", err)
	}

	// Put inside a transaction to prevent read-then-write race
	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction for auth record: %w", err)
	}
	defer tx.Rollback()

	var currentFailureCount int
	err = tx.QueryRow(`
		SELECT failed_count FROM share_access_attempts 
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID).Scan(&currentFailureCount)
	if err != nil {
		return fmt.Errorf("failed to query current auth failure count: %w", err)
	}

	// Increment failure count
	newFailureCount := currentFailureCount + 1

	// Calculate next allowed attempt time
	penalty := calculateAuthPenalty(newFailureCount, endpointType)
	nextAllowed := time.Now().Add(penalty)

	// Update database
	_, err = tx.Exec(`
		UPDATE share_access_attempts 
		SET failed_count = ?, last_failed_attempt = CURRENT_TIMESTAMP, next_allowed_attempt = ?
		WHERE share_id = ? AND entity_id = ?
	`, newFailureCount, nextAllowed, shareID, entityID)

	if err != nil {
		return fmt.Errorf("failed to update auth rate limit entry: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit auth record transaction: %w", err)
	}

	logging.InfoLogger.Printf("Auth rate limit updated for %s, entity %s: %d failures, next allowed: %v",
		endpointType, entityID, newFailureCount, nextAllowed)

	return nil
}
