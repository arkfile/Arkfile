package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
)

// ShareRateLimitEntry represents a rate limiting entry for share access
type ShareRateLimitEntry struct {
	ShareID            string
	EntityID           string
	FailedCount        int
	LastFailedAttempt  *time.Time
	NextAllowedAttempt *time.Time
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
	var entry ShareRateLimitEntry
	var lastFailedAttempt, nextAllowedAttempt sql.NullTime

	err := database.DB.QueryRow(`
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

	if err == sql.ErrNoRows {
		// Create new entry
		entry = ShareRateLimitEntry{
			ShareID:     shareID,
			EntityID:    entityID,
			FailedCount: 0,
		}

		_, err = database.DB.Exec(`
			INSERT INTO share_access_attempts (share_id, entity_id, failed_count, created_at)
			VALUES (?, ?, 0, CURRENT_TIMESTAMP)
		`, shareID, entityID)

		if err != nil {
			return nil, fmt.Errorf("failed to create rate limit entry: %w", err)
		}
	} else if err != nil {
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
	entry, err := getOrCreateRateLimitEntry(shareID, entityID)
	if err != nil {
		return err
	}

	// Increment failure count
	newFailureCount := entry.FailedCount + 1

	// Calculate next allowed attempt time
	penalty := calculateSharePenalty(newFailureCount)
	nextAllowed := time.Now().Add(penalty)

	// Update database
	_, err = database.DB.Exec(`
		UPDATE share_access_attempts 
		SET failed_count = ?, last_failed_attempt = CURRENT_TIMESTAMP, next_allowed_attempt = ?
		WHERE share_id = ? AND entity_id = ?
	`, newFailureCount, nextAllowed, shareID, entityID)

	if err != nil {
		return fmt.Errorf("failed to update rate limit entry: %w", err)
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

// resetRateLimit resets the rate limit for successful authentication
func resetRateLimit(shareID, entityID string) error {
	_, err := database.DB.Exec(`
		UPDATE share_access_attempts 
		SET failed_count = 0, last_failed_attempt = NULL, next_allowed_attempt = NULL
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID)

	if err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	logging.InfoLogger.Printf("Rate limit reset for share %s, entity %s", shareID, entityID)
	return nil
}

// ShareRateLimitMiddleware provides rate limiting for share access attempts
func ShareRateLimitMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Only apply to share-related endpoints
		path := c.Request().URL.Path
		if !isShareEndpoint(path) {
			return next(c)
		}

		// Get share ID from URL parameter
		shareID := c.Param("id")
		if shareID == "" {
			return next(c) // No share ID, continue normally
		}

		// Get entity ID for rate limiting
		entityID := logging.GetOrCreateEntityID(c)

		// Check rate limit
		allowed, delay, err := checkRateLimit(shareID, entityID)
		if err != nil {
			logging.ErrorLogger.Printf("Rate limit check failed: %v", err)
			// Continue on error to avoid blocking legitimate users
			return next(c)
		}

		if !allowed {
			logging.InfoLogger.Printf("Rate limit exceeded for share %s, entity %s: %v remaining",
				shareID, entityID, delay)

			return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
				"error":      "rate_limited",
				"message":    "Too many failed attempts. Please try again later.",
				"retryAfter": int(delay.Seconds()),
			})
		}

		return next(c)
	}
}

// isShareEndpoint checks if the path is a share-related endpoint
func isShareEndpoint(path string) bool {
	shareEndpoints := []string{
		"/api/share/",
		"/shared/",
		"/api/files/share",
	}

	for _, endpoint := range shareEndpoints {
		if len(path) >= len(endpoint) && path[:len(endpoint)] == endpoint {
			return true
		}
	}

	return false
}

// TimingProtectionMiddleware enforces minimum response times for anonymous endpoints
func TimingProtectionMiddleware(minDelay time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Only apply to share access endpoints (anonymous access)
			path := c.Request().URL.Path
			if !requiresTimingProtection(path) {
				return next(c)
			}

			startTime := time.Now()

			// Process the request
			err := next(c)

			// Calculate elapsed time
			elapsed := time.Since(startTime)

			// If response was faster than minimum, add delay
			if elapsed < minDelay {
				remainingDelay := minDelay - elapsed
				time.Sleep(remainingDelay)

				logging.InfoLogger.Printf("Timing protection applied: %v delay added to %s",
					remainingDelay, path)
			}

			return err
		}
	}
}

// requiresTimingProtection checks if an endpoint requires timing protection
func requiresTimingProtection(path string) bool {
	protectedEndpoints := []string{
		"/api/share/", // Share password authentication
		"/shared/",    // Share page access
	}

	for _, endpoint := range protectedEndpoints {
		if len(path) >= len(endpoint) && path[:len(endpoint)] == endpoint {
			return true
		}
	}

	return false
}

// RateLimitShareAccess wraps share access functions with rate limiting logic
func RateLimitShareAccess(shareID string, c echo.Context, accessFunc func() error) error {
	entityID := logging.GetOrCreateEntityID(c)

	// Check rate limit before attempting access
	allowed, delay, err := checkRateLimit(shareID, entityID)
	if err != nil {
		logging.ErrorLogger.Printf("Rate limit check failed: %v", err)
		// Continue on error to avoid blocking legitimate users
	} else if !allowed {
		return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
			"error":      "rate_limited",
			"message":    "Too many failed attempts. Please try again later.",
			"retryAfter": int(delay.Seconds()),
		})
	}

	// Attempt the access function
	err = accessFunc()

	// Handle the result
	if err != nil {
		// Check if this is an authentication failure
		if httpErr, ok := err.(*echo.HTTPError); ok {
			if httpErr.Code == http.StatusUnauthorized || httpErr.Code == http.StatusNotFound {
				// Record failed attempt for rate limiting
				if recordErr := recordFailedAttempt(shareID, entityID); recordErr != nil {
					logging.ErrorLogger.Printf("Failed to record failed attempt: %v", recordErr)
				}
			}
		}
		return err
	}

	// Success - reset rate limit
	if resetErr := resetRateLimit(shareID, entityID); resetErr != nil {
		logging.ErrorLogger.Printf("Failed to reset rate limit: %v", resetErr)
		// Don't fail the request for this
	}

	return nil
}
