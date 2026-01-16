package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
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
	// Get current failure count from database
	var currentFailureCount int
	err := database.DB.QueryRow(`
		SELECT failed_count FROM share_access_attempts 
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID).Scan(&currentFailureCount)

	if err != nil {
		// If entry doesn't exist, create it with failure count 1
		if err == sql.ErrNoRows {
			penalty := calculateSharePenalty(1)
			nextAllowed := time.Now().Add(penalty)

			_, err = database.DB.Exec(`
				INSERT INTO share_access_attempts (share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt, created_at)
				VALUES (?, ?, 1, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP)
			`, shareID, entityID, nextAllowed)

			if err != nil {
				return fmt.Errorf("failed to create rate limit entry with failure: %w", err)
			}

			logging.InfoLogger.Printf("Rate limit created for share %s, entity %s: 1 failure, next allowed: %v",
				shareID, entityID, nextAllowed)
			return nil
		}
		return fmt.Errorf("failed to query current failure count: %w", err)
	}

	// Increment failure count
	newFailureCount := currentFailureCount + 1

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

			// Store rate limit response in context so timing protection can still apply
			c.Set("rate_limited_response", map[string]interface{}{
				"success":    false,
				"error":      "rate_limited",
				"retryAfter": retryAfter,
				"message":    fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", retryAfter),
			})
			c.Set("rate_limited", true)

			// Return rate limited response with 429 status
			// TimingProtectionMiddleware will still apply its delay
			return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
				"success":    false,
				"error":      "rate_limited",
				"retryAfter": retryAfter,
				"message":    fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", retryAfter),
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

// General rate limiting for authentication endpoints

// AuthRateLimitEntry represents a rate limiting entry for authentication endpoints
type AuthRateLimitEntry struct {
	EndpointType       string // "login", "register", "totp_verify", "totp_auth"
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
	case "totp_verify", "totp_auth":
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
			return next(c) // Continue on error
		}

		if !allowed {
			retryAfter := int(delay.Seconds())
			c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			return echo.NewHTTPError(http.StatusTooManyRequests,
				fmt.Sprintf("Too many login attempts. Try again in %d seconds.", retryAfter))
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
			return next(c) // Continue on error
		}

		if !allowed {
			retryAfter := int(delay.Seconds())
			c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			return echo.NewHTTPError(http.StatusTooManyRequests,
				fmt.Sprintf("Too many registration attempts. Try again in %d seconds.", retryAfter))
		}

		return next(c)
	}
}

// TOTPRateLimitMiddleware provides rate limiting for TOTP endpoints
func TOTPRateLimitMiddleware(endpointType string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			entityID := logging.GetOrCreateEntityID(c)

			allowed, delay, err := checkAuthRateLimit(endpointType, entityID)
			if err != nil {
				logging.ErrorLogger.Printf("TOTP rate limit check failed: %v", err)
				return next(c) // Continue on error
			}

			if !allowed {
				retryAfter := int(delay.Seconds())
				c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				return echo.NewHTTPError(http.StatusTooManyRequests,
					fmt.Sprintf("Too many TOTP attempts. Try again in %d seconds.", retryAfter))
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
	var entry AuthRateLimitEntry
	var lastFailedAttempt, nextAllowedAttempt sql.NullTime

	// Use a different table/approach - we'll reuse share_access_attempts with endpoint_type as share_id
	shareID := "auth_" + endpointType + "_" + entityID

	err := database.DB.QueryRow(`
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

	if err == sql.ErrNoRows {
		// Create new entry
		entry = AuthRateLimitEntry{
			EndpointType: endpointType,
			EntityID:     entityID,
			FailedCount:  0,
		}

		_, err = database.DB.Exec(`
			INSERT INTO share_access_attempts (share_id, entity_id, failed_count, created_at)
			VALUES (?, ?, 0, CURRENT_TIMESTAMP)
		`, shareID, entityID)

		if err != nil {
			return nil, fmt.Errorf("failed to create auth rate limit entry: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to query auth rate limit entry: %w", err)
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

// recordAuthFailedAttempt records a failed authentication attempt
func recordAuthFailedAttempt(endpointType, entityID string) error {
	shareID := "auth_" + endpointType + "_" + entityID

	// Get current failure count from database
	var currentFailureCount int
	err := database.DB.QueryRow(`
		SELECT failed_count FROM share_access_attempts 
		WHERE share_id = ? AND entity_id = ?
	`, shareID, entityID).Scan(&currentFailureCount)

	if err != nil {
		// If entry doesn't exist, create it with failure count 1
		if err == sql.ErrNoRows {
			penalty := calculateAuthPenalty(1, endpointType)
			nextAllowed := time.Now().Add(penalty)

			_, err = database.DB.Exec(`
				INSERT INTO share_access_attempts (share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt, created_at)
				VALUES (?, ?, 1, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP)
			`, shareID, entityID, nextAllowed)

			if err != nil {
				return fmt.Errorf("failed to create auth rate limit entry with failure: %w", err)
			}

			logging.InfoLogger.Printf("Auth rate limit created for %s, entity %s: 1 failure, next allowed: %v",
				endpointType, entityID, nextAllowed)
			return nil
		}
		return fmt.Errorf("failed to query current auth failure count: %w", err)
	}

	// Increment failure count
	newFailureCount := currentFailureCount + 1

	// Calculate next allowed attempt time
	penalty := calculateAuthPenalty(newFailureCount, endpointType)
	nextAllowed := time.Now().Add(penalty)

	// Update database
	_, err = database.DB.Exec(`
		UPDATE share_access_attempts 
		SET failed_count = ?, last_failed_attempt = CURRENT_TIMESTAMP, next_allowed_attempt = ?
		WHERE share_id = ? AND entity_id = ?
	`, newFailureCount, nextAllowed, shareID, entityID)

	if err != nil {
		return fmt.Errorf("failed to update auth rate limit entry: %w", err)
	}

	logging.InfoLogger.Printf("Auth rate limit updated for %s, entity %s: %d failures, next allowed: %v",
		endpointType, entityID, newFailureCount, nextAllowed)

	return nil
}
