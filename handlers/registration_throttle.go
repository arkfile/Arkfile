package handlers

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
)

// Positive registration throttle. Counts successful account creations per
// privacy-preserving entityID over a rolling 24h window and, once the free
// allowance is consumed, imposes escalating cooldowns measured from the
// attempt that tripped the throttle.
//
// This is intentionally separate from the failure-based RegisterRateLimitMiddleware
// (which penalizes repeated failed auth attempts) and from the share_access_attempts
// table. It records only completed registrations so a flood of denied attempts
// cannot inflate a caller's cooldown. The entityID is the composite HMAC
// identifier from logging.GetOrCreateEntityID (IP plus coarse User-Agent and
// Accept-Language buckets); the raw IP is never persisted.
const (
	// registrationFreePerWindow is the number of successful registrations an
	// entityID may complete per rolling 24h window before cooldowns apply.
	registrationFreePerWindow = 7
	// registrationWindow is the rolling window length.
	registrationWindow = 24 * time.Hour
	// registrationAttemptRetention is how long rows are kept before pruning.
	// 48h gives a full window plus buffer for the rolling-window queries.
	registrationAttemptRetention = 48 * time.Hour
	// registrationBaseCooldown is the wait imposed on the first over-limit
	// attempt (the 8th). Each subsequent over-limit attempt doubles the wait.
	registrationBaseCooldown = 2 * time.Hour
	// registrationMaxCooldown caps the escalating wait so an active attacker
	// (or a busy shared NAT) cannot be locked out indefinitely.
	registrationMaxCooldown = 24 * time.Hour
	// registrationAttemptCleanupInterval paces the background prune sweep.
	registrationAttemptCleanupInterval = time.Hour
	// registrationAttemptTimeFormat is the UTC text layout used for SQL
	// comparisons against CURRENT_TIMESTAMP columns.
	registrationAttemptTimeFormat = "2006-01-02 15:04:05"
)

var (
	registrationAttemptCleanupMu     sync.Mutex
	lastRegistrationAttemptCleanupAt = time.Now()
)

// CheckRegistrationThrottle reports whether a new registration from the given
// entityID is currently allowed and, if not, how long until the next attempt
// would be permitted. It counts only successful registrations recorded in the
// last registrationWindow. When the count is at or above the free allowance,
// the (count+1)th attempt requires an escalating cooldown measured from the
// attempt that tripped the throttle (the registrationFreePerWindow-th one).
func CheckRegistrationThrottle(entityID string) (allowed bool, retryAfter time.Duration, err error) {
	maybePruneRegistrationAttempts(time.Now())

	now := time.Now()
	// Compare as UTC "YYYY-MM-DD HH:MM:SS" text so the SQL comparison aligns
	// with CURRENT_TIMESTAMP values written by RecordRegistrationAttempt.
	// Mixing a Go time.Time parameter (which the driver renders with a zone
	// suffix) against the zoneless CURRENT_TIMESTAMP text breaks the
	// lexicographic comparison SQLite/rqlite use for DATETIME columns.
	windowStartStr := now.UTC().Add(-registrationWindow).Format(registrationAttemptTimeFormat)

	var count int
	if err = database.DB.QueryRow(
		`SELECT COUNT(*) FROM registration_attempts WHERE entity_id = ? AND created_at > ?`,
		entityID, windowStartStr,
	).Scan(&count); err != nil {
		return false, 0, fmt.Errorf("registration throttle: count: %w", err)
	}

	if count < registrationFreePerWindow {
		return true, 0, nil
	}

	// Locate the attempt that tripped the throttle: the Nth free attempt,
	// which is the (registrationFreePerWindow-1)-th row in ascending time order
	// within the window. All counted rows are within the window by construction.
	var triggerStr string
	if err = database.DB.QueryRow(
		`SELECT created_at FROM registration_attempts
		 WHERE entity_id = ? AND created_at > ?
		 ORDER BY created_at ASC
		 LIMIT 1 OFFSET ?`,
		entityID, windowStartStr, registrationFreePerWindow-1,
	).Scan(&triggerStr); err != nil {
		return false, 0, fmt.Errorf("registration throttle: read trigger attempt: %w", err)
	}

	trigger, perr := parseRegistrationAttemptTime(triggerStr)
	if perr != nil {
		return false, 0, fmt.Errorf("registration throttle: parse trigger time: %w", perr)
	}

	required := registrationCooldownFor(count + 1)
	elapsed := now.Sub(trigger)
	if elapsed >= required {
		return true, 0, nil
	}
	return false, required - elapsed, nil
}

// registrationCooldownFor returns the wait required before the attemptNumber-th
// successful registration is permitted. The first registrationFreePerWindow
// attempts are free; each over-limit attempt doubles the base cooldown, capped
// at registrationMaxCooldown.
func registrationCooldownFor(attemptNumber int) time.Duration {
	if attemptNumber <= registrationFreePerWindow {
		return 0
	}
	shift := attemptNumber - registrationFreePerWindow - 1 // 8th attempt -> shift 0
	if shift > 20 {
		return registrationMaxCooldown
	}
	d := registrationBaseCooldown << uint(shift)
	if d <= 0 || d > registrationMaxCooldown {
		return registrationMaxCooldown
	}
	return d
}

// RecordRegistrationAttempt logs a successful registration for throttle
// accounting. Call only after the user record has been committed.
func RecordRegistrationAttempt(entityID, username string) error {
	_, err := database.DB.Exec(
		`INSERT INTO registration_attempts (entity_id, username, created_at)
		 VALUES (?, ?, CURRENT_TIMESTAMP)`,
		entityID, username,
	)
	if err != nil {
		return fmt.Errorf("registration throttle: record: %w", err)
	}
	return nil
}

// enforceRegistrationThrottle checks the per-entityID registration throttle and,
// when the caller must wait, writes an HTTP 429 response. Returns allowed=true
// when the attempt may proceed. A non-nil error means the throttle itself
// failed (caller should return 503); allowed=false with nil error means the
// 429 response was already written (caller should return nil).
//
// Without a usable entity identifier the throttle fails open: registration is
// a public good and the entityID layer is a privacy primitive, not an auth
// gate. The failure-based RegisterRateLimitMiddleware still applies in that case.
func enforceRegistrationThrottle(c echo.Context) (allowed bool, err error) {
	entityID := logging.GetOrCreateEntityID(c)
	if entityID == "" || entityID == "unknown" || entityID == "uninitialized" {
		return true, nil
	}

	allowed, retryAfter, err := CheckRegistrationThrottle(entityID)
	if err != nil {
		logging.ErrorLogger.Printf("Registration throttle check failed: %v", err)
		return false, err
	}
	if !allowed {
		retryAfterSeconds := int(retryAfter.Seconds())
		if retryAfterSeconds < 1 {
			retryAfterSeconds = 1
		}
		c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds))
		_ = JSONErrorCodeData(c, http.StatusTooManyRequests, "rate_limited",
			fmt.Sprintf("Too many registrations from this network. Try again in %d seconds.", retryAfterSeconds),
			map[string]interface{}{
				"retry_after_seconds": retryAfterSeconds,
				"endpoint":            "register",
			})
		return false, nil
	}
	return true, nil
}

// recordSuccessfulRegistration records a completed registration for throttle
// accounting. Failures are logged but never block the already-completed
// registration.
func recordSuccessfulRegistration(c echo.Context, username string) {
	entityID := logging.GetOrCreateEntityID(c)
	if entityID == "" || entityID == "unknown" || entityID == "uninitialized" {
		return
	}
	if err := RecordRegistrationAttempt(entityID, username); err != nil {
		logging.ErrorLogger.Printf("Failed to record registration attempt for %s: %v", username, err)
	}
}

// AdminResetRegistrationThrottle clears the registration_attempts table. This
// is a dev/test-only endpoint (registered only when ADMIN_DEV_TEST_API_ENABLED)
// used by the e2e throttle-interaction test to start from a known state and to
// avoid leaving the test host's entityID in a multi-hour cooldown that would
// block manual testing afterward.
func AdminResetRegistrationThrottle(c echo.Context) error {
	adminUsername, errResp := requireAdminWithUsername(c)
	if errResp != nil {
		return errResp
	}

	result, err := database.DB.Exec(`DELETE FROM registration_attempts`)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to reset registration throttle: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to reset registration throttle")
	}

	rows, _ := result.RowsAffected()
	// Also reset the in-process cleanup pacing so the next check re-prunes.
	registrationAttemptCleanupMu.Lock()
	lastRegistrationAttemptCleanupAt = time.Now()
	registrationAttemptCleanupMu.Unlock()

	if err := LogAdminAction(database.DB, adminUsername, "reset_registration_throttle", "",
		fmt.Sprintf("deleted %d rows", rows)); err != nil {
		logging.ErrorLogger.Printf("Failed to log registration throttle reset: %v", err)
	}

	return JSONResponse(c, http.StatusOK, "Registration throttle reset", map[string]interface{}{
		"deleted": rows,
	})
}

func maybePruneRegistrationAttempts(now time.Time) {
	registrationAttemptCleanupMu.Lock()
	defer registrationAttemptCleanupMu.Unlock()

	if now.Sub(lastRegistrationAttemptCleanupAt) < registrationAttemptCleanupInterval {
		return
	}

	rows, err := pruneRegistrationAttempts(now.Add(-registrationAttemptRetention))
	if err != nil {
		logging.ErrorLogger.Printf("Registration attempt cleanup failed: %v", err)
		return
	}
	lastRegistrationAttemptCleanupAt = now
	if rows > 0 {
		logging.InfoLogger.Printf("Pruned %d expired registration attempt rows", rows)
	}
}

func pruneRegistrationAttempts(cutoff time.Time) (int64, error) {
	result, err := database.DB.Exec(
		`DELETE FROM registration_attempts WHERE created_at < ?`,
		cutoff.UTC().Format(registrationAttemptTimeFormat),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to prune registration attempts: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return rows, nil
}

// parseRegistrationAttemptTime parses a created_at value coming back from
// rqlite/SQLite, which may render as either a naive "YYYY-MM-DD HH:MM:SS"
// string or an RFC3339 timestamp.
func parseRegistrationAttemptTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable timestamp %q", s)
}
