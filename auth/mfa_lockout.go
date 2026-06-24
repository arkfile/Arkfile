package auth

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/arkfile/Arkfile/logging"
)

const (
	mfaSoftLockoutThreshold = 10
	mfaHardCapThreshold     = 30
	mfaWindowDuration       = 24 * time.Hour
	mfaBackoffCapMinutes    = 60
)

// MFALockoutError is returned when an MFA attempt is rejected due to failure-rate lockout.
type MFALockoutError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *MFALockoutError) Error() string {
	return e.Reason
}

type mfaLockoutState struct {
	failedAttempts int
	windowStarted  *time.Time
	lastFailed     *time.Time
}

func computeLockoutState(s mfaLockoutState, now time.Time) (allowed bool, retryAfter time.Duration, reason string) {
	if s.windowStarted == nil || now.Sub(*s.windowStarted) >= mfaWindowDuration {
		return true, 0, ""
	}

	if s.failedAttempts >= mfaHardCapThreshold {
		windowEnds := s.windowStarted.Add(mfaWindowDuration)
		wait := windowEnds.Sub(now)
		if wait < 0 {
			wait = 0
		}
		return false, wait, "too many failed attempts; try again later"
	}

	if s.failedAttempts >= mfaSoftLockoutThreshold && s.lastFailed != nil {
		backoffExp := s.failedAttempts - mfaSoftLockoutThreshold
		backoffMinutes := 1 << backoffExp
		if backoffMinutes > mfaBackoffCapMinutes {
			backoffMinutes = mfaBackoffCapMinutes
		}
		backoff := time.Duration(backoffMinutes) * time.Minute
		retryAt := s.lastFailed.Add(backoff)
		if now.Before(retryAt) {
			return false, retryAt.Sub(now), "too many failed attempts; try again later"
		}
	}

	return true, 0, ""
}

func getMFALockoutState(db *sql.DB, username string) (mfaLockoutState, error) {
	var s mfaLockoutState
	var failedAttempts int
	var windowStartedStr sql.NullString
	var lastFailedStr sql.NullString

	err := db.QueryRow(`
		SELECT failed_attempts_in_window, window_started_at, last_failed_attempt_at
		FROM user_mfa_lockout
		WHERE username = ?`, username,
	).Scan(&failedAttempts, &windowStartedStr, &lastFailedStr)

	if err != nil {
		if err == sql.ErrNoRows {
			return s, nil
		}
		return s, err
	}

	s.failedAttempts = failedAttempts

	parseTS := func(raw sql.NullString) *time.Time {
		if !raw.Valid || raw.String == "" {
			return nil
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, raw.String); err == nil {
				return &t
			}
		}
		return nil
	}

	s.windowStarted = parseTS(windowStartedStr)
	s.lastFailed = parseTS(lastFailedStr)
	return s, nil
}

func recordMFAFailure(db *sql.DB, username string, now time.Time) (mfaLockoutState, error) {
	cur, err := getMFALockoutState(db, username)
	if err != nil {
		return cur, err
	}

	var newAttempts int
	var newWindowStart time.Time

	if cur.windowStarted == nil || now.Sub(*cur.windowStarted) >= mfaWindowDuration {
		newAttempts = 1
		newWindowStart = now
	} else {
		newAttempts = cur.failedAttempts + 1
		newWindowStart = *cur.windowStarted
	}

	_, err = db.Exec(`
		INSERT INTO user_mfa_lockout (
			username, failed_attempts_in_window, window_started_at, last_failed_attempt_at
		) VALUES (?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			failed_attempts_in_window = excluded.failed_attempts_in_window,
			window_started_at = excluded.window_started_at,
			last_failed_attempt_at = excluded.last_failed_attempt_at`,
		username, newAttempts, newWindowStart, now,
	)
	if err != nil {
		return cur, err
	}

	return mfaLockoutState{
		failedAttempts: newAttempts,
		windowStarted:  &newWindowStart,
		lastFailed:     &now,
	}, nil
}

func clearMFAFailures(db *sql.DB, username string) error {
	_, err := db.Exec(`DELETE FROM user_mfa_lockout WHERE username = ?`, username)
	return err
}

func emitMFALockoutEvent(_ *sql.DB, username, eventType, detail string) {
	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("SECURITY: %s for user: %s (%s)", eventType, username, detail)
	}
}

func checkMFALockout(db *sql.DB, username string, now time.Time) error {
	lockState, err := getMFALockoutState(db, username)
	if err != nil {
		return fmt.Errorf("failed to check MFA lockout state: %w", err)
	}

	allowed, retryAfter, reason := computeLockoutState(lockState, now)
	if !allowed {
		return &MFALockoutError{Reason: reason, RetryAfter: retryAfter}
	}
	return nil
}

func recordMFAFailureAndEmit(db *sql.DB, username string, now time.Time) {
	updated, recErr := recordMFAFailure(db, username, now)
	if recErr != nil && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("Failed to record MFA failure for user %s: %v", username, recErr)
	}
	if updated.failedAttempts == mfaSoftLockoutThreshold+1 {
		emitMFALockoutEvent(db, username, "MFASoftLockout",
			fmt.Sprintf("failure count reached %d", updated.failedAttempts))
	} else if updated.failedAttempts == mfaHardCapThreshold+1 {
		emitMFALockoutEvent(db, username, "MFAHardCap",
			fmt.Sprintf("failure count reached %d; locked for 24h", updated.failedAttempts))
	}
}

func clearMFAFailuresIfLocked(db *sql.DB, username string, lockState mfaLockoutState) {
	wasLocked := lockState.failedAttempts >= mfaSoftLockoutThreshold
	if clearErr := clearMFAFailures(db, username); clearErr != nil && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("Failed to clear MFA failures for user %s: %v", username, clearErr)
	}
	if wasLocked {
		emitMFALockoutEvent(db, username, "MFALockoutCleared", "successful verification after lockout")
	}
}
