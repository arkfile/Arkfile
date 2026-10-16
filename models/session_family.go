package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	SessionIdleLimit             = 6 * time.Hour
	sessionActivityWriteInterval = time.Minute

	SessionEndReasonIdle     = "idle"
	SessionEndReasonAbsolute = "absolute"
	SessionEndReasonLogout   = "logout"

	SessionErrorIdle      = "session_idle"
	SessionErrorAbsolute  = "session_absolute"
	SessionErrorLoggedOut = "session_logged_out"
)

var (
	ErrSessionIdle      = errors.New("session ended after six hours without activity")
	ErrSessionAbsolute  = errors.New("session reached its absolute lifetime")
	ErrSessionLoggedOut = errors.New("session was logged out")
)

type SessionFamily struct {
	FamilyID              string
	Username              string
	LoginKind             string
	SessionStartedAt      time.Time
	LastUserActivity      time.Time
	LastTransferRequestAt *time.Time
	GraceTarget           string
	GraceTargetKind       string
	GraceLastRequestAt    *time.Time
	EndedAt               *time.Time
	EndedReason           string
	EndedNow              bool
}

type sessionActivityEntry struct {
	acceptedAt  time.Time
	persistedAt time.Time
}

var sessionActivityCache = struct {
	sync.RWMutex
	entries map[string]sessionActivityEntry
}{
	entries: make(map[string]sessionActivityEntry),
}

func parseDatabaseTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported database timestamp %q", value)
}

func nullableDatabaseTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil, nil
	}
	parsed, err := parseDatabaseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func GetSessionFamily(db *sql.DB, familyID string) (*SessionFamily, error) {
	var (
		family                SessionFamily
		loginKind             sql.NullString
		sessionStartedAt      string
		lastUserActivity      string
		lastTransferRequestAt sql.NullString
		graceTarget           sql.NullString
		graceTargetKind       sql.NullString
		graceLastRequestAt    sql.NullString
		endedAt               sql.NullString
		endedReason           sql.NullString
	)

	err := db.QueryRow(
		`SELECT family_id, username, login_kind, session_started_at, last_user_activity,
		        last_transfer_request_at, grace_target, grace_target_kind,
		        grace_last_request_at, ended_at, ended_reason
		   FROM session_families
		  WHERE family_id = ?`,
		familyID,
	).Scan(
		&family.FamilyID,
		&family.Username,
		&loginKind,
		&sessionStartedAt,
		&lastUserActivity,
		&lastTransferRequestAt,
		&graceTarget,
		&graceTargetKind,
		&graceLastRequestAt,
		&endedAt,
		&endedReason,
	)
	if err != nil {
		return nil, err
	}

	family.LoginKind = loginKind.String
	family.GraceTarget = graceTarget.String
	family.GraceTargetKind = graceTargetKind.String
	family.EndedReason = endedReason.String

	family.SessionStartedAt, err = parseDatabaseTime(sessionStartedAt)
	if err != nil {
		return nil, fmt.Errorf("parse session_started_at: %w", err)
	}
	family.LastUserActivity, err = parseDatabaseTime(lastUserActivity)
	if err != nil {
		return nil, fmt.Errorf("parse last_user_activity: %w", err)
	}
	family.LastTransferRequestAt, err = nullableDatabaseTime(lastTransferRequestAt)
	if err != nil {
		return nil, fmt.Errorf("parse last_transfer_request_at: %w", err)
	}
	family.GraceLastRequestAt, err = nullableDatabaseTime(graceLastRequestAt)
	if err != nil {
		return nil, fmt.Errorf("parse grace_last_request_at: %w", err)
	}
	family.EndedAt, err = nullableDatabaseTime(endedAt)
	if err != nil {
		return nil, fmt.Errorf("parse ended_at: %w", err)
	}

	return &family, nil
}

func sessionErrorForReason(reason string) error {
	switch reason {
	case SessionEndReasonIdle:
		return ErrSessionIdle
	case SessionEndReasonAbsolute:
		return ErrSessionAbsolute
	case SessionEndReasonLogout:
		return ErrSessionLoggedOut
	default:
		return fmt.Errorf("session ended for unknown reason %q", reason)
	}
}

func SessionErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrSessionIdle):
		return SessionErrorIdle
	case errors.Is(err, ErrSessionAbsolute):
		return SessionErrorAbsolute
	case errors.Is(err, ErrSessionLoggedOut):
		return SessionErrorLoggedOut
	default:
		return ""
	}
}

func effectiveLastUserActivity(familyID string, persisted time.Time) time.Time {
	sessionActivityCache.RLock()
	entry, ok := sessionActivityCache.entries[familyID]
	sessionActivityCache.RUnlock()
	if ok && entry.acceptedAt.After(persisted) {
		return entry.acceptedAt
	}
	return persisted
}

func CheckSessionFamily(db *sql.DB, familyID string, now time.Time) (*SessionFamily, error) {
	family, err := GetSessionFamily(db, familyID)
	if err != nil {
		return nil, err
	}
	if family.EndedAt != nil {
		return family, sessionErrorForReason(family.EndedReason)
	}

	lastActivity := effectiveLastUserActivity(familyID, family.LastUserActivity)
	if !now.Before(lastActivity.Add(SessionIdleLimit)) {
		reason, endedNow, endErr := endSessionFamily(db, familyID, SessionEndReasonIdle, now)
		if endErr != nil {
			return nil, endErr
		}
		family.EndedReason = reason
		family.EndedAt = &now
		family.EndedNow = endedNow
		return family, sessionErrorForReason(reason)
	}

	return family, nil
}

func RecordSessionActivity(db *sql.DB, familyID string, now time.Time) error {
	sessionActivityCache.Lock()
	previous := sessionActivityCache.entries[familyID]
	entry := previous
	shouldPersist := entry.persistedAt.IsZero() || !now.Before(entry.persistedAt.Add(sessionActivityWriteInterval))
	if !shouldPersist {
		entry.acceptedAt = now
		sessionActivityCache.entries[familyID] = entry
		sessionActivityCache.Unlock()
		return nil
	}
	if now.After(entry.acceptedAt) {
		entry.acceptedAt = now
	}
	entry.persistedAt = now
	sessionActivityCache.entries[familyID] = entry
	sessionActivityCache.Unlock()

	result, err := db.Exec(
		`UPDATE session_families
		    SET last_user_activity = ?
		  WHERE family_id = ? AND ended_at IS NULL`,
		now,
		familyID,
	)
	if err != nil {
		sessionActivityCache.Lock()
		if current := sessionActivityCache.entries[familyID]; current.persistedAt.Equal(now) {
			sessionActivityCache.entries[familyID] = previous
		}
		sessionActivityCache.Unlock()
		return err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil {
		return rowsErr
	} else if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func EndSessionFamily(db *sql.DB, familyID, reason string, now time.Time) (string, error) {
	storedReason, _, err := endSessionFamily(db, familyID, reason, now)
	return storedReason, err
}

func endSessionFamily(db *sql.DB, familyID, reason string, now time.Time) (string, bool, error) {
	if reason != SessionEndReasonIdle && reason != SessionEndReasonAbsolute && reason != SessionEndReasonLogout {
		return "", false, fmt.Errorf("invalid session end reason %q", reason)
	}
	result, err := db.Exec(
		`UPDATE session_families
		    SET ended_at = ?, ended_reason = ?
		  WHERE family_id = ? AND ended_at IS NULL`,
		now,
		reason,
		familyID,
	)
	if err != nil {
		return "", false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return "", false, err
	}

	var storedReason sql.NullString
	if err := db.QueryRow(
		"SELECT ended_reason FROM session_families WHERE family_id = ?",
		familyID,
	).Scan(&storedReason); err != nil {
		return "", false, err
	}
	if !storedReason.Valid || storedReason.String == "" {
		return "", false, fmt.Errorf("session family %s did not record an end reason", familyID)
	}

	sessionActivityCache.Lock()
	delete(sessionActivityCache.entries, familyID)
	sessionActivityCache.Unlock()
	return storedReason.String, rowsAffected > 0, nil
}

func ShiftSessionFamilyClocks(db *sql.DB, familyID string, now time.Time, idleOffset, ageOffset time.Duration) error {
	family, err := GetSessionFamily(db, familyID)
	if err != nil {
		return err
	}
	if family.EndedAt != nil {
		return fmt.Errorf("session family %s has already ended", familyID)
	}

	lastActivity := family.LastUserActivity
	if idleOffset > 0 {
		lastActivity = now.Add(-idleOffset)
	}
	sessionStarted := family.SessionStartedAt
	if ageOffset > 0 {
		sessionStarted = now.Add(-ageOffset)
	}

	result, err := db.Exec(
		`UPDATE session_families
		    SET session_started_at = ?, last_user_activity = ?
		  WHERE family_id = ? AND ended_at IS NULL`,
		sessionStarted,
		lastActivity,
		familyID,
	)
	if err != nil {
		return err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil {
		return rowsErr
	} else if rows == 0 {
		return sql.ErrNoRows
	}

	sessionActivityCache.Lock()
	sessionActivityCache.entries[familyID] = sessionActivityEntry{
		acceptedAt:  lastActivity,
		persistedAt: lastActivity,
	}
	sessionActivityCache.Unlock()
	return nil
}

func BackfillSessionFamilies(db *sql.DB, migrationTime time.Time) error {
	rows, err := db.Query(
		`SELECT family_id, username, MIN(created_at)
		   FROM refresh_tokens
		  WHERE family_id IS NOT NULL AND family_id <> ''
		  GROUP BY family_id, username`,
	)
	if err != nil {
		return err
	}

	type legacyFamily struct {
		familyID string
		username string
		started  time.Time
	}
	var families []legacyFamily
	for rows.Next() {
		var familyID, username, startedRaw string
		if err := rows.Scan(&familyID, &username, &startedRaw); err != nil {
			rows.Close()
			return err
		}
		started, err := parseDatabaseTime(startedRaw)
		if err != nil {
			rows.Close()
			return fmt.Errorf("parse family %s start: %w", familyID, err)
		}
		families = append(families, legacyFamily{
			familyID: familyID,
			username: username,
			started:  started,
		})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, family := range families {
		if _, err := db.Exec(
			`INSERT OR IGNORE INTO session_families
			 (family_id, username, login_kind, session_started_at, last_user_activity)
			 VALUES (?, ?, NULL, ?, ?)`,
			family.familyID,
			family.username,
			family.started,
			migrationTime,
		); err != nil {
			return fmt.Errorf("backfill family %s: %w", family.familyID, err)
		}
	}
	return nil
}
