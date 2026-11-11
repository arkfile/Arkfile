package models

import (
	"database/sql"
	"errors"
	"time"
)

const (
	LoginKindAdmin = "admin"

	SessionAbsoluteLimit = 24 * time.Hour
	SessionGraceExtra    = 12 * time.Hour
	SessionHardCeiling   = SessionAbsoluteLimit + SessionGraceExtra
	AdminSessionLimit    = 60 * time.Minute
	AdminIdleLimit       = 15 * time.Minute
	GraceQuietTimeout    = 30 * time.Minute

	GraceKindUpload = "upload_session"
	GraceKindFile   = "file"

	endedFamilyRetention = 7 * 24 * time.Hour
)

// ErrAdminSessionNotLocal is returned when a marked admin refresh is presented
// from outside a direct local connection, or from a cookie.
var ErrAdminSessionNotLocal = errors.New("admin session is only valid on this server")

// SessionUse describes the request being checked against a login family.
type SessionUse struct {
	Refresh bool
	// Transfer marks upload chunk, complete, status, cancel, and download chunk.
	Transfer bool
	// GraceKind and GraceID may claim or continue one-file grace after 24 hours.
	GraceKind string
	GraceID   string
	// UploadStarted is the upload session created_at. A new upload grace target
	// is accepted only when this is before the 24-hour mark.
	UploadStarted *time.Time
	// DirectLocal and FromCookie apply to refresh of a marked admin login.
	DirectLocal bool
	FromCookie  bool
}

func SessionAbsoluteExpiry(started time.Time, loginKind string) time.Time {
	if loginKind == LoginKindAdmin {
		return started.Add(AdminSessionLimit)
	}
	return started.Add(SessionAbsoluteLimit)
}

func SessionIdleLimitFor(loginKind string) time.Duration {
	if loginKind == LoginKindAdmin {
		return AdminIdleLimit
	}
	return SessionIdleLimit
}

func SessionRefreshCeiling(started time.Time, loginKind string) time.Time {
	if loginKind == LoginKindAdmin {
		return started.Add(AdminSessionLimit)
	}
	return started.Add(SessionHardCeiling)
}

func RefreshCookieMaxAge(started time.Time, loginKind string, now time.Time) int {
	if started.IsZero() {
		return int(SessionHardCeiling.Seconds())
	}
	remaining := int(SessionRefreshCeiling(started, loginKind).Sub(now).Seconds())
	if remaining < 1 {
		return 0
	}
	return remaining
}

func refreshWithin(ts *time.Time, now time.Time, window time.Duration) bool {
	return ts != nil && now.Before(ts.Add(window))
}

// DecideSessionUse applies the lifetime rules without recording activity.
// A request outside an active grace target returns ErrSessionAbsolute and
// leaves the family open so the file already in grace can finish.
func DecideSessionUse(db *sql.DB, familyID string, now time.Time, use SessionUse) (*SessionFamily, error) {
	family, err := GetSessionFamily(db, familyID)
	if err != nil {
		return nil, err
	}
	if family.EndedAt != nil {
		return family, sessionErrorForReason(family.EndedReason)
	}

	if family.LoginKind == LoginKindAdmin && !now.Before(family.SessionStartedAt.Add(AdminSessionLimit)) {
		return endAbsolute(db, family, now)
	}
	if use.Refresh && family.LoginKind == LoginKindAdmin && (!use.DirectLocal || use.FromCookie) {
		return family, ErrAdminSessionNotLocal
	}
	if !now.Before(SessionRefreshCeiling(family.SessionStartedAt, family.LoginKind)) {
		return endAbsolute(db, family, now)
	}

	if family.LoginKind != LoginKindAdmin && !now.Before(family.SessionStartedAt.Add(SessionAbsoluteLimit)) {
		allowed, rejectOpen, decideErr := decideGrace(db, family, now, use)
		if decideErr != nil {
			return family, decideErr
		}
		if !allowed {
			if rejectOpen {
				return family, ErrSessionAbsolute
			}
			return endAbsolute(db, family, now)
		}
	}

	lastActivity := effectiveLastUserActivity(familyID, family.LastUserActivity)
	if !now.Before(lastActivity.Add(SessionIdleLimitFor(family.LoginKind))) {
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

func endAbsolute(db *sql.DB, family *SessionFamily, now time.Time) (*SessionFamily, error) {
	reason, endedNow, err := endSessionFamily(db, family.FamilyID, SessionEndReasonAbsolute, now)
	if err != nil {
		return nil, err
	}
	family.EndedReason = reason
	family.EndedAt = &now
	family.EndedNow = endedNow
	return family, sessionErrorForReason(reason)
}

// decideGrace reports whether this request may continue after the 24-hour mark.
// rejectOpen is true when the family stays open for a different grace target.
func decideGrace(db *sql.DB, family *SessionFamily, now time.Time, use SessionUse) (allowed bool, rejectOpen bool, err error) {
	if family.GraceTarget != "" && !refreshWithin(family.GraceLastRequestAt, now, GraceQuietTimeout) {
		return false, false, nil
	}
	if family.GraceTarget != "" {
		if use.Refresh {
			return true, false, nil
		}
		if use.GraceKind == family.GraceTargetKind && use.GraceID != "" && use.GraceID == family.GraceTarget {
			return true, false, nil
		}
		return false, true, nil
	}

	if use.Refresh {
		return refreshWithin(family.LastTransferRequestAt, now, GraceQuietTimeout), false, nil
	}
	if !canClaimGrace(family, use) {
		return false, false, nil
	}
	claimed, claimErr := claimGraceTarget(db, family, now, use)
	if claimErr != nil {
		return false, false, claimErr
	}
	if !claimed {
		return false, true, nil
	}
	return true, false, nil
}

func canClaimGrace(family *SessionFamily, use SessionUse) bool {
	if use.GraceID == "" {
		return false
	}
	switch use.GraceKind {
	case GraceKindFile:
		return true
	case GraceKindUpload:
		if use.UploadStarted == nil {
			return false
		}
		return use.UploadStarted.Before(family.SessionStartedAt.Add(SessionAbsoluteLimit))
	default:
		return false
	}
}

func claimGraceTarget(db *sql.DB, family *SessionFamily, now time.Time, use SessionUse) (bool, error) {
	result, err := db.Exec(
		`UPDATE session_families
		    SET grace_target = ?, grace_target_kind = ?, grace_last_request_at = ?
		  WHERE family_id = ? AND ended_at IS NULL
		    AND (grace_target IS NULL OR grace_target = '')`,
		use.GraceID, use.GraceKind, now, family.FamilyID,
	)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows > 0 {
		family.GraceTarget = use.GraceID
		family.GraceTargetKind = use.GraceKind
		family.GraceLastRequestAt = &now
		noteGraceWrite(family.FamilyID, now)
		return true, nil
	}

	current, err := GetSessionFamily(db, family.FamilyID)
	if err != nil {
		return false, err
	}
	*family = *current
	if family.EndedAt != nil {
		return false, sessionErrorForReason(family.EndedReason)
	}
	return family.GraceTarget == use.GraceID && family.GraceTargetKind == use.GraceKind, nil
}

// AuthorizeSessionUse checks the request and records activity when it is allowed.
func AuthorizeSessionUse(db *sql.DB, familyID string, now time.Time, use SessionUse) (*SessionFamily, error) {
	family, err := DecideSessionUse(db, familyID, now, use)
	if err != nil {
		return family, err
	}
	if use.Refresh {
		return family, nil
	}
	if err := RecordSessionActivity(db, familyID, now); err != nil {
		return family, err
	}
	if use.Transfer {
		if err := recordTransferActivity(db, familyID, now); err != nil {
			return family, err
		}
	}
	if family.GraceTarget != "" && use.GraceKind == family.GraceTargetKind && use.GraceID == family.GraceTarget {
		if err := recordGraceActivity(db, familyID, now); err != nil {
			return family, err
		}
	}
	return family, nil
}

func noteGraceWrite(familyID string, now time.Time) {
	sessionActivityCache.Lock()
	entry := sessionActivityCache.entries[familyID]
	entry.graceAccepted = now
	entry.gracePersisted = now
	sessionActivityCache.entries[familyID] = entry
	sessionActivityCache.Unlock()
}

func recordTransferActivity(db *sql.DB, familyID string, now time.Time) error {
	return recordThrottledTime(db, familyID, now, "last_transfer_request_at", func(entry *sessionActivityEntry) (accepted, persisted *time.Time) {
		return &entry.transferAccepted, &entry.transferPersisted
	})
}

func recordGraceActivity(db *sql.DB, familyID string, now time.Time) error {
	return recordThrottledTime(db, familyID, now, "grace_last_request_at", func(entry *sessionActivityEntry) (accepted, persisted *time.Time) {
		return &entry.graceAccepted, &entry.gracePersisted
	})
}

func recordThrottledTime(
	db *sql.DB,
	familyID string,
	now time.Time,
	column string,
	fields func(*sessionActivityEntry) (accepted, persisted *time.Time),
) error {
	sessionActivityCache.Lock()
	previous := sessionActivityCache.entries[familyID]
	entry := previous
	accepted, persisted := fields(&entry)
	shouldPersist := persisted.IsZero() || !now.Before(persisted.Add(sessionActivityWriteInterval))
	if !shouldPersist {
		if now.After(*accepted) {
			*accepted = now
		}
		sessionActivityCache.entries[familyID] = entry
		sessionActivityCache.Unlock()
		return nil
	}
	if now.After(*accepted) {
		*accepted = now
	}
	*persisted = now
	sessionActivityCache.entries[familyID] = entry
	sessionActivityCache.Unlock()

	result, err := db.Exec(
		`UPDATE session_families SET `+column+` = ? WHERE family_id = ? AND ended_at IS NULL`,
		now, familyID,
	)
	if err != nil {
		sessionActivityCache.Lock()
		current := sessionActivityCache.entries[familyID]
		_, curPersisted := fields(&current)
		if curPersisted.Equal(now) {
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

// ApplyAbsoluteSessionLimits ends families already past their cap and shortens
// refresh-token expiry to the hard ceiling. It does not move either clock.
func ApplyAbsoluteSessionLimits(db *sql.DB, now time.Time) error {
	rows, err := db.Query(`SELECT family_id FROM session_families WHERE ended_at IS NULL`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, id := range ids {
		family, err := GetSessionFamily(db, id)
		if err != nil {
			return err
		}
		if family.EndedAt != nil {
			continue
		}
		cap := SessionAbsoluteExpiry(family.SessionStartedAt, family.LoginKind)
		if !now.Before(cap) {
			if _, _, err := endSessionFamily(db, id, SessionEndReasonAbsolute, now); err != nil {
				return err
			}
		}
		if err := shrinkRefreshExpiry(db, id, SessionRefreshCeiling(family.SessionStartedAt, family.LoginKind)); err != nil {
			return err
		}
	}
	return nil
}

func shrinkRefreshExpiry(db *sql.DB, familyID string, ceiling time.Time) error {
	rows, err := db.Query(
		`SELECT id, expires_at FROM refresh_tokens WHERE family_id = ? AND revoked = false`,
		familyID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	type row struct {
		id      string
		expires time.Time
	}
	var pending []row
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		expires, err := parseDatabaseTime(raw)
		if err != nil {
			return err
		}
		if expires.After(ceiling) {
			pending = append(pending, row{id: id, expires: ceiling})
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range pending {
		if _, err := db.Exec(`UPDATE refresh_tokens SET expires_at = ? WHERE id = ?`, item.expires, item.id); err != nil {
			return err
		}
	}
	return nil
}

// CleanupEndedSessionFamilies deletes families ended more than seven days ago,
// including refresh tokens a client might still present for the stored reason.
func CleanupEndedSessionFamilies(db *sql.DB, now time.Time) error {
	rows, err := db.Query(`SELECT family_id, ended_at FROM session_families WHERE ended_at IS NOT NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()

	cutoff := now.Add(-endedFamilyRetention)
	var ids []string
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		ended, err := parseDatabaseTime(raw)
		if err != nil {
			return err
		}
		if ended.Before(cutoff) {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := db.Exec(`DELETE FROM refresh_tokens WHERE family_id = ?`, id); err != nil {
			return err
		}
		if _, err := db.Exec(`DELETE FROM session_families WHERE family_id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}
