package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionFamilyIdleEndsRefresh(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "idle-user", "")
	require.NoError(t, err)
	require.NoError(t, ShiftSessionFamilyClocks(
		db,
		session.FamilyID,
		time.Now(),
		SessionIdleLimit+time.Minute,
		0,
	))

	ended, err := ValidateRefreshSession(db, session.RefreshToken)
	require.ErrorIs(t, err, ErrSessionIdle)
	require.NotNil(t, ended)
	assert.Equal(t, session.FamilyID, ended.FamilyID)
	assert.True(t, ended.SessionEndedNow)

	ended, err = ValidateRefreshSession(db, session.RefreshToken)
	require.ErrorIs(t, err, ErrSessionIdle)
	assert.False(t, ended.SessionEndedNow)
}

func TestSessionFamilyUserActionInsideIdleWindow(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "active-user", "")
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, ShiftSessionFamilyClocks(
		db,
		session.FamilyID,
		now,
		SessionIdleLimit-time.Minute,
		0,
	))

	_, err = CheckSessionFamily(db, session.FamilyID, now)
	require.NoError(t, err)
	require.NoError(t, RecordSessionActivity(db, session.FamilyID, now))

	rotated, err := ValidateRefreshSession(db, session.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, session.FamilyID, rotated.FamilyID)
}

func TestRefreshDoesNotMoveSessionActivity(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "refresh-user", "")
	require.NoError(t, err)
	before, err := GetSessionFamily(db, session.FamilyID)
	require.NoError(t, err)

	rotated, err := ValidateRefreshSession(db, session.RefreshToken)
	require.NoError(t, err)
	after, err := GetSessionFamily(db, rotated.FamilyID)
	require.NoError(t, err)

	assert.Equal(t, before.LastUserActivity, after.LastUserActivity)
	assert.Equal(t, before.SessionStartedAt, after.SessionStartedAt)
}

func TestSessionActivityThrottleStillCountsAcceptedRequest(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "throttle-user", "")
	require.NoError(t, err)
	require.NoError(t, RecordSessionActivity(db, session.FamilyID, session.SessionStartedAt.Add(10*time.Second)))

	persisted, err := GetSessionFamily(db, session.FamilyID)
	require.NoError(t, err)
	assert.WithinDuration(t, session.SessionStartedAt, persisted.LastUserActivity, time.Millisecond)

	_, err = CheckSessionFamily(db, session.FamilyID, session.SessionStartedAt.Add(SessionIdleLimit+5*time.Second))
	require.NoError(t, err)

	later := session.SessionStartedAt.Add(70 * time.Second)
	require.NoError(t, RecordSessionActivity(db, session.FamilyID, later))
	persisted, err = GetSessionFamily(db, session.FamilyID)
	require.NoError(t, err)
	assert.WithinDuration(t, later, persisted.LastUserActivity, time.Millisecond)
}

func TestEndingOneSessionFamilyLeavesAnotherValid(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	first, err := CreateRefreshSession(db, "two-login-user", "")
	require.NoError(t, err)
	second, err := CreateRefreshSession(db, "two-login-user", "")
	require.NoError(t, err)

	reason, err := EndSessionFamily(db, first.FamilyID, SessionEndReasonLogout, time.Now())
	require.NoError(t, err)
	assert.Equal(t, SessionEndReasonLogout, reason)
	require.NoError(t, RevokeRefreshToken(db, first.RefreshToken))

	_, err = ValidateRefreshSession(db, first.RefreshToken)
	require.ErrorIs(t, err, ErrSessionLoggedOut)
	_, err = ValidateRefreshSession(db, second.RefreshToken)
	require.NoError(t, err)
}

func TestBackfillSessionFamiliesIsIdempotent(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "legacy-user", "")
	require.NoError(t, err)
	_, err = db.Exec("DELETE FROM session_families WHERE family_id = ?", session.FamilyID)
	require.NoError(t, err)

	migrationTime := time.Now().Add(-time.Minute)
	require.NoError(t, BackfillSessionFamilies(db, migrationTime))
	family, err := GetSessionFamily(db, session.FamilyID)
	require.NoError(t, err)
	assert.WithinDuration(t, migrationTime, family.LastUserActivity, time.Millisecond)

	secondRun := time.Now()
	require.NoError(t, BackfillSessionFamilies(db, secondRun))
	family, err = GetSessionFamily(db, session.FamilyID)
	require.NoError(t, err)
	assert.WithinDuration(t, migrationTime, family.LastUserActivity, time.Millisecond)
}
