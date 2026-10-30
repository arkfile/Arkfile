package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionAbsoluteEndsRefreshWithoutGrace(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "absolute-user", "")
	require.NoError(t, err)
	require.NoError(t, ShiftSessionFamilyClocks(db, session.FamilyID, time.Now(), 0, SessionAbsoluteLimit+time.Minute))

	ended, err := ValidateRefreshSession(db, session.RefreshToken)
	require.ErrorIs(t, err, ErrSessionAbsolute)
	require.NotNil(t, ended)
	assert.True(t, ended.SessionEndedNow)

	ended, err = ValidateRefreshSession(db, session.RefreshToken)
	require.ErrorIs(t, err, ErrSessionAbsolute)
	assert.False(t, ended.SessionEndedNow)
}

func TestRecentTransferAllowsRefreshAfterAbsoluteMark(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "transfer-user", "")
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, ShiftSessionFamilyClocks(db, session.FamilyID, now, 0, SessionAbsoluteLimit+time.Minute))
	_, err = db.Exec(
		`UPDATE session_families SET last_transfer_request_at = ? WHERE family_id = ?`,
		now.Add(-time.Minute), session.FamilyID,
	)
	require.NoError(t, err)

	rotated, err := ValidateRefreshSession(db, session.RefreshToken)
	require.NoError(t, err)
	assert.NotEqual(t, session.RefreshToken, rotated.RefreshToken)
	assert.Equal(t, session.FamilyID, rotated.FamilyID)
}

func TestGraceTargetRejectsASecondFileWithoutEnding(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "grace-user", "")
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, ShiftSessionFamilyClocks(db, session.FamilyID, now, time.Minute, SessionAbsoluteLimit+time.Minute))

	first, err := AuthorizeSessionUse(db, session.FamilyID, now, SessionUse{
		Transfer:  true,
		GraceKind: GraceKindFile,
		GraceID:   "file-a",
	})
	require.NoError(t, err)
	assert.Equal(t, "file-a", first.GraceTarget)

	second, err := AuthorizeSessionUse(db, session.FamilyID, now, SessionUse{
		Transfer:  true,
		GraceKind: GraceKindFile,
		GraceID:   "file-b",
	})
	require.ErrorIs(t, err, ErrSessionAbsolute)
	require.NotNil(t, second)
	assert.Nil(t, second.EndedAt)

	again, err := AuthorizeSessionUse(db, session.FamilyID, now, SessionUse{
		Transfer:  true,
		GraceKind: GraceKindFile,
		GraceID:   "file-a",
	})
	require.NoError(t, err)
	assert.Equal(t, "file-a", again.GraceTarget)
}

func TestAdminSessionEndsAtSixtyMinutes(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "admin-user", LoginKindAdmin)
	require.NoError(t, err)
	require.NoError(t, ShiftSessionFamilyClocks(db, session.FamilyID, time.Now(), 0, AdminSessionLimit+time.Minute))

	ended, err := ValidateRefreshSessionUse(db, session.RefreshToken, SessionUse{DirectLocal: true})
	require.ErrorIs(t, err, ErrSessionAbsolute)
	assert.True(t, ended.SessionEndedNow)
}

func TestAdminRefreshRefusedWhenNotLocal(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "admin-user", LoginKindAdmin)
	require.NoError(t, err)

	_, err = ValidateRefreshSessionUse(db, session.RefreshToken, SessionUse{DirectLocal: false})
	require.ErrorIs(t, err, ErrAdminSessionNotLocal)

	rotated, err := ValidateRefreshSessionUse(db, session.RefreshToken, SessionUse{DirectLocal: true})
	require.NoError(t, err)
	assert.NotEmpty(t, rotated.RefreshToken)
}

func TestApplyAbsoluteSessionLimitsEndsOldFamilies(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	session, err := CreateRefreshSession(db, "old-user", "")
	require.NoError(t, err)
	require.NoError(t, ShiftSessionFamilyClocks(db, session.FamilyID, time.Now(), 0, SessionAbsoluteLimit+time.Hour))

	require.NoError(t, ApplyAbsoluteSessionLimits(db, time.Now()))
	require.NoError(t, ApplyAbsoluteSessionLimits(db, time.Now()))

	family, err := GetSessionFamily(db, session.FamilyID)
	require.NoError(t, err)
	assert.Equal(t, SessionEndReasonAbsolute, family.EndedReason)
}
