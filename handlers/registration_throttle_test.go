package handlers

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/database"
)

func TestRegistrationCooldownFor(t *testing.T) {
	cases := []struct {
		n    int
		want time.Duration
	}{
		{1, 0},
		{7, 0},
		{8, 2 * time.Hour},
		{9, 4 * time.Hour},
		{10, 8 * time.Hour},
		{11, 16 * time.Hour},
		{12, 24 * time.Hour}, // 2h<<4 = 32h, capped at 24h
		{13, 24 * time.Hour},
		{100, 24 * time.Hour},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, registrationCooldownFor(c.n), "attempt %d", c.n)
	}
}

func newRegistrationThrottleDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE registration_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entity_id TEXT NOT NULL,
		username TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	return db
}

func TestCheckRegistrationThrottle_AllowedUnderFreeAllowance(t *testing.T) {
	db := newRegistrationThrottleDB(t)
	defer db.Close()
	origDB := database.DB
	database.DB = db
	defer func() { database.DB = origDB }()

	// Fresh entity is always allowed.
	allowed, _, err := CheckRegistrationThrottle("fresh")
	require.NoError(t, err)
	assert.True(t, allowed)

	utc := func(ago time.Duration) string {
		return time.Now().UTC().Add(-ago).Format(registrationAttemptTimeFormat)
	}
	oneHourAgo := utc(time.Hour)

	// 6 attempts within the window: still under the 7-free allowance.
	for i := 0; i < 6; i++ {
		_, err := db.Exec(`INSERT INTO registration_attempts (entity_id, username, created_at) VALUES (?, 'u', ?)`, "six", oneHourAgo)
		require.NoError(t, err)
	}
	allowed, _, err = CheckRegistrationThrottle("six")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestCheckRegistrationThrottle_BlocksAndEscalates(t *testing.T) {
	db := newRegistrationThrottleDB(t)
	defer db.Close()
	origDB := database.DB
	database.DB = db
	defer func() { database.DB = origDB }()

	utc := func(ago time.Duration) string {
		return time.Now().UTC().Add(-ago).Format(registrationAttemptTimeFormat)
	}

	insertN := func(entityID string, n int, ago time.Duration) {
		ts := utc(ago)
		for i := 0; i < n; i++ {
			_, err := db.Exec(`INSERT INTO registration_attempts (entity_id, username, created_at) VALUES (?, 'u', ?)`, entityID, ts)
			require.NoError(t, err)
		}
	}

	// 7 attempts with the trigger ~1h ago: the 8th attempt needs a 2h cooldown,
	// only 1h has elapsed, so it is blocked for ~1h.
	insertN("blocked", 7, time.Hour)
	allowed, retry, err := CheckRegistrationThrottle("blocked")
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.WithinDuration(t, time.Now().Add(time.Hour), time.Now().Add(retry), 30*time.Second)

	// Same count but the trigger is 3h ago: 2h cooldown has elapsed -> allowed.
	insertN("cleared", 7, 3*time.Hour)
	allowed, _, err = CheckRegistrationThrottle("cleared")
	require.NoError(t, err)
	assert.True(t, allowed)

	// 8 attempts (the 9th is being attempted) require a 4h cooldown from the
	// 7th attempt; only 3h have elapsed -> blocked for ~1h (escalation check).
	insertN("escalated", 8, 3*time.Hour)
	allowed, retry, err = CheckRegistrationThrottle("escalated")
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.WithinDuration(t, time.Now().Add(time.Hour), time.Now().Add(retry), 30*time.Second)
}

func TestRecordRegistrationAttempt(t *testing.T) {
	db := newRegistrationThrottleDB(t)
	defer db.Close()
	origDB := database.DB
	database.DB = db
	defer func() { database.DB = origDB }()

	require.NoError(t, RecordRegistrationAttempt("eid", "alice"))

	var entityID, username string
	err := db.QueryRow(`SELECT entity_id, username FROM registration_attempts WHERE entity_id = ?`, "eid").Scan(&entityID, &username)
	require.NoError(t, err)
	assert.Equal(t, "eid", entityID)
	assert.Equal(t, "alice", username)
}
