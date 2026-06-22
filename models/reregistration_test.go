package models

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB_Reregistration creates an in-memory SQLite DB with just enough of
// the users table to exercise the re-registration flag helpers.
func setupTestDB_Reregistration(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		requires_reregistration BOOLEAN NOT NULL DEFAULT false,
		deleted_at TIMESTAMP DEFAULT NULL
	);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	for _, u := range []string{"alice12345", "bob1234567", "carol12345"} {
		_, err = db.Exec(`INSERT INTO users (username) VALUES (?)`, u)
		require.NoError(t, err)
	}
	// A soft-deleted user must be ignored by every helper.
	_, err = db.Exec(`INSERT INTO users (username, deleted_at) VALUES ('deleted999', CURRENT_TIMESTAMP)`)
	require.NoError(t, err)

	return db
}

func TestUserRequiresReregistration_DefaultsFalse(t *testing.T) {
	db := setupTestDB_Reregistration(t)
	defer db.Close()

	flag, err := UserRequiresReregistration(db, "alice12345")
	require.NoError(t, err)
	assert.False(t, flag)
}

func TestUserRequiresReregistration_MissingUserIsFalse(t *testing.T) {
	db := setupTestDB_Reregistration(t)
	defer db.Close()

	flag, err := UserRequiresReregistration(db, "nonexistent")
	require.NoError(t, err)
	assert.False(t, flag)

	// Soft-deleted users are treated as absent.
	flag, err = UserRequiresReregistration(db, "deleted999")
	require.NoError(t, err)
	assert.False(t, flag)
}

func TestSetUserRequiresReregistration_RoundTrip(t *testing.T) {
	db := setupTestDB_Reregistration(t)
	defer db.Close()

	require.NoError(t, SetUserRequiresReregistration(db, "alice12345", true))
	flag, err := UserRequiresReregistration(db, "alice12345")
	require.NoError(t, err)
	assert.True(t, flag)

	// Only the targeted user is affected.
	flag, err = UserRequiresReregistration(db, "bob1234567")
	require.NoError(t, err)
	assert.False(t, flag)

	require.NoError(t, SetUserRequiresReregistration(db, "alice12345", false))
	flag, err = UserRequiresReregistration(db, "alice12345")
	require.NoError(t, err)
	assert.False(t, flag)
}

func TestSetUserRequiresReregistration_UnknownUserErrors(t *testing.T) {
	db := setupTestDB_Reregistration(t)
	defer db.Close()

	err := SetUserRequiresReregistration(db, "nonexistent", true)
	assert.Error(t, err)

	// Soft-deleted users cannot be flagged.
	err = SetUserRequiresReregistration(db, "deleted999", true)
	assert.Error(t, err)
}

func TestFlagAllUsersForReregistration_OnlyActiveUsers(t *testing.T) {
	db := setupTestDB_Reregistration(t)
	defer db.Close()

	count, err := FlagAllUsersForReregistration(db)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count, "only the three active users should be flagged")

	for _, u := range []string{"alice12345", "bob1234567", "carol12345"} {
		flag, err := UserRequiresReregistration(db, u)
		require.NoError(t, err)
		assert.True(t, flag, "user %s should be flagged", u)
	}

	// The soft-deleted user is left untouched.
	var deletedFlag bool
	require.NoError(t, db.QueryRow(`SELECT requires_reregistration FROM users WHERE username = 'deleted999'`).Scan(&deletedFlag))
	assert.False(t, deletedFlag)
}
