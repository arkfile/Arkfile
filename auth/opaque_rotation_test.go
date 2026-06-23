package auth

import (
	"database/sql"
	"testing"

	"github.com/84adam/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openOpaqueRotationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE users (
			username TEXT PRIMARY KEY,
			deleted_at TIMESTAMP,
			requires_reregistration BOOLEAN NOT NULL DEFAULT false
		);
		CREATE TABLE opaque_user_data (
			username TEXT PRIMARY KEY,
			opaque_user_record BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func insertOpaqueRotationUser(t *testing.T, db *sql.DB, username string, flagged bool) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO users (username, requires_reregistration) VALUES (?, ?)`,
		username, flagged,
	)
	require.NoError(t, err)
}

func TestReplaceOpaqueServerKeys_ChangesMaterialAndReloads(t *testing.T) {
	ResetOpaqueServerKeysForTest()
	require.NoError(t, SetupServerKeys(nil))

	privBefore, err := GetServerPrivateKey()
	require.NoError(t, err)

	result, err := ReplaceOpaqueServerKeys()
	require.NoError(t, err)
	assert.NotEqual(t, result.PreviousPrivateKeyFP, result.PrivateKeyFingerprint)
	assert.NotEqual(t, result.PreviousOPRFSeedFP, result.OPRFSeedFingerprint)

	privAfter, err := GetServerPrivateKey()
	require.NoError(t, err)
	assert.NotEqual(t, privBefore, privAfter)
}

func TestVerifyOpaqueKeyRotationPreconditions_RejectsUnflaggedUsers(t *testing.T) {
	db := openOpaqueRotationTestDB(t)
	insertOpaqueRotationUser(t, db, "alice", false)

	err := VerifyOpaqueKeyRotationPreconditions(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not flagged")
}

func TestVerifyOpaqueKeyRotationPreconditions_RejectsRemainingRecords(t *testing.T) {
	db := openOpaqueRotationTestDB(t)
	insertOpaqueRotationUser(t, db, "alice", true)
	_, err := db.Exec(`INSERT INTO opaque_user_data (username, opaque_user_record) VALUES ('alice', X'0102')`)
	require.NoError(t, err)

	err = VerifyOpaqueKeyRotationPreconditions(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opaque_user_data")
}

func TestReplaceOpaqueServerKeysGuarded_RequiresPreconditions(t *testing.T) {
	ResetOpaqueServerKeysForTest()
	require.NoError(t, SetupServerKeys(nil))

	db := openOpaqueRotationTestDB(t)
	insertOpaqueRotationUser(t, db, "alice", false)

	_, err := ReplaceOpaqueServerKeysGuarded(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not flagged")
}

func TestReplaceOpaqueServerKeysGuarded_SucceedsWhenReady(t *testing.T) {
	ResetOpaqueServerKeysForTest()
	require.NoError(t, SetupServerKeys(nil))

	db := openOpaqueRotationTestDB(t)
	insertOpaqueRotationUser(t, db, "alice", true)

	result, err := ReplaceOpaqueServerKeysGuarded(db)
	require.NoError(t, err)
	assert.NotEmpty(t, result.PrivateKeyFingerprint)
}

func TestRotateOpaqueServerKeysDeployment_FlagsUsersAndReplacesKeys(t *testing.T) {
	ResetOpaqueServerKeysForTest()
	require.NoError(t, SetupServerKeys(nil))

	db := openOpaqueRotationTestDB(t)
	insertOpaqueRotationUser(t, db, "alice", false)
	insertOpaqueRotationUser(t, db, "bob", false)
	_, err := db.Exec(`INSERT INTO opaque_user_data (username, opaque_user_record) VALUES ('alice', X'0102')`)
	require.NoError(t, err)

	km, err := crypto.GetKeyManager()
	require.NoError(t, err)
	oldPriv, err := km.GetKey(OpaqueServerPrivateKeyID, OpaqueKeyType)
	require.NoError(t, err)

	result, err := RotateOpaqueServerKeysDeployment(db)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.UsersFlagged)
	assert.Len(t, result.Usernames, 2)

	var remaining int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM opaque_user_data`).Scan(&remaining))
	assert.Equal(t, 0, remaining)

	var unflagged int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE requires_reregistration = false`).Scan(&unflagged))
	assert.Equal(t, 0, unflagged)

	newPriv, err := km.GetKey(OpaqueServerPrivateKeyID, OpaqueKeyType)
	require.NoError(t, err)
	assert.NotEqual(t, oldPriv, newPriv)

	privInMemory, err := GetServerPrivateKey()
	require.NoError(t, err)
	assert.Equal(t, newPriv, privInMemory)
}
