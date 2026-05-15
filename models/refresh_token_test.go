package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB_RefreshToken creates an in-memory SQLite DB for refresh token tests.
func setupTestDB_RefreshToken(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	schema := `
	CREATE TABLE refresh_tokens (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		revoked BOOLEAN DEFAULT FALSE,
		last_used TIMESTAMP,
		family_id TEXT NOT NULL,
		superseded_by_hash TEXT,
		family_revoked_at TIMESTAMP
	);
	CREATE TABLE user_jwt_revocations (
		username TEXT PRIMARY KEY,
		revoked_at TIMESTAMP NOT NULL,
		reason TEXT
	);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db
}

// hashStr is a local convenience that matches how the model hashes tokens.
func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestCreateRefreshToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "test_username"
	raw, err := CreateRefreshToken(db, username)

	require.NoError(t, err)
	assert.NotEmpty(t, raw, "raw token should not be empty")
	// Token must be 44 chars: base64url of 32 random bytes.
	assert.Equal(t, 44, len(raw), "expected 44-char base64url token")

	// Verify row was inserted with the expected hash.
	var dbUsername string
	var familyID string
	var expiresAtStr string
	err = db.QueryRow(
		"SELECT username, family_id, expires_at FROM refresh_tokens WHERE token_hash = ?",
		hashStr(raw),
	).Scan(&dbUsername, &familyID, &expiresAtStr)
	require.NoError(t, err)
	assert.Equal(t, username, dbUsername)
	assert.NotEmpty(t, familyID, "family_id must be populated")

	// Expiry must be around 30 days from now.
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if expiresAt, parseErr := time.Parse(layout, expiresAtStr); parseErr == nil {
			expected := time.Now().Add(30 * 24 * time.Hour)
			assert.WithinDuration(t, expected, expiresAt, 10*time.Second)
			break
		}
	}
}

func TestValidateRefreshToken_ValidRotation(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "rotate_user"
	raw0, err := CreateRefreshToken(db, username)
	require.NoError(t, err)

	// Validate (rotates): returns username + new raw token.
	gotUser, newRaw, err := ValidateRefreshToken(db, raw0)
	require.NoError(t, err)
	assert.Equal(t, username, gotUser)
	assert.NotEmpty(t, newRaw)
	assert.NotEqual(t, raw0, newRaw, "rotated token must differ from old")

	// Old token must now have superseded_by_hash set.
	var superseded sql.NullString
	err = db.QueryRow(
		"SELECT superseded_by_hash FROM refresh_tokens WHERE token_hash = ?",
		hashStr(raw0),
	).Scan(&superseded)
	require.NoError(t, err)
	assert.True(t, superseded.Valid && superseded.String != "", "old row must have superseded_by_hash")

	// New token row must exist with same family_id, superseded_by_hash NULL.
	var oldFamilyID, newFamilyID string
	var newSuperseded sql.NullString
	require.NoError(t, db.QueryRow(
		"SELECT family_id FROM refresh_tokens WHERE token_hash = ?", hashStr(raw0),
	).Scan(&oldFamilyID))
	require.NoError(t, db.QueryRow(
		"SELECT family_id, superseded_by_hash FROM refresh_tokens WHERE token_hash = ?", hashStr(newRaw),
	).Scan(&newFamilyID, &newSuperseded))

	assert.Equal(t, oldFamilyID, newFamilyID, "both tokens must share family_id")
	assert.False(t, newSuperseded.Valid, "new token must have NULL superseded_by_hash")
}

func TestValidateRefreshToken_ExpiredToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	raw, err := CreateRefreshToken(db, "expired_user")
	require.NoError(t, err)

	// Force-expire the token.
	_, err = db.Exec(
		"UPDATE refresh_tokens SET expires_at = ? WHERE token_hash = ?",
		time.Now().Add(-1*time.Hour), hashStr(raw),
	)
	require.NoError(t, err)

	_, _, err = ValidateRefreshToken(db, raw)
	assert.ErrorIs(t, err, ErrRefreshTokenExpired)
}

func TestValidateRefreshToken_RevokedToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	raw, err := CreateRefreshToken(db, "revoked_user")
	require.NoError(t, err)

	require.NoError(t, RevokeRefreshToken(db, raw))

	_, _, err = ValidateRefreshToken(db, raw)
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

func TestValidateRefreshToken_NonExistentToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	_, _, err := ValidateRefreshToken(db, "non-existent-token")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

// TestValidateRefreshToken_ReuseDetection verifies the family-revoke path (A-10).
// Presenting a superseded token must: revoke all family rows, write a
// user_jwt_revocations row, and return ErrRefreshTokenReuse.
func TestValidateRefreshToken_ReuseDetection(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "reuse_user"
	raw0, err := CreateRefreshToken(db, username)
	require.NoError(t, err)

	// First use: rotate raw0 → raw1.
	_, raw1, err := ValidateRefreshToken(db, raw0)
	require.NoError(t, err)
	assert.NotEmpty(t, raw1)

	// Second use of the same raw0 (reuse): must be rejected.
	_, _, err = ValidateRefreshToken(db, raw0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRefreshTokenReuse)

	// All rows in the family must have family_revoked_at set.
	var count int
	err = db.QueryRow(
		"SELECT COUNT(*) FROM refresh_tokens WHERE family_revoked_at IS NULL AND username = ?",
		username,
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "all family rows must be revoked after reuse")

	// user_jwt_revocations row must exist.
	var revokedAt string
	err = db.QueryRow(
		"SELECT revoked_at FROM user_jwt_revocations WHERE username = ?", username,
	).Scan(&revokedAt)
	require.NoError(t, err)
	assert.NotEmpty(t, revokedAt, "user_jwt_revocations row must be written on reuse")
}

// TestValidateRefreshToken_FamilyRevokedRow verifies that a token whose
// family was already revoked (by a prior reuse) is immediately rejected.
func TestValidateRefreshToken_FamilyRevokedRow(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "family_revoked_user"
	raw0, err := CreateRefreshToken(db, username)
	require.NoError(t, err)

	// Rotate once to get raw1.
	_, raw1, err := ValidateRefreshToken(db, raw0)
	require.NoError(t, err)

	// Trigger reuse on raw0 to revoke the family.
	_, _, err = ValidateRefreshToken(db, raw0)
	require.ErrorIs(t, err, ErrRefreshTokenReuse)

	// Now try to use raw1 (part of the same revoked family).
	_, _, err = ValidateRefreshToken(db, raw1)
	// raw1 has superseded_by_hash=NULL but family_revoked_at IS NOT NULL → rejected.
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrRefreshTokenReuse, "should be ErrRefreshTokenNotFound not reuse")
}

func TestRevokeRefreshToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "revoke_username"
	tokenToRevoke, err := CreateRefreshToken(db, username)
	require.NoError(t, err)
	tokenToKeep, err := CreateRefreshToken(db, username)
	require.NoError(t, err)

	require.NoError(t, RevokeRefreshToken(db, tokenToRevoke))

	var isRevoked bool
	require.NoError(t, db.QueryRow(
		"SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hashStr(tokenToRevoke),
	).Scan(&isRevoked))
	assert.True(t, isRevoked)

	require.NoError(t, db.QueryRow(
		"SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hashStr(tokenToKeep),
	).Scan(&isRevoked))
	assert.False(t, isRevoked)

	// Revoking a non-existent token returns ErrRefreshTokenNotFound.
	err = RevokeRefreshToken(db, "non-existent-token")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

func TestRevokeAllUserTokens(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	t1, err := CreateRefreshToken(db, "user1")
	require.NoError(t, err)
	t2, err := CreateRefreshToken(db, "user1")
	require.NoError(t, err)
	t3, err := CreateRefreshToken(db, "user2")
	require.NoError(t, err)

	require.NoError(t, RevokeAllUserTokens(db, "user1"))

	for _, raw := range []string{t1, t2} {
		var rev bool
		require.NoError(t, db.QueryRow(
			"SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hashStr(raw),
		).Scan(&rev))
		assert.True(t, rev, "user1 token should be revoked")
	}

	var rev bool
	require.NoError(t, db.QueryRow(
		"SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hashStr(t3),
	).Scan(&rev))
	assert.False(t, rev, "user2 token should not be revoked")
}

func TestRevokeFamilyByFamilyID(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	raw, err := CreateRefreshToken(db, "family_user")
	require.NoError(t, err)

	var familyID string
	require.NoError(t, db.QueryRow(
		"SELECT family_id FROM refresh_tokens WHERE token_hash = ?", hashStr(raw),
	).Scan(&familyID))

	require.NoError(t, RevokeFamilyByFamilyID(db, familyID))

	var familyRevokedAt sql.NullString
	require.NoError(t, db.QueryRow(
		"SELECT family_revoked_at FROM refresh_tokens WHERE token_hash = ?", hashStr(raw),
	).Scan(&familyRevokedAt))
	assert.True(t, familyRevokedAt.Valid, "family_revoked_at must be set")
}

func TestRevokeAllUserJWTsByUsername(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "jwt_revoke_user"
	require.NoError(t, RevokeAllUserJWTsByUsername(db, username, "test reason"))

	revokedAt, err := GetUserJWTRevocationTime(db, username)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), revokedAt, 5*time.Second)

	// Second call updates the row (upsert).
	time.Sleep(2 * time.Millisecond)
	require.NoError(t, RevokeAllUserJWTsByUsername(db, username, "updated"))
	revokedAt2, err := GetUserJWTRevocationTime(db, username)
	require.NoError(t, err)
	assert.True(t, !revokedAt2.Before(revokedAt), "second revocation time must be >= first")
}

func TestGetUserJWTRevocationTime_NoRow(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	zeroTime, err := GetUserJWTRevocationTime(db, "never_revoked")
	require.NoError(t, err)
	assert.True(t, zeroTime.IsZero(), "should return zero time when no row exists")
}

func TestRefreshTokenEntropy(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	raw, err := CreateRefreshToken(db, "entropy_user")
	require.NoError(t, err)

	// 32 bytes base64url-encoded = exactly 44 characters (no padding stripped).
	assert.Equal(t, 44, len(raw), "token must be 44-char base64url (256 bits)")

	// Generate a second token; they must not be equal.
	raw2, err := CreateRefreshToken(db, "entropy_user")
	require.NoError(t, err)
	assert.NotEqual(t, raw, raw2, "two tokens must not collide")
}

func TestCleanupExpiredTokens_RefreshToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	expiredRaw, err := CreateRefreshToken(db, "cleanup_username")
	require.NoError(t, err)
	activeRaw, err := CreateRefreshToken(db, "cleanup_username")
	require.NoError(t, err)

	_, err = db.Exec(
		"UPDATE refresh_tokens SET expires_at = ? WHERE token_hash = ?",
		time.Now().Add(-1*time.Hour), hashStr(expiredRaw),
	)
	require.NoError(t, err)

	require.NoError(t, CleanupExpiredTokens(db))

	var countExpired, countActive int
	require.NoError(t, db.QueryRow(
		"SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ?", hashStr(expiredRaw),
	).Scan(&countExpired))
	assert.Equal(t, 0, countExpired)

	require.NoError(t, db.QueryRow(
		"SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ?", hashStr(activeRaw),
	).Scan(&countActive))
	assert.Equal(t, 1, countActive)
}
