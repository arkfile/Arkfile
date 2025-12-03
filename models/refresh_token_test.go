package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for tests
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB_RefreshToken creates an in-memory SQLite DB for refresh token tests.
// Using a different name to avoid conflicts if run in the same package scope during broader tests.
func setupTestDB_RefreshToken(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to open in-memory SQLite DB for refresh token tests")

	schema := `
	CREATE TABLE refresh_tokens (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		revoked BOOLEAN DEFAULT FALSE,
		last_used TIMESTAMP
	);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err, "Failed to create refresh_tokens table")

	return db
}

func TestCreateRefreshToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "test_username"

	// Execute CreateRefreshToken
	tokenString, err := CreateRefreshToken(db, username)

	// Assert: No error and token string is generated
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString, "Generated token string should not be empty")

	// Assert: Database state
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	var dbUsername string
	var dbExpiresAt time.Time
	err = db.QueryRow("SELECT username, expires_at FROM refresh_tokens WHERE token_hash = ?", tokenHash).Scan(&dbUsername, &dbExpiresAt)
	assert.NoError(t, err, "Token hash should exist in DB")
	assert.Equal(t, username, dbUsername, "Username in DB should match")

	// Assert: Expiry time is approximately 30 days in the future
	expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, dbExpiresAt, 5*time.Second, "Expiry time should be around 30 days")
}

func TestValidateRefreshToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "validate_username"
	validTokenString, _ := CreateRefreshToken(db, username) // Valid token
	expiredTokenString, _ := CreateRefreshToken(db, username)
	usedTokenString, _ := CreateRefreshToken(db, username)
	revokedTokenString, _ := CreateRefreshToken(db, username)

	// Modify tokens in DB for test cases
	hashExpired := sha256.Sum256([]byte(expiredTokenString))
	hashUsed := sha256.Sum256([]byte(usedTokenString))
	hashRevoked := sha256.Sum256([]byte(revokedTokenString))

	_, err := db.Exec("UPDATE refresh_tokens SET expires_at = ? WHERE token_hash = ?",
		time.Now().Add(-1*time.Hour), hex.EncodeToString(hashExpired[:]))
	require.NoError(t, err)

	_, err = db.Exec("UPDATE refresh_tokens SET last_used = ? WHERE token_hash = ?",
		time.Now(), hex.EncodeToString(hashUsed[:]))
	require.NoError(t, err)

	_, err = db.Exec("UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = ?",
		hex.EncodeToString(hashRevoked[:]))
	require.NoError(t, err)

	testCases := []struct {
		name           string
		token          string
		expectUsername string
		expectErrText  string // Substring of the expected error message
		expectUsed     bool   // Whether the token should be marked as used after validation
	}{
		{
			name:           "Valid token",
			token:          validTokenString,
			expectUsername: username,
			expectUsed:     true,
		},
		{
			name:          "Expired token",
			token:         expiredTokenString,
			expectErrText: "refresh token has expired",
			expectUsed:    false, // Should not be marked used if invalid
		},
		{
			name:           "Already used token",
			token:          usedTokenString,
			expectUsername: username, // Should succeed as tokens are reusable
			expectUsed:     true,     // Remains used
		},
		{
			name:          "Revoked token",
			token:         revokedTokenString,
			expectErrText: "refresh token not found", // Revoked tokens are treated as not found
			expectUsed:    false,                     // Should not be marked used if invalid
		},
		{
			name:          "Invalid/Non-existent token",
			token:         "non-existent-token",
			expectErrText: "refresh token not found",
			expectUsed:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute ValidateRefreshToken
			validatedUsername, err := ValidateRefreshToken(db, tc.token)

			// Assert: Error expectation
			if tc.expectErrText != "" {
				require.Error(t, err, "Expected an error")
				assert.Contains(t, err.Error(), tc.expectErrText, "Error message mismatch")
				assert.Empty(t, validatedUsername, "Username should be empty on error")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.Equal(t, tc.expectUsername, validatedUsername, "Validated username mismatch")
			}

			// Assert: Check 'last_used' status in DB
			hash := sha256.Sum256([]byte(tc.token))
			tokenHash := hex.EncodeToString(hash[:])
			var lastUsed sql.NullTime // Use NullTime to handle non-existent tokens gracefully
			dbErr := db.QueryRow("SELECT last_used FROM refresh_tokens WHERE token_hash = ?", tokenHash).Scan(&lastUsed)

			if dbErr == sql.ErrNoRows {
				assert.False(t, tc.expectUsed, "Token should not be marked used if it doesn't exist")
			} else {
				assert.NoError(t, dbErr, "DB query for last_used failed")
				assert.Equal(t, tc.expectUsed, lastUsed.Valid, "'last_used' status mismatch in DB")
			}
		})
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	username := "revoke_username"
	tokenToRevoke, _ := CreateRefreshToken(db, username)
	tokenToKeep, _ := CreateRefreshToken(db, username) // Another token for the same user

	// Execute RevokeRefreshToken
	err := RevokeRefreshToken(db, tokenToRevoke)

	// Assert: No error
	assert.NoError(t, err)

	// Assert: Check revoked status in DB for the revoked token
	hashRevoked := sha256.Sum256([]byte(tokenToRevoke))
	var isRevoked bool
	err = db.QueryRow("SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(hashRevoked[:])).Scan(&isRevoked)
	assert.NoError(t, err)
	assert.True(t, isRevoked, "Token should be marked as revoked in DB")

	// Assert: Check revoked status for the token that should NOT be revoked
	hashKeep := sha256.Sum256([]byte(tokenToKeep))
	err = db.QueryRow("SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(hashKeep[:])).Scan(&isRevoked)
	assert.NoError(t, err)
	assert.False(t, isRevoked, "Other token for the same user should not be revoked")

	// Test revoking a non-existent token
	err = RevokeRefreshToken(db, "non-existent-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token not found")
}

func TestRevokeAllUserTokens(t *testing.T) {
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	user1Username := "user1_username"
	user2Username := "user2_username"

	// Create tokens for both users
	token1User1, _ := CreateRefreshToken(db, user1Username)
	token2User1, _ := CreateRefreshToken(db, user1Username)
	token1User2, _ := CreateRefreshToken(db, user2Username)

	// Execute RevokeAllUserTokens for user1
	err := RevokeAllUserTokens(db, user1Username)

	// Assert: No error
	assert.NoError(t, err)

	// Assert: Check status for user1's tokens (should be revoked)
	hash1User1 := sha256.Sum256([]byte(token1User1))
	hash2User1 := sha256.Sum256([]byte(token2User1))
	var isRevoked1, isRevoked2 bool
	err = db.QueryRow("SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(hash1User1[:])).Scan(&isRevoked1)
	assert.NoError(t, err)
	assert.True(t, isRevoked1, "First token for user1 should be revoked")
	err = db.QueryRow("SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(hash2User1[:])).Scan(&isRevoked2)
	assert.NoError(t, err)
	assert.True(t, isRevoked2, "Second token for user1 should be revoked")

	// Assert: Check status for user2's token (should NOT be revoked)
	hash1User2 := sha256.Sum256([]byte(token1User2))
	var isRevokedUser2 bool
	err = db.QueryRow("SELECT revoked FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(hash1User2[:])).Scan(&isRevokedUser2)
	assert.NoError(t, err)
	assert.False(t, isRevokedUser2, "Token for user2 should not be revoked")
}

func TestCleanupExpiredTokens_RefreshToken(t *testing.T) { // Renamed to avoid conflict
	db := setupTestDB_RefreshToken(t)
	defer db.Close()

	// Add expired and active tokens
	expiredTokenString, _ := CreateRefreshToken(db, "cleanup_username")
	activeTokenString, _ := CreateRefreshToken(db, "cleanup_username")

	// Manually expire one token
	hashExpired := sha256.Sum256([]byte(expiredTokenString))
	_, err := db.Exec("UPDATE refresh_tokens SET expires_at = ? WHERE token_hash = ?",
		time.Now().Add(-1*time.Hour), hex.EncodeToString(hashExpired[:]))
	require.NoError(t, err)

	// Execute CleanupExpiredTokens
	// Note: Assuming CleanupExpiredTokens function exists in the models package (as per your code review)
	// If it's in auth package, adjust the call. Using models.CleanupExpiredTokens based on file name.
	err = CleanupExpiredTokens(db)
	assert.NoError(t, err)

	// Assert: Check DB state
	var countExpired, countActive int
	hashActive := sha256.Sum256([]byte(activeTokenString))

	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(hashExpired[:])).Scan(&countExpired)
	assert.NoError(t, err)
	assert.Equal(t, 0, countExpired, "Expired refresh token should be deleted")

	err = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(hashActive[:])).Scan(&countActive)
	assert.NoError(t, err)
	assert.Equal(t, 1, countActive, "Active refresh token should remain")
}
