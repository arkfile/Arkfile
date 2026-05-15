package models

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Pre-defined errors for token validation
var (
	ErrRefreshTokenExpired  = errors.New("refresh token has expired")
	ErrUserNotFound         = errors.New("user not found for token")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenReuse    = errors.New("refresh token reuse detected; all sessions revoked")
)

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	ID               string
	Username         string
	TokenHash        string
	ExpiresAt        time.Time
	CreatedAt        time.Time
	Revoked          bool
	LastUsed         *time.Time
	FamilyID         string
	SupersededByHash *string
	FamilyRevokedAt  *time.Time
}

// generateRefreshTokenRaw generates a cryptographically secure 256-bit refresh token.
// Returns the raw base64url-encoded token (44 chars) and its SHA-256 hex hash.
func generateRefreshTokenRaw() (raw string, hash string, err error) {
	b := make([]byte, 32) // 32 bytes = 256 bits
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token bytes: %w", err)
	}
	raw = base64.URLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(h[:])
	return raw, hash, nil
}

// generateFamilyID generates a random 16-byte hex string for a new refresh-token family.
func generateFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate family ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashRefreshToken computes SHA-256(raw) and returns hex. Used when validating
// an incoming token string without needing to re-generate.
func hashRefreshToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// CreateRefreshToken generates a new 256-bit refresh token for a user and persists it.
// A fresh family_id is generated (new login event). Returns the raw token string.
func CreateRefreshToken(db *sql.DB, username string) (string, error) {
	raw, hash, err := generateRefreshTokenRaw()
	if err != nil {
		return "", err
	}

	familyID, err := generateFamilyID()
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	createdAt := time.Now()

	_, err = db.Exec(
		`INSERT INTO refresh_tokens
		 (id, username, token_hash, expires_at, created_at, revoked, last_used,
		  family_id, superseded_by_hash, family_revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hash, username, hash, expiresAt, createdAt, false, nil,
		familyID, nil, nil,
	)
	if err != nil {
		return "", err
	}

	return raw, nil
}

// ValidateRefreshToken checks if a refresh token is valid and returns the username.
// It implements four-step family-revoke logic (A-10):
//  1. Unknown token → 401.
//  2. superseded_by_hash IS NOT NULL → reuse detected → revoke family + user JWTs → 401.
//  3. family_revoked_at IS NOT NULL → family already revoked → 401.
//  4. Normal rotation: insert new token (same family_id), set superseded_by_hash on old row.
//
// Returns (username, newRawToken, error). newRawToken is non-empty on successful rotation.
func ValidateRefreshToken(db *sql.DB, tokenString string) (username string, newRawToken string, err error) {
	hash := hashRefreshToken(tokenString)

	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	debug := debugMode == "true" || debugMode == "1"

	var (
		id                 string
		expiresAtStr       string
		revoked            bool
		lastUsedStr        sql.NullString
		familyID           string
		supersededByHash   sql.NullString
		familyRevokedAtStr sql.NullString
	)

	err = db.QueryRow(
		`SELECT id, username, expires_at, revoked, last_used,
		        family_id, superseded_by_hash, family_revoked_at
		 FROM refresh_tokens
		 WHERE token_hash = ?`,
		hash,
	).Scan(&id, &username, &expiresAtStr, &revoked, &lastUsedStr,
		&familyID, &supersededByHash, &familyRevokedAtStr)

	if err != nil {
		if debug {
			if err == sql.ErrNoRows {
				fmt.Printf("[DEBUG] ValidateRefreshToken: token not found\n")
			} else {
				fmt.Printf("[DEBUG] ValidateRefreshToken: DB error: %v\n", err)
			}
		}
		if err == sql.ErrNoRows {
			return "", "", ErrRefreshTokenNotFound
		}
		return "", "", err
	}

	// Parse expiry
	expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr)
	if parseErr != nil {
		if expiresAt, parseErr = time.Parse("2006-01-02 15:04:05", expiresAtStr); parseErr != nil {
			return "", "", fmt.Errorf("failed to parse expires_at: %w", parseErr)
		}
	}

	if time.Now().After(expiresAt) {
		return "", "", ErrRefreshTokenExpired
	}

	if revoked {
		return "", "", ErrRefreshTokenNotFound
	}

	// Step 2: reuse detection.
	if supersededByHash.Valid && supersededByHash.String != "" {
		// This token has already been rotated past. Revoke the entire family.
		if revokeErr := RevokeFamilyByFamilyID(db, familyID); revokeErr != nil && debug {
			fmt.Printf("[DEBUG] ValidateRefreshToken: RevokeFamilyByFamilyID error: %v\n", revokeErr)
		}
		// Write user-wide JWT revocation so outstanding full JWTs are also rejected.
		if revokeErr := RevokeAllUserJWTsByUsername(db, username, "refresh token reuse detected"); revokeErr != nil && debug {
			fmt.Printf("[DEBUG] ValidateRefreshToken: RevokeAllUserJWTs error: %v\n", revokeErr)
		}
		return "", "", ErrRefreshTokenReuse
	}

	// Step 3: family already revoked.
	if familyRevokedAtStr.Valid && familyRevokedAtStr.String != "" {
		return "", "", ErrRefreshTokenNotFound
	}

	// Step 4: normal rotation.
	newRaw, newHash, err := generateRefreshTokenRaw()
	if err != nil {
		return "", "", err
	}

	newExpiresAt := time.Now().Add(14 * 24 * time.Hour)
	now := time.Now()

	// Insert the new token in the same family.
	_, err = db.Exec(
		`INSERT INTO refresh_tokens
		 (id, username, token_hash, expires_at, created_at, revoked, last_used,
		  family_id, superseded_by_hash, family_revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newHash, username, newHash, newExpiresAt, now, false, nil,
		familyID, nil, nil,
	)
	if err != nil {
		return "", "", err
	}

	// Mark the consumed row as superseded.
	_, err = db.Exec(
		`UPDATE refresh_tokens
		 SET superseded_by_hash = ?, last_used = ?
		 WHERE id = ?`,
		newHash, now, id,
	)
	if err != nil {
		return "", "", err
	}

	return username, newRaw, nil
}

// RevokeRefreshToken marks a specific token as revoked by its raw value.
func RevokeRefreshToken(db *sql.DB, tokenString string) error {
	hash := hashRefreshToken(tokenString)

	result, err := db.Exec(
		"UPDATE refresh_tokens SET revoked = true WHERE token_hash = ?",
		hash,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRefreshTokenNotFound
	}

	return nil
}

// RevokeFamilyByFamilyID sets family_revoked_at on every row sharing family_id.
// Used when reuse is detected so all tokens in the chain are simultaneously invalidated.
func RevokeFamilyByFamilyID(db *sql.DB, familyID string) error {
	_, err := db.Exec(
		`UPDATE refresh_tokens SET family_revoked_at = ? WHERE family_id = ?`,
		time.Now(), familyID,
	)
	return err
}

// RevokeAllUserTokens revokes all refresh tokens for a user (sets revoked=true).
func RevokeAllUserTokens(db *sql.DB, username string) error {
	_, err := db.Exec(
		"UPDATE refresh_tokens SET revoked = true WHERE username = ?",
		username,
	)
	return err
}

// RevokeAllUserJWTsByUsername writes (or updates) a user_jwt_revocations row so that
// TokenRevocationMiddleware rejects any full JWT issued before now. This is called
// from the refresh handler on reuse detection, and from admin force-logout.
func RevokeAllUserJWTsByUsername(db *sql.DB, username, reason string) error {
	_, err := db.Exec(
		`INSERT INTO user_jwt_revocations (username, revoked_at, reason)
		 VALUES (?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET revoked_at = excluded.revoked_at, reason = excluded.reason`,
		username, time.Now(), reason,
	)
	return err
}

// GetUserJWTRevocationTime returns the revoked_at timestamp for a user, if any.
// Returns (zero time, nil) when no revocation row exists.
func GetUserJWTRevocationTime(db *sql.DB, username string) (time.Time, error) {
	var revokedAtStr string
	err := db.QueryRow(
		`SELECT revoked_at FROM user_jwt_revocations WHERE username = ?`, username,
	).Scan(&revokedAtStr)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, parseErr := time.Parse(layout, revokedAtStr); parseErr == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("failed to parse user_jwt_revocations.revoked_at: %q", revokedAtStr)
}

// CleanupExpiredTokens removes expired tokens from the database.
func CleanupExpiredTokens(db *sql.DB) error {
	_, err := db.Exec(
		"DELETE FROM refresh_tokens WHERE expires_at < ?",
		time.Now(),
	)
	return err
}
