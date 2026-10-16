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

// RefreshSession carries the stable per-login identity alongside the raw
// refresh token returned to the client.
type RefreshSession struct {
	Username         string
	RefreshToken     string
	FamilyID         string
	LoginKind        string
	SessionStartedAt time.Time
	SessionEndedNow  bool
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

// CreateRefreshSession creates a refresh token and its per-login family state.
func CreateRefreshSession(db *sql.DB, username, loginKind string) (*RefreshSession, error) {
	raw, hash, err := generateRefreshTokenRaw()
	if err != nil {
		return nil, err
	}

	familyID, err := generateFamilyID()
	if err != nil {
		return nil, err
	}

	createdAt := time.Now()
	expiresAt := createdAt.Add(30 * 24 * time.Hour)
	var storedLoginKind interface{}
	if loginKind != "" {
		storedLoginKind = loginKind
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(
		`INSERT INTO session_families
		 (family_id, username, login_kind, session_started_at, last_user_activity)
		 VALUES (?, ?, ?, ?, ?)`,
		familyID, username, storedLoginKind, createdAt, createdAt,
	); err != nil {
		return nil, err
	}

	_, err = tx.Exec(
		`INSERT INTO refresh_tokens
		 (id, username, token_hash, expires_at, created_at, revoked, last_used,
		  family_id, superseded_by_hash, family_revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hash, username, hash, expiresAt, createdAt, false, nil,
		familyID, nil, nil,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	sessionActivityCache.Lock()
	sessionActivityCache.entries[familyID] = sessionActivityEntry{
		acceptedAt:  createdAt,
		persistedAt: createdAt,
	}
	sessionActivityCache.Unlock()

	return &RefreshSession{
		Username:         username,
		RefreshToken:     raw,
		FamilyID:         familyID,
		LoginKind:        loginKind,
		SessionStartedAt: createdAt,
	}, nil
}

// ValidateRefreshSession checks token reuse, family revocation and idle state
// before rotating the refresh token. The returned session preserves the family
// identity and login kind across rotation.
func ValidateRefreshSession(db *sql.DB, tokenString string) (*RefreshSession, error) {
	hash := hashRefreshToken(tokenString)

	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	debug := debugMode == "true" || debugMode == "1"

	var (
		id                 string
		username           string
		expiresAtStr       string
		revoked            bool
		lastUsedStr        sql.NullString
		familyID           string
		supersededByHash   sql.NullString
		familyRevokedAtStr sql.NullString
	)

	err := db.QueryRow(
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
				fmt.Printf("[DEBUG] ValidateRefreshSession: token not found\n")
			} else {
				fmt.Printf("[DEBUG] ValidateRefreshSession: DB error: %v\n", err)
			}
		}
		if err == sql.ErrNoRows {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}

	// Step 2: reuse detection.
	if supersededByHash.Valid && supersededByHash.String != "" {
		// This token has already been rotated past. Revoke the entire family.
		if revokeErr := RevokeFamilyByFamilyID(db, familyID); revokeErr != nil && debug {
			fmt.Printf("[DEBUG] ValidateRefreshSession: RevokeFamilyByFamilyID error: %v\n", revokeErr)
		}
		// Write user-wide JWT revocation so outstanding full JWTs are also rejected.
		if revokeErr := RevokeAllUserJWTsByUsername(db, username, "refresh token reuse detected"); revokeErr != nil && debug {
			fmt.Printf("[DEBUG] ValidateRefreshSession: RevokeAllUserJWTs error: %v\n", revokeErr)
		}
		return &RefreshSession{Username: username, FamilyID: familyID}, ErrRefreshTokenReuse
	}

	// Step 3: family already revoked.
	if familyRevokedAtStr.Valid && familyRevokedAtStr.String != "" {
		return nil, ErrRefreshTokenNotFound
	}

	now := time.Now()
	family, familyErr := CheckSessionFamily(db, familyID, now)
	if familyErr != nil {
		session := &RefreshSession{Username: username, FamilyID: familyID}
		if family != nil {
			session.LoginKind = family.LoginKind
			session.SessionStartedAt = family.SessionStartedAt
			session.SessionEndedNow = family.EndedNow
		}
		return session, familyErr
	}
	if family.Username != username {
		return nil, fmt.Errorf("refresh token username does not match session family")
	}

	if revoked {
		return nil, ErrRefreshTokenNotFound
	}

	expiresAt, parseErr := parseDatabaseTime(expiresAtStr)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", parseErr)
	}
	if now.After(expiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	// Step 4: normal rotation.
	newRaw, newHash, err := generateRefreshTokenRaw()
	if err != nil {
		return nil, err
	}

	newExpiresAt := now.Add(14 * 24 * time.Hour)

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Claim this token for one rotation before inserting its successor.
	result, err := tx.Exec(
		`UPDATE refresh_tokens
		 SET superseded_by_hash = ?, last_used = ?
		 WHERE id = ?
		   AND superseded_by_hash IS NULL
		   AND revoked = false
		   AND family_revoked_at IS NULL
		   AND EXISTS (
		       SELECT 1 FROM session_families
		        WHERE session_families.family_id = refresh_tokens.family_id
		          AND session_families.ended_at IS NULL
		   )`,
		newHash, now, id,
	)
	if err != nil {
		return nil, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		_ = tx.Rollback()

		var concurrentSuperseded, concurrentFamilyRevoked sql.NullString
		var concurrentRevoked bool
		if err := db.QueryRow(
			`SELECT revoked, superseded_by_hash, family_revoked_at
			   FROM refresh_tokens
			  WHERE id = ?`,
			id,
		).Scan(&concurrentRevoked, &concurrentSuperseded, &concurrentFamilyRevoked); err != nil {
			if err == sql.ErrNoRows {
				return nil, ErrRefreshTokenNotFound
			}
			return nil, err
		}

		if endedFamily, endedErr := CheckSessionFamily(db, familyID, time.Now()); SessionErrorCode(endedErr) != "" {
			return &RefreshSession{
				Username:         username,
				FamilyID:         familyID,
				LoginKind:        endedFamily.LoginKind,
				SessionStartedAt: endedFamily.SessionStartedAt,
				SessionEndedNow:  endedFamily.EndedNow,
			}, endedErr
		}

		if concurrentSuperseded.Valid && concurrentSuperseded.String != "" {
			if revokeErr := RevokeFamilyByFamilyID(db, familyID); revokeErr != nil && debug {
				fmt.Printf("[DEBUG] ValidateRefreshSession: concurrent RevokeFamilyByFamilyID error: %v\n", revokeErr)
			}
			if revokeErr := RevokeAllUserJWTsByUsername(db, username, "refresh token reuse detected"); revokeErr != nil && debug {
				fmt.Printf("[DEBUG] ValidateRefreshSession: concurrent RevokeAllUserJWTs error: %v\n", revokeErr)
			}
			return &RefreshSession{Username: username, FamilyID: familyID}, ErrRefreshTokenReuse
		}
		if concurrentRevoked || (concurrentFamilyRevoked.Valid && concurrentFamilyRevoked.String != "") {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, ErrRefreshTokenNotFound
	}

	// Insert the new token in the same family.
	_, err = tx.Exec(
		`INSERT INTO refresh_tokens
		 (id, username, token_hash, expires_at, created_at, revoked, last_used,
		  family_id, superseded_by_hash, family_revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newHash, username, newHash, newExpiresAt, now, false, nil,
		familyID, nil, nil,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &RefreshSession{
		Username:         username,
		RefreshToken:     newRaw,
		FamilyID:         familyID,
		LoginKind:        family.LoginKind,
		SessionStartedAt: family.SessionStartedAt,
	}, nil
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
