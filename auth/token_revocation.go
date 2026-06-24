package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/arkfile/Arkfile/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// In-memory cache for faster per-JTI revocation checks
var (
	revokedTokensCache = make(map[string]bool)
	cacheMutex         = &sync.RWMutex{}
	cacheInitialized   = false
)

// userRevocationCache caches the latest user-wide JWT revocation timestamp so
// TokenRevocationMiddleware does not hit the DB on every single request.
// Entries expire after userRevocationCacheTTL; invalidated on each revocation write.
const userRevocationCacheTTL = 30 * time.Second

type userRevocationEntry struct {
	revokedAt time.Time // zero value = no revocation
	cachedAt  time.Time
}

var (
	userRevocationCache      = make(map[string]userRevocationEntry)
	userRevocationCacheMutex sync.RWMutex
)

// InvalidateUserRevocationCache removes a user's cached entry so the next
// request re-reads from the DB. Call after writing user_jwt_revocations.
func InvalidateUserRevocationCache(username string) {
	userRevocationCacheMutex.Lock()
	delete(userRevocationCache, username)
	userRevocationCacheMutex.Unlock()
}

// getUserRevocationTimeCached returns the user's JWT revocation timestamp,
// using the in-process cache to avoid a DB round-trip on every request.
func getUserRevocationTimeCached(db *sql.DB, username string) (time.Time, error) {
	now := time.Now()

	userRevocationCacheMutex.RLock()
	entry, ok := userRevocationCache[username]
	userRevocationCacheMutex.RUnlock()

	if ok && now.Sub(entry.cachedAt) < userRevocationCacheTTL {
		return entry.revokedAt, nil
	}

	// Cache miss or stale: read from DB.
	revokedAt, err := models.GetUserJWTRevocationTime(db, username)
	if err != nil {
		return time.Time{}, err
	}

	userRevocationCacheMutex.Lock()
	userRevocationCache[username] = userRevocationEntry{revokedAt: revokedAt, cachedAt: now}
	userRevocationCacheMutex.Unlock()

	return revokedAt, nil
}

// parseEitherTierToken parses a token string, accepting either the full-tier
// or the temp-tier signing key. Used by RevokeToken so logout works for both
// post-OPAQUE temp tokens and post-TOTP full tokens. Audience is NOT enforced
// here -- revocation should accept any otherwise-valid Arkfile JWT.
func parseEitherTierToken(tokenString string) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))

	// Try full-tier first (the common case), accepting any version in the
	// verification set so logout works across a key rotation overlap.
	token, err := parseEdDSAAnyKey(parser, tokenString, GetJWTFullVerificationKeys())
	if err == nil && token.Valid {
		return token, nil
	}

	// Fall back to temp-tier.
	token2, err2 := parseEdDSAAnyKey(parser, tokenString, GetJWTTempVerificationKeys())
	if err2 == nil && token2.Valid {
		return token2, nil
	}

	// Both failed -- return the original full-tier error for diagnostic clarity
	return nil, err
}

// RevokeToken adds a token to the revocation list. Accepts either temp-tier
// or full-tier tokens so that /api/logout and /api/revoke-token work for any
// session state.
func RevokeToken(db *sql.DB, tokenString, reason string) error {
	token, err := parseEitherTierToken(tokenString)
	if err != nil {
		return err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return errors.New("invalid token claims")
	}

	// Get token ID and expiry
	tokenID := claims.ID
	if tokenID == "" {
		return errors.New("token has no ID (jti) claim")
	}

	expiryTime := claims.ExpiresAt.Time

	// Add to database
	_, err = db.Exec(
		`INSERT INTO revoked_tokens (token_id, username, expires_at, reason) 
		 VALUES (?, ?, ?, ?)`,
		tokenID, claims.Username, expiryTime, reason,
	)
	if err != nil {
		return err
	}

	// Update cache
	cacheMutex.Lock()
	revokedTokensCache[tokenID] = true
	cacheMutex.Unlock()

	return nil
}

// IsRevoked checks if a token has been revoked
func IsRevoked(db *sql.DB, tokenID string) (bool, error) {
	// First check the cache to avoid database lookups when possible
	cacheMutex.RLock()
	if isRevoked, exists := revokedTokensCache[tokenID]; exists {
		cacheMutex.RUnlock()
		return isRevoked, nil
	}
	cacheMutex.RUnlock()

	// Initialize cache if not already done
	if !cacheInitialized {
		if err := initializeCache(db); err != nil {
			return false, err
		}

		// Check cache again after initialization
		cacheMutex.RLock()
		if isRevoked, exists := revokedTokensCache[tokenID]; exists {
			cacheMutex.RUnlock()
			return isRevoked, nil
		}
		cacheMutex.RUnlock()
	}

	// If not found in cache, check the database
	var exists int
	err := db.QueryRow("SELECT 1 FROM revoked_tokens WHERE token_id = ?", tokenID).Scan(&exists)

	if err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}

	// If found in the database but not in cache, update the cache
	cacheMutex.Lock()
	revokedTokensCache[tokenID] = true
	cacheMutex.Unlock()

	return true, nil
}

// initializeCache loads active revoked tokens into the in-memory cache
func initializeCache(db *sql.DB) error {
	// Only load non-expired tokens to keep the cache small
	rows, err := db.Query(
		"SELECT token_id FROM revoked_tokens WHERE expires_at > ?",
		time.Now(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Load all revoked token IDs into cache
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	for rows.Next() {
		var tokenID string
		if err := rows.Scan(&tokenID); err != nil {
			return err
		}
		revokedTokensCache[tokenID] = true
	}

	if err := rows.Err(); err != nil {
		return err
	}

	cacheInitialized = true
	return nil
}

// RevokeAllUserJWTTokens invalidates all full-tier JWTs issued before now for the
// user. Writes user_jwt_revocations (enforced by TokenRevocationMiddleware) and
// clears the in-process revocation cache so the next request sees the update.
func RevokeAllUserJWTTokens(db *sql.DB, username, reason string) error {
	if err := models.RevokeAllUserJWTsByUsername(db, username, reason); err != nil {
		return err
	}
	InvalidateUserRevocationCache(username)
	return nil
}

// CleanupExpiredTokens removes expired per-JTI entries from revoked_tokens.
func CleanupExpiredTokens(db *sql.DB) error {
	// Delete expired tokens from database
	_, err := db.Exec("DELETE FROM revoked_tokens WHERE expires_at < ?", time.Now())
	if err != nil {
		return err
	}

	// Reset the cache to force reinitialization
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	revokedTokensCache = make(map[string]bool)
	cacheInitialized = false

	return nil
}

func DeleteAllRefreshTokensForUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM refresh_tokens WHERE username = ?", username)
	return err
}

// TokenRevocationMiddleware checks tokens against both the per-JTI revocation list
// and the user-wide JWT revocation table. The user-wide check uses a
// 30-second in-process cache to avoid a DB round-trip on every request.
func TokenRevocationMiddleware(db *sql.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user")
			if user == nil {
				return next(c)
			}

			token, ok := user.(*jwt.Token)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token format")
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid claims format")
			}

			tokenID := claims.ID
			if tokenID == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing token ID")
			}

			// Per-JTI revocation check.
			isRevoked, err := IsRevoked(db, tokenID)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "Error validating token")
			}
			if isRevoked {
				return echo.NewHTTPError(http.StatusUnauthorized, "Token has been revoked")
			}

			// Per-user user-wide JWT revocation check.
			// Uses a cached lookup; cache TTL is 30 seconds.
			if claims.Username != "" && claims.IssuedAt != nil {
				revokedAt, err := getUserRevocationTimeCached(db, claims.Username)
				if err == nil && !revokedAt.IsZero() && revokedAt.After(claims.IssuedAt.Time) {
					return echo.NewHTTPError(http.StatusUnauthorized, "Token has been revoked")
				}
			}

			return next(c)
		}
	}
}
