package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// In-memory cache for faster revocation checks
var (
	revokedTokensCache = make(map[string]bool)
	cacheMutex         = &sync.RWMutex{}
	cacheInitialized   = false
)

// RevokeToken adds a token to the revocation list
func RevokeToken(db *sql.DB, tokenString, reason string) error {
	// Parse the token to get claims
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return GetJWTPublicKey(), nil
	})

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

// RevokeAllUserJWTTokens creates a user-wide JWT revocation entry
// This invalidates all JWTs issued to a user before the current timestamp
func RevokeAllUserJWTTokens(db *sql.DB, username, reason string) error {
	currentTime := time.Now()

	// Create a special token ID that represents user-wide revocation
	// Format: "user-revoke:{username}:{timestamp}"
	userRevokeTokenID := fmt.Sprintf("user-revoke:%s:%d", username, currentTime.Unix())

	// Set expiry far in the future (1 year from now) to catch all current tokens
	// This is safe because JWT tokens are short-lived (30 minutes)
	expiryTime := currentTime.Add(365 * 24 * time.Hour)

	// Insert user-wide revocation entry
	_, err := db.Exec(
		`INSERT INTO revoked_tokens (token_id, username, expires_at, reason) 
		 VALUES (?, ?, ?, ?)`,
		userRevokeTokenID, username, expiryTime, reason,
	)
	if err != nil {
		return err
	}

	// Update cache with the user revocation entry
	cacheMutex.Lock()
	revokedTokensCache[userRevokeTokenID] = true
	cacheMutex.Unlock()

	return nil
}

// IsUserJWTRevoked checks if all JWTs for a user have been revoked after a specific time
// This is used during JWT validation to check for user-wide revocations
func IsUserJWTRevoked(db *sql.DB, username string, tokenIssuedAt time.Time) (bool, error) {
	// Query for user-wide revocation entries that are newer than the token
	rows, err := db.Query(`
		SELECT token_id FROM revoked_tokens 
		WHERE username = ? 
		AND token_id LIKE 'user-revoke:%' 
		AND expires_at > ?
		ORDER BY rowid DESC
		LIMIT 1`,
		username, time.Now())

	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var revokeTokenID string
		if err := rows.Scan(&revokeTokenID); err != nil {
			return false, err
		}

		// Extract timestamp from token ID format: "user-revoke:{username}:{timestamp}"
		parts := strings.Split(revokeTokenID, ":")
		if len(parts) != 3 {
			continue // Skip malformed entries
		}

		revokeTimestamp, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			continue // Skip entries with invalid timestamps
		}

		revokeTime := time.Unix(revokeTimestamp, 0)

		// If the revocation happened after the token was issued, the token is revoked
		if revokeTime.After(tokenIssuedAt) {
			return true, nil
		}
	}

	return false, rows.Err()
}

// CleanupExpiredTokens removes expired tokens from the database
// This should be called periodically, perhaps daily, to clean up the database
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

// TokenRevocationMiddleware creates a middleware that checks tokens against the revocation list
func TokenRevocationMiddleware(db *sql.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get the JWT token from the context
			user := c.Get("user")
			if user == nil {
				// No token to check, proceed
				return next(c)
			}

			token, ok := user.(*jwt.Token)
			if !ok {
				// Invalid token type, proceed
				return next(c)
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				// Invalid claims type, proceed
				return next(c)
			}

			// Get the token ID
			tokenID := claims.ID
			if tokenID == "" {
				// No token ID, proceed
				return next(c)
			}

			// Check if token is revoked
			isRevoked, err := IsRevoked(db, tokenID)
			if err != nil {
				// Error checking revocation, log and proceed
				return echo.NewHTTPError(http.StatusInternalServerError, "Error validating token")
			}

			if isRevoked {
				// Token is revoked, deny access
				return echo.NewHTTPError(http.StatusUnauthorized, "Token has been revoked")
			}

			// Token is not revoked, proceed
			return next(c)
		}
	}
}
