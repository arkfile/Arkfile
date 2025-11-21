package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Pre-defined errors for token validation
var (
	ErrRefreshTokenExpired  = errors.New("refresh token has expired")
	ErrUserNotFound         = errors.New("user not found for token")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	ID        string
	Username  string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
	LastUsed  *time.Time
}

// CreateRefreshToken generates a new refresh token for a user
func CreateRefreshToken(db *sql.DB, username string) (string, error) {
	// Generate a random token
	tokenString := uuid.New().String()

	// Hash the token for storage
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	// Set expiry (30 days)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	// Use the token hash as the unique ID for the token.
	id := tokenHash

	// Insert token into database.
	createdAt := time.Now()
	_, err := db.Exec(
		`INSERT INTO refresh_tokens (id, username, token_hash, expires_at, created_at, revoked, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, username, tokenHash, expiresAt, createdAt, false, nil,
	)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateRefreshToken checks if a refresh token is valid and returns the username
// Uses sliding window expiry - extends token lifetime on successful use
func ValidateRefreshToken(db *sql.DB, tokenString string) (string, error) {
	// Hash the token to compare with stored hash
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	// Debug logging
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	if debugMode == "true" || debugMode == "1" {
		fmt.Printf("[DEBUG] ValidateRefreshToken: token=%s, hash=%s\n", tokenString, tokenHash)
	}

	var (
		id           string
		username     string
		expiresAtStr string // Scan as string first to handle RQLite timestamp format
		revoked      bool
		lastUsedStr  sql.NullString // Scan as string first to handle RQLite timestamp format
	)

	err := db.QueryRow(
		`SELECT id, username, expires_at, revoked, last_used 
		 FROM refresh_tokens 
		 WHERE token_hash = ?`,
		tokenHash,
	).Scan(&id, &username, &expiresAtStr, &revoked, &lastUsedStr)

	if err != nil {
		if debugMode == "true" || debugMode == "1" {
			if err == sql.ErrNoRows {
				fmt.Printf("[DEBUG] ValidateRefreshToken: token not found in database\n")
			} else {
				fmt.Printf("[DEBUG] ValidateRefreshToken: database error: %v\n", err)
			}
		}
		if err == sql.ErrNoRows {
			return "", ErrRefreshTokenNotFound
		}
		return "", err
	}

	// Parse the expires_at timestamp from string to time.Time
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		// Try alternative timestamp formats if RFC3339 fails
		if expiresAt, err = time.Parse("2006-01-02 15:04:05", expiresAtStr); err != nil {
			if debugMode == "true" || debugMode == "1" {
				fmt.Printf("[DEBUG] ValidateRefreshToken: failed to parse expires_at timestamp: %s, error: %v\n", expiresAtStr, err)
			}
			return "", fmt.Errorf("failed to parse expires_at timestamp: %v", err)
		}
	}

	if debugMode == "true" || debugMode == "1" {
		fmt.Printf("[DEBUG] ValidateRefreshToken: found token - id=%s, username=%s, expires_at=%s, revoked=%t, last_used=%v\n",
			id, username, expiresAt.Format(time.RFC3339), revoked, lastUsedStr)
	}

	// Check if token is expired
	if time.Now().After(expiresAt) {
		if debugMode == "true" || debugMode == "1" {
			fmt.Printf("[DEBUG] ValidateRefreshToken: token expired - expires_at=%s, now=%s\n",
				expiresAt.Format(time.RFC3339), time.Now().Format(time.RFC3339))
		}
		return "", ErrRefreshTokenExpired
	}

	// Check if token is revoked
	if revoked {
		if debugMode == "true" || debugMode == "1" {
			fmt.Printf("[DEBUG] ValidateRefreshToken: token is revoked\n")
		}
		return "", ErrRefreshTokenNotFound // Treat revoked tokens as not found for security
	}

	// Note: Removed single-use restriction - tokens can be used multiple times until expiry
	// This follows OAuth 2.0 RFC 6749 recommendations for refresh token behavior

	// Implement sliding window: extend the expiry time on successful use
	// This provides a balance between security and usability
	newExpiresAt := time.Now().Add(14 * 24 * time.Hour) // 14-day sliding window
	now := time.Now()

	_, err = db.Exec(
		"UPDATE refresh_tokens SET expires_at = ?, last_used = ? WHERE id = ?",
		newExpiresAt, now, id,
	)
	if err != nil {
		if debugMode == "true" || debugMode == "1" {
			fmt.Printf("[DEBUG] ValidateRefreshToken: failed to update expiry: %v\n", err)
		}
		return "", err
	}

	if debugMode == "true" || debugMode == "1" {
		fmt.Printf("[DEBUG] ValidateRefreshToken: token validated successfully, updated expiry to %s\n",
			newExpiresAt.Format(time.RFC3339))
	}

	return username, nil
}

// RevokeRefreshToken marks a token as revoked
func RevokeRefreshToken(db *sql.DB, tokenString string) error {
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	result, err := db.Exec(
		"UPDATE refresh_tokens SET revoked = true WHERE token_hash = ?",
		tokenHash,
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

// RevokeAllUserTokens revokes all refresh tokens for a user
func RevokeAllUserTokens(db *sql.DB, username string) error {
	_, err := db.Exec(
		"UPDATE refresh_tokens SET revoked = true WHERE username = ?",
		username,
	)
	return err
}

// CleanupExpiredTokens removes expired tokens from the database
func CleanupExpiredTokens(db *sql.DB) error {
	_, err := db.Exec(
		"DELETE FROM refresh_tokens WHERE expires_at < ?",
		time.Now(),
	)
	return err
}
