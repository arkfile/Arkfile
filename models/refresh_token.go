package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	ID        string
	UserEmail string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	IsRevoked bool
	IsUsed    bool
}

// CreateRefreshToken generates a new refresh token for a user
func CreateRefreshToken(db *sql.DB, userEmail string) (string, error) {
	// Generate a random token
	tokenString := uuid.New().String()

	// Hash the token for storage
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	// Set expiry (30 days)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	// Create a unique ID for the token
	id := uuid.New().String()

	// Insert token into database
	createdAt := time.Now() // Explicitly set created_at
	_, err := db.Exec(
		`INSERT INTO refresh_tokens (
			id, user_email, token_hash, expires_at, created_at, is_revoked, is_used
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, userEmail, tokenHash, expiresAt, createdAt, false, false, // Add created_at, is_revoked, is_used
	)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateRefreshToken checks if a refresh token is valid and returns the user email
func ValidateRefreshToken(db *sql.DB, tokenString string) (string, error) {
	// Hash the token to compare with stored hash
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	var (
		id        string
		userEmail string
		expiresAt time.Time
		isRevoked bool
		isUsed    bool
	)

	err := db.QueryRow(
		`SELECT id, user_email, expires_at, is_revoked, is_used 
		 FROM refresh_tokens 
		 WHERE token_hash = ?`,
		tokenHash,
	).Scan(&id, &userEmail, &expiresAt, &isRevoked, &isUsed)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("token not found")
		}
		return "", err
	}

	// Check if token is expired, revoked, or used
	if time.Now().After(expiresAt) {
		return "", errors.New("token expired")
	}

	if isRevoked {
		return "", errors.New("token revoked")
	}

	if isUsed {
		return "", errors.New("token already used")
	}

	// Mark the token as used
	_, err = db.Exec(
		"UPDATE refresh_tokens SET is_used = true WHERE id = ?",
		id,
	)
	if err != nil {
		return "", err
	}

	return userEmail, nil
}

// RevokeRefreshToken marks a token as revoked
func RevokeRefreshToken(db *sql.DB, tokenString string) error {
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	result, err := db.Exec(
		"UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = ?",
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
		return errors.New("token not found")
	}

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func RevokeAllUserTokens(db *sql.DB, userEmail string) error {
	_, err := db.Exec(
		"UPDATE refresh_tokens SET is_revoked = true WHERE user_email = ?",
		userEmail,
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
