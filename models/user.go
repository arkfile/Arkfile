package models

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/utils"
)

// DBTX is an interface for database operations that can be handled
// by either a *sql.DB or a *sql.Tx
type DBTX interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type User struct {
	ID                int64          `json:"id"`
	Username          string         `json:"username"`
	Email             *string        `json:"email,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	TotalStorageBytes int64          `json:"total_storage_bytes"`
	StorageLimitBytes int64          `json:"storage_limit_bytes"`
	IsApproved        bool           `json:"is_approved"`
	ApprovedBy        sql.NullString `json:"approved_by,omitempty"`
	ApprovedAt        sql.NullTime   `json:"approved_at,omitempty"`
	IsAdmin           bool           `json:"is_admin"`
}

const (
	DefaultStorageLimit int64 = 1181116006 // 1.1GB in bytes
)

// validateUsername wrapper function for utils.ValidateUsername
func validateUsername(username string) error {
	return utils.ValidateUsername(username)
}

// isAdminUsername checks if a username is in the admin list
func isAdminUsername(username string) bool {
	// Block dev admin accounts in production
	if utils.IsProductionEnvironment() {
		if utils.IsDevAdminAccount(username) {
			logging.ErrorLogger.Printf("SECURITY WARNING: Blocked dev admin account '%s' in production", username)
			return false
		}
	}

	// Normal admin username check
	adminUsernames := strings.Split(getEnvOrDefault("ADMIN_USERNAMES", ""), ",")
	for _, adminUsername := range adminUsernames {
		if strings.TrimSpace(adminUsername) == username {
			return true
		}
	}
	return false
}

// CreateUser creates a new user in the database for OPAQUE authentication
func CreateUser(dbtx DBTX, username string, email *string) (*User, error) {
	// Validate username
	if err := validateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	isAdmin := isAdminUsername(username)
	result, err := dbtx.Exec(
		`INSERT INTO users (
			username, email, storage_limit_bytes, is_admin, is_approved
		) VALUES (?, ?, ?, ?, ?)`,
		username, email, DefaultStorageLimit, isAdmin, isAdmin, // Auto-approve admin usernames
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &User{
		ID:                id,
		Username:          username,
		Email:             email,
		StorageLimitBytes: DefaultStorageLimit,
		CreatedAt:         time.Now(),
		IsApproved:        isAdmin,
		IsAdmin:           isAdmin,
	}, nil
}

// GetUserByUsername retrieves a user by username
func GetUserByUsername(dbtx DBTX, username string) (*User, error) {
	// DEBUG: Log the lookup attempt

	user := &User{}
	var createdAtStr string
	var approvedAtStr sql.NullString
	var totalStorageInterface interface{}
	var storageLimitInterface interface{}
	var emailStr sql.NullString

	query := `SELECT id, username, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = ?`

	err := dbtx.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &emailStr, &createdAtStr,
		&totalStorageInterface, &storageLimitInterface,
		&user.IsApproved, &user.ApprovedBy, &approvedAtStr, &user.IsAdmin,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err // Return sql.ErrNoRows directly
		}
		return nil, err
	}

	// DEBUG: Log when user is found
	fmt.Printf("DEBUG: Found user '%s' with ID %d\n", user.Username, user.ID)

	// Handle optional email field
	if emailStr.Valid {
		user.Email = &emailStr.String
	}

	// Parse the timestamp strings
	if createdAtStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr); parseErr == nil {
			user.CreatedAt = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			user.CreatedAt = parsedTime
		}
	}

	if approvedAtStr.Valid && approvedAtStr.String != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", approvedAtStr.String); parseErr == nil {
			user.ApprovedAt = sql.NullTime{Time: parsedTime, Valid: true}
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, approvedAtStr.String); parseErr == nil {
			user.ApprovedAt = sql.NullTime{Time: parsedTime, Valid: true}
		}
	}

	// Handle numeric fields that might come as float64 from rqlite
	if totalStorageInterface != nil {
		switch v := totalStorageInterface.(type) {
		case int64:
			user.TotalStorageBytes = v
		case float64:
			user.TotalStorageBytes = int64(v)
		default:
			user.TotalStorageBytes = 0
		}
	}

	if storageLimitInterface != nil {
		switch v := storageLimitInterface.(type) {
		case int64:
			user.StorageLimitBytes = v
		case float64:
			user.StorageLimitBytes = int64(v)
		default:
			user.StorageLimitBytes = DefaultStorageLimit
		}
	}

	return user, nil
}

// HasAdminPrivileges checks if a user has admin privileges
func (u *User) HasAdminPrivileges() bool {
	// Check if user is admin by username
	return u.IsAdmin || isAdminUsername(u.Username)
}

// ApproveUser approves a user (admin only)
func (u *User) ApproveUser(dbtx DBTX, adminUsername string) error {
	if !isAdminUsername(adminUsername) {
		return errors.New("unauthorized: admin privileges required")
	}

	now := time.Now()
	_, err := dbtx.Exec(`
		UPDATE users 
		SET is_approved = true, 
		approved_by = ?,
		    approved_at = ?
		WHERE id = ?`,
		adminUsername, now, u.ID,
	)
	if err != nil {
		return err
	}

	// Update struct fields using sql.Null* types
	u.IsApproved = true
	u.ApprovedBy = sql.NullString{String: adminUsername, Valid: true}
	u.ApprovedAt = sql.NullTime{Time: now, Valid: true}

	return nil
}

// CheckStorageAvailable checks if a file of the given size can be stored
func (u *User) CheckStorageAvailable(size int64) bool {
	return (u.TotalStorageBytes + size) <= u.StorageLimitBytes
}

// UpdateStorageUsage updates the user's total storage (should be called in a transaction)
func (u *User) UpdateStorageUsage(tx *sql.Tx, deltaBytes int64) error {
	// deltaBytes can be positive (for additions) or negative (for deletions)
	newTotal := u.TotalStorageBytes + deltaBytes
	if newTotal < 0 {
		newTotal = 0
	}

	_, err := tx.Exec(
		"UPDATE users SET total_storage_bytes = ? WHERE id = ?",
		newTotal, u.ID,
	)
	if err != nil {
		return err
	}

	u.TotalStorageBytes = newTotal
	return nil
}

// GetStorageUsagePercent returns the user's storage usage as a percentage
func (u *User) GetStorageUsagePercent() float64 {
	if u.StorageLimitBytes == 0 {
		return 0.0
	}
	return (float64(u.TotalStorageBytes) / float64(u.StorageLimitBytes)) * 100
}

// GetPendingUsers retrieves users pending approval (admin only)
func GetPendingUsers(dbtx DBTX) ([]*User, error) {
	rows, err := dbtx.Query(`
		SELECT id, username, email, created_at, total_storage_bytes, storage_limit_bytes
		FROM users
		WHERE is_approved = false
		ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		var emailStr sql.NullString
		var createdAtStr string                                      // Scan as string first to handle RQLite timestamp format
		var totalStorageInterface, storageLimitInterface interface{} // Handle numeric types
		err := rows.Scan(
			&user.ID, &user.Username, &emailStr, &createdAtStr,
			&totalStorageInterface, &storageLimitInterface,
		)
		if err != nil {
			return nil, err
		}

		// Handle optional email field
		if emailStr.Valid {
			user.Email = &emailStr.String
		}

		// Parse timestamp string to time.Time
		if createdAtStr != "" {
			if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr); parseErr == nil {
				user.CreatedAt = parsedTime
			} else if parsedTime, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
				user.CreatedAt = parsedTime
			} else {
				// Fallback to current time if parsing fails
				user.CreatedAt = time.Now()
			}
		}

		// Handle numeric fields that might come as float64 from rqlite
		if totalStorageInterface != nil {
			switch v := totalStorageInterface.(type) {
			case int64:
				user.TotalStorageBytes = v
			case float64:
				user.TotalStorageBytes = int64(v)
			default:
				user.TotalStorageBytes = 0
			}
		}

		if storageLimitInterface != nil {
			switch v := storageLimitInterface.(type) {
			case int64:
				user.StorageLimitBytes = v
			case float64:
				user.StorageLimitBytes = int64(v)
			default:
				user.StorageLimitBytes = DefaultStorageLimit
			}
		}

		users = append(users, user)
	}

	return users, rows.Err()
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// HasOPAQUEAccount checks if the user has an OPAQUE account registered
// Uses the RFC-compliant opaque_user_data table
func (u *User) HasOPAQUEAccount(db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM opaque_user_data WHERE username = ?`, u.Username).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Delete removes the user and all associated data
func (u *User) Delete(db *sql.DB) error {
	// Start transaction for atomic deletion
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// First, clean up all OPAQUE records using the transaction
	_, err = tx.Exec(`
		DELETE FROM opaque_password_records 
		WHERE associated_username = ? OR record_identifier = ?`,
		u.Username, u.Username)
	if err != nil {
		return fmt.Errorf("failed to delete OPAQUE records: %w", err)
	}

	// Delete user record
	_, err = tx.Exec("DELETE FROM users WHERE id = ?", u.ID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit deletion: %w", err)
	}

	return nil
}
