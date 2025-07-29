package models

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/84adam/arkfile/auth"
)

type User struct {
	ID                int64          `json:"id"`
	Email             string         `json:"email"`
	CreatedAt         time.Time      `json:"created_at"`
	TotalStorageBytes int64          `json:"total_storage_bytes"`
	StorageLimitBytes int64          `json:"storage_limit_bytes"`
	IsApproved        bool           `json:"is_approved"`
	ApprovedBy        sql.NullString `json:"approved_by,omitempty"`
	ApprovedAt        sql.NullTime   `json:"approved_at,omitempty"`
	IsAdmin           bool           `json:"is_admin"`
}

const (
	DefaultStorageLimit int64 = 10737418240 // 10GB in bytes
)

// CreateUser creates a new user in the database for OPAQUE authentication
func CreateUser(db *sql.DB, email string) (*User, error) {
	isAdmin := isAdminEmail(email)
	result, err := db.Exec(
		`INSERT INTO users (
			email, storage_limit_bytes, is_admin, is_approved
		) VALUES (?, ?, ?, ?)`,
		email, DefaultStorageLimit, isAdmin, isAdmin, // Auto-approve admin emails
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
		Email:             email,
		StorageLimitBytes: DefaultStorageLimit,
		CreatedAt:         time.Now(),
		IsApproved:        isAdmin,
		IsAdmin:           isAdmin,
	}, nil
}

// GetUserByEmail retrieves a user by email (OPAQUE-only)
func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	user := &User{}
	var createdAtStr string
	var approvedAtStr sql.NullString
	var totalStorageInterface interface{}
	var storageLimitInterface interface{}

	query := `SELECT id, email, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE email = ?`

	err := db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &createdAtStr,
		&totalStorageInterface, &storageLimitInterface,
		&user.IsApproved, &user.ApprovedBy, &approvedAtStr, &user.IsAdmin,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err // Return sql.ErrNoRows directly
		}
		return nil, err
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
	return u.IsAdmin || isAdminEmail(u.Email)
}

// ApproveUser approves a user (admin only)
func (u *User) ApproveUser(db *sql.DB, adminEmail string) error {
	if !isAdminEmail(adminEmail) {
		return errors.New("unauthorized: admin privileges required")
	}

	now := time.Now()
	_, err := db.Exec(`
		UPDATE users 
		SET is_approved = true, 
		approved_by = ?,
		    approved_at = ?
		WHERE id = ?`,
		adminEmail, now, u.ID,
	)
	if err != nil {
		return err
	}

	// Update struct fields using sql.Null* types
	u.IsApproved = true
	u.ApprovedBy = sql.NullString{String: adminEmail, Valid: true}
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
func GetPendingUsers(db *sql.DB) ([]*User, error) {
	rows, err := db.Query(`
		SELECT id, email, created_at, total_storage_bytes, storage_limit_bytes
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
		err := rows.Scan(
			&user.ID, &user.Email, &user.CreatedAt,
			&user.TotalStorageBytes, &user.StorageLimitBytes,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// isAdminEmail checks if an email is in the admin list
func isAdminEmail(email string) bool {
	adminEmails := strings.Split(getEnvOrDefault("ADMIN_EMAILS", ""), ",")
	for _, adminEmail := range adminEmails {
		if strings.TrimSpace(adminEmail) == email {
			return true
		}
	}
	return false
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// OPAQUE Integration - Comprehensive OPAQUE lifecycle management

// OPAQUEAccountStatus represents the OPAQUE authentication status for a user
type OPAQUEAccountStatus struct {
	HasAccountPassword bool       `json:"has_account_password"`
	FilePasswordCount  int        `json:"file_password_count"`
	SharePasswordCount int        `json:"share_password_count"`
	LastOPAQUEAuth     *time.Time `json:"last_opaque_auth"`
	OPAQUECreatedAt    *time.Time `json:"opaque_created_at"`
}

// CreateUserWithOPAQUE creates user AND registers OPAQUE account in single transaction
func CreateUserWithOPAQUE(db *sql.DB, email, password string) (*User, error) {
	// Start transaction to ensure atomicity
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Create user record first
	isAdmin := isAdminEmail(email)
	result, err := tx.Exec(
		`INSERT INTO users (
			email, storage_limit_bytes, is_admin, is_approved
		) VALUES (?, ?, ?, ?)`,
		email, DefaultStorageLimit, isAdmin, isAdmin,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	// Register OPAQUE account
	err = auth.RegisterUser(db, email, password)
	if err != nil {
		return nil, fmt.Errorf("failed to register OPAQUE account: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &User{
		ID:                id,
		Email:             email,
		StorageLimitBytes: DefaultStorageLimit,
		CreatedAt:         time.Now(),
		IsApproved:        isAdmin,
		IsAdmin:           isAdmin,
	}, nil
}

// RegisterOPAQUEAccount registers an OPAQUE account for an existing user
func (u *User) RegisterOPAQUEAccount(db *sql.DB, password string) error {
	return auth.RegisterUser(db, u.Email, password)
}

// AuthenticateOPAQUE authenticates the user's account password via OPAQUE
func (u *User) AuthenticateOPAQUE(db *sql.DB, password string) ([]byte, error) {
	sessionKey, err := auth.AuthenticateUser(db, u.Email, password)
	if err != nil {
		return nil, fmt.Errorf("OPAQUE authentication failed: %w", err)
	}
	return sessionKey, nil
}

// HasOPAQUEAccount checks if the user has an OPAQUE account registered
func (u *User) HasOPAQUEAccount(db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM opaque_password_records 
		WHERE record_type = 'account' AND record_identifier = ? AND is_active = TRUE`,
		u.Email).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("failed to check OPAQUE account: %w", err)
	}

	return count > 0, nil
}

// DeleteOPAQUEAccount deactivates all OPAQUE records for this user
func (u *User) DeleteOPAQUEAccount(db *sql.DB) error {
	// Deactivate all OPAQUE records associated with this user
	_, err := db.Exec(`
		UPDATE opaque_password_records 
		SET is_active = FALSE 
		WHERE record_identifier = ? OR associated_user_email = ?`,
		u.Email, u.Email)

	if err != nil {
		return fmt.Errorf("failed to delete OPAQUE account: %w", err)
	}

	return nil
}

// GetOPAQUEAccountStatus returns comprehensive OPAQUE status for the user
func (u *User) GetOPAQUEAccountStatus(db *sql.DB) (*OPAQUEAccountStatus, error) {
	status := &OPAQUEAccountStatus{}

	// Check for account password
	var accountCount int
	var accountCreatedAt sql.NullString
	var accountLastUsed sql.NullString

	err := db.QueryRow(`
		SELECT COUNT(*), MIN(created_at), MAX(last_used_at)
		FROM opaque_password_records 
		WHERE record_type = 'account' AND record_identifier = ? AND is_active = TRUE`,
		u.Email).Scan(&accountCount, &accountCreatedAt, &accountLastUsed)

	if err != nil {
		return nil, fmt.Errorf("failed to check account status: %w", err)
	}

	status.HasAccountPassword = accountCount > 0

	// Parse timestamps if available
	if accountCreatedAt.Valid {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", accountCreatedAt.String); parseErr == nil {
			status.OPAQUECreatedAt = &parsedTime
		}
	}

	if accountLastUsed.Valid {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", accountLastUsed.String); parseErr == nil {
			status.LastOPAQUEAuth = &parsedTime
		}
	}

	// Count file passwords
	err = db.QueryRow(`
		SELECT COUNT(*) FROM opaque_password_records 
		WHERE record_type = 'file_custom' AND associated_user_email = ? AND is_active = TRUE`,
		u.Email).Scan(&status.FilePasswordCount)

	if err != nil {
		return nil, fmt.Errorf("failed to count file passwords: %w", err)
	}

	// Count share passwords
	err = db.QueryRow(`
		SELECT COUNT(*) FROM opaque_password_records 
		WHERE record_type = 'share' AND associated_user_email = ? AND is_active = TRUE`,
		u.Email).Scan(&status.SharePasswordCount)

	if err != nil {
		return nil, fmt.Errorf("failed to count share passwords: %w", err)
	}

	return status, nil
}

// RegisterFilePassword registers a custom password for a specific file
func (u *User) RegisterFilePassword(db *sql.DB, fileID, password, keyLabel, passwordHint string) error {
	opm := auth.NewOPAQUEPasswordManager()
	return opm.RegisterCustomFilePassword(u.Email, fileID, password, keyLabel, passwordHint)
}

// GetFilePasswordRecords gets all password records for a specific file owned by this user
func (u *User) GetFilePasswordRecords(db *sql.DB, fileID string) ([]*auth.OPAQUEPasswordRecord, error) {
	opm := auth.NewOPAQUEPasswordManager()
	return opm.GetFilePasswordRecords(fileID)
}

// AuthenticateFilePassword authenticates a file-specific password and returns the export key
func (u *User) AuthenticateFilePassword(db *sql.DB, fileID, password string) ([]byte, error) {
	recordIdentifier := fmt.Sprintf("%s:file:%s", u.Email, fileID)
	opm := auth.NewOPAQUEPasswordManager()

	exportKey, err := opm.AuthenticatePassword(recordIdentifier, password)
	if err != nil {
		return nil, fmt.Errorf("file password authentication failed: %w", err)
	}

	return exportKey, nil
}

// DeleteFilePassword removes a specific file password record
func (u *User) DeleteFilePassword(db *sql.DB, fileID, keyLabel string) error {
	recordIdentifier := fmt.Sprintf("%s:file:%s", u.Email, fileID)
	opm := auth.NewOPAQUEPasswordManager()
	return opm.DeletePasswordRecord(recordIdentifier)
}

// Delete removes the user and all associated OPAQUE records
func (u *User) Delete(db *sql.DB) error {
	// Start transaction for atomic deletion
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// First, clean up all OPAQUE records
	if err := u.DeleteOPAQUEAccount(db); err != nil {
		return fmt.Errorf("failed to clean up OPAQUE records: %w", err)
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
