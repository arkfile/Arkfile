package models

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/utils"
)

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
func CreateUser(db *sql.DB, username string, email *string) (*User, error) {
	// Validate username
	if err := validateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	isAdmin := isAdminUsername(username)
	result, err := db.Exec(
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
func GetUserByUsername(db *sql.DB, username string) (*User, error) {
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

	err := db.QueryRow(query, username).Scan(
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
func (u *User) ApproveUser(db *sql.DB, adminUsername string) error {
	if !isAdminUsername(adminUsername) {
		return errors.New("unauthorized: admin privileges required")
	}

	now := time.Now()
	_, err := db.Exec(`
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
func GetPendingUsers(db *sql.DB) ([]*User, error) {
	rows, err := db.Query(`
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
		err := rows.Scan(
			&user.ID, &user.Username, &emailStr, &user.CreatedAt,
			&user.TotalStorageBytes, &user.StorageLimitBytes,
		)
		if err != nil {
			return nil, err
		}

		// Handle optional email field
		if emailStr.Valid {
			user.Email = &emailStr.String
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
func CreateUserWithOPAQUE(db *sql.DB, username, password string, email *string) (*User, error) {
	// Start transaction to ensure atomicity
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Create user record first
	isAdmin := isAdminUsername(username)
	result, err := tx.Exec(
		`INSERT INTO users (
			username, email, storage_limit_bytes, is_admin, is_approved
		) VALUES (?, ?, ?, ?, ?)`,
		username, email, DefaultStorageLimit, isAdmin, isAdmin,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	// Register OPAQUE account using unified password manager
	recordIdentifier := username // Account passwords now use username as identifier

	// Use provider interface
	provider := auth.GetOPAQUEProvider()
	if !provider.IsAvailable() {
		return nil, fmt.Errorf("OPAQUE provider not available")
	}

	// Get server keys
	_, serverPrivateKey, err := provider.GetServerKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get server keys: %w", err)
	}

	// Register user record with OPAQUE provider
	userRecord, exportKey, err := provider.RegisterUser([]byte(password), serverPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to register OPAQUE account: %w", err)
	}

	// Store in unified password system (account password)
	// In production, this stores in opaque_password_records table
	// In test environment, this may be mocked differently
	_, err = tx.Exec(`
		INSERT INTO opaque_password_records 
		(record_type, record_identifier, opaque_user_record, associated_username, is_active)
		VALUES (?, ?, ?, ?, ?)`,
		"account", recordIdentifier, userRecord, username, true)
	if err != nil {
		return nil, fmt.Errorf("failed to store OPAQUE record: %w", err)
	}

	// Clear export key (we don't store it)
	if len(exportKey) > 0 {
		for i := range exportKey {
			exportKey[i] = 0
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
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

// RegisterOPAQUEAccount registers an OPAQUE account for an existing user
func (u *User) RegisterOPAQUEAccount(db *sql.DB, password string) error {
	provider := auth.GetOPAQUEProvider()
	if !provider.IsAvailable() {
		return fmt.Errorf("OPAQUE provider not available")
	}

	// Get server keys
	_, serverPrivateKey, err := provider.GetServerKeys()
	if err != nil {
		return fmt.Errorf("failed to get server keys: %w", err)
	}

	// Register user with OPAQUE provider
	userRecord, _, err := provider.RegisterUser([]byte(password), serverPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to register OPAQUE account: %w", err)
	}

	// Store record in database (even in mock mode for testing)
	_, err = db.Exec(`
		INSERT INTO opaque_password_records 
		(record_type, record_identifier, opaque_user_record, associated_username, is_active)
		VALUES (?, ?, ?, ?, ?)`,
		"account", u.Username, userRecord, u.Username, true)
	if err != nil {
		return fmt.Errorf("failed to store OPAQUE record: %w", err)
	}

	return nil
}

// AuthenticateOPAQUE authenticates the user's account password via OPAQUE
func (u *User) AuthenticateOPAQUE(db *sql.DB, password string) ([]byte, error) {
	// Use unified password manager for account password authentication
	recordIdentifier := u.Username // Account passwords now use username as identifier

	opm := auth.GetOPAQUEPasswordManagerWithDB(db)

	exportKey, err := opm.AuthenticatePassword(recordIdentifier, password)
	if err != nil {
		return nil, fmt.Errorf("account password authentication failed: %w", err)
	}

	return exportKey, nil
}

// GetOPAQUEExportKey retrieves the export key after successful authentication
// This method should only be called immediately after successful AuthenticateOPAQUE
func (u *User) GetOPAQUEExportKey(db *sql.DB, password string) ([]byte, error) {
	// This method is essentially the same as AuthenticateOPAQUE but with clearer naming
	// for Phase 5A export key integration
	return u.AuthenticateOPAQUE(db, password)
}

// ValidateOPAQUEExportKey validates that an export key has the expected properties
func (u *User) ValidateOPAQUEExportKey(exportKey []byte) error {
	if len(exportKey) == 0 {
		return fmt.Errorf("OPAQUE export key cannot be empty")
	}

	// OPAQUE export keys should be 64 bytes (512 bits) as per the protocol specification
	if len(exportKey) != 64 {
		return fmt.Errorf("OPAQUE export key must be exactly 64 bytes, got %d", len(exportKey))
	}

	// Check that the key is not all zeros
	allZero := true
	for _, b := range exportKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("OPAQUE export key cannot be all zeros")
	}

	return nil
}

// SecureZeroExportKey securely clears export key material from memory
func (u *User) SecureZeroExportKey(exportKey []byte) {
	if exportKey != nil {
		for i := range exportKey {
			exportKey[i] = 0
		}
	}
}

// HasOPAQUEAccount checks if the user has an OPAQUE account registered
func (u *User) HasOPAQUEAccount(db *sql.DB) (bool, error) {
	// Check database for OPAQUE records
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM opaque_password_records 
		WHERE record_type = 'account' AND record_identifier = ? AND is_active = true`,
		u.Username).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// DeleteOPAQUEAccount deactivates all OPAQUE records for this user
func (u *User) DeleteOPAQUEAccount(db *sql.DB) error {
	// Deactivate all OPAQUE records for this user
	_, err := db.Exec(`
		UPDATE opaque_password_records 
		SET is_active = false 
		WHERE associated_username = ? OR record_identifier = ?`,
		u.Username, u.Username)
	if err != nil {
		return fmt.Errorf("failed to deactivate OPAQUE records: %w", err)
	}
	return nil
}

// GetOPAQUEAccountStatus returns comprehensive OPAQUE status for the user
func (u *User) GetOPAQUEAccountStatus(db *sql.DB) (*OPAQUEAccountStatus, error) {
	// Query database for actual statistics
	status := &OPAQUEAccountStatus{}

	// Check for account password
	var accountCount int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM opaque_password_records 
		WHERE record_type = 'account' AND record_identifier = ? AND is_active = true`,
		u.Username).Scan(&accountCount)
	if err != nil {
		return nil, err
	}
	status.HasAccountPassword = accountCount > 0

	// Count file passwords
	var fileCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM opaque_password_records 
		WHERE record_type = 'file' AND associated_username = ? AND is_active = true`,
		u.Username).Scan(&fileCount)
	if err != nil {
		return nil, err
	}
	status.FilePasswordCount = fileCount

	// Get timestamps if account exists
	if status.HasAccountPassword {
		var createdAt, lastUsed sql.NullTime
		err = db.QueryRow(`
			SELECT created_at, last_used_at FROM opaque_password_records 
			WHERE record_type = 'account' AND record_identifier = ? AND is_active = true LIMIT 1`,
			u.Username).Scan(&createdAt, &lastUsed)
		if err == nil {
			if createdAt.Valid {
				status.OPAQUECreatedAt = &createdAt.Time
			}
			if lastUsed.Valid {
				status.LastOPAQUEAuth = &lastUsed.Time
			}
		}
	}

	return status, nil
}

// RegisterFilePassword registers a custom password for a specific file
func (u *User) RegisterFilePassword(db *sql.DB, fileID, password, keyLabel, passwordHint string) error {
	opm := auth.GetOPAQUEPasswordManagerWithDB(db)
	return opm.RegisterCustomFilePassword(u.Username, fileID, password, keyLabel, passwordHint)
}

// GetFilePasswordRecords gets all password records for a specific file owned by this user
func (u *User) GetFilePasswordRecords(db *sql.DB, fileID string) ([]*auth.OPAQUEPasswordRecord, error) {
	opm := auth.GetOPAQUEPasswordManagerWithDB(db)
	return opm.GetFilePasswordRecords(fileID)
}

// AuthenticateFilePassword authenticates a file-specific password and returns the export key
func (u *User) AuthenticateFilePassword(db *sql.DB, fileID, password string) ([]byte, error) {
	recordIdentifier := fmt.Sprintf("%s:file:%s", u.Username, fileID)
	opm := auth.GetOPAQUEPasswordManagerWithDB(db)

	exportKey, err := opm.AuthenticatePassword(recordIdentifier, password)
	if err != nil {
		return nil, fmt.Errorf("file password authentication failed: %w", err)
	}

	return exportKey, nil
}

// DeleteFilePassword removes a specific file password record
func (u *User) DeleteFilePassword(db *sql.DB, fileID, keyLabel string) error {
	recordIdentifier := fmt.Sprintf("%s:file:%s", u.Username, fileID)
	opm := auth.GetOPAQUEPasswordManagerWithDB(db)
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
