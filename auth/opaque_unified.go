package auth

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/database"
)

// OPAQUEPasswordManagerInterface defines the interface for OPAQUE password management
type OPAQUEPasswordManagerInterface interface {
	AuthenticatePassword(recordIdentifier, password string) ([]byte, error)
	GetPasswordRecord(recordIdentifier string) (*OPAQUEPasswordRecord, error)
	GetFilePasswordRecords(fileID string) ([]*OPAQUEPasswordRecord, error)
	DeletePasswordRecord(recordIdentifier string) error
}

// OPAQUEPasswordManager handles all password authentication via OPAQUE
type OPAQUEPasswordManager struct {
	db *sql.DB
}

// Ensure OPAQUEPasswordManager implements the interface
var _ OPAQUEPasswordManagerInterface = (*OPAQUEPasswordManager)(nil)

// NewOPAQUEPasswordManager creates a new password manager instance
func NewOPAQUEPasswordManager() *OPAQUEPasswordManager {
	return &OPAQUEPasswordManager{
		db: database.DB,
	}
}

// NewOPAQUEPasswordManagerWithDB creates a new password manager instance with a specific database
func NewOPAQUEPasswordManagerWithDB(db *sql.DB) *OPAQUEPasswordManager {
	return &OPAQUEPasswordManager{
		db: db,
	}
}

// GetOPAQUEPasswordManager returns the OPAQUE password manager implementation
func GetOPAQUEPasswordManager() OPAQUEPasswordManagerInterface {
	return NewOPAQUEPasswordManager()
}

// GetOPAQUEPasswordManagerWithDB returns the OPAQUE password manager implementation with database
func GetOPAQUEPasswordManagerWithDB(db *sql.DB) OPAQUEPasswordManagerInterface {
	return NewOPAQUEPasswordManagerWithDB(db)
}

// OPAQUEPasswordRecord represents a unified password record
type OPAQUEPasswordRecord struct {
	ID                 int        `json:"id"`
	RecordType         string     `json:"record_type"`         // 'account', 'file_custom', 'share'
	RecordIdentifier   string     `json:"record_identifier"`   // username, 'user:file:filename', 'share:shareID'
	OPAQUEUserRecord   []byte     `json:"opaque_user_record"`  // OPAQUE registration data
	AssociatedFileID   *string    `json:"associated_file_id"`  // NULL for account, filename for file/share
	AssociatedUsername *string    `json:"associated_username"` // User who created this record
	KeyLabel           *string    `json:"key_label"`           // Human-readable label
	CreatedAt          time.Time  `json:"created_at"`
	LastUsedAt         *time.Time `json:"last_used_at"`
	IsActive           bool       `json:"is_active"`
}

// AuthenticatePassword authenticates any password via OPAQUE and returns the export key
func (opm *OPAQUEPasswordManager) AuthenticatePassword(
	recordIdentifier, password string) ([]byte, error) {

	// Get OPAQUE user record
	var userRecord []byte
	err := opm.db.QueryRow(`
		SELECT opaque_user_record FROM opaque_password_records 
		WHERE record_identifier = ? AND is_active = TRUE`,
		recordIdentifier).Scan(&userRecord)

	if err != nil {
		return nil, fmt.Errorf("password record not found: %w", err)
	}

	// rqlite stores binary data as base64-encoded text, but libopaque expects raw binary
	// Check if data appears to be base64 encoded and decode it
	if len(userRecord) != 256 {
		// Try to decode from base64
		if decodedRecord, err := base64.StdEncoding.DecodeString(string(userRecord)); err == nil && len(decodedRecord) == 256 {
			userRecord = decodedRecord
		}
	}

	// Use provider interface for authentication
	provider := GetOPAQUEProvider()
	if !provider.IsAvailable() {
		return nil, fmt.Errorf("OPAQUE provider not available")
	}

	// Authenticate with OPAQUE
	exportKey, err := provider.AuthenticateUser([]byte(password), userRecord)
	if err != nil {
		return nil, fmt.Errorf("OPAQUE authentication failed: %w", err)
	}

	// Update last used timestamp
	_, _ = opm.db.Exec(`
		UPDATE opaque_password_records 
		SET last_used_at = CURRENT_TIMESTAMP 
		WHERE record_identifier = ?`, recordIdentifier)

	return exportKey, nil
}

// GetPasswordRecord retrieves a password record by identifier
func (opm *OPAQUEPasswordManager) GetPasswordRecord(recordIdentifier string) (*OPAQUEPasswordRecord, error) {
	var record OPAQUEPasswordRecord

	err := opm.db.QueryRow(`
		SELECT id, record_type, record_identifier, opaque_user_record, 
		       associated_file_id, associated_username, key_label, 
		       created_at, last_used_at, is_active
		FROM opaque_password_records 
		WHERE record_identifier = ? AND is_active = TRUE`,
		recordIdentifier).Scan(
		&record.ID, &record.RecordType, &record.RecordIdentifier,
		&record.OPAQUEUserRecord, &record.AssociatedFileID,
		&record.AssociatedUsername, &record.KeyLabel,
		&record.CreatedAt,
		&record.LastUsedAt, &record.IsActive)

	if err != nil {
		return nil, err
	}

	return &record, nil
}

// GetFilePasswordRecords gets all password records for a specific file
func (opm *OPAQUEPasswordManager) GetFilePasswordRecords(fileID string) ([]*OPAQUEPasswordRecord, error) {
	rows, err := opm.db.Query(`
		SELECT id, record_type, record_identifier, opaque_user_record, 
		       associated_file_id, associated_username, key_label, 
		       created_at, last_used_at, is_active
		FROM opaque_password_records 
		WHERE associated_file_id = ? AND is_active = TRUE
		ORDER BY created_at DESC`,
		fileID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*OPAQUEPasswordRecord
	for rows.Next() {
		var record OPAQUEPasswordRecord
		err := rows.Scan(
			&record.ID, &record.RecordType, &record.RecordIdentifier,
			&record.OPAQUEUserRecord, &record.AssociatedFileID,
			&record.AssociatedUsername, &record.KeyLabel,
			&record.CreatedAt,
			&record.LastUsedAt, &record.IsActive)

		if err != nil {
			return nil, err
		}

		records = append(records, &record)
	}

	return records, rows.Err()
}

// DeletePasswordRecord deactivates a password record
func (opm *OPAQUEPasswordManager) DeletePasswordRecord(recordIdentifier string) error {
	_, err := opm.db.Exec(`
		UPDATE opaque_password_records 
		SET is_active = FALSE 
		WHERE record_identifier = ?`, recordIdentifier)

	return err
}
