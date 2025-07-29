package auth

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	"github.com/84adam/arkfile/crypto"
	"github.com/84adam/arkfile/database"
)

// OPAQUEPasswordManager handles all password authentication via OPAQUE
type OPAQUEPasswordManager struct {
	db *sql.DB
}

// NewOPAQUEPasswordManager creates a new password manager instance
func NewOPAQUEPasswordManager() *OPAQUEPasswordManager {
	return &OPAQUEPasswordManager{
		db: database.DB,
	}
}

// OPAQUEPasswordRecord represents a unified password record
type OPAQUEPasswordRecord struct {
	ID                    int        `json:"id"`
	RecordType            string     `json:"record_type"`             // 'account', 'file_custom', 'share'
	RecordIdentifier      string     `json:"record_identifier"`       // email, 'user:file:filename', 'share:shareID'
	OPAQUEUserRecord      []byte     `json:"opaque_user_record"`      // OPAQUE registration data
	AssociatedFileID      *string    `json:"associated_file_id"`      // NULL for account, filename for file/share
	AssociatedUserEmail   *string    `json:"associated_user_email"`   // User who created this record
	KeyLabel              *string    `json:"key_label"`               // Human-readable label
	PasswordHintEncrypted []byte     `json:"password_hint_encrypted"` // Encrypted with export key
	CreatedAt             time.Time  `json:"created_at"`
	LastUsedAt            *time.Time `json:"last_used_at"`
	IsActive              bool       `json:"is_active"`
}

// RegisterCustomFilePassword registers a custom password for a specific file
func (opm *OPAQUEPasswordManager) RegisterCustomFilePassword(
	userEmail, fileID, password, keyLabel, passwordHint string) error {

	recordIdentifier := fmt.Sprintf("%s:file:%s", userEmail, fileID)

	// Ensure server keys are loaded
	if serverKeys == nil {
		if err := SetupServerKeys(opm.db); err != nil {
			return fmt.Errorf("failed to setup server keys: %w", err)
		}
	}

	// Register with OPAQUE
	userRecord, exportKey, err := libopaqueRegisterUser([]byte(password), serverKeys.ServerPrivateKey)
	if err != nil {
		return fmt.Errorf("OPAQUE registration failed: %w", err)
	}
	defer crypto.SecureZeroBytes(exportKey)

	// Encrypt password hint with export key if provided
	var encryptedHint []byte
	if passwordHint != "" {
		encryptedHint, err = encryptPasswordHint(passwordHint, exportKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt password hint: %w", err)
		}
	}

	// Store OPAQUE record
	_, err = opm.db.Exec(`
		INSERT INTO opaque_password_records 
		(record_type, record_identifier, opaque_user_record, associated_file_id, 
		 associated_user_email, key_label, password_hint_encrypted)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"file_custom", recordIdentifier, userRecord, fileID, userEmail, keyLabel, encryptedHint)

	return err
}

// RegisterSharePassword registers a password for anonymous share access
func (opm *OPAQUEPasswordManager) RegisterSharePassword(
	shareID, fileID, ownerEmail, password string) error {

	recordIdentifier := fmt.Sprintf("share:%s", shareID)

	// Register with OPAQUE (anonymous)
	userRecord, exportKey, err := libopaqueRegisterUser([]byte(password), serverKeys.ServerPrivateKey)
	if err != nil {
		return fmt.Errorf("OPAQUE registration failed: %w", err)
	}
	defer crypto.SecureZeroBytes(exportKey)

	// Store OPAQUE record
	_, err = opm.db.Exec(`
		INSERT INTO opaque_password_records 
		(record_type, record_identifier, opaque_user_record, associated_file_id, associated_user_email)
		VALUES (?, ?, ?, ?, ?)`,
		"share", recordIdentifier, userRecord, fileID, ownerEmail)

	return err
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

	// Authenticate with OPAQUE
	exportKey, err := libopaqueAuthenticateUser([]byte(password), userRecord)
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
		       associated_file_id, associated_user_email, key_label, 
		       password_hint_encrypted, created_at, last_used_at, is_active
		FROM opaque_password_records 
		WHERE record_identifier = ? AND is_active = TRUE`,
		recordIdentifier).Scan(
		&record.ID, &record.RecordType, &record.RecordIdentifier,
		&record.OPAQUEUserRecord, &record.AssociatedFileID,
		&record.AssociatedUserEmail, &record.KeyLabel,
		&record.PasswordHintEncrypted, &record.CreatedAt,
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
		       associated_file_id, associated_user_email, key_label, 
		       password_hint_encrypted, created_at, last_used_at, is_active
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
			&record.AssociatedUserEmail, &record.KeyLabel,
			&record.PasswordHintEncrypted, &record.CreatedAt,
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

// GetPasswordHint decrypts and returns the password hint for a record
func (opm *OPAQUEPasswordManager) GetPasswordHint(recordIdentifier string, exportKey []byte) (string, error) {
	var encryptedHint []byte
	err := opm.db.QueryRow(`
		SELECT password_hint_encrypted FROM opaque_password_records 
		WHERE record_identifier = ? AND is_active = TRUE`,
		recordIdentifier).Scan(&encryptedHint)

	if err != nil {
		return "", err
	}

	if len(encryptedHint) == 0 {
		return "", nil // No hint available
	}

	return decryptPasswordHint(encryptedHint, exportKey)
}

// Helper function to encrypt password hints with export key
func encryptPasswordHint(hint string, exportKey []byte) ([]byte, error) {
	hintKey, err := crypto.DerivePasswordHintKey(exportKey, "hint")
	if err != nil {
		return nil, err
	}
	defer crypto.SecureZeroBytes(hintKey)

	// Generate random nonce
	nonce := make([]byte, 12) // 96-bit nonce for AES-GCM
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with AES-GCM
	encrypted, err := crypto.EncryptAESGCM([]byte(hint), hintKey, nonce)
	if err != nil {
		return nil, err
	}

	// Prepend nonce to encrypted data
	result := make([]byte, len(nonce)+len(encrypted))
	copy(result, nonce)
	copy(result[len(nonce):], encrypted)

	return result, nil
}

// Helper function to decrypt password hints with export key
func decryptPasswordHint(encryptedHint, exportKey []byte) (string, error) {
	if len(encryptedHint) < 12 {
		return "", fmt.Errorf("encrypted hint too short")
	}

	hintKey, err := crypto.DerivePasswordHintKey(exportKey, "hint")
	if err != nil {
		return "", err
	}
	defer crypto.SecureZeroBytes(hintKey)

	// Extract nonce and encrypted data
	nonce := encryptedHint[:12]
	encrypted := encryptedHint[12:]

	// Decrypt with AES-GCM
	decrypted, err := crypto.DecryptAESGCM(encrypted, hintKey, nonce)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
