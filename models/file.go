package models

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/logging"
	"github.com/google/uuid"
)

type File struct {
	ID                     int64          `json:"id"`
	FileID                 string         `json:"file_id"`    // UUID v4 for file identification
	StorageID              string         `json:"storage_id"` // UUID v4 for storage backend
	OwnerUsername          string         `json:"owner_username"`
	PasswordHint           string         `json:"password_hint,omitempty"`
	PasswordType           string         `json:"password_type"`
	FilenameNonce          string         // Now stored as base64 strings directly
	EncryptedFilename      string         // Now stored as base64 strings directly
	Sha256sumNonce         string         // Now stored as base64 strings directly
	EncryptedSha256sum     string         // Now stored as base64 strings directly
	EncryptedFileSha256sum sql.NullString `json:"-"` // Hidden from JSON - server-side hash (nullable)
	EncryptedFEK           string         // Now stored as base64 strings directly
	SizeBytes              int64          `json:"size_bytes"`  // Original file size
	PaddedSize             sql.NullInt64  `json:"padded_size"` // Size with padding for privacy/security
	UploadDate             time.Time      `json:"upload_date"`
}

// GenerateStorageID creates a new UUID v4 for storage
func GenerateStorageID() string {
	return uuid.New().String()
}

// GenerateFileID creates a new UUID v4 for file identification
func GenerateFileID() string {
	return uuid.New().String()
}

// CreateFile creates a new file record in the database with encrypted metadata (base64 strings)
func CreateFile(db *sql.DB, fileID, storageID, ownerUsername, passwordHint, passwordType string,
	filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum string, sizeBytes int64) (*File, error) {

	result, err := db.Exec(`
		INSERT INTO file_metadata (
			file_id, storage_id, owner_username, password_hint, password_type,
			filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, size_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fileID, storageID, ownerUsername, passwordHint, passwordType,
		filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum, sizeBytes,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &File{
		ID:                 id,
		FileID:             fileID,
		StorageID:          storageID,
		OwnerUsername:      ownerUsername,
		PasswordHint:       passwordHint,
		PasswordType:       passwordType,
		FilenameNonce:      filenameNonce,      // Already base64 strings
		EncryptedFilename:  encryptedFilename,  // Already base64 strings
		Sha256sumNonce:     sha256sumNonce,     // Already base64 strings
		EncryptedSha256sum: encryptedSha256sum, // Already base64 strings
		SizeBytes:          sizeBytes,
		UploadDate:         time.Now(),
	}, nil
}

// GetFileByFileID retrieves a file record by file_id
func GetFileByFileID(db *sql.DB, fileID string) (*File, error) {
	file := &File{}
	var encryptedFileSha256sum string
	var sizeBytes interface{} // Use interface{} to handle both int64 and float64
	var uploadDateStr string  // Scan as string first to handle RQLite timestamp format

	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum,
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date
		FROM file_metadata WHERE file_id = ?`,
		fileID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename, // Scan directly into string fields
		&file.Sha256sumNonce, &file.EncryptedSha256sum, // Scan directly into string fields
		&encryptedFileSha256sum, &file.EncryptedFEK, // Scan directly into string fields
		&sizeBytes, &file.PaddedSize, &uploadDateStr,
	)

	// ENHANCED DEBUG: Log metadata as retrieved from database (EGRESS)
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG] GetFileByFileID %s - Retrieved metadata from database:", fileID)
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   filename_nonce: '%s' (length: %d)", file.FilenameNonce, len(file.FilenameNonce))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_filename: '%s' (length: %d)", file.EncryptedFilename, len(file.EncryptedFilename))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   sha256sum_nonce: '%s' (length: %d)", file.Sha256sumNonce, len(file.Sha256sumNonce))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_sha256sum: '%s' (length: %d)", file.EncryptedSha256sum, len(file.EncryptedSha256sum))

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

	// Convert sizeBytes from interface{} to int64, handling both int64 and float64
	switch v := sizeBytes.(type) {
	case int64:
		file.SizeBytes = v
	case float64:
		file.SizeBytes = int64(v)
	case nil:
		file.SizeBytes = 0
	default:
		return nil, fmt.Errorf("GetFileByFileID: unexpected type for size_bytes: %T", v)
	}

	// Parse timestamp string to time.Time
	if uploadDateStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else {
			// Fallback to current time if parsing fails
			file.UploadDate = time.Now()
		}
	}

	// Handle the nullable encrypted_file_sha256sum field
	if encryptedFileSha256sum != "" {
		file.EncryptedFileSha256sum = sql.NullString{
			String: encryptedFileSha256sum,
			Valid:  true,
		}
	} else {
		file.EncryptedFileSha256sum = sql.NullString{
			String: "",
			Valid:  false,
		}
	}

	return file, nil
}

// GetFileByStorageID retrieves a file record by storage_id
func GetFileByStorageID(db *sql.DB, storageID string) (*File, error) {
	file := &File{}
	var encryptedFileSha256sum string
	var sizeBytes interface{} // Use interface{} to handle both int64 and float64
	var uploadDateStr string  // Scan as string first to handle RQLite timestamp format

	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum,
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date
		FROM file_metadata WHERE storage_id = ?`,
		storageID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename, // Scan directly into string fields
		&file.Sha256sumNonce, &file.EncryptedSha256sum, // Scan directly into string fields
		&encryptedFileSha256sum, &file.EncryptedFEK, // Scan directly into string fields
		&sizeBytes, &file.PaddedSize, &uploadDateStr,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

	// Convert sizeBytes from interface{} to int64, handling both int64 and float64
	switch v := sizeBytes.(type) {
	case int64:
		file.SizeBytes = v
	case float64:
		file.SizeBytes = int64(v)
	case nil:
		file.SizeBytes = 0
	default:
		return nil, fmt.Errorf("GetFileByStorageID: unexpected type for size_bytes: %T", v)
	}

	// Parse timestamp string to time.Time
	if uploadDateStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else {
			// Fallback to current time if parsing fails
			file.UploadDate = time.Now()
		}
	}

	// Handle the nullable encrypted_file_sha256sum field
	if encryptedFileSha256sum != "" {
		file.EncryptedFileSha256sum = sql.NullString{
			String: encryptedFileSha256sum,
			Valid:  true,
		}
	} else {
		file.EncryptedFileSha256sum = sql.NullString{
			String: "",
			Valid:  false,
		}
	}

	return file, nil
}

// GetFilesByOwner retrieves all files owned by a specific user
func GetFilesByOwner(db *sql.DB, ownerUsername string) ([]*File, error) {
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG] GetFilesByOwner called for user: %s", ownerUsername)

	if db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date 
		FROM file_metadata WHERE owner_username = ? ORDER BY upload_date DESC`

	rows, err := db.Query(query, ownerUsername)
	if err != nil {
		return nil, fmt.Errorf("sql query failed for user '%s': %w", ownerUsername, err)
	}
	defer rows.Close()

	var files []*File
	fileCount := 0
	for rows.Next() {
		file := &File{}
		var encryptedFileSha256sum string
		var sizeBytes interface{}
		var uploadDateStr string

		err := rows.Scan(
			&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
			&file.PasswordHint, &file.PasswordType,
			&file.FilenameNonce, &file.EncryptedFilename, // Scan directly into string fields
			&file.Sha256sumNonce, &file.EncryptedSha256sum, // Scan directly into string fields
			&encryptedFileSha256sum, &file.EncryptedFEK, // Scan directly into string fields
			&sizeBytes, &file.PaddedSize, &uploadDateStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row for user '%s': %w", ownerUsername, err)
		}

		fileCount++
		logging.InfoLogger.Printf("[INFO_METADATA_DEBUG] File #%d - Retrieved from database:", fileCount)
		logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   file_id: %s", file.FileID)
		logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   filename_nonce: '%s' (length: %d)", file.FilenameNonce, len(file.FilenameNonce))
		logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_filename: '%s' (length: %d)", file.EncryptedFilename, len(file.EncryptedFilename))
		logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   sha256sum_nonce: '%s' (length: %d)", file.Sha256sumNonce, len(file.Sha256sumNonce))
		logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_sha256sum: '%s' (length: %d)", file.EncryptedSha256sum, len(file.EncryptedSha256sum))
		logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_fek: '%s' (length: %d)", file.EncryptedFEK, len(file.EncryptedFEK))

		// Convert sizeBytes from interface{} to int64
		switch v := sizeBytes.(type) {
		case int64:
			file.SizeBytes = v
		case float64:
			file.SizeBytes = int64(v)
		case nil:
			file.SizeBytes = 0
		default:
			return nil, fmt.Errorf("unexpected type for size_bytes: %T", v)
		}

		// Parse timestamp string to time.Time
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if uploadDateStr != "" {
			// Skip if parsing fails - no logging needed in this bulk operation
		}

		// Handle nullable encrypted_file_sha256sum
		if encryptedFileSha256sum != "" {
			file.EncryptedFileSha256sum = sql.NullString{String: encryptedFileSha256sum, Valid: true}
		}

		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error for user '%s': %w", ownerUsername, err)
	}

	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG] GetFilesByOwner returning %d files for user %s", len(files), ownerUsername)
	return files, nil
}

// DeleteFile removes a file record from the database by file_id
func DeleteFile(db *sql.DB, fileID string, ownerUsername string) error {
	result, err := db.Exec(
		"DELETE FROM file_metadata WHERE file_id = ? AND owner_username = ?",
		fileID, ownerUsername,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return errors.New("file not found or unauthorized")
	}

	return nil
}

// UpdatePasswordHint updates the password hint for a file
func (f *File) UpdatePasswordHint(db *sql.DB, newHint string) error {
	_, err := db.Exec(
		"UPDATE file_metadata SET password_hint = ? WHERE id = ?",
		newHint, f.ID,
	)
	if err != nil {
		return err
	}

	f.PasswordHint = newHint
	return nil
}

// FileMetadataForClient represents the encrypted metadata that gets sent to the client.
// All binary data is Base64-encoded as strings for robust JSON transport.
type FileMetadataForClient struct {
	FileID             string    `json:"file_id"`
	StorageID          string    `json:"storage_id"`
	PasswordHint       string    `json:"password_hint,omitempty"`
	PasswordType       string    `json:"password_type"`
	FilenameNonce      string    `json:"filename_nonce"`
	EncryptedFilename  string    `json:"encrypted_filename"`
	Sha256sumNonce     string    `json:"sha256sum_nonce"`
	EncryptedSha256sum string    `json:"encrypted_sha256sum"`
	EncryptedFEK       string    `json:"encrypted_fek"`
	SizeBytes          int64     `json:"size_bytes"`
	UploadDate         time.Time `json:"upload_date"`
}

// ToClientMetadata converts a File to FileMetadataForClient for sending to the client.
// All data is now stored as base64 strings directly, so we return them as-is.
func (f *File) ToClientMetadata() *FileMetadataForClient {
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG] ToClientMetadata called for file_id: %s", f.FileID)
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG] INPUT from File struct:")
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   filename_nonce: '%s' (length: %d)", f.FilenameNonce, len(f.FilenameNonce))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_filename: '%s' (length: %d)", f.EncryptedFilename, len(f.EncryptedFilename))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   sha256sum_nonce: '%s' (length: %d)", f.Sha256sumNonce, len(f.Sha256sumNonce))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_sha256sum: '%s' (length: %d)", f.EncryptedSha256sum, len(f.EncryptedSha256sum))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_fek: '%s' (length: %d)", f.EncryptedFEK, len(f.EncryptedFEK))

	clientFile := &FileMetadataForClient{
		FileID:             f.FileID,
		StorageID:          f.StorageID,
		PasswordHint:       f.PasswordHint,
		PasswordType:       f.PasswordType,
		FilenameNonce:      f.FilenameNonce,
		EncryptedFilename:  f.EncryptedFilename,
		Sha256sumNonce:     f.Sha256sumNonce,
		EncryptedSha256sum: f.EncryptedSha256sum,
		EncryptedFEK:       f.EncryptedFEK,
		SizeBytes:          f.SizeBytes,
		UploadDate:         f.UploadDate,
	}

	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG] OUTPUT to ClientMetadata:")
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   filename_nonce: '%s' (length: %d)", clientFile.FilenameNonce, len(clientFile.FilenameNonce))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_filename: '%s' (length: %d)", clientFile.EncryptedFilename, len(clientFile.EncryptedFilename))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   sha256sum_nonce: '%s' (length: %d)", clientFile.Sha256sumNonce, len(clientFile.Sha256sumNonce))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_sha256sum: '%s' (length: %d)", clientFile.EncryptedSha256sum, len(clientFile.EncryptedSha256sum))
	logging.InfoLogger.Printf("[INFO_METADATA_DEBUG]   encrypted_fek: '%s' (length: %d)", clientFile.EncryptedFEK, len(clientFile.EncryptedFEK))

	return clientFile
}
