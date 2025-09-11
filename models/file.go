package models

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type File struct {
	ID                     int64          `json:"id"`
	FileID                 string         `json:"file_id"`    // UUID v4 for file identification
	StorageID              string         `json:"storage_id"` // UUID v4 for storage backend
	OwnerUsername          string         `json:"owner_username"`
	PasswordHint           string         `json:"password_hint,omitempty"`
	PasswordType           string         `json:"password_type"`
	FilenameNonce          []byte         `json:"-"`           // Hidden from JSON - 12 bytes
	EncryptedFilename      []byte         `json:"-"`           // Hidden from JSON - encrypted blob
	Sha256sumNonce         []byte         `json:"-"`           // Hidden from JSON - 12 bytes
	EncryptedSha256sum     []byte         `json:"-"`           // Hidden from JSON - encrypted blob (client-side)
	EncryptedFileSha256sum sql.NullString `json:"-"`           // Hidden from JSON - server-side hash (nullable)
	EncryptedFEK           []byte         `json:"-"`           // Hidden from JSON - encrypted File Encryption Key
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

// CreateFile creates a new file record in the database with encrypted metadata
func CreateFile(db *sql.DB, fileID, storageID, ownerUsername, passwordHint, passwordType string,
	filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum []byte, sizeBytes int64) (*File, error) {

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
		FilenameNonce:      filenameNonce,
		EncryptedFilename:  encryptedFilename,
		Sha256sumNonce:     sha256sumNonce,
		EncryptedSha256sum: encryptedSha256sum,
		SizeBytes:          sizeBytes,
		UploadDate:         time.Now(),
	}, nil
}

// GetFileByFileID retrieves a file record by file_id
func GetFileByFileID(db *sql.DB, fileID string) (*File, error) {
	file := &File{}
	var encryptedFileSha256sum string
	var encryptedFekRaw interface{}   // Use interface{} to handle driver differences
	var filenameNonceRaw interface{}  // Use interface{} to handle RQLite base64 BLOB returns
	var sha256sumNonceRaw interface{} // Use interface{} to handle RQLite base64 BLOB returns
	var sizeBytes interface{}         // Use interface{} to handle both int64 and float64
	var uploadDateStr string          // Scan as string first to handle RQLite timestamp format
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date 
		FROM file_metadata WHERE file_id = ?`,
		fileID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&filenameNonceRaw, &file.EncryptedFilename,
		&sha256sumNonceRaw, &file.EncryptedSha256sum,
		&encryptedFileSha256sum, &encryptedFekRaw, &sizeBytes, &file.PaddedSize, &uploadDateStr,
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

	// Handle FilenameNonce - may be a base64 string from rqlite
	switch v := filenameNonceRaw.(type) {
	case []byte:
		file.FilenameNonce = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 for filename_nonce: %w", err)
		}
		file.FilenameNonce = decoded
	case nil:
		file.FilenameNonce = nil
	default:
		return nil, fmt.Errorf("unexpected type for filename_nonce: %T", v)
	}

	// Handle Sha256sumNonce - may be a base64 string from rqlite
	switch v := sha256sumNonceRaw.(type) {
	case []byte:
		file.Sha256sumNonce = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 for sha256sum_nonce: %w", err)
		}
		file.Sha256sumNonce = decoded
	case nil:
		file.Sha256sumNonce = nil
	default:
		return nil, fmt.Errorf("unexpected type for sha256sum_nonce: %T", v)
	}

	// Correctly handle encrypted_fek, which may be a base64 string from rqlite
	switch v := encryptedFekRaw.(type) {
	case []byte:
		file.EncryptedFEK = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 for encrypted_fek: %w", err)
		}
		file.EncryptedFEK = decoded
	case nil:
		file.EncryptedFEK = nil
	default:
		return nil, fmt.Errorf("unexpected type for encrypted_fek: %T", v)
	}

	return file, nil
}

// GetFileByStorageID retrieves a file record by storage_id
func GetFileByStorageID(db *sql.DB, storageID string) (*File, error) {
	file := &File{}
	var encryptedFileSha256sum string
	var encryptedFekRaw interface{}   // Use interface{} to handle driver differences
	var filenameNonceRaw interface{}  // Use interface{} to handle RQLite base64 BLOB returns
	var sha256sumNonceRaw interface{} // Use interface{} to handle RQLite base64 BLOB returns
	var sizeBytes interface{}         // Use interface{} to handle both int64 and float64
	var uploadDateStr string          // Scan as string first to handle RQLite timestamp format
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date 
		FROM file_metadata WHERE storage_id = ?`,
		storageID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&filenameNonceRaw, &file.EncryptedFilename,
		&sha256sumNonceRaw, &file.EncryptedSha256sum,
		&encryptedFileSha256sum, &encryptedFekRaw, &sizeBytes, &file.PaddedSize, &uploadDateStr,
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

	// Handle FilenameNonce - may be a base64 string from rqlite
	switch v := filenameNonceRaw.(type) {
	case []byte:
		file.FilenameNonce = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 for filename_nonce: %w", err)
		}
		file.FilenameNonce = decoded
	case nil:
		file.FilenameNonce = nil
	default:
		return nil, fmt.Errorf("unexpected type for filename_nonce: %T", v)
	}

	// Handle Sha256sumNonce - may be a base64 string from rqlite
	switch v := sha256sumNonceRaw.(type) {
	case []byte:
		file.Sha256sumNonce = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 for sha256sum_nonce: %w", err)
		}
		file.Sha256sumNonce = decoded
	case nil:
		file.Sha256sumNonce = nil
	default:
		return nil, fmt.Errorf("unexpected type for sha256sum_nonce: %T", v)
	}

	// Correctly handle encrypted_fek, which may be a base64 string from rqlite
	switch v := encryptedFekRaw.(type) {
	case []byte:
		file.EncryptedFEK = v
	case string:
		// rqlite driver returns BLOBs as base64-encoded strings
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 for encrypted_fek: %w", err)
		}
		file.EncryptedFEK = decoded
	case nil:
		file.EncryptedFEK = nil
	default:
		return nil, fmt.Errorf("unexpected type for encrypted_fek: %T", v)
	}

	return file, nil
}

// GetFilesByOwner retrieves all files owned by a specific user
func GetFilesByOwner(db *sql.DB, ownerUsername string) ([]*File, error) {
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
	for rows.Next() {
		file := &File{}
		var encryptedFileSha256sum string
		var encryptedFekRaw interface{}
		var filenameNonceRaw interface{}  // Use interface{} to handle RQLite base64 BLOB returns
		var sha256sumNonceRaw interface{} // Use interface{} to handle RQLite base64 BLOB returns
		var sizeBytes interface{}
		var uploadDateStr string

		err := rows.Scan(
			&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
			&file.PasswordHint, &file.PasswordType,
			&filenameNonceRaw, &file.EncryptedFilename,
			&sha256sumNonceRaw, &file.EncryptedSha256sum,
			&encryptedFileSha256sum, &encryptedFekRaw, &sizeBytes, &file.PaddedSize, &uploadDateStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row for user '%s': %w", ownerUsername, err)
		}

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

		// Handle FilenameNonce - may be a base64 string from rqlite
		switch v := filenameNonceRaw.(type) {
		case []byte:
			file.FilenameNonce = v
		case string:
			// rqlite driver returns BLOBs as base64-encoded strings
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 for filename_nonce: %w", err)
			}
			file.FilenameNonce = decoded
		case nil:
			file.FilenameNonce = nil
		default:
			return nil, fmt.Errorf("unexpected type for filename_nonce: %T", v)
		}

		// Handle Sha256sumNonce - may be a base64 string from rqlite
		switch v := sha256sumNonceRaw.(type) {
		case []byte:
			file.Sha256sumNonce = v
		case string:
			// rqlite driver returns BLOBs as base64-encoded strings
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 for sha256sum_nonce: %w", err)
			}
			file.Sha256sumNonce = decoded
		case nil:
			file.Sha256sumNonce = nil
		default:
			return nil, fmt.Errorf("unexpected type for sha256sum_nonce: %T", v)
		}

		// Convert encryptedFekRaw from interface{} to []byte, preventing driver corruption
		switch v := encryptedFekRaw.(type) {
		case []byte:
			file.EncryptedFEK = v
		case string:
			// rqlite driver returns BLOBs as base64-encoded strings
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 for encrypted_fek: %w", err)
			}
			file.EncryptedFEK = decoded
		case nil:
			file.EncryptedFEK = nil
		default:
			return nil, fmt.Errorf("unexpected type for encrypted_fek: %T", v)
		}

		// Parse timestamp string to time.Time
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if uploadDateStr != "" {
			// In a real application, this would be a logged warning.
			// For now, we just skip if parsing fails.
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

// ToClientMetadata converts a File to FileMetadataForClient for sending to the client,
// ensuring all binary data is Base64 encoded.
func (f *File) ToClientMetadata() *FileMetadataForClient {
	return &FileMetadataForClient{
		FileID:             f.FileID,
		StorageID:          f.StorageID,
		PasswordHint:       f.PasswordHint,
		PasswordType:       f.PasswordType,
		FilenameNonce:      base64.StdEncoding.EncodeToString(f.FilenameNonce),
		EncryptedFilename:  base64.StdEncoding.EncodeToString(f.EncryptedFilename),
		Sha256sumNonce:     base64.StdEncoding.EncodeToString(f.Sha256sumNonce),
		EncryptedSha256sum: base64.StdEncoding.EncodeToString(f.EncryptedSha256sum),
		EncryptedFEK:       base64.StdEncoding.EncodeToString(f.EncryptedFEK),
		SizeBytes:          f.SizeBytes,
		UploadDate:         f.UploadDate,
	}
}
